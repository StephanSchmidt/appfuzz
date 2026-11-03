//! Mutate data encoded inside WIT strings, without throwing away its parser.
use rand::{RngExt, rngs::StdRng};
use serde_json::{Value, json};

const MAX_BYTES: usize = 256 * 1024;
const MAX_NODES: usize = 2048;
const MAX_EDITS: usize = 32;

enum Document {
    Json(Value),
    // Header-bearing, comma-separated UTF-8 CSV. Header field values are kept.
    Csv(Vec<Vec<String>>),
}

impl Document {
    fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_BYTES {
            return None;
        }
        let trimmed = text.trim_start();
        if trimmed.starts_with(['{', '[']) {
            let value: Value = serde_json::from_str(text).ok()?;
            let mut budget = MAX_NODES;
            fn fits(v: &Value, budget: &mut usize) -> bool {
                if *budget == 0 {
                    return false;
                }
                *budget -= 1;
                match v {
                    Value::Array(a) => a.iter().all(|v| fits(v, budget)),
                    Value::Object(o) => o.values().all(|v| fits(v, budget)),
                    _ => true,
                }
            }
            return fits(&value, &mut budget).then_some(Self::Json(value));
        }
        if !text.contains(',') || !text.contains('\n') {
            return None;
        }
        let mut reader = csv::ReaderBuilder::new().has_headers(false).from_reader(text.as_bytes());
        let mut rows = Vec::new();
        let mut cells = 0;
        for row in reader.records() {
            let row = row.ok()?;
            if row.len() < 2 {
                return None;
            }
            cells += row.len();
            if cells > MAX_NODES {
                return None;
            }
            rows.push(row.iter().map(str::to_string).collect());
        }
        (rows.len() >= 2).then_some(Self::Csv(rows))
    }

    fn encode(&self) -> Option<String> {
        let text = match self {
            Self::Json(v) => serde_json::to_string(v).ok()?,
            Self::Csv(rows) => {
                let mut writer = csv::WriterBuilder::new().from_writer(Vec::new());
                for row in rows {
                    writer.write_record(row).ok()?;
                }
                String::from_utf8(writer.into_inner().ok()?).ok()?
            }
        };
        (text.len() <= MAX_BYTES).then_some(text)
    }
}

/// Paths of candidate strings. Bounds scanning even for large guest responses.
pub(crate) fn locations(value: &Value) -> Vec<String> {
    fn walk(v: &Value, path: String, out: &mut Vec<String>, nodes: &mut usize, bytes: &mut usize) {
        if *nodes == 0 || out.len() >= 64 {
            return;
        }
        *nodes -= 1;
        match v {
            Value::String(s) if s.len() <= *bytes => {
                *bytes -= s.len();
                if Document::parse(s).is_some() {
                    out.push(path);
                }
            }
            Value::Object(o) => {
                for (key, v) in o {
                    walk(v, format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")), out, nodes, bytes);
                    if *nodes == 0 {
                        break;
                    }
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    walk(v, format!("{path}/{i}"), out, nodes, bytes);
                    if *nodes == 0 {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    let (mut nodes, mut bytes) = (MAX_NODES, MAX_BYTES);
    walk(value, String::new(), &mut out, &mut nodes, &mut bytes);
    out
}

fn scalar(value: &Value, rng: &mut StdRng, words: &[String], numbers: &[i64]) -> Value {
    match value {
        Value::Bool(b) => json!(!b),
        Value::Number(_) => {
            let edges = [0, 1, -1, 2, 16, 127, 255, 256, 65535, i32::MAX as i64, i32::MIN as i64];
            let n = if !numbers.is_empty() && rng.random_bool(0.3) { numbers[rng.random_range(0..numbers.len())] } else { edges[rng.random_range(0..edges.len())] };
            json!(n)
        }
        Value::String(_) => {
            let edges = ["", "0", "-1", "é🦀", "\"quoted\",cell\nnext", "null"];
            if !words.is_empty() && rng.random_bool(0.3) { json!(words[rng.random_range(0..words.len())]) } else { json!(edges[rng.random_range(0..edges.len())]) }
        }
        Value::Null => json!(""),
        _ => value.clone(),
    }
}

pub(crate) fn mutate(text: &str, rng: &mut StdRng, words: &[String], numbers: &[i64]) -> Option<String> {
    let mut doc = Document::parse(text)?;
    match &mut doc {
        Document::Json(root) => {
            let mut paths = Vec::new();
            crate::fuzz::nodes(root, String::new(), &mut paths);
            if paths.is_empty() {
                return None;
            }
            let path = &paths[rng.random_range(0..paths.len())];
            let node = root.pointer_mut(path)?;
            match node {
                Value::Array(a) => match rng.random_range(0..3) {
                    0 if !a.is_empty() => {
                        a.remove(rng.random_range(0..a.len()));
                    }
                    1 if !a.is_empty() && a.len() < 256 => {
                        let value = a[rng.random_range(0..a.len())].clone();
                        a.push(value);
                    }
                    _ if a.len() < 256 => a.push(a.last().cloned().unwrap_or(json!(0))),
                    _ => return None,
                },
                _ => *node = scalar(node, rng, words, numbers),
            }
        }
        Document::Csv(rows) => {
            let row = rng.random_range(1..rows.len());
            match rng.random_range(0..5) {
                0 if rows.len() > 2 => {
                    rows.remove(row);
                }
                1 if rows.len() < 256 => rows.push(rows[row].clone()),
                _ => {
                    let column = rng.random_range(0..rows[row].len());
                    let old = &rows[row][column];
                    let value = old.parse::<serde_json::Number>().map(Value::Number).unwrap_or_else(|_| json!(old));
                    let new = scalar(&value, rng, words, numbers);
                    rows[row][column] = new.as_str().map(str::to_string).unwrap_or_else(|| new.to_string());
                }
            }
        }
    }
    let new = doc.encode()?;
    // Reject oversized/deep expansions, as well as no-op edits.
    (new != text && Document::parse(&new).is_some()).then_some(new)
}

fn simpler(value: &Value) -> Vec<Value> {
    match value {
        Value::Number(n) => {
            if let Some(n) = n.as_u64() {
                [0, 1, n / 2, n.saturating_sub(1)].into_iter().filter(|m| *m < n).map(|m| json!(m)).collect()
            } else if n.as_f64().is_some_and(|n| n != 0.0) {
                vec![json!(0)]
            } else {
                vec![]
            }
        }
        Value::String(s) if !s.is_empty() => vec![json!(""), json!(s.chars().take(s.chars().count() / 2).collect::<String>())],
        Value::Bool(true) => vec![json!(false)],
        Value::Array(a) if !a.is_empty() => vec![json!([]), json!(&a[..a.len() / 2]), json!(&a[..a.len() - 1])],
        _ => vec![],
    }
}

/// Simplify inside the document before attempting raw string truncation.
pub(crate) fn shrink(text: &str) -> Vec<String> {
    let Some(doc) = Document::parse(text) else {
        return vec![];
    };
    let mut out = Vec::new();
    match doc {
        Document::Json(root) => {
            let mut paths = Vec::new();
            crate::fuzz::nodes(&root, String::new(), &mut paths);
            // Optional object fields may disappear too. Required ones survive the predicate.
            fn objects(v: &Value, path: String, out: &mut Vec<String>) {
                match v {
                    Value::Object(o) => {
                        out.push(path.clone());
                        for (k, v) in o {
                            objects(v, format!("{path}/{}", k.replace('~', "~0").replace('/', "~1")), out);
                        }
                    }
                    Value::Array(a) => {
                        for (i, v) in a.iter().enumerate() {
                            objects(v, format!("{path}/{i}"), out);
                        }
                    }
                    _ => {}
                }
            }
            let mut object_paths = Vec::new();
            objects(&root, String::new(), &mut object_paths);
            for path in &paths {
                for value in simpler(root.pointer(path).expect("path")) {
                    let mut next = root.clone();
                    *next.pointer_mut(path).expect("path") = value;
                    if let Some(s) = Document::Json(next).encode() {
                        out.push(s);
                    }
                    if out.len() == MAX_EDITS {
                        return out;
                    }
                }
            }
            for path in object_paths {
                for key in root.pointer(&path).and_then(Value::as_object).expect("object").keys() {
                    let mut next = root.clone();
                    next.pointer_mut(&path).and_then(Value::as_object_mut).expect("object").remove(key);
                    if let Some(s) = Document::Json(next).encode() {
                        out.push(s);
                    }
                    if out.len() == MAX_EDITS {
                        return out;
                    }
                }
            }
        }
        Document::Csv(rows) => {
            // Keep at least one data row so subsequent passes still recognize CSV.
            if rows.len() > 2 {
                for keep in [2, 1 + (rows.len() - 1) / 2, rows.len() - 1] {
                    if let Some(s) = Document::Csv(rows[..keep].to_vec()).encode() {
                        out.push(s);
                    }
                }
            }
            for row in 1..rows.len() {
                for col in 0..rows[row].len() {
                    let old = &rows[row][col];
                    let value = old.parse::<serde_json::Number>().map(Value::Number).unwrap_or_else(|_| json!(old));
                    for value in simpler(&value) {
                        let mut next = rows.clone();
                        next[row][col] = value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string());
                        if let Some(s) = Document::Csv(next).encode() {
                            out.push(s);
                        }
                        if out.len() >= MAX_EDITS {
                            return out;
                        }
                    }
                }
            }
        }
    }
    out.retain(|s| s != text);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn json_mutations_keep_keys_and_valid_syntax() {
        let text = r#"{"order":{"quantity":12,"label":"hello"},"items":[1,2],"active":true}"#;
        let mut rng = StdRng::seed_from_u64(1);
        let mut zero = false;
        for _ in 0..300 {
            let Some(new) = mutate(text, &mut rng, &[], &[]) else {
                continue;
            };
            let v: Value = serde_json::from_str(&new).unwrap();
            assert!(v["order"].get("quantity").is_some());
            zero |= v["order"]["quantity"] == 0;
        }
        assert!(zero);
        assert!(shrink(text).iter().all(|s| serde_json::from_str::<Value>(s).is_ok()));
    }

    #[test]
    fn csv_quotes_unicode_and_multiline_survive_mutation_and_shrinking() {
        let text = "id,note,amount\r\n1,\"é, and \"\"quotes\"\"\nnext\",12\r\n2,ok,5\r\n";
        let mut rng = StdRng::seed_from_u64(3);
        for new in (0..100).filter_map(|_| mutate(text, &mut rng, &[], &[])).chain(shrink(text)) {
            let Document::Csv(rows) = Document::parse(&new).unwrap() else {
                panic!("CSV");
            };
            assert_eq!(rows[0], ["id", "note", "amount"]);
            assert!(rows.iter().all(|r| r.len() == 3));
        }
        assert!(Document::parse("hello, world").is_none());
        assert!(Document::parse("a,b\n1,2,3\n").is_none());
        assert!(Document::parse(&"x".repeat(MAX_BYTES + 1)).is_none());
    }
}
