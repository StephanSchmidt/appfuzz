//! What appfuzz knows about well-known host APIs without a manifest: Spin's
//! SQL, key-value, Redis and MQTT, and `wasi:keyvalue`. Their WIT says what
//! a call does (a SQL statement, a write, a message sent), so these labels
//! are facts, not guesses. A manifest section for the same function keeps
//! what it sets; only fields it leaves empty are filled in.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use crate::manifest::{FunctionSpec, Manifest};
use crate::wit::Interface;

const KNOWN: &str = r#"
# Spin 2/3 (fermyon:spin@2.0.0) and the Spin 3 packages.
["fermyon:spin/sqlite#[method]connection.execute"]
params = { statement = "sql" }
["spin:sqlite/sqlite#[method]connection.execute"]
params = { statement = "sql" }
["fermyon:spin/postgres#[method]connection.query"]
params = { statement = "sql" }
["fermyon:spin/postgres#[method]connection.execute"]
params = { statement = "sql" }
["spin:postgres/postgres#[method]connection.query"]
params = { statement = "sql" }
["spin:postgres/postgres#[method]connection.execute"]
params = { statement = "sql" }
["fermyon:spin/mysql#[method]connection.query"]
params = { statement = "sql" }
["fermyon:spin/mysql#[method]connection.execute"]
params = { statement = "sql" }

# Spin 4 (spin-sdk 7): async functions; rows arrive as a stream.
["spin:sqlite/sqlite#[method]connection.execute-async"]
params = { statement = "sql" }
["spin:postgres/postgres#[method]connection.query-async"]
params = { statement = "sql" }
["spin:postgres/postgres#[method]connection.execute-async"]
params = { statement = "sql" }
["spin:mysql/mysql#[method]connection.query"]
params = { statement = "sql" }
["spin:mysql/mysql#[method]connection.execute"]
params = { statement = "sql" }

["fermyon:spin/key-value#[method]store.set"]
effect = "write"
idempotent = true
["fermyon:spin/key-value#[method]store.delete"]
effect = "delete"
idempotent = true
["spin:key-value/key-value#[method]store.set"]
effect = "write"
idempotent = true
["spin:key-value/key-value#[method]store.delete"]
effect = "delete"
idempotent = true

["fermyon:spin/redis#[method]connection.publish"]
effect = "external"
["fermyon:spin/redis#[method]connection.set"]
effect = "write"
idempotent = true
["fermyon:spin/redis#[method]connection.incr"]
effect = "write"
["fermyon:spin/redis#[method]connection.sadd"]
effect = "write"
idempotent = true
["fermyon:spin/redis#[method]connection.del"]
effect = "delete"
idempotent = true
["fermyon:spin/redis#[method]connection.srem"]
effect = "delete"
idempotent = true

["spin:redis/redis#[method]connection.publish"]
effect = "external"
["spin:redis/redis#[method]connection.set"]
effect = "write"
idempotent = true
["spin:redis/redis#[method]connection.incr"]
effect = "write"
["spin:redis/redis#[method]connection.sadd"]
effect = "write"
idempotent = true
["spin:redis/redis#[method]connection.del"]
effect = "delete"
idempotent = true
["spin:redis/redis#[method]connection.srem"]
effect = "delete"
idempotent = true

["fermyon:spin/mqtt#[static]connection.open"]
params = { password = "secret" }
["fermyon:spin/mqtt#[method]connection.publish"]
effect = "external"
["spin:mqtt/mqtt#[static]connection.open"]
params = { password = "secret" }
["spin:mqtt/mqtt#[method]connection.publish"]
effect = "external"

# wasi:keyvalue 0.2 drafts (Spin 3, wasmCloud).
["wasi:keyvalue/store#[method]bucket.set"]
effect = "write"
idempotent = true
["wasi:keyvalue/store#[method]bucket.delete"]
effect = "delete"
idempotent = true
["wasi:keyvalue/atomics#increment"]
effect = "write"
["wasi:keyvalue/batch#get-many"]
batch_of = "wasi:keyvalue/store#[method]bucket.get"
["wasi:keyvalue/batch#set-many"]
effect = "write"
idempotent = true
batch_of = "wasi:keyvalue/store#[method]bucket.set"
["wasi:keyvalue/batch#delete-many"]
effect = "delete"
idempotent = true
batch_of = "wasi:keyvalue/store#[method]bucket.delete"
"#;

/// Fills in the labels of known host functions the component imports.
pub fn defaults(manifest: &mut Manifest, imports: &[Interface]) -> Result<()> {
    let known: BTreeMap<String, FunctionSpec> = toml::from_str(KNOWN).context("built-in host API labels")?;
    for f in imports.iter().flat_map(|i| &i.funcs) {
        let Some(k) = known.get(&f.key) else { continue };
        let key = manifest
            .functions
            .keys()
            .find(|m| {
                let (i, n) = m.split_once('#').unwrap_or(("", m));
                crate::manifest::fn_key(i, n) == f.key
            })
            .cloned()
            .unwrap_or_else(|| f.key.clone());
        let spec = manifest.functions.entry(key).or_default();
        for (p, l) in &k.params {
            spec.params.entry(p.clone()).or_insert(*l);
        }
        if spec.effect.is_none() && k.effect.is_some() {
            spec.effect = k.effect;
            spec.idempotent |= k.idempotent;
        }
        if spec.batch_of.is_none() {
            spec.batch_of.clone_from(&k.batch_of);
        }
    }
    Ok(())
}

/// Spin's SQL calls whose answer has columns and rows: the null value of
/// their rows, and whether a column is a record with a name (or a string).
const SQL_ANSWERS: &[(&str, &str, bool)] = &[
    ("fermyon:spin/sqlite#[method]connection.execute", "null", false),
    ("spin:sqlite/sqlite#[method]connection.execute", "null", false),
    ("spin:sqlite/sqlite#[method]connection.execute-async", "null", false),
    ("fermyon:spin/postgres#[method]connection.query", "db-null", true),
    ("spin:postgres/postgres#[method]connection.query", "db-null", true),
    ("spin:postgres/postgres#[method]connection.query-async", "db-null", true),
    ("fermyon:spin/mysql#[method]connection.query", "db-null", true),
    ("spin:mysql/mysql#[method]connection.query", "db-null", true),
];

pub fn is_sql_answer(key: &str) -> bool {
    SQL_ANSWERS.iter().any(|(k, _, _)| *k == key)
}

/// What a database always answers, whatever the rows: the columns a
/// `SELECT` names, and one value per column in each row. Applied to
/// generated answers; a plan's answer is the plan's.
pub fn sql_answer(key: &str, statement: Option<&str>, answer: &mut serde_json::Value) {
    use serde_json::{Value, json};
    let Some(&(_, null, named)) = SQL_ANSWERS.iter().find(|(k, _, _)| *k == key) else { return };
    let Some(ok) = answer.get_mut("ok") else { return };
    // A `row-set` record, or the async tuple `(columns, rows, end)`.
    let (columns, rows) = match ok {
        Value::Object(m) => {
            let Some(rows) = m.get_mut("rows").map(std::mem::take) else { return };
            let Some(columns) = m.get_mut("columns") else { return };
            let mut rows = rows;
            fit(columns, &mut rows, statement, null, named);
            m.insert("rows".into(), rows);
            return;
        }
        Value::Array(xs) if xs.len() >= 2 => {
            let (a, b) = xs.split_at_mut(1);
            (&mut a[0], &mut b[0])
        }
        _ => return,
    };
    fit(columns, rows, statement, null, named);

    fn fit(columns: &mut Value, rows: &mut Value, statement: Option<&str>, null: &str, named: bool) {
        let Value::Array(cols) = columns else { return };
        if let Some(names) = statement.and_then(select_names) {
            let template = cols.first().cloned();
            *cols = names
                .into_iter()
                .map(|n| match (&template, named) {
                    (Some(Value::Object(o)), _) => {
                        let mut o = o.clone();
                        o.insert("name".into(), json!(n));
                        Value::Object(o)
                    }
                    (_, true) => json!({ "name": n, "data-type": "str" }),
                    (_, false) => json!(n),
                })
                .collect();
        }
        let width = cols.len();
        let Value::Array(rows) = rows else { return };
        for row in rows {
            let values = match row {
                Value::Object(m) => m.get_mut("values"),
                v => Some(v),
            };
            let Some(Value::Array(values)) = values else { continue };
            let have = values.len();
            values.truncate(width);
            for i in have..width {
                let v = if have == 0 { Value::String(null.into()) } else { values[i % have].clone() };
                values.push(v);
            }
        }
    }
}

/// The column names of `SELECT a, b AS c, t.d FROM …`: `a`, `c`, `d`. None
/// for other statements and for `*`, whose names depend on the schema.
fn select_names(sql: &str) -> Option<Vec<String>> {
    let s = sql.trim_start();
    let head = s.get(..7)?;
    if !head[..6].eq_ignore_ascii_case("select") || !head[6..].starts_with(char::is_whitespace) {
        return None;
    }
    let body = &s[6..];
    let parts = top_level(body, true);
    let mut names = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let mut p = part.trim();
        if i == 0 {
            for word in ["distinct", "all"] {
                if p.len() > word.len() && p[..word.len()].eq_ignore_ascii_case(word) && p[word.len()..].starts_with(char::is_whitespace) {
                    p = p[word.len()..].trim_start();
                }
            }
        }
        if p.is_empty() || p == "*" || p.ends_with(".*") {
            return None;
        }
        let words = top_level(p, false);
        let name = match words.as_slice() {
            [.., as_, alias] if as_.eq_ignore_ascii_case("as") => alias,
            [.., before, alias]
                if is_identifier(alias) && !keyword(alias) && !keyword(before) && !before.ends_with(['+', '-', '*', '/', '|', '%', '<', '>', '=', '&']) =>
            {
                alias
            }
            [one] if one.split('.').all(is_identifier) => one.rsplit('.').next().unwrap_or(one),
            _ => p,
        };
        names.push(unquote(name).to_string());
    }
    Some(names)
}

/// Splits at top-level commas (`commas`) or whitespace, outside quotes and
/// parentheses. With commas, stops at a top-level `FROM` or `;`.
fn top_level(text: &str, commas: bool) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut quote, mut start) = (0i32, None::<char>, 0);
    let mut end = text.len();
    let mut prev = ' ';
    for (i, c) in text.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else {
            match c {
                '\'' | '"' | '`' => quote = Some(c),
                '[' => quote = Some(']'),
                '(' => depth += 1,
                ')' => depth -= 1,
                ';' if depth == 0 && commas => {
                    end = i;
                    break;
                }
                ',' if depth == 0 && commas => {
                    parts.push(&text[start..i]);
                    start = i + 1;
                }
                _ if depth == 0
                    && commas
                    && prev.is_whitespace()
                    && text[i..].get(..4).is_some_and(|w| w.eq_ignore_ascii_case("from"))
                    && text[i + 4..].chars().next().is_none_or(char::is_whitespace) =>
                {
                    end = i;
                    break;
                }
                c if depth == 0 && !commas && c.is_whitespace() => {
                    if start < i {
                        parts.push(&text[start..i]);
                    }
                    start = i + c.len_utf8();
                }
                _ => {}
            }
        }
        prev = c;
    }
    if start < end {
        parts.push(&text[start..end]);
    }
    parts
}

/// A column name: a word, or one in `"…"`, `` `…` `` or `[…]` quotes.
fn is_identifier(s: &str) -> bool {
    let quoted = !s.starts_with('\'') && unquote(s).len() + 2 == s.len();
    quoted || (s.starts_with(|c: char| c.is_alphabetic() || c == '_') && s.chars().all(|c| c.is_alphanumeric() || c == '_'))
}

fn keyword(word: &str) -> bool {
    ["and", "or", "not", "is", "null", "like", "in", "between", "case", "when", "then", "else", "end", "collate", "asc", "desc"]
        .iter()
        .any(|k| word.eq_ignore_ascii_case(k))
}

fn unquote(s: &str) -> &str {
    for (a, b) in [('"', '"'), ('`', '`'), ('[', ']'), ('\'', '\'')] {
        if s.len() >= 2 && s.starts_with(a) && s.ends_with(b) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_lists_name_their_columns() {
        let names = |s: &str| select_names(s).map(|v| v.join(","));
        assert_eq!(names("SELECT id, name, email FROM users ORDER BY id").as_deref(), Some("id,name,email"));
        assert_eq!(names("select u.id, count(*) as n, max(x) top FROM t").as_deref(), Some("id,n,top"));
        assert_eq!(names("SELECT DISTINCT \"Name\", a + b FROM t").as_deref(), Some("Name,a + b"));
        assert_eq!(names("SELECT coalesce(a, b), 1;").as_deref(), Some("coalesce(a, b),1"));
        assert_eq!(names("SELECT * FROM t"), None);
        assert_eq!(names("SELECT t.* FROM t"), None);
        assert_eq!(names("INSERT INTO t VALUES (1)"), None);
        assert_eq!(names("SELECT a FROMAGE").as_deref(), Some("FROMAGE"));
        assert_eq!(names("SELECT CASE WHEN x THEN 1 END, y IS NULL FROM t").as_deref(), Some("CASE WHEN x THEN 1 END,y IS NULL"));
    }

    #[test]
    fn rows_have_one_value_per_column() {
        use serde_json::json;
        let key = "spin:sqlite/sqlite#[method]connection.execute-async";
        let mut a = json!({ "ok": [["x"], [{ "values": [] }, { "values": [{ "integer": 1 }, "null", { "text": "t" }, "null"] }], { "ok": null }] });
        sql_answer(key, Some("SELECT id, name FROM users"), &mut a);
        assert_eq!(a, json!({ "ok": [["id", "name"], [{ "values": ["null", "null"] }, { "values": [{ "integer": 1 }, "null"] }], { "ok": null }] }));
        let key = "spin:postgres/postgres#[method]connection.query";
        let mut a = json!({ "ok": { "columns": [], "rows": [[{ "int32": 3 }]] } });
        sql_answer(key, Some("SELECT a, b FROM t"), &mut a);
        assert_eq!(
            a,
            json!({ "ok": { "columns": [{ "name": "a", "data-type": "str" }, { "name": "b", "data-type": "str" }], "rows": [[{ "int32": 3 }, { "int32": 3 }]] } })
        );
        let mut err = json!({ "err": "access-denied" });
        sql_answer(key, Some("SELECT a FROM t"), &mut err);
        assert_eq!(err, json!({ "err": "access-denied" }));
    }

    #[test]
    fn table_parses() {
        let known: BTreeMap<String, FunctionSpec> = toml::from_str(KNOWN).unwrap();
        assert!(known["fermyon:spin/sqlite#[method]connection.execute"].params.contains_key("statement"));
    }
}
