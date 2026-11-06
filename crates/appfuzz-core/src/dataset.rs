//! Deterministic relational host data, isolated per request or owned by a sequence.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ROWS: usize = 10_000;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
    #[serde(default = "default_rows")]
    pub rows: usize,
    pub key: String,
    pub template: Map<String, Value>,
    #[serde(default)]
    pub choices: BTreeMap<String, Vec<Value>>,
    /// Field -> dataset whose primary key it references.
    #[serde(default)]
    pub references: BTreeMap<String, String>,
    /// The field that names the user a record belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Fields anyone may see, also in other users' records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public: Vec<String>,
}
fn default_rows() -> usize {
    4
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub dataset: String,
    /// Record field -> host parameter name (exact equality).
    #[serde(default)]
    pub filter: BTreeMap<String, String>,
    #[serde(default)]
    pub one: bool,
    /// Return one field instead of the entire record.
    #[serde(default)]
    pub select: Option<String>,
    /// Wrap a successful value in e.g. `ok`.
    #[serde(default)]
    pub wrap: Option<String>,
    /// Complete WIT-shaped response for an empty single-record lookup.
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::value::present_json_value")]
    pub missing: Option<Value>,
    /// Record fields the rows are sorted by; ties keep the collection's order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order: Vec<String>,
    /// The platform returns the rows a page at a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<Page>,
}

/// How a paged query reads its window from the host call and answers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    /// Host parameter (path) with the number of rows asked for; `max` without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
    /// Host parameter with the position of the first row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<String>,
    /// Host parameter with a cursor the previous page handed out; empty or
    /// none for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Result field holding the rows; without it the result is the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<String>,
    /// Result field saying where the next page starts (a cursor, or an
    /// offset); none on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    /// The most rows one page returns, whatever was asked.
    pub max: usize,
    /// The platform may return fewer rows than asked while more remain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub short: bool,
    /// The complete response to a cursor the platform never handed out
    /// (default `{ err = "invalid cursor" }`).
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::value::present_json_value")]
    pub invalid: Option<Value>,
}
impl Page {
    pub fn invalid(&self) -> Value {
        self.invalid.clone().unwrap_or_else(|| json!({"err": "invalid cursor"}))
    }
}
pub type World = BTreeMap<String, Vec<Value>>;

pub fn validate(defs: &BTreeMap<String, Dataset>) -> Result<()> {
    for (name, d) in defs {
        if d.rows > MAX_ROWS {
            bail!("dataset {name}: rows exceeds {MAX_ROWS}");
        }
        let key = d.template.get(&d.key).with_context(|| format!("dataset {name}: key absent from template"))?;
        if !key.is_string() && key.as_u64().is_none() {
            bail!("dataset {name}: key template must be a string or unsigned integer");
        }
        for (field, values) in &d.choices {
            if !d.template.contains_key(field) || values.is_empty() || *field == d.key || d.references.contains_key(field) {
                bail!("dataset {name}: invalid choices for {field}");
            }
        }
        for (field, target) in &d.references {
            if *field == d.key || !d.template.contains_key(field) || !defs.contains_key(target) {
                bail!("dataset {name}: invalid reference {field} -> {target}");
            }
        }
        if d.owner.as_ref().is_some_and(|f| *f == d.key || !d.template.contains_key(f)) {
            bail!("dataset {name}: owner must name a record field other than the key");
        }
        if !d.public.is_empty() && d.owner.is_none() {
            bail!("dataset {name}: public fields need an owner field");
        }
        if let Some(f) = d.public.iter().find(|f| !d.template.contains_key(*f)) {
            bail!("dataset {name}: public names the unknown field {f}");
        }
    }
    build(defs, &BTreeMap::new(), 0)?;
    Ok(())
}

/// The users records belong to: the keys of the dataset the first owner
/// field references, else that field's choices or template value.
pub fn tenants(defs: &BTreeMap<String, Dataset>, world: &World) -> Vec<Value> {
    defs.values()
        .find_map(|d| {
            let owner = d.owner.as_ref()?;
            Some(match (d.references.get(owner), d.choices.get(owner)) {
                (Some(target), _) => world.get(target).into_iter().flatten().map(|p| p[&defs[target].key].clone()).collect(),
                (None, Some(choices)) => choices.clone(),
                (None, None) => vec![d.template[owner].clone()],
            })
        })
        .unwrap_or_default()
}

/// Whether every reference names an existing record.
pub fn intact(defs: &BTreeMap<String, Dataset>, tables: &World) -> bool {
    defs.iter().all(|(name, d)| {
        d.references.iter().all(|(field, target)| {
            let keys = keys_of(defs, tables, target);
            tables.get(name).is_none_or(|rows| rows.iter().all(|r| r.get(field).is_some_and(|v| keys.contains(&v.to_string()))))
        })
    })
}
fn keys_of(defs: &BTreeMap<String, Dataset>, tables: &World, name: &str) -> BTreeSet<String> {
    tables.get(name).into_iter().flatten().filter_map(|r| r.get(&defs[name].key)).map(Value::to_string).collect()
}

/// Keys of records an edit adds start above this, so records a request
/// creates get the same keys with and without the edit.
pub const ADDED_KEYS: u64 = 1_000_000;

/// A change to the generated world before a run, to rows and values the
/// platform could hold. Held in the run's plan, so a run with edits
/// replays, caches and shrinks like any other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    /// Remove these records and the records that reference them.
    Drop { dataset: String, keys: Vec<Value> },
    /// Give these fields of these records another value: the next of the
    /// field's choices, the next parent for a reference, else the value of
    /// the next listed record.
    Rotate { dataset: String, keys: Vec<Value>, fields: Vec<String> },
    /// Add records made like generated ones, with `set` fields fixed.
    Add {
        dataset: String,
        rows: usize,
        #[serde(default, skip_serializing_if = "Map::is_empty")]
        set: Map<String, Value>,
    },
}
impl Edit {
    pub fn dataset(&self) -> &str {
        match self {
            Edit::Drop { dataset, .. } | Edit::Rotate { dataset, .. } | Edit::Add { dataset, .. } => dataset,
        }
    }
}

/// Apply edits in order. A key no record has changes nothing, and so does
/// an edit that would leave a reference without its record.
pub fn apply(defs: &BTreeMap<String, Dataset>, state: &mut State, edits: &[Edit], seed: u64) -> Result<()> {
    let mut added: BTreeMap<&str, u64> = BTreeMap::new();
    for edit in edits {
        let name = edit.dataset();
        let d = defs.get(name).with_context(|| format!("dataset edit names the unknown dataset {name}"))?;
        let fields: Vec<&String> = match edit {
            Edit::Rotate { fields, .. } => fields.iter().collect(),
            Edit::Add { set, .. } => set.keys().collect(),
            Edit::Drop { .. } => vec![],
        };
        if let Some(f) = fields.iter().find(|f| ***f == d.key || !d.template.contains_key(**f)) {
            bail!("dataset edit on {name}: {f} is not a record field it may change");
        }
        let before = state.tables.clone();
        let rows = state.tables.get_mut(name).context("missing dataset")?;
        match edit {
            Edit::Drop { keys, .. } => {
                rows.retain(|r| !keys.contains(&r[&d.key]));
                cascade(defs, &mut state.tables);
            }
            Edit::Rotate { keys, fields, .. } => {
                let at: Vec<usize> = rows.iter().enumerate().filter(|(_, r)| keys.contains(&r[&d.key])).map(|(i, _)| i).collect();
                for f in fields {
                    let parents = d.references.get(f).map(|t| before[t].iter().map(|p| p[&defs[t].key].clone()).collect::<Vec<_>>());
                    let options = d.choices.get(f).cloned().or(parents);
                    let old: Vec<Value> = at.iter().map(|&i| rows[i][f.as_str()].clone()).collect();
                    for (j, &i) in at.iter().enumerate() {
                        rows[i][f.as_str()] = match &options {
                            Some(o) if o.len() > 1 => o[o.iter().position(|v| *v == old[j]).map_or(0, |p| (p + 1) % o.len())].clone(),
                            Some(_) => old[j].clone(),
                            None => old[(j + 1) % old.len()].clone(),
                        };
                    }
                }
            }
            Edit::Add { rows: n, set, .. } => {
                if rows.len().saturating_add(*n) > MAX_ROWS {
                    bail!("dataset edit on {name}: more than {MAX_ROWS} rows");
                }
                if d.references.values().any(|t| before[t].is_empty()) {
                    continue;
                }
                let count = added.entry(name).or_default();
                for _ in 0..*n {
                    *count += 1;
                    let k = ADDED_KEYS + *count;
                    let mut row = d.template.clone();
                    row.insert(d.key.clone(), if let Some(prefix) = d.template[&d.key].as_str() { json!(format!("{prefix}_{k}")) } else { json!(k) });
                    for (field, values) in &d.choices {
                        row.insert(field.clone(), values[index(seed, name, field, k as usize, values.len())].clone());
                    }
                    for (field, target) in &d.references {
                        let parent = &before[target];
                        row.insert(field.clone(), parent[index(seed, name, field, k as usize, parent.len())][&defs[target].key].clone());
                    }
                    row.extend(set.clone());
                    rows.push(Value::Object(row));
                }
            }
        }
        if !intact(defs, &state.tables) {
            state.tables = before;
        }
    }
    Ok(())
}

/// Remove records whose reference lost its record, until none is left.
fn cascade(defs: &BTreeMap<String, Dataset>, tables: &mut World) {
    loop {
        let mut changed = false;
        for (name, d) in defs {
            for (field, target) in &d.references {
                let keys = keys_of(defs, tables, target);
                let Some(rows) = tables.get_mut(name) else { continue };
                let n = rows.len();
                rows.retain(|r| r.get(field).is_some_and(|v| keys.contains(&v.to_string())));
                changed |= rows.len() != n;
            }
        }
        if !changed {
            return;
        }
    }
}

pub fn build(defs: &BTreeMap<String, Dataset>, sizes: &BTreeMap<String, usize>, seed: u64) -> Result<World> {
    for (name, n) in sizes {
        if !defs.contains_key(name) || *n > MAX_ROWS {
            bail!("invalid dataset size {name}={n} (maximum {MAX_ROWS})");
        }
    }
    let mut world = World::new();
    let mut pending: BTreeSet<_> = defs.keys().cloned().collect();
    while !pending.is_empty() {
        let ready: Vec<_> = pending.iter().filter(|n| defs[*n].references.values().all(|r| world.contains_key(r))).cloned().collect();
        if ready.is_empty() {
            bail!("dataset references contain a cycle or unknown dataset");
        }
        for name in ready {
            let d = &defs[&name];
            let n = sizes.get(&name).copied().unwrap_or(d.rows);
            if n > MAX_ROWS {
                bail!("dataset {name}: rows exceeds {MAX_ROWS}");
            }
            let empty_parent = d.references.values().any(|r| world[r].is_empty());
            let mut rows = Vec::new();
            for i in 0..if empty_parent { 0 } else { n } {
                let mut row = d.template.clone();
                let key = d.template.get(&d.key).context("dataset key absent")?;
                row.insert(d.key.clone(), if let Some(prefix) = key.as_str() { json!(format!("{prefix}_{}", i + 1)) } else { json!(i + 1) });
                for (field, values) in &d.choices {
                    row.insert(field.clone(), values[index(seed, &name, field, i, values.len())].clone());
                }
                for (field, target) in &d.references {
                    let parent = &world[target];
                    row.insert(field.clone(), parent[index(seed, &name, field, i, parent.len())][&defs[target].key].clone());
                }
                rows.push(Value::Object(row));
            }
            world.insert(name.clone(), rows);
            pending.remove(&name);
        }
    }
    Ok(world)
}
/// An opaque cursor for the page starting at `start`: a guest can't make one
/// up or step it forward, only pass on what the platform handed out.
pub fn encode_cursor(dataset: &str, start: usize) -> String {
    let check = blake3::hash(format!("cursor:{dataset}:{start}").as_bytes());
    format!("{}{start:x}", &check.to_hex()[..8])
}
pub fn decode_cursor(dataset: &str, token: &str) -> Option<usize> {
    let start = usize::from_str_radix(token.get(8..)?, 16).ok()?;
    (encode_cursor(dataset, start) == token).then_some(start)
}
fn page_arg<'a>(args: &'a [(String, Value)], path: &str) -> Option<&'a Value> {
    let (root, rest) = path.split_once('.').unwrap_or((path, ""));
    crate::harness::field(&args.iter().find(|(k, _)| k == root)?.1, rest).filter(|v| !v.is_null())
}
fn index(seed: u64, dataset: &str, field: &str, row: usize, len: usize) -> usize {
    let hash = blake3::hash(format!("{seed}:{dataset}:{field}:{row}").as_bytes());
    (u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap()) % len as u64) as usize
}
impl Query {
    pub fn validate(&self, defs: &BTreeMap<String, Dataset>) -> Result<()> {
        let d = defs.get(&self.dataset).context("query names an unknown dataset")?;
        if self.filter.keys().any(|k| !d.template.contains_key(k)) {
            bail!("query filter names an unknown record field");
        }
        if self.select.as_ref().is_some_and(|f| !d.template.contains_key(f)) {
            bail!("query selects an unknown record field");
        }
        if !self.one && self.missing.is_some() {
            bail!("query missing response requires one = true");
        }
        if self.wrap.as_ref().is_some_and(|w| w != "ok") {
            bail!("query wrap must be 'ok'");
        }
        if self.order.iter().any(|f| !d.template.contains_key(f)) {
            bail!("query orders by an unknown record field");
        }
        if let Some(p) = &self.page {
            if self.one {
                bail!("a paged query returns a list, so it cannot have one = true");
            }
            if p.max == 0 || p.max > MAX_ROWS {
                bail!("query page.max must be between 1 and {MAX_ROWS}");
            }
            if p.offset.is_some() && p.cursor.is_some() {
                bail!("query page takes an offset or a cursor, not both");
            }
            if p.next.is_some() && p.items.is_none() {
                bail!("query page.next needs page.items: the rows and the next page share a record");
            }
            if p.cursor.is_some() && p.next.is_none() {
                bail!("query page.cursor needs page.next, which hands out the cursors");
            }
            if p.invalid.is_some() && p.cursor.is_none() {
                bail!("query page.invalid answers a made-up cursor, so it needs page.cursor");
            }
        }
        Ok(())
    }
    /// Host parameters a query reads, as `(role, path)`.
    pub fn parameters(&self) -> Vec<(&str, &str)> {
        let page = self.page.iter().flat_map(|p| [("page.limit", &p.limit), ("page.offset", &p.offset), ("page.cursor", &p.cursor)]);
        self.filter.values().map(|p| ("filter", p.as_str())).chain(page.filter_map(|(role, p)| Some((role, p.as_deref()?)))).collect()
    }
    /// The query's answer. `page_size` caps a page below what was asked,
    /// where the platform says pages may be short.
    pub fn resolve(&self, world: &World, args: &[(String, Value)], page_size: Option<usize>) -> Result<Value> {
        for param in self.filter.values() {
            if !args.iter().any(|(k, _)| k == param) {
                bail!("dataset query: unknown parameter {param}");
            }
        }
        let mut rows: Vec<&Value> = world
            .get(&self.dataset)
            .context("unknown dataset")?
            .iter()
            .filter(|r| self.filter.iter().all(|(field, param)| args.iter().find(|(k, _)| k == param).is_some_and(|(_, v)| r.get(field) == Some(v))))
            .collect();
        if !self.order.is_empty() {
            rows.sort_by(|a, b| self.order.iter().map(|f| crate::value::cmp_json(&a[f], &b[f])).find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal));
        }
        let select = |r: &&Value| self.select.as_ref().map_or_else(|| (*r).clone(), |f| r[f].clone());
        if let Some(page) = &self.page {
            let arg = |path: &Option<String>| path.as_deref().and_then(|p| page_arg(args, p));
            let start = match (arg(&page.offset), arg(&page.cursor).and_then(Value::as_str).filter(|c| !c.is_empty())) {
                (Some(offset), _) => offset.as_u64().map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX)),
                (None, Some(token)) => match decode_cursor(&self.dataset, token) {
                    Some(start) => start,
                    None => return Ok(page.invalid()),
                },
                (None, None) => 0,
            };
            let asked = arg(&page.limit).and_then(Value::as_u64).map_or(page.max, |n| usize::try_from(n).unwrap_or(usize::MAX).min(page.max));
            let size = page_size.map_or(asked, |s| s.min(asked));
            let start = start.min(rows.len());
            let end = start.saturating_add(size).min(rows.len());
            let items = Value::Array(rows[start..end].iter().map(select).collect());
            let value = match &page.items {
                None => items,
                Some(field) => {
                    let mut record = Map::from_iter([(field.clone(), items)]);
                    if let Some(next) = &page.next {
                        let at = if end == rows.len() {
                            Value::Null
                        } else if page.cursor.is_some() {
                            json!(encode_cursor(&self.dataset, end))
                        } else {
                            json!(end)
                        };
                        record.insert(next.clone(), at);
                    }
                    Value::Object(record)
                }
            };
            return Ok(if let Some(w) = &self.wrap { json!({w: value}) } else { value });
        }
        let rows: Vec<Value> = rows.iter().map(select).collect();
        let value = if self.one {
            if rows.is_empty()
                && let Some(missing) = &self.missing
            {
                return Ok(missing.clone());
            }
            rows.into_iter().next().unwrap_or(Value::Null)
        } else {
            Value::Array(rows)
        };
        Ok(if let Some(w) = &self.wrap { json!({w: value}) } else { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definitions() -> BTreeMap<String, Dataset> {
        serde_json::from_value(json!({
            "users": {"rows": 3, "key":"id", "template":{"id":"user", "name":"Alice"}, "choices":{"name":["Alice", "Zoë", "<b>untrusted</b>"]}},
            "orders": {"rows":20, "key":"id", "template":{"id":1,"owner":"", "day":"2026-11-02"}, "references":{"owner":"users"}}
        }))
        .unwrap()
    }
    #[test]
    fn deterministic_worlds_preserve_unique_keys_and_references_when_resized() {
        let defs = definitions();
        validate(&defs).unwrap();
        for seed in 0..30 {
            for n in [0, 1, 2, 12] {
                let sizes = BTreeMap::from([("users".into(), n)]);
                let w = build(&defs, &sizes, seed).unwrap();
                assert_eq!(w, build(&defs, &sizes, seed).unwrap());
                let ids: BTreeSet<_> = w["users"].iter().map(|r| r["id"].as_str().unwrap()).collect();
                assert_eq!(ids.len(), n);
                assert!(w["orders"].iter().all(|o| ids.contains(o["owner"].as_str().unwrap())));
                if n == 0 {
                    assert!(w["orders"].is_empty());
                }
            }
        }
        assert_ne!(build(&defs, &BTreeMap::new(), 0).unwrap(), build(&defs, &BTreeMap::new(), 1).unwrap());
    }
    #[test]
    fn queries_filter_and_return_the_same_records() {
        let w = build(&definitions(), &BTreeMap::new(), 7).unwrap();
        let q: Query = serde_json::from_value(json!({"dataset":"orders", "filter":{"owner":"user"},"wrap":"ok"})).unwrap();
        let result = q.resolve(&w, &[("user".into(), json!("user_1"))], None).unwrap();
        assert!(result["ok"].as_array().unwrap().iter().all(|r| r["owner"] == "user_1"));
        assert!(q.resolve(&w, &[], None).is_err());
        let q: Query = serde_json::from_value(json!({"dataset":"orders","filter":{"id":"id"}, "one":true,"missing":{"err":"missing"},"wrap":"ok"})).unwrap();
        assert_eq!(q.resolve(&w, &[("id".into(), json!(1))], None).unwrap(), json!({"ok":w["orders"][0]}));
        assert_eq!(q.resolve(&w, &[("id".into(), json!(999))], None).unwrap(), json!({"err":"missing"}));
    }
    #[test]
    fn invalid_models_and_unbounded_sizes_are_rejected() {
        let mut defs = definitions();
        defs.get_mut("users").unwrap().references.insert("name".into(), "orders".into());
        assert!(validate(&defs).is_err());
        assert!(build(&definitions(), &BTreeMap::from([("users".into(), MAX_ROWS + 1)]), 1).is_err());
        assert!(build(&definitions(), &BTreeMap::from([("typo".into(), 1)]), 1).is_err());
        let mut defs = definitions();
        defs.get_mut("users").unwrap().choices.insert("id".into(), vec![json!("duplicate")]);
        assert!(validate(&defs).is_err());
    }
}

/// State is owned by one request sequence. Components themselves are recreated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub tables: World,
    pub next: BTreeMap<String, u64>,
}
impl State {
    pub fn new(tables: World) -> Self {
        let next = tables.iter().map(|(k, rows)| (k.clone(), rows.len() as u64 + 1)).collect();
        Self { tables, next }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Update,
    Delete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub dataset: String,
    pub operation: Operation,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub filter: BTreeMap<String, String>,
    /// Complete WIT-shaped success response. In a create, the string `"$key"`
    /// stands for the new record's key and `"$row"` for the whole record.
    pub response: Value,
    #[serde(default = "rejected")]
    pub reject: Value,
}
fn rejected() -> Value {
    json!({"err":"dataset constraint violation"})
}
fn parameter<'a>(args: &'a [(String, Value)], path: &str) -> Result<&'a Value> {
    let (root, rest) = path.split_once('.').unwrap_or((path, ""));
    let value = args.iter().find(|(k, _)| k == root).map(|(_, v)| v).context("unknown mutation parameter")?;
    crate::harness::field(value, rest).context("mutation parameter path is absent")
}
impl Mutation {
    pub fn validate(&self, defs: &BTreeMap<String, Dataset>) -> Result<()> {
        let d = defs.get(&self.dataset).context("mutation names an unknown dataset")?;
        if self.fields.keys().chain(self.filter.keys()).any(|f| !d.template.contains_key(f)) || self.fields.contains_key(&d.key) {
            bail!("mutation names an unknown field or assigns the primary key");
        }
        match self.operation {
            Operation::Create if !self.filter.is_empty() => bail!("create cannot have a filter"),
            Operation::Update | Operation::Delete if self.filter.is_empty() => bail!("update/delete require a filter"),
            Operation::Delete if !self.fields.is_empty() => bail!("delete cannot assign fields"),
            _ => {}
        }
        if !matches!(self.operation, Operation::Create) && (placeholders(&self.response) || placeholders(&self.reject)) {
            bail!("only a create response can name \"$key\" or \"$row\"");
        }
        if placeholders(&self.reject) {
            bail!("a rejection creates no record, so it cannot name \"$key\" or \"$row\"");
        }
        Ok(())
    }
    /// The success response with the template's key and record in place of
    /// `"$key"` and `"$row"`, for checking it against the WIT type.
    pub fn sample_response(&self, defs: &BTreeMap<String, Dataset>) -> Result<Value> {
        let d = defs.get(&self.dataset).context("mutation names an unknown dataset")?;
        let row = Value::Object(d.template.clone());
        Ok(fill(&self.response, &row[&d.key], &row))
    }
    /// Prepare an atomic change and the rows it changes. The harness validates
    /// its WIT result before commit.
    pub fn prepare(&self, defs: &BTreeMap<String, Dataset>, state: &State, args: &[(String, Value)]) -> Result<(State, Value, Vec<RowChange>)> {
        let mut next = state.clone();
        let d = &defs[&self.dataset];
        let fields: Map<String, Value> = self.fields.iter().map(|(k, p)| Ok((k.clone(), parameter(args, p)?.clone()))).collect::<Result<_>>()?;
        let filters: Map<String, Value> = self.filter.iter().map(|(k, p)| Ok((k.clone(), parameter(args, p)?.clone()))).collect::<Result<_>>()?;
        let rows = next.tables.get_mut(&self.dataset).context("missing mutation dataset")?;
        let matches = |r: &Value| filters.iter().all(|(k, v)| r.get(k) == Some(v));
        let change = |before: Option<&Value>, after: Option<&Value>| RowChange {
            dataset: self.dataset.clone(),
            key: before.or(after).map(|r| r[&d.key].clone()).unwrap_or_default(),
            before: before.cloned(),
            after: after.cloned(),
        };
        let mut changes = Vec::new();
        let mut response = self.response.clone();
        match self.operation {
            Operation::Create => {
                if rows.len() >= MAX_ROWS {
                    return Ok((state.clone(), self.reject.clone(), vec![]));
                }
                let n = next.next.get_mut(&self.dataset).context("missing dataset counter")?;
                let mut row = d.template.clone();
                row.extend(fields);
                row.insert(d.key.clone(), if let Some(prefix) = d.template[&d.key].as_str() { json!(format!("{prefix}_{n}")) } else { json!(*n) });
                *n = n.checked_add(1).context("dataset key overflow")?;
                let row = Value::Object(row);
                response = fill(&response, &row[&d.key], &row);
                changes.push(change(None, Some(&row)));
                rows.push(row);
            }
            Operation::Update => {
                for row in rows.iter_mut().filter(|r| matches(r)) {
                    let before = row.clone();
                    row.as_object_mut().context("dataset row must be a record")?.extend(fields.clone());
                    if *row != before {
                        changes.push(change(Some(&before), Some(row)));
                    }
                }
            }
            Operation::Delete => {
                changes.extend(rows.iter().filter(|r| matches(r)).map(|r| change(Some(r), None)));
                rows.retain(|r| !matches(r));
            }
        }
        // Deleting a referenced parent is restricted; writes cannot create dangling references.
        if !intact(defs, &next.tables) {
            return Ok((state.clone(), self.reject.clone(), vec![]));
        }
        Ok((next, response, changes))
    }
}

pub use crate::record::RowChange;

fn placeholders(v: &Value) -> bool {
    match v {
        Value::String(s) => s == "$key" || s == "$row",
        Value::Array(a) => a.iter().any(placeholders),
        Value::Object(o) => o.values().any(placeholders),
        _ => false,
    }
}

/// `v` with `"$key"` and `"$row"` replaced by the created record's key and record.
fn fill(v: &Value, key: &Value, row: &Value) -> Value {
    match v {
        Value::String(s) if s == "$key" => key.clone(),
        Value::String(s) if s == "$row" => row.clone(),
        Value::Array(a) => Value::Array(a.iter().map(|x| fill(x, key, row)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), fill(x, key, row))).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::*;
    #[test]
    fn mutations_are_atomic_keep_references_and_never_reuse_deleted_keys() {
        let defs: BTreeMap<String, Dataset> = serde_json::from_value(json!({
            "users":{"rows":1,"key":"id","template":{"id":1,"name":"Alice"}},
            "orders":{"rows":0,"key":"id","template":{"id":1,"owner":1},"references":{"owner":"users"}}
        }))
        .unwrap();
        let mut state = State::new(build(&defs, &BTreeMap::new(), 1).unwrap());
        let create: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"create","fields":{"owner":"who"},"response":{"ok":true}})).unwrap();
        create.validate(&defs).unwrap();
        let (rejected, response, changes) = create.prepare(&defs, &state, &[("who".into(), json!(999))]).unwrap();
        assert_eq!(state, rejected);
        assert!(response.get("err").is_some());
        assert!(changes.is_empty(), "a rejected write changes nothing");
        state = create.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap().0;
        let delete: Mutation = serde_json::from_value(json!({"dataset":"users","operation":"delete","filter":{"id":"who"},"response":{"ok":true}})).unwrap();
        let (rejected, response, changes) = delete.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap();
        assert_eq!(state, rejected);
        assert!(response.get("err").is_some());
        assert!(changes.is_empty());
        let mut delete = delete;
        delete.dataset = "orders".into();
        state = delete.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap().0;
        state = create.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap().0;
        assert_eq!(state.tables["orders"][0]["id"], 2);
        let update: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"update","filter":{"id":"id"},"fields":{"owner":"who"},"response":{"ok":true}}))
                .unwrap();
        let (rejected, _, _) = update.prepare(&defs, &state, &[("id".into(), json!(2)), ("who".into(), json!(999))]).unwrap();
        assert_eq!(state, rejected);
    }

    #[test]
    fn mutations_report_the_rows_they_change_and_creates_can_answer_with_the_new_key() {
        let defs: BTreeMap<String, Dataset> = serde_json::from_value(json!({
            "orders":{"rows":2,"key":"id","template":{"id":"order","status":"draft"}}
        }))
        .unwrap();
        let state = State::new(build(&defs, &BTreeMap::new(), 1).unwrap());
        let create: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"create","fields":{"status":"s"},"response":{"ok":{"id":"$key","row":"$row"}}}))
                .unwrap();
        create.validate(&defs).unwrap();
        assert_eq!(create.sample_response(&defs).unwrap(), json!({"ok":{"id":"order","row":{"id":"order","status":"draft"}}}));
        let (state, response, changes) = create.prepare(&defs, &state, &[("s".into(), json!("paid"))]).unwrap();
        assert_eq!(response, json!({"ok":{"id":"order_3","row":{"id":"order_3","status":"paid"}}}));
        assert_eq!(
            changes,
            vec![RowChange { dataset: "orders".into(), key: json!("order_3"), before: None, after: Some(json!({"id":"order_3","status":"paid"})) }]
        );

        let update: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"update","filter":{"id":"id"},"fields":{"status":"s"},"response":{"ok":true}}))
                .unwrap();
        let (_, _, changes) = update.prepare(&defs, &state, &[("id".into(), json!("order_1")), ("s".into(), json!("paid"))]).unwrap();
        assert_eq!(changes[0].before, Some(json!({"id":"order_1","status":"draft"})));
        assert_eq!(changes[0].after, Some(json!({"id":"order_1","status":"paid"})));
        let (_, _, unchanged) = update.prepare(&defs, &state, &[("id".into(), json!("order_1")), ("s".into(), json!("draft"))]).unwrap();
        assert!(unchanged.is_empty(), "writing the same value changes no row");

        let delete: Mutation = serde_json::from_value(json!({"dataset":"orders","operation":"delete","filter":{"id":"id"},"response":{"ok":true}})).unwrap();
        let (_, _, changes) = delete.prepare(&defs, &state, &[("id".into(), json!("order_2"))]).unwrap();
        assert_eq!((changes[0].key.clone(), changes[0].after.clone()), (json!("order_2"), None));

        let keyed_update: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"update","filter":{"id":"id"},"response":{"ok":"$key"}})).unwrap();
        assert!(keyed_update.validate(&defs).is_err(), "only a create has a new key");
        let keyed_reject: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"create","response":{"ok":true},"reject":{"err":"$key"}})).unwrap();
        assert!(keyed_reject.validate(&defs).is_err());
    }
}

#[cfg(test)]
mod world_tests {
    use super::*;
    fn defs() -> BTreeMap<String, Dataset> {
        serde_json::from_value(json!({
            "users": {"rows": 2, "key": "id", "template": {"id": "user", "name": "A"}},
            "customers": {"rows": 11, "key": "id", "template": {"id": 1, "owner": "", "name": "C", "balance": 0},
                "references": {"owner": "users"}, "owner": "owner", "public": ["name"],
                "choices": {"name": ["Ada", "Bo", "Cy"], "balance": [10, 20, 30]}},
            "orders": {"rows": 6, "key": "id", "template": {"id": 1, "customer": 1}, "references": {"customer": "customers"}}
        }))
        .unwrap()
    }
    fn query(page: Value) -> Query {
        serde_json::from_value(json!({"dataset": "customers", "order": ["name"], "select": "id", "page": page, "wrap": "ok"})).unwrap()
    }

    #[test]
    fn offset_pages_cover_the_ordered_rows_once() {
        let defs = defs();
        validate(&defs).unwrap();
        let world = build(&defs, &BTreeMap::new(), 3).unwrap();
        let q = query(json!({"limit": "limit", "offset": "offset", "items": "items", "next": "next", "max": 4}));
        q.validate(&defs).unwrap();
        let mut seen = Vec::new();
        let mut offset = json!(0);
        while !offset.is_null() {
            let page = q.resolve(&world, &[("limit".into(), json!(10)), ("offset".into(), offset.clone())], None).unwrap();
            let items = page["ok"]["items"].as_array().unwrap();
            assert!(items.len() <= 4, "max caps what was asked");
            seen.extend(items.iter().cloned());
            offset = page["ok"]["next"].clone();
        }
        let mut by_name: Vec<&Value> = world["customers"].iter().collect();
        by_name.sort_by(|a, b| crate::value::cmp_json(&a["name"], &b["name"]));
        assert_eq!(seen, by_name.iter().map(|r| r["id"].clone()).collect::<Vec<_>>(), "ordered by name, ties by creation");
        // Short pages, where the platform allows them.
        let page = q.resolve(&world, &[("limit".into(), json!(3)), ("offset".into(), json!(0))], Some(2)).unwrap();
        assert_eq!(page["ok"]["items"].as_array().unwrap().len(), 2);
        assert_eq!(page["ok"]["next"], 2);
    }

    #[test]
    fn cursors_are_handed_out_and_made_up_ones_are_refused() {
        let defs = defs();
        let world = build(&defs, &BTreeMap::new(), 3).unwrap();
        let q = query(json!({"cursor": "after", "items": "items", "next": "next", "max": 5, "invalid": {"err": "bad cursor"}}));
        q.validate(&defs).unwrap();
        let first = q.resolve(&world, &[("after".into(), Value::Null)], None).unwrap();
        let token = first["ok"]["next"].as_str().unwrap().to_string();
        assert_eq!(decode_cursor("customers", &token), Some(5));
        let second = q.resolve(&world, &[("after".into(), json!(token))], None).unwrap();
        assert_eq!(second["ok"]["items"].as_array().unwrap().len(), 5);
        let last = q.resolve(&world, &[("after".into(), second["ok"]["next"].clone())], None).unwrap();
        assert_eq!((last["ok"]["items"].as_array().unwrap().len(), &last["ok"]["next"]), (1, &Value::Null));
        for forged in ["5", "00000000a", &encode_cursor("orders", 5)] {
            assert_eq!(q.resolve(&world, &[("after".into(), json!(forged))], None).unwrap(), json!({"err": "bad cursor"}), "{forged}");
        }
    }

    #[test]
    fn invalid_pages_and_owners_are_refused() {
        let defs = defs();
        for page in [
            json!({"max": 0}),
            json!({"max": 2, "offset": "o", "cursor": "c", "items": "items", "next": "next"}),
            json!({"max": 2, "next": "next"}),
            json!({"max": 2, "cursor": "c", "items": "items"}),
            json!({"max": 2, "invalid": {"err": "x"}}),
        ] {
            assert!(query(page.clone()).validate(&defs).is_err(), "{page}");
        }
        let mut one = query(json!({"max": 2}));
        one.one = true;
        assert!(one.validate(&defs).is_err());
        let mut bad = defs.clone();
        bad.get_mut("customers").unwrap().owner = Some("id".into());
        assert!(validate(&bad).is_err());
        let mut bad = defs.clone();
        bad.get_mut("orders").unwrap().public = vec!["customer".into()];
        assert!(validate(&bad).is_err(), "public without an owner");
    }

    #[test]
    fn edits_drop_rotate_and_add_only_what_the_platform_could_hold() {
        let defs = defs();
        let fresh = State::new(build(&defs, &BTreeMap::new(), 3).unwrap());
        let edit = |edits: Value| {
            let mut state = fresh.clone();
            apply(&defs, &mut state, &serde_json::from_value::<Vec<Edit>>(edits).unwrap(), 3).map(|()| state)
        };
        // Dropping a customer drops its orders too; the key counters stay.
        let first = fresh.tables["orders"][0]["customer"].clone();
        let dropped = edit(json!([{"drop": {"dataset": "customers", "keys": [first, 999]}}])).unwrap();
        assert_eq!(dropped.tables["customers"].len(), 10);
        assert!(dropped.tables["orders"].iter().all(|o| o["customer"] != first));
        assert!(intact(&defs, &dropped.tables));
        assert_eq!(dropped.next, fresh.next);
        // Rotating takes the next choice, the next parent, or the next row's value.
        let rotated = edit(json!([{"rotate": {"dataset": "customers", "keys": [1, 2], "fields": ["balance", "owner"]}}])).unwrap();
        for i in 0..2 {
            let (was, now) = (&fresh.tables["customers"][i], &rotated.tables["customers"][i]);
            assert_ne!(was["balance"], now["balance"]);
            assert_ne!(was["owner"], now["owner"]);
            assert_eq!(was["name"], now["name"]);
        }
        let plain = edit(json!([{"rotate": {"dataset": "orders", "keys": [1, 2], "fields": ["customer"]}}])).unwrap();
        assert!(intact(&defs, &plain.tables));
        // Added rows take reserved keys, so a request's own records keep theirs.
        let added =
            edit(json!([{"add": {"dataset": "customers", "rows": 2, "set": {"owner": "user_2"}}}, {"add": {"dataset": "customers", "rows": 1}}])).unwrap();
        let keys: Vec<_> = added.tables["customers"][11..].iter().map(|r| r["id"].clone()).collect();
        assert_eq!(keys, [json!(ADDED_KEYS + 1), json!(ADDED_KEYS + 2), json!(ADDED_KEYS + 3)]);
        assert_eq!(added.tables["customers"][11]["owner"], "user_2");
        assert_eq!(added.next, fresh.next);
        // An edit that would leave a dangling reference changes nothing.
        assert_eq!(edit(json!([{"add": {"dataset": "customers", "rows": 1, "set": {"owner": "nobody"}}}])).unwrap(), fresh);
        assert!(edit(json!([{"rotate": {"dataset": "customers", "keys": [1], "fields": ["id"]}}])).is_err());
        assert!(edit(json!([{"drop": {"dataset": "typo", "keys": [1]}}])).is_err());
        assert!(serde_json::from_value::<Edit>(json!({"drop": {"dataset": "users", "keys": [], "extra": 1}})).is_err());
    }

    #[test]
    fn records_belong_to_the_users_their_owner_field_names() {
        let defs = defs();
        let world = build(&defs, &BTreeMap::new(), 3).unwrap();
        assert_eq!(tenants(&defs, &world), vec![json!("user_1"), json!("user_2")]);
        let mut by_choice = defs.clone();
        let customers = by_choice.get_mut("customers").unwrap();
        customers.references.clear();
        customers.choices.insert("owner".into(), vec![json!("alice"), json!("bob")]);
        assert_eq!(tenants(&by_choice, &world), vec![json!("alice"), json!("bob")]);
        let mut unowned = defs;
        unowned.values_mut().for_each(|d| d.owner = None);
        assert!(tenants(&unowned, &world).is_empty());
    }
}
