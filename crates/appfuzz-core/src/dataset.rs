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
    }
    build(defs, &BTreeMap::new(), 0)?;
    Ok(())
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
        Ok(())
    }
    pub fn resolve(&self, world: &World, args: &[(String, Value)]) -> Result<Value> {
        for param in self.filter.values() {
            if !args.iter().any(|(k, _)| k == param) {
                bail!("dataset query: unknown parameter {param}");
            }
        }
        let rows: Vec<_> = world
            .get(&self.dataset)
            .context("unknown dataset")?
            .iter()
            .filter(|r| self.filter.iter().all(|(field, param)| args.iter().find(|(k, _)| k == param).is_some_and(|(_, v)| r.get(field) == Some(v))))
            .map(|r| self.select.as_ref().map_or_else(|| r.clone(), |f| r[f].clone()))
            .collect();
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
        let result = q.resolve(&w, &[("user".into(), json!("user_1"))]).unwrap();
        assert!(result["ok"].as_array().unwrap().iter().all(|r| r["owner"] == "user_1"));
        assert!(q.resolve(&w, &[]).is_err());
        let q: Query = serde_json::from_value(json!({"dataset":"orders","filter":{"id":"id"}, "one":true,"missing":{"err":"missing"},"wrap":"ok"})).unwrap();
        assert_eq!(q.resolve(&w, &[("id".into(), json!(1))]).unwrap(), json!({"ok":w["orders"][0]}));
        assert_eq!(q.resolve(&w, &[("id".into(), json!(999))]).unwrap(), json!({"err":"missing"}));
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
        for (name, definition) in defs {
            for (field, target) in &definition.references {
                if next.tables[name].iter().any(|r| !next.tables[target].iter().any(|p| p.get(&defs[target].key) == r.get(field))) {
                    return Ok((state.clone(), self.reject.clone(), vec![]));
                }
            }
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
