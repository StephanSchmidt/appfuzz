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
    #[serde(default)]
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
    /// Complete WIT-shaped success response.
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
        Ok(())
    }
    /// Prepare an atomic change. The harness validates its WIT result before commit.
    pub fn prepare(&self, defs: &BTreeMap<String, Dataset>, state: &State, args: &[(String, Value)]) -> Result<(State, Value)> {
        let mut next = state.clone();
        let d = &defs[&self.dataset];
        let fields: Map<String, Value> = self.fields.iter().map(|(k, p)| Ok((k.clone(), parameter(args, p)?.clone()))).collect::<Result<_>>()?;
        let filters: Map<String, Value> = self.filter.iter().map(|(k, p)| Ok((k.clone(), parameter(args, p)?.clone()))).collect::<Result<_>>()?;
        let rows = next.tables.get_mut(&self.dataset).context("missing mutation dataset")?;
        let matches = |r: &Value| filters.iter().all(|(k, v)| r.get(k) == Some(v));
        match self.operation {
            Operation::Create => {
                if rows.len() >= MAX_ROWS {
                    return Ok((state.clone(), self.reject.clone()));
                }
                let n = next.next.get_mut(&self.dataset).context("missing dataset counter")?;
                let mut row = d.template.clone();
                row.extend(fields);
                row.insert(d.key.clone(), if let Some(prefix) = d.template[&d.key].as_str() { json!(format!("{prefix}_{n}")) } else { json!(*n) });
                *n = n.checked_add(1).context("dataset key overflow")?;
                rows.push(Value::Object(row));
            }
            Operation::Update => {
                for row in rows.iter_mut().filter(|r| matches(r)) {
                    row.as_object_mut().context("dataset row must be a record")?.extend(fields.clone());
                }
            }
            Operation::Delete => rows.retain(|r| !matches(r)),
        }
        // Deleting a referenced parent is restricted; writes cannot create dangling references.
        for (name, definition) in defs {
            for (field, target) in &definition.references {
                if next.tables[name].iter().any(|r| !next.tables[target].iter().any(|p| p.get(&defs[target].key) == r.get(field))) {
                    return Ok((state.clone(), self.reject.clone()));
                }
            }
        }
        Ok((next, self.response.clone()))
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
        let (rejected, response) = create.prepare(&defs, &state, &[("who".into(), json!(999))]).unwrap();
        assert_eq!(state, rejected);
        assert!(response.get("err").is_some());
        state = create.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap().0;
        let delete: Mutation = serde_json::from_value(json!({"dataset":"users","operation":"delete","filter":{"id":"who"},"response":{"ok":true}})).unwrap();
        let (rejected, response) = delete.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap();
        assert_eq!(state, rejected);
        assert!(response.get("err").is_some());
        let mut delete = delete;
        delete.dataset = "orders".into();
        state = delete.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap().0;
        state = create.prepare(&defs, &state, &[("who".into(), json!(1))]).unwrap().0;
        assert_eq!(state.tables["orders"][0]["id"], 2);
        let update: Mutation =
            serde_json::from_value(json!({"dataset":"orders","operation":"update","filter":{"id":"id"},"fields":{"owner":"who"},"response":{"ok":true}}))
                .unwrap();
        let (rejected, _) = update.prepare(&defs, &state, &[("id".into(), json!(2)), ("who".into(), json!(999))]).unwrap();
        assert_eq!(state, rejected);
    }
}
