//! Tenant isolation: what one user sees and changes must not depend on
//! other users' records.
//!
//! The pair: the same world, with the private fields of other users'
//! records changed (and, where a dataset declares no `public` fields, half
//! of them gone and one more added). Another answer, or other arguments to a
//! call that changes something, is `tenant_leak`. Records the caller's own
//! records reference stay as they are: the caller may see those.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::dataset::Edit;
use crate::detect::{Finding, Severity};
use crate::harness::App;
use crate::labels::id_text;
use crate::manifest::Manifest;
use crate::output::response;
use crate::record::{RunRecord, RunSpec};

/// The variant of `r` where only other users' records change, or None when
/// the caller is unknown or no record belongs to anyone else.
pub fn variant(app: &App, r: &RunRecord) -> Option<RunSpec> {
    let m = &app.manifest;
    if !m.datasets.values().any(|d| d.owner.is_some()) {
        return None;
    }
    let state = app.initial_state(&r.spec.plan, r.spec.seed).ok()?;
    let world = &state.tables;
    let caller = crate::identity::known_caller(&r.spec, m, world)?;
    let mine = |d: &crate::dataset::Dataset, row: &Value| d.owner.as_ref().is_some_and(|o| row.get(o).is_some_and(|v| id_text(v) == caller));
    // Records the caller's own records point at.
    let mut referenced: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (name, d) in &m.datasets {
        for row in world.get(name).into_iter().flatten().filter(|row| mine(d, row)) {
            for (field, target) in &d.references {
                if let Some(v) = row.get(field) {
                    referenced.entry(target.as_str()).or_default().insert(v.to_string());
                }
            }
        }
    }
    let tenants = crate::dataset::tenants(&m.datasets, world);
    let other = tenants.iter().find(|t| id_text(t) != caller);
    let mut edits = Vec::new();
    for (name, d) in m.datasets.iter().filter(|(_, d)| d.owner.is_some()) {
        let owner = d.owner.as_deref().unwrap_or_default();
        let foreign: Vec<Value> = world
            .get(name)
            .into_iter()
            .flatten()
            .filter(|row| !mine(d, row))
            .filter_map(|row| row.get(&d.key))
            .filter(|k| !referenced.get(name.as_str()).is_some_and(|keys| keys.contains(&k.to_string())))
            .cloned()
            .collect();
        if foreign.is_empty() {
            continue;
        }
        let private: Vec<String> =
            d.template.keys().filter(|f| **f != d.key && f.as_str() != owner && !d.public.contains(f) && !d.references.contains_key(*f)).cloned().collect();
        if !private.is_empty() {
            edits.push(Edit::Rotate { dataset: name.clone(), keys: foreign.clone(), fields: private });
        }
        // Without public fields nothing of another user's record is the
        // caller's business, not even that it exists. The first one stays,
        // changed, so the edits never cancel out.
        if d.public.is_empty() {
            edits.push(Edit::Drop { dataset: name.clone(), keys: foreign.iter().skip(1).step_by(2).cloned().collect() });
            if let Some(other) = other {
                edits.push(Edit::Add { dataset: name.clone(), rows: 1, set: Map::from_iter([(owner.to_string(), other.clone())]) });
            }
        }
    }
    if edits.is_empty() {
        return None;
    }
    let mut spec = r.spec.clone();
    let defaults = spec.plan.0.entry("_defaults".into()).or_default();
    defaults.dataset_seed = Some(defaults.dataset_seed.unwrap_or(r.spec.seed));
    defaults.identity = Some(caller);
    defaults.dataset_edits.extend(edits);
    Some(spec)
}

/// Calls that change something, as the caller's request makes them.
fn effects(m: &Manifest, r: &RunRecord) -> Vec<(String, Map<String, Value>)> {
    r.events
        .iter()
        .filter(|e| m.effect_of(&e.func).is_some_and(|x| x.changes()) && !m.function(&e.func).is_some_and(|f| f.shared))
        .map(|e| (e.func.clone(), e.args.clone()))
        .collect()
}

/// What the tenant variant run says, next to its base run.
pub fn compare(m: &Manifest, base: &RunRecord, vr: &RunRecord, mut detail: Value) -> Option<Finding> {
    let ex = &base.spec.export;
    let caller = vr.spec.plan.0.get("_defaults").and_then(|d| d.identity.clone()).unwrap_or_default();
    let datasets: Vec<String> = detail["datasets"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
    let what = datasets.join(" and ");
    let (a, b) = (response(base, m), response(vr, m));
    let (ab, bb) = (a.body.clone().unwrap_or_default(), b.body.clone().unwrap_or_default());
    let content = ab != bb || (a.body.is_none() && base.result != vr.result);
    let (ea, eb) = (effects(m, base), effects(m, vr));
    let effect = (ea != eb)
        .then(|| ea.iter().zip(&eb).find(|(x, y)| x != y).map(|(x, _)| x.0.clone()).or_else(|| ea.get(eb.len()).or(eb.get(ea.len())).map(|e| e.0.clone())))
        .flatten();
    let meta = a.status != b.status || base.result != vr.result;
    let (severity, title) = if content {
        let (gone, new) = crate::metamorphic::word_diff(&ab, &bb);
        let shown = if gone.is_empty() && new.is_empty() { String::new() } else { format!(" ('{}' → '{}')", gone.join(" "), new.join(" ")) };
        (Severity::Fail, format!("the answer of {ex} for {caller} changes when only other users' {what} change{shown}"))
    } else if let Some(f) = &effect {
        (Severity::Fail, format!("{ex} calls {f} with other arguments for {caller} when only other users' {what} change"))
    } else if meta {
        (Severity::Warn, format!("the status or headers of {ex} for {caller} change when only other users' {what} change: they show that other records exist"))
    } else {
        return None;
    };
    if let Value::Object(d) = &mut detail {
        d.insert("caller".into(), json!(caller));
        d.insert("effect".into(), json!(effect));
    }
    Some(Finding::new("tenant_leak", &format!("{ex}\0tenant"), severity, title, detail, Some(&vr.id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{HostCall, Outcome, OutcomeKind, Totals};

    fn manifest(shared: bool) -> Manifest {
        let toml = format!(
            "[app]\nwasm = \"a.wasm\"\n[entry]\nexport = \"h\"\noutput = {{ status = \"status\", body = \"body\" }}\n[functions.\"x:y/log#add\"]\neffect = \"write\"\nshared = {shared}\n"
        );
        toml::from_str(&toml).unwrap()
    }

    fn run(id: &str, status: u16, body: &str, logged: u32) -> RunRecord {
        let mut plan = crate::plan::Plan::default();
        plan.0.entry("_defaults".into()).or_default().identity = Some("user_1".into());
        let spec = RunSpec {
            component: String::new(),
            contract: String::new(),
            export: "h".into(),
            args: vec![],
            plan,
            now: String::new(),
            seed: 0,
            fuel: 0,
            memory: 0,
            ns_per_fuel: 0.0,
        };
        let add = HostCall {
            n: 1,
            func: "x:y/log#add".into(),
            call: 1,
            args: Map::from_iter([("total".into(), json!(logged))]),
            result: Some(json!(null)),
            granted: true,
            ..Default::default()
        };
        RunRecord {
            id: id.into(),
            spec,
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: Some(json!({"status": status, "body": body})),
            totals: Totals::default(),
            events: vec![add],
            guest_error: None,
            rejected_output: None,
            command_exit_code: None,
            memory_limit_hit: false,
            capture_limited: false,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn other_users_records_must_not_change_the_answer_or_the_changes() {
        let m = manifest(false);
        let detail = || json!({"datasets": ["deals"]});
        let base = run("a", 200, "<p>Pipeline: 1015</p>", 3);
        assert!(compare(&m, &base, &run("b", 200, "<p>Pipeline: 1015</p>", 3), detail()).is_none());
        let f = compare(&m, &base, &run("b", 200, "<p>Pipeline: 1940</p>", 3), detail()).unwrap();
        assert_eq!(f.severity, Severity::Fail);
        assert!(f.title.starts_with("the answer of h for user_1 changes when only other users' deals change ("), "{}", f.title);
        let f = compare(&m, &base, &run("b", 200, "<p>Pipeline: 1015</p>", 4), detail()).unwrap();
        assert_eq!((f.severity, f.title.as_str()), (Severity::Fail, "h calls x:y/log#add with other arguments for user_1 when only other users' deals change"));
        // A shared log may count everyone's records.
        assert!(compare(&manifest(true), &base, &run("b", 200, "<p>Pipeline: 1015</p>", 4), detail()).is_none());
        // Only the status: it shows that other records exist.
        let f = compare(&m, &base, &run("b", 404, "<p>Pipeline: 1015</p>", 3), detail()).unwrap();
        assert_eq!(f.severity, Severity::Warn);
    }
}
