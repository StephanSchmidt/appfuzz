//! Identity labels: who the caller is (`identity`, on a host result or as
//! a request field role), which parameters name a user (`user-id`), and
//! who a record belongs to (`owner`).
//!
//! Two checks: a `user-id` argument that is not the caller
//! (`foreign_user_access`), and a record of someone else shown in a page
//! (`missing_owner_check`). Generated `owner` values are the caller about
//! half of the time, so an app that checks ownership shows its page in
//! some runs and refuses in others.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::detect::{Finding, Severity};
use crate::labels::{Label, id_text, ids_at};
use crate::manifest::Manifest;
use crate::record::{RunRecord, RunSpec};

/// The request field role that carries the caller's id.
pub const ROLE: &str = "identity";

/// The caller of a run: the request field with the `identity` role, else
/// an id derived from the seed.
pub fn caller(spec: &RunSpec, m: &Manifest) -> String {
    request_identity(spec, m).unwrap_or_else(|| (1000 + spec.seed % 9000).to_string())
}

fn request_identity(spec: &RunSpec, m: &Manifest) -> Option<String> {
    let (path, _) = m.entry.as_ref()?.fields.iter().find(|(_, r)| r.as_str() == ROLE)?;
    crate::harness::field(spec.args.first()?, path).map(id_text)
}

/// Whether the manifest says where the caller's identity comes from.
pub fn declared(m: &Manifest) -> bool {
    m.entry.as_ref().is_some_and(|e| e.fields.values().any(|r| r == ROLE))
        || m.functions.values().any(|f| f.result.iter().flat_map(|r| r.paths()).any(|(_, l)| l == Label::Identity))
}

/// Identity findings of one run.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let uses_ids =
        m.functions.values().any(|f| f.params.values().any(|l| *l == Label::UserId) || f.result.iter().flat_map(|r| r.paths()).any(|(_, l)| l == Label::Owner));
    if !uses_ids || !declared(m) {
        return Vec::new();
    }
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let mut out = Vec::new();

    // Who the caller is, as the run learns it.
    let mut known: BTreeSet<String> = request_identity(&r.spec, m).into_iter().collect();
    let mut req_leaves = Vec::new();
    for a in &r.spec.args {
        leaves(a, String::new(), &mut req_leaves);
    }
    for e in &r.events {
        for (p, a) in e.text_args().iter() {
            if m.param_label(&e.func, p) != Some(Label::UserId) {
                continue;
            }
            let mut vals = Vec::new();
            leaves(a, String::new(), &mut vals);
            if let Some((_, v)) = vals.into_iter().find(|(_, v)| !known.contains(v)) {
                let from = req_leaves
                    .iter()
                    .find(|(_, x)| *x == v)
                    .map(|(path, _)| format!(", which comes from the request field {}", crate::output::strip_index(path)))
                    .unwrap_or_default();
                let who = if known.is_empty() {
                    "the app never asked who the caller is".to_string()
                } else {
                    format!("the caller is {}", known.iter().map(|k| format!("{k:?}")).collect::<Vec<_>>().join(" or "))
                };
                out.push(Finding::new(
                    "foreign_user_access",
                    &format!("{ex}\0{}\0{p}", e.func),
                    Severity::Fail,
                    format!("{} gets the user id {v:?} (parameter {p}){from}; {who}", e.func),
                    json!({"func": e.func, "param": p, "n": e.n, "value": v, "caller": known, "label": "user-id"}),
                    run,
                ));
            }
        }
        if let Some(v) = &e.result {
            for (p, l) in m.call_result_labels(&e.func, &e.args) {
                if l == Label::Identity {
                    known.extend(ids_at(v, &p));
                }
            }
        }
    }

    // Someone else's record already shown to the client.
    let resp = crate::output::response(r, m);
    let body = resp.body.as_deref().unwrap_or_default();
    if body.is_empty() {
        return out;
    }
    // Texts that may show for another reason: in the caller's own
    // records, or in results with no owner.
    let mut elsewhere: BTreeSet<String> = BTreeSet::new();
    let mut foreign: Vec<(&crate::record::HostCall, String, String, &Map<String, Value>)> = Vec::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        let owned: Vec<String> = m.call_result_labels(&e.func, &e.args).into_iter().filter(|(_, l)| *l == Label::Owner).map(|(p, _)| p).collect();
        if owned.is_empty() {
            crate::output::strings(v, &mut elsewhere);
            continue;
        }
        for p in owned {
            let segs: Vec<&str> = p.split('.').filter(|s| !s.is_empty()).collect();
            let Some((field, parent)) = segs.split_last() else { continue };
            let mut recs = Vec::new();
            records(v, parent, &mut recs);
            for rec in recs {
                let Some(owner) = rec.get(*field).map(id_text) else { continue };
                if known.contains(&owner) {
                    rec.values().for_each(|x| crate::output::strings(x, &mut elsewhere));
                } else {
                    foreign.push((e, p.clone(), field.to_string(), rec));
                }
            }
        }
    }
    let mut reported = BTreeSet::new();
    for (e, p, field, rec) in foreign {
        if reported.contains(&(e.func.as_str(), p.clone())) {
            continue;
        }
        let owner = rec.get(&field).map(id_text).unwrap_or_default();
        {
            {
                let mut texts = BTreeSet::new();
                for (k, x) in rec {
                    if *k != field {
                        crate::output::strings(x, &mut texts);
                    }
                }
                let Some(shown) = texts
                    .into_iter()
                    .filter(|s| !elsewhere.contains(s))
                    .find(|s| s.chars().count() >= 4 && (body.contains(s.as_str()) || body.contains(&escape(s))))
                else {
                    continue;
                };
                reported.insert((e.func.as_str(), p.clone()));
                let who = if known.is_empty() { "the app never asked who the caller is".to_string() } else { format!("the caller is not {owner:?}") };
                out.push(Finding::new(
                    "missing_owner_check",
                    &format!("{ex}\0{}\0{p}", e.func),
                    Severity::Fail,
                    format!("the page shows a record {} returned that belongs to {owner:?} ({p}); {who}", e.func),
                    json!({"func": e.func, "path": p, "owner": owner, "caller": known, "shown": shown, "n": e.n, "status": resp.status, "label": "owner"}),
                    run,
                ));
            }
        }
    }
    out
}

/// A generated field can coincide with static page text ("order" in a 404).
/// Drop that candidate only when the exact changed host result is observed,
/// ownership stays fixed, and the client sees the identical response again.
pub fn drop_static(app: &crate::harness::App, r: &RunRecord, findings: &mut Vec<Finding>) {
    if r.result.is_none() {
        return;
    }
    findings.retain(|finding| {
        if finding.kind != "missing_owner_check" {
            return true;
        }
        let Some(n) = finding.detail["n"].as_u64() else { return true };
        let Some(shown) = finding.detail["shown"].as_str() else { return true };
        let Some(event) = r.events.iter().find(|e| u64::from(e.n) == n) else { return true };
        let Some(result) = &event.result else { return true };
        let protected: BTreeSet<String> = app
            .manifest
            .call_result_labels(&event.func, &event.args)
            .into_iter()
            .filter(|(_, label)| matches!(label, Label::Owner | Label::Identity))
            .flat_map(|(path, _)| ids_at(result, &path))
            .collect();
        if protected.contains(shown) {
            return true;
        }
        let mut changed = result.clone();
        if !replace_text(&mut changed, shown, "appfuzz_private_value_7f29") {
            return true;
        }
        let mut spec = r.spec.clone();
        if !spec.plan.0.contains_key(&event.func)
            && let Some(effective) = spec.plan.get(&event.func).cloned()
        {
            spec.plan.0.insert(event.func.clone(), effective);
        }
        let response = spec.plan.0.entry(event.func.clone()).or_default().on_call.entry(event.call.to_string()).or_default();
        response.ret = Some(changed.clone());
        response.generate = None;
        response.trap = None;
        response.commit_then_trap = None;
        let variant = app.run(&spec);
        let observed =
            variant.events.iter().any(|e| e.func == event.func && e.call == event.call && e.args == event.args && e.result.as_ref() == Some(&changed));
        !(observed && variant.outcome.kind == r.outcome.kind && variant.result == r.result)
    });
}

fn replace_text(value: &mut Value, from: &str, to: &str) -> bool {
    match value {
        Value::String(s) if s == from && s != to => {
            *s = to.into();
            true
        }
        Value::Array(a) => a.iter_mut().fold(false, |changed, v| replace_text(v, from, to) | changed),
        Value::Object(o) => o.values_mut().fold(false, |changed, v| replace_text(v, from, to) | changed),
        _ => false,
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Scalars of a JSON value with their paths.
fn leaves(v: &Value, path: String, out: &mut Vec<(String, String)>) {
    match v {
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                // A `[key, value]` pair in a list is a field named `key`.
                match x.as_array().map(Vec::as_slice) {
                    Some([Value::String(k), y]) if !y.is_array() => leaves(y, if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, out),
                    _ => leaves(x, format!("{path}[{i}]"), out),
                }
            }
        }
        Value::Object(o) => o.iter().for_each(|(k, x)| leaves(x, if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, out)),
        Value::Null => {}
        x => out.push((path, id_text(x))),
    }
}

/// The records at a path, through lists, options and `ok`.
fn records<'a>(v: &'a Value, segs: &[&str], out: &mut Vec<&'a Map<String, Value>>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| records(x, segs, out)),
        Value::Object(o) if o.len() == 1 && o.contains_key("ok") && segs.first() != Some(&"ok") => records(&o["ok"], segs, out),
        Value::Object(o) if o.len() == 1 && o.contains_key("err") => {}
        Value::Object(o) if segs.is_empty() => out.push(o),
        Value::Object(o) => {
            if let Some(x) = o.get(segs[0]) {
                records(x, &segs[1..], out)
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::OutcomeKind;
    use crate::record::{HostCall, Outcome, Totals};

    fn manifest() -> Manifest {
        toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            output = { status = "status", body = "body" }
            [functions."x:y/users#current"]
            result = { id = "identity" }
            [functions."x:y/orders#for-user"]
            params = { user-id = "user-id" }
            [functions."x:y/orders#get"]
            result = { owner = "owner" }
            "#,
        )
        .unwrap()
    }

    fn call(n: u32, func: &str, args: Value, result: Value) -> HostCall {
        HostCall {
            n,
            func: func.into(),
            call: 1,
            args: args.as_object().cloned().unwrap_or_default(),
            value_checks: None,
            result: Some(result),
            trap: None,
            source: String::new(),
            granted: true,
            latency_ns: 0u64.into(),
            cost: 0,
            fuel_before: 0,
            t_ns: 0u64.into(),
            stack: vec![],
        }
    }

    fn run(query: Value, body: &str, events: Vec<HostCall>) -> RunRecord {
        let spec = RunSpec {
            component: String::new(),
            contract: String::new(),
            export: "h".into(),
            args: vec![json!({"method": "GET", "query": query})],
            plan: Default::default(),
            now: String::new(),
            seed: 0,
            fuel: 0,
            memory: 0,
            ns_per_fuel: 0.0,
        };
        RunRecord {
            id: "r1".into(),
            spec,
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: Some(json!({"status": 200, "body": body})),
            totals: Totals::default(),
            events,
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
    fn identity() {
        let m = manifest();
        let me = || call(1, "x:y/users#current", json!({}), json!({"id": "1000", "name": "Ann"}));
        let for_user = |u: &str| call(2, "x:y/orders#for-user", json!({"user-id": u}), json!([]));
        let f = check(&run(json!([["user", "77"]]), "", vec![me(), for_user("77")]), &m);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "foreign_user_access");
        assert!(f[0].title.contains("request field query.user"), "{}", f[0].title);
        assert!(check(&run(json!([]), "", vec![me(), for_user("1000")]), &m).is_empty());

        let order = |owner: &str| call(2, "x:y/orders#get", json!({"id": 5}), json!({"ok": {"id": 5, "owner": owner, "item": "Blue chair"}}));
        let f = check(&run(json!([]), "<p>Blue chair</p>", vec![me(), order("1001")]), &m);
        assert_eq!(f.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(), ["missing_owner_check"]);
        assert!(check(&run(json!([]), "<p>Blue chair</p>", vec![me(), order("1000")]), &m).is_empty());
        assert!(check(&run(json!([]), "<p>Not yours</p>", vec![me(), order("1001")]), &m).is_empty());
    }

    #[test]
    fn marks_owners() {
        let mut v = json!([{"owner": "a"}, {"owner": "b"}, {"owner": "c"}, {"owner": "d"}, {"owner": "e"}, {"owner": "f"}]);
        crate::labels::mark(&mut v, &[("owner".into(), Label::Owner)], 3, "1000");
        let owners: BTreeSet<String> = ids_at(&v, "owner").into_iter().collect();
        assert_eq!(owners, BTreeSet::from(["1000".to_string(), "1001".to_string()]));
    }
}
