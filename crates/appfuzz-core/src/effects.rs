//! Effect labels: what a host function does to the world (`read`, `write`,
//! `delete`, `external`), whether it may be repeated (`idempotent`), and
//! which function does it for many at once (`batch_of`).
//!
//! The per-run checks here need no state between requests: a change on a
//! safe method, the same change twice, and a change that stays after a
//! later one failed. Amplification and retries are weighted by effect
//! where they are found (`scale`, `detect`).

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::record::{OutcomeKind, RunRecord};

/// HTTP methods that must not change anything.
pub const SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

/// The request's HTTP method, if the request has one.
pub fn method(r: &RunRecord, m: &Manifest) -> Option<String> {
    let req = r.spec.args.first()?;
    let fields = m.entry.as_ref().map(|e| e.fields.clone()).unwrap_or_default();
    let p = crate::fuzz::role_path(&fields, req, "method")?;
    crate::harness::field(req, &p)?.as_str().map(str::to_ascii_uppercase)
}

fn is_err(e: &crate::record::HostCall) -> bool {
    e.trap.is_some() || matches!(&e.result, Some(Value::Object(o)) if o.len() == 1 && o.contains_key("err"))
}

/// Effect findings of one run.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    if !m.functions.values().any(|f| f.effect.is_some()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());

    if let Some(meth) = method(r, m).filter(|x| SAFE_METHODS.contains(&x.as_str())) {
        let mut seen = Vec::new();
        for e in &r.events {
            let Some(eff) = m.effect_of(&e.func).filter(|x| x.changes()) else { continue };
            if seen.contains(&e.func) {
                continue;
            }
            seen.push(e.func.clone());
            out.push(Finding::new(
                "write_on_safe_method",
                &format!("{ex}\0{}", e.func),
                Severity::Fail,
                format!("a {meth} request calls {} (effect {}); a link, a prefetch or a crawler can trigger it", e.func, eff.name()),
                json!({"func": e.func, "effect": eff.name(), "method": meth, "n": e.n, "label": format!("effect:{}", eff.name())}),
                run,
            ));
        }
    }

    // The same change twice in one request, after the first one worked (a
    // retry after a failure is `retry_storm`). Not when an earlier host
    // list held the same element twice: then the host data repeats.
    let mut same: BTreeMap<(&str, String), Vec<u32>> = BTreeMap::new();
    for e in r.events.iter().filter(|e| m.unrepeatable(&e.func)) {
        same.entry((e.func.as_str(), Value::Object(e.args.clone()).to_string())).or_default().push(e.n);
    }
    let mut reported = Vec::new();
    for ((f, args), ns) in same {
        if ns.len() < 2 || reported.contains(&f) {
            continue;
        }
        let calls: Vec<&crate::record::HostCall> = r.events.iter().filter(|e| ns.contains(&e.n)).collect();
        let Some(i) = calls.iter().position(|e| !is_err(e)) else { continue };
        if i + 1 >= calls.len() || duplicate_host_data(&r.events, calls[i + 1].n) {
            continue;
        }
        reported.push(f);
        let eff = m.effect_of(f).map(|x| x.name()).unwrap_or_default();
        out.push(Finding::new(
            "repeated_write",
            &format!("{ex}\0{f}"),
            Severity::Fail,
            format!("{f} (effect {eff}, not idempotent) is called {} times with the same arguments in one request", ns.len()),
            json!({"func": f, "effect": eff, "calls": ns, "args": serde_json::from_str::<Value>(&args).unwrap_or(Value::Null), "label": format!("effect:{eff}")}),
            run,
        ));
    }

    // A change that stays after a later one failed, and a response that
    // says all went well.
    let status = crate::output::response(r, m).status;
    if r.outcome.kind == OutcomeKind::Ok && status.is_some_and(|s| s < 400) {
        let changes: Vec<&crate::record::HostCall> = r.events.iter().filter(|e| m.effect_of(&e.func).is_some_and(|x| x.changes())).collect();
        if let Some(fail) = changes.iter().find(|e| is_err(e)
            && !changes.iter().any(|later| later.n > e.n && later.func == e.func && later.args == e.args && !is_err(later)))
            && let Some(done) = changes.iter().find(|e| e.n < fail.n && !is_err(e) && (e.func != fail.func || e.args != fail.args))
        {
            out.push(Finding::new(
                "partial_write",
                &format!("{ex}\0{}\0{}", done.func, fail.func),
                Severity::Warn,
                format!(
                    "{} succeeds, then {} fails, and the response is status {}: the first change stays and nobody is told",
                    done.func,
                    fail.func,
                    status.unwrap_or_default()
                ),
                json!({"done": done.func, "done_n": done.n, "failed": fail.func, "failed_n": fail.n, "status": status}),
                run,
            ));
        }
    }
    out
}

/// Whether a host list returned before call `n` holds the same element
/// twice (equal, or with the same `id`).
pub(crate) fn duplicate_host_data(events: &[crate::record::HostCall], n: u32) -> bool {
    events.iter().take_while(|e| e.n < n).filter_map(|e| e.result.as_ref().and_then(crate::detect::list_in)).any(|list| {
        let mut seen = std::collections::BTreeSet::new();
        list.iter().any(|x| !seen.insert(x.get("id").map(Value::to_string).unwrap_or_else(|| x.to_string())))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{HostCall, Outcome, RunSpec, Totals};

    fn manifest() -> Manifest {
        toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            output = { status = "status", body = "body" }
            [functions."x:y/store#save"]
            effect = "write"
            [functions."x:y/store#put"]
            effect = "write"
            idempotent = true
            [functions."x:y/mail#send"]
            effect = "external"
            [functions."x:y/items#get-many"]
            batch_of = "x:y/items#get"
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
            latency_ns: 0,
            cost: 0,
            fuel_before: 0,
            t_ns: 0,
            stack: vec![],
        }
    }

    fn run(method: &str, events: Vec<HostCall>) -> RunRecord {
        let spec = RunSpec {
            component: String::new(),
            contract: String::new(),
            export: "h".into(),
            args: vec![json!({"method": method, "path": "/"})],
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
            result: Some(json!({"status": 200, "body": ""})),
            totals: Totals::default(),
            events,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind.as_str()).collect()
    }

    #[test]
    fn effects() {
        let m = manifest();
        let save = |n, v: &str, res: Value| call(n, "x:y/store#save", json!({"key": "k", "value": v}), res);
        let f = check(&run("GET", vec![save(1, "a", json!({"ok": 1}))]), &m);
        assert_eq!(kinds(&f), ["write_on_safe_method"]);
        assert!(check(&run("POST", vec![save(1, "a", json!({"ok": 1}))]), &m).is_empty());
        let f = check(&run("POST", vec![save(1, "a", json!({"ok": 1})), save(2, "a", json!({"ok": 2}))]), &m);
        assert_eq!(kinds(&f), ["repeated_write"]);
        // A retry after a failure is not a repeated write.
        let f = check(&run("POST", vec![save(1, "a", json!({"err": "busy"})), save(2, "a", json!({"ok": 2}))]), &m);
        assert!(f.is_empty());
        let put = |n| call(n, "x:y/store#put", json!({"key": "k"}), json!({"ok": null}));
        assert!(check(&run("POST", vec![put(1), put(2)]), &m).is_empty());
        let mail = call(2, "x:y/mail#send", json!({"to": "a"}), json!({"err": "down"}));
        let f = check(&run("POST", vec![save(1, "a", json!({"ok": 1})), mail]), &m);
        assert_eq!(kinds(&f), ["partial_write"]);
        assert_eq!(m.batch_for("x:y/items#get").as_deref(), Some("x:y/items#get-many"));
        assert!(m.unrepeatable("x:y/store#save") && !m.unrepeatable("x:y/store#put"));
    }
}
