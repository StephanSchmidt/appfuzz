//! Pairs of runs: a run, and the same run with one thing changed that
//! should (or should not) change what the app does. All host results of
//! the base run are pinned (`on_call`), so the pair differs only in that
//! one thing.
//!
//! - reversed list → output words change: `order_dependence`
//! - duplicated element → impossible percentages: `duplicate_sensitivity`
//! - other random seed / clock (request clock fields kept) → output
//!   changes: `nondeterminism`
//! - one call fails → the same answer: `error_ignored`; an error status
//!   with the normal page: `inconsistent_response`
//! - one host function 10× slower → over the latency limit:
//!   `slow_host_sensitivity`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::detect::{Finding, Severity, list_in, ms};
use crate::harness::{App, fn_key_eq};
use crate::output::{impossible_percentages, response, word_bag};
use crate::par::{self, Runner};
use crate::plan::Response;
use crate::record::{OutcomeKind, RunRecord, RunSpec};
use crate::wasi::{format_datetime, parse_datetime};

/// Lists, functions and the like tried per kind of variant.
const PER_KIND: usize = 3;
const SLOW_FUNCS: usize = 4;
const SLOW_FACTOR: f64 = 10.0;
/// Latency of a "slow" call when the function has none.
const SLOW_MIN_MS: f64 = 20.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Reverse,
    Duplicate,
    Seed,
    Clock,
    Fault,
    Slow,
}

#[derive(Debug, Clone, Serialize)]
pub struct Variant {
    pub change: Change,
    /// The host function changed, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub func: Option<String>,
    /// Its call number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call: Option<u32>,
    #[serde(skip)]
    pub spec: RunSpec,
}

/// The base spec with every host result of `r` pinned, or None if a
/// result was shortened when recorded (it cannot be replayed).
pub fn pinned(r: &RunRecord) -> Option<RunSpec> {
    let mut spec = r.spec.clone();
    for e in &r.events {
        let v = e.result.clone().unwrap_or(Value::Null);
        if e.trap.is_some() || v.to_string().contains(" bytes #") {
            return None;
        }
        spec.plan.0.entry(e.func.clone()).or_default().on_call.insert(e.call.to_string(), Response { ret: Some(v), ..Default::default() });
    }
    Some(spec)
}

/// The variants worth running for an ok run.
pub fn variants(app: &App, r: &RunRecord) -> Vec<Variant> {
    let mut out = Vec::new();
    if r.outcome.kind != OutcomeKind::Ok {
        return out;
    }
    let Some(base) = pinned(r) else { return out };
    let set = |spec: &mut RunSpec, e: &crate::record::HostCall, v: Value| {
        spec.plan.0.entry(e.func.clone()).or_default().on_call.insert(e.call.to_string(), Response { ret: Some(v), ..Default::default() });
    };
    // Lists of at least two different elements.
    let lists: Vec<_> = r
        .events
        .iter()
        .filter(|e| e.result.as_ref().and_then(list_in).is_some_and(|a| a.len() >= 2 && a.iter().any(|x| *x != a[0])))
        .take(PER_KIND)
        .collect();
    for e in &lists {
        let mut v = e.result.clone().unwrap_or_default();
        if let Some(a) = list_mut(&mut v) {
            a.reverse();
        }
        let mut s = base.clone();
        set(&mut s, e, v);
        out.push(Variant { change: Change::Reverse, func: Some(e.func.clone()), call: Some(e.call), spec: s });
    }
    for e in r.events.iter().filter(|e| e.result.as_ref().and_then(list_in).is_some_and(|a| !a.is_empty())).take(PER_KIND) {
        let mut v = e.result.clone().unwrap_or_default();
        if let Some(a) = list_mut(&mut v) {
            let x = a[0].clone();
            a.insert(1, x);
        }
        let mut s = base.clone();
        set(&mut s, e, v);
        out.push(Variant { change: Change::Duplicate, func: Some(e.func.clone()), call: Some(e.call), spec: s });
    }
    // Always: reads of the insecure seed (hash maps) are not counted.
    // Two other seeds: a small hash map keeps its order under one now and then.
    for k in 1..=3 {
        out.push(Variant { change: Change::Seed, func: None, call: None, spec: RunSpec { seed: base.seed.wrapping_add(k), ..base.clone() } });
    }
    let entry = app.manifest.entry.as_ref().filter(|e| fn_key_eq(&e.export, &r.spec.export));
    let has_clock_fields = entry.is_some_and(|e| e.fields.values().any(|f| f.starts_with("clock.")));
    if r.totals.clock_reads > 0
        && has_clock_fields
        && let Some(t) = parse_datetime(&base.now)
    {
        // A day and an hour later on the wall clock only.
        let (d, _, hms) = format_datetime(t + 25 * 3600);
        out.push(Variant { change: Change::Clock, func: None, call: None, spec: RunSpec { now: format!("{d}T{hms}"), ..base.clone() } });
    }
    // A call that succeeded with something (failing instead of returning
    // nothing may rightly look the same).
    let something = |v: &Value| !matches!(v, Value::Null) && v.as_array().is_none_or(|a| !a.is_empty()) && v.as_str().is_none_or(|s| !s.is_empty());
    if let Some(e) = r.events.iter().find(|e| matches!(&e.result, Some(Value::Object(o)) if o.len() == 1 && o.get("ok").is_some_and(something))) {
        let mut s = base.clone();
        set(&mut s, e, json!({"err": "appfuzz: injected failure"}));
        out.push(Variant { change: Change::Fault, func: Some(e.func.clone()), call: Some(e.call), spec: s });
    }
    let mut funcs: Vec<&str> = Vec::new();
    for e in &r.events {
        if !funcs.contains(&e.func.as_str()) && funcs.len() < SLOW_FUNCS {
            funcs.push(&e.func);
        }
    }
    if app.manifest.limits.max_latency_ms.is_some() {
        for f in funcs {
            let calls: Vec<_> = r.events.iter().filter(|e| e.func == f).collect();
            let mean = calls.iter().map(|e| e.latency_ns).sum::<u64>() as f64 / calls.len() as f64 / 1e6;
            let mut s = base.clone();
            s.plan.0.entry(f.to_string()).or_default().response.latency_ms = Some((mean * SLOW_FACTOR).max(SLOW_MIN_MS));
            // Pinned results carry no latency of their own, so the
            // function's latency applies to every call.
            out.push(Variant { change: Change::Slow, func: Some(f.to_string()), call: None, spec: s });
        }
    }
    out
}

fn list_mut(v: &mut Value) -> Option<&mut Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 && (o.contains_key("ok") || o.contains_key("some")) => o.values_mut().next().and_then(list_mut),
        _ => None,
    }
}

/// What a variant run says about the app, next to its base run.
pub fn compare(app: &App, base: &RunRecord, v: &Variant, vr: &RunRecord) -> Vec<Finding> {
    let mut out = Vec::new();
    if vr.outcome.kind != OutcomeKind::Ok {
        // Crashes and hangs are per-run findings of the variant run.
        return out;
    }
    let m = &app.manifest;
    let ex = &base.spec.export;
    let run = Some(vr.id.as_str());
    let (a, b) = (response(base, m), response(vr, m));
    let (ab, bb) = (a.body.clone().unwrap_or_default(), b.body.clone().unwrap_or_default());
    let same = a.status == b.status && ab == bb && base.result == vr.result;
    let func = v.func.clone().unwrap_or_default();
    let detail = |extra: Value| {
        let mut d = json!({"change": v.change, "func": v.func, "call": v.call, "base_run": base.id, "variant_run": vr.id});
        if let (Value::Object(d), Value::Object(x)) = (&mut d, extra) {
            d.extend(x);
        }
        d
    };
    match v.change {
        Change::Reverse if !same && word_bag(&ab) != word_bag(&bb) => {
            let (gone, new) = word_diff(&ab, &bb);
            out.push(Finding::new(
                "order_dependence",
                &format!("{ex}\0{func}"),
                Severity::Info,
                format!("{ex} shows different things when {func} returns the same elements in another order"),
                detail(json!({"words_gone": gone, "words_new": new})),
                run,
            ));
        }
        Change::Duplicate => {
            let before = impossible_percentages(&ab);
            let after = impossible_percentages(&bb);
            // A base that already shows one is another problem.
            if before.is_empty() && !after.is_empty() {
                out.push(Finding::new(
                    "duplicate_sensitivity",
                    &format!("{ex}\0{func}"),
                    Severity::Warn,
                    format!("{ex} shows {} when {func} returns one element twice", after.join(", ")),
                    detail(json!({"impossible": after})),
                    run,
                ));
            }
        }
        Change::Seed | Change::Clock if !same => {
            let (gone, new) = word_diff(&ab, &bb);
            let what = if v.change == Change::Seed { "another random seed" } else { "another wall clock time (the request's date and time unchanged)" };
            out.push(Finding::new(
                "nondeterminism",
                &format!("{ex}\0{:?}", v.change),
                Severity::Info,
                format!("{ex} answers differently with {what}"),
                detail(json!({"words_gone": gone, "words_new": new, "random_bytes": base.totals.random_bytes, "clock_reads": base.totals.clock_reads})),
                run,
            ));
        }
        Change::Fault => {
            let retried = vr.events.iter().filter(|e| e.func == func).count() > base.events.iter().filter(|e| e.func == func).count();
            if same && !retried {
                out.push(Finding::new(
                    "error_ignored",
                    &format!("{ex}\0{func}"),
                    Severity::Info,
                    format!("{ex} answers exactly the same when {func} fails"),
                    detail(json!({})),
                    run,
                ));
            }
            if let (Some(s), Some(s0)) = (b.status, a.status)
                && s >= 400
                && (200..300).contains(&s0)
                && !ab.is_empty()
                && ab == bb
            {
                out.push(Finding::new(
                    "inconsistent_response",
                    &format!("{ex}\0error_with_content\0{func}"),
                    Severity::Warn,
                    format!("{ex} answers {s} when {func} fails, but with the normal page"),
                    detail(json!({"status": s})),
                    run,
                ));
            }
        }
        Change::Slow => {
            let limit = m.limits.max_latency_ms.unwrap_or(f64::MAX);
            let (t0, t1) = (ms(base.totals.virtual_ns), ms(vr.totals.virtual_ns));
            if t0 <= limit && t1 > limit {
                let calls = vr.events.iter().filter(|e| e.func == func).count();
                let per = v.spec.plan.0.get(&func).and_then(|p| p.response.latency_ms).unwrap_or(0.0);
                out.push(Finding::new(
                    "slow_host_sensitivity",
                    &format!("{ex}\0{func}"),
                    if calls >= 3 { Severity::Warn } else { Severity::Info },
                    format!("{ex} takes {t1} ms (limit {limit}) when {func} answers in {per} ms; it calls it {calls} times"),
                    detail(json!({"calls": calls, "latency_ms": per, "base_ms": t0, "slow_ms": t1, "limit_ms": limit})),
                    run,
                ));
            }
        }
        _ => {}
    }
    out
}

/// Per-run findings of a variant run that the change itself causes.
pub fn expected(v: &Variant, f: &Finding) -> bool {
    match v.change {
        Change::Slow => f.kind == "over_budget" || f.kind == "serial_chain",
        _ => false,
    }
}

/// Words in one body and not in the other (at most 10 each).
fn word_diff(a: &str, b: &str) -> (Vec<String>, Vec<String>) {
    let (wa, wb) = (word_bag(a), word_bag(b));
    let minus = |x: &[String], y: &[String]| {
        let mut y = y.to_vec();
        let mut out = Vec::new();
        for w in x {
            if let Some(i) = y.iter().position(|v| v == w) {
                y.swap_remove(i);
            } else if out.len() < 10 {
                out.push(w.clone());
            }
        }
        out
    };
    (minus(&wa, &wb), minus(&wb, &wa))
}

#[derive(Debug, Serialize)]
pub struct PairResult {
    #[serde(flatten)]
    pub variant: Variant,
    pub run: String,
    pub outcome: OutcomeKind,
    pub same_output: bool,
}

/// Runs every variant of `r` and compares. Returns the variant runs (for
/// storing), a line per pair, and the findings.
pub fn pairs(app: &App, r: &RunRecord, run: Runner) -> (Vec<RunRecord>, Vec<PairResult>, Vec<Finding>) {
    let vs = variants(app, r);
    let recs = par::map(&vs, |v| run(&v.spec));
    let mut lines = Vec::new();
    let mut findings = Vec::new();
    for (v, vr) in vs.iter().zip(&recs) {
        findings.extend(compare(app, r, v, vr));
        findings.extend(crate::detect::per_run(vr, &app.manifest).into_iter().filter(|f| !expected(v, f)));
        lines.push(PairResult { variant: v.clone(), run: vr.id.clone(), outcome: vr.outcome.kind, same_output: vr.result == r.result });
    }
    (recs, lines, findings)
}
