//! Probes: targeted runs that ask one question each.
//!
//! `values`: does the app survive every kind of value a host function may
//! legally return (empty lists, `err`, `none`, edge numbers, odd strings)?

use serde::Serialize;
use serde_json::json;
use wasmtime::component::Type;

use crate::detect::{Finding, Severity, per_run};
use crate::harness::App;
use crate::par::{self, Runner};
use crate::plan::{FnPlan, Response};
use crate::record::{OutcomeKind, RunSpec};
use crate::scale::steady;
use crate::value::GenOpts;
use crate::wit::ImportKind;

#[derive(Debug, Clone, Serialize)]
pub struct ValueProbe {
    pub func: String,
    pub variant: String,
    pub run: String,
    pub outcome: OutcomeKind,
    pub host_calls: u32,
}

#[derive(Default)]
struct Shape {
    list: bool,
    result: bool,
    option: bool,
    number: bool,
    string: bool,
}

fn shape(t: &Type, s: &mut Shape) {
    match t {
        Type::List(l) => {
            s.list = true;
            shape(&l.ty(), s)
        }
        Type::FixedLengthList(l) => shape(&l.ty(), s),
        Type::Result(r) => {
            s.result = true;
            if let Some(t) = r.ok() {
                shape(&t, s)
            }
            if let Some(t) = r.err() {
                shape(&t, s)
            }
        }
        Type::Option(o) => {
            s.option = true;
            shape(&o.ty(), s)
        }
        Type::Record(r) => r.fields().for_each(|f| shape(&f.ty, s)),
        Type::Tuple(t) => t.types().for_each(|t| shape(&t, s)),
        Type::Variant(v) => v.cases().filter_map(|c| c.ty).for_each(|t| shape(&t, s)),
        Type::String | Type::Char => s.string = true,
        Type::S8 | Type::U8 | Type::S16 | Type::U16 | Type::S32 | Type::U32 | Type::S64 | Type::U64 | Type::Float32 | Type::Float64 => {
            s.number = true
        }
        _ => {}
    }
}

/// Value classes worth trying for a result type.
pub fn variants(t: &Type) -> Vec<(&'static str, GenOpts)> {
    let mut s = Shape::default();
    shape(t, &mut s);
    let g = |f: &dyn Fn(&mut GenOpts)| {
        let mut o = GenOpts { list_len: Some(1), ..Default::default() };
        f(&mut o);
        o
    };
    let mut v = Vec::new();
    if s.list {
        v.push(("empty list", g(&|o| o.list_len = Some(0))));
        v.push(("long list", g(&|o| o.list_len = Some(50))));
    }
    if s.result {
        v.push(("err", g(&|o| o.results = Some("err".into()))));
    }
    if s.option {
        v.push(("none", g(&|o| o.options = Some("none".into()))));
    }
    if s.number {
        v.push(("edge numbers", g(&|o| o.numbers = Some("edge".into()))));
    }
    if s.string {
        v.push(("empty strings", g(&|o| o.strings = Some("empty".into()))));
        v.push(("unicode strings", g(&|o| o.strings = Some("unicode".into()))));
        // Byte slicing (`&s[..10]`) panics unless the index is a char
        // boundary for every one of these.
        v.push(("2-byte chars", g(&|o| o.strings = Some("utf8-2".into()))));
        v.push(("3-byte chars", g(&|o| o.strings = Some("utf8-3".into()))));
        v.push(("3-byte chars after 1 byte", g(&|o| o.strings = Some("utf8-3o".into()))));
        v.push(("4-byte chars", g(&|o| o.strings = Some("utf8-4".into()))));
        v.push(("long strings", g(&|o| o.strings = Some("long".into()))));
    }
    v
}

/// Runs every value class of every host function (or those matching
/// `only`). Returns the probes and the findings they produced.
pub fn values(
    app: &App,
    base: &RunSpec,
    only: Option<&str>,
    run: Runner,
) -> (Vec<ValueProbe>, Vec<Finding>) {
    let base = RunSpec { plan: steady(&base.plan), ..base.clone() };
    let mut probes = Vec::new();
    let mut findings = Vec::new();
    let funcs = app.imports.iter().filter(|i| i.kind == ImportKind::Platform).flat_map(|i| i.funcs.iter()).filter(|f| app.manifest.function(&f.key).and_then(|s| s.fails) != Some(false));
    let mut tries = Vec::new();
    for f in funcs.filter(|f| only.is_none_or(|o| f.key.contains(o))) {
        let Some(t) = f.ty.results().next() else { continue };
        for (variant, opts) in variants(&t) {
            let mut spec = base.clone();
            if let Some(q) = app.manifest.function(&f.key).and_then(|s| s.query.as_ref()) {
                if matches!(variant, "empty list" | "long list") {
                    spec.plan.0.entry("_defaults".into()).or_default().dataset_rows.insert(q.dataset.clone(), opts.list_len.unwrap());
                    tries.push((f, variant, spec));
                    continue;
                }
                if !matches!(variant, "err" | "none") { continue; }
            }
            let fp = spec.plan.0.entry(f.key.clone()).or_default();
            *fp = FnPlan {
                response: Response { generate: Some(opts), latency_ms: fp.response.latency_ms, ..Default::default() },
                cost: fp.cost,
                ..Default::default()
            };
            tries.push((f, variant, spec));
        }
    }
    let runs = par::map(&tries, |(_, _, s)| run(s));
    for ((f, variant, _), r) in tries.into_iter().zip(runs) {
        probes.push(ValueProbe { func: f.key.clone(), variant: variant.into(), run: r.id.clone(), outcome: r.outcome.kind, host_calls: r.totals.host_calls });
        for mut x in per_run(&r, &app.manifest) {
            // Name the value that caused it.
            if matches!(x.kind.as_str(), "crash" | "hang") {
                let kind = format!("{}_on_host_value", x.kind);
                x = Finding::new(
                    &kind,
                    &format!("{}\0{variant}\0{}", f.key, x.title),
                    Severity::Fail,
                    format!("{} when {} returns {variant}: {}", x.kind, f.key, x.title),
                    json!({"func": f.key, "variant": variant, "cause": x.detail}),
                    Some(&r.id),
                );
            }
            findings.push(x);
        }
    }
    (probes, findings)
}

/// Calendar and clock edges: leap days, year/month ends, midnight, DST
/// switch hours (EU and US), 2038, the epoch, a non-leap century.
pub const EDGE_TIMES: &[(&str, &str)] = &[
    ("2028-02-29T12:00:00", "leap day"),
    ("2027-02-28T23:59:59", "last second of February"),
    ("2100-02-28T12:00:00", "February of a non-leap century"),
    ("2027-12-31T23:59:59", "last second of the year"),
    ("2028-01-01T00:00:00", "first second of the year"),
    ("2027-01-31T23:59:00", "end of a 31-day month"),
    ("2027-04-30T23:59:00", "end of a 30-day month"),
    ("2027-03-28T02:30:00", "EU DST gap"),
    ("2027-10-31T02:30:00", "EU DST overlap"),
    ("2027-03-14T02:30:00", "US DST gap"),
    ("2027-01-04T00:00:00", "midnight on a Monday"),
    ("2027-01-03T23:59:59", "end of a Sunday"),
    ("2038-01-19T03:14:08", "after the 32-bit epoch overflow"),
    ("1970-01-01T00:00:00", "the Unix epoch"),
    ("2026-12-31T23:59:59", "end of week 53 year"),
    ("2199-12-31T23:59:59", "far future"),
];

#[derive(Debug, Clone, Serialize)]
pub struct TimeProbe {
    pub now: String,
    pub what: String,
    pub run: String,
    pub outcome: OutcomeKind,
}

/// Runs the export at every edge time. A crash or hang there is a
/// `crash_at_time` / `hang_at_time` finding.
pub fn times(app: &App, base: &RunSpec, run: Runner) -> (Vec<TimeProbe>, Vec<Finding>) {
    // A hang ends at twice the production limit.
    let fuel = base.fuel.min(app.manifest.limits.fuel.saturating_mul(2));
    let base = RunSpec { plan: steady(&base.plan), fuel, ..base.clone() };
    let mut probes = Vec::new();
    let mut findings = Vec::new();
    let specs: Vec<RunSpec> = EDGE_TIMES
        .iter()
        .map(|(now, _)| {
            let mut spec = base.clone();
            spec.now = now.to_string();
            // Request fields that carry the clock follow `now`.
            let entry = app.manifest.entry.as_ref().filter(|e| crate::harness::fn_key_eq(&e.export, &spec.export));
            if let (Some(e), Some(a)) = (entry, spec.args.first_mut()) {
                crate::harness::set_clock_fields(a, &e.fields, now);
            }
            spec
        })
        .collect();
    let runs = par::map(&specs, |s| run(s));
    for ((now, what), r) in EDGE_TIMES.iter().zip(runs) {
        probes.push(TimeProbe { now: now.to_string(), what: what.to_string(), run: r.id.clone(), outcome: r.outcome.kind });
        for mut x in per_run(&r, &app.manifest) {
            if matches!(x.kind.as_str(), "crash" | "hang") {
                let kind = format!("{}_at_time", x.kind);
                x = Finding::new(
                    &kind,
                    &format!("{now}\0{}", x.title),
                    Severity::Fail,
                    format!("{} at {now} ({what}): {}", x.kind, x.title),
                    json!({"now": now, "what": what, "cause": x.detail}),
                    Some(&r.id),
                );
            }
            findings.push(x);
        }
    }
    (probes, findings)
}
