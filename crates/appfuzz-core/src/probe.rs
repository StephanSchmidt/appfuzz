//! Probes: targeted runs that ask one question each.
//!
//! `values`: does the app survive every kind of value a host function may
//! legally return (empty lists, `err`, `none`, edge numbers, odd strings)?

use serde::Serialize;
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::detect::{Finding, Severity};
use crate::harness::App;
use crate::par::{self, Runner};
use crate::plan::{FnPlan, Response};
use crate::record::{OutcomeKind, RunRecord, RunSpec};
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
        Type::S8 | Type::U8 | Type::S16 | Type::U16 | Type::S32 | Type::U32 | Type::S64 | Type::U64 | Type::Float32 | Type::Float64 => s.number = true,
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
/// `only`). Returns the probes and the findings they produced. A crash or
/// hang there is `crash_on_host_value` / `hang_on_host_value`, unless the
/// request fails the same way without the odd value.
pub fn values(app: &App, base: &RunSpec, only: Option<&str>, run: Runner) -> (Vec<ValueProbe>, Vec<Finding>) {
    let base = RunSpec { plan: steady(&base.plan), ..base.clone() };
    let mut probes = Vec::new();
    let mut findings = Vec::new();
    let funcs = app.imports.iter().filter(|i| i.kind == ImportKind::Platform).flat_map(|i| i.funcs.iter());
    let mut tries = Vec::new();
    for f in funcs.filter(|f| only.is_none_or(|o| f.key.contains(o))) {
        let Some(t) = f.ty.results().next() else { continue };
        // A call that never fails still answers with odd values.
        let never_fails = app.manifest.function(&f.key).and_then(|s| s.fails) == Some(false);
        for (variant, opts) in variants(&t).into_iter().filter(|(v, _)| !(never_fails && *v == "err")) {
            let mut spec = base.clone();
            if let Some(q) = app.manifest.function(&f.key).and_then(|s| s.query.as_ref()) {
                if matches!(variant, "empty list" | "long list") {
                    spec.plan.0.entry("_defaults".into()).or_default().dataset_rows.insert(q.dataset.clone(), opts.list_len.unwrap());
                    tries.push((f, variant, spec));
                    continue;
                }
                if !matches!(variant, "err" | "none") {
                    continue;
                }
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
    // A crash the request has without the odd value is not its doing.
    let own = run(&base);
    let always: Vec<String> =
        crate::detect::per_run_checked(app, &own).into_iter().filter(|x| matches!(x.kind.as_str(), "crash" | "hang")).map(|x| x.title).collect();
    for ((f, variant, _), r) in tries.into_iter().zip(runs) {
        probes.push(ValueProbe { func: f.key.clone(), variant: variant.into(), run: r.id.clone(), outcome: r.outcome.kind, host_calls: r.totals.host_calls });
        for mut x in crate::detect::per_run_checked(app, &r) {
            // Name the value that caused it.
            if matches!(x.kind.as_str(), "crash" | "hang") && !always.contains(&x.title) {
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
/// `crash_at_time` / `hang_at_time` finding, unless the request fails the
/// same way at its own time: then the time is not the cause.
pub fn times(app: &App, base: &RunSpec, run: Runner) -> (Vec<TimeProbe>, Vec<Finding>) {
    // A hang ends at twice the production limit.
    let fuel = base.fuel.min(app.manifest.limits.fuel.saturating_mul(2));
    let base = RunSpec { plan: steady(&base.plan), fuel, ..base.clone() };
    let mut probes = Vec::new();
    let mut findings = Vec::new();
    let mut specs: Vec<RunSpec> = EDGE_TIMES
        .iter()
        .map(|(now, _)| {
            let mut spec = base.clone();
            spec.now = now.to_string();
            // Request fields that carry the clock follow `now`.
            if let Some(e) = app.manifest.entry.as_ref() {
                e.set_clock(&mut spec.args, now);
            }
            spec
        })
        .collect();
    specs.push(base);
    let mut runs = par::map(&specs, |s| run(s));
    let own = runs.pop().expect("the run at the request's own time");
    let always: Vec<String> =
        crate::detect::per_run_checked(app, &own).into_iter().filter(|x| matches!(x.kind.as_str(), "crash" | "hang")).map(|x| x.title).collect();
    for ((now, what), r) in EDGE_TIMES.iter().zip(runs) {
        probes.push(TimeProbe { now: now.to_string(), what: what.to_string(), run: r.id.clone(), outcome: r.outcome.kind });
        for mut x in crate::detect::per_run_checked(app, &r) {
            if matches!(x.kind.as_str(), "crash" | "hang") && !always.contains(&x.title) {
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

#[derive(Debug, Clone, Serialize)]
pub struct WebProbe {
    pub what: String,
    pub run: String,
    pub outcome: OutcomeKind,
}

/// The request from a foreign website and claiming a foreign host
/// (`web::variants`); `permissive_cors` and `host_header_injection` come
/// from these runs. Nothing for an entry without `uri` and `headers`.
pub fn web(app: &App, base: &RunSpec, run: Runner) -> (Vec<WebProbe>, Vec<Finding>) {
    let Some(req) = base.args.first() else { return (vec![], vec![]) };
    let variants = crate::web::variants(req, &app.manifest);
    let specs: Vec<RunSpec> = variants
        .iter()
        .map(|(_, v)| {
            let mut s = base.clone();
            s.args[0] = v.clone();
            s
        })
        .collect();
    let runs = par::map(&specs, |s| run(s));
    let mut probes = Vec::new();
    let mut findings = Vec::new();
    for ((what, _), r) in variants.iter().zip(runs) {
        probes.push(WebProbe { what: what.clone(), run: r.id.clone(), outcome: r.outcome.kind });
        findings.extend(crate::detect::per_run_checked(app, &r));
    }
    (probes, findings)
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthProbe {
    pub path: String,
    pub what: String,
    pub run: String,
    pub outcome: OutcomeKind,
}

/// Each base request without credentials; where that is turned away, with
/// forged ones (`auth::forged`): `auth_bypass` comes from comparing them.
/// Where the app reads a secret to check them, the secret's prefixes:
/// `timing_unsafe_compare`. Session tokens in the responses, with other
/// random seeds and a second later: `predictable_token`. Bases with the same
/// method and path are tried once.
pub fn auth(app: &App, bases: &[RunSpec], run: Runner) -> (Vec<AuthProbe>, Vec<Finding>) {
    let m = &app.manifest;
    let mut seen = std::collections::BTreeSet::new();
    let anon: Vec<RunSpec> = bases
        .iter()
        .filter_map(|b| {
            let req = crate::auth::anonymous(b.args.first()?)?;
            seen.insert(format!("{} {}", req["method"].as_str().unwrap_or_default(), crate::auth::path(&req))).then(|| {
                let mut s = b.clone();
                s.args[0] = req;
                s
            })
        })
        .collect();
    let anon_runs = par::map(&anon, |s| run(s));
    let mut probes = Vec::new();
    let mut findings = Vec::new();
    let (mut bypass, mut timing) = (false, false);
    let mut issuing: Vec<RunRecord> = Vec::new();
    for (s, a) in anon.iter().zip(&anon_runs) {
        let p = crate::auth::path(&s.args[0]);
        probes.push(AuthProbe { path: p.clone(), what: "no credentials".into(), run: a.id.clone(), outcome: a.outcome.kind });
        issuing.push(a.clone());
        if crate::auth::rejected(a, m).is_none() {
            continue;
        }
        let forged = forged_runs(s, None, run);
        for (f, r) in &forged {
            probes.push(AuthProbe { path: p.clone(), what: f.what.into(), run: r.id.clone(), outcome: r.outcome.kind });
            findings.extend(crate::detect::per_run_checked(app, r));
        }
        let pairs: Vec<(&crate::auth::Forged, &RunRecord)> = forged.iter().map(|(f, r)| (f, r)).collect();
        if !bypass && let Some(f) = crate::auth::check(a, &pairs, m) {
            findings.push(f);
            bypass = true;
        }
        if !timing {
            for (f, r) in &pairs {
                let Some((finding, with_secret)) = secret_prefixes(app, f.what, r, run, &mut probes) else { continue };
                issuing.extend(with_secret);
                if let Some(x) = finding {
                    findings.push(x);
                    timing = true;
                    break;
                }
            }
        }
    }
    findings.extend(predictable_tokens(app, &issuing, run, &mut probes));
    (probes, findings)
}

/// One of `probe auth`'s checks again, from `spec`: what `confirm` shrinks
/// and `replay` repeats.
pub fn auth_again(app: &App, recipe: &crate::auth::Recipe, spec: &RunSpec, run: Runner) -> Vec<Finding> {
    use crate::auth::Recipe;
    match recipe {
        Recipe::Bypass { forged } => {
            let Some(req) = spec.args.first().and_then(crate::auth::anonymous) else { return Vec::new() };
            let mut s = spec.clone();
            s.args[0] = req;
            let a = run(&s);
            if crate::auth::rejected(&a, &app.manifest).is_none() {
                return Vec::new();
            }
            let forged = forged_runs(&s, Some(forged), run);
            let pairs: Vec<(&crate::auth::Forged, &RunRecord)> = forged.iter().map(|(f, r)| (f, r)).collect();
            crate::auth::check(&a, &pairs, &app.manifest).into_iter().collect()
        }
        Recipe::Timing { forged } => {
            let r = run(spec);
            secret_prefixes(app, forged, &r, run, &mut Vec::new()).and_then(|(f, _)| f).into_iter().collect()
        }
        Recipe::Token => predictable_tokens(app, &[run(spec)], run, &mut Vec::new()),
    }
}

/// The request `s` (without credentials) with forged ones, all or the one
/// named `only`, and their runs.
fn forged_runs(s: &RunSpec, only: Option<&str>, run: Runner) -> Vec<(crate::auth::Forged, RunRecord)> {
    let forged: Vec<crate::auth::Forged> = crate::auth::forged(&s.args[0]).into_iter().filter(|f| only.is_none_or(|w| f.what == w)).collect();
    let specs: Vec<RunSpec> = forged
        .iter()
        .map(|f| {
            let mut v = s.clone();
            v.args[0] = f.request.clone();
            v
        })
        .collect();
    let runs = par::map(&specs, |s| run(s));
    forged.into_iter().zip(runs).collect()
}

/// The forged credential `forged` in run `r` replaced by prefixes of the
/// secret the app read while checking it: the finding, and the run with
/// the whole secret. Only for a credential the app compared (a bearer
/// token or an API key).
fn secret_prefixes(app: &App, forged: &str, r: &RunRecord, run: Runner, probes: &mut Vec<AuthProbe>) -> Option<(Option<Finding>, Option<RunRecord>)> {
    let (what, header, prefix) = match forged {
        "a made-up bearer token" => ("the bearer token", "authorization", "Bearer "),
        "a made-up API key" => ("the API key", "x-api-key", ""),
        _ => return None,
    };
    let secret = crate::auth::secrets(r, &app.manifest).into_iter().next()?;
    let base = crate::metamorphic::pinned(r).unwrap_or_else(|| r.spec.clone());
    let with = |text: String| {
        let mut s = base.clone();
        for h in s.args[0]["headers"].as_array_mut().into_iter().flatten() {
            if h.get(0).and_then(Value::as_str).is_some_and(|k| k.eq_ignore_ascii_case(header)) {
                h[1] = json!(format!("{prefix}{text}"));
            }
        }
        s
    };
    let lengths = crate::auth::prefix_lengths(&secret);
    let mut specs: Vec<RunSpec> = lengths.iter().map(|&k| with(crate::auth::prefix_of(&secret, k, 1))).collect();
    specs.push(with(crate::auth::prefix_of(&secret, 0, 2)));
    specs.push(with(secret.clone()));
    let mut runs = par::map(&specs, |s| run(s));
    let full = runs.pop();
    let control = runs.pop()?;
    let p = crate::auth::path(&base.args[0]);
    for (k, x) in lengths.iter().zip(&runs) {
        probes.push(AuthProbe { path: p.clone(), what: format!("{what}: {k} characters of the secret"), run: x.id.clone(), outcome: x.outcome.kind });
    }
    let refs: Vec<&RunRecord> = runs.iter().collect();
    let recipe = crate::auth::Recipe::Timing { forged: forged.into() };
    Some((crate::auth::timing(&r.spec.export, what, &lengths, &refs, &control).map(|f| recipe.mark(f, &r.id)), full))
}

/// Runs that issue session tokens, again with two other random seeds and a
/// second later, host answers pinned.
fn predictable_tokens(app: &App, issuing: &[RunRecord], run: Runner, probes: &mut Vec<AuthProbe>) -> Vec<Finding> {
    let m = &app.manifest;
    let mut findings = Vec::new();
    for r in issuing.iter().filter(|r| !crate::auth::tokens(r, m).is_empty()).take(8) {
        let Some(mut base) = crate::metamorphic::pinned(r) else { continue };
        if !m.datasets.is_empty() {
            let d = base.plan.0.entry("_defaults".into()).or_default();
            d.dataset_seed = Some(d.dataset_seed.unwrap_or(r.spec.seed));
        }
        let mut specs: Vec<RunSpec> = (1..=2).map(|k| RunSpec { seed: base.seed.wrapping_add(k), ..base.clone() }).collect();
        if let Some(t) = crate::wasi::parse_datetime(&base.now) {
            let (d, _, hms) = crate::wasi::format_datetime(t + 1);
            let mut later = RunSpec { now: format!("{d}T{hms}"), ..base.clone() };
            if let Some(e) = m.entry.as_ref().filter(|e| crate::harness::fn_key_eq(&e.export, &base.export)) {
                let now = later.now.clone();
                e.set_clock(&mut later.args, &now);
            }
            specs.push(later);
        }
        let runs = par::map(&specs, |s| run(s));
        let p = crate::auth::path(&base.args[0]);
        for (x, what) in runs.iter().zip(["another random seed", "a third random seed", "a second later"]) {
            probes.push(AuthProbe { path: p.clone(), what: format!("the session token with {what}"), run: x.id.clone(), outcome: x.outcome.kind });
        }
        let seeds: Vec<&RunRecord> = runs.iter().take(2).collect();
        findings.extend(crate::auth::predictable(r, &seeds, runs.get(2), m).into_iter().map(|f| crate::auth::Recipe::Token.mark(f, &r.id)));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The result type of each function `wit`'s world exports, by name.
    fn results(wit: &str) -> std::collections::BTreeMap<String, Type> {
        let mut resolve = wit_parser::Resolve::new();
        let pkg = resolve.push_str("probe.wit", wit).unwrap();
        let world = resolve.select_world(&[pkg], None).unwrap();
        let mut module = wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
        wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
        let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
        let engine = crate::harness::engine().unwrap();
        let component = wasmtime::component::Component::new(&engine, &bytes).unwrap();
        crate::wit::exports(&engine, &component).into_iter().filter_map(|f| Some((f.name.clone(), f.ty.results().next()?))).collect()
    }

    const STRINGS: [&str; 7] =
        ["empty strings", "unicode strings", "2-byte chars", "3-byte chars", "3-byte chars after 1 byte", "4-byte chars", "long strings"];

    #[test]
    fn value_classes_follow_the_result_type() {
        let types = results(
            r#"package test:probe;
            world app {
              record item { tags: list<char>, at: tuple<s8, f64> }
              variant answer { found(option<u8>), gone }
              export ids: func() -> list<u32>;
              export count: func() -> result<u32, string>;
              export done: func() -> result;
              export flag: func() -> option<bool>;
              export yes: func() -> bool;
              export name: func() -> string;
              export item: func() -> item;
              export answer: func() -> answer;
              export nothing: func();
            }"#,
        );
        let names = |f: &str| variants(&types[f]).into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        let with = |head: &[&'static str]| [head, &STRINGS[..]].concat();
        assert_eq!(names("ids"), ["empty list", "long list", "edge numbers"]);
        assert_eq!(names("count"), with(&["err", "edge numbers"]));
        assert_eq!(names("done"), ["err"]);
        assert_eq!(names("flag"), ["none"]);
        assert!(names("yes").is_empty(), "a bool has no edge values worth a run");
        assert_eq!(names("name"), with(&[]));
        // Lists, numbers and strings anywhere in a record, a tuple or a variant.
        assert_eq!(names("item"), with(&["empty list", "long list", "edge numbers"]));
        assert_eq!(names("answer"), ["none", "edge numbers"]);
        assert!(!types.contains_key("nothing"));
    }

    #[test]
    fn each_value_class_changes_one_option() {
        let types = results("package test:probe; world app { export get: func() -> result<option<list<u8>>, string>; }");
        let classes = variants(&types["get"]);
        assert_eq!(classes.len(), 5 + STRINGS.len());
        for (name, opts) in &classes {
            opts.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
            let one = || GenOpts { list_len: Some(1), ..Default::default() };
            let expect = match *name {
                "empty list" => GenOpts { list_len: Some(0), ..one() },
                "long list" => GenOpts { list_len: Some(50), ..one() },
                "err" => GenOpts { results: Some("err".into()), ..one() },
                "none" => GenOpts { options: Some("none".into()), ..one() },
                "edge numbers" => GenOpts { numbers: Some("edge".into()), ..one() },
                "empty strings" => GenOpts { strings: Some("empty".into()), ..one() },
                "unicode strings" => GenOpts { strings: Some("unicode".into()), ..one() },
                "2-byte chars" => GenOpts { strings: Some("utf8-2".into()), ..one() },
                "3-byte chars" => GenOpts { strings: Some("utf8-3".into()), ..one() },
                "3-byte chars after 1 byte" => GenOpts { strings: Some("utf8-3o".into()), ..one() },
                "4-byte chars" => GenOpts { strings: Some("utf8-4".into()), ..one() },
                "long strings" => GenOpts { strings: Some("long".into()), ..one() },
                other => panic!("unexpected class {other}"),
            };
            assert_eq!(serde_json::to_value(opts).unwrap(), serde_json::to_value(&expect).unwrap(), "{name}");
        }
    }

    #[test]
    fn edge_times_are_the_times_they_name() {
        let mut seen = std::collections::BTreeSet::new();
        // Monday is 0; 1970-01-01 was a Thursday.
        let weekday = |t: i64| (t.div_euclid(86_400) + 3).rem_euclid(7);
        for (now, what) in EDGE_TIMES {
            let t = crate::wasi::parse_datetime(now).unwrap_or_else(|| panic!("{now} ({what}) does not parse"));
            let (date, _, time) = crate::wasi::format_datetime(t);
            assert_eq!(format!("{date}T{time}"), *now, "{what}: no such time");
            assert!(seen.insert(t), "{now} twice");
            let day: u32 = date[8..].parse().unwrap();
            match *what {
                "leap day" => assert!(date.ends_with("-02-29")),
                "first second of the year" => assert!(date.ends_with("-01-01") && time == "00:00:00"),
                "last second of the year" => assert!(date.ends_with("-12-31") && time == "23:59:59"),
                // The last Sunday of March and of October, the second Sunday of March.
                "EU DST gap" | "EU DST overlap" => assert!(weekday(t) == 6 && day + 7 > 31, "{what}: {date}"),
                "US DST gap" => assert!(weekday(t) == 6 && (8..=14).contains(&day), "{what}: {date}"),
                "midnight on a Monday" => assert!(weekday(t) == 0 && time == "00:00:00"),
                "end of a Sunday" => assert!(weekday(t) == 6 && time == "23:59:59"),
                "after the 32-bit epoch overflow" => assert_eq!(t, i64::from(i32::MAX) + 1),
                "the Unix epoch" => assert_eq!(t, 0),
                _ => {}
            }
        }
        let whats: std::collections::BTreeSet<_> = EDGE_TIMES.iter().map(|(_, w)| w).collect();
        assert_eq!(whats.len(), EDGE_TIMES.len(), "two edge times with one name");
    }
}
