//! Commands to dig into runs: check a property, sweep a field, compare
//! two runs, trace where a host argument came from, profile guest work,
//! explain a run, list host call sites never reached, WASI usage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use appfuzz_core::assertion::Assertion;
use appfuzz_core::check::Property;
use appfuzz_core::detect::{self, Finding};
use appfuzz_core::dormant;
use appfuzz_core::fuzz;
use appfuzz_core::harness::{App, field, field_mut};
use appfuzz_core::output::response;
use appfuzz_core::record::{OutcomeKind, RunRecord, RunSpec};
use appfuzz_core::statics::Statics;
use appfuzz_core::store::RunStore;
use appfuzz_core::wit::{self, ImportKind};

use super::{Cli, diff, lock, ms, record_findings, run_cached};

/// `--let name=path` arguments as a map.
fn lets_of(lets: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for l in lets {
        let (k, v) = l.split_once('=').ok_or_else(|| anyhow!("--let needs name=path, got {l:?}"))?;
        if out.insert(k.trim().to_string(), v.trim().to_string()).is_some() {
            bail!("--let binds {} twice", k.trim());
        }
    }
    Ok(out)
}

fn assertion(app: &App, export: &str, expr: &str, lets: &[String], assume: Option<&str>) -> Result<Assertion> {
    let a = Assertion::new(&lets_of(lets)?, expr, assume)?;
    appfuzz_core::assertion::validate_wit(&a.bindings, &app.imports, &app.exports, Some(export))?;
    Ok(a)
}

/// Evaluates an expression on a stored run: every binding, the value, the verdict.
pub fn eval(app: &App, r: &RunRecord, expr: &str, lets: &[String], assume: Option<&str>) -> Result<Value> {
    let a = assertion(app, &r.spec.export, expr, lets, assume)?;
    let mut bindings = Map::new();
    let mut values = BTreeMap::new();
    for b in &a.bindings {
        match b.resolve(r, &app.manifest) {
            Ok(v) => {
                bindings.insert(b.name.clone(), json!({"path": b.path, "value": appfuzz_core::assertion::shorten(&v)}));
                values.insert(b.name.clone(), v);
            }
            Err(e) => {
                bindings.insert(b.name.clone(), json!({"path": b.path, "undefined": e}));
            }
        }
    }
    let defined = values.len() == a.bindings.len();
    let value = if defined { a.value(&values).map_or_else(|e| json!({"error": e}), |v| json!(v)) } else { Value::Null };
    let (status, _, detail) = appfuzz_core::assertion::status(&a, r, &app.manifest);
    Ok(json!({"run": r.id, "expression": a.expr.text, "assume": a.assume.as_ref().map(|x| &x.text), "bindings": bindings, "value": value,
        "status": status, "detail": detail,
        "note": "status is what a saved acceptance check would report for this run; `value` is the whole expression, which need not be true or false here"}))
}

/// Binding paths for this app: sources, host functions with signatures, request fields, and example values.
pub fn bindings(app: &App, run: Option<RunRecord>) -> Result<Value> {
    let example = |path: &str| -> Value {
        let Some(r) = &run else { return Value::Null };
        match appfuzz_core::assertion::Binding::parse("x", path) {
            Ok(b) => b.resolve(r, &app.manifest).map_or_else(|e| json!({"undefined": e}), |v| appfuzz_core::assertion::shorten(&v)),
            Err(_) => Value::Null,
        }
    };
    let funcs: Vec<&wit::FuncInfo> = app.imports.iter().filter(|i| i.kind == ImportKind::Platform).flat_map(|i| &i.funcs).collect();
    let short = |key: &str| -> String {
        let s = key.rsplit_once('/').map_or(key, |(_, s)| s);
        if funcs.iter().filter(|f| appfuzz_core::assertion::fn_matches(&f.key, s)).count() == 1 { s.to_string() } else { key.to_string() }
    };
    let mut host = Vec::new();
    for f in &funcs {
        let k = short(&f.key);
        let mut paths = vec![format!("host.{k}.calls"), format!("host.{k}.results")];
        if f.ty.results().next().is_some() {
            paths.push(format!("host.{k}.result"));
        }
        paths.extend(f.ty.params().map(|(p, _)| format!("host.{k}.args.{p}")));
        host.push(
            json!({"func": f.key, "signature": f.signature(), "paths": paths.iter().map(|p| json!({"path": p, "example": example(p)})).collect::<Vec<_>>()}),
        );
    }
    let mut request = Vec::new();
    if let Some(req) = run
        .as_ref()
        .and_then(|r| r.spec.args.first())
        .cloned()
        .or_else(|| app.default_export().ok().and_then(|e| app.default_args(e, &app.manifest.start_time()).ok()).and_then(|a| a.into_iter().next()))
    {
        fn walk(v: &Value, prefix: &str, out: &mut Vec<String>, depth: usize) {
            match v {
                Value::Object(o) if depth < 3 => o.iter().for_each(|(k, x)| walk(x, &format!("{prefix}.{k}"), out, depth + 1)),
                Value::Array(a) if a.iter().all(|p| p.as_array().is_some_and(|p| p.len() == 2 && p[0].is_string())) => {
                    if a.is_empty() {
                        out.push(format!("{prefix}.<name>"));
                    }
                    for p in a {
                        out.push(format!("{prefix}.{}", p[0].as_str().unwrap_or_default()));
                    }
                }
                _ => out.push(prefix.to_string()),
            }
        }
        let mut paths = Vec::new();
        walk(&req, "request", &mut paths, 0);
        request = paths.iter().map(|p| json!({"path": p, "example": if p.contains('<') { Value::Null } else { example(p) }})).collect();
    }
    let output: Vec<Value> =
        ["out.status", "out.body", "out.headers", "out.result", "out.json"].iter().map(|p| json!({"path": p, "example": example(p)})).collect();
    let run_wide: Vec<Value> =
        ["calls", "totals", "clock.now", "clock.today", "clock.time", "logs", "outcome"].iter().map(|p| json!({"path": p, "example": example(p)})).collect();
    Ok(json!({
        "run": run.as_ref().map(|r| &r.id),
        "sources": appfuzz_core::assertion::SOURCES.iter().map(|(p, d)| json!({"path": p, "gives": d})).collect::<Vec<_>>(),
        "functions": appfuzz_core::assertion::FUNCTIONS.iter().map(|(f, d)| json!({"function": f, "gives": d})).collect::<Vec<_>>(),
        "request": request, "host": host, "output": output, "run_wide": run_wide,
        "notes": ["a trailing ? makes a missing value null: request.form.note?",
                  "host.<fn>.result is undefined unless the function was called exactly once; bind .results or .calls otherwise",
                  "select <selector> gives a list of texts: select .row, select #total, select /Total: (\\d+)/"],
    }))
}

/// Fuzzes until a run breaks the property, then shrinks that run.
pub fn check(cli: &Cli, app: &App, store: &RunStore, base: &RunSpec, prop: Property, opts: fuzz::FuzzOpts, max_runs: u32) -> Result<Value> {
    // Stored runs first: a counterexample may be at hand.
    let stored = store.all()?.into_iter().filter(|r| r.spec.component == app.hash && r.spec.contract == app.contract && r.spec.export == base.export);
    let stored: Vec<_> = stored.collect();
    let matches = AtomicU64::new(stored.iter().map(|r| prop.matches(r, &app.manifest) as u64).sum());
    let mut hit = stored.into_iter().filter(|r| prop.broken(r, &app.manifest).is_some()).min_by_key(|r| (r.totals.host_calls, r.totals.fuel));
    let mut searched = json!({"stored_runs": true});
    if hit.is_none() {
        let fstore = detect::FindingStore::new(&cli.state, &app.state_key);
        let known = fstore.all()?.into_iter().filter(|f| f.kind != "check_failed").map(|f| f.id).collect();
        let prior = fuzz::Corpus::load(&cli.state, &app.state_key)?.entries;
        let opts = fuzz::FuzzOpts { property: Some(prop.clone()), stop_on: Some("check_failed".into()), ..opts };
        let save_err = Mutex::new(None);
        let on_run = |r: &RunRecord, kept: bool, found: &[Finding]| {
            matches.fetch_add(prop.matches(r, &app.manifest) as u64, Ordering::Relaxed);
            if (kept || !found.is_empty())
                && let Err(e) = store.save(r)
            {
                *lock(&save_err) = Some(e);
            }
        };
        let (rep, corpus) = fuzz::fuzz(app, base, prior, known, &opts, &on_run)?;
        if let Some(e) = lock(&save_err).take() {
            return Err(e);
        }
        corpus.save(&cli.state)?;
        searched = json!({"stored_runs": true, "fuzz_runs": rep.runs, "elapsed_ms": rep.elapsed_ms, "stopped": rep.stopped});
        hit = rep.findings.iter().filter(|f| f.kind == "check_failed").find_map(|f| f.run.as_ref().and_then(|id| store.get(id).ok().flatten()));
    }
    let Some(orig) = hit else {
        let n = matches.load(Ordering::Relaxed);
        return Ok(json!({"property": prop.text, "holds": if n > 0 { json!(true) } else { Value::Null },
            "status": if n > 0 { "holds" } else { "not_exercised" }, "matches": n,
            "exit_code": if n > 0 { 0 } else { 3 }, "searched": searched,
            "note": if n > 0 { "no exercised value broke the property" } else { "no applicable values matched; check the selector and request" }}));
    };
    let keeps = |r: &RunRecord| prop.broken(r, &app.manifest).is_some();
    let runner = |s: &RunSpec| app.run(s);
    let default = app.default_args(app.export(&orig.spec.export)?, &orig.spec.now)?;
    let (spec, shrink_runs) = appfuzz_core::shrink::minimise(app, &orig.spec, &default, &keeps, max_runs, &runner);
    let min = app.run(&spec);
    store.save(&min)?;
    let (why, detail) = prop.broken(&min, &app.manifest).or_else(|| prop.broken(&orig, &app.manifest)).unwrap_or_default();
    let mut changed = Vec::new();
    diff(&json!(default), &json!(spec.args), String::new(), &mut changed);
    let found = prop.finding(&min, &app.manifest).into_iter().collect();
    Ok(json!({
        "property": prop.text, "holds": false, "status": "broken", "matches": matches.load(Ordering::Relaxed), "exit_code": 2, "searched": searched,
        "counterexample": {
            "run": min.id, "original_run": orig.id, "shrink_runs": shrink_runs,
            "size_before": appfuzz_core::shrink::size(&orig.spec), "size_after": appfuzz_core::shrink::size(&spec), "why": why, "detail": detail,
            "request_changes": changed, "plan": spec.plan, "now": spec.now, "seed": spec.seed,
            // Generated values are not in the plan: what the host returned.
            "host_results": min.events.iter().map(|e| json!({"n": e.n, "func": e.func, "result": e.result})).collect::<Vec<_>>(),
        },
        "findings": record_findings(cli, app, found)?,
    }))
}

const SWEEP_NUMBERS: &[&str] = &[
    "-2147483648",
    "-1",
    "0",
    "1",
    "2",
    "7",
    "10",
    "99",
    "100",
    "101",
    "255",
    "256",
    "1000",
    "65535",
    "65536",
    "2147483647",
    "2147483648",
    "9007199254740993",
];
const SWEEP_DATES: &[&str] = &[
    "2026-02-28",
    "2026-02-29",
    "2028-02-29",
    "2026-12-31",
    "2027-01-01",
    "1970-01-01",
    "2038-01-19",
    "9999-12-31",
    "2026-13-01",
    "2026-00-10",
    "2026-1-1",
    "26-01-01",
    "",
];
const SWEEP_TIMES: &[&str] = &["00:00", "00:01", "11:59", "12:00", "23:59", "24:00", "12:60", "-1:00", "9:5", "02:30", ""];
const SWEEP_STRINGS: &[&str] =
    &["", " ", "a", "Zoë", "東京", "👩\u{200d}💻", "<b>x</b>", "\"'<>&", "../..", "%00", "a\r\nb", "\u{202e}x", "null", "0", "-1", "true"];

/// Values for a sweep kind.
pub fn sweep_values(kind: &str, st: &Statics) -> Result<Vec<String>> {
    Ok(match kind {
        "numbers" => SWEEP_NUMBERS.iter().map(|s| s.to_string()).collect(),
        "dates" => SWEEP_DATES.iter().map(|s| s.to_string()).collect(),
        "times" => SWEEP_TIMES.iter().map(|s| s.to_string()).collect(),
        "strings" => SWEEP_STRINGS.iter().map(|s| s.to_string()).collect(),
        "words" => appfuzz_core::scale::dictionary(st, 60),
        "lengths" => [0usize, 1, 8, 64, 256, 1024, 4096, 65536].iter().map(|n| "a".repeat(*n)).collect(),
        k => bail!("--gen must be numbers, dates, times, strings, words or lengths, not {k:?}"),
    })
}

/// Sets a request field to a value: a number where the field is one.
fn set_value(req: &mut Value, path: &str, v: &str) -> Result<()> {
    let was_number = field(req, path).is_some_and(Value::is_number);
    appfuzz_core::scale::set_text(req, path, v)?;
    if was_number && let (Some(slot), Ok(n)) = (field_mut(req, path), v.parse::<serde_json::Number>()) {
        *slot = Value::Number(n);
    }
    Ok(())
}

/// One run per value of a request field.
pub fn sweep(cli: &Cli, app: &App, store: &RunStore, base: &RunSpec, path: &str, values: Vec<String>) -> Result<Value> {
    let mut specs = Vec::new();
    for v in &values {
        let mut s = base.clone();
        let req = s.args.first_mut().ok_or_else(|| anyhow!("the export takes no arguments"))?;
        set_value(req, path, v)?;
        specs.push(s);
    }
    let runs = appfuzz_core::par::map(&specs, |s| run_cached(app, store, s)).into_iter().collect::<Result<Vec<_>>>()?;
    let mut found = Vec::new();
    let mut rows = Vec::new();
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (v, r) in values.iter().zip(&runs) {
        let resp = response(r, &app.manifest);
        let text = resp.body.as_deref().map(visible_text).unwrap_or_default();
        let shown: String = text.chars().take(100).collect();
        let fs = detect::per_run(r, &app.manifest);
        groups
            .entry(format!(
                "{} {} {}",
                detect::kind_name(r.outcome.kind),
                resp.status.map_or("-".into(), |s| s.to_string()),
                r.call_counts().iter().map(|(f, n)| format!("{f}={n}")).collect::<Vec<_>>().join(",")
            ))
            .or_default()
            .push(short(v));
        rows.push(json!({
            "value": short(v), "outcome": r.outcome.kind, "status": resp.status, "host_calls": r.totals.host_calls,
            "virtual_ms": ms(r.totals.virtual_ns), "fuel": r.totals.fuel, "text": shown, "findings": fs.iter().map(|f| &f.kind).collect::<Vec<_>>(), "run": r.id,
        }));
        found.extend(fs);
    }
    Ok(json!({
        "field": path, "values": values.len(), "table": rows,
        // Values that behave alike (outcome, status, calls): the edges are between groups.
        "behaviours": groups.into_iter().map(|(k, vs)| json!({"behaviour": k, "values": vs})).collect::<Vec<_>>(),
        "findings": record_findings(cli, app, found)?,
    }))
}

/// Whole numbers without `.0`.
fn num(x: f64) -> Value {
    if x.fract() == 0.0 && x.abs() < 9e15 { json!(x as i64) } else { json!(x) }
}

fn short(v: &str) -> String {
    if v.len() > 40 { format!("{}…[{} bytes]", v.chars().take(20).collect::<String>(), v.len()) } else { v.to_string() }
}

fn visible_text(body: &str) -> String {
    static TAGS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"<[^>]*>").unwrap());
    TAGS.replace_all(body, " ").split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Body lines for a line diff: one tag or text run per line.
fn body_lines(body: &str) -> Vec<String> {
    body.replace("><", ">\n<").lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

/// What differs between two runs: input, outcome, totals, calls, the
/// first host call that differs, and the output.
pub fn diff_runs(app: &App, a: &RunRecord, b: &RunRecord) -> Value {
    let mut input = Vec::new();
    let (sa, sb) = (serde_json::to_value(&a.spec).unwrap_or_default(), serde_json::to_value(&b.spec).unwrap_or_default());
    diff(&sa, &sb, String::new(), &mut input);
    let (ta, tb) = (&a.totals, &b.totals);
    let delta = |x: f64, y: f64| json!({"a": num(x), "b": num(y), "delta": num(((y - x) * 100.0).round() / 100.0)});
    let cost_delta = if tb.cost >= ta.cost {
        appfuzz_core::wide::json(tb.cost - ta.cost)
    } else if ta.cost - tb.cost <= 1u128 << 63 {
        json!((-((ta.cost - tb.cost) as i128)) as i64)
    } else {
        json!(format!("-{}", ta.cost - tb.cost))
    };
    let totals = json!({
        "fuel": delta(ta.fuel as f64, tb.fuel as f64), "host_calls": delta(ta.host_calls as f64, tb.host_calls as f64),
        "virtual_ms": delta(ms(ta.virtual_ns), ms(tb.virtual_ns)),
        "cost": {"a":appfuzz_core::wide::json(ta.cost), "b":appfuzz_core::wide::json(tb.cost), "delta":cost_delta},
        "peak_memory": delta(ta.peak_memory as f64, tb.peak_memory as f64),
    });
    let (ca, cb): (BTreeMap<String, u32>, BTreeMap<String, u32>) = (a.call_counts().into_iter().collect(), b.call_counts().into_iter().collect());
    let calls: Vec<Value> = ca
        .keys()
        .chain(cb.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|f| ca.get(*f) != cb.get(*f))
        .map(|f| json!({"func": f, "a": ca.get(f).copied().unwrap_or(0), "b": cb.get(f).copied().unwrap_or(0)}))
        .collect();
    let first = a.events.iter().zip(&b.events).position(|(x, y)| x.func != y.func || x.args != y.args || x.result != y.result || x.trap != y.trap);
    let diverges = match first {
        Some(i) => {
            let (x, y) = (&a.events[i], &b.events[i]);
            let what = if x.func != y.func {
                "function"
            } else if x.args != y.args {
                "arguments"
            } else {
                "result"
            };
            json!({"n": x.n, "differs_in": what, "a": {"func": x.func, "args": x.args, "result": x.result}, "b": {"func": y.func, "args": y.args, "result": y.result}})
        }
        None if a.events.len() != b.events.len() => {
            let n = a.events.len().min(b.events.len());
            json!({"n": n + 1, "differs_in": "length", "a_calls": a.events.len(), "b_calls": b.events.len()})
        }
        None => Value::Null,
    };
    let (ra, rb) = (response(a, &app.manifest), response(b, &app.manifest));
    let (la, lb) = (body_lines(ra.body.as_deref().unwrap_or("")), body_lines(rb.body.as_deref().unwrap_or("")));
    let minus = |x: &[String], y: &[String]| {
        let mut y = y.to_vec();
        x.iter()
            .filter(|l| match y.iter().position(|m| m == *l) {
                Some(i) => {
                    y.swap_remove(i);
                    false
                }
                None => true,
            })
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut result = Vec::new();
    if ra.body.is_none() {
        diff(&a.result.clone().unwrap_or_default(), &b.result.clone().unwrap_or_default(), String::new(), &mut result);
    }
    json!({
        "a": a.id, "b": b.id,
        "input": input.into_iter().filter(|d| !d["path"].as_str().is_some_and(|p| p == "component")).collect::<Vec<_>>(),
        "outcome": {"a": a.outcome.kind, "b": b.outcome.kind},
        "status": {"a": ra.status, "b": rb.status},
        "totals": totals, "calls": calls, "first_different_call": diverges,
        "output": {"only_in_a": minus(&la, &lb), "only_in_b": minus(&lb, &la), "result": result},
        "same_output": a.result == b.result,
    })
}

/// Leaf values of a JSON value with their paths (`query.q`, pairs by key).
fn leaves(v: &Value, path: String, out: &mut Vec<(String, Value)>) {
    match v {
        Value::Array(a) if !a.is_empty() && a.iter().all(|p| p.as_array().is_some_and(|p| p.len() == 2 && p[0].is_string())) => {
            for p in a {
                leaves(&p[1], format!("{path}.{}", p[0].as_str().unwrap_or_default()), out);
            }
        }
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| leaves(x, format!("{path}[{i}]"), out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| leaves(x, if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, out)),
        Value::Null => {}
        _ => out.push((path, v.clone())),
    }
}

fn days(s: &str) -> Option<i64> {
    let d = s.get(..10)?;
    appfuzz_core::wasi::parse_datetime(d).filter(|_| d.as_bytes().get(4) == Some(&b'-')).map(|t| t / 86_400)
}

/// An earlier host call: number, function, leaves of its result.
type Earlier<'a> = (u32, &'a str, Vec<(String, Value)>);

/// Where each argument of host call N came from (heuristic: equal or
/// contained values).
pub fn provenance(app: &App, r: &RunRecord, n: u32) -> Result<Value> {
    let st = Statics::parse(&app.bytes)?;
    let e = r.events.iter().find(|e| e.n == n).ok_or_else(|| anyhow!("run {} has no host call {n}", r.id))?;
    let mut req = Vec::new();
    for (i, a) in r.spec.args.iter().enumerate() {
        leaves(a, if r.spec.args.len() == 1 { String::new() } else { format!("@{i}") }, &mut req);
    }
    let earlier: Vec<Earlier> = r
        .events
        .iter()
        .filter(|x| x.n < n)
        .map(|x| {
            let mut l = Vec::new();
            leaves(x.result.as_ref().unwrap_or(&Value::Null), String::new(), &mut l);
            (x.n, x.func.as_str(), l)
        })
        .collect();
    let consts: BTreeSet<&str> = st
        .modules
        .iter()
        .flat_map(|m| m.strings.iter().map(|(_, s)| s.as_str()).chain(m.funcs.iter().flat_map(|f| f.text_consts.iter().map(|(_, s)| s.as_str()))))
        .collect();
    let numbers: BTreeSet<i64> = st.modules.iter().flat_map(|m| m.funcs.iter().flat_map(|f| f.cmp_consts.iter().copied())).collect();
    let mut args = Vec::new();
    let mut mine = Vec::new();
    leaves(&Value::Object(e.args.clone()), String::new(), &mut mine);
    for (path, v) in mine {
        let text = v.as_str().map_or_else(|| v.to_string(), str::to_string);
        let mut sources = Vec::new();
        for (p, rv) in &req {
            let rt = rv.as_str().map_or_else(|| rv.to_string(), str::to_string);
            if rt == text {
                sources.push(json!({"from": "request", "field": p, "how": "equal"}));
            } else if rt.len() >= 3 && text.contains(&rt) {
                sources.push(json!({"from": "request", "field": p, "how": "contained"}));
            } else if let (Some(a), Some(b)) = (days(&rt), days(&text)) {
                sources.push(json!({"from": "request", "field": p, "how": format!("date {:+} days", b - a)}));
            }
        }
        for (m, f, l) in &earlier {
            for (p, rv) in l {
                let rt = rv.as_str().map_or_else(|| rv.to_string(), str::to_string);
                if rt == text {
                    sources.push(json!({"from": "host_result", "call": m, "func": f, "path": p}));
                }
            }
        }
        if sources.is_empty() {
            if v.is_string() && consts.iter().any(|c| *c == text || (text.len() >= 4 && c.contains(text.as_str()))) {
                sources.push(json!({"from": "binary", "how": "string constant"}));
            } else if v.as_i64().is_some_and(|x| numbers.contains(&x)) {
                sources.push(json!({"from": "binary", "how": "number the code compares with"}));
            }
        }
        sources.truncate(5);
        args.push(json!({"arg": path, "value": v, "sources": if sources.is_empty() { json!("unknown (computed)") } else { json!(sources) }}));
    }
    Ok(json!({"run": r.id, "n": n, "func": e.func, "args": args, "note": "heuristic: values are matched by equality and containment, not traced"}))
}

/// Guest instructions between host calls, by the function that was
/// running: `self` (innermost app frame) and `inclusive` (every frame).
pub fn profile(app: &App, r: &RunRecord, top: usize) -> Result<Value> {
    let st = Statics::parse(&app.bytes)?;
    let mut own: BTreeMap<String, u64> = BTreeMap::new();
    let mut incl: BTreeMap<String, u64> = BTreeMap::new();
    let mut prev = 0u64;
    for e in &r.events {
        let fuel = e.fuel_before.saturating_sub(prev);
        prev = e.fuel_before;
        let name = st.app_frame(&e.stack).map(|f| st.frame_name(f)).unwrap_or_else(|| "(unknown)".into());
        *own.entry(name).or_default() += fuel;
        let names: BTreeSet<String> = e.stack.iter().map(|f| st.frame_name(f)).collect();
        for n in names {
            *incl.entry(n).or_default() += fuel;
        }
    }
    let tail = r.totals.fuel.saturating_sub(prev);
    let total = r.totals.fuel.max(1) as f64;
    let rank = |m: BTreeMap<String, u64>| {
        let mut v: Vec<(String, u64)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter().take(top).map(|(f, n)| json!({"func": f, "fuel": n, "percent": (n as f64 * 1000.0 / total).round() / 10.0})).collect::<Vec<_>>()
    };
    Ok(json!({
        "run": r.id, "fuel": r.totals.fuel, "host_calls": r.events.len(), "measurement": "host_boundary_fuel_estimate", "function_cpu_profile": false,
        "before_host_calls": {"self": rank(own), "inclusive": rank(incl)},
        "after_last_host_call": {"fuel": tail, "percent": (tail as f64 * 1000.0 / total).round() / 10.0, "note": "work after the last host call has no stack; see `appfuzz wasm loops`"},
        "note": "fuel spent between two host calls is charged to the stack of the second call",
    }))
}

type Metric<'a> = &'a dyn Fn(&RunRecord) -> f64;

/// A run in plain terms, next to the typical run of the same export.
pub fn explain(app: &App, store: &RunStore, r: &RunRecord) -> Result<Value> {
    let others: Vec<RunRecord> = store
        .all()?
        .into_iter()
        .filter(|x| {
            x.spec.component == r.spec.component && x.spec.contract == r.spec.contract && x.spec.export == r.spec.export && x.outcome.kind == OutcomeKind::Ok
        })
        .collect();
    let median = |f: &dyn Fn(&RunRecord) -> f64| {
        let mut v: Vec<f64> = others.iter().map(f).collect();
        v.sort_by(|a, b| a.total_cmp(b));
        v.get(v.len() / 2).copied()
    };
    let metrics: [(&str, Metric); 6] = [
        ("fuel", &|x| x.totals.fuel as f64),
        ("host_calls", &|x| x.totals.host_calls as f64),
        ("virtual_ms", &|x| ms(x.totals.virtual_ns)),
        ("cost", &|x| x.totals.cost as f64),
        ("peak_memory", &|x| x.totals.peak_memory as f64),
        ("output_bytes", &|x| x.result.as_ref().map_or(0, |v| v.to_string().len()) as f64),
    ];
    let mut compared = serde_json::Map::new();
    let mut unusual = Vec::new();
    for (name, f) in metrics {
        let v = f(r);
        let m = median(f);
        let ratio = m.filter(|m| *m > 0.0).map(|m| (v / m * 100.0).round() / 100.0);
        if ratio.is_some_and(|x| !(1.0 / 3.0..=3.0).contains(&x)) {
            unusual.push(format!("{name} is {}× the median", ratio.unwrap_or_default()));
        }
        compared.insert(name.into(), json!({"this": num(v), "median": m.map(num), "ratio": ratio}));
    }
    let default = app.default_args(app.export(&r.spec.export)?, &r.spec.now)?;
    let mut input = Vec::new();
    diff(&json!(default), &json!(r.spec.args), String::new(), &mut input);
    let resp = response(r, &app.manifest);
    let mut plan: Vec<String> = r.spec.plan.0.keys().cloned().collect();
    plan.retain(|k| !k.starts_with('_'));
    let failed: Vec<Value> = r
        .events
        .iter()
        .filter(|e| e.trap.is_some() || e.result.as_ref().is_some_and(|v| v.get("err").is_some()))
        .map(|e| json!({"n": e.n, "func": e.func}))
        .collect();
    Ok(json!({
        "run": r.id, "export": r.spec.export, "outcome": r.outcome.kind, "message": r.outcome.message.as_deref().map(|m| m.lines().next().unwrap_or("")),
        "status": resp.status, "text": resp.body.as_deref().map(|b| visible_text(b).chars().take(200).collect::<String>()),
        "input_vs_default": input, "host_plan_for": plan, "now": r.spec.now, "seed": r.spec.seed,
        "calls": r.call_counts().into_iter().map(|(f, n)| (f, json!(n))).collect::<serde_json::Map<_, _>>(),
        "failed_calls": failed,
        "vs_stored_runs": {"runs": others.len(), "metrics": compared, "unusual": unusual},
        "findings": detect::per_run(r, &app.manifest).iter().map(|f| {
            let mut o = json!({"kind": f.kind, "severity": f.severity, "title": f.title});
            if let Some(x) = evidence_excerpt(f, resp.body.as_deref()) {
                o["excerpt"] = json!(x);
            }
            o
        }).collect::<Vec<_>>(),
    }))
}

/// For a finding about a canary, the text around it as the app wrote it,
/// markup included: the `<i>` in a page is what proves a reflection.
fn evidence_excerpt(f: &Finding, body: Option<&str>) -> Option<String> {
    let canary = f.detail.get("canary")?.as_str()?;
    let text = match f.kind.as_str() {
        "reflection" | "stored_reflection" => body?,
        _ => f.detail.get("arg")?.as_str()?,
    };
    let at = text.find(canary)?;
    let from = text[..at].char_indices().rev().nth(39).map_or(0, |(i, _)| i);
    let to = text[at..].char_indices().nth(canary.len() + 40).map_or(text.len(), |(i, _)| at + i);
    Some(format!("{}{}{}", if from > 0 { "…" } else { "" }, &text[from..to], if to < text.len() { "…" } else { "" }))
}

/// Host call sites in the code that no stored run reached, with the
/// constants the surrounding function compares with or uses: the inputs
/// that may lead there.
/// Also the `dormant_code` findings, for the caller to record.
pub fn unexplored(app: &App, store: &RunStore) -> Result<(Value, Vec<Finding>)> {
    let st = Statics::parse(&app.bytes)?;
    let runs: Vec<RunRecord> = store.all()?.into_iter().filter(|r| r.spec.component == app.hash && r.spec.contract == app.contract).collect();
    let hit = dormant::reached(&runs);
    let funcs: BTreeSet<(String, u32)> = runs.iter().flat_map(|r| r.events.iter().flat_map(|e| e.stack.iter().map(|f| (f.module.clone(), f.func)))).collect();
    let all = dormant::sites(&st);
    let mut sites = Vec::new();
    for s in all.iter().filter(|s| !dormant::is_reached(s, &hit, &funcs)) {
        let Some(m) = st.module(&s.module) else { continue };
        let callers = m.callers();
        // Constants of the function and of its callers (two levels):
        // the condition that leads to a call is often one level up.
        let mut texts: Vec<String> = Vec::new();
        let mut numbers: Vec<i64> = Vec::new();
        let mut via = Vec::new();
        let mut level = vec![s.func];
        for depth in 0..3 {
            let mut next = Vec::new();
            for g in &level {
                if let Some(f) = m.func(*g) {
                    for (_, t) in f.text_consts.iter().take(8) {
                        if !texts.contains(t) {
                            texts.push(t.clone());
                        }
                    }
                    for n in f.cmp_consts.iter().copied().filter(|n| !(-1..=1).contains(n) && n.unsigned_abs() < 1 << 24).take(12) {
                        if !numbers.contains(&n) {
                            numbers.push(n);
                        }
                    }
                }
                if depth > 0 {
                    via.push(m.label(*g));
                }
                next.extend(callers.get(g).into_iter().flatten().map(|(x, _)| *x).filter(|x| !level.contains(x)));
            }
            next.sort();
            next.dedup();
            next.truncate(4);
            level = next;
        }
        let mut o = dormant::site_json(m, s);
        o["function_runs"] = json!(funcs.contains(&(s.module.clone(), s.func)));
        o["called_via"] = json!(via);
        o["texts"] = json!(texts);
        o["compares_with"] = json!(numbers);
        sites.push(o);
    }
    let found = dormant::find(&st, &runs);
    Ok((
        json!({
            "runs_used": runs.len(), "static_sites": all.len(), "unreached": sites.len(), "sites": sites,
            "note": "a site is a call instruction; it counts as reached when it is on the stack of a host call in a stored run. Small wrappers around one host function are looked through (via)",
        }),
        found,
    ))
}

/// WASI the component imports, what the manifest grants, and what the
/// stored runs used.
pub fn wasi(app: &App, store: &RunStore) -> Result<Value> {
    let imports: Vec<Value> = app
        .imports
        .iter()
        .filter(|i| i.kind == ImportKind::Wasi)
        .map(|i| json!({"interface": i.name, "granted": app.manifest.grants_wasi(&i.name), "funcs": i.funcs.len()}))
        .collect();
    let runs: Vec<RunRecord> = store.all()?.into_iter().filter(|r| r.spec.component == app.hash && r.spec.contract == app.contract).collect();
    let used = |f: &dyn Fn(&RunRecord) -> u64| {
        let v: Vec<u64> = runs.iter().map(f).collect();
        json!({"runs": v.iter().filter(|x| **x > 0).count(), "max": v.iter().max().copied().unwrap_or(0), "total": v.iter().sum::<u64>()})
    };
    Ok(json!({
        "imports": imports,
        "runs_used": runs.len(),
        "usage": {
            "clock_reads": used(&|r| r.totals.clock_reads), "random_bytes": used(&|r| r.totals.random_bytes),
            "sleep_ms": used(&|r| r.totals.sleep_ns / 1_000_000), "stdout_bytes": used(&|r| r.stdout.len() as u64),
            "stderr_bytes": used(&|r| r.stderr.len() as u64),
        },
        "note": "reads of the insecure random seed (hash maps) are not counted",
    }))
}
