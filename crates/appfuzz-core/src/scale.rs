//! Scaling: turn one knob (a host list's length, a request field) through
//! a range of sizes, measure every resource, fit growth laws, and find the
//! size at which a budget breaks. `amplify` finds the knobs by itself.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::detect::{Finding, Severity};
use crate::growth::{Class, Law, fit};
use crate::harness::App;
use crate::par::{self, Runner};
use crate::plan::{FnPlan, Plan, Response};
use crate::record::{OutcomeKind, RunRecord, RunSpec};
use crate::statics::Statics;
use crate::value::{GenOpts, Generator, json_to_val};
use crate::wit::ImportKind;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum Knob {
    /// Length of the list a host function returns.
    HostList(String),
    /// A request field set to n (number, or number as text).
    Field(String),
    /// A request string field set to n characters.
    FieldLen(String),
}

impl Knob {
    pub fn describe(&self) -> String {
        match self {
            Knob::HostList(f) => format!("length of the list {f} returns"),
            Knob::Field(p) if p.starts_with('@') && !p.contains('.') => format!("number of elements in argument {}", &p[1..]),
            Knob::Field(p) => format!("request field {p} = n"),
            Knob::FieldLen(p) => format!("length of request field {p}"),
        }
    }
    pub fn parse(s: &str) -> Result<Knob> {
        if let Some(f) = s.strip_prefix("fn:") {
            Ok(Knob::HostList(f.to_string()))
        } else if let Some(p) = s.strip_prefix("len:") {
            Ok(Knob::FieldLen(p.to_string()))
        } else if let Some(p) = s.strip_prefix("field:") {
            Ok(Knob::Field(p.to_string()))
        } else if s.contains('#') {
            Ok(Knob::HostList(s.to_string()))
        } else {
            Ok(Knob::Field(s.to_string()))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Point {
    pub n: u64,
    pub run: String,
    pub outcome: OutcomeKind,
    pub calls: BTreeMap<String, u32>,
    pub host_calls: u32,
    pub fuel: u64,
    pub peak_memory: u64,
    pub virtual_ms: Value,
    /// Exact nanoseconds, also retained in reports when fitting is approximate.
    pub virtual_ns: crate::natural::Natural,
    #[serde(serialize_with = "crate::wide::serialize")]
    pub cost: u128,
    pub output_bytes: u64,
    pub host_arg_bytes: u64,
    /// List items each host function returned, over all its calls.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rows: BTreeMap<String, u64>,
    /// Bytes all host calls returned, as compact JSON.
    pub host_result_bytes: u64,
    /// This run's own fuel limit, where it depends on the input (Shopify).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fuel_limit: Option<u64>,
}

impl Point {
    pub fn of(n: u64, r: &RunRecord) -> Self {
        let mut calls = BTreeMap::new();
        for (k, c) in r.call_counts() {
            calls.insert(k, c);
        }
        let mut rows = BTreeMap::new();
        for e in &r.events {
            if let Some(n) = e.result_items {
                *rows.entry(e.func.clone()).or_default() += u64::from(n);
            }
        }
        Point {
            n,
            run: r.id.clone(),
            outcome: r.outcome.kind,
            calls,
            host_calls: r.totals.host_calls,
            fuel: r.totals.fuel,
            peak_memory: r.totals.peak_memory,
            virtual_ms: r.totals.virtual_ns.ms_json(),
            virtual_ns: r.totals.virtual_ns.clone(),
            cost: r.totals.cost,
            output_bytes: r.result.as_ref().map(|v| v.to_string().len() as u64).unwrap_or(0),
            host_arg_bytes: r.events.iter().map(|e| Value::Object(e.args.clone()).to_string().len() as u64).sum(),
            rows,
            host_result_bytes: r.totals.host_result_bytes,
            fuel_limit: r.shopify.as_ref().map(|s| s.instructions_limit),
        }
    }
}

/// The spec for one knob setting.
pub fn apply(app: &App, base: &RunSpec, knob: &Knob, n: u64) -> Result<RunSpec> {
    let mut spec = base.clone();
    match knob {
        Knob::HostList(f) => {
            let info = platform_fn(app, f).ok_or_else(|| anyhow!("no platform import {f}"))?;
            if let Some(q) = app.manifest.function(&info.key).and_then(|s| s.query.as_ref()) {
                if n > crate::dataset::MAX_ROWS as u64 {
                    bail!("dataset scale exceeds {}", crate::dataset::MAX_ROWS);
                }
                spec.plan.0.entry("_defaults".into()).or_default().dataset_rows.insert(q.dataset.clone(), n as usize);
                return Ok(spec);
            }
            let ty = info.ty.results().next().ok_or_else(|| anyhow!("{f} returns nothing"))?;
            let template = spec.plan.0.get(&info.key).and_then(|p| p.response.ret.clone());
            // New elements follow the function's (or the default) generate options.
            let opts = spec
                .plan
                .0
                .get(&info.key)
                .and_then(|p| p.response.generate.clone())
                .or_else(|| spec.plan.0.get("_defaults").and_then(|p| p.response.generate.clone()))
                .unwrap_or_default();
            let grown = grow(&ty, template.as_ref(), n as usize, spec.seed, &opts)?;
            let mut fp = spec.plan.0.remove(&info.key).unwrap_or_default();
            fp.response = Response { ret: Some(grown), generate: None, trap: None, commit_then_trap: None, latency_ms: fp.response.latency_ms };
            spec.plan.0.insert(info.key.clone(), fp);
        }
        Knob::Field(p) | Knob::FieldLen(p) => {
            // `@1.now`, or `req.now` for a parameter the manifest's export names.
            let (i, path) = app.manifest.entry.as_ref().map_or_else(|| split_arg(p), |e| e.locate(p));
            let req = spec.args.get_mut(i).ok_or_else(|| anyhow!("the export has no argument {i}"))?;
            let len = matches!(knob, Knob::FieldLen(_));
            if path.is_empty() {
                *req = resized(Some(req), n, len);
            } else {
                set_field(req, path, n, len)?;
            }
            // The platform lets no other value through.
            crate::constraints::conform_request_typed(&mut spec.args, app, &spec.export, spec.seed)?;
        }
    }
    Ok(spec)
}

/// The platform import a knob names: the full key, or its end (`customers#all`).
fn platform_fn<'a>(app: &'a App, f: &str) -> Option<&'a crate::wit::FuncInfo> {
    app.imports
        .iter()
        .filter(|i| i.kind == ImportKind::Platform)
        .flat_map(|i| i.funcs.iter())
        .find(|x| x.key == *f || x.key.ends_with(&format!("/{f}")) || x.key.ends_with(&format!("#{f}")))
}

/// `@1.page` → (1, "page"); `@2` → (2, ""); `query.days` → (0, "query.days").
pub fn split_arg(p: &str) -> (usize, &str) {
    if let Some(rest) = p.strip_prefix('@') {
        let (i, path) = rest.split_once('.').unwrap_or((rest, ""));
        return (i.parse().unwrap_or(0), path);
    }
    (0, p)
}

/// A value of "size" n shaped like `old`: a number, a list of n
/// elements, numeric text, or (`as_len`) n characters.
fn resized(old: Option<&Value>, n: u64, as_len: bool) -> Value {
    if as_len {
        return Value::String("a".repeat(n as usize));
    }
    match old {
        Some(Value::Number(_)) => json!(n),
        // Copies get distinct ids, so a per-element call is not redundant.
        Some(Value::Array(a)) if !a.is_empty() => Value::Array(
            (0..n as usize)
                .map(|i| {
                    let mut v = a[i % a.len()].clone();
                    bump_first_number(&mut v, (i / a.len()) as u64 * 1000);
                    v
                })
                .collect(),
        ),
        _ => Value::String(n.to_string()),
    }
}

fn bump_first_number(v: &mut Value, by: u64) -> bool {
    match v {
        Value::Number(x) => match x.as_u64() {
            Some(u) => {
                // The largest u64 (an edge value) wraps instead of panicking.
                *v = json!(u.wrapping_add(by));
                true
            }
            None => false,
        },
        Value::Array(a) => a.iter_mut().any(|x| bump_first_number(x, by)),
        Value::Object(o) => o.values_mut().any(|x| bump_first_number(x, by)),
        _ => false,
    }
}

/// Pins generated host lists to one element and takes the happy path
/// (`some`, `ok`), so only the knob moves.
pub fn steady(plan: &Plan) -> Plan {
    let mut p = plan.clone();
    p.0.entry("_defaults".into()).or_insert_with(|| FnPlan {
        response: Response {
            generate: Some(GenOpts { list_len: Some(1), options: Some("some".into()), results: Some("ok".into()), ..Default::default() }),
            ..Default::default()
        },
        ..Default::default()
    });
    p
}

/// The value of query parameter `key` in a URL.
fn query_value(uri: &str, key: &str) -> Option<String> {
    let q = uri.split_once('?')?.1;
    let q = q.split_once('#').map_or(q, |(q, _)| q);
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then(|| v.to_string())
    })
}

/// A URL with query parameter `key` set to `value` (added if missing).
/// The value stays readable; only what would split it is encoded.
pub(crate) fn with_query(uri: &str, key: &str, value: &str) -> String {
    let (uri, fragment) = uri.split_once('#').map_or((uri, None), |(u, f)| (u, Some(f)));
    let (head, q) = uri.split_once('?').unwrap_or((uri, ""));
    let value = value.replace('%', "%25").replace('&', "%26").replace('#', "%23");
    let mut parts: Vec<String> = q.split('&').filter(|kv| !kv.is_empty() && kv.split('=').next() != Some(key)).map(str::to_string).collect();
    parts.push(format!("{key}={value}"));
    let mut out = format!("{head}?{}", parts.join("&"));
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}

/// Sets `path` in a request to `n` (or a string of n characters). A path
/// into a list of `[key, value]` pairs adds the pair if missing; `uri?key`
/// sets a query parameter of the URL in field `uri`.
pub fn set_field(req: &mut Value, path: &str, n: u64, as_len: bool) -> Result<()> {
    if let Some((field, key)) = path.split_once('?') {
        let slot = crate::harness::field_mut(req, field).filter(|v| v.is_string()).ok_or_else(|| anyhow!("no URL field {field}"))?;
        let uri = slot.as_str().unwrap_or_default().to_string();
        let v = match resized(query_value(&uri, key).map(Value::String).as_ref(), n, as_len) {
            Value::String(t) => t,
            other => other.to_string(),
        };
        *slot = Value::String(with_query(&uri, key, &v));
        return Ok(());
    }
    let (parent, last) = match path.rsplit_once('.') {
        Some((a, b)) => (crate::harness::field_mut(req, a).ok_or_else(|| anyhow!("no field {a}"))?, b),
        None => (req, path),
    };
    let new = |old: Option<&Value>| resized(old, n, as_len);
    match parent {
        Value::Object(o) => {
            let v = new(o.get(last));
            o.insert(last.to_string(), v);
        }
        Value::Array(a) => {
            let pos = a.iter().position(|p| p.as_array().and_then(|p| p.first()).and_then(Value::as_str) == Some(last));
            match pos {
                Some(i) => {
                    let v = new(a[i].get(1));
                    a[i] = json!([last, v]);
                }
                None => a.push(json!([last, new(None)])),
            }
        }
        _ => bail!("{path}: not inside a record or a list of pairs"),
    }
    Ok(())
}

/// Sets `path` to a text value (adding a `[key, value]` pair if needed).
pub fn set_text(req: &mut Value, path: &str, text: &str) -> Result<()> {
    if let Some((field, key)) = path.split_once('?') {
        let slot = crate::harness::field_mut(req, field).filter(|v| v.is_string()).ok_or_else(|| anyhow!("no URL field {field}"))?;
        *slot = Value::String(with_query(slot.as_str().unwrap_or_default(), key, text));
        return Ok(());
    }
    set_field(req, path, 0, false)?;
    let slot = crate::harness::field_mut(req, path).ok_or_else(|| anyhow!("no field {path}"))?;
    *slot = Value::String(text.to_string());
    Ok(())
}

/// Recovers a key of length `len` that the app compares byte by byte,
/// from the fuel each guess costs. None if fuel gives no gradient.
pub fn solve_key(len: usize, fuel: &(dyn Fn(&str) -> u64 + Sync)) -> Option<String> {
    const CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789_-.";
    let chars: Vec<char> = CHARS.chars().collect();
    let mut prefix = String::new();
    for i in 0..len {
        let rest = filler(len - i - 1, '~');
        let tries: Vec<(u64, char)> = par::map(&chars, |&c| (fuel(&format!("{prefix}{c}{rest}")), c));
        let max = tries.iter().map(|t| t.0).max()?;
        let at_max: Vec<char> = tries.iter().filter(|t| t.0 == max).map(|t| t.1).collect();
        if at_max.len() != 1 {
            return None;
        }
        prefix.push(at_max[0]);
    }
    Some(prefix)
}

/// A key nobody reads, of a given length.
fn filler(len: usize, c: char) -> String {
    std::iter::repeat_n(c, len).collect()
}

/// A host result whose (first) list has `n` elements: template elements
/// first, then copies with fresh `id`s.
pub fn grow(ty: &Type, template: Option<&Value>, n: usize, seed: u64, opts: &GenOpts) -> Result<Value> {
    match ty {
        Type::List(l) => {
            let elem = l.ty();
            let given: Vec<Value> = template.and_then(Value::as_array).cloned().unwrap_or_default();
            let mut g = Generator::new(seed, GenOpts { list_len: Some(1), ..opts.clone() });
            let base = if given.is_empty() { vec![g.gen_json(&elem)] } else { given.clone() };
            // Copies count on from the largest id (or number, in a list of
            // numbers), so they repeat no value the template has.
            let max_id = base.iter().filter_map(|e| e.get("id").and_then(Value::as_u64).or_else(|| e.as_u64())).max().unwrap_or(0);
            let mut out = Vec::with_capacity(n);
            for k in 0..n {
                let mut e = base[k % base.len()].clone();
                if k >= base.len() || given.is_empty() {
                    uniquify(&mut e, k as u64, max_id);
                }
                if json_to_val(&e, &elem).is_err() {
                    e = g.gen_json(&elem);
                }
                out.push(e);
            }
            Ok(Value::Array(out))
        }
        Type::Result(r) => {
            let ok = r.ok().ok_or_else(|| anyhow!("result without an ok type"))?;
            let inner = template.and_then(|t| t.get("ok"));
            Ok(json!({"ok": grow(&ok, inner, n, seed, opts)?}))
        }
        Type::Option(o) => {
            let inner = template.and_then(|t| t.get("some"));
            Ok(json!({"some": grow(&o.ty(), inner, n, seed, opts)?}))
        }
        _ => bail!("the result has no list to grow"),
    }
}

fn uniquify(e: &mut Value, k: u64, max_id: u64) {
    match e {
        Value::Object(o) => {
            if let Some(id) = o.get_mut("id")
                && id.is_number()
            {
                *id = json!(max_id.wrapping_add(k).wrapping_add(1));
            } else if let Some((_, v)) = o.iter_mut().find(|(_, v)| v.is_number()) {
                *v = json!(k + 1);
            }
            if let Some((_, v)) = o.iter_mut().find(|(_, v)| v.is_string()) {
                let s = v.as_str().unwrap_or("").split(" #").next().unwrap_or("").to_string();
                *v = json!(format!("{s} #{}", k + 1));
            }
        }
        Value::Number(_) => *e = json!(max_id.wrapping_add(k).wrapping_add(1)),
        Value::String(s) => *e = json!(format!("{s} #{}", k + 1)),
        _ => {}
    }
}

/// Lists a host function can return, i.e. functions worth growing.
pub fn list_functions(app: &App) -> Vec<String> {
    fn has_list(t: &Type) -> bool {
        match t {
            Type::List(_) => true,
            Type::Result(r) => r.ok().is_some_and(|t| has_list(&t)),
            Type::Option(o) => has_list(&o.ty()),
            _ => false,
        }
    }
    app.imports
        .iter()
        .filter(|i| i.kind == ImportKind::Platform)
        .flat_map(|i| i.funcs.iter())
        .filter(|f| f.ty.results().next().is_some_and(|t| has_list(&t)))
        .map(|f| f.key.clone())
        .collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Growth {
    pub metric: String,
    pub law: Law,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breaks_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub break_evidence: Option<&'static str>,
    /// An extrapolation remains separate from an observed violation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicted_breaks_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScaleReport {
    pub knob: Knob,
    /// A request setting the knob was turned in (`query.view=week`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub points: Vec<Point>,
    /// Only metrics that change with the knob.
    pub growth: Vec<Growth>,
    pub findings: Vec<Finding>,
}

/// Biggest n we extrapolate breaking points to.
const MAX_BREAK_N: u64 = 1_000_000;

#[derive(Clone, Copy)]
enum Budget {
    Cost(u64),
    Latency(f64),
    Fuel(u64),
    Memory(u64),
}
impl Budget {
    fn exceeds(self, p: &Point) -> bool {
        match self {
            Self::Cost(n) => p.cost > u128::from(n),
            Self::Latency(ms) => p.virtual_ns.exceeds_ms(ms),
            Self::Fuel(n) => p.fuel > p.fuel_limit.unwrap_or(n),
            Self::Memory(n) => p.peak_memory > n,
        }
    }
    fn approximate(self) -> f64 {
        match self {
            Self::Cost(n) | Self::Fuel(n) | Self::Memory(n) => n as f64,
            Self::Latency(ms) => ms,
        }
    }
    fn display(self) -> Value {
        match self {
            Self::Cost(n) | Self::Fuel(n) | Self::Memory(n) => json!(n),
            Self::Latency(ms) => json!(ms),
        }
    }
}

pub fn analyze(app: &App, knob: Knob, mut points: Vec<Point>) -> ScaleReport {
    points.sort_by_key(|p| p.n);
    let l = &app.manifest.limits;
    // Points after a failure (hang, crash) distort the fit.
    let good: Vec<&Point> = points.iter().take_while(|p| p.outcome == OutcomeKind::Ok).collect();
    // A limit that grows with the input (Shopify): predict against the
    // largest size measured, which the limit only grows from.
    let fuel_limit = good.last().and_then(|p| p.fuel_limit).unwrap_or(l.fuel);
    let mut growth = Vec::new();
    let mut add = |metric: String, f: &dyn Fn(&Point) -> f64, budget: Option<Budget>| {
        let pts: Vec<(f64, f64)> = good.iter().map(|p| (p.n as f64, f(p))).collect();
        let time_scale =
            (metric == "virtual_ms" && pts.iter().any(|(_, y)| !y.is_finite())).then(|| good.iter().map(|p| p.virtual_ns.clone()).max().unwrap_or_default());
        let pts = time_scale.as_ref().map_or(pts, |scale| good.iter().map(|p| (p.n as f64, p.virtual_ns.ratio(scale))).collect());
        let Some(mut law) = fit(&pts) else { return };
        if let Some(scale) = time_scale {
            law.text = format!("({}) × {} ms", law.text, scale.ms_text());
            law.time_scale_ns = Some(scale);
        }
        if law.class == Class::Constant || !law.increasing() {
            return;
        }
        // Fuel and memory wobble; ignore growth under 2 % over the range.
        let (lo, hi) = (pts.first().map(|p| p.1).unwrap_or(0.0), pts.last().map(|p| p.1).unwrap_or(0.0));
        if hi <= lo * 1.02 {
            return;
        }
        let measured = budget.and_then(|limit| points.iter().find(|p| limit.exceeds(p)).map(|p| p.n));
        let predicted = budget
            .and_then(|limit| law.breaking_point(limit.approximate(), MAX_BREAK_N))
            .filter(|&n| !points.iter().any(|p| p.n >= n && p.outcome == OutcomeKind::Ok && budget.is_some_and(|limit| !limit.exceeds(p))));
        let breaks_at = measured.or(predicted);
        let break_evidence = if measured.is_some() { Some("measured") } else { predicted.map(|_| "inferred") };
        growth.push(Growth { metric, law, breaks_at, limit: budget.map(Budget::display), break_evidence, predicted_breaks_at: predicted });
    };
    let funcs: BTreeSet<String> = points.iter().flat_map(|p| p.calls.keys().cloned()).collect();
    for f in &funcs {
        let key = f.clone();
        add(format!("calls {f}"), &move |p: &Point| *p.calls.get(&key).unwrap_or(&0) as f64, None);
    }
    add("cost".into(), &|p| p.cost as f64, l.cost_per_request.map(Budget::Cost));
    add("virtual_ms".into(), &|p| p.virtual_ns.ms(), l.max_latency_ms.map(Budget::Latency));
    add("fuel".into(), &|p| p.fuel as f64, Some(Budget::Fuel(fuel_limit)));
    add("peak_memory".into(), &|p| p.peak_memory as f64, Some(Budget::Memory(l.memory)));
    add("output_bytes".into(), &|p| p.output_bytes as f64, None);
    add("host_arg_bytes".into(), &|p| p.host_arg_bytes as f64, None);

    let findings = findings(app, &knob, &points, &growth);
    ScaleReport { knob, context: None, points, growth, findings }
}

fn findings(app: &App, knob: &Knob, points: &[Point], growth: &[Growth]) -> Vec<Finding> {
    let mut out = Vec::new();
    let worst = points.iter().rfind(|p| p.outcome == OutcomeKind::Ok).or(points.last()).map(|p| p.run.as_str());
    let budget_break = growth.iter().filter_map(|g| g.breaks_at.map(|b| (b, g.metric.clone()))).min();
    let budget_growth = budget_break.as_ref().and_then(|(_, metric)| growth.iter().find(|g| &g.metric == metric));
    let policy_break = growth.iter().flat_map(|g| [g.breaks_at, g.predicted_breaks_at]).flatten().min();
    let kind = match knob {
        Knob::HostList(_) => "n_plus_1",
        _ => "input_amplification",
    };
    let ex = app.manifest.entry.as_ref().map(|e| e.export.clone()).unwrap_or_default();
    for g in growth.iter().filter(|g| g.metric.starts_with("calls ")) {
        let f = &g.metric["calls ".len()..];
        // The list being grown, also when the knob names it short (`items#all`).
        if let Knob::HostList(src) = knob
            && platform_fn(app, src).map_or(src.as_str(), |i| i.key.as_str()) == f
        {
            continue;
        }
        // A request field is the requester's to choose: any break counts.
        let input = !matches!(knob, Knob::HostList(_));
        // Labels: a change in a loop, or a loop where a batch call exists.
        let effect = app.manifest.effect_of(f).filter(|e| e.changes());
        let batch = app.manifest.batch_for(f);
        let sev = if g.law.class == Class::Capped {
            // The app bounds it: a hint, not an n+1.
            Severity::Info
        } else if g.law.class.superlinear() || policy_break.is_some_and(|b| input || b <= 100) || effect.is_some() || batch.is_some() {
            Severity::Fail
        } else {
            Severity::Warn
        };
        let mut title = format!("calls to {f} grow as {} with n = {}", g.law.text, knob.describe());
        if let Some(e) = effect {
            title.push_str(&format!(" (effect {}: one change per element)", e.name()));
        }
        if let Some((b, m)) = &budget_break {
            if budget_growth.is_some_and(|g| g.break_evidence == Some("measured")) {
                title.push_str(&format!("; {m} exceeds its limit at measured n = {b}"));
            } else {
                title.push_str(&format!("; {m} is predicted to exceed its limit at n = {b}"));
            }
        }
        if let Some(b) = &batch {
            title.push_str(&format!("; {b} does it in one call"));
        }
        out.push(Finding::new(
            kind,
            &format!("{ex}\0{knob:?}\0{f}"),
            sev,
            title,
            json!({"knob": knob, "func": f, "law": g.law.text, "class": g.law.class, "breaks_at": budget_break, "break_evidence":budget_growth.and_then(|g|g.break_evidence),
                   "predicted_breaks_at":budget_growth.and_then(|g|g.predicted_breaks_at), "worst_run": worst,
                   "effect": effect.map(|e| e.name()), "batch": batch}),
            worst,
        ));
    }
    for g in growth.iter().filter(|g| !g.metric.starts_with("calls ") && g.law.class.superlinear()) {
        let kind = match g.metric.as_str() {
            "fuel" | "virtual_ms" => "cpu_blowup",
            "peak_memory" => "memory_blowup",
            "output_bytes" => "output_amplification",
            "host_arg_bytes" => "payload_amplification",
            _ => "superlinear_growth",
        };
        // A host list of thousands is unusual; a request field is the
        // requester's to choose.
        let near = [g.breaks_at, g.predicted_breaks_at].into_iter().flatten().any(|b| b <= HOST_LIST_REALISTIC);
        let sev = if matches!(knob, Knob::HostList(_)) && !near { Severity::Info } else { Severity::Warn };
        out.push(Finding::new(
            kind,
            &format!("{ex}\0{knob:?}\0{}", g.metric),
            sev,
            format!("{} grows as {} with n = {}", g.metric, g.law.text, knob.describe()),
            json!({"knob": knob, "metric": g.metric, "law": g.law.text, "class": g.law.class, "breaks_at": g.breaks_at, "break_evidence":g.break_evidence, "predicted_breaks_at":g.predicted_breaks_at, "worst_run": worst}),
            worst,
        ));
    }
    if let Some(p) = points.iter().find(|p| !matches!(p.outcome, OutcomeKind::Ok | OutcomeKind::Error | OutcomeKind::PlanError | OutcomeKind::BudgetExceeded))
        && points.first().is_some_and(|f| f.outcome == OutcomeKind::Ok)
    {
        out.push(Finding::new(
            "fails_at_size",
            &format!("{ex}\0{knob:?}"),
            Severity::Fail,
            format!("{} at n = {} ({})", crate::detect::kind_name(p.outcome), p.n, knob.describe()),
            json!({"knob": knob, "n": p.n, "outcome": p.outcome}),
            Some(&p.run),
        ));
    }
    out
}

/// Words from the binary's strings that could be request keys.
pub fn dictionary(st: &Statics, limit: usize) -> Vec<String> {
    let mut words = BTreeSet::new();
    for m in &st.modules {
        let consts = m.funcs.iter().flat_map(|f| f.text_consts.iter());
        for (_, s) in m.strings.iter().chain(consts) {
            // Split runs of packed literals at non-letters and at
            // lower→upper case changes.
            let mut cur = String::new();
            let mut prev_lower = false;
            for c in s.chars() {
                let boundary = !(c.is_ascii_alphanumeric() || c == '_' || c == '-') || (prev_lower && c.is_ascii_uppercase());
                if boundary {
                    push_word(&mut words, &cur);
                    cur.clear();
                }
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    cur.push(c);
                }
                prev_lower = c.is_ascii_lowercase();
            }
            push_word(&mut words, &cur);
        }
    }
    let mut v: Vec<String> = words.into_iter().collect();
    v.sort_by_key(|w| (w.len(), w.clone()));
    v.truncate(limit);
    v
}

fn push_word(words: &mut BTreeSet<String>, w: &str) {
    let w = w.trim_matches(|c| c == '-' || c == '_');
    let word = |lower: bool| {
        let letter = |c: char| if lower { c.is_ascii_lowercase() } else { c.is_ascii_uppercase() };
        w.chars().next().is_some_and(letter) && w.chars().all(|c| letter(c) || c.is_ascii_digit() || c == '_' || c == '-')
    };
    // `copies`, `view_mode`; and all-caps words such as `POST`.
    if (2..=24).contains(&w.len()) && (word(true) || word(false)) {
        words.insert(w.to_string());
    }
}

/// Request leaves that can be knobs: numbers, numeric text, strings, and
/// the keys of `[key, value]` lists.
pub fn request_knobs(args: &[Value]) -> (Vec<Knob>, Vec<String>) {
    let mut knobs = Vec::new();
    let mut pair_lists = Vec::new();
    fn walk(v: &Value, path: String, knobs: &mut Vec<Knob>, pairs: &mut Vec<String>) {
        match v {
            Value::Number(_) => knobs.push(Knob::Field(path)),
            Value::String(s) => {
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
                    knobs.push(Knob::Field(path.clone()));
                }
                knobs.push(Knob::FieldLen(path));
            }
            Value::Object(o) => {
                for (k, x) in o {
                    walk(x, if path.is_empty() || path == "@0" { k.clone() } else { format!("{path}.{k}") }, knobs, pairs);
                }
            }
            Value::Array(a) => {
                let is_pairs = a.iter().all(|p| p.as_array().is_some_and(|p| p.len() == 2 && p[0].is_string()));
                if !a.is_empty() && !is_pairs {
                    // A list in the request: its length is a knob.
                    knobs.push(Knob::Field(path.clone()));
                }
                if is_pairs {
                    pairs.push(path.clone());
                    for p in a {
                        let k = p[0].as_str().unwrap_or_default();
                        let base = if path == "@0" { String::new() } else { format!("{path}.") };
                        walk(&p[1], format!("{base}{k}"), knobs, pairs);
                    }
                }
            }
            _ => {}
        }
    }
    for (i, a) in args.iter().enumerate() {
        walk(a, format!("@{i}"), &mut knobs, &mut pair_lists);
    }
    // Paths into the first argument are written without `@0.`.
    let strip = |p: String| p.strip_prefix("@0.").map(str::to_string).unwrap_or(p);
    let knobs = knobs
        .into_iter()
        .map(|k| match k {
            Knob::Field(p) => Knob::Field(strip(p)),
            Knob::FieldLen(p) => Knob::FieldLen(strip(p)),
            k => k,
        })
        .collect();
    (knobs, pair_lists.into_iter().map(strip).collect())
}

/// What a run did, coarsely: used to tell whether a probe changed anything.
pub fn behaviour(r: &RunRecord) -> String {
    let calls: Vec<String> = r.call_counts().into_iter().map(|(k, n)| format!("{k}×{n}")).collect();
    let out = r.result.as_ref().map(|v| blake3::hash(v.to_string().as_bytes()).to_hex()[..8].to_string()).unwrap_or_default();
    format!("{:?}|{}|{}", r.outcome.kind, out, calls.join(","))
}

pub const COUNT_SIZES: [u64; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
/// Request numbers are the requester's to choose, so they go further.
pub const FIELD_SIZES: [u64; 11] = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
pub const LENGTH_SIZES: [u64; 5] = [16, 64, 256, 1024, 4096];

pub fn default_sizes(knob: &Knob) -> Vec<u64> {
    match knob {
        Knob::FieldLen(_) => LENGTH_SIZES.to_vec(),
        Knob::Field(_) => FIELD_SIZES.to_vec(),
        Knob::HostList(_) => COUNT_SIZES.to_vec(),
    }
}

/// Runs a knob over sizes, all at once. `run` executes (and may store) a
/// spec. Points after the first failing size are dropped.
pub fn scale(app: &App, base: &RunSpec, knob: Knob, sizes: &[u64], run: Runner) -> Result<ScaleReport> {
    let mut specs = sizes.iter().map(|&n| apply(app, base, &knob, n).map(|s| (n, s))).collect::<Result<Vec<_>>>()?;
    // A size the field's type cannot hold (256 in a u8) is no request the
    // platform can send: the app never runs, so it is no failure at size n.
    specs.retain(|(_, s)| fits(app, s));
    let mut points = Vec::new();
    for (p, refused) in par::map(&specs, |(n, s)| {
        let r = run(s);
        (Point::of(*n, &r), r.shopify.as_ref().is_some_and(crate::shopify::RunInfo::input_refused))
    }) {
        // Shopify sends no input this big: no size from here on happens.
        if refused {
            break;
        }
        let stop = p.outcome != OutcomeKind::Ok;
        points.push(p);
        if stop {
            break;
        }
    }
    let mut report = analyze(app, knob, points);
    if let Some(f) = unbounded_read(app, base, &report, run) {
        report.findings.push(f);
    }
    Ok(report)
}

/// Host lists up to this many rows are ordinary for a read that loads them all.
const UNBOUNDED_REALISTIC: u64 = 10_000;
/// Fewer rows than this at the largest size say little about a read.
const UNBOUNDED_MIN_ROWS: u64 = 16;

/// A host list the app reads whole while its answer stays the same size:
/// each new row makes the request slower and bigger and changes nothing.
/// Dropping the first, middle and last row shows whether every row counts.
fn unbounded_read(app: &App, base: &RunSpec, report: &ScaleReport, run: Runner) -> Option<Finding> {
    let Knob::HostList(name) = &report.knob else { return None };
    let key = platform_fn(app, name)?.key.clone();
    if app.manifest.effect_of(&key).is_some_and(|e| e.changes()) {
        return None;
    }
    let good: Vec<&Point> = report.points.iter().take_while(|p| p.outcome == OutcomeKind::Ok).collect();
    let rows = |p: &Point| p.rows.get(&key).copied().unwrap_or(0);
    let last = *good.last()?;
    if good.len() < 4 || rows(last) < UNBOUNDED_MIN_ROWS {
        return None;
    }
    let law = fit(&good.iter().map(|p| (p.n as f64, rows(p) as f64)).collect::<Vec<_>>())?;
    if !law.increasing() || !matches!(law.class, Class::Linear | Class::NLogN | Class::Quadratic | Class::Cubic | Class::Exponential) {
        return None;
    }
    // An answer that grows with the rows shows them; that is no unbounded read.
    if report.growth.iter().any(|g| g.metric == "output_bytes" && !matches!(g.law.class, Class::Constant | Class::Log | Class::Capped)) {
        return None;
    }
    let spec = apply(app, base, &report.knob, last.n).ok()?;
    let top = run(&spec);
    let (pinned, drops) = dropped_rows(app, &spec, &top, &key);
    let reference = pinned.map_or(top, |s| run(&s));
    let tried: Vec<(String, bool, String)> = if reference.outcome.kind == OutcomeKind::Ok {
        par::map(&drops, |(row, s)| {
            let r = run(s);
            (row.clone(), r.outcome.kind == OutcomeKind::Ok && answer(app, &r) == answer(app, &reference), r.id.clone())
        })
    } else {
        vec![]
    };
    let unused: Vec<&str> = tried.iter().filter(|t| t.1).map(|t| t.0.as_str()).collect();
    let dataset = app.manifest.function(&key).and_then(|s| s.query.as_ref()).map(|q| q.dataset.clone());
    let paged = dataset.as_ref().and_then(|ds| {
        let mut paged: Vec<(String, usize)> = app
            .manifest
            .functions
            .iter()
            .filter_map(|(k, s)| s.query.as_ref().filter(|q| q.dataset == *ds).and_then(|q| q.page.as_ref()).map(|p| (k.clone(), p.max)))
            .collect();
        paged.sort_by_key(|(k, _)| *k != key);
        paged.into_iter().next()
    });
    let reads_pages = paged.as_ref().is_some_and(|(k, _)| *k == key);
    let breaks = report
        .growth
        .iter()
        .filter(|g| !g.metric.starts_with("calls "))
        .filter_map(|g| g.breaks_at.map(|b| (b, g.metric.clone(), g.break_evidence)))
        .min_by_key(|b| b.0);
    let near = breaks.as_ref().is_some_and(|b| b.0 <= UNBOUNDED_REALISTIC);
    let sev = if paged.is_some() && !unused.is_empty() && near {
        Severity::Fail
    } else if !unused.is_empty() && (paged.is_some() || near) {
        Severity::Warn
    } else {
        Severity::Info
    };
    let mut title = if reads_pages {
        format!("the app reads every page of {key}, all n rows, while its answer stays the same size")
    } else {
        format!("{key} returns all n rows while the answer stays the same size")
    };
    if !unused.is_empty() {
        title.push_str(&format!("; some rows never affect it (dropping the {} row changes nothing)", unused.join(" or ")));
    } else if !tried.is_empty() {
        title.push_str("; each dropped row changes it");
    }
    if let Some((b, metric, evidence)) = &breaks {
        title.push_str(&if *evidence == Some("measured") {
            format!("; {metric} exceeds its limit at measured n = {b}")
        } else {
            format!("; {metric} is predicted to exceed its limit at n = {b}")
        });
    }
    if let Some((k, max)) = paged.as_ref().filter(|_| !reads_pages) {
        title.push_str(&format!("; {k} reads pages of up to {max}"));
    }
    let ex = app.manifest.entry.as_ref().map(|e| e.export.clone()).unwrap_or_default();
    Some(Finding::new(
        "unbounded_read",
        &format!("{ex}\0{:?}\0unbounded_read", report.knob),
        sev,
        title,
        json!({"knob": report.knob, "func": key, "law": law.text, "class": law.class, "n": last.n, "rows": rows(last),
               "dropped": tried.iter().map(|(row, same, run)| json!({"row": row, "unchanged": same, "run": run})).collect::<Vec<_>>(),
               "unused_rows": !unused.is_empty(), "breaks_at": breaks.as_ref().map(|b| json!([b.0, b.1])), "break_evidence": breaks.as_ref().and_then(|b| b.2),
               "paged": paged.as_ref().map(|(f, max)| json!({"func": f, "max": max})), "worst_run": last.run}),
        Some(&last.run),
    ))
}

/// What a run answered and changed, to tell whether a row mattered.
fn answer(app: &App, r: &RunRecord) -> Value {
    let effects: Vec<Value> =
        r.events.iter().filter(|e| app.manifest.effect_of(&e.func).is_some_and(|x| x.changes())).map(|e| json!([e.func, e.args])).collect();
    json!([r.outcome.kind, r.result, effects])
}

/// The spec without the first, middle and last row the run read from `key`.
/// A generated list is first pinned as the run saw it: that spec comes first.
fn dropped_rows(app: &App, spec: &RunSpec, top: &RunRecord, key: &str) -> (Option<RunSpec>, Vec<(String, RunSpec)>) {
    let picks = |n: usize| {
        let mut v = vec![("first", 0), ("middle", n / 2), ("last", n.saturating_sub(1))];
        v.dedup_by_key(|x| x.1);
        v
    };
    if let Some(q) = app.manifest.function(key).and_then(|s| s.query.as_ref()) {
        let d = &app.manifest.datasets[&q.dataset];
        let items = q.page.as_ref().and_then(|p| p.items.as_deref());
        let mut keys: Vec<Value> = top
            .events
            .iter()
            .filter(|e| e.func == key)
            .filter_map(|e| e.result.as_ref())
            .filter_map(|v| match items {
                Some(field) => v.get("ok").unwrap_or(v).get(field).and_then(Value::as_array),
                None => crate::detect::list_in(v),
            })
            .flatten()
            .filter_map(|item| match q.select.as_deref() {
                None => item.get(&d.key).cloned(),
                Some(f) if f == d.key => Some(item.clone()),
                Some(_) => None,
            })
            .collect();
        // A list read twice names each row twice.
        let mut seen = BTreeSet::new();
        keys.retain(|k| seen.insert(k.to_string()));
        if keys.is_empty()
            && let Ok(state) = app.initial_state(&spec.plan, spec.seed)
        {
            keys = state.tables.get(&q.dataset).into_iter().flatten().map(|r| r[&d.key].clone()).collect();
        }
        if keys.is_empty() {
            return (None, vec![]);
        }
        let drops = picks(keys.len())
            .into_iter()
            .map(|(row, i)| {
                let mut s = spec.clone();
                let edit = crate::dataset::Edit::Drop { dataset: q.dataset.clone(), keys: vec![keys[i].clone()] };
                s.plan.0.entry("_defaults".into()).or_default().dataset_edits.push(edit);
                (row.to_string(), s)
            })
            .collect();
        return (None, drops);
    }
    // A list the plan returns, or the one generated list the run read: the
    // same list without one element.
    let literal = spec.plan.0.get(key).is_some_and(|p| p.response.ret.is_some());
    let mut base = spec.clone();
    if !literal {
        let calls: Vec<_> = top.events.iter().filter(|e| e.func == key).collect();
        let [call] = calls[..] else { return (None, vec![]) };
        let Some(seen) = call.result.clone() else { return (None, vec![]) };
        base.plan.0.entry(key.to_string()).or_default().response.ret = Some(seen);
    }
    let Some(n) = base.plan.0.get(key).and_then(|p| p.response.ret.as_ref()).and_then(crate::detect::list_in).map(Vec::len).filter(|n| *n > 0) else {
        return (None, vec![]);
    };
    let drops = picks(n)
        .into_iter()
        .map(|(row, i)| {
            let mut s = base.clone();
            if let Some(list) = s.plan.0.get_mut(key).and_then(|p| p.response.ret.as_mut()).and_then(list_in_mut) {
                list.remove(i);
            }
            (row.to_string(), s)
        })
        .collect();
    (if literal { None } else { Some(base) }, drops)
}

fn list_in_mut(v: &mut Value) -> Option<&mut Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 && (o.contains_key("ok") || o.contains_key("some")) => o.values_mut().next().and_then(list_in_mut),
        _ => None,
    }
}

/// The arguments convert to the export's parameter types.
fn fits(app: &App, s: &RunSpec) -> bool {
    let Ok(export) = app.export(&s.export) else { return true };
    export.ty.params().zip(&s.args).all(|((_, ty), v)| json_to_val(v, &ty).is_ok())
}

#[derive(Debug, Clone, Serialize)]
pub struct FanOut {
    pub func: String,
    pub base_calls: u32,
    pub max_calls: u32,
    pub knob: Knob,
    pub n: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub law: Option<String>,
    pub run: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AmplifyReport {
    pub knobs: Vec<Knob>,
    /// Request keys found in the binary's strings that change behaviour.
    pub discovered_keys: Vec<String>,
    /// Modes found: request values and host values that change behaviour.
    pub contexts: Vec<String>,
    pub fan_out: Vec<FanOut>,
    /// Pairs of knobs whose effects on one function multiply.
    pub nested: Vec<Nested>,
    pub reports: Vec<ScaleReport>,
    /// Findings of amplify itself (the reports carry their own).
    pub findings: Vec<Finding>,
    pub runs: u32,
}

/// Two knobs that drive up calls to one function together: calls at
/// (2, 2), (2, 8), (8, 2), (8, 8). `interaction` is the part of the
/// growth that is a product (1 for one call per outer × inner element).
#[derive(Debug, Clone, Serialize)]
pub struct Nested {
    pub func: String,
    pub outer: Knob,
    pub inner: Knob,
    pub calls: [u32; 4],
    pub interaction: f64,
    pub run: String,
}

/// Knob pairs tried for nesting.
const MAX_PAIRS: usize = 10;
/// Interaction from which calls count as nested (N × M).
const NESTED_MIN: f64 = 0.5;

/// A finding of a knob turned in a mode (`query.view=week`): its own id,
/// and the mode in the title and detail.
pub fn in_context(f: Finding, label: &str) -> Finding {
    let mut detail = f.detail;
    if let Value::Object(d) = &mut detail {
        d.insert("context".into(), json!(label));
    }
    Finding::new(&f.kind, &format!("{}\0{label}", f.id), f.severity, format!("{} (with {label})", f.title), detail, f.run.as_deref())
}

/// Pairs of knobs that each drive up calls to the same function, turned
/// together: one call per pair of elements is a loop inside a loop.
fn nested(app: &App, base: &RunSpec, reports: &[ScaleReport], only: Option<&str>, run: Runner) -> (Vec<Nested>, Vec<Finding>) {
    let mut growers: BTreeMap<&str, Vec<&Knob>> = BTreeMap::new();
    for r in reports.iter().filter(|r| r.context.is_none() && !matches!(r.knob, Knob::FieldLen(_))) {
        let mut funcs: BTreeSet<&str> = BTreeSet::new();
        for p in &r.points {
            for (f, c) in &p.calls {
                let first = r.points.first().and_then(|p0| p0.calls.get(f)).copied().unwrap_or(0);
                if *c > first && !matches!(&r.knob, Knob::HostList(src) if src == f) && only.is_none_or(|o| f.contains(o)) {
                    funcs.insert(f);
                }
            }
        }
        for f in funcs {
            growers.entry(f).or_default().push(&r.knob);
        }
    }
    let mut pairs: Vec<(&str, &Knob, &Knob)> = Vec::new();
    for (f, ks) in &growers {
        for (i, a) in ks.iter().enumerate() {
            for b in &ks[i + 1..] {
                if a != b && pairs.len() < MAX_PAIRS {
                    pairs.push((f, a, b));
                }
            }
        }
    }
    let specs: Vec<Option<RunSpec>> = pairs.iter().flat_map(|(_, a, b)| nested_specs(app, base, a, b)).collect();
    let recs = par::map(&specs, |s| s.as_ref().map(run));
    pairs.iter().zip(recs.chunks(4)).filter_map(|((f, a, b), rs)| nested_finding(&base.export, f, a, b, rs)).unzip()
}

/// The four runs a nesting is measured on: `a` and `b` at 2 and 8.
fn nested_specs(app: &App, base: &RunSpec, a: &Knob, b: &Knob) -> [Option<RunSpec>; 4] {
    [(2, 2), (2, 8), (8, 2), (8, 8)].map(|(x, y)| apply(app, base, a, x).and_then(|s| apply(app, &s, b, y)).ok())
}

/// The nested fan-out the four runs show, if calls to `f` grow with the
/// product of `a` and `b`.
fn nested_finding(export: &str, f: &str, a: &Knob, b: &Knob, rs: &[Option<RunRecord>]) -> Option<(Nested, Finding)> {
    let rs = rs.iter().map(|r| r.as_ref().filter(|r| r.outcome.kind == OutcomeKind::Ok)).collect::<Option<Vec<_>>>()?;
    let c: Vec<u32> = rs.iter().map(|r| r.call_counts().into_iter().find(|(g, _)| g == f).map_or(0, |(_, n)| n)).collect();
    let d = (c[3] as f64 - c[2] as f64 - c[1] as f64 + c[0] as f64) / 36.0;
    if d < NESTED_MIN {
        return None;
    }
    let n = Nested {
        func: f.to_string(),
        outer: a.clone(),
        inner: b.clone(),
        calls: [c[0], c[1], c[2], c[3]],
        interaction: (d * 100.0).round() / 100.0,
        run: rs[3].id.clone(),
    };
    let finding = Finding::new(
        "nested_fan_out",
        &format!("{export}\0{f}\0{a:?}\0{b:?}"),
        Severity::Warn,
        format!("{f} is called for each pair of elements: {} × {} (8 × 8 gives {} calls)", a.describe(), b.describe(), c[3]),
        serde_json::json!({"func": f, "knobs": [a, b], "calls_2x2": c[0], "calls_2x8": c[1], "calls_8x2": c[2], "calls_8x8": c[3], "interaction": n.interaction}),
        Some(&n.run),
    );
    Some((n, finding))
}

/// A nested fan-out measured again from `base` (to confirm it).
pub fn nested_again(app: &App, base: &RunSpec, f: &str, a: &Knob, b: &Knob, run: Runner) -> Option<Finding> {
    let recs: Vec<Option<RunRecord>> = nested_specs(app, base, a, b).iter().map(|s| s.as_ref().map(run)).collect();
    nested_finding(&base.export, f, a, b, &recs).map(|(_, f)| f)
}

/// A mode of the app, found by trying values from the binary: a request
/// field (`method=POST`) or what a host function returns (`hour = 13`).
pub struct Ctx {
    pub label: String,
    pub spec: RunSpec,
    /// The request field it sets (not turned as a knob in this context).
    pub field: Option<String>,
    /// Knobs only found in this context.
    pub knobs: Vec<Knob>,
}

/// Outcome and calls, without the output: a host value that changes
/// what the page prints is no mode.
fn calls_behaviour(r: &RunRecord) -> String {
    let calls: Vec<String> = r.call_counts().into_iter().map(|(k, n)| format!("{k}×{n}")).collect();
    format!("{:?}|{}", r.outcome.kind, calls.join(","))
}

const MAX_CONTEXTS: usize = 24;

/// Keys of a `[key, value]` list the app reads, from dictionary words:
/// by a change in behaviour, or by fuel (byte-wise compares, solved byte by
/// byte). Returns (key, behaviour with value "1").
fn discover_keys(base: &RunSpec, prefix: &str, words: &[String], run: Runner) -> Vec<(String, String)> {
    let with = |pairs: &[(&str, &str)]| -> RunSpec {
        let mut spec = base.clone();
        for (k, v) in pairs {
            let full = format!("{prefix}{k}");
            let (i, path) = split_arg(&full);
            if let Some(a) = spec.args.get_mut(i) {
                let _ = set_text(a, path, v);
            }
        }
        spec
    };
    let base_b = behaviour(&run(base));
    // Per word: behaviour with value "1" and "10", and fuel with "1". A key
    // whose value only reaches a host call (`?sku=` pasted into SQL) changes
    // neither the page nor the calls: a marker value shows it in the arguments.
    let marker = "zq7xk2";
    let probes = par::map(words, |w| {
        let r1 = run(&with(&[(w, "1")]));
        let r10 = run(&with(&[(w, "10")]));
        let (b1, b10) = (behaviour(&r1), behaviour(&r10));
        let passed = b1 == b10 && b1 == base_b && {
            let r = run(&with(&[(w, marker)]));
            r.events.iter().any(|e| e.args.values().any(|v| v.to_string().contains(marker)))
        };
        (b1, b10, r1.totals.fuel, passed)
    });
    // Fuel of an unread key, per key length; None if unread keys of the
    // same length cost different fuel (fuel says nothing).
    let lens: Vec<usize> = words.iter().map(String::len).collect::<BTreeSet<_>>().into_iter().collect();
    let unread: BTreeMap<usize, Option<u64>> = lens
        .iter()
        .copied()
        .zip(par::map(&lens, |&len| {
            let a = run(&with(&[(&filler(len, '\u{1}'), "1")])).totals.fuel;
            let b = run(&with(&[(&filler(len, '\u{2}'), "1")])).totals.fuel;
            (a == b).then_some(a)
        }))
        .collect();
    let mut keys: Vec<(String, String)> = Vec::new();
    let mut fuel_only: BTreeMap<usize, Vec<(u64, String)>> = BTreeMap::new();
    for (w, (b1, b10, fuel, passed)) in words.iter().zip(probes) {
        if b1 != b10 || b1 != base_b || passed {
            keys.push((w.clone(), b1));
        } else if unread[&w.len()].is_some_and(|f| f != fuel) {
            fuel_only.entry(w.len()).or_default().push((fuel, w.clone()));
        }
    }
    let fuel_only: Vec<(usize, Vec<(u64, String)>)> = fuel_only.into_iter().collect();
    let solved = par::map(&fuel_only, |(len, ws)| {
        let mut ws = ws.clone();
        ws.sort();
        let key = solve_key(*len, &|k| run(&with(&[(k, "1")])).totals.fuel).unwrap_or_else(|| ws.last().map(|w| w.1.clone()).unwrap_or_default());
        let b1 = (!key.is_empty()).then(|| behaviour(&run(&with(&[(&key, "1")]))));
        (key, b1)
    });
    for (key, b1) in solved {
        if let Some(b1) = b1
            && !keys.iter().any(|(k, _)| *k == key)
        {
            keys.push((key, b1));
        }
    }
    keys
}

/// Integer constants that functions reaching a platform host function
/// compare against, most common first.
pub fn compare_constants(st: &Statics, limit: usize) -> Vec<i64> {
    let mut count: BTreeMap<i64, u32> = BTreeMap::new();
    for m in &st.modules {
        let reach = m.host_reach();
        for f in m.funcs.iter().filter(|f| reach.contains_key(&f.index)) {
            for &c in &f.cmp_consts {
                if (2..=1_000_000).contains(&c) {
                    *count.entry(c).or_default() += 1;
                }
            }
        }
    }
    let mut v: Vec<(i64, u32)> = count.into_iter().collect();
    v.sort_by_key(|(c, n)| (std::cmp::Reverse(*n), *c));
    v.into_iter().take(limit).map(|(c, _)| c).collect()
}

/// What a result type holds: (numbers, strings).
fn holds(t: &Type) -> (bool, bool) {
    match t {
        Type::List(l) => holds(&l.ty()),
        Type::Option(o) => holds(&o.ty()),
        Type::Result(r) => {
            let a = r.ok().map(|t| holds(&t)).unwrap_or_default();
            let b = r.err().map(|t| holds(&t)).unwrap_or_default();
            (a.0 || b.0, a.1 || b.1)
        }
        Type::Record(r) => r.fields().map(|f| holds(&f.ty)).fold((false, false), |a, b| (a.0 || b.0, a.1 || b.1)),
        Type::Tuple(t) => t.types().map(|t| holds(&t)).fold((false, false), |a, b| (a.0 || b.0, a.1 || b.1)),
        Type::String => (false, true),
        Type::S8 | Type::U8 | Type::S16 | Type::U16 | Type::S32 | Type::U32 | Type::S64 | Type::U64 => (true, false),
        _ => (false, false),
    }
}

/// What `amplify` (and the fuzzer's seeding) learns about the app before
/// turning knobs: the knobs, request keys the app reads, and its modes.
pub struct Discovery {
    pub knobs: Vec<Knob>,
    /// Request key paths found (`query.days`, `form.copies (with method=POST)`).
    pub discovered: Vec<String>,
    /// Plain key paths, for mutating requests (`query.days`).
    pub keys: Vec<String>,
    pub contexts: Vec<Ctx>,
    pub base_run: RunRecord,
}

/// Finds knobs, keys and modes, from the example request (already steady).
pub fn discover(app: &App, base: &RunSpec, dict_limit: usize, run: Runner) -> Result<Discovery> {
    let base_run = run(base);
    if base_run.capture_limited {
        bail!("run {}: {}", base_run.id, base_run.outcome.message.as_deref().unwrap_or("evidence capture is incomplete"));
    }
    let base_b = behaviour(&base_run);
    let base_cb = calls_behaviour(&base_run);
    let st = Statics::parse(&app.bytes)?;
    let words = dictionary(&st, dict_limit);
    let mut knobs: Vec<Knob> = list_functions(app).into_iter().map(Knob::HostList).collect();
    let mut discovered = Vec::new();
    let mut ctxs: Vec<Ctx> = Vec::new();
    let mut seen_b = BTreeSet::from([base_b.clone()]);
    let (fields, pair_lists) = if base.args.is_empty() { (vec![], vec![]) } else { request_knobs(&base.args) };
    knobs.extend(fields.iter().cloned());

    // 1. Modes from plain string fields (`method=POST`), clock fields aside.
    let clock: BTreeSet<String> = app.manifest.entry.iter().flat_map(|e| e.fields.keys().map(|p| e.arg_path(p))).collect();
    let in_pairs = |p: &str| pair_lists.iter().any(|l| p.starts_with(&format!("{l}.")) || l == "@0");
    let mut tries: Vec<(String, String, RunSpec)> = Vec::new();
    for k in &fields {
        let Knob::FieldLen(path) = k else { continue };
        if clock.contains(path) || in_pairs(path) {
            continue;
        }
        for w in &words {
            let mut spec = base.clone();
            let (i, p) = split_arg(path);
            if spec.args.get_mut(i).is_none_or(|a| set_text(a, p, w).is_err()) {
                break;
            }
            tries.push((path.clone(), w.clone(), spec));
        }
    }
    let seen = par::map(&tries, |(_, _, s)| {
        let r = run(s);
        (r.outcome.kind == OutcomeKind::Ok).then(|| behaviour(&r))
    });
    for ((path, w, spec), b) in tries.into_iter().zip(seen) {
        if let Some(b) = b
            && seen_b.insert(b)
            && ctxs.len() < MAX_CONTEXTS
        {
            ctxs.push(Ctx { label: format!("{path}={w}"), spec, field: Some(path), knobs: vec![] });
        }
    }

    // 1b. Pages the base page links to and forms it submits (`POST /add`
    //     needs two fields at once; the app's own form has both).
    let (request, entry_fields) = crate::fuzz::request_fields(app);
    let inputs = base_run.result.as_ref().map(crate::fuzz::form_inputs).unwrap_or_default();
    let ones: Vec<String> = inputs.iter().map(|_| "1".to_string()).collect();
    let mut crawl: Vec<(String, RunSpec)> = Vec::new();
    for u in crate::urls::extract_output(&base_run, &app.manifest).into_iter().filter(|u| u.kind == "same_host").take(MAX_CRAWL) {
        let mut spec = base.clone();
        if let Some(req) = spec.args.get_mut(request)
            && crate::fuzz::crawl_into(req, &entry_fields, &u.url, &u.method, &inputs, &ones)
            && !crawl.iter().any(|(_, s)| s.args == spec.args)
        {
            crawl.push((format!("{} {}", u.method, u.url), spec));
        }
    }
    let seen = par::map(&crawl, |(_, s)| {
        let r = run(s);
        (r.outcome.kind == OutcomeKind::Ok).then(|| behaviour(&r))
    });
    for ((label, spec), b) in crawl.into_iter().zip(seen) {
        if let Some(b) = b
            && seen_b.insert(b)
            && ctxs.len() < MAX_CONTEXTS
        {
            ctxs.push(Ctx { label, spec, field: None, knobs: vec![] });
        }
    }

    // 2. Keys of `[key, value]` lists, in the base request and in each mode
    //    so far (`form.copies` may only be read on POST). Values of a key
    //    that change behaviour are modes too (`view=week`).
    let field_ctxs = ctxs.len();
    // Short keys (`q`, `id`) are often compared inline and never stored as
    // strings: try common ones too.
    let mut key_words = words.clone();
    key_words.extend(COMMON_KEYS.iter().map(|k| k.to_string()).filter(|k| !words.contains(k)));
    // A whole URL (Fastly, wasi:http): the keys of its query, as `uri?key`.
    let mut prefixes: Vec<String> = pair_lists.iter().map(|l| format!("{l}.")).collect();
    let (request, fields) = crate::fuzz::request_fields(app);
    if let Some(req) = base.args.get(request) {
        let at = if request == 0 { String::new() } else { format!("@{request}.") };
        if let Some(p) = crate::fuzz::role_path(&fields, req, "uri").filter(|p| crate::harness::field(req, p).is_some_and(Value::is_string)) {
            prefixes.push(format!("{at}{p}?"));
        }
    }
    for c in 0..=field_ctxs {
        let spec = if c == 0 { base.clone() } else { ctxs[c - 1].spec.clone() };
        let ref_b = behaviour(&run(&spec));
        for prefix in &prefixes {
            for (k, b1) in discover_keys(&spec, prefix, &key_words, run) {
                let path = format!("{prefix}{k}");
                let label = if c == 0 { path.clone() } else { format!("{path} (with {})", ctxs[c - 1].label) };
                if !discovered.contains(&label) {
                    discovered.push(label);
                }
                if c == 0 {
                    knobs.push(Knob::Field(path.clone()));
                } else {
                    ctxs[c - 1].knobs.push(Knob::Field(path.clone()));
                }
                let mut seen = BTreeSet::from([b1, ref_b.clone()]);
                let tries: Vec<(&String, RunSpec)> = words
                    .iter()
                    .filter_map(|v| {
                        let mut s = spec.clone();
                        let (i, p) = split_arg(&path);
                        set_text(s.args.get_mut(i)?, p, v).ok()?;
                        Some((v, s))
                    })
                    .collect();
                let bs = par::map(&tries, |(_, s)| behaviour(&run(s)));
                // Free text (a search box echoed into the page): almost
                // every value behaves differently. A mode switch has few.
                let distinct = bs.iter().collect::<BTreeSet<_>>().len();
                if distinct > MAX_VALUE_MODES {
                    continue;
                }
                for ((v, s), b) in tries.into_iter().zip(bs) {
                    if seen.insert(b.clone()) && seen_b.insert(b) && ctxs.len() < MAX_CONTEXTS {
                        let parent = if c == 0 { String::new() } else { format!("{}, ", ctxs[c - 1].label) };
                        ctxs.push(Ctx { label: format!("{parent}{path}={v}"), spec: s, field: Some(path.clone()), knobs: vec![] });
                    }
                }
            }
        }
    }

    // 3. Modes from what host functions return: every number (or string)
    //    set to a value the code compares against (`if b.hour == 13`).
    let consts = compare_constants(&st, 32);
    let funcs: Vec<_> = app.imports.iter().filter(|i| i.kind == ImportKind::Platform).flat_map(|i| i.funcs.iter()).collect();
    let mut tries: Vec<(String, String, RunSpec)> = Vec::new();
    for f in funcs {
        let Some(t) = f.ty.results().next() else { continue };
        let (nums, strs) = holds(&t);
        let values: Vec<(String, String)> = consts
            .iter()
            .filter(|_| nums)
            .map(|c| (format!("cast:{c}"), format!("numbers = {c}")))
            .chain(words.iter().filter(|_| strs).map(|w| (format!("={w}"), format!("strings = {w:?}"))))
            .collect();
        for (v, what) in values {
            let mut spec = base.clone();
            let mut opts = GenOpts { list_len: Some(1), options: Some("some".into()), results: Some("ok".into()), ..Default::default() };
            if what.starts_with("numbers") {
                opts.numbers = Some(v);
            } else {
                opts.strings = Some(v);
            }
            let fp = spec.plan.0.entry(f.key.clone()).or_default();
            fp.response = Response { generate: Some(opts), latency_ms: fp.response.latency_ms, ..Default::default() };
            tries.push((f.key.clone(), what, spec));
        }
    }
    let bs = par::map(&tries, |(_, _, s)| {
        let r = run(s);
        (r.outcome.kind == OutcomeKind::Ok).then(|| calls_behaviour(&r))
    });
    for ((key, what, spec), b) in tries.into_iter().zip(bs) {
        if let Some(b) = b
            && b != base_cb
            && seen_b.insert(b)
            && ctxs.len() < MAX_CONTEXTS
        {
            ctxs.push(Ctx { label: format!("{key} returns {what}"), spec, field: None, knobs: vec![] });
        }
    }

    let mut keys: Vec<String> = Vec::new();
    for k in knobs.iter().chain(ctxs.iter().flat_map(|c| c.knobs.iter())) {
        if let Knob::Field(p) = k
            && prefixes.iter().any(|l| p.starts_with(l.as_str()))
            && !keys.contains(p)
        {
            keys.push(p.clone());
        }
    }
    Ok(Discovery { knobs, discovered, keys, contexts: ctxs, base_run })
}

/// Finds the knobs and turns each of them, in the base request and in
/// every mode (context) the app has.
pub fn amplify(app: &App, base: &RunSpec, only: Option<&str>, dict_limit: usize, run: Runner) -> Result<AmplifyReport> {
    let mut base = RunSpec { plan: steady(&base.plan), ..base.clone() };
    // Enough fuel to see a production overrun; hangs end sooner.
    base.fuel = base.fuel.min(app.manifest.limits.fuel.saturating_mul(2));
    let runs = std::sync::atomic::AtomicU32::new(0);
    let counted = |s: &RunSpec| {
        runs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        run(s)
    };
    let Discovery { mut knobs, discovered, contexts: ctxs, base_run, .. } = discover(app, &base, dict_limit, &counted)?;
    knobs.sort();
    knobs.dedup();
    // Every knob in the base request, then again in each mode (except the
    // mode's own field): all scaled at once.
    let mut jobs: Vec<(Option<&Ctx>, Knob)> = knobs.iter().map(|k| (None, k.clone())).collect();
    for c in &ctxs {
        let mut ks: Vec<&Knob> = knobs.iter().chain(c.knobs.iter()).collect();
        ks.sort();
        ks.dedup();
        for k in ks.into_iter().filter(|k| !matches!(k, Knob::Field(p) | Knob::FieldLen(p) if Some(p) == c.field.as_ref())) {
            jobs.push((Some(c), k.clone()));
        }
    }
    let scaled = par::map(&jobs, |(c, k)| scale(app, c.map_or(&base, |c| &c.spec), k.clone(), &default_sizes(k), &counted).ok());
    let mut reports = Vec::new();
    for ((c, _), r) in jobs.iter().zip(scaled) {
        let Some(mut r) = r else { continue };
        if let Some(c) = c {
            r.findings = r.findings.into_iter().map(|f| in_context(f, &c.label)).collect();
            r.context = Some(c.label.clone());
        }
        reports.push(r);
    }
    dedupe_by_law(&mut reports);
    for c in &ctxs {
        for k in &c.knobs {
            if !knobs.contains(k) {
                knobs.push(k.clone());
            }
        }
    }
    // Fan-out table: the most calls each host function was driven to.
    let base_calls: BTreeMap<String, u32> = base_run.call_counts().into_iter().collect();
    let mut table: BTreeMap<String, FanOut> = BTreeMap::new();
    for r in &reports {
        for p in &r.points {
            for (f, &c) in &p.calls {
                if let Knob::HostList(src) = &r.knob
                    && src == f
                {
                    continue;
                }
                if only.is_some_and(|o| !f.contains(o)) {
                    continue;
                }
                let law = r.growth.iter().find(|g| g.metric == format!("calls {f}")).map(|g| g.law.text.clone());
                let better = table.get(f).is_none_or(|t| c > t.max_calls || (c == t.max_calls && law.is_some() && t.law.is_none()));
                if better {
                    table.insert(
                        f.clone(),
                        FanOut {
                            func: f.clone(),
                            base_calls: *base_calls.get(f).unwrap_or(&0),
                            max_calls: c,
                            knob: r.knob.clone(),
                            n: p.n,
                            law,
                            run: p.run.clone(),
                        },
                    );
                }
            }
        }
    }
    let mut fan_out: Vec<FanOut> = table.into_values().filter(|f| f.max_calls > f.base_calls).collect();
    fan_out.sort_by_key(|f| std::cmp::Reverse(f.max_calls));
    let contexts = ctxs.iter().map(|c| c.label.clone()).collect();
    let (nested, findings) = nested(app, &base, &reports, only, &counted);
    Ok(AmplifyReport { knobs, discovered_keys: discovered, contexts, fan_out, nested, reports, findings, runs: runs.into_inner() })
}

/// A key with more distinct behaviours over the dictionary is free text.
const MAX_VALUE_MODES: usize = 8;

/// Links and forms of the base page tried as modes.
const MAX_CRAWL: usize = 16;

/// Request keys common on the web, tried besides the binary's words.
const COMMON_KEYS: &[&str] = &[
    "q", "s", "id", "p", "n", "page", "limit", "offset", "count", "size", "sort", "order", "search", "query", "filter", "from", "to", "date", "day", "days",
    "start", "end", "view", "mode", "type", "lang", "next", "url", "redirect", "return", "name", "user", "debug",
];

/// Host lists longer than this are unusual: superlinear growth that only
/// breaks a limit beyond it is a hint (info), not a warning.
const HOST_LIST_REALISTIC: u64 = 1000;

/// The same law under many modes (`view=week`, `error=x`, …) is one
/// problem: keep the finding without a mode (or the first mode) and list
/// the other modes on it.
fn dedupe_by_law(reports: &mut [ScaleReport]) {
    let key = |f: &Finding| {
        let d = &f.detail;
        format!("{}\0{}\0{}\0{}\0{}", f.kind, d["knob"], d["metric"], d["func"], d["class"])
    };
    let mut order: Vec<usize> = (0..reports.len()).collect();
    order.sort_by_key(|&i| reports[i].context.is_some());
    let mut first: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut also: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for &i in &order {
        let ctx = reports[i].context.clone();
        let mut keep = Vec::new();
        for f in std::mem::take(&mut reports[i].findings) {
            let k = key(&f);
            match first.entry(k) {
                std::collections::btree_map::Entry::Occupied(o) => {
                    also.entry(o.key().clone()).or_default().push(ctx.clone().unwrap_or_else(|| "no mode".into()));
                }
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert((i, keep.len()));
                    keep.push(f);
                }
            }
        }
        reports[i].findings = keep;
    }
    for (k, modes) in also {
        let (i, j) = first[&k];
        let f = &mut reports[i].findings[j];
        if let serde_json::Value::Object(o) = &mut f.detail {
            o.insert("also_with".into(), serde_json::json!(modes));
        }
        f.title = format!("{} (and {} more modes)", f.title, modes.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::natural::Natural;
    use crate::record::{HostCall, Outcome, Totals};
    use crate::statics::{FuncInfo as StaticFunc, ImportInfo, ModuleInfo};
    use std::sync::LazyLock;

    const ALL: &str = "test:shop/items#all";
    const PAGED: &str = "test:shop/items#paged";
    const GET: &str = "test:shop/items#get";
    const SAVE: &str = "test:shop/items#save";
    const COUNT: &str = "test:shop/items#count";

    const WIT: &str = r#"
        package test:shop;

        interface items {
            record item { id: u32, name: string }
            record big { id: u64 }
            all: func() -> list<item>;
            paged: func() -> list<item>;
            maybe: func() -> option<list<item>>;
            fallible: func() -> result<list<item>, string>;
            names: func() -> list<string>;
            ids: func() -> list<u32>;
            bigs: func() -> list<big>;
            no-ok: func() -> result<_, string>;
            get: func(id: u32) -> option<item>;
            save: func(id: string);
            count: func() -> u32;
            pair: func() -> tuple<u8, bool>;
            ratio: func() -> f64;
            either: func() -> result<u32, string>;
        }

        world app {
            import items;
            record request { days: u32, small: u8, name: string, query: list<tuple<string, string>> }
            export handle: func(req: request, extra: list<u32>) -> string;
        }
    "#;

    /// A component that imports `items` and exports `handle`; it never runs.
    static COMPONENT: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let mut resolve = wit_parser::Resolve::new();
        let pkg = resolve.push_str("shop.wit", WIT).unwrap();
        let world = resolve.select_world(&[pkg], Some("app")).unwrap();
        let mut module = wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
        wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
        wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
    });

    fn app(manifest: &str) -> App {
        let m: Manifest = toml::from_str(&format!("[app]\nwasm = \"shop.wasm\"\n{manifest}")).unwrap();
        App::from_bytes(m, COMPONENT.clone()).unwrap()
    }

    fn result_type(app: &App, f: &str) -> Type {
        platform_fn(app, f).unwrap().ty.results().next().unwrap()
    }

    fn base(app: &App) -> RunSpec {
        let req = json!({"days": 3, "small": 1, "name": "ada", "query": [["view", "list"]]});
        app.spec(app.export("handle").unwrap(), vec![req, json!([1, 2])], Plan::default(), 7)
    }

    fn call(func: &str, args: Value, result: Option<Value>) -> HostCall {
        let result_items = result.as_ref().and_then(crate::detect::list_in).map(|l| l.len() as u32);
        HostCall { func: func.into(), args: args.as_object().cloned().unwrap_or_default(), result, result_items, ..HostCall::default() }
    }

    fn record(spec: &RunSpec, kind: OutcomeKind, events: Vec<HostCall>, result: Value) -> RunRecord {
        RunRecord {
            id: spec.id(),
            spec: spec.clone(),
            outcome: Outcome { kind, message: None, stack: vec![] },
            result: Some(result),
            command_exit_code: None,
            totals: Totals { host_calls: events.len() as u32, ..Totals::default() },
            events,
            capture_limited: false,
            guest_error: None,
            rejected_output: None,
            memory_limit_hit: false,
            stdout: String::new(),
            stderr: String::new(),
            shopify: None,
        }
    }

    fn point(n: u64) -> Point {
        Point {
            n,
            run: format!("r{n}"),
            outcome: OutcomeKind::Ok,
            calls: BTreeMap::new(),
            host_calls: 0,
            fuel: 5000,
            peak_memory: 1 << 16,
            virtual_ms: json!(0),
            virtual_ns: Natural::default(),
            cost: 0,
            output_bytes: 100,
            host_arg_bytes: 0,
            rows: BTreeMap::new(),
            host_result_bytes: 0,
            fuel_limit: None,
        }
    }

    fn points(sizes: &[u64], set: impl Fn(u64, &mut Point)) -> Vec<Point> {
        sizes
            .iter()
            .map(|&n| {
                let mut p = point(n);
                set(n, &mut p);
                p
            })
            .collect()
    }

    /// Calls to `f` at each size.
    fn calls(sizes: &[u64], f: &'static str, c: impl Fn(u64) -> u64) -> Vec<Point> {
        points(sizes, |n, p| {
            p.calls.insert(f.into(), c(n) as u32);
        })
    }

    fn growth<'a>(r: &'a ScaleReport, metric: &str) -> &'a Growth {
        r.growth.iter().find(|g| g.metric == metric).unwrap_or_else(|| panic!("no growth of {metric}: {:?}", r.growth))
    }

    fn found<'a>(r: &'a ScaleReport, kind: &str) -> Vec<&'a Finding> {
        r.findings.iter().filter(|f| f.kind == kind).collect()
    }

    fn one<'a>(r: &'a ScaleReport, kind: &str) -> &'a Finding {
        let f = found(r, kind);
        assert_eq!(f.len(), 1, "{kind}: {:#?}", r.findings);
        f[0]
    }

    const SIZES: [u64; 5] = [1, 2, 4, 8, 16];

    // --- Knobs -----------------------------------------------------------

    #[test]
    fn knobs_parse_from_their_prefix_or_shape() {
        assert_eq!(Knob::parse("fn:customers#all").unwrap(), Knob::HostList("customers#all".into()));
        assert_eq!(Knob::parse("items#all").unwrap(), Knob::HostList("items#all".into()));
        assert_eq!(Knob::parse("len:query.q").unwrap(), Knob::FieldLen("query.q".into()));
        // An explicit field may contain `#`.
        assert_eq!(Knob::parse("field:a#b").unwrap(), Knob::Field("a#b".into()));
        assert_eq!(Knob::parse("query.days").unwrap(), Knob::Field("query.days".into()));
        assert_eq!(Knob::parse("@1").unwrap(), Knob::Field("@1".into()));
    }

    #[test]
    fn knobs_say_what_n_is() {
        assert_eq!(Knob::HostList("x#all".into()).describe(), "length of the list x#all returns");
        assert_eq!(Knob::Field("@2".into()).describe(), "number of elements in argument 2");
        assert_eq!(Knob::Field("@1.page".into()).describe(), "request field @1.page = n");
        assert_eq!(Knob::Field("query.days".into()).describe(), "request field query.days = n");
        assert_eq!(Knob::FieldLen("name".into()).describe(), "length of request field name");
        let wire = serde_json::to_value(Knob::FieldLen("q".into())).unwrap();
        assert_eq!(wire, json!({"kind": "field_len", "target": "q"}));
        assert_eq!(serde_json::from_value::<Knob>(wire).unwrap(), Knob::FieldLen("q".into()));
    }

    #[test]
    fn argument_paths_split_into_index_and_path() {
        assert_eq!(split_arg("@1.page"), (1, "page"));
        assert_eq!(split_arg("@1.a.b"), (1, "a.b"));
        assert_eq!(split_arg("@2"), (2, ""));
        assert_eq!(split_arg("query.days"), (0, "query.days"));
        // An index that is no number means the first argument.
        assert_eq!(split_arg("@x.y"), (0, "y"));
    }

    #[test]
    fn default_sizes_follow_the_knob() {
        assert_eq!(default_sizes(&Knob::HostList("f".into())), COUNT_SIZES.to_vec());
        assert_eq!(default_sizes(&Knob::Field("f".into())), FIELD_SIZES.to_vec());
        assert_eq!(default_sizes(&Knob::FieldLen("f".into())), LENGTH_SIZES.to_vec());
        // Request fields go further than host lists.
        assert!(FIELD_SIZES.last() > COUNT_SIZES.last());
    }

    // --- Setting request values -------------------------------------------

    #[test]
    fn resized_values_keep_the_old_shape() {
        assert_eq!(resized(Some(&json!(5)), 9, false), json!(9));
        assert_eq!(resized(Some(&json!(5)), 3, true), json!("aaa"));
        assert_eq!(resized(Some(&json!("12")), 4, false), json!("4"));
        assert_eq!(resized(None, 4, false), json!("4"));
        assert_eq!(resized(None, 0, true), json!(""));
        // An empty list has nothing to copy.
        assert_eq!(resized(Some(&json!([])), 4, false), json!("4"));
        assert_eq!(resized(Some(&json!([1, 2])), 0, false), json!([]));
        // Copies of list elements get distinct numbers.
        assert_eq!(resized(Some(&json!([1, 2])), 5, false), json!([1, 2, 1001, 1002, 2001]));
        assert_eq!(
            resized(Some(&json!([{"id": 7, "name": "a"}])), 3, false),
            json!([{"id": 7, "name": "a"}, {"id": 1007, "name": "a"}, {"id": 2007, "name": "a"}])
        );
        // Text cannot be told apart.
        assert_eq!(resized(Some(&json!(["a"])), 2, false), json!(["a", "a"]));
    }

    #[test]
    fn the_first_unsigned_number_is_bumped() {
        let mut v = json!({"a": "x", "b": [-1, 2.5, 3], "c": 4});
        assert!(bump_first_number(&mut v, 10));
        assert_eq!(v, json!({"a": "x", "b": [-1, 2.5, 13], "c": 4}));
        for mut v in [json!(-1), json!(1.5), json!("7"), json!(null), json!([]), json!({})] {
            let before = v.clone();
            assert!(!bump_first_number(&mut v, 10));
            assert_eq!(v, before);
        }
    }

    #[test]
    fn bumping_the_largest_number_does_not_overflow() {
        // A request list may hold the largest u64 (the fuzzer's edge values).
        // It wraps, as release builds always did, and stays distinct.
        assert_eq!(resized(Some(&json!([u64::MAX])), 2, false), json!([u64::MAX, 999]));
    }

    #[test]
    fn query_values_are_read_before_the_fragment() {
        assert_eq!(query_value("/a?x=1&y=2#f", "y").as_deref(), Some("2"));
        assert_eq!(query_value("/a?x=1#y=3", "y"), None);
        assert_eq!(query_value("/a?flag&x=1", "flag").as_deref(), Some(""));
        assert_eq!(query_value("/a?xx=1", "x"), None);
        assert_eq!(query_value("/a", "x"), None);
    }

    #[test]
    fn query_parameters_are_set_once_and_encoded_only_where_needed() {
        assert_eq!(with_query("/a", "n", "5"), "/a?n=5");
        assert_eq!(with_query("/a?", "n", ""), "/a?n=");
        // An existing value is replaced (and moves to the end).
        assert_eq!(with_query("/a?n=1&m=2", "n", "5"), "/a?m=2&n=5");
        // A bare key counts as set; a longer key is another parameter.
        assert_eq!(with_query("/a?&n&nn=3", "n", "7"), "/a?nn=3&n=7");
        // Only what would split the value is encoded; the fragment stays.
        assert_eq!(with_query("/a?n=1#top", "n", "a b&c#d%"), "/a?n=a b%26c%23d%25#top");
        assert_eq!(query_value(&with_query("/a?m=1#f", "n", "9"), "n").as_deref(), Some("9"));
    }

    #[test]
    fn fields_are_set_in_records_pair_lists_and_urls() {
        let mut req = json!({"days": 2, "form": {"n": 1}, "query": [["days", "3"]], "uri": "/p?x=1"});
        set_field(&mut req, "days", 9, false).unwrap();
        set_field(&mut req, "form.n", 4, false).unwrap();
        set_field(&mut req, "form.text", 3, true).unwrap();
        set_field(&mut req, "query.days", 30, false).unwrap();
        set_field(&mut req, "query.limit", 5, false).unwrap();
        set_field(&mut req, "uri?x", 8, false).unwrap();
        set_field(&mut req, "uri?q", 3, true).unwrap();
        assert_eq!(req, json!({"days": 9, "form": {"n": 4, "text": "aaa"}, "query": [["days", "30"], ["limit", "5"]], "uri": "/p?x=8&q=aaa"}));
        assert_eq!(set_field(&mut req, "nope.x", 1, false).unwrap_err().to_string(), "no field nope");
        assert_eq!(set_field(&mut req, "days.x", 1, false).unwrap_err().to_string(), "days.x: not inside a record or a list of pairs");
        assert_eq!(set_field(&mut req, "form?x", 1, false).unwrap_err().to_string(), "no URL field form");
        assert_eq!(set_field(&mut req, "nope?x", 1, false).unwrap_err().to_string(), "no URL field nope");
    }

    #[test]
    fn text_is_set_in_records_pair_lists_and_urls() {
        let mut req = json!({"form": {"name": 1}, "query": [], "uri": "/p?x=1"});
        set_text(&mut req, "form.name", "ada").unwrap();
        set_text(&mut req, "query.view", "week").unwrap();
        set_text(&mut req, "query.view", "month").unwrap();
        set_text(&mut req, "uri?view", "a&b").unwrap();
        assert_eq!(req, json!({"form": {"name": "ada"}, "query": [["view", "month"]], "uri": "/p?x=1&view=a%26b"}));
        assert!(set_text(&mut req, "missing.name", "x").is_err());
        assert!(set_text(&mut req, "form?x", "x").is_err());
    }

    #[test]
    fn keys_compared_byte_by_byte_are_solved_from_fuel() {
        let secret = "k3y-";
        let fuel = |k: &str| 100 + 7 * k.chars().zip(secret.chars()).take_while(|(a, b)| a == b).count() as u64;
        assert_eq!(solve_key(4, &fuel).as_deref(), Some(secret));
        assert_eq!(solve_key(0, &fuel).as_deref(), Some(""));
        // No gradient: every guess costs the same.
        assert_eq!(solve_key(3, &|_| 42), None);
        // A character outside the alphabet ties all guesses.
        let upper = |k: &str| 100 + u64::from(k.starts_with('K'));
        assert_eq!(solve_key(1, &upper), None);
        assert_eq!(filler(3, '~'), "~~~");
        assert_eq!(filler(0, '~'), "");
    }

    // --- Growing host lists -----------------------------------------------

    #[test]
    fn steady_plans_pin_lists_to_one_happy_element() {
        let p = steady(&Plan::default());
        let g = p.0["_defaults"].response.generate.clone().unwrap();
        assert_eq!((g.list_len, g.options.as_deref(), g.results.as_deref()), (Some(1), Some("some"), Some("ok")));
        // Defaults of the plan's own win.
        let mut own = Plan::default();
        own.0.insert("_defaults".into(), FnPlan { response: Response { latency_ms: Some(3.0), ..Default::default() }, ..Default::default() });
        own.0.insert(ALL.into(), FnPlan::default());
        assert_eq!(steady(&own), own);
    }

    #[test]
    fn copies_get_fresh_ids_and_names() {
        let mut e = json!({"id": 3, "n": 9, "name": "Ann #2", "tag": "x"});
        uniquify(&mut e, 4, 10);
        assert_eq!(e, json!({"id": 15, "n": 9, "name": "Ann #5", "tag": "x"}));
        // Without a numeric id, the first number is the id.
        let mut e = json!({"id": "abc", "count": 2, "flag": true});
        uniquify(&mut e, 0, 10);
        assert_eq!(e, json!({"id": "abc #1", "count": 1, "flag": true}));
        let (mut n, mut s, mut b) = (json!(5), json!("s"), json!(true));
        uniquify(&mut n, 4, 0);
        uniquify(&mut s, 4, 0);
        uniquify(&mut b, 4, 0);
        assert_eq!((n, s, b), (json!(5), json!("s #5"), json!(true)), "a number counts on from the largest");
    }

    #[test]
    fn grown_lists_keep_the_template_then_add_copies() {
        let app = app("");
        let ty = result_type(&app, ALL);
        let t = json!([{"id": 4, "name": "a"}, {"id": 9, "name": "b"}]);
        let v = grow(&ty, Some(&t), 5, 1, &GenOpts::default()).unwrap();
        assert_eq!(
            v,
            json!([{"id": 4, "name": "a"}, {"id": 9, "name": "b"}, {"id": 12, "name": "a #3"}, {"id": 13, "name": "b #4"}, {"id": 14, "name": "a #5"}])
        );
        assert_eq!(grow(&ty, Some(&t), 1, 1, &GenOpts::default()).unwrap(), json!([{"id": 4, "name": "a"}]));
        assert_eq!(grow(&ty, Some(&t), 0, 1, &GenOpts::default()).unwrap(), json!([]));
        let names = grow(&result_type(&app, "names"), Some(&json!(["a", "b"])), 4, 1, &GenOpts::default()).unwrap();
        assert_eq!(names, json!(["a", "b", "a #3", "b #4"]));
    }

    #[test]
    fn grown_lists_without_a_template_are_generated_and_distinct() {
        let app = app("");
        let ty = result_type(&app, ALL);
        let v = grow(&ty, None, 6, 3, &GenOpts::default()).unwrap();
        let list = v.as_array().unwrap();
        assert_eq!(list.len(), 6);
        let ids: BTreeSet<u64> = list.iter().map(|e| e["id"].as_u64().unwrap()).collect();
        let names: BTreeSet<&str> = list.iter().map(|e| e["name"].as_str().unwrap()).collect();
        assert_eq!((ids.len(), names.len()), (6, 6), "{v}");
        let Type::List(l) = &ty else { panic!("{ty:?}") };
        assert!(list.iter().all(|e| json_to_val(e, &l.ty()).is_ok()));
        // The same seed grows the same list.
        assert_eq!(grow(&ty, None, 6, 3, &GenOpts::default()).unwrap(), v);
        // An element that does not fit the type is replaced.
        let bad = grow(&ty, Some(&json!([{"id": "x"}])), 2, 3, &GenOpts::default()).unwrap();
        assert!(bad.as_array().unwrap().iter().all(|e| json_to_val(e, &l.ty()).is_ok()), "{bad}");
        // Generate options shape the new elements.
        let opts = GenOpts { strings: Some("=zz".into()), ..Default::default() };
        let zz = grow(&ty, None, 3, 3, &opts).unwrap();
        assert!(zz.as_array().unwrap().iter().all(|e| e["name"].as_str().unwrap().starts_with("zz #")), "{zz}");
    }

    #[test]
    fn copies_of_a_number_list_do_not_repeat_the_template() {
        let app = app("");
        let v = grow(&result_type(&app, "ids"), Some(&json!([1, 2, 3])), 6, 1, &GenOpts::default()).unwrap();
        assert_eq!(v, json!([1, 2, 3, 7, 8, 9]));
        // Ids count on from the largest.
        let v = grow(&result_type(&app, "bigs"), Some(&json!([{"id": 4}, {"id": 2}])), 3, 1, &GenOpts::default()).unwrap();
        assert_eq!(v, json!([{"id": 4}, {"id": 2}, {"id": 7}]));
    }

    #[test]
    fn copies_of_the_largest_id_do_not_overflow() {
        let app = app("");
        let v = grow(&result_type(&app, "bigs"), Some(&json!([{"id": u64::MAX}])), 3, 1, &GenOpts::default()).unwrap();
        assert_eq!(v, json!([{"id": u64::MAX}, {"id": 1}, {"id": 2}]));
    }

    #[test]
    fn lists_inside_options_and_results_grow() {
        let app = app("");
        let t = json!({"some": [{"id": 1, "name": "a"}]});
        let v = grow(&result_type(&app, "maybe"), Some(&t), 2, 1, &GenOpts::default()).unwrap();
        assert_eq!(v, json!({"some": [{"id": 1, "name": "a"}, {"id": 3, "name": "a #2"}]}));
        let t = json!({"ok": [{"id": 1, "name": "a"}]});
        let v = grow(&result_type(&app, "fallible"), Some(&t), 2, 1, &GenOpts::default()).unwrap();
        assert_eq!(v, json!({"ok": [{"id": 1, "name": "a"}, {"id": 3, "name": "a #2"}]}));
        // An error template has no list: a generated one grows.
        let v = grow(&result_type(&app, "fallible"), Some(&json!({"err": "x"})), 3, 1, &GenOpts::default()).unwrap();
        assert_eq!(v["ok"].as_array().unwrap().len(), 3);
        let err = |f: &str| grow(&result_type(&app, f), None, 2, 1, &GenOpts::default()).unwrap_err().to_string();
        assert_eq!(err("no-ok"), "result without an ok type");
        assert_eq!(err("count"), "the result has no list to grow");
        assert_eq!(err("get"), "the result has no list to grow");
    }

    #[test]
    fn list_functions_are_those_that_return_a_list() {
        let app = app("");
        let got: BTreeSet<String> = list_functions(&app).into_iter().collect();
        let want: BTreeSet<String> = ["all", "paged", "maybe", "fallible", "names", "ids", "bigs"].iter().map(|f| format!("test:shop/items#{f}")).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn platform_functions_are_found_by_their_full_key_or_its_end() {
        let app = app("");
        for name in [ALL, "items#all", "all"] {
            assert_eq!(platform_fn(&app, name).map(|f| f.key.as_str()), Some(ALL), "{name}");
        }
        assert!(platform_fn(&app, "ll").is_none());
        assert!(platform_fn(&app, "shop/items#al").is_none());
        assert!(platform_fn(&app, "handle").is_none());
    }

    // --- Applying a knob ----------------------------------------------------

    #[test]
    fn a_host_list_knob_returns_n_elements_and_keeps_the_latency() {
        let app = app("");
        let mut b = base(&app);
        let response = Response { ret: Some(json!([{"id": 1, "name": "a"}])), trap: Some("x".into()), latency_ms: Some(4.0), ..Default::default() };
        b.plan.0.insert(ALL.into(), FnPlan { response, ..Default::default() });
        let s = apply(&app, &b, &Knob::HostList("items#all".into()), 3).unwrap();
        let r = &s.plan.0[ALL].response;
        assert_eq!(r.ret, Some(json!([{"id": 1, "name": "a"}, {"id": 3, "name": "a #2"}, {"id": 4, "name": "a #3"}])));
        assert_eq!((r.trap.as_deref(), r.generate.is_none(), r.latency_ms), (None, true, Some(4.0)));
        assert_eq!(s.args, b.args);
    }

    #[test]
    fn new_host_elements_follow_the_functions_or_the_default_generate_options() {
        let app = app("");
        let generate = |s: &str| Response { generate: Some(GenOpts { strings: Some(format!("={s}")), ..Default::default() }), ..Default::default() };
        let mut b = base(&app);
        b.plan.0.insert("_defaults".into(), FnPlan { response: generate("dflt"), ..Default::default() });
        let names = |s: &RunSpec| -> Vec<String> {
            s.plan.0[ALL].response.ret.as_ref().unwrap().as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap().to_string()).collect()
        };
        let s = apply(&app, &b, &Knob::HostList(ALL.into()), 2).unwrap();
        assert!(names(&s).iter().all(|n| n.starts_with("dflt #")), "{:?}", names(&s));
        b.plan.0.insert(ALL.into(), FnPlan { response: generate("own"), ..Default::default() });
        let s = apply(&app, &b, &Knob::HostList(ALL.into()), 2).unwrap();
        assert!(names(&s).iter().all(|n| n.starts_with("own #")), "{:?}", names(&s));
    }

    #[test]
    fn host_list_knobs_need_a_platform_function_with_a_list() {
        let app = app("");
        let b = base(&app);
        let err = |f: &str| apply(&app, &b, &Knob::HostList(f.into()), 2).unwrap_err().to_string();
        assert_eq!(err("nope#x"), "no platform import nope#x");
        assert_eq!(err("save"), "save returns nothing");
        assert_eq!(err("count"), "the result has no list to grow");
    }

    #[test]
    fn request_knobs_set_fields_lengths_and_whole_arguments() {
        let app = app("");
        let b = base(&app);
        let s = apply(&app, &b, &Knob::Field("days".into()), 40).unwrap();
        assert_eq!(s.args[0]["days"], json!(40));
        let s = apply(&app, &b, &Knob::Field("query.view".into()), 6).unwrap();
        assert_eq!(s.args[0]["query"], json!([["view", "6"]]));
        let s = apply(&app, &b, &Knob::FieldLen("name".into()), 5).unwrap();
        assert_eq!(s.args[0]["name"], json!("aaaaa"));
        let s = apply(&app, &b, &Knob::Field("@1".into()), 3).unwrap();
        assert_eq!(s.args[1], json!([1, 2, 1001]));
        assert_eq!(s.plan, b.plan);
        assert_eq!(apply(&app, &b, &Knob::Field("@5".into()), 3).unwrap_err().to_string(), "the export has no argument 5");
        assert!(apply(&app, &b, &Knob::Field("nope.x".into()), 3).is_err());
    }

    const DATASET: &str = r#"
        [datasets.items]
        rows = 4
        key = "id"
        template = { id = 1, name = "Item" }
        [functions."test:shop/items#all"]
        query = { dataset = "items" }
        [functions."test:shop/items#paged"]
        query = { dataset = "items", page = { max = 50 } }
    "#;

    #[test]
    fn a_dataset_knob_sizes_the_collection() {
        let app = app(DATASET);
        let b = base(&app);
        let s = apply(&app, &b, &Knob::HostList("all".into()), 50).unwrap();
        assert_eq!(s.plan.0["_defaults"].dataset_rows["items"], 50);
        assert!(!s.plan.0.contains_key(ALL));
        assert!(apply(&app, &b, &Knob::HostList("all".into()), 10_000).is_ok());
        assert_eq!(apply(&app, &b, &Knob::HostList("all".into()), 10_001).unwrap_err().to_string(), "dataset scale exceeds 10000");
    }

    #[test]
    fn specs_fit_the_export_or_are_not_requests() {
        let app = app("");
        let mut s = base(&app);
        assert!(fits(&app, &s));
        s.args[0]["small"] = json!(256);
        assert!(!fits(&app, &s));
        s.export = "nope".into();
        assert!(fits(&app, &s));
    }

    // --- Budgets ------------------------------------------------------------

    #[test]
    fn budgets_are_exceeded_only_above_their_limit() {
        let mut p = point(1);
        p.cost = 101;
        assert!(Budget::Cost(100).exceeds(&p) && !Budget::Cost(101).exceeds(&p));
        p.cost = u128::from(u64::MAX) + 1;
        assert!(Budget::Cost(u64::MAX).exceeds(&p));
        p.fuel = 50;
        assert!(Budget::Fuel(40).exceeds(&p) && !Budget::Fuel(50).exceeds(&p));
        // A run's own fuel limit (Shopify) wins over the manifest's.
        p.fuel_limit = Some(60);
        assert!(!Budget::Fuel(40).exceeds(&p));
        p.fuel_limit = Some(49);
        assert!(Budget::Fuel(4000).exceeds(&p));
        p.peak_memory = 10;
        assert!(Budget::Memory(9).exceeds(&p) && !Budget::Memory(10).exceeds(&p));
        p.virtual_ns = Natural::from(2_500_000u64);
        assert!(Budget::Latency(2.0).exceeds(&p) && !Budget::Latency(2.5).exceeds(&p));
        assert!(!Budget::Latency(f64::INFINITY).exceeds(&p) && !Budget::Latency(f64::NAN).exceeds(&p));
        assert_eq!((Budget::Cost(7).approximate(), Budget::Latency(1.5).approximate()), (7.0, 1.5));
        assert_eq!((Budget::Memory(7).display(), Budget::Latency(1.5).display()), (json!(7), json!(1.5)));
    }

    // --- Points -------------------------------------------------------------

    #[test]
    fn a_point_measures_one_run() {
        let app = app("");
        let s = base(&app);
        let list = |n: u32| Some(json!((0..n).map(|i| json!({"id": i, "name": "a"})).collect::<Vec<_>>()));
        let events = vec![call(ALL, json!({}), list(3)), call(GET, json!({"id": 1}), Some(json!({"some": null}))), call(ALL, json!({}), list(2))];
        let mut r = record(&s, OutcomeKind::Ok, events, json!({"a": 1}));
        r.totals.fuel = 9;
        r.totals.cost = 4;
        r.totals.virtual_ns = Natural::from(2_500_000u64);
        r.totals.host_result_bytes = 77;
        r.shopify = Some(crate::shopify::RunInfo::new("t", 1.0));
        let p = Point::of(8, &r);
        assert_eq!((p.n, p.run.as_str(), p.outcome, p.host_calls, p.fuel, p.cost), (8, r.id.as_str(), OutcomeKind::Ok, 3, 9, 4));
        assert_eq!(p.calls, BTreeMap::from([(ALL.to_string(), 2), (GET.to_string(), 1)]));
        assert_eq!(p.rows, BTreeMap::from([(ALL.to_string(), 5)]));
        assert_eq!((p.output_bytes, p.host_arg_bytes, p.host_result_bytes), (7, 2 + 8 + 2, 77));
        assert_eq!(p.virtual_ms, json!(2.5));
        assert_eq!(p.fuel_limit, Some(r.shopify.as_ref().unwrap().instructions_limit));
        r.result = None;
        assert_eq!(Point::of(8, &r).output_bytes, 0);
    }

    // --- Growth laws, breaking points and findings -----------------------------

    #[test]
    fn calls_per_element_are_an_n_plus_1_with_the_measured_break() {
        let app = app("[limits]\ncost_per_request = 100\n");
        let ps = points(&SIZES, |n, p| {
            p.calls.insert(ALL.into(), 1);
            p.calls.insert(GET.into(), (1 + 28 * n) as u32);
            p.cost = u128::from(1 + 28 * n);
        });
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        // Only what changes with n: the one call to `all`, fuel and memory stay.
        let metrics: Vec<&str> = r.growth.iter().map(|g| g.metric.as_str()).collect();
        assert_eq!(metrics, [format!("calls {GET}").as_str(), "cost"]);
        let calls = growth(&r, &format!("calls {GET}"));
        assert_eq!((calls.law.class, calls.law.text.as_str()), (Class::Linear, "1 + 28·n"));
        assert_eq!((calls.breaks_at, calls.limit.clone(), calls.break_evidence), (None, None, None));
        let cost = growth(&r, "cost");
        assert_eq!((cost.breaks_at, cost.break_evidence, cost.predicted_breaks_at), (Some(4), Some("measured"), Some(4)));
        assert_eq!(cost.limit, Some(json!(100)));
        let f = one(&r, "n_plus_1");
        assert_eq!(f.severity, Severity::Fail);
        assert_eq!(f.title, format!("calls to {GET} grow as 1 + 28·n with n = length of the list {ALL} returns; cost exceeds its limit at measured n = 4"));
        assert_eq!(f.detail["breaks_at"], json!([4, "cost"]));
        assert_eq!((&f.detail["func"], &f.detail["class"], &f.detail["law"]), (&json!(GET), &json!("linear"), &json!("1 + 28·n")));
        assert_eq!((f.detail["worst_run"].as_str(), f.run.as_deref()), (Some("r16"), Some("r16")));
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    }

    #[test]
    fn a_host_list_that_breaks_a_limit_within_100_elements_fails() {
        let at = |limit: u64, sizes: &[u64]| {
            let app = app(&format!("[limits]\ncost_per_request = {limit}\n"));
            let ps = points(sizes, |n, p| {
                p.calls.insert(GET.into(), n as u32);
                p.cost = u128::from(10 * n);
            });
            analyze(&app, Knob::HostList(ALL.into()), ps)
        };
        let r = at(1000, &[1, 2, 4, 8]);
        let cost = growth(&r, "cost");
        assert_eq!((cost.law.text.as_str(), cost.breaks_at, cost.break_evidence, cost.predicted_breaks_at), ("10·n", Some(101), Some("inferred"), Some(101)));
        let f = one(&r, "n_plus_1");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.title.ends_with("; cost is predicted to exceed its limit at n = 101"), "{}", f.title);
        assert_eq!(f.detail["break_evidence"], json!("inferred"));
        let r = at(999, &[1, 2, 4, 8]);
        assert_eq!(growth(&r, "cost").breaks_at, Some(100));
        assert_eq!(one(&r, "n_plus_1").severity, Severity::Fail);
        // The earlier of the measured and the predicted break decides.
        let sizes = [1, 2, 4, 8, 16, 32, 64, 128];
        let r = at(999, &sizes);
        let cost = growth(&r, "cost");
        assert_eq!((cost.breaks_at, cost.predicted_breaks_at), (Some(128), Some(100)));
        assert_eq!(one(&r, "n_plus_1").severity, Severity::Fail);
        assert_eq!(one(&at(1009, &sizes), "n_plus_1").severity, Severity::Warn);
    }

    #[test]
    fn a_request_field_that_breaks_a_limit_at_any_size_fails() {
        let ps = || {
            points(&[1, 2, 4, 8], |n, p| {
                p.calls.insert(GET.into(), n as u32);
                p.cost = u128::from(10 * n);
            })
        };
        let r = analyze(&app("[limits]\ncost_per_request = 100000\n"), Knob::Field("query.days".into()), ps());
        assert_eq!(growth(&r, "cost").breaks_at, Some(10_001));
        let f = one(&r, "input_amplification");
        assert_eq!(f.severity, Severity::Fail);
        assert!(f.title.starts_with(&format!("calls to {GET} grow as 1·n with n = request field query.days = n;")), "{}", f.title);
        // Nothing it could break: the growth is a warning.
        let r = analyze(&app(""), Knob::Field("query.days".into()), ps());
        assert_eq!(one(&r, "input_amplification").severity, Severity::Warn);
        assert!(found(&r, "n_plus_1").is_empty());
    }

    #[test]
    fn a_limit_out_of_reach_is_never_broken() {
        let app = app("[limits]\ncost_per_request = 1000000000\n");
        let ps = points(&SIZES, |n, p| {
            p.calls.insert(GET.into(), (1 + 28 * n) as u32);
            p.cost = u128::from(1 + 28 * n);
        });
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        let cost = growth(&r, "cost");
        assert_eq!((cost.breaks_at, cost.break_evidence, cost.predicted_breaks_at), (None, None, None));
        assert_eq!(cost.limit, Some(json!(1_000_000_000)));
        let f = one(&r, "n_plus_1");
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(f.title, format!("calls to {GET} grow as 1 + 28·n with n = length of the list {ALL} returns"));
        assert_eq!(f.detail["breaks_at"], Value::Null);
    }

    #[test]
    fn breaks_are_extrapolated_up_to_a_million_elements() {
        let at = |limit: u64| {
            let app = app(&format!("[limits]\ncost_per_request = {limit}\n"));
            let ps = points(&SIZES, |n, p| p.cost = u128::from(1 + 28 * n));
            analyze(&app, Knob::HostList(ALL.into()), ps).growth.iter().find(|g| g.metric == "cost").and_then(|g| g.breaks_at)
        };
        // 1 + 28·n is 28,000,001 at n = 1,000,000.
        assert_eq!(at(27_999_990), Some(MAX_BREAK_N));
        assert_eq!(at(28_000_100), None);
    }

    #[test]
    fn a_limit_broken_at_the_first_size_breaks_there() {
        let app = app("[limits]\ncost_per_request = 10\n");
        let ps = points(&SIZES, |n, p| {
            p.calls.insert(GET.into(), n as u32);
            p.cost = u128::from(1 + 28 * n);
        });
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        let cost = growth(&r, "cost");
        assert_eq!((cost.breaks_at, cost.break_evidence, cost.predicted_breaks_at), (Some(1), Some("measured"), Some(1)));
        assert!(one(&r, "n_plus_1").title.ends_with("; cost exceeds its limit at measured n = 1"));
    }

    #[test]
    fn a_break_between_sizes_is_measured_at_the_next_size_and_predicted_exactly() {
        let app = app("[limits]\ncost_per_request = 50\n");
        let ps = points(&SIZES, |n, p| {
            p.calls.insert(GET.into(), n as u32);
            p.cost = u128::from(10 * n);
        });
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        let cost = growth(&r, "cost");
        // 10·n passes 50 at n = 6; the first size measured above it is 8.
        assert_eq!((cost.breaks_at, cost.break_evidence, cost.predicted_breaks_at), (Some(8), Some("measured"), Some(6)));
        let f = one(&r, "n_plus_1");
        assert_eq!((&f.detail["breaks_at"], &f.detail["predicted_breaks_at"]), (&json!([8, "cost"]), &json!(6)));
    }

    #[test]
    fn small_wobbles_and_shrinking_metrics_are_no_growth() {
        let app = app("");
        let ps = points(&SIZES, |n, p| {
            p.fuel = 5000 + 6 * n; // 1.8 % over the range
            p.host_arg_bytes = 5000 + 20 * n; // 6 %
            p.peak_memory = 65536 + 4096 * n;
            p.output_bytes = 200 - 10 * n;
        });
        let r = analyze(&app, Knob::Field("n".into()), ps);
        let metrics: Vec<&str> = r.growth.iter().map(|g| g.metric.as_str()).collect();
        assert_eq!(metrics, ["peak_memory", "host_arg_bytes"]);
        assert_eq!(growth(&r, "peak_memory").law.text, "65536 + 4096·n");
        assert_eq!(growth(&r, "host_arg_bytes").law.text, "5000 + 20·n");
        // Linear resources are no finding.
        assert!(r.findings.is_empty(), "{:?}", r.findings);
    }

    #[test]
    fn fewer_than_three_good_sizes_fit_no_law() {
        let app = app("");
        let r = analyze(&app, Knob::HostList(ALL.into()), calls(&[1, 2], GET, |n| 5 * n));
        assert!(r.growth.is_empty() && r.findings.is_empty());
        // Sizes after a failure do not count.
        let mut ps = calls(&SIZES, GET, |n| 5 * n);
        ps[2].outcome = OutcomeKind::OutOfFuel;
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        assert!(r.growth.is_empty(), "{:?}", r.growth);
        let f = one(&r, "fails_at_size");
        assert_eq!(f.title, format!("out_of_fuel at n = 4 (length of the list {ALL} returns)"));
        assert_eq!((f.severity, f.run.as_deref(), &f.detail["n"]), (Severity::Fail, Some("r4"), &json!(4)));
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn points_are_sorted_before_fitting() {
        let app = app("");
        let mut ps = calls(&SIZES, GET, |n| 3 * n);
        ps.reverse();
        let r = analyze(&app, Knob::Field("n".into()), ps);
        assert_eq!(r.points.iter().map(|p| p.n).collect::<Vec<_>>(), SIZES);
        assert_eq!(growth(&r, &format!("calls {GET}")).law.text, "3·n");
    }

    #[test]
    fn zeros_fit_no_law_and_growth_from_zero_has_no_intercept() {
        let app = app("");
        let ps = points(&[0, 1, 2, 4], |n, p| {
            (p.fuel, p.peak_memory, p.output_bytes) = (0, 0, 0);
            p.calls.insert(GET.into(), (3 * n) as u32);
        });
        let r = analyze(&app, Knob::Field("n".into()), ps);
        assert_eq!(r.growth.len(), 1, "{:?}", r.growth);
        assert_eq!(growth(&r, &format!("calls {GET}")).law.text, "3·n");
    }

    #[test]
    fn calls_the_app_caps_are_a_hint() {
        // Even a write in a loop is no n+1 when the app stops at 4.
        let app = app(&format!("[functions.\"{SAVE}\"]\neffect = \"write\"\n"));
        let r = analyze(&app, Knob::HostList(ALL.into()), calls(&SIZES, SAVE, |n| n.min(4)));
        let g = growth(&r, &format!("calls {SAVE}"));
        assert_eq!((g.law.class, g.law.text.as_str()), (Class::Capped, "capped at 4"));
        assert_eq!(one(&r, "n_plus_1").severity, Severity::Info);
    }

    #[test]
    fn superlinear_calls_fail_without_any_limit() {
        let app = app("");
        let r = analyze(&app, Knob::HostList(ALL.into()), calls(&SIZES, GET, |n| n * n));
        let g = growth(&r, &format!("calls {GET}"));
        assert_eq!((g.law.class, g.law.text.as_str()), (Class::Quadratic, "1·n²"));
        let f = one(&r, "n_plus_1");
        assert_eq!((f.severity, &f.detail["class"]), (Severity::Fail, &json!("quadratic")));
    }

    #[test]
    fn a_change_or_a_loop_with_a_batch_function_fails() {
        let manifest = format!("[functions.\"{SAVE}\"]\neffect = \"write\"\n[functions.\"test:shop/items#ids\"]\nbatch_of = \"{GET}\"\n");
        let app = app(&manifest);
        let ps = points(&SIZES, |n, p| {
            p.calls.insert(GET.into(), n as u32);
            p.calls.insert(SAVE.into(), n as u32);
        });
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        let by_func = |f: &str| r.findings.iter().find(|x| x.detail["func"] == json!(f)).unwrap();
        let save = by_func(SAVE);
        assert_eq!(save.severity, Severity::Fail);
        assert_eq!(save.title, format!("calls to {SAVE} grow as 1·n with n = length of the list {ALL} returns (effect write: one change per element)"));
        assert_eq!((&save.detail["effect"], &save.detail["batch"]), (&json!("write"), &Value::Null));
        let get = by_func(GET);
        assert_eq!(get.severity, Severity::Fail);
        assert!(get.title.ends_with("; test:shop/items#ids does it in one call"), "{}", get.title);
        assert_eq!((&get.detail["effect"], &get.detail["batch"]), (&Value::Null, &json!("test:shop/items#ids")));
    }

    #[test]
    fn calls_to_the_list_being_grown_are_no_n_plus_1() {
        let app = app("");
        // A paged read calls the list once per page.
        for knob in [ALL, "items#all", "all"] {
            let r = analyze(&app, Knob::HostList(knob.into()), calls(&SIZES, ALL, |n| n / 2 + 1));
            assert_eq!(growth(&r, &format!("calls {ALL}")).law.class, Class::Linear);
            assert!(found(&r, "n_plus_1").is_empty(), "{knob}: {:?}", r.findings);
        }
        // Another list is.
        let r = analyze(&app, Knob::HostList(PAGED.into()), calls(&SIZES, ALL, |n| n / 2 + 1));
        assert_eq!(one(&r, "n_plus_1").detail["func"], json!(ALL));
    }

    /// Every resource grows as 1000 + 10·n².
    fn quadratic(n: u64, p: &mut Point) {
        let q = 1000 + 10 * n * n;
        (p.fuel, p.peak_memory, p.output_bytes, p.host_arg_bytes, p.cost) = (q, q, q, q, u128::from(q));
        p.virtual_ns = Natural::from(q * 1000);
    }

    fn by_metric(r: &ScaleReport) -> BTreeMap<String, (String, Severity)> {
        r.findings.iter().map(|f| (f.detail["metric"].as_str().unwrap().to_string(), (f.kind.clone(), f.severity))).collect()
    }

    #[test]
    fn superlinear_resources_are_named_by_what_grows() {
        let r = analyze(&app(""), Knob::Field("n".into()), points(&SIZES, quadratic));
        let want = [
            ("cost", "superlinear_growth"),
            ("virtual_ms", "cpu_blowup"),
            ("fuel", "cpu_blowup"),
            ("peak_memory", "memory_blowup"),
            ("output_bytes", "output_amplification"),
            ("host_arg_bytes", "payload_amplification"),
        ];
        // A request field is the requester's to choose: each is a warning.
        let want: BTreeMap<String, (String, Severity)> = want.iter().map(|(m, k)| (m.to_string(), (k.to_string(), Severity::Warn))).collect();
        assert_eq!(by_metric(&r), want);
        let fuel = r.findings.iter().find(|f| f.detail["metric"] == json!("fuel")).unwrap();
        assert_eq!(fuel.title, "fuel grows as 1000 + 10·n² with n = request field n = n");
        assert_eq!(fuel.detail["class"], json!("quadratic"));
    }

    #[test]
    fn superlinear_resources_of_a_host_list_warn_only_within_1000_elements() {
        // Fuel breaks its limit at n = 14,142 and memory (64 MiB) at 2,591: hints.
        let r = analyze(&app(""), Knob::HostList(ALL.into()), points(&SIZES, quadratic));
        assert!(by_metric(&r).values().all(|(_, s)| *s == Severity::Info), "{:?}", by_metric(&r));
        // 1 MB of memory is reached at n = 317.
        let r = analyze(&app("[limits]\nmemory = 1000000\n"), Knob::HostList(ALL.into()), points(&SIZES, quadratic));
        assert_eq!(growth(&r, "peak_memory").predicted_breaks_at, Some(317));
        let m = by_metric(&r);
        assert_eq!((m["peak_memory"].1, m["fuel"].1), (Severity::Warn, Severity::Info));
    }

    #[test]
    fn a_fuel_limit_that_grows_with_the_input_is_taken_from_the_largest_run() {
        let app = app("[limits]\nfuel = 10\n");
        // Shopify: each run has its own limit, growing with the cart.
        let ps = points(&SIZES, |n, p| {
            p.fuel = 1000 * n;
            p.fuel_limit = Some(10_000 + 1000 * n);
        });
        let r = analyze(&app, Knob::Field("n".into()), ps);
        let fuel = growth(&r, "fuel");
        // No run went over its own limit; 1000·n passes 26,000 at n = 27.
        assert_eq!((fuel.breaks_at, fuel.break_evidence, fuel.limit.clone()), (Some(27), Some("inferred"), Some(json!(26_000))));
    }

    #[test]
    fn failures_are_blamed_on_the_size_only_when_the_app_failed() {
        let app = app("");
        let mut ps = calls(&SIZES, GET, |n| 2 * n);
        ps[4].outcome = OutcomeKind::Trap;
        let r = analyze(&app, Knob::HostList(ALL.into()), ps);
        // The worst run is the largest size that worked.
        assert_eq!(one(&r, "n_plus_1").detail["worst_run"], json!("r8"));
        assert_eq!(one(&r, "fails_at_size").run.as_deref(), Some("r16"));
        // Runs appfuzz could not make, or stopped at the budget, are no failure.
        for kind in [OutcomeKind::Error, OutcomeKind::PlanError, OutcomeKind::BudgetExceeded] {
            let mut ps = calls(&SIZES, GET, |n| 2 * n);
            ps[4].outcome = kind;
            assert!(found(&analyze(&app, Knob::HostList(ALL.into()), ps), "fails_at_size").is_empty(), "{kind:?}");
        }
        // Nothing worked: no size to blame.
        let r = analyze(&app, Knob::HostList(ALL.into()), points(&SIZES, |_, p| p.outcome = OutcomeKind::Trap));
        assert!(r.findings.is_empty() && r.growth.is_empty());
    }

    #[test]
    fn finding_ids_are_stable_and_tell_knobs_and_exports_apart() {
        let ids = |app: &App, knob: Knob| analyze(app, knob, calls(&SIZES, GET, |n| n)).findings.into_iter().map(|f| f.id).collect::<Vec<_>>();
        let plain = app("");
        let a = ids(&plain, Knob::HostList(ALL.into()));
        assert_eq!(a.len(), 1);
        assert_eq!(a, ids(&plain, Knob::HostList(ALL.into())));
        assert_ne!(a, ids(&plain, Knob::HostList(PAGED.into())));
        assert_ne!(a, ids(&app("[entry]\nexport = \"handle\"\n"), Knob::HostList(ALL.into())));
    }

    // --- Words, constants and request knobs -------------------------------------

    fn module(strings: &[&str], imports: Vec<ImportInfo>, funcs: Vec<StaticFunc>) -> ModuleInfo {
        ModuleInfo {
            id: "m".into(),
            index: 0,
            role: "main".into(),
            start: 0,
            end: 0,
            imports,
            exports: vec![],
            func_imports: 0,
            funcs,
            strings: strings.iter().map(|s| (0, s.to_string())).collect(),
            has_names: false,
        }
    }

    fn function(index: u32, calls: &[u32], cmp_consts: &[i64], text: &[&str]) -> StaticFunc {
        StaticFunc {
            index,
            name: None,
            start: 0,
            end: 0,
            calls: calls.iter().map(|&c| (c, 0)).collect(),
            call_indirect: 0,
            loops: vec![],
            instructions: 0,
            text_consts: text.iter().map(|t| (0, t.to_string())).collect(),
            cmp_consts: cmp_consts.to_vec(),
            magic: vec![],
        }
    }

    #[test]
    fn dictionary_words_are_split_from_packed_strings() {
        let strings = ["viewMode=week&copies=3", "POST /api/v1", "x", "Hello", "__debug__", "a-very-long-identifier-that-is-too-long", "page_size9", "9lives"];
        let st = Statics { modules: vec![module(&strings, vec![], vec![function(0, &[], &[], &["limit"])]), module(&["view"], vec![], vec![])] };
        assert_eq!(dictionary(&st, 100), ["v1", "api", "POST", "view", "week", "debug", "limit", "copies", "page_size9"]);
        // The shortest words are kept.
        assert_eq!(dictionary(&st, 3), ["v1", "api", "POST"]);
        assert!(dictionary(&Statics { modules: vec![] }, 10).is_empty());
    }

    #[test]
    fn compared_constants_come_from_code_that_reaches_the_host() {
        let host = ImportInfo { module: "test:shop/items".into(), name: "get".into(), kind: "func".into(), func: Some(0), host: Some(GET.into()) };
        let funcs =
            vec![function(1, &[0], &[13, 13, 1, 1_000_001, 7, 1_000_000, -5], &[]), function(2, &[1], &[7, 2], &[]), function(3, &[], &[99, 99, 99], &[])];
        let st = Statics { modules: vec![module(&[], vec![host], funcs)] };
        // Most common first, then smallest; 1, negatives and huge values are no modes.
        assert_eq!(compare_constants(&st, 10), [7, 13, 2, 1_000_000]);
        assert_eq!(compare_constants(&st, 2), [7, 13]);
    }

    #[test]
    fn request_leaves_and_pair_keys_are_knobs() {
        let req = json!({"days": 3, "id": "42", "name": "ada", "empty": "", "query": [["page", "2"], ["q", "x"]],
                         "tags": [1, 2], "none": [], "flag": true, "nested": {"limit": 5}});
        let (knobs, pairs) = request_knobs(&[req, json!(7), json!({"x": "9"})]);
        let f = |p: &str| Knob::Field(p.into());
        let l = |p: &str| Knob::FieldLen(p.into());
        let want = [
            f("days"),
            f("id"),
            l("id"),
            l("name"),
            l("empty"),
            f("query.page"),
            l("query.page"),
            l("query.q"),
            f("tags"),
            f("nested.limit"),
            f("@1"),
            f("@2.x"),
            l("@2.x"),
        ];
        assert_eq!(knobs, want);
        assert_eq!(pairs, ["query", "none"]);
        // A first argument that is a list of pairs.
        let (knobs, pairs) = request_knobs(&[json!([["a", "1"]]), json!("5")]);
        assert_eq!(knobs, [f("a"), l("a"), f("@1"), l("@1")]);
        assert_eq!(pairs, ["@0"]);
        assert_eq!(request_knobs(&[]), (vec![], vec![]));
    }

    // --- Behaviour, modes and duplicates ------------------------------------------

    #[test]
    fn behaviour_is_outcome_answer_and_calls() {
        let app = app("");
        let s = base(&app);
        let events = || vec![call(GET, json!({"id": 1}), None), call(GET, json!({"id": 2}), None), call(ALL, json!({}), None)];
        let r = record(&s, OutcomeKind::Ok, events(), json!("a"));
        let b = behaviour(&r);
        assert!(b.starts_with("Ok|") && b.ends_with(&format!("|{GET}×2,{ALL}×1")), "{b}");
        assert_eq!(b.split('|').nth(1).unwrap().len(), 8);
        // Arguments do not count; the answer does, except for calls_behaviour.
        let mut other_args = r.clone();
        other_args.events[0].args.insert("id".into(), json!(9));
        assert_eq!(behaviour(&other_args), b);
        let other_answer = record(&s, OutcomeKind::Ok, events(), json!("b"));
        assert_ne!(behaviour(&other_answer), b);
        assert_eq!(calls_behaviour(&other_answer), format!("Ok|{GET}×2,{ALL}×1"));
        assert_eq!(calls_behaviour(&r), calls_behaviour(&other_answer));
        let mut failed = r.clone();
        failed.outcome.kind = OutcomeKind::Trap;
        assert_ne!(calls_behaviour(&failed), calls_behaviour(&r));
        let mut silent = r.clone();
        silent.result = None;
        assert_eq!(behaviour(&silent), format!("Ok||{GET}×2,{ALL}×1"));
    }

    #[test]
    fn findings_in_a_mode_get_their_own_id_and_say_the_mode() {
        let f = Finding::new("n_plus_1", "k", Severity::Warn, "calls grow".into(), json!({"func": GET}), Some("r1"));
        let g = in_context(f.clone(), "query.view=week");
        assert_eq!((g.kind.as_str(), g.severity, g.run.as_deref()), ("n_plus_1", Severity::Warn, Some("r1")));
        assert_eq!(g.title, "calls grow (with query.view=week)");
        assert_eq!(g.detail, json!({"func": GET, "context": "query.view=week"}));
        assert_ne!(g.id, f.id);
        assert_eq!(g.id, in_context(f.clone(), "query.view=week").id);
        assert_ne!(g.id, in_context(f, "query.view=day").id);
        let plain = Finding::new("x", "k", Severity::Info, "t".into(), Value::Null, None);
        assert_eq!(in_context(plain, "m").detail, Value::Null);
    }

    fn law_finding(func: &str, class: &str) -> Finding {
        let detail = json!({"knob": Knob::HostList(ALL.into()), "func": func, "class": class});
        Finding::new("n_plus_1", &format!("{func}\0{class}"), Severity::Warn, format!("calls to {func}"), detail, None)
    }

    fn report_with(context: Option<&str>, findings: Vec<Finding>) -> ScaleReport {
        ScaleReport { knob: Knob::HostList(ALL.into()), context: context.map(str::to_string), points: vec![], growth: vec![], findings }
    }

    #[test]
    fn one_law_under_many_modes_is_one_finding() {
        let a = law_finding(GET, "linear");
        let mut reports = vec![
            report_with(Some("view=week"), vec![in_context(a.clone(), "view=week"), law_finding(GET, "quadratic")]),
            report_with(None, vec![a.clone()]),
            report_with(Some("mode=x"), vec![in_context(a.clone(), "mode=x")]),
        ];
        dedupe_by_law(&mut reports);
        // The finding without a mode stays and names the other modes.
        assert_eq!(reports[1].findings.len(), 1);
        let kept = &reports[1].findings[0];
        assert_eq!((kept.id.as_str(), kept.title.as_str()), (a.id.as_str(), "calls to test:shop/items#get (and 2 more modes)"));
        assert_eq!(kept.detail["also_with"], json!(["view=week", "mode=x"]));
        // Another law is another problem.
        assert_eq!(reports[0].findings.len(), 1);
        assert_eq!(reports[0].findings[0].detail["class"], json!("quadratic"));
        assert!(reports[2].findings.is_empty());
    }

    #[test]
    fn without_a_finding_outside_modes_the_first_mode_keeps_it() {
        let a = law_finding(GET, "linear");
        let mut reports = vec![
            report_with(Some("a=1"), vec![in_context(a.clone(), "a=1")]),
            report_with(Some("b=2"), vec![in_context(a.clone(), "b=2")]),
            report_with(None, vec![]),
        ];
        dedupe_by_law(&mut reports);
        assert_eq!(reports[0].findings[0].detail["also_with"], json!(["b=2"]));
        assert!(reports[0].findings[0].title.ends_with("(with a=1) (and 1 more modes)"), "{}", reports[0].findings[0].title);
        assert!(reports[1].findings.is_empty());
        // Twice without a mode: the other one is "no mode".
        let mut reports = vec![report_with(None, vec![a.clone()]), report_with(None, vec![a.clone()])];
        dedupe_by_law(&mut reports);
        assert_eq!(reports[0].findings[0].detail["also_with"], json!(["no mode"]));
        // Nothing to merge: nothing changes.
        let mut single = vec![report_with(None, vec![a.clone()])];
        dedupe_by_law(&mut single);
        assert_eq!((single[0].findings[0].title.as_str(), single[0].findings[0].detail.get("also_with")), (a.title.as_str(), None));
    }

    // --- Nested loops -------------------------------------------------------------

    /// Runs at (2, 2), (2, 8), (8, 2) and (8, 8) with these calls to `get`.
    fn quad_runs(app: &App, counts: [u32; 4], kind: OutcomeKind) -> Vec<Option<RunRecord>> {
        let s = base(app);
        let run = |(i, c): (usize, &u32)| {
            let mut r = record(&s, kind, (0..*c).map(|_| call(GET, json!({}), None)).collect(), Value::Null);
            r.id = format!("r{i}");
            Some(r)
        };
        counts.iter().enumerate().map(run).collect()
    }

    #[test]
    fn calls_for_each_pair_of_elements_are_a_nested_fan_out() {
        let app = app("");
        let (a, b) = (Knob::HostList(ALL.into()), Knob::Field("@1".into()));
        let nested = |counts, kind| nested_finding("handle", GET, &a, &b, &quad_runs(&app, counts, kind));
        let (n, f) = nested([4, 16, 16, 64], OutcomeKind::Ok).unwrap();
        assert_eq!((n.calls, n.interaction, n.run.as_str(), &n.outer, &n.inner), ([4, 16, 16, 64], 1.0, "r3", &a, &b));
        assert_eq!((f.kind.as_str(), f.severity, f.run.as_deref()), ("nested_fan_out", Severity::Warn, Some("r3")));
        assert_eq!(
            f.title,
            format!("{GET} is called for each pair of elements: length of the list {ALL} returns × number of elements in argument 1 (8 × 8 gives 64 calls)")
        );
        assert_eq!((&f.detail["calls_2x8"], &f.detail["interaction"]), (&json!(16), &json!(1.0)));
        // Two loops one after the other add up: no interaction.
        assert!(nested([4, 10, 10, 16], OutcomeKind::Ok).is_none());
        // From half a call per pair of elements.
        assert_eq!(nested([0, 0, 0, 18], OutcomeKind::Ok).unwrap().0.interaction, 0.5);
        assert!(nested([0, 0, 0, 17], OutcomeKind::Ok).is_none());
        assert_eq!(nested([0, 0, 0, 25], OutcomeKind::Ok).unwrap().0.interaction, 0.69);
        // A run that failed, or could not be made, proves nothing.
        assert!(nested([4, 16, 16, 64], OutcomeKind::Trap).is_none());
        let mut missing = quad_runs(&app, [4, 16, 16, 64], OutcomeKind::Ok);
        missing[1] = None;
        assert!(nested_finding("handle", GET, &a, &b, &missing).is_none());
    }

    /// Calls `get` days × len(extra) times (or days + len(extra)).
    fn pairs_app(product: bool) -> impl Fn(&RunSpec) -> RunRecord + Sync {
        move |s: &RunSpec| {
            let days = s.args[0]["days"].as_u64().unwrap();
            let extra = s.args[1].as_array().unwrap().len() as u64;
            let n = if product { days * extra } else { days + extra };
            record(s, OutcomeKind::Ok, (0..n).map(|_| call(GET, json!({}), None)).collect(), Value::Null)
        }
    }

    #[test]
    fn a_nested_fan_out_is_measured_again_from_a_spec() {
        let app = app("");
        let (a, b) = (Knob::Field("days".into()), Knob::Field("@1".into()));
        let f = nested_again(&app, &base(&app), GET, &a, &b, &pairs_app(true)).unwrap();
        assert_eq!((f.kind.as_str(), &f.detail["calls_8x8"], &f.detail["knobs"]), ("nested_fan_out", &json!(64), &json!([a, b])));
        assert!(nested_again(&app, &base(&app), GET, &a, &b, &pairs_app(false)).is_none());
        // A knob that cannot be set gives no runs to compare.
        assert!(nested_again(&app, &base(&app), GET, &Knob::Field("@9".into()), &b, &pairs_app(true)).is_none());
    }

    #[test]
    fn knobs_that_drive_up_the_same_function_are_turned_together() {
        let app = app("");
        let b = base(&app);
        let run = pairs_app(true);
        let report = |knob: &str, context: Option<&str>| {
            let mut r = scale(&app, &b, Knob::parse(knob).unwrap(), &[1, 2, 4, 8], &run).unwrap();
            r.context = context.map(str::to_string);
            r
        };
        let reports = vec![report("days", None), report("@1", None), report("len:name", None)];
        let (found, findings) = nested(&app, &b, &reports, None, &run);
        assert_eq!(found.len(), 1);
        assert_eq!((&found[0].outer, &found[0].inner, found[0].calls), (&Knob::Field("days".into()), &Knob::Field("@1".into()), [4, 16, 16, 64]));
        assert_eq!(findings.len(), 1);
        // `only` keeps the functions it names.
        assert!(nested(&app, &b, &reports, Some("#save"), &run).0.is_empty());
        assert_eq!(nested(&app, &b, &reports, Some("#get"), &run).0.len(), 1);
        // Knobs turned in a mode are not paired.
        let moded = vec![report("days", None), report("@1", Some("view=week"))];
        assert!(nested(&app, &b, &moded, None, &run).0.is_empty());
    }

    // --- Lists, types and dropped rows --------------------------------------------

    #[test]
    fn lists_are_found_inside_ok_and_some() {
        for mut v in [json!([1]), json!({"ok": [1]}), json!({"some": [1]}), json!({"ok": {"some": [1]}})] {
            list_in_mut(&mut v).unwrap().push(json!(2));
            assert_eq!(crate::detect::list_in(&v), Some(&vec![json!(1), json!(2)]), "{v}");
        }
        for mut v in [json!({"err": [1]}), json!({"ok": [1], "x": 1}), json!(1), json!({"ok": 1})] {
            assert!(list_in_mut(&mut v).is_none(), "{v}");
        }
    }

    #[test]
    fn result_types_say_whether_they_hold_numbers_or_text() {
        let app = app("");
        let holds_of = |f: &str| holds(&result_type(&app, f));
        assert_eq!(holds_of("all"), (true, true));
        assert_eq!(holds_of("maybe"), (true, true));
        assert_eq!(holds_of("names"), (false, true));
        assert_eq!(holds_of("count"), (true, false));
        assert_eq!(holds_of("either"), (true, true));
        assert_eq!(holds_of("no-ok"), (false, true));
        assert_eq!(holds_of("pair"), (true, false));
        // Floats are no integer constants to compare with.
        assert_eq!(holds_of("ratio"), (false, false));
    }

    fn items(ids: &[u32]) -> Value {
        json!(ids.iter().map(|i| json!({"id": i, "name": "x"})).collect::<Vec<_>>())
    }

    fn ret(s: &RunSpec, f: &str) -> Option<Value> {
        s.plan.0.get(f).and_then(|p| p.response.ret.clone())
    }

    fn rows_left(drops: &[(String, RunSpec)], f: &str) -> Vec<(String, Option<Value>)> {
        drops.iter().map(|(row, s)| (row.clone(), ret(s, f))).collect()
    }

    #[test]
    fn rows_are_dropped_first_middle_and_last_from_the_list_the_run_saw() {
        let app = app("");
        let spec = base(&app);
        let top = record(&spec, OutcomeKind::Ok, vec![call(ALL, json!({}), Some(items(&[1, 2, 3, 4])))], Value::Null);
        let (pinned, drops) = dropped_rows(&app, &spec, &top, ALL);
        // A generated list is pinned first, so a drop changes only that row.
        assert_eq!(ret(&pinned.unwrap(), ALL), Some(items(&[1, 2, 3, 4])));
        let want = [("first", items(&[2, 3, 4])), ("middle", items(&[1, 2, 4])), ("last", items(&[1, 2, 3]))];
        assert_eq!(rows_left(&drops, ALL), want.map(|(r, v)| (r.to_string(), Some(v))));
    }

    #[test]
    fn short_lists_drop_each_row_once() {
        let app = app("");
        let literal = |list: Value| {
            let mut spec = base(&app);
            spec.plan.0.insert(ALL.into(), FnPlan { response: Response { ret: Some(list), ..Default::default() }, ..Default::default() });
            let (pinned, drops) = dropped_rows(&app, &spec, &record(&spec, OutcomeKind::Ok, vec![], Value::Null), ALL);
            // The plan's own list needs no pinning.
            assert!(pinned.is_none());
            rows_left(&drops, ALL)
        };
        assert_eq!(literal(items(&[1, 2])), [("first".to_string(), Some(items(&[2]))), ("middle".to_string(), Some(items(&[1])))]);
        assert_eq!(literal(items(&[1])), [("first".to_string(), Some(items(&[])))]);
        assert_eq!(literal(json!({"ok": items(&[5, 6, 7])}))[1], ("middle".to_string(), Some(json!({"ok": items(&[5, 7])}))));
    }

    #[test]
    fn rows_cannot_be_dropped_from_a_list_the_run_did_not_read_once() {
        let app = app("");
        let spec = base(&app);
        let nothing = |events: Vec<HostCall>| {
            let (pinned, drops) = dropped_rows(&app, &spec, &record(&spec, OutcomeKind::Ok, events, Value::Null), ALL);
            pinned.is_none() && drops.is_empty()
        };
        assert!(nothing(vec![]));
        assert!(nothing(vec![call(ALL, json!({}), Some(items(&[1]))), call(ALL, json!({}), Some(items(&[1])))]));
        assert!(nothing(vec![call(ALL, json!({}), None)]));
        assert!(nothing(vec![call(ALL, json!({}), Some(items(&[])))]));
        assert!(nothing(vec![call(ALL, json!({}), Some(json!({"err": "x"})))]));
    }

    /// The dataset keys each drop removes.
    fn dropped_keys(drops: &[(String, RunSpec)]) -> Vec<(String, Value)> {
        drops
            .iter()
            .map(|(row, s)| {
                let edits = &s.plan.0["_defaults"].dataset_edits;
                let [crate::dataset::Edit::Drop { dataset, keys }] = &edits[..] else { panic!("{edits:?}") };
                assert_eq!(dataset, "items");
                (row.clone(), json!(keys))
            })
            .collect()
    }

    #[test]
    fn dataset_rows_are_dropped_by_key() {
        let app = app(DATASET);
        let spec = apply(&app, &base(&app), &Knob::HostList(ALL.into()), 5).unwrap();
        let top = record(&spec, OutcomeKind::Ok, vec![call(ALL, json!({}), Some(items(&[11, 12, 13, 14, 15])))], Value::Null);
        let (pinned, drops) = dropped_rows(&app, &spec, &top, ALL);
        assert!(pinned.is_none());
        let want = [("first", 11), ("middle", 13), ("last", 15)].map(|(r, k)| (r.to_string(), json!([k])));
        assert_eq!(dropped_keys(&drops), want);
        // Without a call to read keys from, the generated collection has them.
        let (_, drops) = dropped_rows(&app, &spec, &record(&spec, OutcomeKind::Ok, vec![], Value::Null), ALL);
        let keys: BTreeSet<String> = dropped_keys(&drops).into_iter().map(|(_, k)| k.to_string()).collect();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn a_dataset_list_read_twice_still_drops_its_middle_row() {
        let app = app(DATASET);
        let spec = apply(&app, &base(&app), &Knob::HostList(ALL.into()), 4).unwrap();
        let read = || call(ALL, json!({}), Some(items(&[1, 2, 3, 4])));
        let (_, drops) = dropped_rows(&app, &spec, &record(&spec, OutcomeKind::Ok, vec![read(), read()], Value::Null), ALL);
        let want = [("first", 1), ("middle", 3), ("last", 4)].map(|(r, k)| (r.to_string(), json!([k])));
        assert_eq!(dropped_keys(&drops), want);
    }

    // --- Scaling with a simulated app ------------------------------------------------

    /// An app that reads `all` and gets each item: an n+1 with a fixed answer.
    fn shop(s: &RunSpec) -> RunRecord {
        let list = ret(s, ALL).unwrap_or_else(|| items(&[1]));
        let gets: Vec<HostCall> = list.as_array().unwrap().iter().map(|e| call(GET, json!({"id": e["id"]}), Some(json!({"some": e})))).collect();
        let n = gets.len() as u64;
        let mut events = vec![call(ALL, json!({}), Some(list))];
        events.extend(gets);
        let mut r = record(s, OutcomeKind::Ok, events, json!({"status": 200}));
        r.totals.cost = u128::from(1 + n);
        r
    }

    const ROWS: [u64; 6] = [1, 2, 4, 8, 16, 32];

    fn sizes_of(r: &ScaleReport) -> Vec<u64> {
        r.points.iter().map(|p| p.n).collect()
    }

    #[test]
    fn scaling_a_host_list_finds_the_n_plus_1_and_the_unbounded_read() {
        let app = app("[limits]\ncost_per_request = 1000\n");
        let r = scale(&app, &base(&app), Knob::HostList("items#all".into()), &ROWS, &shop).unwrap();
        assert_eq!(sizes_of(&r), ROWS);
        assert_eq!((r.points[5].calls[GET], r.points[5].rows[ALL]), (32, 32));
        let f = one(&r, "n_plus_1");
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(
            f.title,
            format!("calls to {GET} grow as 1·n with n = length of the list items#all returns; cost is predicted to exceed its limit at n = 1000")
        );
        let u = one(&r, "unbounded_read");
        assert_eq!(u.severity, Severity::Warn);
        assert_eq!(
            u.title,
            format!(
                "{ALL} returns all n rows while the answer stays the same size; some rows never affect it (dropping the first or middle or last row changes nothing); cost is predicted to exceed its limit at n = 1000"
            )
        );
        assert_eq!((&u.detail["n"], &u.detail["rows"], &u.detail["unused_rows"], &u.detail["paged"]), (&json!(32), &json!(32), &json!(true), &Value::Null));
        let dropped: Vec<(&str, bool)> =
            u.detail["dropped"].as_array().unwrap().iter().map(|d| (d["row"].as_str().unwrap(), d["unchanged"].as_bool().unwrap())).collect();
        assert_eq!(dropped, [("first", true), ("middle", true), ("last", true)]);
        assert_eq!((&u.detail["breaks_at"], &u.detail["break_evidence"]), (&json!([1000, "cost"]), &json!("inferred")));
        assert_eq!(u.run.as_deref(), Some(r.points[5].run.as_str()));
    }

    #[test]
    fn rows_that_each_change_the_answer_are_read_for_a_reason() {
        let app = app("");
        // A fixed-size answer that depends on every row.
        let digest = |s: &RunSpec| {
            let mut r = shop(s);
            let ids = r.events[0].result.as_ref().unwrap().to_string();
            r.result = Some(json!({"digest": blake3::hash(ids.as_bytes()).to_hex()[..16].to_string()}));
            r
        };
        let r = scale(&app, &base(&app), Knob::HostList(ALL.into()), &ROWS, &digest).unwrap();
        let u = one(&r, "unbounded_read");
        assert_eq!(u.severity, Severity::Info);
        assert!(u.title.ends_with("; each dropped row changes it"), "{}", u.title);
        assert_eq!(u.detail["unused_rows"], json!(false));
    }

    #[test]
    fn no_unbounded_read_for_writes_growing_answers_few_rows_or_request_fields() {
        let none = |app: &App, knob: &str, sizes: &[u64], run: Runner| {
            found(&scale(app, &base(app), Knob::parse(knob).unwrap(), sizes, run).unwrap(), "unbounded_read").is_empty()
        };
        let writes = app(&format!("[functions.\"{ALL}\"]\neffect = \"write\"\n"));
        assert!(none(&writes, ALL, &ROWS, &shop));
        let app = app("");
        let showing = |s: &RunSpec| {
            let mut r = shop(s);
            r.result = r.events[0].result.clone();
            r
        };
        assert!(none(&app, ALL, &ROWS, &showing));
        // Fewer than 16 rows at the largest size, or fewer than 4 sizes.
        assert!(none(&app, ALL, &[1, 2, 4, 8], &shop));
        assert!(none(&app, ALL, &[16, 32, 64], &shop));
        assert!(none(&app, "days", &ROWS, &shop));
        // The control: these sizes do show it.
        assert!(!none(&app, ALL, &ROWS, &shop));
    }

    /// An app that reads the dataset's rows whole and answers the same.
    fn reader(f: &'static str) -> impl Fn(&RunSpec) -> RunRecord + Sync {
        move |s: &RunSpec| {
            let defaults = s.plan.0.get("_defaults");
            let n = defaults.and_then(|p| p.dataset_rows.get("items").copied()).unwrap_or(4) as u32;
            let dropped: Vec<Value> = defaults
                .into_iter()
                .flat_map(|p| &p.dataset_edits)
                .flat_map(|e| match e {
                    crate::dataset::Edit::Drop { keys, .. } => keys.clone(),
                    _ => vec![],
                })
                .collect();
            let ids: Vec<u32> = (1..=n).filter(|i| !dropped.contains(&json!(i))).collect();
            let mut r = record(s, OutcomeKind::Ok, vec![call(f, json!({}), Some(items(&ids)))], json!("same"));
            r.totals.cost = u128::from(1 + n);
            r
        }
    }

    #[test]
    fn a_whole_read_where_a_paged_query_exists_fails() {
        let app = app(&format!("{DATASET}\n[limits]\ncost_per_request = 1000\n"));
        let r = scale(&app, &base(&app), Knob::HostList("all".into()), &ROWS, &reader(ALL)).unwrap();
        let u = one(&r, "unbounded_read");
        assert_eq!(u.severity, Severity::Fail);
        assert!(u.title.starts_with(&format!("{ALL} returns all n rows while the answer stays the same size; some rows never affect it")), "{}", u.title);
        assert!(u.title.ends_with(&format!("; {PAGED} reads pages of up to 50")), "{}", u.title);
        assert_eq!(u.detail["paged"], json!({"func": PAGED, "max": 50}));
        // Reading every page of the paged query is said so.
        let r = scale(&app, &base(&app), Knob::HostList(PAGED.into()), &ROWS, &reader(PAGED)).unwrap();
        let u = one(&r, "unbounded_read");
        assert!(u.title.starts_with(&format!("the app reads every page of {PAGED}, all n rows, while its answer stays the same size")), "{}", u.title);
        assert!(!u.title.contains("reads pages of up to"), "{}", u.title);
        assert_eq!(u.detail["paged"], json!({"func": PAGED, "max": 50}));
    }

    #[test]
    fn scaling_stops_at_the_first_size_that_fails() {
        let app = app("");
        let breaking = |s: &RunSpec| {
            let mut r = shop(s);
            if r.events.len() > 8 {
                r.outcome.kind = OutcomeKind::Unreachable;
            }
            r
        };
        let r = scale(&app, &base(&app), Knob::HostList(ALL.into()), &ROWS, &breaking).unwrap();
        assert_eq!(sizes_of(&r), [1, 2, 4, 8]);
        assert_eq!(one(&r, "fails_at_size").title, format!("unreachable at n = 8 (length of the list {ALL} returns)"));
        assert!(found(&r, "unbounded_read").is_empty());
    }

    #[test]
    fn sizes_the_field_type_cannot_hold_or_shopify_refuses_are_not_run() {
        let app = app("");
        let r = scale(&app, &base(&app), Knob::Field("small".into()), &[1, 128, 255, 256, 1024], &shop).unwrap();
        assert_eq!(sizes_of(&r), [1, 128, 255]);
        assert!(r.findings.is_empty());
        let refusing = |s: &RunSpec| {
            let mut r = shop(s);
            let mut info = crate::shopify::RunInfo::new("t", 1.0);
            info.input_bytes = if r.events.len() > 4 { info.input_limit + 1 } else { 0 };
            r.shopify = Some(info);
            r
        };
        let r = scale(&app, &base(&app), Knob::HostList(ALL.into()), &ROWS, &refusing).unwrap();
        assert_eq!(sizes_of(&r), [1, 2]);
        assert!(found(&r, "fails_at_size").is_empty());
        assert!(scale(&app, &base(&app), Knob::HostList("nope".into()), &ROWS, &shop).is_err());
    }

    // --- Discovery and amplify --------------------------------------------------------

    /// An app with knobs and keys to find: a `get` per pair of `all` and
    /// `extra` elements, a `count` per `days`; query `page` changes the
    /// answer, `q` only reaches a host call, and `sizz` is only compared
    /// byte by byte.
    fn modes(s: &RunSpec) -> RunRecord {
        let req = &s.args[0];
        let pairs: Vec<(&str, &str)> = req["query"].as_array().unwrap().iter().map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap())).collect();
        let query = |k: &str| pairs.iter().find(|p| p.0 == k).map_or("", |p| p.1);
        let list = ret(s, ALL).unwrap_or_else(|| items(&[1]));
        let extra = s.args[1].as_array().unwrap().len();
        let mut events = vec![call(ALL, json!({}), Some(list.clone()))];
        for e in list.as_array().unwrap() {
            events.extend((0..extra).map(|_| call(GET, json!({"id": e["id"]}), None)));
        }
        events.extend((0..req["days"].as_u64().unwrap()).map(|_| call(COUNT, json!({}), None)));
        events.push(call(SAVE, json!({"id": query("q")}), None));
        let secret = "sizz";
        let matched: usize =
            pairs.iter().filter(|p| p.0.len() == secret.len()).map(|p| p.0.chars().zip(secret.chars()).take_while(|(a, b)| a == b).count()).sum();
        let mut r = record(s, OutcomeKind::Ok, events, json!(format!("page {}", query("page"))));
        r.totals.fuel = 1000 + 10 * matched as u64;
        r
    }

    #[test]
    fn amplify_finds_knobs_keys_and_nested_loops() {
        let app = app("");
        let most_fuel = std::sync::atomic::AtomicU64::new(0);
        let run = |s: &RunSpec| {
            most_fuel.fetch_max(s.fuel, std::sync::atomic::Ordering::Relaxed);
            modes(s)
        };
        let a = amplify(&app, &base(&app), None, 64, &run).unwrap();
        // By a changed answer, by a value seen in a host call, and by fuel.
        for k in ["query.q", "query.page", "query.sizz"] {
            assert!(a.discovered_keys.contains(&k.to_string()), "{k}: {:?}", a.discovered_keys);
        }
        for k in ["fn:test:shop/items#all", "days", "@1", "len:name", "query.sizz"] {
            assert!(a.knobs.contains(&Knob::parse(k).unwrap()), "{k}: {:?}", a.knobs);
        }
        let kinds: BTreeSet<(String, Knob, String)> = a
            .reports
            .iter()
            .filter(|r| r.context.is_none())
            .flat_map(|r| r.findings.iter().map(|f| (f.kind.clone(), r.knob.clone(), f.detail["func"].as_str().unwrap_or_default().to_string())))
            .collect();
        assert!(kinds.contains(&("n_plus_1".into(), Knob::HostList(ALL.into()), GET.into())), "{kinds:?}");
        assert!(kinds.contains(&("input_amplification".into(), Knob::Field("@1".into()), GET.into())), "{kinds:?}");
        assert!(kinds.contains(&("input_amplification".into(), Knob::Field("days".into()), COUNT.into())), "{kinds:?}");
        // Fan-out: the most calls each function was driven to, most first.
        let get = a.fan_out.iter().find(|f| f.func == GET).unwrap();
        assert_eq!((get.base_calls, get.max_calls), (2, 1024));
        assert!(a.fan_out.windows(2).all(|w| w[0].max_calls >= w[1].max_calls));
        assert!(a.fan_out.iter().all(|f| f.func != ALL && f.func != SAVE), "{:?}", a.fan_out.iter().map(|f| &f.func).collect::<Vec<_>>());
        // A get per pair of `all` and `extra` elements.
        assert_eq!(a.nested.len(), 1, "{:?}", a.nested);
        let n = &a.nested[0];
        assert_eq!((n.func.as_str(), &n.outer, &n.inner, n.calls), (GET, &Knob::HostList(ALL.into()), &Knob::Field("@1".into()), [4, 16, 16, 64]));
        assert_eq!(a.findings.len(), 1);
        assert!(a.runs > 100, "{}", a.runs);
        // Runs get twice the production fuel at most.
        assert!(most_fuel.into_inner() <= 2 * app.manifest.limits.fuel);
    }

    #[test]
    fn amplify_can_look_at_one_function() {
        let app = app("");
        let a = amplify(&app, &base(&app), Some("#count"), 64, &modes).unwrap();
        assert_eq!(a.fan_out.iter().map(|f| f.func.as_str()).collect::<Vec<_>>(), [COUNT]);
        assert!(a.nested.is_empty());
    }

    #[test]
    fn discovery_without_a_request_turns_host_lists_only() {
        let app = app("");
        let mut b = base(&app);
        b.args.clear();
        let d = discover(&app, &b, 64, &shop).unwrap();
        assert_eq!(d.knobs, list_functions(&app).into_iter().map(Knob::HostList).collect::<Vec<_>>());
        assert!(d.discovered.is_empty() && d.keys.is_empty());
    }

    #[test]
    fn discovery_stops_when_the_base_run_lost_evidence() {
        let app = app("");
        let limited = |s: &RunSpec| {
            let mut r = modes(s);
            r.capture_limited = true;
            r.outcome.message = Some("trace too long".into());
            r
        };
        let err = discover(&app, &base(&app), 8, &limited).err().unwrap().to_string();
        assert!(err.starts_with("run r") && err.ends_with(": trace too long"), "{err}");
        assert!(amplify(&app, &base(&app), None, 8, &limited).is_err());
    }
}
