//! Scaling: turn one knob (a host list's length, a request field) through
//! a range of sizes, measure every resource, fit growth laws, and find the
//! size at which a budget breaks. `amplify` finds the knobs by itself.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::detect::{Finding, Severity, ms};
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
    pub virtual_ms: f64,
    /// Unrounded, for fitting: `virtual_ms` keeps two decimals, and on a
    /// fast handler the rounding alone can look like superlinear growth.
    #[serde(skip)]
    pub virtual_ns: u64,
    pub cost: u64,
    pub output_bytes: u64,
    pub host_arg_bytes: u64,
}

impl Point {
    pub fn of(n: u64, r: &RunRecord) -> Self {
        let mut calls = BTreeMap::new();
        for (k, c) in r.call_counts() {
            calls.insert(k, c);
        }
        Point {
            n,
            run: r.id.clone(),
            outcome: r.outcome.kind,
            calls,
            host_calls: r.totals.host_calls,
            fuel: r.totals.fuel,
            peak_memory: r.totals.peak_memory,
            virtual_ms: ms(r.totals.virtual_ns),
            virtual_ns: r.totals.virtual_ns,
            cost: r.totals.cost,
            output_bytes: r.result.as_ref().map(|v| v.to_string().len() as u64).unwrap_or(0),
            host_arg_bytes: r.events.iter().map(|e| Value::Object(e.args.clone()).to_string().len() as u64).sum(),
        }
    }
}

/// The spec for one knob setting.
pub fn apply(app: &App, base: &RunSpec, knob: &Knob, n: u64) -> Result<RunSpec> {
    let mut spec = base.clone();
    match knob {
        Knob::HostList(f) => {
            let info = app
                .imports
                .iter()
                .filter(|i| i.kind == ImportKind::Platform)
                .flat_map(|i| i.funcs.iter())
                .find(|x| x.key == *f || x.key.ends_with(&format!("/{f}")) || x.key.ends_with(&format!("#{f}")))
                .ok_or_else(|| anyhow!("no platform import {f}"))?;
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
            let (i, path) = split_arg(p);
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
                *v = json!(u + by);
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
            let max_id = base.iter().filter_map(|e| e.get("id").and_then(Value::as_u64)).max().unwrap_or(0);
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
                *id = json!(max_id + k + 1);
            } else if let Some((_, v)) = o.iter_mut().find(|(_, v)| v.is_number()) {
                *v = json!(k + 1);
            }
            if let Some((_, v)) = o.iter_mut().find(|(_, v)| v.is_string()) {
                let s = v.as_str().unwrap_or("").split(" #").next().unwrap_or("").to_string();
                *v = json!(format!("{s} #{}", k + 1));
            }
        }
        Value::Number(_) => *e = json!(k),
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
    pub limit: Option<f64>,
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

pub fn analyze(app: &App, knob: Knob, points: Vec<Point>) -> ScaleReport {
    let l = &app.manifest.limits;
    // Points after a failure (hang, crash) distort the fit.
    let good: Vec<&Point> = points.iter().take_while(|p| p.outcome == OutcomeKind::Ok).collect();
    let mut growth = Vec::new();
    let mut add = |metric: String, f: &dyn Fn(&Point) -> f64, limit: Option<f64>| {
        let pts: Vec<(f64, f64)> = good.iter().map(|p| (p.n as f64, f(p))).collect();
        let Some(law) = fit(&pts) else { return };
        if law.class == Class::Constant || law.b <= 0.0 {
            return;
        }
        // Fuel and memory wobble; ignore growth under 2 % over the range.
        let (lo, hi) = (pts.first().map(|p| p.1).unwrap_or(0.0), pts.last().map(|p| p.1).unwrap_or(0.0));
        if hi <= lo * 1.02 {
            return;
        }
        let breaks_at = limit.and_then(|lim| {
            // A measured break wins over the extrapolated one.
            points
                .iter()
                .find(|p| f(p) > lim)
                .map(|p| p.n)
                .filter(|&n| law.breaking_point(lim, MAX_BREAK_N).is_none_or(|b| b > n))
                .or(law.breaking_point(lim, MAX_BREAK_N))
        });
        growth.push(Growth { metric, law, breaks_at, limit });
    };
    let funcs: BTreeSet<String> = points.iter().flat_map(|p| p.calls.keys().cloned()).collect();
    for f in &funcs {
        let key = f.clone();
        add(format!("calls {f}"), &move |p: &Point| *p.calls.get(&key).unwrap_or(&0) as f64, None);
    }
    add("cost".into(), &|p| p.cost as f64, l.cost_per_request.map(|c| c as f64));
    add("virtual_ms".into(), &|p| p.virtual_ns as f64 / 1e6, l.max_latency_ms);
    add("fuel".into(), &|p| p.fuel as f64, Some(l.fuel as f64));
    add("peak_memory".into(), &|p| p.peak_memory as f64, Some(l.memory as f64));
    add("output_bytes".into(), &|p| p.output_bytes as f64, None);
    add("host_arg_bytes".into(), &|p| p.host_arg_bytes as f64, None);

    let findings = findings(app, &knob, &points, &growth);
    ScaleReport { knob, context: None, points, growth, findings }
}

fn findings(app: &App, knob: &Knob, points: &[Point], growth: &[Growth]) -> Vec<Finding> {
    let mut out = Vec::new();
    let worst = points.iter().rfind(|p| p.outcome == OutcomeKind::Ok).or(points.last()).map(|p| p.run.as_str());
    let budget_break = growth.iter().filter_map(|g| g.breaks_at.map(|b| (b, g.metric.clone()))).min();
    let kind = match knob {
        Knob::HostList(_) => "n_plus_1",
        _ => "input_amplification",
    };
    let ex = app.manifest.entry.as_ref().map(|e| e.export.clone()).unwrap_or_default();
    for g in growth.iter().filter(|g| g.metric.starts_with("calls ")) {
        let f = &g.metric["calls ".len()..];
        if let Knob::HostList(src) = knob
            && src == f
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
        } else if g.law.class.superlinear() || budget_break.as_ref().is_some_and(|(b, _)| input || *b <= 100) || effect.is_some() || batch.is_some() {
            Severity::Fail
        } else {
            Severity::Warn
        };
        let mut title = format!("calls to {f} grow as {} with n = {}", g.law.text, knob.describe());
        if let Some(e) = effect {
            title.push_str(&format!(" (effect {}: one change per element)", e.name()));
        }
        if let Some((b, m)) = &budget_break {
            title.push_str(&format!("; {m} breaks its limit at n = {b}"));
        }
        if let Some(b) = &batch {
            title.push_str(&format!("; {b} does it in one call"));
        }
        out.push(Finding::new(
            kind,
            &format!("{ex}\0{knob:?}\0{f}"),
            sev,
            title,
            json!({"knob": knob, "func": f, "law": g.law.text, "class": g.law.class, "breaks_at": budget_break, "worst_run": worst,
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
        let near = g.breaks_at.is_some_and(|b| b <= HOST_LIST_REALISTIC);
        let sev = if matches!(knob, Knob::HostList(_)) && !near { Severity::Info } else { Severity::Warn };
        out.push(Finding::new(
            kind,
            &format!("{ex}\0{knob:?}\0{}", g.metric),
            sev,
            format!("{} grows as {} with n = {}", g.metric, g.law.text, knob.describe()),
            json!({"knob": knob, "metric": g.metric, "law": g.law.text, "class": g.law.class, "breaks_at": g.breaks_at, "worst_run": worst}),
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
    for p in par::map(&specs, |(n, s)| Point::of(*n, &run(s))) {
        let stop = p.outcome != OutcomeKind::Ok;
        points.push(p);
        if stop {
            break;
        }
    }
    Ok(analyze(app, knob, points))
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
    let clock: BTreeSet<String> = app.manifest.entry.iter().flat_map(|e| e.fields.keys().cloned()).collect();
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
    let entry_fields = app.manifest.entry.as_ref().map(|e| e.fields.clone()).unwrap_or_default();
    let inputs = base_run.result.as_ref().map(crate::fuzz::form_inputs).unwrap_or_default();
    let ones: Vec<String> = inputs.iter().map(|_| "1".to_string()).collect();
    let mut crawl: Vec<(String, RunSpec)> = Vec::new();
    for u in crate::urls::extract_output(&base_run, &app.manifest).into_iter().filter(|u| u.kind == "same_host").take(MAX_CRAWL) {
        let mut spec = base.clone();
        if let Some(req) = spec.args.first_mut()
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
    if let Some(req) = base.args.first() {
        let fields = app.manifest.entry.as_ref().map(|e| e.fields.clone()).unwrap_or_default();
        if let Some(p) = crate::fuzz::role_path(&fields, req, "uri").filter(|p| crate::harness::field(req, p).is_some_and(Value::is_string)) {
            prefixes.push(format!("{p}?"));
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
