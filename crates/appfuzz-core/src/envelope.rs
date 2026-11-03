//! Experimental runtime envelope: what the reviewed app was seen to do, written
//! down so a platform can hold it to that in production.
//!
//! A review only sees the runs it made. A time bomb, a trigger on a rare
//! value or a switch the author flips later does what no review run did.
//! The envelope records, from the stored runs: per host function the
//! most calls per request, the call sites (guest frames) and the
//! destinations its arguments named; the destinations the output fires
//! requests to; whether scripts appear; and the most fuel, cost, latency
//! and memory a run used. `check` holds a production trace to it and
//! reports `outside_envelope`.
//!
//! The format is documented in ENVELOPE.md.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::dest::{self, Origin};
use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::record::{Frame, HostCall, Outcome, OutcomeKind, RunRecord, RunSpec, Totals};

pub const VERSION: u32 = 2;
/// How far above the most seen a count or budget may go before it counts.
pub const MARGIN: f64 = 2.0;
/// Guest frames that make up a call site.
pub const SITE_FRAMES: usize = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub version: u32,
    /// blake3 of the component the runs were made with.
    pub component: String,
    pub contract: String,
    /// The acceptance suite the review was judged against.
    #[serde(default)]
    pub requirements: String,
    pub review: String,
    pub acceptance: String,
    pub runs: usize,
    pub margin: f64,
    pub functions: BTreeMap<String, FnEnvelope>,
    pub output: OutputEnvelope,
    pub budget: Budget,
    /// Host call sites in the code that no run reached.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreached: Vec<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FnEnvelope {
    /// Most calls in one run.
    pub max_calls: u32,
    /// Call sites, innermost guest frames first (`module:func>…`).
    pub sites: BTreeSet<String>,
    /// `host:port` the app's own code named in the arguments.
    pub destinations: BTreeSet<String>,
    /// Some argument named a destination taken from the request or the host.
    pub destinations_from_input: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct OutputEnvelope {
    /// `host:port` the output fires requests to (loads, forms, redirects,
    /// script URLs), from the app's own code.
    pub destinations: BTreeSet<String>,
    pub destinations_from_input: bool,
    /// A script appeared in some output.
    pub scripts: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Budget {
    pub fuel: u64,
    pub cost: u64,
    pub virtual_ms: f64,
    pub memory: u64,
    pub host_calls: u32,
}

/// One request as a platform saw it. The CLI validates complete identity,
/// events, totals and output before checking. Library callers must do likewise.
/// A stored run (`RunRecord`) reads as a trace too.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Trace {
    pub component: String,
    pub contract: String,
    pub export: String,
    /// The export's arguments (the request), WIT-shaped JSON.
    pub args: Vec<Value>,
    pub events: Vec<TraceCall>,
    pub result: Option<Value>,
    pub stdout: String,
    pub stderr: String,
    pub totals: Option<Totals>,
    /// Lets a stored run be read as a trace.
    pub spec: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceCall {
    pub func: String,
    pub args: Map<String, Value>,
    pub result: Option<Value>,
    pub stack: Vec<Frame>,
}

impl Trace {
    /// The trace as a run record, so the run detectors can read it.
    pub fn to_record(&self) -> RunRecord {
        let spec = self.spec.as_ref();
        let export = spec.and_then(|s| s["export"].as_str()).map(str::to_string).unwrap_or_else(|| self.export.clone());
        let args = spec.and_then(|s| s["args"].as_array()).cloned().unwrap_or_else(|| self.args.clone());
        let mut totals = self.totals.clone().unwrap_or_default();
        totals.host_calls = totals.host_calls.max(self.events.len() as u32);
        RunRecord {
            id: "trace".into(),
            spec: RunSpec {
                component: spec.and_then(|s| s["component"].as_str()).unwrap_or(&self.component).to_string(),
                contract: spec.and_then(|s| s["contract"].as_str()).unwrap_or(&self.contract).to_string(),
                export,
                args,
                plan: Default::default(),
                now: String::new(),
                seed: 0,
                fuel: 0,
                memory: 0,
                ns_per_fuel: 0.0,
            },
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: self.result.clone(),
            totals,
            events: self
                .events
                .iter()
                .enumerate()
                .map(|(i, e)| HostCall {
                    n: i as u32 + 1,
                    func: e.func.clone(),
                    call: 0,
                    args: e.args.clone(),
                    value_checks: None,
                    result: e.result.clone(),
                    trap: None,
                    source: "trace".into(),
                    granted: true,
                    latency_ns: 0,
                    cost: 0,
                    fuel_before: 0,
                    t_ns: 0,
                    stack: e.stack.clone(),
                })
                .collect(),
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
        }
    }
}

/// The call site of a host call: its innermost guest frames.
pub fn site(stack: &[Frame]) -> String {
    stack.iter().take(SITE_FRAMES).map(|f| format!("{}:{}", f.module, f.func)).collect::<Vec<_>>().join(">")
}

/// Destinations (`host:port`) in the arguments of call `i`, with whether
/// the app's own code named them.
fn call_destinations(r: &RunRecord, i: usize, m: &Manifest) -> Vec<(String, bool)> {
    let e = &r.events[i];
    let mut out = Vec::new();
    for (p, v) in &e.args {
        let whole = m.param_label(&e.func, p) == Some(crate::labels::Label::Url);
        let mut ss = Vec::new();
        strings(v, &mut ss);
        for s in ss {
            for u in dest::in_arg(&s, whole) {
                if let Some(d) = dest::absolute(&u) {
                    let own = dest::origin(r, &d, Some(e.n)) == Origin::Binary;
                    out.push((d.endpoint, own));
                }
            }
        }
    }
    out
}

/// Destinations the output fires requests to.
fn output_destinations(r: &RunRecord, m: &Manifest) -> Vec<(String, bool, String)> {
    let mut out = Vec::new();
    for u in crate::urls::extract_output(r, m) {
        if !matches!(u.trigger.as_str(), "load" | "form" | "auto" | "unknown" | "redirect" | "refresh") {
            continue;
        }
        if let Some(d) = dest::absolute(&u.url) {
            let own = dest::origin(r, &d, None) == Origin::Binary;
            out.push((d.endpoint, own, u.url));
        }
    }
    out
}

fn has_script(r: &RunRecord, m: &Manifest) -> bool {
    let resp = crate::output::response(r, m);
    resp.body.as_deref().is_some_and(|b| crate::markup::scripts(b).iter().any(|h| h.severity == Severity::Fail))
}

fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

impl Envelope {
    /// The envelope of the given runs (all of one component).
    pub fn build(runs: &[RunRecord], m: &Manifest) -> Self {
        let mut e = Envelope { version: VERSION, margin: MARGIN, runs: runs.len(), ..Default::default() };
        e.component = runs.first().map(|r| r.spec.component.clone()).unwrap_or_default();
        e.contract = m.fingerprint();
        e.requirements = m.requirements_fingerprint();
        for r in runs {
            for (f, n) in r.call_counts() {
                let x = e.functions.entry(f.clone()).or_default();
                x.max_calls = x.max_calls.max(n);
                x.effect = m.effect_of(&f).map(|ef| format!("{ef:?}").to_ascii_lowercase());
            }
            for (i, c) in r.events.iter().enumerate() {
                let x = e.functions.entry(c.func.clone()).or_default();
                if !c.stack.is_empty() {
                    x.sites.insert(site(&c.stack));
                }
                for (d, own) in call_destinations(r, i, m) {
                    if own {
                        x.destinations.insert(d);
                    } else {
                        x.destinations_from_input = true;
                    }
                }
            }
            if r.outcome.kind == OutcomeKind::Ok {
                for (d, own, _) in output_destinations(r, m) {
                    if own {
                        e.output.destinations.insert(d);
                    } else {
                        e.output.destinations_from_input = true;
                    }
                }
                e.output.scripts |= has_script(r, m);
            }
            let (b, t) = (&mut e.budget, &r.totals);
            b.fuel = b.fuel.max(t.fuel);
            b.cost = b.cost.max(t.cost);
            b.virtual_ms = b.virtual_ms.max(crate::detect::ms(t.virtual_ns));
            b.memory = b.memory.max(t.peak_memory);
            b.host_calls = b.host_calls.max(t.host_calls);
        }
        e
    }

    /// Host call `i` of a trace against the envelope.
    pub fn check_call(&self, r: &RunRecord, i: usize, m: &Manifest) -> Vec<Violation> {
        let c = &r.events[i];
        let mut out = Vec::new();
        let Some(f) = self.functions.get(&c.func) else {
            out.push(Violation::fail("function", &c.func, format!("calls {}, which no reviewed run called", c.func), json!({"func": c.func, "n": c.n})));
            return out;
        };
        let n = r.events[..=i].iter().filter(|e| e.func == c.func).count() as u32;
        if n as f64 > f.max_calls as f64 * self.margin && r.events[i + 1..].iter().all(|e| e.func != c.func) {
            out.push(Violation::warn(
                "calls",
                &c.func,
                format!("calls {} {n} times; reviewed runs called it at most {} times", c.func, f.max_calls),
                json!({"func": c.func, "calls": n, "max_calls": f.max_calls}),
            ));
        }
        if !c.stack.is_empty() && !f.sites.is_empty() {
            let s = site(&c.stack);
            if !f.sites.contains(&s) {
                out.push(Violation::warn(
                    "site",
                    &format!("{}\0{s}", c.func),
                    format!("calls {} from code no reviewed run called it from ({s})", c.func),
                    json!({"func": c.func, "n": c.n, "site": s, "frames": c.stack.iter().take(SITE_FRAMES).collect::<Vec<_>>()}),
                ));
            }
        }
        for (d, own) in call_destinations(r, i, m) {
            if own && !f.destinations.contains(&d) {
                out.push(Violation::fail(
                    "destination",
                    &format!("{}\0{d}", c.func),
                    format!("calls {} with {d}, a destination of its own that no reviewed run named", c.func),
                    json!({"func": c.func, "n": c.n, "destination": d}),
                ));
            } else if !own && !f.destinations_from_input {
                out.push(Violation::warn(
                    "destination_from_input",
                    &format!("{}\0{d}", c.func),
                    format!("calls {} with {d}, taken from input; reviewed runs only named fixed destinations", c.func),
                    json!({"func": c.func, "n": c.n, "destination": d}),
                ));
            }
        }
        out
    }

    /// The response of a trace against the envelope.
    pub fn check_output(&self, r: &RunRecord, m: &Manifest) -> Vec<Violation> {
        let mut out = Vec::new();
        for (d, own, url) in output_destinations(r, m) {
            if own && !self.output.destinations.contains(&d) {
                out.push(Violation::fail(
                    "output_destination",
                    &d,
                    format!("the output fires a request to {d}, which no reviewed output did"),
                    json!({"destination": d, "url": {"untrusted": url}}),
                ));
            }
        }
        if !self.output.scripts && has_script(r, m) {
            out.push(Violation::fail("script", "", "the output holds a script; no reviewed output did".into(), json!({})));
        }
        out
    }

    /// Budgets of a trace against the envelope.
    pub fn check_budget(&self, t: &Totals) -> Vec<Violation> {
        let b = &self.budget;
        let mut out = Vec::new();
        let mut over = |what: &str, used: f64, max: f64| {
            if max > 0.0 && used > max * self.margin {
                out.push(Violation::warn(
                    "budget",
                    what,
                    format!("uses {used} {what}; reviewed runs used at most {max}"),
                    json!({"budget": what, "used": used, "max": max}),
                ));
            }
        };
        over("fuel", t.fuel as f64, b.fuel as f64);
        over("cost", t.cost as f64, b.cost as f64);
        over("virtual_ms", crate::detect::ms(t.virtual_ns), b.virtual_ms);
        over("memory", t.peak_memory as f64, b.memory as f64);
        out
    }

    /// Every check on one trace, as `outside_envelope` findings.
    pub fn check(&self, r: &RunRecord, m: &Manifest) -> Vec<Finding> {
        let mut v = Vec::new();
        if self.version != VERSION || self.component.is_empty() || r.spec.component != self.component || r.spec.contract != self.contract || self.contract != m.fingerprint()
            || self.requirements != m.requirements_fingerprint()
        {
            return vec![Finding::new("outside_envelope", "identity", Severity::Fail,
                "trace, envelope and platform contract must identify the same build and configuration".into(),
                json!({"what": "identity"}), Some(&r.id))];
        }
        for i in 0..r.events.len() {
            v.extend(self.check_call(r, i, m));
        }
        if r.outcome.kind == OutcomeKind::Ok {
            v.extend(self.check_output(r, m));
        }
        if r.totals.fuel > 0 {
            v.extend(self.check_budget(&r.totals));
        }
        let ex = &r.spec.export;
        let mut seen = BTreeSet::new();
        v.into_iter()
            .filter(|x| seen.insert((x.what.clone(), x.key.clone())))
            .map(|x| {
                let mut d = x.detail;
                d["what"] = json!(x.what);
                Finding::new("outside_envelope", &format!("{ex}\0{}\0{}", x.what, x.key), x.severity, format!("{ex} {}", x.title), d, Some(&r.id))
            })
            .collect()
    }
}

/// One way a trace leaves the envelope.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    /// `function`, `calls`, `site`, `destination`, `destination_from_input`,
    /// `output_destination`, `script`, `budget`.
    pub what: String,
    pub key: String,
    pub severity: Severity,
    pub title: String,
    pub detail: Value,
}

impl Violation {
    fn fail(what: &str, key: &str, title: String, detail: Value) -> Self {
        Violation { what: what.into(), key: key.into(), severity: Severity::Fail, title, detail }
    }
    fn warn(what: &str, key: &str, title: String, detail: Value) -> Self {
        Violation { what: what.into(), key: key.into(), severity: Severity::Warn, title, detail }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        toml::from_str("[app]\nwasm = \"x.wasm\"\n[functions.\"a/http#fetch\"]\nparams = { url = \"url\" }\n").unwrap()
    }

    fn trace(calls: &[(&str, &str)]) -> RunRecord {
        Trace {
            component: "fixture".into(),
            contract: manifest().fingerprint(),
            export: "x#handle".into(),
            events: calls
                .iter()
                .map(|(f, url)| TraceCall {
                    func: f.to_string(),
                    args: json!({"url": url}).as_object().unwrap().clone(),
                    stack: vec![Frame { module: "m1".into(), func: 7, name: None, offset: None }],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
        .to_record()
    }

    #[test]
    fn holds_traces_to_the_envelope() {
        let m = manifest();
        let reviewed = trace(&[("a/http#fetch", "https://api.example.com/v1")]);
        let e = Envelope::build(std::slice::from_ref(&reviewed), &m);
        assert_eq!(e.functions["a/http#fetch"].destinations, BTreeSet::from(["api.example.com:443".to_string()]));
        assert!(e.check(&reviewed, &m).is_empty());
        let bomb = trace(&[("a/http#fetch", "https://api.example.com/v1"), ("a/http#fetch", "https://drop.example.org/c")]);
        let f = e.check(&bomb, &m);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].kind.as_str(), f[0].severity, f[0].detail["what"].as_str()), ("outside_envelope", Severity::Fail, Some("destination")));
        let new_fn = trace(&[("a/mail#send", "x")]);
        assert_eq!(e.check(&new_fn, &m)[0].detail["what"], "function");
        let many = trace(&[("a/http#fetch", "https://api.example.com/v1"); 3]);
        assert_eq!(e.check(&many, &m)[0].detail["what"], "calls");
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), e);
    }
}
