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
    #[serde(with = "crate::wide")]
    pub cost: u128,
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
    /// Preserve execution diagnostics when reading a stored run as a trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    pub stdout: String,
    pub stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_output: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub memory_limit_hit: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub capture_limited: bool,
    pub totals: Option<Totals>,
    /// Lets a stored run be read as a trace.
    pub spec: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceCall {
    pub func: String,
    pub args: Map<String, Value>,
    pub result: Option<Value>,
    #[serde(default)]
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
        let mut outcome = self.outcome.clone().unwrap_or_else(|| match self.guest_error.as_ref().filter(|error| !error.is_empty()) {
            Some(error) => Outcome { kind: OutcomeKind::Trap, message: Some(format!("the guest reported an error: {error}")), stack: vec![] },
            None if self.rejected_output.is_some() => {
                Outcome { kind: OutcomeKind::Trap, message: Some("the guest's output was rejected".into()), stack: vec![] }
            }
            None => Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
        });
        if self.capture_limited {
            outcome.kind = OutcomeKind::Error;
            outcome.message.get_or_insert_with(|| "trace capture is incomplete".into());
        }
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
            outcome,
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
            guest_error: self.guest_error.clone(),
            rejected_output: self.rejected_output.clone(),
            memory_limit_hit: self.memory_limit_hit,
            capture_limited: self.capture_limited,
        }
    }
}

/// The call site of a host call: its innermost guest frames.
pub fn site(stack: &[Frame]) -> String {
    stack.iter().take(SITE_FRAMES).map(|f| format!("{}:{}", f.module, f.func)).collect::<Vec<_>>().join(">")
}

/// Destinations (`host:port`) in the arguments of call `i`, with whether
/// the app's own code named them.
fn call_destinations(r: &RunRecord, i: usize, m: &Manifest, is_binary: &mut impl FnMut(&dest::Dest, Option<u32>) -> bool) -> Vec<(String, bool)> {
    let e = &r.events[i];
    let mut out = Vec::new();
    for (p, v) in &e.args {
        let whole = m.param_label(&e.func, p) == Some(crate::labels::Label::Url);
        let mut ss = Vec::new();
        strings(v, &mut ss);
        for s in ss {
            for u in dest::in_arg(&s, whole) {
                if let Some(d) = dest::absolute(&u) {
                    let own = is_binary(&d, Some(e.n));
                    out.push((d.endpoint, own));
                }
            }
        }
    }
    out
}

/// Destinations the output fires requests to.
fn output_destinations(r: &RunRecord, m: &Manifest, is_binary: &mut impl FnMut(&dest::Dest, Option<u32>) -> bool) -> Vec<(String, bool, String)> {
    let mut out = Vec::new();
    for u in crate::urls::extract_output(r, m) {
        if !matches!(u.trigger.as_str(), "load" | "form" | "auto" | "unknown" | "redirect" | "refresh") {
            continue;
        }
        if let Some(d) = dest::absolute(&u.url) {
            let own = is_binary(&d, None);
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
        // The runs carry the contract as written, before built-in labels.
        e.contract = runs.first().map_or_else(|| m.fingerprint(), |r| r.spec.contract.clone());
        e.requirements = m.requirements_fingerprint();
        for r in runs {
            let mut origins = dest::OriginIndex::new(r);
            let mut is_binary = |d: &dest::Dest, before| origins.is_binary(d, before);
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
                for (d, own) in call_destinations(r, i, m, &mut is_binary) {
                    if own {
                        x.destinations.insert(d);
                    } else {
                        x.destinations_from_input = true;
                    }
                }
            }
            if r.outcome.kind == OutcomeKind::Ok {
                for (d, own, _) in output_destinations(r, m, &mut is_binary) {
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
            b.virtual_ms = b.virtual_ms.max(t.virtual_ns as f64 / 1_000_000.0);
            b.memory = b.memory.max(t.peak_memory);
            b.host_calls = b.host_calls.max(t.host_calls);
        }
        e
    }

    /// Host call `i` of a trace against the envelope.
    pub fn check_call(&self, r: &RunRecord, i: usize, m: &Manifest) -> Vec<Violation> {
        let n = r.events[..=i].iter().filter(|e| e.func == r.events[i].func).count() as u32;
        self.check_call_with(r, i, m, n, &mut |d, before| dest::origin(r, d, before) == Origin::Binary)
    }

    fn check_call_with(&self, r: &RunRecord, i: usize, m: &Manifest, n: u32, is_binary: &mut impl FnMut(&dest::Dest, Option<u32>) -> bool) -> Vec<Violation> {
        let c = &r.events[i];
        let mut out = Vec::new();
        let Some(f) = self.functions.get(&c.func) else {
            out.push(Violation::fail("function", &c.func, format!("calls {}, which no reviewed run called", c.func), json!({"func": c.func, "n": c.n})));
            return out;
        };
        if n as f64 > f.max_calls as f64 * self.margin {
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
        for (d, own) in call_destinations(r, i, m, is_binary) {
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
        let mut origins = dest::OriginIndex::new(r);
        self.check_output_with(r, m, &mut |d, before| origins.is_binary(d, before))
    }

    fn check_output_with(&self, r: &RunRecord, m: &Manifest, is_binary: &mut impl FnMut(&dest::Dest, Option<u32>) -> bool) -> Vec<Violation> {
        let mut out = Vec::new();
        for (d, own, url) in output_destinations(r, m, is_binary) {
            if own && !self.output.destinations.contains(&d) {
                out.push(Violation::fail(
                    "output_destination",
                    &d,
                    format!("the output fires a request to {d}, which no reviewed output did"),
                    json!({"destination": d, "url": {"untrusted": url}}),
                ));
            } else if !own && !self.output.destinations_from_input {
                out.push(Violation::warn(
                    "output_destination_from_input",
                    &d,
                    format!("the output fires a request to {d}, taken from input; reviewed outputs only named fixed destinations"),
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
        let mut over = |what: &str, used: u128, max: u128| {
            let exceeds = crate::value_contract::Decimal::parse(&self.margin.to_string()).and_then(|margin| margin.scaled_by(max)).map_or_else(
                || used as f64 > max as f64 * self.margin,
                |bound| crate::value_contract::Decimal::parse(&used.to_string()).expect("integer decimal").cmp(&bound).is_gt(),
            );
            if exceeds {
                out.push(Violation::warn(
                    "budget",
                    what,
                    format!("uses {used} {what}; reviewed runs used at most {max}"),
                    json!({"budget": what, "used": crate::wide::json(used), "max": crate::wide::json(max)}),
                ));
            }
        };
        over("fuel", u128::from(t.fuel), u128::from(b.fuel));
        over("cost", t.cost, b.cost);
        over("memory", u128::from(t.peak_memory), u128::from(b.memory));
        over("host_calls", u128::from(t.host_calls), u128::from(b.host_calls));
        let virtual_ms = t.virtual_ns as f64 / 1_000_000.0;
        if virtual_ms > b.virtual_ms * self.margin {
            out.push(Violation::warn(
                "budget",
                "virtual_ms",
                format!("uses {virtual_ms} virtual_ms; reviewed runs used at most {}", b.virtual_ms),
                json!({"budget":"virtual_ms", "used":virtual_ms, "max":b.virtual_ms}),
            ));
        }
        out
    }

    /// Every check on one trace, as `outside_envelope` findings.
    pub fn check(&self, r: &RunRecord, m: &Manifest) -> Vec<Finding> {
        let mut v = Vec::new();
        if self.version != VERSION
            || self.component.is_empty()
            || r.spec.component != self.component
            || r.spec.contract != self.contract
            || self.contract != m.fingerprint()
            || self.requirements != m.requirements_fingerprint()
        {
            return vec![Finding::new(
                "outside_envelope",
                "identity",
                Severity::Fail,
                "trace, envelope and platform contract must identify the same build and configuration".into(),
                json!({"what": "identity"}),
                Some(&r.id),
            )];
        }
        if r.capture_limited || matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            return vec![Finding::new(
                "outside_envelope",
                "evidence",
                Severity::Fail,
                "the trace does not contain complete execution evidence".into(),
                json!({"what":"evidence", "capture_limited":r.capture_limited, "outcome":r.outcome.kind}),
                Some(&r.id),
            )];
        }
        if r.outcome.kind == OutcomeKind::BudgetExceeded {
            return vec![Finding::new(
                "outside_envelope",
                "production_budget",
                Severity::Fail,
                "execution stopped after exceeding a production budget".into(),
                json!({"what":"production_budget"}),
                Some(&r.id),
            )];
        }
        let mut origins = dest::OriginIndex::new(r);
        let mut is_binary = |d: &dest::Dest, before| origins.is_binary(d, before);
        let mut counts = BTreeMap::<&str, usize>::new();
        for (i, call) in r.events.iter().enumerate() {
            let n = counts.entry(&call.func).or_default();
            *n += 1;
            v.extend(self.check_call_with(r, i, m, *n as u32, &mut is_binary));
        }
        if r.outcome.kind == OutcomeKind::Ok {
            v.extend(self.check_output_with(r, m, &mut is_binary));
        }
        v.extend(self.check_budget(&r.totals));
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
    /// `output_destination`, `output_destination_from_input`, `script`, `budget`.
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

    #[test]
    fn output_destinations_from_input_require_reviewed_evidence() {
        let m: Manifest = toml::from_str("[app]\nwasm = 'x.wasm'\n[entry]\nexport = 'x#handle'\noutput = { body = 'body', body_format = 'html' }\n").unwrap();
        let mut reviewed = trace(&[]);
        reviewed.spec.contract = m.fingerprint();
        reviewed.result = Some(json!({"body":"<p>Hello</p>"}));
        let e = Envelope::build(std::slice::from_ref(&reviewed), &m);
        let mut changed = reviewed.clone();
        changed.spec.args = vec![json!({"url":"https://input.example/image"})];
        changed.result = Some(json!({"body":"<img src='https://input.example/image'>"}));
        let findings = e.check(&changed, &m);
        assert!(findings.iter().any(|f| f.detail["what"] == "output_destination_from_input" && f.severity == Severity::Warn), "{findings:?}");
        let allowed = Envelope::build(std::slice::from_ref(&changed), &m);
        assert!(allowed.output.destinations_from_input);
        assert!(allowed.check(&changed, &m).is_empty());
    }

    #[test]
    fn zero_fuel_does_not_disable_other_budgets() {
        let m = manifest();
        let mut reviewed = trace(&[]);
        reviewed.totals.cost = 1;
        reviewed.totals.virtual_ns = 1_000_000;
        reviewed.totals.peak_memory = 1024;
        let e = Envelope::build(std::slice::from_ref(&reviewed), &m);
        let mut changed = reviewed;
        changed.totals.cost = 3;
        changed.totals.virtual_ns = 3_000_000;
        changed.totals.peak_memory = 3072;
        let findings = e.check(&changed, &m);
        for budget in ["cost", "virtual_ms", "memory"] {
            assert!(findings.iter().any(|f| f.detail["budget"] == budget), "missing {budget}: {findings:?}");
        }
    }

    #[test]
    fn zero_budget_is_an_observed_limit() {
        let e = Envelope::default();
        assert!(e.check_budget(&Totals::default()).is_empty());
        let violations = e.check_budget(&Totals { fuel: 1, cost: 1, virtual_ns: 1, peak_memory: 1, host_calls: 1, ..Default::default() });
        for budget in ["fuel", "cost", "virtual_ms", "memory", "host_calls"] {
            assert!(violations.iter().any(|v| v.detail["budget"] == budget), "missing {budget}: {violations:?}");
        }
    }

    #[test]
    fn latency_budgets_preserve_nanosecond_precision() {
        let m = manifest();
        let mut reviewed = trace(&[]);
        reviewed.totals.virtual_ns = 1;
        let e = Envelope::build(&[reviewed], &m);
        assert_eq!(e.budget.virtual_ms, 0.000001);
        assert!(e.check_budget(&Totals { virtual_ns: 2, ..Default::default() }).is_empty());
        assert!(e.check_budget(&Totals { virtual_ns: 3, ..Default::default() }).iter().any(|v| v.detail["budget"] == "virtual_ms"));
    }

    #[test]
    fn total_host_calls_are_bounded_across_functions() {
        let m = manifest();
        let a = trace(&[("a/http#fetch", "https://api.example.com")]);
        let b = trace(&[("a/store#get", "key")]);
        let e = Envelope::build(&[a, b], &m);
        let changed = trace(&[("a/http#fetch", "https://api.example.com"), ("a/store#get", "key"), ("a/store#get", "key")]);
        let findings = e.check(&changed, &m);
        assert!(findings.iter().any(|f| f.detail["budget"] == "host_calls"), "{findings:?}");
        assert!(!findings.iter().any(|f| f.detail["what"] == "calls"));
    }

    #[test]
    fn call_checks_depend_only_on_the_current_prefix() {
        let m = manifest();
        let reviewed = trace(&[("a/http#fetch", "https://api.example.com")]);
        let e = Envelope::build(&[reviewed], &m);
        let complete = trace(&[("a/http#fetch", "https://api.example.com"); 4]);
        let prefix = trace(&[("a/http#fetch", "https://api.example.com"); 3]);
        assert!(e.check_call(&prefix, 2, &m).iter().any(|v| v.what == "calls"));
        assert!(e.check_call(&complete, 2, &m).iter().any(|v| v.what == "calls"));
    }

    #[test]
    fn whole_trace_preserves_first_violations_and_changing_destination_origins() {
        let m = manifest();
        let reviewed = trace(&[("a/http#fetch", "https://api.example.com"), ("a/store#get", "key")]);
        let envelope = Envelope::build(&[reviewed], &m);
        let mut changed = trace(&[
            ("a/http#fetch", "https://new.example"),
            ("a/store#get", "key"),
            ("a/http#fetch", "https://new.example"),
            ("a/http#fetch", "https://new.example"),
            ("a/store#get", "key"),
            ("a/http#fetch", "https://new.example"),
        ]);
        changed.events[1].result = Some(json!({"url":"https://new.example"}));
        // Trace::to_record deliberately has no per-function call counters.
        assert!(changed.events.iter().all(|call| call.call == 0));
        let findings = envelope.check(&changed, &m);
        let actual: Vec<_> = findings.iter().map(|f| (f.detail["what"].as_str().unwrap(), f.detail["n"].as_u64(), f.detail["calls"].as_u64())).collect();
        assert_eq!(actual, [("destination", Some(1), None), ("destination_from_input", Some(3), None), ("calls", None, Some(3)), ("budget", None, None)]);
        assert_eq!(findings[0].severity, Severity::Fail);
        assert_eq!(findings[1].severity, Severity::Warn);
        let rebuilt = Envelope::build(&[changed], &m);
        assert!(rebuilt.functions["a/http#fetch"].destinations.contains("new.example:443"));
        assert!(rebuilt.functions["a/http#fetch"].destinations_from_input);
    }
}
