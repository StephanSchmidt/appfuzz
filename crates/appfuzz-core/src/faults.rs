//! Systematic, position-specific host failures. A lazy cursor avoids making one
//! full input copy for every call in a long trace.
use crate::{
    detect::Finding,
    harness::App,
    metamorphic::{self, Change, Variant},
    par::Runner,
    plan::Response,
    record::{HostCall, OutcomeKind, RunRecord},
    value::GenOpts,
    wit::ImportKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};
use wasmtime::component::Type;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Once,
    Outage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    pub func: String,
    pub call: u32,
    pub mode: Mode,
}

impl Recipe {
    fn key(&self) -> String {
        format!("{}{}", self.call, if self.mode == Mode::Outage { "+" } else { "" })
    }

    pub fn variant(&self, app: &App, base: &RunRecord) -> Option<Variant> {
        let target = base.events.iter().find(|e| e.func == self.func && e.call == self.call)?;
        let (response, _) = failure(app, target)?;
        let mut spec = base.spec.clone();
        if !spec.plan.0.contains_key(&self.func)
            && let Some(effective) = spec.plan.get(&self.func).cloned()
        {
            spec.plan.0.insert(self.func.clone(), effective);
        }
        let fp = spec.plan.0.entry(self.func.clone()).or_default();
        if self.mode == Mode::Outage {
            // Existing exact overrides must not accidentally recover the service.
            fp.on_call.retain(|k, _| crate::plan::call_start(k).is_some_and(|(n, _)| n < self.call));
        }
        fp.on_call.insert(self.key(), response);
        Some(Variant { change: Change::Fault, func: Some(self.func.clone()), call: Some(self.call), spec })
    }
}

fn result_type(app: &App, func: &str) -> Option<Type> {
    app.imports.iter().filter(|i| i.kind == ImportKind::Platform).flat_map(|i| &i.funcs).find(|f| f.key == func).and_then(|f| f.ty.results().next())
}

/// A typed error is essential: an error payload need not be a string.
/// A trap is an expected service abort, never itself an app crash finding.
fn failure(app: &App, event: &HostCall) -> Option<(Response, bool)> {
    if event.trap.is_some() {
        return None;
    }
    let (generate, recoverable) = match result_type(app, &event.func) {
        Some(Type::Result(_)) => {
            if !event.result.as_ref().is_some_and(|v| v.get("ok").is_some()) {
                return None;
            }
            (Some(GenOpts { results: Some("err".into()), ..Default::default() }), true)
        }
        Some(Type::Option(_)) => {
            if event.result.as_ref().is_none_or(Value::is_null) {
                return None;
            }
            (Some(GenOpts { options: Some("none".into()), ..Default::default() }), true)
        }
        _ => (None, false),
    };
    Some((Response { generate, trap: (!recoverable).then(|| "appfuzz: injected host failure".into()), ..Default::default() }, recoverable))
}

pub(crate) fn first_variant(app: &App, base: &RunRecord) -> Option<Variant> {
    let event = base.events.iter().find(|e| failure(app, e).is_some_and(|(_, recoverable)| recoverable))?;
    Recipe { func: event.func.clone(), call: event.call, mode: Mode::Once }.variant(app, base)
}

/// Each successful host occurrence, in trace order: once, then an outage.
#[derive(Clone, Default)]
pub struct Cursor {
    position: usize,
    outage: bool,
}
impl Cursor {
    pub fn next(&mut self, app: &App, base: &RunRecord, only: Option<&str>) -> Option<Recipe> {
        while let Some(event) = base.events.get(self.position) {
            let mode = if self.outage { Mode::Outage } else { Mode::Once };
            if self.outage {
                self.position += 1;
                self.outage = false;
            } else {
                self.outage = true;
            }
            if only.is_some_and(|f| !event.func.contains(f)) {
                self.position += usize::from(self.outage);
                self.outage = false;
                continue;
            }
            let Some((_, recoverable)) = failure(app, event) else {
                self.position += usize::from(self.outage);
                self.outage = false;
                continue;
            };
            // An unrecoverable trap terminates the request, so an outage adds nothing.
            if !recoverable {
                self.position += usize::from(self.outage);
                self.outage = false;
            }
            return Some(Recipe { func: event.func.clone(), call: event.call, mode });
        }
        None
    }
}

/// Verify both the unchanged prefix and that the host actually delivered the
/// fault. Platform rules and value constraints can legitimately override it.
pub fn injected(base: &RunRecord, recipe: &Recipe, actual: &RunRecord) -> bool {
    let Some(at) = base.events.iter().position(|e| e.func == recipe.func && e.call == recipe.call) else {
        return false;
    };
    let Some(target) = actual.events.get(at) else {
        return false;
    };
    if !base.events[..at].iter().zip(&actual.events[..at]).all(|(a, b)| a.func == b.func && a.args == b.args && a.result == b.result && a.trap == b.trap) {
        return false;
    }
    let expected = &base.events[at];
    let failed = target.trap.is_some() || target.result.as_ref().is_some_and(|v| v.is_null() || v.get("err").is_some());
    target.func == expected.func
        && target.call == expected.call
        && target.args == expected.args
        && target.source == format!("on_call {}", recipe.key())
        && failed
        && (target.result != expected.result || target.trap != expected.trap)
}

pub fn compare(app: &App, base: &RunRecord, recipe: &Recipe, variant: &Variant, actual: &RunRecord) -> Vec<Finding> {
    if !injected(base, recipe, actual) {
        return vec![];
    }
    let mut found = metamorphic::compare(app, base, variant, actual);
    for finding in &mut found {
        if let Some(detail) = finding.detail.as_object_mut() {
            detail.insert("fault".into(), json!(recipe));
        }
    }
    found
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Coverage {
    pub traces: u64,
    pub attempted: u64,
    pub injected: u64,
    pub blocked: u64,
    pub queued_traces: usize,
    pub skipped_traces: u64,
}

pub(crate) struct Search {
    traces: VecDeque<(Arc<RunRecord>, Cursor)>,
    seen: BTreeSet<String>,
    coverage: Coverage,
}
impl Search {
    pub fn new() -> Self {
        Self { traces: VecDeque::new(), seen: BTreeSet::new(), coverage: Coverage::default() }
    }
    pub fn enqueue(&mut self, app: &App, record: Arc<RunRecord>) {
        if record.outcome.kind != OutcomeKind::Ok || !crate::constraints::broken_request(&record.spec.args, &app.manifest).is_empty() {
            return;
        }
        if !record.events.iter().any(|e| failure(app, e).is_some()) {
            return;
        }
        // Include clock, seed and host plan: identical call shapes can have
        // different error handling under those execution contexts.
        let key = record.id.clone();
        if self.seen.contains(&key) {
            return;
        }
        if self.traces.len() >= 16 || self.seen.len() >= 512 {
            self.coverage.skipped_traces += 1;
            return;
        }
        self.seen.insert(key);
        self.coverage.traces += 1;
        self.traces.push_back((record, Cursor::default()));
    }
    pub fn next(&mut self, app: &App) -> Option<(Arc<RunRecord>, Recipe)> {
        while let Some((record, mut cursor)) = self.traces.pop_front() {
            if let Some(recipe) = cursor.next(app, &record, None) {
                if cursor.clone().next(app, &record, None).is_some() {
                    self.traces.push_back((record.clone(), cursor));
                }
                return Some((record, recipe));
            }
        }
        None
    }
    pub fn observe(&mut self, delivered: bool) {
        self.coverage.attempted += 1;
        if delivered {
            self.coverage.injected += 1;
        } else {
            self.coverage.blocked += 1;
        }
    }
    pub fn coverage(mut self) -> Coverage {
        self.coverage.queued_traces = self.traces.len();
        self.coverage
    }
}

#[derive(Serialize)]
pub struct Probe {
    pub fault: Recipe,
    pub position: u32,
    pub run: String,
    pub injected: bool,
    pub outcome: OutcomeKind,
}

pub fn probe(app: &App, base: &RunRecord, only: Option<&str>, budget: u64, run: Runner) -> (Vec<Probe>, Vec<Finding>, bool) {
    let mut cursor = Cursor::default();
    let mut probes = Vec::new();
    let mut found = Vec::new();
    for _ in 0..budget {
        let Some(recipe) = cursor.next(app, base, only) else {
            return (probes, found, true);
        };
        let variant = recipe.variant(app, base).expect("cursor yielded applicable fault");
        let actual = run(&variant.spec);
        found.extend(crate::detect::per_run_checked(app, &actual));
        found.extend(compare(app, base, &recipe, &variant, &actual));
        probes.push(Probe {
            position: base.events.iter().find(|e| e.func == recipe.func && e.call == recipe.call).expect("event").n,
            injected: injected(base, &recipe, &actual),
            fault: recipe,
            run: actual.id,
            outcome: actual.outcome.kind,
        });
    }
    (probes, found, cursor.next(app, base, only).is_none())
}
