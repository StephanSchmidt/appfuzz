//! Sequential requests against one simulated backend, with executable invariants.
use crate::{
    dataset::State,
    detect::{self, Finding, Severity},
    harness::App,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use anyhow::{Context, Result, bail};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

pub const MAX_STEPS: usize = 32;
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub export: Option<String>,
    pub request: Option<Value>,
    pub args: Option<Vec<Value>>,
    pub now: Option<String>,
    #[serde(default)]
    pub plan: Plan,
    /// Argument path (e.g. `/0/id`) -> previous record path (`/0/result/id`).
    #[serde(default)]
    pub args_from: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Invariant {
    Unique { dataset: String, fields: Vec<String> },
    MaxRows { dataset: String, max: usize },
    Idempotent { dataset: String },
    UnchangedOnError { dataset: String },
}
impl Invariant {
    fn dataset(&self) -> &str {
        match self {
            Self::Unique { dataset, .. } | Self::MaxRows { dataset, .. } | Self::Idempotent { dataset } | Self::UnchangedOnError { dataset } => dataset,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    #[serde(default = "seed_one")]
    pub seed: u64,
    #[serde(default)]
    pub plan: Plan,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub checks: Vec<Invariant>,
}
fn seed_one() -> u64 {
    1
}
#[derive(Serialize, Deserialize)]
pub struct Report {
    pub records: Vec<RunRecord>,
    pub initial: State,
    pub states: Vec<State>,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
}
impl Report {
    pub fn digest(&self) -> String {
        let mut value = serde_json::to_value(self).expect("report serializes");
        for r in value["records"].as_array_mut().unwrap() {
            r["totals"]["wall_us"] = json!(0);
        }
        blake3::hash(&serde_json::to_vec(&value).unwrap()).to_hex().to_string()
    }
}
pub fn validate(app: &App, scenario: &Scenario) -> Result<()> {
    scenario.plan.validate()?;
    if scenario.steps.is_empty() || scenario.steps.len() > MAX_STEPS {
        bail!("sequence requires 1..={MAX_STEPS} steps");
    }
    for c in &scenario.checks {
        let d = app.manifest.datasets.get(c.dataset()).context("sequence check names an unknown dataset")?;
        if let Invariant::Unique { fields, .. } = c
            && (fields.is_empty() || fields.iter().any(|f| !d.template.contains_key(f)))
        {
            bail!("unique check requires existing record fields");
        }
    }
    for s in &scenario.steps {
        s.plan.validate()?;
        if s.request.is_some() && s.args.is_some() {
            bail!("sequence step cannot specify both request and args");
        }
        if s.plan.0.get("_defaults").is_some_and(|p| !p.dataset_rows.is_empty() || p.dataset_seed.is_some()) {
            bail!("dataset size/seed controls belong in the scenario initial plan");
        }
    }
    Ok(())
}
pub fn run(app: &App, scenario: &Scenario) -> Result<Report> {
    validate(app, scenario)?;
    let initial = app.initial_state(&scenario.plan, scenario.seed)?;
    for c in &scenario.checks {
        let rows = &initial.tables[c.dataset()];
        let invalid = match c {
            Invariant::Unique { fields, .. } => {
                rows.iter().map(|r| serde_json::to_string(&fields.iter().map(|f| &r[f]).collect::<Vec<_>>()).unwrap()).collect::<BTreeSet<_>>().len()
                    != rows.len()
            }
            Invariant::MaxRows { max, .. } => rows.len() > *max,
            _ => false,
        };
        if invalid {
            bail!("initial data violates a sequence invariant: {}", serde_json::to_string(c)?);
        }
    }
    let state = Arc::new(Mutex::new(initial.clone()));
    let mut report = Report { records: vec![], initial, states: vec![], findings: vec![], errors: vec![] };
    let mut previous_input = None;
    let mut previous_error = true;
    let mut seen = BTreeSet::new();
    for (index, step) in scenario.steps.iter().enumerate() {
        let export = app.export(step.export.as_deref().unwrap_or(app.manifest.entry.as_ref().map(|e| e.export.as_str()).unwrap_or("")))?;
        let now = step.now.clone().unwrap_or_else(|| app.manifest.start_time());
        let args = if let Some(a) = &step.args {
            a.clone()
        } else if let Some(r) = &step.request {
            vec![r.clone()]
        } else {
            app.default_args(export, &now)?
        };
        let mut args = Value::Array(args);
        let prior = serde_json::to_value(&report.records)?;
        for (target, source) in &step.args_from {
            *args.pointer_mut(target).context("args_from target does not exist")? = prior.pointer(source).context("args_from source does not exist")?.clone();
        }
        let mut plan = scenario.plan.clone();
        for (key, entry) in &step.plan.0 {
            plan.0.insert(key.clone(), entry.clone());
        }
        let mut spec = app.spec(export, args.as_array().unwrap().clone(), plan, scenario.seed);
        spec.now = now;
        let input = json!([spec.export, spec.args]);
        let before = state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let record = app.run_in_state(&spec, state.clone());
        let after = state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if matches!(record.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            report.errors.push(format!("step {index}: {}", record.outcome.message.as_deref().unwrap_or("did not execute")));
        }
        for f in detect::per_run(&record, &app.manifest) {
            if seen.insert(f.id.clone()) {
                report.findings.push(f);
            }
        }
        let error = record.outcome.kind != OutcomeKind::Ok
            || crate::output::response(&record, &app.manifest).status.is_some_and(|s| s >= 400)
            || record.result.as_ref().is_some_and(|r| r.get("err").is_some());
        for (n, c) in scenario.checks.iter().enumerate() {
            let rows = &after.tables[c.dataset()];
            let broken = match c {
                Invariant::Unique { fields, .. } => {
                    let keys: BTreeSet<_> = rows.iter().map(|r| serde_json::to_string(&fields.iter().map(|f| &r[f]).collect::<Vec<_>>()).unwrap()).collect();
                    keys.len() != rows.len()
                }
                Invariant::MaxRows { max, .. } => rows.len() > *max,
                Invariant::Idempotent { .. } => {
                    let prior_before = if report.states.len() >= 2 { &report.states[report.states.len() - 2] } else { &report.initial };
                    previous_input.as_ref() == Some(&input)
                        && (!previous_error || prior_before.tables[c.dataset()] != before.tables[c.dataset()])
                        && before.tables[c.dataset()] != *rows
                }
                Invariant::UnchangedOnError { .. } => error && before.tables[c.dataset()] != *rows,
            };
            if broken {
                let f = Finding::new(
                    "sequence_check_failed",
                    &format!("{n}:{}", serde_json::to_string(c)?),
                    Severity::Fail,
                    format!("sequence invariant {n} broke after step {index}"),
                    json!({"step":index,"check":c,"check_index":n}),
                    Some(&record.id),
                );
                if seen.insert(f.id.clone()) {
                    report.findings.push(f);
                }
            }
        }
        previous_input = Some(input);
        previous_error = error;
        report.records.push(record);
        report.states.push(after);
        if !report.errors.is_empty() {
            break;
        }
    }
    Ok(report)
}

/// Remove chunks, then individual requests, preserving the finding and valid execution.
pub fn shrink(app: &App, scenario: &Scenario, finding: &str, budget: u64) -> Result<(Scenario, u64)> {
    let mut current = scenario.clone();
    let mut attempts = 0;
    let mut width = (current.steps.len() / 2).max(1);
    loop {
        let mut changed = false;
        let mut start = 0;
        while current.steps.len() > 1 && start < current.steps.len() && attempts < budget {
            let mut candidate = current.clone();
            candidate.steps.drain(start..(start + width).min(candidate.steps.len()));
            if candidate.steps.is_empty() {
                start += width;
                continue;
            }
            attempts += 1;
            if run(app, &candidate).is_ok_and(|r| r.errors.is_empty() && r.findings.iter().any(|f| f.matches_id(finding))) {
                current = candidate;
                changed = true;
            } else {
                start += width;
            }
        }
        if attempts >= budget {
            break;
        }
        if width == 1 {
            if !changed {
                break;
            }
        } else {
            width = (width / 2).max(1);
        }
    }
    Ok((current, attempts))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub version: u32,
    pub component: String,
    pub contract: String,
    pub scenario: Scenario,
    pub finding: Option<String>,
    pub digest: String,
}
pub struct Campaign {
    pub scenario: Scenario,
    pub report: Report,
    pub evaluations: u64,
    pub shrink_evaluations: u64,
}
/// Sequence mutations keep each action's declared argument shape. Replayable
/// actions form the pool; duplicate, reorder, insert and remove requests.
pub fn fuzz(app: &App, scenario: &Scenario, evaluations: u64, seed: u64, shrink_budget: u64) -> Result<Campaign> {
    if evaluations == 0 {
        bail!("sequence fuzz requires --runs greater than zero");
    }
    validate(app, scenario)?;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut last: Option<(Scenario, Report)> = None;
    for i in 0..evaluations {
        let mut candidate = scenario.clone();
        if i == 1 && candidate.steps.len() < MAX_STEPS {
            candidate.steps.push(scenario.steps.last().unwrap().clone());
        } else if i > 1 {
            let pool = &scenario.steps;
            let length = rng.random_range(1..=MAX_STEPS.min(pool.len().saturating_mul(3).max(2)));
            candidate.steps = (0..length).map(|_| pool[rng.random_range(0..pool.len())].clone()).collect();
            if rng.random_bool(0.25) {
                candidate.plan.0.entry("_defaults".into()).or_default().dataset_seed = Some(rng.random());
            }
        }
        let report = match run(app, &candidate) {
            Ok(r) => r,
            Err(e) if i == 0 => return Err(e),
            Err(_) => continue, // invalid reordered dependencies are not execution evidence
        };
        if !report.errors.is_empty() {
            return Ok(Campaign { scenario: candidate, report, evaluations: i + 1, shrink_evaluations: 0 });
        }
        if let Some(f) = report.findings.iter().find(|f| f.severity == Severity::Fail) {
            let id = f.id.clone();
            let (small, attempts) = shrink(app, &candidate, &id, shrink_budget)?;
            let report = run(app, &small)?;
            return Ok(Campaign { scenario: small, report, evaluations: i + 1, shrink_evaluations: attempts });
        }
        let score = |r: &Report| (r.findings.iter().map(|f| f.severity).max(), r.findings.len());
        if last.as_ref().is_none_or(|(_, best)| score(&report) > score(best)) {
            last = Some((candidate, report));
        }
    }
    let (scenario, report) = last.expect("positive budget");
    Ok(Campaign { scenario, report, evaluations, shrink_evaluations: 0 })
}
