//! Historical replay and regression execution use the same case predicate.
use super::*;
use appfuzz_core::{record::OutcomeKind, shrink::Across};

pub(super) fn matches(f: &Finding, r: &RunRecord, app: &App) -> bool {
    let found = detect::per_run_checked(app, r);
    if found.iter().any(|x| x.id == f.id) {
        return true;
    }
    // Probe findings name the stimulus, but their predicate is the underlying
    // crash/hang. Keep that predicate when replaying or minimizing the case.
    if let Some(kind) = f.kind.strip_suffix("_on_host_value").or_else(|| f.kind.strip_suffix("_at_time")) {
        return found.iter().any(|x| x.kind == kind);
    }
    false
}

pub(super) fn replay(app: &App, store: &RunStore, path: &str, current: bool) -> Result<Value> {
    let case: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if case["kind"] == "acceptance" {
        return crate::acceptance::replay(app, store, path, current);
    }
    let mut spec: RunSpec = serde_json::from_value(case["spec"].clone()).context("case file has no spec")?;
    let finding: Finding = serde_json::from_value(case["finding"].clone()).context("case file has no finding")?;
    if current {
        spec.component = app.hash.clone();
        spec.contract = app.contract.clone();
        spec.fuel = app.manifest.limits.fuel.saturating_mul(5);
        spec.memory = app.manifest.limits.memory.saturating_mul(4);
        spec.ns_per_fuel = app.manifest.limits.ns_per_fuel;
    }
    let error = Mutex::new(None);
    let runner = |s: &RunSpec| {
        let r = app.run(s);
        if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            *lock(&error) = Some(r.outcome.message.clone().unwrap_or_else(|| "case could not execute".into()));
        }
        if let Err(e) = store.save(&r) {
            *lock(&error) = Some(e.to_string());
        }
        r
    };
    let first = runner(&spec);
    if let Some(e) = lock(&error).take() {
        bail!("{e}");
    }
    let reproduced = if case["per_run"] == true {
        matches(&finding, &first, app)
    } else {
        let recipe = case
            .get("recipe")
            .filter(|v| !v.is_null())
            .map(|v| serde_json::from_value::<Across>(v.clone()))
            .transpose()?
            .or_else(|| Across::of(&finding))
            .ok_or_else(|| anyhow!("case has no executable comparison recipe; confirm it again"))?;
        recipe.evaluate(app, &finding.id, &spec, &runner)?.is_some()
    };
    if let Some(e) = lock(&error).take() {
        bail!("{e}");
    }
    Ok(json!({"case": path, "finding": finding.id, "run": first.id, "outcome": first.outcome.kind,
        "mode": if current { "regression" } else { "exact" }, "reproduced": reproduced,
        "exit_code": if current { if reproduced { 2 } else { 0 } } else if reproduced { 0 } else { 2 }}))
}
