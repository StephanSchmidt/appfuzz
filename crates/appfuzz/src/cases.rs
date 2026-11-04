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
        app.rebase(&mut spec);
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

/// Whether a run of another build shows the finding again. A crash is
/// named by where it happened (the panic's line, the trap's offset), which
/// moves with the code: there, any crash of that kind on the input counts.
pub(super) fn shows_again(f: &Finding, r: &RunRecord, app: &App) -> bool {
    matches(f, r, app) || (matches!(f.kind.as_str(), "crash" | "stack_overflow") && detect::per_run_checked(app, r).iter().any(|x| x.kind == f.kind))
}

/// A stored finding checked on the current build: its run's input (and a
/// comparison's source run) moved onto this build and judged again.
pub(super) struct Recheck {
    pub found: bool,
    /// Findings the new runs showed, the rechecked one among them if found.
    pub findings: Vec<Finding>,
}

/// Errors when the input doesn't run on this build (another signature, a
/// missing export) or its evidence is gone.
pub(super) fn recheck(app: &App, root: &RunStore, save: &RunStore, f: &Finding) -> Result<Recheck> {
    let old = root.load(f.run.as_deref().context("the finding has no run")?)?;
    let mut spec = old.spec.clone();
    app.rebase(&mut spec);
    let error = Mutex::new(None);
    let runner = |s: &RunSpec| {
        let r = app.run(s);
        if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            *lock(&error) = Some(r.outcome.message.clone().unwrap_or_else(|| "the input could not execute".into()));
        }
        if let Err(e) = save.save(&r) {
            *lock(&error) = Some(e.to_string());
        }
        r
    };
    let r = runner(&spec);
    if let Some(e) = lock(&error).take() {
        bail!("{e}");
    }
    let mut out = Recheck { found: shows_again(f, &r, app), findings: detect::per_run_checked(app, &r) };
    if let Some(across) = Across::of(f) {
        let source = root.load(across.start_run(f).context("the comparison has no source run")?)?;
        let mut spec = source.spec.clone();
        app.rebase(&mut spec);
        let shown = across.evaluate(app, &f.id, &spec, &runner)?;
        if let Some(e) = lock(&error).take() {
            bail!("{e}");
        }
        out.found = shown.is_some();
        out.findings.extend(shown);
    }
    Ok(out)
}

/// `replay <run> --against-current`: a run of an earlier build or contract,
/// its input on this one, with the findings it showed checked again (exit
/// 2 while one shows).
pub(super) fn replay_run(cli: &Cli, app: &App, store: &RunStore, run: &str) -> Result<Value> {
    let old = store.load(run)?;
    let mut spec = old.spec.clone();
    app.rebase(&mut spec);
    let new = app.run(&spec);
    if matches!(new.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
        bail!("{}", new.outcome.message.unwrap_or_default());
    }
    store.save(&new)?;
    let mut seen = std::collections::BTreeSet::new();
    let before: Vec<Finding> = FindingStore::everywhere(&cli.state)?
        .into_iter()
        .filter(|f| f.run.as_deref() == Some(old.id.as_str()) && f.severity > Severity::Info && seen.insert(f.id.clone()))
        .collect();
    let mut rows = Vec::new();
    for f in &before {
        let found = if Across::of(f).is_some() { recheck(app, store, store, f)?.found } else { shows_again(f, &new, app) };
        rows.push(json!({"id": f.id, "kind": f.kind, "severity": f.severity, "title": f.title, "found_again": found}));
    }
    let reproduced = rows.iter().any(|r| r["found_again"] == true);
    let now = record_findings(cli, app, detect::per_run_checked(app, &new))?;
    Ok(json!({"run": old.id, "rerun": new.id, "mode": "regression", "outcome": new.outcome.kind, "before": rows, "findings": now,
        "reproduced": reproduced, "exit_code": if reproduced { 2 } else { 0 }}))
}
