//! Historical replay and regression execution use the same case predicate.
use super::*;
use appfuzz_core::{record::OutcomeKind, shrink::Across};

pub(super) fn matches(f: &Finding, r: &RunRecord, app: &App) -> bool {
    let found = detect::per_run_checked(app, r);
    if found.iter().any(|x| x.matches_id(&f.id)) {
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
        if current { shows_again(&finding, &first, app) } else { matches(&finding, &first, app) }
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

/// Replays a finding's run, shrinks it to a small spec that still shows
/// the finding and writes the case file.
pub(super) fn confirm(cli: &Cli, app: &App, store: &RunStore, target: &str, finding: Option<&str>, times: u32, max_runs: u32) -> Result<Value> {
    let fstore = FindingStore::new(&cli.state, &app.state_key);
    let all = fstore.all()?;
    let (run_id, wanted) = match all.iter().find(|f| f.id == *target) {
        Some(f) => (f.run.clone().ok_or_else(|| anyhow!("finding {target} has no run"))?, Some(f.id.clone())),
        None => (target.to_string(), finding.map(str::to_string)),
    };
    let orig = store.load(&run_id)?;
    let shown = detect::per_run_checked(app, &orig);
    let mut f = match &wanted {
        Some(id) => all.iter().find(|f| f.id == *id).cloned().or_else(|| shown.iter().find(|f| f.id == *id).cloned()),
        None => shown.iter().max_by_key(|f| f.severity).cloned(),
    }
    .ok_or_else(|| anyhow!("no such finding for run {run_id}"))?;
    // Deterministic: N replays give the same record.
    let key = |r: &RunRecord| strip_wall(serde_json::to_value(r).unwrap_or_default());
    let want = key(&orig);
    let replays: Vec<u32> = (0..times).collect();
    let same = appfuzz_core::par::map(&replays, |_| key(&app.run(&orig.spec)) == want).into_iter().filter(|s| *s).count() as u32;
    let deterministic = same == times;
    let per_run = cases::matches(&f, &orig, app);
    let mut out = json!({"finding": finding_json(&f), "run": orig.id, "replays": times, "identical": same, "deterministic": deterministic, "per_run": per_run});
    if !deterministic {
        out["confirmed"] = json!(false);
        out["why"] = json!("replays differ; see `appfuzz replay`");
        return Ok(out);
    }
    use appfuzz_core::shrink::{self, Across};
    let runner = |s: &RunSpec| app.run(s);
    let base = app.default_args(app.export(&orig.spec.export)?, &orig.spec.now)?;
    // A finding from comparing runs shrinks by rerunning the
    // comparison, from the run it compared.
    let across = if per_run { None } else { Across::of(&f) };
    let start = match across.as_ref().and_then(|a| a.start_run(&f)) {
        Some(id) if id != orig.id => store.load(id).ok().map(|r| r.spec),
        _ => Some(orig.spec.clone()),
    };
    let across = across.zip(start).filter(|(a, s)| a.shows(app, &f.id, s, &runner).is_some());
    let (from, spec, shrink_runs, min, shrunk) = if per_run {
        let keeps = |r: &RunRecord| cases::matches(&f, r, app);
        let (spec, n) = shrink::minimise(app, &orig.spec, &base, &keeps, max_runs, &runner);
        let min = app.run(&spec);
        store.save(&min)?;
        let shrunk = detect::per_run_checked(app, &min).into_iter().find(|g| g.matches_id(&f.id));
        (orig.spec.clone(), spec, n, min.id, shrunk)
    } else if let Some((a, start)) = &across {
        let per = a.runs_per_test();
        let (spec, n) = shrink::shrink(app, start, &base, &|c| a.shows(app, &f.id, c, &runner).is_some(), (max_runs / per).max(1));
        // Once more, keeping the runs: the finding's run is one of them.
        let save_error = Mutex::new(None);
        let saving = |s: &RunSpec| {
            let r = app.run(s);
            if let Err(error) = store.save(&r) {
                *lock(&save_error) = Some(error);
            }
            r
        };
        let shown = a.shows(app, &f.id, &spec, &saving);
        if let Some(error) = lock(&save_error).take() {
            return Err(error.context("saving comparison confirmation runs"));
        }
        let run = shown.as_ref().and_then(|x| x.run.clone()).unwrap_or_else(|| orig.id.clone());
        (start.clone(), spec, n * per, run, shown)
    } else {
        return Ok(json!({"confirmed": false, "why": "no executable predicate reproduces this finding"}));
    };
    // From now on the finding points at the small run, with the
    // title and evidence that run gives it.
    match shrunk {
        Some(g) if g.severity >= f.severity => f = g,
        Some(_) => {}
        None if per_run => f.run = Some(min.clone()),
        None => {}
    }
    let dir = cli.state.join("cases");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", f.id));
    f.confirmed = Some(path.display().to_string());
    let reproduce = across.as_ref().map(|(a, _)| a.describe());
    let note = if per_run {
        "minimised: the finding still shows in this run"
    } else if across.is_some() {
        "minimised: comparing runs from this spec as `reproduce` says still shows the finding"
    } else {
        "found by an analysis across runs; the run is replayed, not minimised"
    };
    let (size_before, size_after) = (shrink::size(&from), shrink::size(&spec));
    let case = json!({
        "version": 1, "finding": f, "per_run": per_run, "spec": spec, "reproduce": reproduce, "recipe": across.as_ref().map(|(a, _)| a), "original_run": orig.id, "run": min,
        "size_before": size_before, "size_after": size_after, "plan_size": shrink::plan_size(&spec), "note": note,
    });
    appfuzz_core::store::write_atomic(&path, &serde_json::to_vec_pretty(&case)?)?;
    fstore.update(&f)?;
    out["finding"] = finding_json(&f);
    out["confirmed"] = json!(true);
    out["case"] = json!(path);
    out["minimised_run"] = json!(min);
    out["shrink_runs"] = json!(shrink_runs);
    out["size_before"] = json!(size_before);
    out["size_after"] = json!(size_after);
    out["plan_size"] = json!(shrink::plan_size(&spec));
    if let Some(r) = reproduce {
        out["reproduce"] = r;
    }
    out["spec"] = json!({"args": spec.args, "plan": spec.plan, "now": spec.now, "seed": spec.seed});
    Ok(out)
}
