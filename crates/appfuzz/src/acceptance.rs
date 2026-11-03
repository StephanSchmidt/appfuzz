//! Suite orchestration, evidence storage and replay. Requirements come from the manifest.
use super::*;
use appfuzz_core::acceptance::{self as core, Case, Check, Evaluation};

fn finding(name: &str, check: &Check, e: &Evaluation, path: &Path) -> Finding {
    let mut f = Finding::new(
        "acceptance_failed",
        &format!("{name}\0{}", e.records[0].spec.export),
        Severity::Fail,
        format!("acceptance check {name} failed"),
        json!({"acceptance_case":true,"name":name,"origin":check.origin,"description":check.description,"evidence":e.detail,"runs":e.records.iter().map(|r|&r.id).collect::<Vec<_>>()}),
        None,
    );
    f.confirmed = Some(path.display().to_string());
    f
}
fn save(store: &RunStore, e: &Evaluation) -> Result<()> {
    for r in &e.records {
        store.save(r)?;
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct Options {
    runs: u64,
    seed: u64,
    shrink_runs: u32,
}
fn check_one(app: &App, state: &Path, name: &str, check: &Check, base: &RunSpec, options: Options) -> Result<Value> {
    let Options { runs, seed, shrink_runs } = options;
    let store = RunStore::new(state);
    let spec = check.spec(app, base)?;
    let initial = core::evaluate(app, check, &spec)?;
    save(&store, &initial)?;
    let mut matches = initial.matches;
    let mut evaluations = 1u64;
    let mut invalid = 0u64;
    let mut witness = initial;
    if check.searches() && witness.status != "broken" && witness.status != "error" {
        for r in store
            .all()?
            .into_iter()
            .filter(|r| r.spec.component == app.hash && r.spec.contract == app.contract && r.spec.export == spec.export && r.id != spec.id())
        {
            evaluations += 1;
            if matches!(r.outcome.kind, appfuzz_core::record::OutcomeKind::Error | appfuzz_core::record::OutcomeKind::PlanError) {
                invalid += 1;
                continue;
            }
            match core::evaluate_record(app, check, r) {
                Ok(e) if e.status != "error" => {
                    matches += e.matches;
                    if e.status == "broken" {
                        witness = e;
                        break;
                    }
                    if witness.matches == 0 && e.matches > 0 {
                        witness = e;
                    }
                }
                _ => invalid += 1,
            }
        }
    }
    if check.searches() && witness.status != "broken" && witness.status != "error" {
        struct Observations {
            matches: usize,
            evaluations: u64,
            invalid: u64,
            hit: Option<RunSpec>,
            exercised: Option<Evaluation>,
            error: Option<String>,
        }
        let observed = Mutex::new(Observations { matches: 0, evaluations: 0, invalid: 0, hit: None, exercised: None, error: None });
        let on_run = |r: &RunRecord, _kept: bool, _found: &[Finding]| {
            let mut o = lock(&observed);
            o.evaluations += 1;
            if matches!(r.outcome.kind, appfuzz_core::record::OutcomeKind::Error | appfuzz_core::record::OutcomeKind::PlanError) {
                o.invalid += 1;
                return;
            }
            // A mutated input can be outside a relation's domain. Only executed
            // comparisons count as evidence; the declared baseline was checked above.
            match core::evaluate_record(app, check, r.clone()) {
                Ok(e) if e.status != "error" => {
                    o.matches += e.matches;
                    if e.status == "broken" && o.hit.is_none() {
                        o.hit = Some(r.spec.clone());
                    }
                    if e.matches > 0 && o.exercised.is_none() {
                        if let Err(err) = save(&store, &e) {
                            o.error = Some(err.to_string());
                        }
                        o.exercised = Some(e);
                    }
                }
                _ => o.invalid += 1,
            }
        };
        let opts = fuzz::FuzzOpts { runs: Some(runs), time: None, seed, discover: false, property: check.property()?, ..Default::default() };
        let (_report, _corpus) = fuzz::fuzz(app, &spec, vec![], Default::default(), &opts, &on_run)?;
        let mut observed = lock(&observed);
        if let Some(e) = observed.error.take() {
            bail!("{e}");
        }
        evaluations += observed.evaluations;
        invalid += observed.invalid;
        matches += observed.matches;
        if let Some(spec) = &observed.hit {
            witness = core::evaluate(app, check, spec)?;
            if witness.status != "broken" {
                bail!("acceptance counterexample did not reproduce");
            }
        } else if witness.matches == 0
            && let Some(e) = observed.exercised.take()
        {
            witness = e;
        }
    }
    let mut attempts = 0;
    let mut path = None;
    let mut findings = vec![];
    if witness.status == "broken" {
        let original = witness.records[0].spec.clone();
        let (small, n) = if check.searches() {
            let args = app.default_args(app.export(&original.export)?, &original.now)?;
            appfuzz_core::shrink::shrink(app, &original, &args, &|s| core::evaluate(app, check, s).is_ok_and(|e| e.status == "broken"), shrink_runs)
        } else {
            (original, 0)
        };
        attempts = n;
        witness = core::evaluate(app, check, &small)?;
        if witness.status != "broken" {
            bail!("acceptance check {name} could not reproduce its counterexample");
        }
        let case = Case {
            kind: "acceptance".into(),
            version: 1,
            component: app.hash.clone(),
            contract: app.contract.clone(),
            name: name.into(),
            check: check.clone(),
            spec: small,
        };
        let bytes = serde_json::to_vec_pretty(&case)?;
        let target = state.join("acceptance").join(format!("{}.json", &blake3_hex(&bytes)[..16]));
        std::fs::create_dir_all(target.parent().unwrap())?;
        appfuzz_core::store::write_atomic(&target, &bytes)?;
        findings.push(finding(name, check, &witness, &target));
        path = Some(target);
    }
    save(&store, &witness)?;
    FindingStore::new(state, &app.state_key).add(&findings)?;
    Ok(json!({"name":name,"origin":check.origin,"description":check.description,"search":check.searches(),
        "status":witness.status,"matches":matches,"evaluations":evaluations,"invalid_candidates":invalid,"shrink_evaluations":attempts,
        "evidence":witness.detail,"runs":witness.records.iter().map(|r|&r.id).collect::<Vec<_>>(),"case":path,"findings":findings}))
}
pub(super) fn run(app: &App, state: &Path, base: &RunSpec, name: Option<&str>, runs: u64, seed: u64, shrink_runs: u32) -> Result<Value> {
    if runs == 0 {
        bail!("acceptance --runs must be greater than zero");
    }
    let suite = app.manifest.acceptance.as_ref().context("no [acceptance] suite in the manifest")?;
    if name.is_some_and(|n| !suite.checks.contains_key(n)) {
        bail!("unknown acceptance check");
    }
    let mut checks = Vec::new();
    let mut findings = Vec::new();
    for (key, check) in suite.checks.iter().filter(|(key, _)| name.is_none_or(|n| n == key.as_str())) {
        let row = match check_one(app, state, key, check, base, Options { runs, seed, shrink_runs }) {
            Ok(v) => v,
            Err(e) => json!({"name":key,"origin":check.origin,"status":"error","error":format!("{e:#}"),"findings":[]}),
        };
        findings.extend(row["findings"].as_array().into_iter().flatten().cloned());
        checks.push(row);
    }
    let incomplete = checks.iter().any(|c| matches!(c["status"].as_str(), Some("not_exercised" | "error")));
    let failed = checks.iter().any(|c| c["status"] == "broken");
    Ok(json!({"suite_version":suite.version,"checks":checks,"findings":findings,"status":if incomplete{"incomplete"}else{"complete"},
        "verdict":if incomplete{"incomplete"}else if failed{"fail"}else{"pass"},"exit_code":if incomplete{3}else if failed{2}else{0}}))
}
pub(super) fn replay(app: &App, store: &RunStore, path: &str, current: bool) -> Result<Value> {
    let mut case: Case = serde_json::from_slice(&std::fs::read(path)?)?;
    if case.kind != "acceptance" || case.version != 1 {
        bail!("unsupported acceptance case");
    }
    if !current && (case.component != app.hash || case.contract != app.contract || case.spec.component != app.hash || case.spec.contract != app.contract) {
        bail!("acceptance case belongs to another build or contract; use --against-current");
    }
    case.check.validate(&app.manifest)?;
    if current {
        case.spec.component = app.hash.clone();
        case.spec.contract = app.contract.clone();
        case.spec.fuel = app.manifest.limits.fuel.saturating_mul(5);
        case.spec.memory = app.manifest.limits.memory.saturating_mul(4);
        case.spec.ns_per_fuel = app.manifest.limits.ns_per_fuel;
    }
    let e = core::evaluate(app, &case.check, &case.spec)?;
    save(store, &e)?;
    let complete = matches!(e.status.as_str(), "holds" | "broken");
    let reproduced = e.status == "broken";
    let findings = if reproduced { vec![finding(&case.name, &case.check, &e, Path::new(path))] } else { vec![] };
    Ok(json!({"case":path,"name":case.name,"origin":case.check.origin,"mode":if current{"regression"}else{"exact"},"reproduced":reproduced,
        "status":if complete{"complete"}else{"incomplete"},"check_status":e.status,"matches":e.matches,"evidence":e.detail,"findings":findings,
        "runs":e.records.iter().map(|r|&r.id).collect::<Vec<_>>(),
        "exit_code":if !complete{3}else if current{if reproduced{2}else{0}}else if reproduced{0}else{2}}))
}
