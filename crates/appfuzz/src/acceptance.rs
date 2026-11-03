//! Suite orchestration, evidence storage and replay. Requirements come from the manifest.
use super::*;
use appfuzz_core::acceptance::{self as core, Case, Check, Evaluation};
use std::collections::BTreeMap;

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
/// Why evaluations did not count, for assert checks.
#[derive(Default)]
struct Tally {
    reasons: BTreeMap<String, u64>,
    vacuous: u64,
    rejected: u64,
    errors: u64,
    first_error: Option<Value>,
}
impl Tally {
    fn note(&mut self, e: &Evaluation) {
        if e.status != "not_exercised" {
            return;
        }
        self.vacuous += u64::from(e.detail["vacuous"] == true);
        self.rejected += u64::from(e.detail["rejected"] == true);
        if let Some(r) = e.detail["reason"].as_str()
            && (self.reasons.len() < 10 || self.reasons.contains_key(r))
        {
            *self.reasons.entry(r.to_string()).or_default() += 1;
        }
    }
    /// An expression error: counted and kept, never passing.
    fn error(&mut self, e: &Evaluation) -> bool {
        if e.detail.get("expression_error").is_none() {
            return false;
        }
        self.errors += 1;
        if self.first_error.is_none() {
            self.first_error = Some(json!({"detail": e.detail, "run": e.records.first().map(|r| &r.id)}));
        }
        true
    }
    fn merge(&mut self, o: Tally) {
        for (k, v) in o.reasons {
            if self.reasons.len() < 10 || self.reasons.contains_key(&k) {
                *self.reasons.entry(k).or_default() += v;
            }
        }
        self.vacuous += o.vacuous;
        self.rejected += o.rejected;
        self.errors += o.errors;
        if self.first_error.is_none() {
            self.first_error = o.first_error;
        }
    }
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
    let mut tally = Tally::default();
    tally.note(&initial);
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
                    tally.note(&e);
                    if e.status == "broken" {
                        witness = e;
                        break;
                    }
                    if witness.matches == 0 && e.matches > 0 {
                        witness = e;
                    }
                }
                Ok(e) if tally.error(&e) => {}
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
            tally: Tally,
        }
        let observed = Mutex::new(Observations { matches: 0, evaluations: 0, invalid: 0, hit: None, exercised: None, error: None, tally: Tally::default() });
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
                    o.tally.note(&e);
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
                Ok(e) if o.tally.error(&e) => {}
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
        tally.merge(std::mem::take(&mut observed.tally));
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
    if witness.status != "broken"
        && witness.status != "error"
        && let Some(first) = &tally.first_error
    {
        // An expression that fails on some inputs does not cover them; scope it.
        witness.status = "error".into();
        witness.detail = json!({"reason": first["detail"]["reason"], "expression_error": first["detail"]["expression_error"], "run": first["run"],
            "hint": "the expression fails on some inputs: guard it (has(), size() > 0), or scope the check with assume, when or input_class"});
    }
    let mut attempts = 0;
    let mut path = None;
    let mut findings = vec![];
    if witness.status == "broken" {
        let original = witness.records[0].spec.clone();
        // Shrinking keeps the same failing conjunct, not just any failure.
        let failing = witness.detail.get("failing").cloned();
        let same = |e: &Evaluation| e.status == "broken" && failing.as_ref().is_none_or(|f| e.detail.get("failing") == Some(f));
        let (small, n) = if check.searches() {
            let args = app.default_args(app.export(&original.export)?, &original.now)?;
            appfuzz_core::shrink::shrink(app, &original, &args, &|s| core::evaluate(app, check, s).is_ok_and(|e| same(&e)), shrink_runs)
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
    let mut weak = None;
    if witness.status == "holds"
        && let Some(a) = check.assertion()?
        && let Ok(values) = a.values(&witness.records[0], &app.manifest)
    {
        weak = a.weak(&values);
        if weak == Some(true) {
            findings.push(Finding::new(
                "weak_assert",
                &format!("{name}\0{}", witness.records[0].spec.export),
                Severity::Warn,
                format!("acceptance check {name} still holds when its values change: it may restate the code or test nothing"),
                json!({"name":name,"origin":check.origin,"property":a.expr.text,
                    "bindings":values.iter().map(|(k,v)|(k.clone(),appfuzz_core::assertion::shorten(v))).collect::<BTreeMap<_,_>>(),
                    "mutations":"each binding: a number +1, a list without its last item, with its first item twice, with its first item changed, with two items swapped"}),
                Some(&witness.records[0].id),
            ));
        }
    }
    let mut health = Vec::new();
    if tally.rejected > 0 && tally.rejected * 10 > (tally.rejected + matches as u64) * 9 {
        health.push(format!("assume rejected {} of {} evaluated runs; widen the request or plan so more runs qualify", tally.rejected, tally.rejected + matches as u64));
    }
    if witness.status == "not_exercised" && tally.vacuous > 0 {
        witness.detail = json!({"reason": "vacuous: it only held on runs where every list it reads was empty; give the host lists items (plan, generate.list_len)"});
    }
    save(&store, &witness)?;
    FindingStore::new(state, &app.state_key).add(&findings)?;
    let mut row = json!({"name":name,"origin":check.origin,"description":check.description,"search":check.searches(),
        "status":witness.status,"matches":matches,"evaluations":evaluations,"invalid_candidates":invalid,"shrink_evaluations":attempts,
        "evidence":witness.detail,"runs":witness.records.iter().map(|r|&r.id).collect::<Vec<_>>(),"case":path,"findings":findings});
    if check.assert.is_some() {
        row["property"] = json!(check.assertion()?.map(|a| a.expr.text.clone()));
        row["not_exercised_reasons"] = json!(tally.reasons);
        row["vacuous"] = json!(tally.vacuous);
        row["rejected"] = json!(tally.rejected);
        row["expression_errors"] = json!(tally.errors);
        row["weak"] = json!(weak);
        row["health"] = json!(health);
    }
    Ok(row)
}
pub(super) fn run(app: &App, state: &Path, base: &RunSpec, name: Option<&str>, runs: u64, seed: u64, shrink_runs: u32) -> Result<Value> {
    if runs == 0 {
        bail!("acceptance --runs must be greater than zero");
    }
    let suite = app.manifest.acceptance.as_ref().context("no [acceptance] suite in the manifest")?;
    // A named assert table runs one check per property: `check` runs them all, `check.property` one.
    let selected: Vec<(String, Check)> =
        suite.expanded().into_iter().filter(|(key, _)| name.is_none_or(|n| key == n || key.strip_prefix(n).is_some_and(|r| r.starts_with('.')))).collect();
    if selected.is_empty() {
        bail!("unknown acceptance check");
    }
    let mut checks = Vec::new();
    let mut findings = Vec::new();
    for (key, check) in &selected {
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
    // A case keeps the requirement it was made with. When the suite no longer
    // holds that exact check, the case documents an old requirement.
    let live = app.manifest.acceptance.as_ref().and_then(|s| s.expanded().into_iter().find(|(n, _)| *n == case.name)).map(|(_, c)| c);
    let superseded = live.is_none_or(|c| serde_json::to_value(&c).ok() != serde_json::to_value(&case.check).ok());
    let e = core::evaluate(app, &case.check, &case.spec)?;
    save(store, &e)?;
    // A shrunk case may read only empty lists; it was a counterexample, so a vacuous hold is still an answer.
    let complete = matches!(e.status.as_str(), "holds" | "broken") || e.detail["vacuous"] == true;
    let reproduced = e.status == "broken";
    let findings = if reproduced { vec![finding(&case.name, &case.check, &e, Path::new(path))] } else { vec![] };
    Ok(json!({"case":path,"name":case.name,"origin":case.check.origin,"mode":if current{"regression"}else{"exact"},"reproduced":reproduced,"superseded":superseded,
        "status":if complete{"complete"}else{"incomplete"},"check_status":e.status,"matches":e.matches,"evidence":e.detail,"findings":findings,
        "runs":e.records.iter().map(|r|&r.id).collect::<Vec<_>>(),
        "exit_code":if !complete{3}else if current{if reproduced{2}else{0}}else if reproduced{0}else{2}}))
}
