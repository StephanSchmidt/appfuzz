//! A complete review is an isolated, recorded analysis session.
//! Typed commands share one loaded component with the interactive CLI.

use crate::{Cli, Cmd, ProbeCmd, RunArgs, SpecArgs, finding_json, load_manifest};
use anyhow::Result;
use appfuzz_core::{
    detect::{FindingStore, Severity},
    fuzz::Corpus,
    harness::App,
    record::OutcomeKind,
    store::RunStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub struct Opts {
    pub time: String,
    pub rng: u64,
    pub fresh: bool,
    pub confirm: usize,
    pub min: Severity,
    pub runs: Option<u64>,
    pub export: Option<String>,
    pub spec: SpecArgs,
    pub internal_feedback: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub id: String,
    pub component: String,
    pub contract: String,
    /// The acceptance suite this review judged; empty for sessions written before it existed.
    #[serde(default)]
    pub requirements: String,
    pub complete: bool,
    pub verdict: String,
    pub runs: Vec<String>,
}

pub fn review(cli: &Cli, o: &Opts) -> Result<Value> {
    let app = App::load(load_manifest(cli)?)?;
    let id = format!("review-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos());
    let state = cli.state.join("review-runs").join(&id);
    let store = RunStore::new(&state);
    let findings = FindingStore::new(&state, &app.state_key);
    let root_store = RunStore::new(&cli.state);
    let root_findings = FindingStore::new(&cli.state, &app.state_key);
    if !o.fresh {
        Corpus::load(&cli.state, &app.state_key)?.save(&state)?;
    }
    let mut steps = Vec::new();
    let mut errors = Vec::new();
    let mut step = |name: &str, cmd: Cmd| -> Option<Value> {
        let started = Instant::now();
        let c = Cli {
            manifest: cli.manifest.clone(),
            wasm: cli.wasm.clone(),
            component: cli.component.clone(),
            state: state.clone(),
            full: true,
            jobs: cli.jobs,
            fast: cli.fast,
            cmd: Some(cmd),
        };
        let result = crate::run_with_app(c, Some(&app));
        let mut row = json!({"step": name, "ms": started.elapsed().as_millis()});
        let output = match result {
            Ok(v) => {
                row["findings"] = json!(v["findings"].as_array().map_or(0, Vec::len));
                for k in ["shrink_runs", "size_before", "size_after", "plan_size"] {
                    if let Some(x) = v.get(k) {
                        row[k] = x.clone();
                    }
                }
                if v["status"] == "incomplete" {
                    errors.push(format!("{name}: required analysis did not complete"));
                }
                if matches!(v["outcome"]["kind"].as_str(), Some("error" | "plan_error")) {
                    let e = format!("{name}: {}", v["outcome"]);
                    row["error"] = json!(e);
                    errors.push(e);
                }
                if v["not_ok"].as_array().is_some_and(|xs| xs.iter().any(|x| matches!(x["outcome"].as_str(), Some("error" | "plan_error")))) {
                    errors.push(format!("{name}: a required probe could not execute"));
                }
                Some(v)
            }
            Err(e) => {
                let e = format!("{name}: {e:#}");
                row["error"] = json!(e);
                errors.push(e);
                None
            }
        };
        steps.push(row);
        output
    };
    step("inspect", Cmd::Inspect { wit: false });
    let baseline = step("run", Cmd::Run(RunArgs { export: o.export.clone(), legacy_export: None, trace: false, spec: o.spec.clone() }));
    let executable = baseline.as_ref().is_some_and(|v| !matches!(v["outcome"]["kind"].as_str(), None | Some("error" | "plan_error")));
    let mut fuzz = None;
    let mut sequence_findings = Vec::new();
    let mut acceptance_results = Value::Null;
    if executable {
        for name in app.manifest.sequences.keys() {
            if let Some(report) = step(
                &format!("sequence {name}"),
                Cmd::Sequence {
                    cmd: crate::cli::SequenceCmd::Fuzz {
                        scenario: name.into(),
                        runs: o.runs.unwrap_or(100).min(100),
                        search_seed: o.rng,
                        shrink_runs: 200,
                        out: None,
                    },
                },
            ) {
                sequence_findings.extend(crate::sequences::review_findings(&report)?);
            }
        }
        step("probe values", Cmd::Probe { cmd: ProbeCmd::Values { func: None, export: o.export.clone(), spec: o.spec.clone() } });
        step("probe times", Cmd::Probe { cmd: ProbeCmd::Times { export: o.export.clone(), spec: o.spec.clone() } });
        step("amplify", Cmd::Amplify { func: None, dict: 200, export: o.export.clone(), spec: o.spec.clone() });
        fuzz = step(
            "fuzz",
            Cmd::Fuzz {
                runs: o.runs,
                internal_feedback: o.internal_feedback,
                time: o.time.clone(),
                until: "budget".into(),
                plateau: 2000,
                rng: o.rng,
                fresh: o.fresh,
                export: o.export.clone(),
                spec: o.spec.clone(),
            },
        );
    }
    if executable && app.manifest.acceptance.is_some() {
        acceptance_results = step(
            "acceptance",
            Cmd::Acceptance {
                cmd: crate::cli::AcceptanceCmd::Run {
                    name: None,
                    runs: o.runs.unwrap_or(100).min(100),
                    search_seed: o.rng,
                    shrink_runs: 200,
                    export: o.export.clone(),
                    spec: o.spec.clone(),
                },
            },
        )
        .unwrap_or(Value::Null);
    }
    let unexplored = step("unexplored", Cmd::Unexplored);
    let urls = step("urls", Cmd::Urls { run: None, domains: true });
    drop(step);
    // Sequence cases retain the complete journey; a stateless run cannot replay them.
    for old in root_findings.all()?.into_iter().filter(|f| f.detail["sequence_case"] == true) {
        match old.confirmed.as_deref() {
            Some(path) => {
                let replay = crate::sequences::command(&app, &state, &crate::cli::SequenceCmd::Replay { case: path.into(), against_current: false });
                match replay {
                    Ok(v) if v["status"] == "complete" && v["reproduced"] == true => sequence_findings.extend(crate::sequences::review_findings(&v)?),
                    Ok(_) => errors.push(format!("historical sequence {} could not reproduce", old.id)),
                    Err(e) => errors.push(format!("historical sequence {}: {e:#}", old.id)),
                }
            }
            None => errors.push(format!("historical sequence {} has no case", old.id)),
        }
    }
    findings.add(&sequence_findings)?;
    for old in root_findings.all()?.into_iter().filter(|f| f.detail["acceptance_case"] == true) {
        let Some(path) = old.confirmed.as_deref() else {
            errors.push(format!("historical acceptance {} has no case", old.id));
            continue;
        };
        match crate::acceptance::replay(&app, &store, path, false) {
            // The requirement changed since this case was made: the current check decides.
            Ok(v) if v["superseded"] == true => {}
            Ok(v) if v["status"] == "complete" && v["reproduced"] == true => {
                let repeated: Vec<appfuzz_core::detect::Finding> = serde_json::from_value(v["findings"].clone())?;
                findings.add(&repeated)?;
                if let Some(rows) = acceptance_results["checks"].as_array_mut() {
                    for row in rows.iter_mut().filter(|r| r["name"] == v["name"]) {
                        row["status"] = json!("broken");
                        row["case"] = v["case"].clone();
                        row["runs"] = v["runs"].clone();
                        row["evidence"] = v["evidence"].clone();
                        row["historical"] = json!(true);
                    }
                    if acceptance_results["status"] == "complete" {
                        acceptance_results["verdict"] = json!("fail");
                        acceptance_results["exit_code"] = json!(2);
                    }
                }
            }
            Ok(_) => errors.push(format!("historical acceptance {} could not reproduce", old.id)),
            Err(e) => errors.push(format!("historical acceptance {}: {e:#}", old.id)),
        }
    }

    // Search novelty never determines a verdict. Re-evaluate historical failure
    // inputs for this exact build and contract, even with a fresh search corpus.
    if executable {
        for f in root_findings.all()?.into_iter().filter(|f| f.run.is_some()) {
            let run = match root_store.get(f.run.as_deref().expect("filtered")) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    errors.push(format!("missing evidence for historical finding {}", f.id));
                    continue;
                }
                Err(e) => {
                    errors.push(e.to_string());
                    continue;
                }
            };
            if run.spec.component != app.hash || run.spec.contract != app.contract {
                continue;
            }
            let r = app.run(&run.spec);
            store.save(&r)?;
            if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
                errors.push(format!("historical case {} could not execute", f.id));
                continue;
            }
            findings.add(&appfuzz_core::detect::per_run_checked(&app, &r))?;
            if let Some(across) = appfuzz_core::shrink::Across::of(&f) {
                let source = match across.start_run(&f).map(|id| root_store.load(id)) {
                    Some(Ok(source)) => source,
                    Some(Err(e)) => {
                        errors.push(format!("historical comparison {} is missing evidence: {e}", f.id));
                        continue;
                    }
                    None => {
                        errors.push(format!("historical comparison {} has no source run", f.id));
                        continue;
                    }
                };
                store.save(&source)?;
                let replay_errors = std::sync::Mutex::new(Vec::new());
                let runner = |s: &appfuzz_core::record::RunSpec| {
                    let r = app.run(s);
                    if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
                        crate::lock(&replay_errors).push(format!("historical comparison {} could not execute", f.id));
                    }
                    if let Err(e) = store.save(&r) {
                        crate::lock(&replay_errors).push(e.to_string());
                    }
                    r
                };
                match across.evaluate(&app, &f.id, &source.spec, &runner) {
                    Ok(Some(shown)) => {
                        findings.add(&[shown])?;
                    }
                    Ok(None) => {}
                    Err(e) => errors.push(e.to_string()),
                }
                errors.extend(crate::lock(&replay_errors).drain(..));
            }
        }
    }
    let mut todo = findings.all()?;
    todo.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in todo.iter().filter(|f| f.severity > Severity::Info && f.run.is_some()).take(o.confirm) {
        let started = Instant::now();
        let c = Cli {
            manifest: cli.manifest.clone(),
            wasm: cli.wasm.clone(),
            component: cli.component.clone(),
            state: state.clone(),
            full: true,
            jobs: cli.jobs,
            fast: cli.fast,
            cmd: Some(Cmd::Confirm { target: f.id.clone(), finding: None, times: 3, max_runs: 500 }),
        };
        match crate::run_with_app(c, Some(&app)) {
            Ok(v) => {
                let mut row = json!({"step": format!("confirm {}", f.id), "ms": started.elapsed().as_millis()});
                for k in ["shrink_runs", "size_before", "size_after", "plan_size"] {
                    row[k] = v[k].clone();
                }
                if v["confirmed"] != true {
                    errors.push(format!("finding {} could not be confirmed", f.id));
                }
                steps.push(row);
            }
            Err(e) => errors.push(format!("confirm {}: {e:#}", f.id)),
        }
    }
    let mut all = findings.all()?;
    all.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
    let count = |s| all.iter().filter(|f| f.severity == s).count();
    let (fail, warn) = (count(Severity::Fail), count(Severity::Warn));
    let complete = errors.is_empty() && executable && fuzz.is_some();
    let (verdict, code) = if !complete {
        ("incomplete", 3)
    } else if fail > 0 {
        ("fail", 2)
    } else if warn > 0 {
        ("warn", 1)
    } else {
        ("pass", 0)
    };
    let runs = store.all()?;
    for r in &runs {
        root_store.save(r)?;
    }
    root_findings.add(&all)?;
    if fuzz.is_some() {
        Corpus::load(&state, &app.state_key)?.save(&cli.state)?;
    }
    let session = Session {
        version: 1,
        id: id.clone(),
        component: app.hash.clone(),
        contract: app.contract.clone(),
        requirements: app.manifest.requirements_fingerprint(),
        complete,
        verdict: verdict.into(),
        runs: runs.iter().map(|r| r.id.clone()).collect(),
    };
    let dir = cli.state.join("reviews");
    std::fs::create_dir_all(&dir)?;
    appfuzz_core::store::write_atomic(&dir.join(format!("{id}.json")), &serde_json::to_vec_pretty(&session)?)?;
    appfuzz_core::store::write_atomic(&dir.join("last"), id.as_bytes())?;
    let confirmed = all.iter().filter(|f| f.confirmed.is_some()).count();
    Ok(json!({
        "session": id, "component": app.manifest.wasm_path(), "contract": app.contract,
        "status": if complete { "complete" } else { "incomplete" }, "verdict": verdict, "exit_code": code,
        "counts": {"fail": fail, "warn": warn, "info": count(Severity::Info), "confirmed": confirmed},
        "findings": all.iter().filter(|f| f.severity >= o.min).map(finding_json).collect::<Vec<_>>(),
        "coverage": {"kind": if fuzz.as_ref().is_some_and(|v|v["feedback"]["mode"]=="internal") {"internal_and_boundary_features"}else{"host_boundary_and_output_features"},
            "internal_feedback":fuzz.as_ref().map(|v| &v["feedback"]), "faults":fuzz.as_ref().map(|v| &v["faults"]), "fuzz_runs": fuzz.as_ref().map(|v| &v["runs"]),
            "host_value_contracts":appfuzz_core::value_contract::coverage(&app,&runs),
            "corpus": fuzz.as_ref().map(|v| &v["corpus"]), "static_call_sites": unexplored.as_ref().map(|v| &v["static_sites"]),
            "unreached_call_sites": unexplored.as_ref().map(|v| &v["unreached"]), "instruction_branch_coverage": false},
        "not_exercised": {"sink_checks": !app.manifest.has_sinks(), "identity_checks": !appfuzz_core::identity::declared(&app.manifest),
            "output_policy": !app.manifest.has_output_labels(), "request_sequences": app.manifest.sequences.is_empty(), "acceptance_suite":app.manifest.acceptance.is_none()},
        "acceptance":acceptance_results,
        "domains": urls.map(|v| v["domains"].clone()), "steps": steps, "errors": errors,
        "budget": {"fuzz_time": o.time, "fuzz_runs": o.runs, "sequence_evaluations_per_scenario": o.runs.unwrap_or(100).min(100), "acceptance_evaluations_per_check":o.runs.unwrap_or(100).min(100), "scope": "fuzz phase; acceptance checks, sequences, probes, scaling and confirmation are additional"},
        "experimental": ["hostile-code heuristics", "runtime envelopes"],
    }))
}
