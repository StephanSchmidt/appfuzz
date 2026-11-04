//! Typed command handlers shared by interactive use and review sessions.
use super::*;

pub(super) fn run(cli: Cli) -> Result<Value> {
    run_with_app(cli, None)
}

#[allow(clippy::too_many_lines, reason = "one match arm per CLI command")]
pub(super) fn run_with_app(cli: Cli, existing: Option<&App>) -> Result<Value> {
    let owned = std::cell::OnceCell::new();
    let load = || -> Result<&App> {
        if let Some(app) = existing {
            return Ok(app);
        }
        if owned.get().is_none() {
            let _ = owned.set(App::load(load_manifest(&cli)?)?);
        }
        Ok(owned.get().expect("initialized"))
    };
    let store = RunStore::new(&cli.state);
    let Some(cmd) = &cli.cmd else { bail!("no command") };
    match cmd {
        Cmd::Review { time, rng, fresh, confirm, min, runs, export, spec, internal_feedback } => {
            parse_duration(time)?;
            review::review(
                &cli,
                &review::Opts {
                    time: time.clone(),
                    rng: *rng,
                    fresh: *fresh,
                    confirm: *confirm,
                    min: severity(min)?,
                    runs: *runs,
                    export: export.clone(),
                    spec: spec.clone(),
                    internal_feedback: *internal_feedback,
                },
            )
        }
        Cmd::Sequence { cmd } => crate::sequences::command(load()?, &cli.state, cmd),
        Cmd::Acceptance { cmd: AcceptanceCmd::Run { name, runs, search_seed, shrink_runs, export, spec } } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            crate::acceptance::run(app, &cli.state, &base, name.as_deref(), *runs, *search_seed, *shrink_runs)
        }
        Cmd::Inspect { wit } => {
            let app = load()?;
            let mut out = inspect(app, *wit)?;
            let st = Statics::parse(&app.bytes)?;
            out["findings"] = record_findings(&cli, app, detect::static_findings(&app.manifest, &app.imports, &st))?;
            Ok(out)
        }
        Cmd::Plan { cmd: PlanCmd::Template } => plan_template(load()?),
        Cmd::Platform { cmd } => platform(&cli, cmd),
        Cmd::Run(a) => {
            let app = load()?;
            let r = execute(app, &store, a)?;
            let mut s = summary(app, &r);
            s["findings"] = record_findings(&cli, app, detect::per_run_checked(app, &r))?;
            if !cli.fast
                && let Some(asserts) = crate::acceptance::asserts_on(app, &r)
            {
                s["asserts"] = asserts;
            }
            if a.trace {
                s["host_calls"] = timeline(&r, &Statics::parse(&app.bytes)?);
            }
            Ok(s)
        }
        Cmd::Call(a) => {
            let app = load()?;
            let r = execute(app, &store, a)?;
            let mut s = summary(app, &r);
            s["findings"] = record_findings(&cli, app, detect::per_run_checked(app, &r))?;
            s["host_calls"] = timeline(&r, &Statics::parse(&app.bytes)?);
            Ok(s)
        }
        Cmd::Show { run, field, view, call, func } => {
            if view != "record" {
                let cmd = match view.as_str() {
                    "summary" => return Ok(summary(load()?, &store.load(run)?)),
                    "calls" => Cmd::Calls { run: run.clone(), func: func.clone() },
                    "timeline" => Cmd::Timeline { run: run.clone() },
                    "logs" => Cmd::Stdout { run: run.clone() },
                    "stack" => Cmd::Why { run: run.clone(), n: call.ok_or_else(|| anyhow!("--view stack requires --call"))? },
                    "provenance" => Cmd::Provenance { run: run.clone(), call: call.ok_or_else(|| anyhow!("--view provenance requires --call"))? },
                    "fuel" => Cmd::Profile { run: run.clone(), top: 15 },
                    "explanation" => Cmd::Explain { run: run.clone() },
                    _ => bail!("unknown view {view:?}"),
                };
                return run_with_app(Cli { cmd: Some(cmd), ..cli }, existing);
            }
            let r = serde_json::to_value(store.load(run)?)?;
            match field {
                None => Ok(r),
                Some(f) => appfuzz_core::harness::field(&r, f).cloned().ok_or_else(|| anyhow!("no field {f}")),
            }
        }
        Cmd::Timeline { run } => {
            let r = store.load(run)?;
            let st = statics_for(&cli)?;
            Ok(json!({"run": r.id, "host_calls": timeline(&r, &st)}))
        }
        Cmd::Calls { run, func } => {
            let r = store.load(run)?;
            Ok(json!({"run": r.id, "functions": by_function(&r, func.as_deref())}))
        }
        Cmd::Why { run, n } => {
            let r = store.load(run)?;
            let e = r.events.iter().find(|e| e.n == *n).ok_or_else(|| anyhow!("run {} has no host call {n}", r.id))?;
            let st = statics_for(&cli)?;
            Ok(json!({
                "run": r.id, "n": n, "func": e.func, "args": e.args,
                "stack": e.stack.iter().map(|f| {
                    let m = st.module(&f.module);
                    json!({
                        "module": f.module, "role": m.map(|m| m.role.clone()), "func": f.func,
                        "name": st.frame_name(f), "offset": f.offset.map(|o| format!("{o:x}")),
                    })
                }).collect::<Vec<_>>(),
            }))
        }
        Cmd::Stdout { run } => {
            let r = store.load(run)?;
            Ok(json!({"run": r.id, "stdout": r.stdout, "stderr": r.stderr}))
        }
        Cmd::Replay { run, against_current } if run.ends_with(".json") && Path::new(run).exists() => cases::replay(load()?, &store, run, *against_current),
        Cmd::Replay { run, against_current: true } => cases::replay_run(&cli, load()?, &store, run),
        Cmd::Replay { run, .. } => {
            let old = store.load(run)?;
            let app = load()?;
            let new = app.run(&old.spec);
            if matches!(new.outcome.kind, appfuzz_core::record::OutcomeKind::Error | appfuzz_core::record::OutcomeKind::PlanError) {
                bail!("{}", new.outcome.message.unwrap_or_default());
            }
            let mut diffs = Vec::new();
            diff(&strip_wall(serde_json::to_value(&old)?), &strip_wall(serde_json::to_value(&new)?), String::new(), &mut diffs);
            Ok(json!({"run": old.id, "same": diffs.is_empty(), "exit_code": if diffs.is_empty() { 0 } else { 2 }, "differences": diffs}))
        }
        Cmd::Scale { knob, sizes, export, spec, points } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let base = RunSpec { plan: scale::steady(&base.plan), ..base };
            let knob = Knob::parse(knob)?;
            let sizes = if sizes.is_empty() { scale::default_sizes(&knob) } else { sizes.clone() };
            let per_run = Mutex::new(Vec::new());
            let runner = |s: &RunSpec| {
                let r = run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
                lock(&per_run).extend(detect::per_run_checked(app, &r).into_iter().map(|f| ((r.totals.host_calls, r.totals.fuel), f)));
                r
            };
            let rep = scale::scale(app, &base, knob, &sizes, &runner)?;
            let mut found = rep.findings.clone();
            found.extend(sorted(per_run));
            let mut out = json!({
                "knob": rep.knob, "sizes": rep.points.iter().map(|p| p.n).collect::<Vec<_>>(),
                "growth": rep.growth.iter().map(|g| {
                    let mut o = json!({"metric": g.metric, "law": g.law.text, "class": g.law.class});
                    if let Some(b) = g.breaks_at { o["breaks_at"] = json!(b); o["limit"] = json!(g.limit); }
                    o
                }).collect::<Vec<_>>(),
                "table": scale_table(&rep),
            });
            if *points {
                out["points"] = json!(rep.points);
            }
            out["findings"] = record_findings(&cli, app, found)?;
            Ok(out)
        }
        Cmd::Amplify { func, dict, export, spec } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let per_run = Mutex::new(Vec::new());
            let runner = |s: &RunSpec| {
                let r = app.run(s);
                lock(&per_run).extend(detect::per_run_checked(app, &r).into_iter().map(|f| ((r.totals.host_calls, r.totals.fuel), f)));
                let _ = store.save(&r);
                r
            };
            let rep = scale::amplify(app, &base, func.as_deref(), *dict, &runner)?;
            let mut found: Vec<Finding> = rep.reports.iter().flat_map(|r| r.findings.clone()).chain(rep.findings.clone()).collect();
            found.extend(sorted(per_run));
            let growing: Vec<Value> = rep
                .reports
                .iter()
                .filter(|r| r.growth.iter().any(|g| g.metric.starts_with("calls ") || g.law.class.superlinear()))
                .map(|r| json!({"knob": r.knob, "context": r.context, "growth": r.growth.iter().map(|g| json!({"metric": g.metric, "law": g.law.text, "breaks_at": g.breaks_at})).collect::<Vec<_>>()}))
                .collect();
            Ok(json!({
                "runs": rep.runs,
                "knobs_tried": rep.knobs.len(),
                "discovered_keys": rep.discovered_keys,
                "contexts": rep.contexts,
                "fan_out": rep.fan_out,
                "nested": rep.nested,
                "growing_knobs": growing,
                "findings": record_findings(&cli, app, found)?,
            }))
        }
        Cmd::Probe { cmd: ProbeCmd::Faults { run, func, runs, export, spec } } => {
            let app = load()?;
            let runner = |s: &RunSpec| run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
            let base = match run {
                Some(id) => store.load(id)?,
                None => runner(&build_spec(app, export.as_deref(), spec)?),
            };
            if base.spec.component != app.hash || base.spec.contract != app.contract {
                anyhow::bail!("fault probes require this build and platform contract");
            }
            if base.outcome.kind != appfuzz_core::record::OutcomeKind::Ok {
                anyhow::bail!("fault probes need a successful baseline; run {} ended {:?}", base.id, base.outcome.kind);
            }
            let (probes, found, exhausted) = appfuzz_core::faults::probe(app, &base, func.as_deref(), *runs, &runner);
            let attempted = probes.len();
            let injected = probes.iter().filter(|p| p.injected).count();
            let applicable = attempted > 0;
            let errors =
                probes.iter().filter(|p| matches!(p.outcome, appfuzz_core::record::OutcomeKind::Error | appfuzz_core::record::OutcomeKind::PlanError)).count();
            let complete = exhausted && applicable && errors == 0;
            Ok(json!({"run":base.id,"status":if complete {"complete"}else{"incomplete"},
                "complete":complete,"attempted":attempted,"injected":injected,"blocked":attempted-injected,
                "execution_errors":errors,
                "note":if !applicable {Some("no applicable host calls matched")}else if errors>0 {Some("some fault evaluations could not execute; inspect their outcomes")}else if !exhausted {Some("fault budget exhausted; increase --runs to finish this trace")}else{None},
                "probes":probes,"findings":record_findings(&cli,app,found)?,"exit_code":if complete {0}else{3}}))
        }
        Cmd::Probe { cmd: ProbeCmd::Values { func, export, spec } } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let runner = |s: &RunSpec| run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
            let (probes, found) = appfuzz_core::probe::values(app, &base, func.as_deref(), &runner);
            let failed: Vec<Value> = probes
                .iter()
                .filter(|p| p.outcome != appfuzz_core::record::OutcomeKind::Ok)
                .map(|p| json!({"func": p.func, "variant": p.variant, "outcome": p.outcome, "run": p.run}))
                .collect();
            Ok(json!({"probes": probes.len(), "not_ok": failed, "findings": record_findings(&cli, app, found)?}))
        }
        Cmd::Probe { cmd: ProbeCmd::Pairs { run, export, spec } } => {
            let app = load()?;
            let runner = |s: &RunSpec| run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
            let base = match run {
                Some(id) => store.load(id)?,
                None => runner(&build_spec(app, export.as_deref(), spec)?),
            };
            if base.outcome.kind != appfuzz_core::record::OutcomeKind::Ok {
                anyhow::bail!("run {} did not end ok ({:?}); pairs need an ok run", base.id, base.outcome.kind);
            }
            if appfuzz_core::metamorphic::pinned(&base).is_none() {
                anyhow::bail!("run {} has host results too long to replay; pairs need every result in full", base.id);
            }
            let (_, lines, found) = appfuzz_core::metamorphic::pairs(app, &base, &runner);
            Ok(json!({"run": base.id, "pairs": lines, "findings": record_findings(&cli, app, found)?}))
        }
        Cmd::Probe { cmd: ProbeCmd::Times { export, spec } } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let runner = |s: &RunSpec| run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
            let (probes, found) = appfuzz_core::probe::times(app, &base, &runner);
            let failed: Vec<Value> = probes
                .iter()
                .filter(|p| p.outcome != appfuzz_core::record::OutcomeKind::Ok)
                .map(|p| json!({"now": p.now, "what": p.what, "outcome": p.outcome, "run": p.run}))
                .collect();
            Ok(json!({"probes": probes.len(), "not_ok": failed, "findings": record_findings(&cli, app, found)?}))
        }
        Cmd::Probe { cmd: ProbeCmd::Web { export, spec } } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let runner = |s: &RunSpec| run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
            let (probes, found) = appfuzz_core::probe::web(app, &base, &runner);
            let failed: Vec<Value> = probes
                .iter()
                .filter(|p| p.outcome != appfuzz_core::record::OutcomeKind::Ok)
                .map(|p| json!({"what": p.what, "outcome": p.outcome, "run": p.run}))
                .collect();
            Ok(json!({"probes": probes.len(), "not_ok": failed, "findings": record_findings(&cli, app, found)?}))
        }
        Cmd::Probe { cmd: ProbeCmd::Auth { export, spec } } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            // Paths the fuzzer saw turned away or issuing a session token.
            let mut bases = vec![base.clone()];
            let mut stored: Vec<RunRecord> = store
                .all()?
                .into_iter()
                .filter(|r| r.spec.component == app.hash && r.spec.contract == app.contract && r.spec.export == base.export)
                .filter(|r| appfuzz_core::auth::rejected(r, &app.manifest).is_some() || !appfuzz_core::auth::tokens(r, &app.manifest).is_empty())
                .collect();
            stored.sort_by(|a, b| a.id.cmp(&b.id));
            let mut paths = std::collections::BTreeSet::new();
            for r in stored {
                if let Some(req) = r.spec.args.first()
                    && paths.len() < 8
                    && paths.insert(appfuzz_core::auth::path(req))
                {
                    bases.push(r.spec);
                }
            }
            let runner = |s: &RunSpec| run_cached(app, &store, s).unwrap_or_else(|_| app.run(s));
            let (probes, found) = appfuzz_core::probe::auth(app, &bases, &runner);
            let failed: Vec<Value> = probes
                .iter()
                .filter(|p| p.outcome != appfuzz_core::record::OutcomeKind::Ok)
                .map(|p| json!({"path": p.path, "what": p.what, "outcome": p.outcome, "run": p.run}))
                .collect();
            Ok(json!({"probes": probes.len(), "not_ok": failed, "findings": record_findings(&cli, app, found)?}))
        }
        Cmd::Envelope { cmd: None, out, review, allow_warnings } => {
            let app = load()?;
            let review_id = if review == "last" {
                std::fs::read_to_string(cli.state.join("reviews/last")).context("no review session; run review first")?
            } else {
                review.clone()
            };
            if review_id.contains(['/', '\\']) || !review_id.starts_with("review-") {
                bail!("invalid review session id");
            }
            let session: review::Session = serde_json::from_slice(&std::fs::read(cli.state.join("reviews").join(format!("{review_id}.json")))?)?;
            if session.version != 1 || !session.complete || !(session.verdict == "pass" || (*allow_warnings && session.verdict == "warn")) {
                bail!("envelope requires a complete passing review; --allow-warnings explicitly accepts a warning verdict");
            }
            if session.component != app.hash || session.contract != app.contract {
                bail!("review belongs to a different build or platform contract");
            }
            if session.requirements != app.manifest.requirements_fingerprint() {
                bail!("the [acceptance] suite changed since this review; run review again");
            }
            let session_store = RunStore::new(&cli.state.join("review-runs").join(&review_id));
            let runs: Vec<RunRecord> = session.runs.iter().map(|id| session_store.load(id)).collect::<Result<_>>()?;
            if runs.is_empty() || runs.iter().any(|r| r.spec.component != app.hash || r.spec.contract != app.contract) {
                bail!("invalid review evidence");
            }
            let mut env = appfuzz_core::envelope::Envelope::build(&runs, &app.manifest);
            env.review = review_id;
            env.acceptance = if *allow_warnings { "pass_or_warn" } else { "pass" }.into();
            env.unreached = dig::unexplored(app, &session_store)?.0["sites"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|s| json!({"host": s["host"], "module": s["module"], "func": s["func"], "name": s["name"], "at": s["at"]}))
                .collect();
            std::fs::write(out, serde_json::to_string_pretty(&env)? + "\n").with_context(|| format!("writing {}", out.display()))?;
            let functions: Vec<Value> = env
                .functions
                .iter()
                .map(|(f, x)| json!({"func": f, "max_calls": x.max_calls, "sites": x.sites.len(), "destinations": x.destinations, "destinations_from_input": x.destinations_from_input}))
                .collect();
            Ok(json!({
                "envelope": out, "experimental": true, "review": env.review, "acceptance": env.acceptance, "runs": env.runs, "functions": functions, "output": env.output, "budget": env.budget,
                "unreached": env.unreached.len(),
            }))
        }
        Cmd::Envelope { cmd: Some(EnvelopeCmd::Check { trace, envelope }), .. } => {
            let m = load_manifest(&cli)?;
            let env: appfuzz_core::envelope::Envelope =
                serde_json::from_str(&std::fs::read_to_string(envelope).with_context(|| format!("reading {}", envelope.display()))?)
                    .with_context(|| format!("parsing {}", envelope.display()))?;
            if env.version != appfuzz_core::envelope::VERSION
                || env.review.is_empty()
                || env.contract != m.fingerprint()
                || env.requirements != m.requirements_fingerprint()
            {
                bail!("envelope is not bound to an accepted review of this platform contract");
            }
            let hash = blake3_hex(&std::fs::read(m.wasm_path())?);
            if env.component != hash {
                bail!("envelope belongs to another build");
            }
            let r = match store.load(trace) {
                Ok(r) => r,
                Err(_) => {
                    let v = parse_json_arg(trace)?;
                    if v.get("events").and_then(Value::as_array).is_none() || !v.get("totals").is_some_and(Value::is_object) {
                        bail!("trace requires events and totals; missing evidence cannot pass");
                    }
                    if v.get("spec").is_some() || v.get("outcome").is_some() {
                        serde_json::from_value::<RunRecord>(v).context("invalid run record")?
                    } else {
                        serde_json::from_value::<appfuzz_core::envelope::Trace>(v).context("not a trace")?.to_record()
                    }
                }
            };
            if r.spec.component.is_empty() || r.spec.contract.is_empty() || r.spec.export.is_empty() {
                bail!("trace requires component, contract and export identity");
            }
            if matches!(r.outcome.kind, appfuzz_core::record::OutcomeKind::Error | appfuzz_core::record::OutcomeKind::PlanError) {
                bail!("trace did not execute");
            }
            if m.entry.as_ref().is_some_and(|e| e.output.body.is_some()) && r.result.is_none() {
                bail!("trace is missing the output to check");
            }
            let mut findings = env.check(&r, &m);
            findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
            let worst = findings.iter().map(|f| f.severity).max();
            let (verdict, code) = match worst {
                Some(Severity::Fail) => ("fail", 2),
                Some(Severity::Warn) => ("warn", 1),
                _ => ("pass", 0),
            };
            let o = json!({
                "experimental": true, "trace": r.id, "verdict": verdict, "exit_code": code, "calls": r.events.len(),
                "findings": findings.iter().map(|f| { let mut o = finding_json(f); o["detail"] = f.detail.clone(); o }).collect::<Vec<_>>(),
            });
            Ok(o)
        }
        Cmd::Urls { run, domains } => {
            let m = load_manifest(&cli)?;
            let runs = match run {
                Some(r) => vec![store.load(r)?],
                None => {
                    let hash = blake3_hex(&std::fs::read(m.wasm_path())?);
                    store.all()?.into_iter().filter(|r| r.spec.component == hash && r.spec.contract == m.fingerprint()).collect()
                }
            };
            let mut inv = appfuzz_core::urls::inventory(&runs, &m);
            if *domains {
                inv.as_object_mut().map(|o| o.remove("urls"));
            }
            Ok(inv)
        }
        Cmd::Fuzz { runs, time, until, plateau, rng, fresh, export, spec, internal_feedback } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let until = match until.as_str() {
                "budget" => fuzz::Until::Budget,
                "new-finding" => fuzz::Until::NewFinding,
                "plateau" => fuzz::Until::Plateau,
                u => bail!("--until must be budget, new-finding or plateau, not {u:?}"),
            };
            let asserts = app
                .manifest
                .acceptance
                .as_ref()
                .filter(|_| !cli.fast)
                .map(|s| s.shared_asserts(&base.export, app.manifest.entry.as_ref().map(|e| e.export.as_str())))
                .unwrap_or_default();
            let opts = fuzz::FuzzOpts {
                runs: *runs,
                time: Some(parse_duration(time)?),
                until,
                seed: *rng,
                plateau: *plateau,
                internal_feedback: *internal_feedback,
                asserts,
                ..Default::default()
            };
            let prior = if *fresh { vec![] } else { fuzz::Corpus::load(&cli.state, &app.state_key)?.entries };
            let findings = FindingStore::new(&cli.state, &app.state_key);
            let known = findings.all()?.into_iter().map(|f| f.id).collect();
            let save_err = Mutex::new(None);
            let on_run = |r: &RunRecord, kept: bool, found: &[Finding]| {
                if (kept || !found.is_empty())
                    && let Err(e) = store.save(r)
                {
                    *lock(&save_err) = Some(e);
                }
            };
            let (rep, corpus) = fuzz::fuzz(app, &base, prior, known, &opts, &on_run)?;
            if let Some(e) = lock(&save_err).take() {
                return Err(e);
            }
            corpus.save(&cli.state)?;
            let maxima: Vec<Value> = rep.maxima.iter().map(|m| json!({"metric": m.metric, "max": m.value, "run": m.run})).collect();
            Ok(json!({
                "runs": rep.runs, "discovery_runs": rep.discovery_runs, "keys": rep.keys, "modes": rep.modes,
                "elapsed_ms": rep.elapsed_ms, "stopped": rep.stopped,
                "feedback":rep.feedback,"faults":rep.faults,"corpus": rep.corpus, "kept": rep.kept, "features": rep.features, "last_new_at_run": rep.last_new_at_run,
                "stages": rep.stages, "maxima": maxima, "jobs": rep.jobs,
                "findings": record_findings(&cli, app, rep.findings)?,
                "asserts": rep.asserts, "assert_cost_pct": rep.assert_cost_pct, "fast": cli.fast,
            }))
        }
        Cmd::Confirm { target, finding, times, max_runs } => {
            let app = load()?;
            let fstore = FindingStore::new(&cli.state, &app.state_key);
            let all = fstore.all()?;
            let (run_id, wanted) = match all.iter().find(|f| f.id == *target) {
                Some(f) => (f.run.clone().ok_or_else(|| anyhow!("finding {target} has no run"))?, Some(f.id.clone())),
                None => (target.clone(), finding.clone()),
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
            let replays: Vec<u32> = (0..*times).collect();
            let same = appfuzz_core::par::map(&replays, |_| key(&app.run(&orig.spec)) == want).into_iter().filter(|s| *s).count() as u32;
            let deterministic = same == *times;
            let per_run = cases::matches(&f, &orig, app);
            let mut out =
                json!({"finding": finding_json(&f), "run": orig.id, "replays": times, "identical": same, "deterministic": deterministic, "per_run": per_run});
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
            let (from, spec, shrink_runs, min) = if per_run {
                let keeps = |r: &RunRecord| cases::matches(&f, r, app);
                let (spec, n) = shrink::minimise(app, &orig.spec, &base, &keeps, *max_runs, &runner);
                let min = app.run(&spec);
                store.save(&min)?;
                (orig.spec.clone(), spec, n, min.id)
            } else if let Some((a, start)) = &across {
                let per = a.runs_per_test();
                let (spec, n) = shrink::shrink(app, start, &base, &|c| a.shows(app, &f.id, c, &runner).is_some(), (*max_runs / per).max(1));
                // Once more, keeping the runs: the finding's run is one of them.
                let saving = |s: &RunSpec| {
                    let r = app.run(s);
                    let _ = store.save(&r);
                    r
                };
                let shown = a.shows(app, &f.id, &spec, &saving);
                let run = shown.and_then(|x| x.run).unwrap_or_else(|| orig.id.clone());
                (start.clone(), spec, n * per, run)
            } else {
                return Ok(json!({"confirmed": false, "why": "no executable predicate reproduces this finding"}));
            };
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
            std::fs::write(&path, serde_json::to_vec_pretty(&case)?)?;
            fstore.update(&f)?;
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
        Cmd::Findings { min } => {
            let m = load_manifest(&cli)?;
            let hash = blake3_hex(&std::fs::read(m.wasm_path())?);
            let min = severity(min)?;
            let mut all: Vec<Finding> = FindingStore::new(&cli.state, &m.state_key(&hash)).all()?.into_iter().filter(|f| f.severity >= min).collect();
            all.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
            let mut out = json!({"count": all.len(), "findings": all.iter().map(finding_json).collect::<Vec<_>>()});
            review::note_rebuild(&cli.state, &m, &hash, &all, &mut out)?;
            Ok(out)
        }
        Cmd::Wasm { cmd } => {
            let m = load_manifest(&cli)?;
            let bytes = std::fs::read(m.wasm_path()).with_context(|| format!("reading {}", m.wasm_path().display()))?;
            let hash = blake3_hex(&bytes);
            let runs: Vec<RunRecord> = store.all()?.into_iter().filter(|r| r.spec.component == hash && r.spec.contract == m.fingerprint()).collect();
            wasm_cmd::run(cmd, &bytes, &runs)
        }
        Cmd::Check { property, runs, time, rng, max_runs, export, spec } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let opts = fuzz::FuzzOpts { runs: *runs, time: Some(parse_duration(time)?), seed: *rng, ..Default::default() };
            let prop = appfuzz_core::check::Property::parse(property)?;
            dig::check(&cli, app, &store, &base, prop, opts, *max_runs)
        }
        Cmd::Eval { run, expr, lets, assume } => {
            let app = load()?;
            dig::eval(app, &store.load(run)?, expr, lets, assume.as_deref())
        }
        Cmd::Bindings { run } => {
            let app = load()?;
            dig::bindings(app, store.load(run).ok())
        }
        Cmd::Sweep { field, r#gen, values, export, spec } => {
            let app = load()?;
            let base = build_spec(app, export.as_deref(), spec)?;
            let values = if values.is_empty() { dig::sweep_values(r#gen, &Statics::parse(&app.bytes)?)? } else { values.clone() };
            dig::sweep(&cli, app, &store, &base, field, values)
        }
        Cmd::Diff { a, b } => {
            let app = load()?;
            Ok(dig::diff_runs(app, &store.load(a)?, &store.load(b)?))
        }
        Cmd::Provenance { run, call } => {
            let app = load()?;
            dig::provenance(app, &store.load(run)?, *call)
        }
        Cmd::Profile { run, top } => {
            let app = load()?;
            dig::profile(app, &store.load(run)?, *top)
        }
        Cmd::Explain { run } => {
            let app = load()?;
            dig::explain(app, &store, &store.load(run)?)
        }
        Cmd::Unexplored => {
            let app = load()?;
            let (mut v, found) = dig::unexplored(app, &store)?;
            v["findings"] = record_findings(&cli, app, found)?;
            Ok(v)
        }
        Cmd::Wasi => dig::wasi(load()?, &store),
        Cmd::Runs => {
            let runs: Vec<Value> = store
                .all()?
                .iter()
                .map(|r| json!({"run": r.id, "export": r.spec.export, "outcome": r.outcome.kind, "host_calls": r.totals.host_calls, "fuel": r.totals.fuel}))
                .collect();
            Ok(json!({"runs": runs}))
        }
    }
}

/// The platform a `platform` command means: `--platform`, else the manifest's.
fn host_manifest(cli: &Cli, spec: Option<&str>) -> Result<appfuzz_core::host_manifest::HostManifest> {
    use appfuzz_core::host_manifest::HostManifest;
    match spec {
        Some(p) => HostManifest::resolve(p, Path::new(".")),
        None => {
            let path = cli.manifest.clone().unwrap_or_else(|| PathBuf::from("appfuzz.toml"));
            HostManifest::of_app(&path).context("no platform: pass --platform, or set [app] platform in the manifest")
        }
    }
}

fn platform(cli: &Cli, cmd: &PlatformCmd) -> Result<Value> {
    use appfuzz_core::host_manifest as hm;
    match cmd {
        PlatformCmd::Docs { platform, func, capability, markdown } => {
            let host = host_manifest(cli, platform.as_deref())?;
            let types = host.types(&Default::default())?;
            let mut d = hm::docs(&host, &types, func.as_deref(), capability.as_deref())?;
            if let Some(path) = markdown {
                std::fs::write(path, hm::docs_markdown(&d)).with_context(|| format!("writing {}", path.display()))?;
                d["markdown"] = json!(path.display().to_string());
            }
            Ok(d)
        }
        PlatformCmd::Check { platform } => {
            let host = host_manifest(cli, platform.as_deref())?;
            let types = host.types(&Default::default())?;
            Ok(hm::check(&host, &types))
        }
    }
}
