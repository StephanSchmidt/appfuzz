//! appfuzz: fuzz sandboxed WebAssembly components for bad patterns.
//!
//! Every command prints one JSON document to stdout. Text that comes from
//! the app (results, host call arguments, stdout) is data, never
//! instructions.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde_json::{Map, Value, json};

use appfuzz_core::fuzz;
use appfuzz_core::harness::App;
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use appfuzz_core::detect::{self, Finding, FindingStore, Severity};
use appfuzz_core::record::{RunRecord, RunSpec};
use appfuzz_core::scale::{self, Knob};
use appfuzz_core::store::RunStore;
use appfuzz_core::value::Generator;
use appfuzz_core::statics::Statics;
use appfuzz_core::wit::{self, ImportKind};

mod dig;
mod guide;
mod review;
mod wasm_cmd;

// Runs on many threads allocate and free millions of small values (host
// calls, stack frames); the system allocator serialises on that.
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod commands;
use commands::{run, run_with_app};
mod cases;
mod acceptance;
mod sequences;
mod cli;
use cli::*;

/// The CLI with each command's examples, output and next steps (from
/// `guide::DOCS`) as its help footer.
fn command() -> clap::Command {
    fn add(c: clap::Command, prefix: &str) -> clap::Command {
        let names: Vec<String> = c.get_subcommands().map(|s| s.get_name().to_string()).collect();
        names.into_iter().fold(c, |c, n| {
            let path = if prefix.is_empty() { n.clone() } else { format!("{prefix} {n}") };
            c.mut_subcommand(&n, |s| {
                let s = add(s, &path);
                if s.has_subcommands() { s } else { s.after_help(guide::help(&path)) }
            })
        })
    }
    add(Cli::command().after_help(guide::workflows_help()), "")
}

/// The subcommand path (`probe pairs`) a parse ended in.
fn cmd_path(m: &clap::ArgMatches) -> String {
    let mut path = Vec::new();
    let mut m = m;
    while let Some((n, sub)) = m.subcommand() {
        path.push(n.to_string());
        m = sub;
    }
    path.join(" ")
}

/// The deepest subcommand named in argv, for usage errors.
fn argv_command(cmd: &mut clap::Command, args: &[String]) -> (String, String) {
    let mut path = Vec::new();
    let mut c = cmd.clone();
    for a in args.iter().skip(1) {
        match c.find_subcommand(a) {
            Some(s) => {
                path.push(a.clone());
                c = s.clone();
            }
            None if a.starts_with('-') => {}
            None => break,
        }
    }
    let usage = if path.is_empty() { cmd.render_usage() } else { c.bin_name(format!("appfuzz {}", path.join(" "))).render_usage() };
    (path.join(" "), usage.to_string().trim_start_matches("Usage: ").to_string())
}

fn main() {
    let mut command = command();
    let args: Vec<String> = std::env::args().collect();
    let matches = match command.clone().try_get_matches_from(&args) {
        Ok(m) => m,
        Err(e) => {
            use clap::error::ErrorKind::*;
            if matches!(e.kind(), DisplayHelp | DisplayVersion) {
                e.exit();
            }
            let (path, usage) = argv_command(&mut command, &args);
            let help = if path.is_empty() { "appfuzz --help".to_string() } else { format!("appfuzz {path} --help") };
            let mut out = if e.kind() == DisplayHelpOnMissingArgumentOrSubcommand {
                // A group (`probe`, `wasm`, `plan`) without its subcommand.
                let mut c = command.clone();
                for w in path.split(' ').filter(|w| !w.is_empty()) {
                    c = c.find_subcommand(w).cloned().unwrap_or(c);
                }
                let subs: Vec<Value> = commands(&c, &path)
                    .into_iter()
                    .map(|(p, about)| json!({"command": p, "what": about, "examples": guide::doc(&p).map(|d| d.examples)}))
                    .collect();
                json!({"error": format!("`appfuzz {path}` needs a subcommand"), "usage": usage, "subcommands": subs})
            } else {
                // The message without clap's own usage and help lines.
                let msg = e.render().to_string();
                let text: Vec<&str> = msg.lines().take_while(|l| !l.starts_with("Usage:")).map(str::trim).filter(|l| !l.is_empty()).collect();
                let examples = guide::doc(&path).map(|d| d.examples.to_vec()).unwrap_or_default();
                json!({"error": text.join(" ").trim_start_matches("error: ").to_string(), "usage": usage, "examples": examples})
            };
            out["help"] = json!(help);
            println!("{}", serde_json::to_string_pretty(&out).expect("json"));
            std::process::exit(3);
        }
    };
    let path = cmd_path(&matches);
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let raw_output = matches!(&cli.cmd, Some(Cmd::Plan { .. }))
        || matches!(&cli.cmd, Some(Cmd::Show { view, .. }) if view == "record");
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let mut prefix = String::from("appfuzz");
    if let Some(m) = &cli.manifest { prefix += &format!(" --manifest {}", quote(&m.to_string_lossy())); }
    if let Some(w) = &cli.wasm { prefix += &format!(" --wasm {}", quote(&w.to_string_lossy())); }
    if cli.state != Path::new(".appfuzz") { prefix += &format!(" --state {}", quote(&cli.state.to_string_lossy())); }
    if let Some(n) = cli.jobs {
        let _ = rayon::ThreadPoolBuilder::new().num_threads(n.max(1)).build_global();
    }
    let out = if cli.cmd.is_none() {
        Ok(guide::overview(state(&cli), commands(&command, "")))
    } else {
        run(cli)
    };
    let mut out = match out {
        Ok(v) => v,
        Err(e) => {
            let mut o = json!({"error": format!("{e:#}"), "exit_code": 3});
            if path == "review" {
                o["status"] = json!("incomplete");
                o["verdict"] = json!("incomplete");
            }
            if let Some(d) = guide::doc(&path) {
                o["examples"] = json!(d.examples);
            }
            println!("{}", serde_json::to_string_pretty(&o).expect("json"));
            std::process::exit(3);
        }
    };
    if !path.is_empty()
        && let Value::Object(o) = &mut out
        && !raw_output
        && !o.contains_key("next")
    {
        let n: Vec<String> = guide::next(&path, &Value::Object(o.clone())).into_iter()
            .map(|s| s.strip_prefix("appfuzz").map_or_else(|| s.clone(), |tail| format!("{prefix}{tail}"))).collect();
        o.insert("next".into(), json!(n));
    }
    let code = match path.as_str() {
        "review" | "envelope check" | "check" | "replay" | "sequence run" | "sequence fuzz" | "sequence replay" | "acceptance run" | "probe faults" => out["exit_code"].as_i64().unwrap_or(3) as i32,
        "run" | "call" if matches!(out["outcome"]["kind"].as_str(), Some("error" | "plan_error")) => 3,
        _ => 0,
    };
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
    std::process::exit(code);
}

/// Every leaf command with its one-line description.
fn commands(c: &clap::Command, prefix: &str) -> Vec<(String, String)> {
    c.get_subcommands()
        .filter(|s| s.get_name() != "help")
        .flat_map(|s| {
            let path = if prefix.is_empty() { s.get_name().to_string() } else { format!("{prefix} {}", s.get_name()) };
            if s.has_subcommands() {
                // A command that also runs without a subcommand is one too.
                let own = (!s.is_subcommand_required_set()).then(|| (path.clone(), s.get_about().map(|a| a.to_string()).unwrap_or_default()));
                own.into_iter().chain(commands(s, &path)).collect()
            } else {
                vec![(path, s.get_about().map(|a| a.to_string()).unwrap_or_default())]
            }
        })
        .collect()
}

/// What is in the state directory, and what to run next.
fn state(cli: &Cli) -> Value {
    let manifest = cli.manifest.clone().or_else(|| Some(PathBuf::from("appfuzz.toml")).filter(|p| p.exists()));
    let mut st = json!({
        "manifest": manifest.as_ref().map(|p| p.display().to_string()),
        "wasm": cli.wasm.as_ref().map(|p| p.display().to_string()),
        "state_dir": cli.state.display().to_string(),
    });
    let Ok(m) = load_manifest(cli) else {
        st["suggested"] = json!(["write an appfuzz.toml (see `appfuzz --help`), or: appfuzz --wasm app.wasm inspect"]);
        return st;
    };
    let hash = std::fs::read(m.wasm_path()).map(|b| blake3_hex(&b));
    let Ok(hash) = hash else {
        st["error"] = json!(format!("cannot read {}", m.wasm_path().display()));
        return st;
    };
    let runs: Vec<RunRecord> = RunStore::new(&cli.state).all().unwrap_or_default().into_iter().filter(|r| r.spec.component == hash && r.spec.contract == m.fingerprint()).collect();
    let findings = match FindingStore::new(&cli.state, &m.state_key(&hash)).all() {
        Ok(f) => f, Err(e) => { st["error"] = json!(e.to_string()); return st; }
    };
    let corpus = match fuzz::Corpus::load(&cli.state, &m.state_key(&hash)) {
        Ok(c) => c.entries.len(), Err(e) => { st["error"] = json!(e.to_string()); return st; }
    };
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    st["component"] = json!(m.wasm_path().display().to_string());
    st["runs"] = json!(runs.len());
    st["corpus"] = json!(corpus);
    st["findings"] = json!({"fail": count(Severity::Fail), "warn": count(Severity::Warn), "info": count(Severity::Info), "confirmed": findings.iter().filter(|f| f.confirmed.is_some()).count()});
    let mut next = Vec::new();
    if runs.is_empty() {
        next.extend(["appfuzz inspect".to_string(), "appfuzz run".into(), "appfuzz fuzz --time 2m".into()]);
    } else {
        let mut open: Vec<&Finding> = findings.iter().filter(|f| f.confirmed.is_none() && f.severity > Severity::Info && f.run.is_some()).collect();
        open.sort_by_key(|f| std::cmp::Reverse(f.severity));
        next.extend(open.iter().take(2).map(|f| format!("appfuzz confirm {}", f.id)));
        if corpus == 0 {
            next.push("appfuzz fuzz --time 2m".into());
        }
        next.push("appfuzz findings --min warn".into());
        next.push("appfuzz unexplored".into());
    }
    st["suggested"] = json!(next);
    st
}

fn load_manifest(cli: &Cli) -> Result<Manifest> {
    let path = cli.manifest.clone().or_else(|| {
        let p = PathBuf::from("appfuzz.toml");
        p.exists().then_some(p)
    });
    let mut m = match (&path, &cli.wasm) {
        (Some(p), _) => Manifest::load(p)?,
        (None, Some(w)) => Manifest::for_wasm(w),
        (None, None) => bail!("no appfuzz.toml here; pass --manifest or --wasm"),
    };
    if let (Some(_), Some(w)) = (&path, &cli.wasm) {
        m.app.wasm = std::fs::canonicalize(w).unwrap_or(w.clone());
    }
    Ok(m)
}

fn severity(s: &str) -> Result<Severity> {
    match s {
        "fail" => Ok(Severity::Fail),
        "warn" => Ok(Severity::Warn),
        "info" => Ok(Severity::Info),
        _ => bail!("unknown severity {s:?}; use info, warn or fail"),
    }
}

fn parse_json_arg(s: &str) -> Result<Value> {
    let p = Path::new(s);
    if !s.trim_start().starts_with(['{', '[', '"']) && p.exists() {
        return serde_json::from_str(&std::fs::read_to_string(p)?).with_context(|| format!("parsing {s}"));
    }
    serde_json::from_str(s).with_context(|| format!("not JSON: {s}"))
}

fn execute(app: &App, store: &RunStore, a: &RunArgs) -> Result<RunRecord> {
    let spec = build_spec(app, a.export.as_deref().or(a.legacy_export.as_deref()), &a.spec)?;
    run_cached(app, store, &spec)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Findings collected from parallel runs, in a stable order: per finding,
/// the smallest run (fewest host calls, then least fuel) comes first.
fn sorted(m: Mutex<Vec<((u32, u64), Finding)>>) -> Vec<Finding> {
    let mut v = m.into_inner().unwrap_or_else(|e| e.into_inner());
    v.sort_by(|(sa, a), (sb, b)| a.id.cmp(&b.id).then(sa.cmp(sb)).then(a.run.cmp(&b.run)));
    v.into_iter().map(|(_, f)| f).collect()
}

fn run_cached(app: &App, store: &RunStore, spec: &RunSpec) -> Result<RunRecord> {
    if let Some(r) = store.get(&spec.id())? {
        return Ok(r);
    }
    let r = app.run(spec);
    store.save(&r)?;
    Ok(r)
}

fn build_spec(app: &App, export: Option<&str>, a: &SpecArgs) -> Result<RunSpec> {
    let export = match export {
        Some(e) => app.export(e)?,
        None => app.default_export()?,
    }
    .clone();
    let now = a.now.clone().unwrap_or_else(|| app.manifest.start_time());
    let args = if let Some(s) = &a.args {
        match parse_json_arg(s)? {
            Value::Array(v) => v,
            _ => bail!("--args must be a JSON array"),
        }
    } else if let Some(s) = &a.request {
        vec![parse_json_arg(s)?]
    } else {
        let mut args = app.default_args(&export, &now)?;
        for s in &a.set {
            let patch = parse_json_arg(s)?;
            if let Some(first) = args.first_mut() {
                merge(first, patch);
            }
        }
        args
    };
    let plan = match &a.plan {
        None => Plan::default(),
        Some(s) if s.trim_start().starts_with('{') => Plan::parse(s)?,
        Some(s) => Plan::load(Path::new(s))?,
    };
    let mut spec = app.spec(&export, args, plan, a.seed);
    spec.now = now;
    if let Some(f) = a.fuel {
        spec.fuel = f;
    }
    Ok(spec)
}

fn merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                merge(b.entry(k).or_insert(Value::Null), v);
            }
        }
        (b, p) => *b = p,
    }
}

fn ms(ns: u64) -> f64 {
    (ns as f64 / 1e4).round() / 100.0
}

fn summary(app: &App, r: &RunRecord) -> Value {
    let l = &app.manifest.limits;
    let t = &r.totals;
    let mut over = Vec::new();
    if t.fuel > l.fuel {
        over.push(json!({"limit": "fuel", "used": t.fuel, "limit_value": l.fuel}));
    }
    if t.peak_memory > l.memory {
        over.push(json!({"limit": "memory", "used": t.peak_memory, "limit_value": l.memory}));
    }
    if let Some(c) = l.cost_per_request
        && t.cost > c
    {
        over.push(json!({"limit": "cost_per_request", "used": t.cost, "limit_value": c}));
    }
    if let Some(m) = l.max_latency_ms
        && ms(t.virtual_ns) > m
    {
        over.push(json!({"limit": "max_latency_ms", "used": ms(t.virtual_ns), "limit_value": m}));
    }
    let mut out = json!({
        "run": r.id,
        "export": r.spec.export,
        "outcome": r.outcome,
        "result": r.result,
        "totals": {
            "fuel": t.fuel,
            "peak_memory": t.peak_memory,
            "virtual_ms": ms(t.virtual_ns),
            "guest_ms": ms(t.guest_ns),
            "host_ms": ms(t.host_ns),
            "sleep_ms": ms(t.sleep_ns),
            "host_calls": t.host_calls,
            "cost": t.cost,
            "clock_reads": t.clock_reads,
            "random_bytes": t.random_bytes,
        },
        "calls_per_function": r.call_counts().into_iter().map(|(k, n)| (k, json!(n))).collect::<Map<_, _>>(),
        "over_limits": over,
    });
    if !r.stdout.is_empty() || !r.stderr.is_empty() {
        out["output_bytes"] = json!({"stdout": r.stdout.len(), "stderr": r.stderr.len()});
    }
    if r.events.iter().any(|e| !e.granted) {
        let ungranted: Vec<&str> = r.events.iter().filter(|e| !e.granted).map(|e| e.func.as_str()).collect();
        out["ungranted_calls"] = json!(ungranted);
    }
    out
}

fn finding_json(f: &Finding) -> Value {
    let mut o = json!({"id": f.id, "severity": f.severity, "kind": f.kind, "title": f.title, "evidence": f.evidence(), "experimental": f.experimental()});
    if let Some(r) = &f.run {
        o["run"] = json!(r);
    }
    if let Some(c) = &f.confirmed {
        o["case"] = json!(c);
    }
    // A finding without a run (statics) points at the code instead.
    if let Some(l) = f.detail.get("look") {
        o["look"] = l.clone();
    }
    o
}

/// Stores findings and returns them (deduplicated), marking the new ones.
fn record_findings(cli: &Cli, app: &App, found: Vec<Finding>) -> Result<Value> {
    let mut seen = std::collections::BTreeSet::new();
    let mut found: Vec<Finding> = found.into_iter().filter(|f| seen.insert(f.id.clone())).collect();
    found.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
    let new = FindingStore::new(&cli.state, &app.state_key).add(&found)?;
    Ok(Value::Array(
        found
            .iter()
            .map(|f| {
                let mut o = finding_json(f);
                o["novel"] = json!(new.contains(&f.id));
                o
            })
            .collect(),
    ))
}

fn scale_table(rep: &scale::ScaleReport) -> Value {
    let metrics: Vec<&str> = rep.growth.iter().map(|g| g.metric.as_str()).collect();
    Value::Array(
        rep.points
            .iter()
            .map(|p| {
                let mut o = json!({"n": p.n, "outcome": p.outcome, "host_calls": p.host_calls, "cost": p.cost, "virtual_ms": p.virtual_ms, "fuel": p.fuel, "run": p.run});
                for m in &metrics {
                    if let Some(f) = m.strip_prefix("calls ") {
                        o[*m] = json!(p.calls.get(f).copied().unwrap_or(0));
                    }
                }
                o
            })
            .collect(),
    )
}

fn blake3_hex(bytes: &[u8]) -> String {
    appfuzz_core::harness::component_hash(bytes)
}

fn statics_for(cli: &Cli) -> Result<Statics> {
    let m = load_manifest(cli)?;
    Statics::parse(&std::fs::read(m.wasm_path()).with_context(|| format!("reading {}", m.wasm_path().display()))?)
}

fn timeline(r: &RunRecord, st: &Statics) -> Value {
    Value::Array(
        r.events
            .iter()
            .map(|e| {
                let mut o = json!({
                    "n": e.n, "t_ms": ms(e.t_ns), "func": e.func, "args": e.args,
                    "latency_ms": ms(e.latency_ns), "cost": e.cost, "source": e.source,
                });
                match (&e.result, &e.trap) {
                    (_, Some(t)) => o["trap"] = json!(t),
                    (Some(v), None) => o["result"] = v.clone(),
                    _ => {}
                }
                let chain: Vec<String> = e
                    .stack
                    .iter()
                    .filter(|f| st.module(&f.module).is_none_or(|m| m.role == "main" || m.role == "other"))
                    .take(3)
                    .map(|f| st.frame_name(f))
                    .collect();
                if !chain.is_empty() {
                    o["from"] = json!(chain.join(" < "));
                }
                o
            })
            .collect(),
    )
}

fn by_function(r: &RunRecord, only: Option<&str>) -> Value {
    let mut out = Map::new();
    for (k, n) in r.call_counts() {
        if only.is_some_and(|o| !k.contains(o)) {
            continue;
        }
        let calls: Vec<&_> = r.events.iter().filter(|e| e.func == k).collect();
        let args: Vec<Value> = calls.iter().map(|e| Value::Object(e.args.clone())).collect();
        let mut distinct = args.clone();
        distinct.sort_by_key(|v| v.to_string());
        distinct.dedup();
        out.insert(
            k,
            json!({
                "calls": n,
                "distinct_args": distinct.len(),
                "cost": calls.iter().map(|e| e.cost).sum::<u64>(),
                "latency_ms": ms(calls.iter().map(|e| e.latency_ns).sum()),
                "args": args,
            }),
        );
    }
    Value::Object(out)
}

fn inspect(app: &App, with_wit: bool) -> Result<Value> {
    let m = &app.manifest;
    let imports: Vec<Value> = app
        .imports
        .iter()
        .filter(|i| !i.funcs.is_empty())
        .map(|i| {
            let granted = match i.kind {
                ImportKind::Platform => i.name.is_empty() || m.grants_import(&i.name),
                ImportKind::Wasi => m.grants_wasi(&i.name),
            };
            let funcs: Vec<Value> = i
                .funcs
                .iter()
                .map(|f| {
                    let mut o = json!({"key": f.key, "sig": f.signature()});
                    if i.kind == ImportKind::Platform {
                        o["cost"] = json!(m.cost_of(&f.key));
                        o["latency_ms"] = json!(m.latency_ms_of(&f.key));
                        if let Some(l) = labels_json(m, &f.key) {
                            o["labels"] = l;
                        }
                        if let Some(s)=m.function(&f.key).filter(|s|!s.param_values.is_empty()) {
                            o["param_values"]=json!(s.param_values);
                            o["value_source"]=json!(s.value_source);
                        }
                    }
                    o
                })
                .collect();
            json!({"interface": i.name, "kind": i.kind, "granted": granted, "funcs": funcs})
        })
        .collect();
    let imported: Vec<String> =
        app.imports.iter().map(|i| appfuzz_core::manifest::strip_version(&i.name).to_string()).collect();
    let unused_grants: Vec<&String> = m
        .grants
        .imports
        .iter()
        .flatten()
        .filter(|g| !imported.iter().any(|i| i == appfuzz_core::manifest::strip_version(g)))
        .collect();
    let ungranted: Vec<&str> = app
        .imports
        .iter()
        .filter(|i| !i.funcs.is_empty())
        .filter(|i| match i.kind {
            ImportKind::Platform => !i.name.is_empty() && !m.grants_import(&i.name),
            ImportKind::Wasi => !m.grants_wasi(&i.name),
        })
        .map(|i| i.name.as_str())
        .collect();
    let mut out = json!({
        "app": {"name": m.app.name, "wasm": m.wasm_path(), "component": app.hash, "bytes": app.bytes.len()},
        "exports": app.exports.iter().map(|f| json!({"key": f.key, "sig": f.signature()})).collect::<Vec<_>>(),
        "imports": imports,
        "ungranted_imports": ungranted,
        "unused_grants": unused_grants,
        "entry": m.entry.as_ref().map(|e| &e.export),
        "limits": m.limits,
    });
    let guess: appfuzz_core::labels::Suggestions = appfuzz_core::labels::suggest(&app.imports)
        .into_iter()
        .filter_map(|(k, s)| s.without(m.function(&k)).map(|s| (k, s)))
        .collect();
    if !guess.is_empty() {
        out["label_suggestions"] = json!({
            "note": "a guess from WIT names, not checked: keep what is true, then add it to appfuzz.toml",
            "toml": appfuzz_core::labels::suggest_toml(&guess),
        });
    }
    if with_wit {
        out["wit"] = json!(wit::wit_text(&app.bytes));
    }
    Ok(out)
}

/// A host function's labels from the manifest, as JSON.
fn labels_json(m: &appfuzz_core::manifest::Manifest, key: &str) -> Option<Value> {
    let f = m.function(key)?;
    if f.params.is_empty() && f.result.is_none() && f.effect.is_none() && f.batch_of.is_none() && f.values.is_empty() {
        return None;
    }
    let mut o = json!({});
    if !f.params.is_empty() {
        o["params"] = json!(f.params);
    }
    if let Some(r) = &f.result {
        o["result"] = json!(r);
    }
    if let Some(e) = f.effect {
        o["effect"] = json!(e);
        o["idempotent"] = json!(f.idempotent);
    }
    if let Some(b) = &f.batch_of {
        o["batch_of"] = json!(b);
    }
    if !f.values.is_empty() {
        o["values"] = json!(f.values);
    }
    Some(o)
}

fn plan_template(app: &App) -> Result<Value> {
    let mut plan = Map::new();
    plan.insert("_defaults".into(), json!({"generate": {"list_len": 2}}));
    let mut g = Generator::new(1, Default::default());
    for i in app.imports.iter().filter(|i| i.kind == ImportKind::Platform) {
        for f in &i.funcs {
            let results: Vec<_> = f.ty.results().collect();
            let example = match results.as_slice() {
                [] => Value::Null,
                [one] => g.gen_json(one),
                many => Value::Array(many.iter().map(|t| g.gen_json(t)).collect()),
            };
            let mut o = json!({"_sig": f.signature(), "_example": example});
            if let Some(q) = app.manifest.function(&f.key).and_then(|s| s.query.as_ref()) { o["_query"] = serde_json::to_value(q)?; }
            if let Some(m) = app.manifest.function(&f.key).and_then(|s| s.mutation.as_ref()) { o["_mutation"] = serde_json::to_value(m)?; }
            if let Some(l) = labels_json(&app.manifest, &f.key) {
                o["_labels"] = l;
            }
            plan.insert(f.key.clone(), o);
        }
    }
    Ok(Value::Object(plan))
}

fn strip_wall(mut v: Value) -> Value {
    if let Some(t) = v.get_mut("totals").and_then(Value::as_object_mut) {
        t.remove("wall_us");
    }
    v
}

fn diff(a: &Value, b: &Value, path: String, out: &mut Vec<Value>) {
    if out.len() >= 20 {
        return;
    }
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for k in x.keys().chain(y.keys().filter(|k| !x.contains_key(*k))) {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                diff(x.get(k).unwrap_or(&Value::Null), y.get(k).unwrap_or(&Value::Null), p, out);
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                diff(p, q, format!("{path}[{i}]"), out);
            }
        }
        _ if a != b => out.push(json!({"path": path, "before": a, "after": b})),
        _ => {}
    }
}

/// `90s`, `5m`, `500ms`, or seconds.
fn parse_duration(s: &str) -> Result<std::time::Duration> {
    let s = s.trim();
    let (n, unit) = s.find(|c: char| !c.is_ascii_digit() && c != '.').map(|i| s.split_at(i)).unwrap_or((s, "s"));
    let n: f64 = n.parse().with_context(|| format!("bad duration {s:?}"))?;
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" | "" => n,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        u => bail!("bad duration unit {u:?} (ms, s, m, h)"),
    };
    if !secs.is_finite() || secs <= 0.0 { bail!("duration must be positive and finite"); }
    std::time::Duration::try_from_secs_f64(secs).context("duration is too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_a_doc_and_every_doc_a_command() {
        let cmds: Vec<String> = commands(&command(), "").into_iter().map(|(p, _)| p).collect();
        for c in &cmds {
            assert!(guide::doc(c).is_some(), "no guide::DOCS entry for `{c}`");
        }
        for d in guide::DOCS {
            assert!(cmds.contains(&d.path.to_string()), "guide::DOCS has `{}`, which is no command", d.path);
        }
    }

    #[test]
    fn every_example_parses() {
        let all = guide::DOCS.iter().flat_map(|d| d.examples.iter()).chain(guide::WORKFLOWS.iter().flat_map(|(_, s)| s.iter()));
        for e in all {
            // Placeholders stand for ids.
            let e = e.replace("<finding id>", "f1").replace("<run a>", "r1").replace("<run b>", "r2").replace("<run>", "r1").replace("<n>", "3");
            let e = e.replace("<first different call>", "3").replace("<host fn>", "x").replace("<key>", "k").replace("<hinted value>", "v");
            let words = guide::words(e.trim_end_matches(" > plan.json"));
            let m = command().try_get_matches_from(&words).unwrap_or_else(|err| panic!("example `{e}` does not parse: {err}"));
            Cli::from_arg_matches(&m).unwrap();
        }
    }

    #[test]
    fn short_about_lines() {
        for (p, about) in commands(&command(), "") {
            assert!(!about.is_empty() && about.len() <= 80, "`{p}`: about should be one short line, is {about:?}");
        }
    }
}
