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

#[derive(Parser)]
#[command(name = "appfuzz", version, about = "Fuzz sandboxed WebAssembly components for bad patterns. Output is JSON.")]
struct Cli {
    /// The manifest (default: ./appfuzz.toml if it exists).
    #[arg(short, long, global = true)]
    manifest: Option<PathBuf>,
    /// A component to use without a manifest (or instead of its [app] wasm).
    #[arg(long, global = true)]
    wasm: Option<PathBuf>,
    /// Where runs are kept.
    #[arg(long, global = true, default_value = ".appfuzz")]
    state: PathBuf,
    /// Do not shorten long strings and lists in the output.
    #[arg(long, global = true)]
    full: bool,
    /// Runs at once (default: one per CPU). Each run may use up to four
    /// times the manifest's memory limit.
    #[arg(short, long, global = true)]
    jobs: Option<usize>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Everything in one go: a verdict, confirmed findings, exit code 0/1/2.
    ///
    /// Runs inspect, run, probe values, probe times, amplify and a
    /// time-boxed fuzz (with pair checks), confirms the worst findings, and
    /// reports coverage and the domains the output refers to. Exit code 0:
    /// pass, 1: warn findings, 2: fail findings (or an error).
    Review {
        /// How long to fuzz (`90s`, `5m`).
        #[arg(long, default_value = "60s")]
        time: String,
        #[arg(long, default_value_t = 1)]
        rng: u64,
        /// Start fuzzing from the example request, not the stored corpus.
        #[arg(long)]
        fresh: bool,
        /// Most findings to confirm (worst first).
        #[arg(long, default_value_t = 10)]
        confirm: usize,
        /// Findings to list: info, warn, fail (counts include all).
        #[arg(long, default_value = "warn")]
        min: String,
    },
    /// What the component imports and exports, and what the manifest grants.
    Inspect {
        /// Also print the component's world as WIT.
        #[arg(long)]
        wit: bool,
    },
    /// Host plan helpers.
    Plan {
        #[command(subcommand)]
        cmd: PlanCmd,
    },
    /// Run an export once and summarize what it did.
    Run(RunArgs),
    /// Run an export and list every host call it made.
    ///
    /// Each call with arguments, result, latency, cost and the app function
    /// that made it.
    Call(RunArgs),
    /// A stored run, whole (or one field of it with --field).
    Show {
        #[arg(default_value = "last")]
        run: String,
        /// Dot path into the record, e.g. `totals` or `result.body`.
        #[arg(long)]
        field: Option<String>,
    },
    /// Host calls of a stored run in order, one line each.
    Timeline {
        #[arg(default_value = "last")]
        run: String,
    },
    /// Host calls of a stored run grouped by function, with all arguments.
    Calls {
        #[arg(default_value = "last")]
        run: String,
        /// Only this function (substring of `interface#function`).
        #[arg(long)]
        func: Option<String>,
    },
    /// Which guest code made host call N of a run.
    Why {
        run: String,
        n: u32,
    },
    /// What the app wrote to stdout and stderr in a run.
    Stdout {
        #[arg(default_value = "last")]
        run: String,
    },
    /// Run a stored run (or a `confirm` case file) again; did anything change?
    Replay {
        #[arg(default_value = "last")]
        run: String,
    },
    /// Stored runs.
    Runs,
    /// Turn one knob through sizes and fit growth laws.
    ///
    /// Measures calls per host function, cost, time, fuel, memory, output.
    /// Knobs: `fn:<host fn>` (length of the list it returns),
    /// `field:<path>` (request field = n), `len:<path>` (request field of n
    /// characters).
    Scale {
        knob: String,
        /// Comma-separated sizes (default 1,2,4,8,16,32; lengths 16…4096).
        #[arg(long, value_delimiter = ',')]
        sizes: Vec<u64>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
        /// Include every measured point.
        #[arg(long)]
        points: bool,
    },
    /// Find inputs that drive up calls to each host function.
    ///
    /// Grows host lists, request fields, and request keys found in the
    /// binary; reports fan-out per function and nested fan-out.
    Amplify {
        /// Only host functions matching this.
        #[arg(long = "fn")]
        func: Option<String>,
        /// How many words from the binary to try as request keys.
        #[arg(long, default_value_t = 200)]
        dict: usize,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Targeted questions: odd host values, clock edges, one-change pairs.
    Probe {
        #[command(subcommand)]
        cmd: ProbeCmd,
    },
    /// Every URL the output refers to, with the domains behind them.
    Urls {
        /// Only this run (default: every stored run of this component).
        #[arg(long)]
        run: Option<String>,
        /// Only the domain list.
        #[arg(long)]
        domains: bool,
    },
    /// Coverage-guided campaign running every detector on every run.
    ///
    /// Mutates requests, host values, list sizes, faults, clock and seed,
    /// follows the app's own links and forms, and checks kept runs with
    /// one-change pairs. The corpus is kept in the state directory and
    /// resumed next time.
    Fuzz {
        /// Stop after this many runs.
        #[arg(long)]
        runs: Option<u64>,
        /// Stop after this long (`90s`, `5m`, `500ms`).
        #[arg(long, default_value = "60s")]
        time: String,
        /// Stop early: `new-finding` or `plateau` (nothing new for
        /// --plateau runs).
        #[arg(long, default_value = "budget")]
        until: String,
        #[arg(long, default_value_t = 2000)]
        plateau: u64,
        /// Seed of the fuzzer's own choices.
        #[arg(long, default_value_t = 1)]
        rng: u64,
        /// Start from the example request only, not the stored corpus.
        #[arg(long)]
        fresh: bool,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Make a finding reproducible and small, and write a case file.
    ///
    /// Replays the finding's run N times (it must give the same record),
    /// shrinks its input while the finding still shows.
    Confirm {
        /// A finding id (`f…`) or a run id.
        target: String,
        /// With a run id: which of its findings (default: the worst).
        #[arg(long)]
        finding: Option<String>,
        #[arg(short = 'n', long, default_value_t = 3)]
        times: u32,
        /// Most runs to spend on shrinking.
        #[arg(long, default_value_t = 400)]
        max_runs: u32,
    },
    /// Fuzz until a run breaks a property, then shrink it to a counterexample.
    ///
    /// Properties: `value_range <selector> <lo> <hi>`
    /// (selector `.class`, `#id`, `tag`, `$.field`, `/regex/`),
    /// `max_calls <fn> <n>`, `no_crash`, `not_contains <regex>`,
    /// `max <metric> <n>` (fuel, memory, host_calls, virtual_ms, cost,
    /// output_bytes, clock_reads). Stored runs are checked first.
    Check {
        /// The property, as words: `value_range .usage 0 100`.
        #[arg(required = true, num_args = 1.., allow_negative_numbers = true)]
        property: Vec<String>,
        #[arg(long)]
        runs: Option<u64>,
        #[arg(long, default_value = "60s")]
        time: String,
        #[arg(long, default_value_t = 1)]
        rng: u64,
        /// Runs spent shrinking the counterexample.
        #[arg(long, default_value_t = 300)]
        max_runs: u32,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// One run per value of a request field, side by side.
    ///
    /// Outcome, status, calls, text and findings per value; values that
    /// behave alike are grouped.
    Sweep {
        /// The request field (`query.days`, `today`).
        #[arg(short = 'f', long)]
        field: String,
        /// Values to try: numbers, dates, times, strings, words (from the
        /// binary), lengths.
        #[arg(long, default_value = "numbers")]
        r#gen: String,
        /// Exactly these values, comma separated (instead of --gen).
        #[arg(long, value_delimiter = ',')]
        values: Vec<String>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// What differs between two stored runs.
    ///
    /// Input, outcome, totals, calls per function, the first host call that
    /// differs, the output.
    Diff { a: String, b: String },
    /// Where the arguments of host call N came from.
    ///
    /// A request field (equal, contained, a date offset), an earlier host
    /// result, a constant in the binary. Heuristic.
    Provenance {
        run: String,
        #[arg(long)]
        call: u32,
    },
    /// Where the guest spends fuel, per function.
    ///
    /// Instructions between host calls, per function (self and inclusive),
    /// and after the last host call.
    Profile {
        run: String,
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// A run in plain terms, compared with the median stored run.
    Explain { run: String },
    /// Host call sites no stored run reached, with hints to get there.
    ///
    /// Texts and numbers of the function and its callers that may lead
    /// there.
    Unexplored,
    /// WASI imports and how stored runs used clock, random, sleep, output.
    Wasi,
    /// Findings so far for this component.
    Findings {
        /// Minimum severity: info, warn, fail.
        #[arg(long, default_value = "info")]
        min: String,
    },
    /// What the reviewed app was seen to do, for a platform to enforce.
    ///
    /// Writes envelope.json from every stored run of this component: per
    /// host function the most calls, call sites and destinations; the
    /// destinations the output fires requests to; scripts; the most fuel,
    /// cost, latency and memory. `envelope check` holds a trace to it.
    Envelope {
        #[command(subcommand)]
        cmd: Option<EnvelopeCmd>,
        /// Where to write the envelope.
        #[arg(long, default_value = "envelope.json")]
        out: PathBuf,
    },
    /// Static views of the code: functions, call graph, loops, strings.
    Wasm {
        #[command(subcommand)]
        cmd: wasm_cmd::WasmCmd,
    },
}

#[derive(Subcommand)]
enum ProbeCmd {
    /// Runs at calendar and clock edges (leap day, year end, DST, 2038).
    Times {
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// The run again with one thing changed; what changed in the answer?
    ///
    /// Every host result is pinned; one variant each reverses a list, adds
    /// a duplicate, changes the random seed or the wall clock, fails one
    /// call, or slows one function.
    Pairs {
        /// A stored run (default: run the request given below).
        run: Option<String>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Every kind of value each host function may return.
    Values {
        /// Only host functions matching this.
        #[arg(long = "fn")]
        func: Option<String>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
}

#[derive(Subcommand)]
enum EnvelopeCmd {
    /// A trace against the envelope: outside_envelope findings, exit code 0/1/2.
    ///
    /// The trace is a stored run (`last`, an id) or a JSON file: a run
    /// record, or {export, args, events: [{func, args, result, stack}],
    /// result, stdout, stderr, totals} (see ENVELOPE.md).
    Check {
        trace: String,
        #[arg(long, default_value = "envelope.json")]
        envelope: PathBuf,
    },
}

#[derive(Subcommand)]
enum PlanCmd {
    /// A plan with every host function, its signature and an example value.
    Template,
}

#[derive(clap::Args, Clone)]
struct RunArgs {
    /// The export (`interface#function`); default: [entry] export.
    export: Option<String>,
    #[command(flatten)]
    spec: SpecArgs,
}

#[derive(clap::Args, Clone)]
struct SpecArgs {
    /// Arguments as a JSON array, one per parameter.
    #[arg(long, conflicts_with = "request")]
    args: Option<String>,
    /// The single argument as JSON (for one-parameter exports).
    #[arg(long)]
    request: Option<String>,
    /// JSON merged into the default request (from the manifest).
    #[arg(long, conflicts_with_all = ["args", "request"])]
    set: Vec<String>,
    /// Host plan: a file, or inline JSON.
    #[arg(long)]
    plan: Option<String>,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Virtual start time, `YYYY-MM-DDTHH:MM:SS`.
    #[arg(long)]
    now: Option<String>,
    /// Fuel for the run (default: 5× the production limit).
    #[arg(long)]
    fuel: Option<u64>,
}

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
            std::process::exit(2);
        }
    };
    let path = cmd_path(&matches);
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let full = cli.full;
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
            let mut o = json!({"error": format!("{e:#}")});
            if let Some(d) = guide::doc(&path) {
                o["examples"] = json!(d.examples);
            }
            println!("{}", serde_json::to_string_pretty(&o).expect("json"));
            std::process::exit(2);
        }
    };
    if !path.is_empty()
        && let Value::Object(o) = &mut out
        && !o.contains_key("next")
    {
        let n = guide::next(&path, &Value::Object(o.clone()));
        o.insert("next".into(), json!(n));
    }
    let code = if path == "review" || path == "envelope check" { out["exit_code"].as_i64().unwrap_or(0) as i32 } else { 0 };
    let out = if full { out } else { shorten(out) };
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
    let runs: Vec<RunRecord> = RunStore::new(&cli.state).all().unwrap_or_default().into_iter().filter(|r| r.spec.component == hash).collect();
    let findings = FindingStore::new(&cli.state, &hash).all();
    let corpus = fuzz::Corpus::load(&cli.state, &hash).entries.len();
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

fn run(cli: Cli) -> Result<Value> {
    let store = RunStore::new(&cli.state);
    let Some(cmd) = &cli.cmd else { bail!("no command") };
    match cmd {
        Cmd::Review { time, rng, fresh, confirm, min } => {
            parse_duration(time)?;
            review::review(&cli, &review::Opts { time: time.clone(), rng: *rng, fresh: *fresh, confirm: *confirm, min: severity(min) })
        }
        Cmd::Inspect { wit } => {
            let app = App::load(load_manifest(&cli)?)?;
            let mut out = inspect(&app, *wit)?;
            let st = Statics::parse(&app.bytes)?;
            out["findings"] = record_findings(&cli, &app, detect::static_findings(&app.manifest, &app.imports, &st))?;
            Ok(out)
        }
        Cmd::Plan { cmd: PlanCmd::Template } => plan_template(&App::load(load_manifest(&cli)?)?),
        Cmd::Run(a) => {
            let app = App::load(load_manifest(&cli)?)?;
            let r = execute(&app, &store, a)?;
            let mut s = summary(&app, &r);
            s["findings"] = record_findings(&cli, &app, detect::per_run(&r, &app.manifest))?;
            Ok(s)
        }
        Cmd::Call(a) => {
            let app = App::load(load_manifest(&cli)?)?;
            let r = execute(&app, &store, a)?;
            let mut s = summary(&app, &r);
            s["findings"] = record_findings(&cli, &app, detect::per_run(&r, &app.manifest))?;
            s["host_calls"] = timeline(&r, &Statics::parse(&app.bytes)?);
            Ok(s)
        }
        Cmd::Show { run, field } => {
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
        Cmd::Replay { run } if run.ends_with(".json") && Path::new(run).exists() => {
            let case: Value = serde_json::from_slice(&std::fs::read(run)?)?;
            let spec: RunSpec = serde_json::from_value(case["spec"].clone()).context("case file has no spec")?;
            let fid = case["finding"]["id"].as_str().unwrap_or_default().to_string();
            let app = App::load(load_manifest(&cli)?)?;
            let r = app.run(&spec);
            store.save(&r)?;
            let shows = detect::per_run(&r, &app.manifest).iter().any(|f| f.id == fid);
            Ok(json!({"case": run, "finding": fid, "run": r.id, "outcome": r.outcome.kind, "reproduced": shows || case["per_run"] == json!(false)}))
        }
        Cmd::Replay { run } => {
            let old = store.load(run)?;
            let app = App::load(load_manifest(&cli)?)?;
            let new = app.run(&old.spec);
            let mut diffs = Vec::new();
            let a = strip_wall(serde_json::to_value(&old)?);
            let b = strip_wall(serde_json::to_value(&new)?);
            diff(&a, &b, String::new(), &mut diffs);
            Ok(json!({"run": old.id, "same": diffs.is_empty(), "differences": diffs}))
        }
        Cmd::Scale { knob, sizes, export, spec, points } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let base = RunSpec { plan: scale::steady(&base.plan), ..base };
            let knob = Knob::parse(knob)?;
            let sizes = if sizes.is_empty() { scale::default_sizes(&knob) } else { sizes.clone() };
            let per_run = Mutex::new(Vec::new());
            let runner = |s: &RunSpec| {
                let r = run_cached(&app, &store, s).unwrap_or_else(|_| app.run(s));
                lock(&per_run).extend(detect::per_run(&r, &app.manifest).into_iter().map(|f| ((r.totals.host_calls, r.totals.fuel), f)));
                r
            };
            let rep = scale::scale(&app, &base, knob, &sizes, &runner)?;
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
            out["findings"] = record_findings(&cli, &app, found)?;
            Ok(out)
        }
        Cmd::Amplify { func, dict, export, spec } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let per_run = Mutex::new(Vec::new());
            let runner = |s: &RunSpec| {
                let r = app.run(s);
                lock(&per_run).extend(detect::per_run(&r, &app.manifest).into_iter().map(|f| ((r.totals.host_calls, r.totals.fuel), f)));
                let _ = store.save(&r);
                r
            };
            let rep = scale::amplify(&app, &base, func.as_deref(), *dict, &runner)?;
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
                "findings": record_findings(&cli, &app, found)?,
            }))
        }
        Cmd::Probe { cmd: ProbeCmd::Values { func, export, spec } } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let runner = |s: &RunSpec| run_cached(&app, &store, s).unwrap_or_else(|_| app.run(s));
            let (probes, found) = appfuzz_core::probe::values(&app, &base, func.as_deref(), &runner);
            let failed: Vec<Value> = probes
                .iter()
                .filter(|p| p.outcome != appfuzz_core::record::OutcomeKind::Ok)
                .map(|p| json!({"func": p.func, "variant": p.variant, "outcome": p.outcome, "run": p.run}))
                .collect();
            Ok(json!({"probes": probes.len(), "not_ok": failed, "findings": record_findings(&cli, &app, found)?}))
        }
        Cmd::Probe { cmd: ProbeCmd::Pairs { run, export, spec } } => {
            let app = App::load(load_manifest(&cli)?)?;
            let runner = |s: &RunSpec| run_cached(&app, &store, s).unwrap_or_else(|_| app.run(s));
            let base = match run {
                Some(id) => store.load(id)?,
                None => runner(&build_spec(&app, export.as_deref(), spec)?),
            };
            if base.outcome.kind != appfuzz_core::record::OutcomeKind::Ok {
                anyhow::bail!("run {} did not end ok ({:?}); pairs need an ok run", base.id, base.outcome.kind);
            }
            if appfuzz_core::metamorphic::pinned(&base).is_none() {
                anyhow::bail!("run {} has host results too long to replay; pairs need every result in full", base.id);
            }
            let (_, lines, found) = appfuzz_core::metamorphic::pairs(&app, &base, &runner);
            Ok(json!({"run": base.id, "pairs": lines, "findings": record_findings(&cli, &app, found)?}))
        }
        Cmd::Probe { cmd: ProbeCmd::Times { export, spec } } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let runner = |s: &RunSpec| run_cached(&app, &store, s).unwrap_or_else(|_| app.run(s));
            let (probes, found) = appfuzz_core::probe::times(&app, &base, &runner);
            let failed: Vec<Value> = probes
                .iter()
                .filter(|p| p.outcome != appfuzz_core::record::OutcomeKind::Ok)
                .map(|p| json!({"now": p.now, "what": p.what, "outcome": p.outcome, "run": p.run}))
                .collect();
            Ok(json!({"probes": probes.len(), "not_ok": failed, "findings": record_findings(&cli, &app, found)?}))
        }
        Cmd::Envelope { cmd: None, out } => {
            let app = App::load(load_manifest(&cli)?)?;
            let runs: Vec<RunRecord> = store.all()?.into_iter().filter(|r| r.spec.component == app.hash).collect();
            if runs.is_empty() {
                anyhow::bail!("no stored runs of this component; run `review` first");
            }
            let mut env = appfuzz_core::envelope::Envelope::build(&runs, &app.manifest);
            env.unreached = dig::unexplored(&app, &store)?.0["sites"]
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
                "envelope": out, "runs": env.runs, "functions": functions, "output": env.output, "budget": env.budget,
                "unreached": env.unreached.len(),
            }))
        }
        Cmd::Envelope { cmd: Some(EnvelopeCmd::Check { trace, envelope }), .. } => {
            let m = load_manifest(&cli)?;
            let env: appfuzz_core::envelope::Envelope = serde_json::from_str(&std::fs::read_to_string(envelope).with_context(|| format!("reading {}", envelope.display()))?)
                .with_context(|| format!("parsing {}", envelope.display()))?;
            let r = match store.load(trace) {
                Ok(r) => r,
                Err(_) => {
                    let v = parse_json_arg(trace)?;
                    match serde_json::from_value::<RunRecord>(v.clone()) {
                        Ok(r) => r,
                        Err(_) => serde_json::from_value::<appfuzz_core::envelope::Trace>(v).context("not a trace")?.to_record(),
                    }
                }
            };
            let mut findings = env.check(&r, &m);
            findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
            let worst = findings.iter().map(|f| f.severity).max();
            let (verdict, code) = match worst {
                Some(Severity::Fail) => ("fail", 2),
                Some(Severity::Warn) => ("warn", 1),
                _ => ("pass", 0),
            };
            let mut o = json!({
                "trace": r.id, "verdict": verdict, "exit_code": code, "calls": r.events.len(),
                "findings": findings.iter().map(|f| { let mut o = finding_json(f); o["detail"] = f.detail.clone(); o }).collect::<Vec<_>>(),
            });
            if !r.spec.component.is_empty() && r.spec.component != env.component {
                o["note"] = json!("the trace comes from another build of the component than the envelope");
            }
            Ok(o)
        }
        Cmd::Urls { run, domains } => {
            let m = load_manifest(&cli)?;
            let runs = match run {
                Some(r) => vec![store.load(r)?],
                None => {
                    let hash = blake3_hex(&std::fs::read(m.wasm_path())?);
                    store.all()?.into_iter().filter(|r| r.spec.component == hash).collect()
                }
            };
            let mut inv = appfuzz_core::urls::inventory(&runs, &m);
            if *domains {
                inv.as_object_mut().map(|o| o.remove("urls"));
            }
            Ok(inv)
        }
        Cmd::Fuzz { runs, time, until, plateau, rng, fresh, export, spec } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let until = match until.as_str() {
                "budget" => fuzz::Until::Budget,
                "new-finding" => fuzz::Until::NewFinding,
                "plateau" => fuzz::Until::Plateau,
                u => bail!("--until must be budget, new-finding or plateau, not {u:?}"),
            };
            let opts = fuzz::FuzzOpts { runs: *runs, time: Some(parse_duration(time)?), until, seed: *rng, plateau: *plateau, ..Default::default() };
            let prior = if *fresh { vec![] } else { fuzz::Corpus::load(&cli.state, &app.hash).entries };
            let findings = FindingStore::new(&cli.state, &app.hash);
            let known = findings.all().into_iter().map(|f| f.id).collect();
            let save_err = Mutex::new(None);
            let on_run = |r: &RunRecord, kept: bool, found: &[Finding]| {
                if (kept || !found.is_empty())
                    && let Err(e) = store.save(r)
                {
                    *lock(&save_err) = Some(e);
                }
            };
            let (rep, corpus) = fuzz::fuzz(&app, &base, prior, known, &opts, &on_run)?;
            if let Some(e) = lock(&save_err).take() {
                return Err(e);
            }
            corpus.save(&cli.state)?;
            let maxima: Vec<Value> = rep.maxima.iter().map(|m| json!({"metric": m.metric, "max": m.value, "run": m.run})).collect();
            Ok(json!({
                "runs": rep.runs, "discovery_runs": rep.discovery_runs, "keys": rep.keys, "modes": rep.modes,
                "elapsed_ms": rep.elapsed_ms, "stopped": rep.stopped,
                "corpus": rep.corpus, "kept": rep.kept, "features": rep.features, "last_new_at_run": rep.last_new_at_run,
                "stages": rep.stages, "maxima": maxima, "jobs": rep.jobs,
                "findings": record_findings(&cli, &app, rep.findings)?,
            }))
        }
        Cmd::Confirm { target, finding, times, max_runs } => {
            let app = App::load(load_manifest(&cli)?)?;
            let fstore = FindingStore::new(&cli.state, &app.hash);
            let all = fstore.all();
            let (run_id, wanted) = match all.iter().find(|f| f.id == *target) {
                Some(f) => (f.run.clone().ok_or_else(|| anyhow!("finding {target} has no run"))?, Some(f.id.clone())),
                None => (target.clone(), finding.clone()),
            };
            let orig = store.load(&run_id)?;
            let shown = detect::per_run(&orig, &app.manifest);
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
            let per_run = shown.iter().any(|x| x.id == f.id);
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
            let across = across.zip(start).filter(|(a, s)| a.shows(&app, &f.id, s, &runner).is_some());
            let (from, spec, shrink_runs, min) = if per_run {
                let id = f.id.clone();
                let keeps = |r: &RunRecord| detect::per_run(r, &app.manifest).iter().any(|x| x.id == id);
                let (spec, n) = shrink::minimise(&app, &orig.spec, &base, &keeps, *max_runs, &runner);
                let min = app.run(&spec);
                store.save(&min)?;
                (orig.spec.clone(), spec, n, min.id)
            } else if let Some((a, start)) = &across {
                let per = a.runs_per_test();
                let (spec, n) = shrink::shrink(&app, start, &base, &|c| a.shows(&app, &f.id, c, &runner).is_some(), (*max_runs / per).max(1));
                // Once more, keeping the runs: the finding's run is one of them.
                let saving = |s: &RunSpec| {
                    let r = app.run(s);
                    let _ = store.save(&r);
                    r
                };
                let shown = a.shows(&app, &f.id, &spec, &saving);
                let run = shown.and_then(|x| x.run).unwrap_or_else(|| orig.id.clone());
                (start.clone(), spec, n * per, run)
            } else {
                (orig.spec.clone(), orig.spec.clone(), 0, orig.id.clone())
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
                "finding": f, "per_run": per_run, "spec": spec, "reproduce": reproduce, "original_run": orig.id, "run": min,
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
            let min = severity(min);
            let mut all: Vec<Finding> = FindingStore::new(&cli.state, &hash).all().into_iter().filter(|f| f.severity >= min).collect();
            all.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
            Ok(json!({"count": all.len(), "findings": all.iter().map(finding_json).collect::<Vec<_>>()}))
        }
        Cmd::Wasm { cmd } => {
            let m = load_manifest(&cli)?;
            let bytes = std::fs::read(m.wasm_path()).with_context(|| format!("reading {}", m.wasm_path().display()))?;
            let hash = blake3_hex(&bytes);
            let runs: Vec<RunRecord> = store.all()?.into_iter().filter(|r| r.spec.component == hash).collect();
            wasm_cmd::run(cmd, &bytes, &runs)
        }
        Cmd::Check { property, runs, time, rng, max_runs, export, spec } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let opts = fuzz::FuzzOpts { runs: *runs, time: Some(parse_duration(time)?), seed: *rng, ..Default::default() };
            dig::check(&cli, &app, &store, &base, property, opts, *max_runs)
        }
        Cmd::Sweep { field, r#gen, values, export, spec } => {
            let app = App::load(load_manifest(&cli)?)?;
            let base = build_spec(&app, export.as_deref(), spec)?;
            let values = if values.is_empty() { dig::sweep_values(r#gen, &Statics::parse(&app.bytes)?)? } else { values.clone() };
            dig::sweep(&cli, &app, &store, &base, field, values)
        }
        Cmd::Diff { a, b } => {
            let app = App::load(load_manifest(&cli)?)?;
            Ok(dig::diff_runs(&app, &store.load(a)?, &store.load(b)?))
        }
        Cmd::Provenance { run, call } => {
            let app = App::load(load_manifest(&cli)?)?;
            dig::provenance(&app, &store.load(run)?, *call)
        }
        Cmd::Profile { run, top } => {
            let app = App::load(load_manifest(&cli)?)?;
            dig::profile(&app, &store.load(run)?, *top)
        }
        Cmd::Explain { run } => {
            let app = App::load(load_manifest(&cli)?)?;
            dig::explain(&app, &store, &store.load(run)?)
        }
        Cmd::Unexplored => {
            let app = App::load(load_manifest(&cli)?)?;
            let (mut v, found) = dig::unexplored(&app, &store)?;
            v["findings"] = record_findings(&cli, &app, found)?;
            Ok(v)
        }
        Cmd::Wasi => dig::wasi(&App::load(load_manifest(&cli)?)?, &store),
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

fn severity(s: &str) -> Severity {
    match s {
        "fail" => Severity::Fail,
        "warn" => Severity::Warn,
        _ => Severity::Info,
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
    let spec = build_spec(app, a.export.as_deref(), &a.spec)?;
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
    let mut o = json!({"id": f.id, "severity": f.severity, "kind": f.kind, "title": f.title});
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
    let new = FindingStore::new(&cli.state, &app.hash).add(&found)?;
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
    Ok(std::time::Duration::from_secs_f64(secs))
}

const MAX_STR: usize = 500;
const MAX_LIST: usize = 50;

/// Shortens long strings and lists so output stays small; `--full` turns
/// this off.
fn shorten(v: Value) -> Value {
    match v {
        Value::String(s) if s.chars().count() > MAX_STR => {
            let head: String = s.chars().take(MAX_STR).collect();
            Value::String(format!("{head}…(+{} chars, --full)", s.chars().count() - MAX_STR))
        }
        Value::Array(a) if a.len() > MAX_LIST => {
            let n = a.len();
            let mut out: Vec<Value> = a.into_iter().take(MAX_LIST).map(shorten).collect();
            out.push(json!(format!("…(+{} more, --full)", n - MAX_LIST)));
            Value::Array(out)
        }
        Value::Array(a) => Value::Array(a.into_iter().map(shorten).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, x)| (k, shorten(x))).collect()),
        other => other,
    }
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
