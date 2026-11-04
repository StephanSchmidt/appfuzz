use super::*;

#[derive(Parser)]
#[command(name = "appfuzz", version, about = "Fuzz sandboxed WebAssembly components for bad patterns. Output is JSON; --human prints it for people.")]
pub(crate) struct Cli {
    /// The manifest (default: ./appfuzz.toml if it exists).
    #[arg(short, long, global = true)]
    pub(crate) manifest: Option<PathBuf>,
    /// A component to use without a manifest (or instead of its [app] wasm).
    /// An https:// URL is downloaded, with the manifest at the same URL
    /// ending in .toml instead of .wasm; `appfuzz <url>` reviews it.
    #[arg(long, global = true)]
    pub(crate) wasm: Option<PathBuf>,
    /// The component of a Spin app (`spin.toml`) to review, when it has
    /// more than one HTTP component.
    #[arg(long, global = true)]
    pub(crate) component: Option<String>,
    /// Print for a person, with colors, instead of JSON (also APPFUZZ_HUMAN=1).
    #[arg(long, global = true)]
    pub(crate) human: bool,
    /// Compatibility option: output is JSON unless --human.
    #[arg(long, global = true, hide = true)]
    pub(crate) json: bool,
    /// Also download plain http:// URLs.
    #[arg(long, global = true)]
    pub(crate) allow_http: bool,
    /// `--wasm` was a URL: use only its downloaded manifest, never ./appfuzz.toml.
    #[arg(skip)]
    pub(crate) remote: bool,
    /// Where runs are kept.
    #[arg(long, global = true, default_value = ".appfuzz")]
    pub(crate) state: PathBuf,
    /// Compatibility option: JSON output is always lossless.
    #[arg(long, global = true, hide = true)]
    pub(crate) full: bool,
    /// Runs at once (default: one per CPU). Each run may use up to four
    /// times the manifest's memory limit.
    #[arg(short, long, global = true)]
    pub(crate) jobs: Option<usize>,
    /// Skip work that slows runs and search: saved asserts are not judged
    /// per run (`acceptance run` and review's acceptance step still check them).
    #[arg(long, global = true)]
    pub(crate) fast: bool,
    #[command(subcommand)]
    pub(crate) cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Everything in one go: a verdict, confirmed findings, exit code 0/1/2/3.
    ///
    /// Runs inspect, run, the manifest's request sequences, probe values,
    /// probe times, probe web, amplify, a time-boxed fuzz (with pair
    /// checks), probe auth and the saved acceptance checks. It tries the
    /// failing inputs of earlier reviews again, confirms the worst
    /// findings, and reports coverage and the domains the output refers
    /// to. Exit code 0: pass, 1: warn findings, 2: fail findings, 3:
    /// incomplete/error.
    Review {
        /// Fuzzing time budget, excluding sequences, probes, scaling and confirmation.
        #[arg(long, default_value = "60s")]
        time: String,
        #[arg(long = "search-seed", visible_alias = "rng", default_value_t = 1)]
        rng: u64,
        /// Maximum fuzz evaluations; use -j 1 and --fresh for repeatable search.
        #[arg(long)]
        runs: Option<u64>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
        /// Start fuzzing from the example request, not the stored corpus.
        #[arg(long)]
        fresh: bool,
        /// Most findings to confirm (worst first).
        #[arg(long, default_value_t = 10)]
        confirm: usize,
        /// Findings to list: info, warn, fail (counts include all).
        #[arg(long, default_value = "warn")]
        min: String,
        /// Guide the fuzz phase by branches and comparisons inside the Wasm (slower).
        #[arg(long)]
        internal_feedback: bool,
    },
    /// Run, fuzz or replay requests sharing a simulated backend.
    Sequence {
        #[command(subcommand)]
        cmd: SequenceCmd,
    },
    /// Run saved acceptance requirements from the manifest.
    Acceptance {
        #[command(subcommand)]
        cmd: AcceptanceCmd,
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
    /// A platform's host API: reference for app authors, and checks.
    Platform {
        #[command(subcommand)]
        cmd: PlatformCmd,
    },
    /// Run an export once and summarize what it did.
    Run(RunArgs),
    /// Compatibility alias for `run --trace`.
    ///
    /// Each call with arguments, result, latency, cost and the app function
    /// that made it.
    #[command(hide = true)]
    Call(RunArgs),
    /// A stored run, whole (or one field of it with --field).
    Show {
        #[arg(default_value = "last")]
        run: String,
        /// Dot path into the record, e.g. `totals` or `result.body`.
        #[arg(long)]
        field: Option<String>,
        /// View: record, summary, calls, timeline, logs, stack, provenance, fuel, explanation.
        #[arg(long, default_value = "record", conflicts_with = "field")]
        view: String,
        /// Call number for stack and provenance views.
        #[arg(long)]
        call: Option<u32>,
        #[arg(long = "fn", visible_alias = "func")]
        func: Option<String>,
    },
    /// Host calls of a stored run in order, one line each.
    #[command(hide = true)]
    Timeline {
        #[arg(default_value = "last")]
        run: String,
    },
    /// Host calls of a stored run grouped by function, with all arguments.
    #[command(hide = true)]
    Calls {
        #[arg(default_value = "last")]
        run: String,
        /// Only this function (substring of `interface#function`).
        #[arg(long = "fn", visible_alias = "func")]
        func: Option<String>,
    },
    /// Which guest code made host call N of a run.
    #[command(hide = true)]
    Why { run: String, n: u32 },
    /// What the app wrote to stdout and stderr in a run.
    #[command(hide = true)]
    Stdout {
        #[arg(default_value = "last")]
        run: String,
    },
    /// Run a stored run (or a `confirm` case file) again; did anything change?
    Replay {
        #[arg(default_value = "last")]
        run: String,
        /// Regression check on the current build/contract: a case file, or a
        /// stored run whose findings are checked again.
        #[arg(long)]
        against_current: bool,
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
        #[arg(long = "fn", visible_alias = "func")]
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
    /// Behavior-guided campaign checking every valid run.
    ///
    /// Mutates requests, host values, list sizes, faults, clock and seed,
    /// follows the app's own links and forms, and checks kept runs with
    /// one-change pairs. The corpus is kept in the state directory and
    /// resumed next time.
    Fuzz {
        /// Guide the search by branches and comparisons inside the Wasm.
        ///
        /// Finds bugs behind computed or byte-by-byte comparisons whose values
        /// are not constants in the binary. Each successful run also executes
        /// an instrumented copy, so the search runs about 2.5 times fewer inputs.
        #[arg(long)]
        internal_feedback: bool,
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
        #[arg(long = "search-seed", visible_alias = "rng", default_value_t = 1)]
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
    /// output_bytes, clock_reads). Stored runs are checked first. Saved
    /// asserts (`[acceptance]` with `let`/`assert`) need no command: `run`,
    /// `fuzz` and `review` judge them on every run.
    Check {
        /// The property, as words: `value_range .usage 0 100`.
        #[arg(required = true, num_args = 1.., allow_negative_numbers = true)]
        property: Vec<String>,
        #[arg(long)]
        runs: Option<u64>,
        #[arg(long, default_value = "60s")]
        time: String,
        #[arg(long = "search-seed", visible_alias = "rng", default_value_t = 1)]
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
    #[command(hide = true)]
    Provenance {
        run: String,
        #[arg(long)]
        call: u32,
    },
    /// Estimated fuel attribution between host calls; not a CPU profile.
    ///
    /// Instructions between host calls, per function (self and inclusive),
    /// and after the last host call.
    #[command(hide = true)]
    Profile {
        run: String,
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// A run in plain terms, compared with the median stored run.
    #[command(hide = true)]
    Explain { run: String },
    /// A CEL expression over a stored run's values: try an assert before saving it.
    ///
    /// Prints every binding's value (or why it has none), the expression's
    /// value, and what an acceptance check would report.
    Eval {
        /// The run: `last` or an id.
        run: String,
        /// The expression: `size(rows) == size(items)`.
        expr: String,
        /// A binding, `name=path` (see `appfuzz bindings`).
        #[arg(long = "let", value_name = "NAME=PATH")]
        lets: Vec<String>,
        #[arg(long)]
        assume: Option<String>,
    },
    /// The paths a `let` binding can name for this app, with types and example values.
    Bindings {
        /// Take example values from this run (`last` or an id).
        #[arg(long, default_value = "last")]
        run: String,
    },
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
    /// Experimental: envelope from an explicitly accepted review session.
    ///
    /// Writes envelope.json from one accepted review of this build and
    /// platform contract. Later exploratory runs do not widen it.
    /// `envelope check` rejects mismatched or incomplete traces.
    Envelope {
        #[command(subcommand)]
        cmd: Option<EnvelopeCmd>,
        /// Where to write the envelope.
        #[arg(long, default_value = "envelope.json")]
        out: PathBuf,
        /// Review session to use (default: latest review).
        #[arg(long, default_value = "last")]
        review: String,
        /// Platform policy accepts warnings; failed/incomplete reviews are rejected.
        #[arg(long)]
        allow_warnings: bool,
    },
    /// Static views of the code: functions, call graph, loops, strings.
    Wasm {
        #[command(subcommand)]
        cmd: wasm_cmd::WasmCmd,
    },
}

#[derive(Subcommand)]
pub(crate) enum ProbeCmd {
    /// Fail each reached host call once, then keep that service failing.
    Faults {
        /// Stored successful run; otherwise execute the supplied request.
        run: Option<String>,
        #[arg(long = "fn")]
        func: Option<String>,
        /// Fault evaluations (the successful baseline is additional).
        #[arg(long, default_value_t = 128, value_parser = clap::value_parser!(u64).range(1..))]
        runs: u64,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Runs at calendar and clock edges (leap day, year end, DST, 2038).
    Times {
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// The run again with one thing changed; what changed in the answer?
    ///
    /// One variant each reverses a list, adds
    /// a duplicate, changes the random seed or the wall clock, fails one
    /// call, or slows one function. Fault recovery keeps the original host plan;
    /// other variants pin the observed host results.
    Pairs {
        /// A stored run (default: run the request given below).
        run: Option<String>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Requests from another website and naming another host (HTTP).
    ///
    /// Catches CORS headers that let any site read the response with the
    /// visitor's cookies, and links, redirects or outbound requests built
    /// from the Host header.
    Web {
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Requests without credentials and with forged ones (HTTP).
    ///
    /// Where the request without credentials is turned away (401, 403, a
    /// redirect), sends a made-up token, an unsigned JWT, a JWT with a
    /// wrong signature, Basic admin:admin and made-up session cookies, and
    /// prefixes of the secret the app checks them against (a comparison
    /// that leaks timing). Sends responses with a session token again with
    /// other random seeds (a token that is not random). Also tries paths of
    /// stored runs that were turned away or issued a token.
    Auth {
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
    /// Every kind of value each host function may return.
    Values {
        /// Only host functions matching this.
        #[arg(long = "fn", visible_alias = "func")]
        func: Option<String>,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
}

#[derive(Subcommand)]
pub(crate) enum EnvelopeCmd {
    /// A trace against the envelope: outside_envelope findings, exit code 0/1/2/3.
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
pub(crate) enum PlatformCmd {
    /// The host API reference: signatures, descriptions, errors, rules, domains.
    Docs {
        /// The platform: a bundled name (`fastly`) or a platform.toml; default: [app] platform.
        #[arg(long)]
        platform: Option<String>,
        /// Only this function (`module#name`, `interface#name`, or the bare name).
        #[arg(long = "fn", visible_alias = "func")]
        func: Option<String>,
        /// Only the functions of this capability.
        #[arg(long)]
        capability: Option<String>,
        /// Also write the reference as Markdown to this file (e.g. HOST-API.md).
        #[arg(long)]
        markdown: Option<PathBuf>,
    },
    /// Checks platform.toml against its WIT or witx; lists undescribed functions.
    Check {
        /// The platform: a bundled name (`fastly`) or a platform.toml; default: [app] platform.
        #[arg(long)]
        platform: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
pub(crate) enum PlanCmd {
    /// A plan with every host function, its signature and an example value.
    Template,
}

#[derive(clap::Args, Clone)]
pub(crate) struct RunArgs {
    /// The export (`interface#function`); default: [entry] export.
    #[arg(long, conflicts_with = "legacy_export")]
    pub(crate) export: Option<String>,
    /// Compatibility positional export.
    #[arg(hide = true)]
    pub(crate) legacy_export: Option<String>,
    /// Include every host call.
    #[arg(long)]
    pub(crate) trace: bool,
    #[command(flatten)]
    pub(crate) spec: SpecArgs,
}

#[derive(clap::Args, Clone)]
pub(crate) struct SpecArgs {
    /// Arguments as a JSON array, one per parameter.
    #[arg(long, conflicts_with = "request")]
    pub(crate) args: Option<String>,
    /// The single argument as JSON (for one-parameter exports).
    #[arg(long)]
    pub(crate) request: Option<String>,
    /// JSON merged into the default request (from the manifest).
    #[arg(long, conflicts_with_all = ["args", "request"])]
    pub(crate) set: Vec<String>,
    /// Host plan: a file, or inline JSON.
    #[arg(long)]
    pub(crate) plan: Option<String>,
    /// Seed for generated host results and guest randomness.
    #[arg(long = "host-seed", visible_alias = "seed", default_value_t = 1)]
    pub(crate) seed: u64,
    /// Virtual start time, `YYYY-MM-DDTHH:MM:SS`.
    #[arg(long)]
    pub(crate) now: Option<String>,
    /// Fuel for the run (default: 5× the production limit).
    #[arg(long)]
    pub(crate) fuel: Option<u64>,
}

#[derive(Subcommand)]
pub(crate) enum SequenceCmd {
    /// Execute a scenario against persistent simulated data.
    Run {
        scenario: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Search request orderings and repetitions, then shrink a failure.
    Fuzz {
        scenario: PathBuf,
        #[arg(long, default_value_t = 100)]
        runs: u64,
        #[arg(long, default_value_t = 1)]
        search_seed: u64,
        #[arg(long, default_value_t = 200)]
        shrink_runs: u64,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Replay a complete sequence case, optionally against the current build.
    Replay {
        case: PathBuf,
        #[arg(long)]
        against_current: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum AcceptanceCmd {
    /// Check the saved suite, or one named requirement.
    Run {
        name: Option<String>,
        #[arg(long, default_value_t = 100)]
        runs: u64,
        #[arg(long, default_value_t = 1)]
        search_seed: u64,
        #[arg(long, default_value_t = 200)]
        shrink_runs: u32,
        #[arg(long)]
        export: Option<String>,
        #[command(flatten)]
        spec: SpecArgs,
    },
}
