//! Speed of the engine, in Go's benchmark format for `benchstat`
//! (`make speed`). Not the bench: `tests/bench.rs` checks what review
//! finds, this measures how fast it gets there.
//!
//! ```text
//! cargo bench -p appfuzz --bench speed -- -count 6 > old.txt
//! cargo bench -p appfuzz --bench speed -- -bench Run -benchtime 100ms
//! benchstat old.txt new.txt
//! ```
//!
//! Four bench apps, four steps each:
//! - `Load`: compile and link the app
//! - `Run`: the manifest's request, once
//! - `Detect`: the per-run checks on that run
//! - `Fuzz`: a campaign of `FUZZ_RUNS` runs on one thread, so every build
//!   does the same work

use std::collections::BTreeSet;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;

use appfuzz_core::detect;
use appfuzz_core::fuzz::{FuzzOpts, fuzz};
use appfuzz_core::harness::App;
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use appfuzz_core::record::{OutcomeKind, RunRecord, RunSpec};
use benchfmt::{CountingAlloc, Suite};
use mimalloc::MiMalloc;

// The CLI's allocator, counted on the calling thread: B/op and allocs/op.
#[global_allocator]
static ALLOC: CountingAlloc<MiMalloc> = CountingAlloc::with_allocator(MiMalloc);

/// A baseline, many host calls, a wasi:http handler, a large page.
const APPS: [&str; 4] = ["clean", "nested-fanout", "http-fanout", "big-output"];

const FUZZ_RUNS: u64 = 300;

struct Bench {
    name: &'static str,
    manifest: Manifest,
    bytes: Vec<u8>,
    app: App,
    spec: RunSpec,
    record: RunRecord,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Builds the app (if it changed) and loads it with the request
/// `appfuzz run` sends.
fn prepare(name: &'static str) -> Bench {
    let dir = root().join("bench/apps").join(name);
    let status = Command::new("cargo")
        .args(["build", "--quiet", "--release", "--target", "wasm32-wasip2", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .status()
        .expect("cargo");
    assert!(status.success(), "building bench app {name} failed (is the wasm32-wasip2 target installed?)");
    let manifest = Manifest::load(&dir.join("appfuzz.toml")).unwrap();
    let bytes = std::fs::read(manifest.wasm_path()).unwrap();
    let app = App::from_bytes(manifest.clone(), bytes.clone()).unwrap();
    let export = app.default_export().unwrap().clone();
    let args = app.default_args(&export, &app.manifest.start_time()).unwrap();
    let spec = app.spec(&export, args, Plan::default(), 1);
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{name}: {:?}", record.outcome.message);
    Bench { name, manifest, bytes, app, spec, record }
}

/// A fuzz campaign as `review` starts it, with a run budget instead of a
/// time budget; the runs it made.
fn campaign(b: &Bench, pool: &rayon::ThreadPool) -> u64 {
    let opts = FuzzOpts { runs: Some(FUZZ_RUNS), time: None, ..FuzzOpts::default() };
    let (report, _) = pool.install(|| fuzz(&b.app, &b.spec, Vec::new(), BTreeSet::new(), &opts, &|_, _, _| {})).unwrap();
    report.runs
}

fn main() {
    let benches: Vec<Bench> = APPS.into_iter().map(prepare).collect();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    for b in &benches {
        assert_eq!(campaign(b, &pool), FUZZ_RUNS, "{}: the campaign stopped early", b.name);
    }
    let mut suite = Suite::from_env("appfuzz").with_alloc(&ALLOC);
    // Compilation runs on other threads: time only.
    for b in &benches {
        suite = suite.bench(format!("Load/app={}", b.name), |t| {
            while t.keep_running() {
                black_box(App::from_bytes(b.manifest.clone(), b.bytes.clone()).unwrap());
            }
        });
    }
    for b in &benches {
        suite = suite.bench(format!("Run/app={}", b.name), |t| {
            t.report_allocs();
            while t.keep_running() {
                black_box(b.app.run(&b.spec));
            }
        });
    }
    for b in &benches {
        suite = suite.bench(format!("Detect/app={}", b.name), |t| {
            t.report_allocs();
            while t.keep_running() {
                black_box(detect::per_run(&b.record, &b.app.manifest));
            }
        });
    }
    // The campaign runs on the pool's thread: time only.
    for b in &benches {
        let pool = &pool;
        suite = suite.bench(format!("Fuzz/app={}", b.name), move |t| {
            while t.keep_running() {
                black_box(campaign(b, pool));
            }
        });
    }
    suite.run();
}
