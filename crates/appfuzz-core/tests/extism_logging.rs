use appfuzz_core::{
    detect,
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};

const CAPACITY: usize = 1 << 20;
const PAGE: u64 = 65_536;
const KERNEL_MEMORY: u64 = 16 * PAGE;

fn run(start: &str, body: &str, memory: u64) -> RunRecord {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-logging-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:logging; world plugin { export run: func() -> string; }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'logging'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("logging.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let wat = format!(
        r#"(module
        (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
        (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
        (import "extism:host/env" "log_info" (func $log (param i64)))
        (import "extism:host/env" "reset" (func $reset))
        (func $message (param $n i64)
            (call $log (call $alloc (local.get $n))))
        (func $init (local $i i32) (local $block i64) {start}) (start $init)
        (func (export "run") (result i32) (local $i i32) (local $block i64)
            {body} (i32.const 0)))"#
    );
    let app = App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap();
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    // Leave room for the fixed kernel memory and whole allocator growth pages.
    spec.memory = KERNEL_MEMORY + memory.div_ceil(PAGE) * PAGE + PAGE;
    let run = app.run(&spec);
    if run.outcome.kind == OutcomeKind::Error {
        assert!(!detect::per_run(&run, &app.manifest).iter().any(|finding| finding.kind == "crash"));
    }
    run
}

fn incomplete(run: &RunRecord) {
    assert_eq!(run.outcome.kind, OutcomeKind::Error, "{:?}", run.outcome);
    assert!(run.capture_limited);
    assert!(run.outcome.message.as_ref().unwrap().contains("log capture"), "{:?}", run.outcome);
    assert!(run.stderr.len() <= CAPACITY, "captured {} bytes", run.stderr.len());
}

#[test]
fn repeated_logging_cannot_accumulate_unbounded_host_memory() {
    let run = run(
        "",
        r#"(loop $again
            (call $message (i64.const 1024))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $again (i32.lt_u (local.get $i) (i32.const 3000))))"#,
        1024,
    );
    incomplete(&run);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
    assert!(!run.stderr.is_empty());
}

#[test]
fn log_framing_counts_toward_the_capture_limit() {
    let run = run(
        "",
        r#"(loop $again
            (call $message (i64.const 1))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $again (i32.lt_u (local.get $i) (i32.const 120000))))"#,
        1,
    );
    incomplete(&run);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn reset_cannot_erase_the_log_capture_budget() {
    let run = run(
        "",
        r#"(loop $again
            (call $message (i64.const 1024))
            (call $reset)
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $again (i32.lt_u (local.get $i) (i32.const 3000))))"#,
        1024,
    );
    incomplete(&run);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn a_message_that_exactly_fills_the_capture_is_preserved() {
    let run = run("", &format!("(call $message (i64.const {}))", CAPACITY - 8), CAPACITY as u64);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.stderr.len(), CAPACITY);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY + 16 * PAGE);
}

#[test]
fn an_additional_message_after_a_full_capture_is_incomplete() {
    let run = run("", &format!("(call $message (i64.const {})) (call $message (i64.const 1))", CAPACITY - 8), CAPACITY as u64);
    incomplete(&run);
    assert_eq!(run.stderr.len(), CAPACITY);
}

#[test]
fn a_single_oversized_message_is_not_copied_into_the_capture() {
    let run = run("", &format!("(call $message (i64.const {}))", CAPACITY * 2), (CAPACITY * 2) as u64);
    incomplete(&run);
    assert!(run.stderr.is_empty());
}

#[test]
fn initialization_and_export_share_one_log_capture_budget() {
    let run = run(&format!("(call $message (i64.const {}))", CAPACITY - 16), "(call $message (i64.const 1))", CAPACITY as u64);
    incomplete(&run);
    assert_eq!(run.stderr.len(), CAPACITY - 8);
}

#[test]
fn invalid_utf8_logs_emit_a_small_sdk_diagnostic_and_release_the_message() {
    let run = run(
        "",
        r#"(local.set $block (call $alloc (i64.const 400000)))
        (loop $fill
            (call $write (i64.add (local.get $block) (i64.extend_i32_u (local.get $i))) (i32.const 255))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $fill (i32.lt_u (local.get $i) (i32.const 400000))))
        (call $log (local.get $block))
        (if (i64.eqz (call $alloc (i64.const 400000))) (then unreachable))"#,
        400000,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.stderr, "[error] unable to log message: Err(invalid utf-8 sequence of 1 bytes from index 0)\n");
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY + 6 * PAGE);
}
