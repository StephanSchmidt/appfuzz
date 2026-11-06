use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};

const PAGE: u64 = 65_536;
const KERNEL: u64 = 16 * PAGE;
fn app(memory_pages: u32, body: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-memory-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:memory; world plugin { export run: func(); }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'memory'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("memory.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let wat = format!(
        r#"(module
      (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
      (import "extism:host/env" "free" (func $free (param i64)))
      (import "extism:host/env" "output_set" (func $output (param i64 i64)))
      (import "extism:host/env" "var_get" (func $var-get (param i64) (result i64)))
      (memory {memory_pages})
      (func (export "run") (result i32) {body} (i32.const 0)))"#
    );
    App::from_bytes(manifest, wat::parse_str(&wat).unwrap()).unwrap()
}

#[test]
fn kernel_allocation_respects_memory_already_used_by_wasm() {
    let app = app(1, "(if (i64.ne (call $alloc (i64.const 65536)) (i64.const 0)) (then unreachable))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL + PAGE + PAGE / 2;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL + PAGE);
}

#[test]
fn wasm_allocation_respects_memory_already_used_by_the_kernel() {
    let app = app(
        0,
        r#"(if (i64.eqz (call $alloc (i64.const 65536))) (then unreachable))
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable))"#,
    );
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL + PAGE + PAGE / 2;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL + PAGE);
}

#[test]
fn guest_traps_after_kernel_allocation_failure_keep_their_actual_cause() {
    let app = app(0, "(if (i64.eqz (call $alloc (i64.const 65536))) (then unreachable))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Unreachable, "{:?}", run.outcome);
    assert!(run.memory_limit_hit);
    assert_eq!(run.totals.peak_memory, KERNEL);
}

#[test]
fn a_kernel_error_after_a_handled_allocation_denial_is_not_out_of_memory() {
    let app = app(0, "(if (i64.ne (call $alloc (i64.const 65536)) (i64.const 0)) (then unreachable)) (drop (call $var-get (i64.const 1)))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.memory_limit_hit);
    assert!(run.outcome.message.unwrap().contains("not a block"));
}

#[test]
fn freeing_a_kernel_block_allows_repeated_allocations_within_the_cap() {
    let app = app(
        0,
        r#"(local $i i32) (local $block i64)
      (loop $again
        (local.set $block (call $alloc (i64.const 65536)))
        (if (i64.eqz (local.get $block)) (then unreachable))
        (call $free (local.get $block))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (i32.const 10))))"#,
    );
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL + PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL + PAGE);
}

#[test]
fn zero_length_kernel_allocations_use_the_null_handle() {
    let app = app(0, "(if (i64.ne (call $alloc (i64.const 0)) (i64.const 0)) (then unreachable))");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL);
}

#[test]
fn freeing_a_block_does_not_refund_retained_linear_memory_pages() {
    let app = app(1, "(call $free (call $alloc (i64.const 65536))) (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL + 2 * PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL + 2 * PAGE);
}

#[test]
fn empty_kernel_output_accepts_the_null_handle() {
    let app = app(0, "(call $output (i64.const 0) (i64.const 0))");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(serde_json::Value::Null));
    assert_eq!(run.totals.peak_memory, KERNEL);
}

#[test]
fn oversized_kernel_allocations_can_be_handled_by_the_guest() {
    let app = app(0, "(if (i64.ne (call $alloc (i64.const 4294967296)) (i64.const 0)) (then unreachable))");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL);
}

#[test]
fn guest_and_kernel_growth_share_the_same_combined_peak() {
    let app =
        app(1, "(if (i64.eqz (call $alloc (i64.const 65536))) (then unreachable)) (if (i32.ne (memory.grow (i32.const 1)) (i32.const 1)) (then unreachable))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = KERNEL + 3 * PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL + 3 * PAGE);
}
