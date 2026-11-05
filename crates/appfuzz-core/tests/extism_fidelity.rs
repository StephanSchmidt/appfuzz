use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};

fn app(body: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-fidelity-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.wit"), "package test:fidelity; world plugin { export run:func()->string; }").unwrap();
    let host = HostManifest::parse("[platform]\nname='fidelity'\nabi='extism'\nwit='app.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("fidelity.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let wat = format!(
        r#"(module
        (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
        (import "extism:host/env" "free" (func $free (param i64)))
        (import "extism:host/env" "length" (func $length (param i64) (result i64)))
        (import "extism:host/env" "load_u8" (func $read (param i64) (result i32)))
        (import "extism:host/env" "store_u64" (func $write64 (param i64 i64)))
        (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
        (import "extism:host/env" "log_info" (func $log (param i64)))
        (import "extism:host/env" "output_set" (func $output (param i64 i64)))
        (import "extism:host/env" "error_set" (func $error (param i64)))
        (import "extism:host/env" "memory_bytes" (func $capacity (result i64)))
        (func (export "run") (result i32) (local $block i64) (local $other i64) (local $i i32)
            {body} (i32.const 0)))"#
    );
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

fn run(body: &str, fuel: u64) -> RunRecord {
    let app = app(body);
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.fuel = fuel;
    app.run(&spec)
}

fn ok(body: &str) -> RunRecord {
    let run = run(body, 2_000_000);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    run
}

#[test]
fn offsets_and_free_reuse_follow_the_shipped_sdk_kernel() {
    ok(r#"(local.set $block (call $alloc (i64.const 3)))
        (if (i64.ne (local.get $block) (i64.const 77)) (then unreachable))
        (call $free (local.get $block))
        (local.set $other (call $alloc (i64.const 1)))
        (if (i64.ne (local.get $other) (i64.const 92)) (then unreachable))"#);
}

#[test]
fn allocator_capacity_is_distinct_from_linear_backing_memory() {
    let run = ok(r#"(if (i64.ne (call $capacity) (i64.const 65472)) (then unreachable))
        (drop (call $alloc (i64.const 65536)))
        (if (i64.ne (call $capacity) (i64.const 131008)) (then unreachable))"#);
    // The pinned shipped artifact has sixteen initial pages, then grows one.
    assert_eq!(run.totals.peak_memory, 17 * 65_536);
}

#[test]
fn kernel_initial_memory_is_included_even_without_guest_allocations() {
    assert_eq!(ok("").totals.peak_memory, 16 * 65_536);
}

#[test]
fn raw_bounds_checks_and_invalid_setters_match_the_kernel() {
    ok(r#"(if (i32.ne (call $read (i64.const 0)) (i32.const 0)) (then unreachable))
        (if (i32.ne (call $read (i64.const -1)) (i32.const 0)) (then unreachable))
        (call $output (i64.const 1) (i64.const 1))
        (call $error (i64.const 1))"#);
}

#[test]
fn allocator_work_consumes_the_same_fuel_budget_as_guest_work() {
    let run = ok(r#"(loop $again
        (drop (call $alloc (i64.const 1)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (i32.const 128))))"#);
    assert!(run.totals.fuel > 3_000, "kernel work was omitted: {} fuel", run.totals.fuel);
}

#[test]
fn malformed_allocator_metadata_cannot_escape_guest_fuel_metering() {
    let run = run(
        r#"(local.set $block (call $alloc (i64.const 1)))
        (call $write64 (i64.sub (local.get $block) (i64.const 8)) (i64.const 0x1fffffff4))
        (drop (call $length (i64.add (local.get $block) (i64.const 1))))"#,
        5_000,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfFuel, "{:?}", run.outcome);
    assert_eq!(run.totals.fuel, 5_000);
    assert!(run.outcome.stack.len() >= 2, "lost the kernel and guest stack: {:?}", run.outcome);
}

#[test]
fn wrapped_sizes_preserve_the_upstream_wasm32_allocator_behavior() {
    ok(r#"(local.set $block (call $alloc (i64.const -1)))
        (if (i64.ne (local.get $block) (i64.const 77)) (then unreachable))
        (if (i64.ne (call $length (local.get $block)) (i64.const 4294967295)) (then unreachable))"#);
}

#[test]
fn corrupt_output_lengths_cannot_read_host_memory_outside_the_kernel() {
    let run = run(
        r#"(local.set $block (call $alloc (i64.const 1)))
        (call $output (local.get $block) (i64.const 1))
        (call $write64 (i64.const 57) (i64.const -1))"#,
        2_000_000,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains("out of bounds"));
    assert!(run.result.is_none());
}

#[test]
fn a_log_emitted_before_a_failing_free_remains_in_the_evidence() {
    let app = app(r#"(local.set $block (call $alloc (i64.const 1)))
        (call $write (local.get $block) (i32.const 65)) (call $log (local.get $block))"#);
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    let normal = app.run(&spec);
    assert_eq!(normal.outcome.kind, OutcomeKind::Ok, "{:?}", normal.outcome);
    let mut exercised = false;
    for fuel in 1..normal.totals.fuel {
        spec.fuel = fuel;
        let run = app.run(&spec);
        // free is export/function 4 in the pinned upstream artifact. Stop at
        // that operation, after logging has happened, rather than assuming a
        // particular compiler fuel cost for it.
        if run.outcome.kind == OutcomeKind::OutOfFuel && run.outcome.stack.first().is_some_and(|frame| frame.func == 4) {
            exercised = true;
            assert_eq!(run.stderr, "[info] A\n", "lost an emitted log at fuel {fuel}");
        }
    }
    assert!(exercised, "did not stop inside the kernel free operation");
}

#[test]
fn preparing_input_uses_the_run_fuel_budget_and_keeps_the_kernel_stack() {
    let app = app("");
    let module = appfuzz_core::extism::Kernel::module(&app.engine).unwrap();
    let mut reference = wasmtime::Store::new(&app.engine, ());
    reference.set_fuel(1_000_000).unwrap();
    reference.set_epoch_deadline(1_000);
    appfuzz_core::extism::Runtime::instantiate(&mut reference, &module).unwrap();
    // Leave one instruction after kernel global initialization, so the stop
    // is inside reset/input preparation rather than before any Wasm frame.
    let fuel = 1_000_000 - reference.get_fuel().unwrap() + 1;
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.fuel = fuel;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfFuel, "{:?}", run.outcome);
    assert_eq!(run.totals.fuel, fuel);
    assert!(!run.outcome.stack.is_empty(), "{:?}", run.outcome);
}
