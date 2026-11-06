use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::json;

const KERNEL_MEMORY: u64 = 16 * 65_536;

fn app(use_offset: bool) -> App {
    app_with(if use_offset { "(drop (call $offset))" } else { "" }, "")
}

fn app_with(body: &str, start: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-input-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:input; world plugin { export run: func(input: string); }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'input'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("input.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let wat = format!(
        r#"(module
      (import "extism:host/env" "input_offset" (func $offset (result i64)))
      (import "extism:host/env" "input_length" (func $length (result i64)))
      (import "extism:host/env" "input_load_u8" (func $read (param i64) (result i32)))
      (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
      (import "extism:host/env" "free" (func $free (param i64)))
      (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
      (func $init {start}) (start $init)
      (func (export "run") (result i32) {body} (i32.const 0)))"#
    );
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn plugin_input_is_charged_even_when_the_guest_ignores_it() {
    let app = app(false);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("x".repeat(65_536))], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY + 65_536);
}

#[test]
fn plugin_input_cannot_exceed_the_run_memory_cap() {
    let app = app(false);
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!("x".repeat(65_536))], Plan::default(), 1);
    spec.memory = KERNEL_MEMORY;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfMemory, "{:?}", run.outcome);
    assert!(run.memory_limit_hit);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn requesting_an_input_offset_does_not_allocate_a_second_input() {
    let (direct, offset) = (app(false), app(true));
    let run = |app: &App| app.run(&app.spec(app.export("run").unwrap(), vec![json!("é".repeat(8))], Plan::default(), 1));
    let (direct, offset) = (run(&direct), run(&offset));
    assert_eq!(direct.outcome.kind, OutcomeKind::Ok, "{:?}", direct.outcome);
    assert_eq!(offset.outcome.kind, OutcomeKind::Ok, "{:?}", offset.outcome);
    assert_eq!(direct.totals.peak_memory, KERNEL_MEMORY);
    assert_eq!(offset.totals.peak_memory, direct.totals.peak_memory);
}

#[test]
fn writing_the_input_block_updates_input_loads() {
    let app = app_with("(call $write (call $offset) (i32.const 90)) (if (i32.ne (call $read (i64.const 0)) (i32.const 90)) (then unreachable))", "");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn freeing_the_input_block_clears_the_input_length() {
    let app = app_with("(call $free (call $offset)) (if (i64.ne (call $length) (i64.const 0)) (then unreachable))", "");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn input_is_prepared_after_module_initialization() {
    let app = app_with("(if (i64.ne (call $length) (i64.const 3)) (then unreachable))", "(if (i64.ne (call $length) (i64.const 0)) (then unreachable))");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn initialization_blocks_are_reset_before_the_input_is_prepared() {
    let app = app_with("(if (i64.ne (call $offset) (i64.const 77)) (then unreachable))", "(drop (call $alloc (i64.const 96)))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!("abcdefghijklmnopq")], Plan::default(), 1);
    spec.memory = KERNEL_MEMORY;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}
