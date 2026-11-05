use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::json;

fn app(body: &str, status: i32) -> App {
    app_with_start(body, status, "")
}

fn app_with_start(body: &str, status: i32, start: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-output-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:output; world plugin { export run: func() -> string; }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'output'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("output.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let wat = format!(
        r#"(module
      (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
      (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
      (import "extism:host/env" "output_set" (func $output (param i64 i64)))
      (import "extism:host/env" "error_set" (func $error (param i64)))
      (import "extism:host/env" "error_get" (func $get_error (result i64)))
      (import "extism:host/env" "free" (func $free (param i64)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 0)
      (func $init (local $block i64) {start}) (start $init)
      (func (export "run") (result i32) (local $block i64) {body} (i32.const {status})))"#
    );
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

const ERROR: &str = r#"(local.set $block (call $alloc (i64.const 3)))
    (call $write (local.get $block) (i32.const 98))
    (call $write (i64.add (local.get $block) (i64.const 1)) (i32.const 97))
    (call $write (i64.add (local.get $block) (i64.const 2)) (i32.const 100))
    (call $error (local.get $block))"#;

#[test]
fn writes_after_output_set_are_visible_in_the_final_output() {
    let app = app(
        r#"(local.set $block (call $alloc (i64.const 1)))
      (call $write (local.get $block) (i32.const 65))
      (call $output (local.get $block) (i64.const 1))
      (call $write (local.get $block) (i32.const 90))"#,
        0,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("Z")));
}

#[test]
fn error_get_returns_the_existing_handle_without_another_allocation() {
    let app = app(
        &format!(
            r#"{ERROR}
      (if (i64.ne (call $get_error) (local.get $block)) (then unreachable))
      (call $error (i64.const 0))"#
        ),
        0,
    );
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = 16 * 65_536;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
    assert_eq!(run.totals.peak_memory, 16 * 65_536);
}

#[test]
fn writes_to_the_error_handle_are_visible_in_the_failure() {
    let app = app(&format!(r#"{ERROR} (call $write (call $get_error) (i32.const 88))"#), 1);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains("Xad"));
}

#[test]
fn a_kernel_error_is_still_a_failure_when_the_export_returns_zero() {
    let app = app(ERROR, 0);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains("bad"));
}

#[test]
fn a_kernel_error_is_preserved_when_wasi_exits_with_zero() {
    let app = app(&format!("{ERROR} (call $exit (i32.const 0))"), 0);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains("bad"));
}

#[test]
fn a_freed_error_handle_does_not_prevent_a_successful_wasi_exit() {
    let app = app(&format!("{ERROR} (call $free (local.get $block)) (call $exit (i32.const 0))"), 0);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
}

#[test]
fn output_slices_observe_later_writes() {
    let app = app(
        r#"(local.set $block (call $alloc (i64.const 3)))
      (call $write (i64.add (local.get $block) (i64.const 1)) (i32.const 65))
      (call $output (i64.add (local.get $block) (i64.const 1)) (i64.const 1))
      (call $write (i64.add (local.get $block) (i64.const 1)) (i32.const 90))"#,
        0,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("Z")));
}

#[test]
fn a_null_output_setter_preserves_the_previous_output() {
    let app = app(
        r#"(local.set $block (call $alloc (i64.const 1)))
      (call $write (local.get $block) (i32.const 65))
      (call $output (local.get $block) (i64.const 1))
      (call $output (i64.const 0) (i64.const 0))"#,
        0,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("A")));
}

#[test]
fn a_valid_nonnull_zero_length_span_clears_the_previous_output() {
    let app = app(
        r#"(local.set $block (call $alloc (i64.const 1)))
      (call $write (local.get $block) (i32.const 65))
      (call $output (local.get $block) (i64.const 1))
      (call $output (local.get $block) (i64.const 0))"#,
        0,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
}

#[test]
fn a_null_output_setter_before_any_output_leaves_an_empty_response() {
    let app = app("(call $output (i64.const 0) (i64.const 0))", 0);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
}

#[test]
fn initialization_output_is_reset_before_the_export() {
    let app = app_with_start(
        "",
        0,
        r#"(local.set $block (call $alloc (i64.const 1)))
      (call $write (local.get $block) (i32.const 65))
      (call $output (local.get $block) (i64.const 1))"#,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
}
