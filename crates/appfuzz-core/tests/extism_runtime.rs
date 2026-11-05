use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};

fn app(wat: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-runtime-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:runtime; world plugin { export run: func(); }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'runtime'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("runtime.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn wasi_reactor_initialization_runs_before_the_plugin_export() {
    let app = app(r#"(module (global $ready (mut i32) (i32.const 0))
      (func (export "_initialize") (global.set $ready (i32.add (global.get $ready) (i32.const 1))))
      (func (export "run") (result i32)
        (if (i32.ne (global.get $ready) (i32.const 1)) (then unreachable)) (i32.const 0)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
}

#[test]
fn constructors_take_precedence_over_wasi_reactor_initialization() {
    let app = app(r#"(module (global $ready (mut i32) (i32.const 0))
      (func (export "__wasm_call_ctors") (global.set $ready (i32.const 1)))
      (func (export "_initialize") unreachable)
      (func (export "run") (result i32)
        (if (i32.ne (global.get $ready) (i32.const 1)) (then unreachable)) (i32.const 0)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
}

#[test]
fn plugin_constructor_traps_are_recorded() {
    let app = app(r#"(module (memory 1) (func $init (export "_initialize") unreachable)
      (func (export "run") (result i32) (i32.const 0)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Unreachable, "{:?}", run.outcome);
    assert!(!run.outcome.stack.is_empty());
    assert_eq!(run.totals.peak_memory, 17 * 65_536);
}

#[test]
fn plugin_constructor_hangs_use_the_run_fuel_limit() {
    let app = app(r#"(module (func (export "_initialize") (loop $forever (br $forever)))
      (func (export "run") (result i32) (i32.const 0)))"#);
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.fuel = 1000;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfFuel, "{:?}", run.outcome);
    assert_eq!(run.totals.fuel, spec.fuel);
}

#[test]
fn a_plugin_export_can_return_no_status_value() {
    let app = app(r#"(module (func (export "run")))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(serde_json::Value::Null));
}

#[test]
fn a_plugin_can_exit_successfully_through_wasi() {
    let app = app(r#"(module
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "run") (result i32) (call $exit (i32.const 0)) unreachable))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
}

#[test]
fn haskell_initialization_runs_after_its_wasi_reactor() {
    let app = app(r#"(module (global $ready (mut i32) (i32.const 0))
      (func (export "_initialize") (global.set $ready (i32.const 1)))
      (func (export "__wasm_call_ctors") unreachable)
      (func (export "hs_init") (param i32 i32)
        (if (i32.or (local.get 0) (local.get 1)) (then unreachable))
        (if (i32.ne (global.get $ready) (i32.const 1)) (then unreachable))
        (global.set $ready (i32.const 2)))
      (func (export "run") (result i32)
        (if (i32.ne (global.get $ready) (i32.const 2)) (then unreachable)) (i32.const 0)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
}

#[test]
fn a_nonzero_wasi_exit_is_still_a_plugin_failure() {
    let app = app(r#"(module
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func (export "run") (result i32) (call $exit (i32.const 7)) unreachable))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains('7'));
}

#[test]
fn an_incompatible_initialization_export_is_not_called() {
    let app = app(r#"(module (func (export "_initialize") (param i32) unreachable)
      (func (export "run") (result i32) (i32.const 0)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
}
