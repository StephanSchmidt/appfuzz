use appfuzz_core::{harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};

fn component(start: &str) -> App {
    let wat = format!(
        r#"(component
      (core module $m (memory 1)
        (func $init {start}) (start $init)
        (func (export "run") (result i32) (i32.const 7)))
      (core instance $m (instantiate $m))
      (func (export "run") (result u32) (canon lift (core func $m "run"))))"#
    );
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("startup.wasm")), wat::parse_str(&wat).unwrap()).unwrap()
}

fn calls_in_start() -> App {
    let wat = r#"(component
      (import "get" (func $get (result u32)))
      (core func $get (canon lower (func $get)))
      (core instance $host (export "get" (func $get)))
      (core module $m
        (import "host" "get" (func $get (result i32)))
        (memory 1)
        (func $init (local $i i32)
          (loop $loop
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br_if $loop (i32.lt_u (local.get $i) (i32.const 10000))))
          (drop (call $get)))
        (start $init)
        (func (export "run") (result i32) (call $get)))
      (core instance $m (instantiate $m (with "host" (instance $host))))
      (func (export "run") (result u32) (canon lift (core func $m "run"))))"#;
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("startup.wasm")), wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn startup_fuel_is_included_in_the_run_total() {
    let app = calls_in_start();
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.events.len(), 2);
    assert!(run.totals.fuel >= run.events[0].fuel_before, "total {} is less than startup work {}", run.totals.fuel, run.events[0].fuel_before);
}

#[test]
fn virtual_time_does_not_go_backwards_after_startup() {
    let app = calls_in_start();
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.events.len(), 2);
    assert!(run.events[1].t_ns >= run.events[0].t_ns.saturating_add(run.events[0].latency_ns), "timeline went backwards: {:?}", run.events);
}

#[test]
fn guest_startup_traps_keep_their_classification_stack_and_memory() {
    let app = component("unreachable");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Unreachable, "{:?}", run.outcome);
    assert!(!run.outcome.stack.is_empty());
    assert_eq!(run.totals.peak_memory, 65536);
    assert!(run.totals.fuel > 0);
}

#[test]
fn guest_startup_hangs_are_fuel_failures() {
    let app = component("(loop $forever (br $forever))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.fuel = 10000;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfFuel, "{:?}", run.outcome);
    assert_eq!(run.totals.fuel, spec.fuel);
    assert_eq!(run.totals.peak_memory, 65536);
}

#[test]
fn initial_memory_above_the_run_cap_is_an_app_memory_failure() {
    let app = component("");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = 0;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfMemory, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, 0);
}

#[test]
fn planned_startup_failures_keep_their_events_and_metrics() {
    let app = calls_in_start();
    let plan = Plan::parse(r#"{"get":{"trap":"service down"}}"#).unwrap();
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::HostTrap, "{:?}", run.outcome);
    assert_eq!(run.events.len(), 1);
    assert_eq!(run.totals.host_calls, 1);
    assert!(run.totals.fuel > 10000);
    assert_eq!(run.totals.peak_memory, 65536);
}

#[test]
fn invalid_startup_plan_values_remain_configuration_errors() {
    let app = calls_in_start();
    let plan = Plan::parse(r#"{"get":{"return":"not a number"}}"#).unwrap();
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::PlanError, "{:?}", run.outcome);
    assert_eq!(run.events.len(), 1);
    assert!(run.totals.fuel > 10000);
}

fn platform_module(wat: &str, plugin: bool) -> App {
    use appfuzz_core::host_manifest::{HostManifest, merge};
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-startup-{}-{plugin}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let platform = if plugin {
        std::fs::write(dir.join("startup.wit"), "package test:startup; world plugin { export run: func(); }").unwrap();
        "[platform]\nname = 'startup'\nabi = 'extism'\nwit = 'startup.wit'"
    } else {
        std::fs::write(dir.join("startup.witx"), "(module $host (@interface func (export \"ping\")))").unwrap();
        "[platform]\nname = 'startup'\nwitx = ['startup.witx']\nstart = '_start'\nentry_wit = 'run: func();'\n[entry]\nexport = 'entry#run'"
    };
    let host = HostManifest::parse(platform, &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("startup.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn plain_module_startup_traps_are_classified_and_metered() {
    let app = platform_module(r#"(module (memory 1) (func $init unreachable) (start $init) (func (export "_start")))"#, false);
    let run = app.run(&app.spec(app.export("entry#run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Unreachable, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, 65536);
    assert!(run.totals.fuel > 0);
    assert!(!run.outcome.stack.is_empty());
}

#[test]
fn a_plain_module_can_exit_successfully_during_startup() {
    let app = platform_module(
        r#"(module
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (func $init (call $exit (i32.const 0))) (start $init)
      (func (export "_start") unreachable))"#,
        false,
    );
    let run = app.run(&app.spec(app.export("entry#run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, 65536);
    assert!(run.totals.fuel > 0);
}

#[test]
fn plugin_startup_traps_are_classified_and_metered() {
    let app = platform_module(r#"(module (memory 1) (func $init unreachable) (start $init) (func (export "run") (result i32) (i32.const 0)))"#, true);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Unreachable, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, 17 * 65_536);
    assert!(run.totals.fuel > 0);
    assert!(!run.outcome.stack.is_empty());
}
