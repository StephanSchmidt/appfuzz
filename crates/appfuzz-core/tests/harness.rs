//! End-to-end tests of the harness on small components built from WAT.

use appfuzz_core::harness::App;
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use appfuzz_core::record::OutcomeKind;
use appfuzz_core::statics::Statics;
use serde_json::json;

#[test]
fn identical_module_interfaces_do_not_confuse_crash_locations() {
    let bytes = wat::parse_str(
        r#"(component
      (core module $a (func (export "run") (result i32) (i32.const 7)))
      (core module $b (func (export "run") (result i32) unreachable))
      (core instance $ia (instantiate $a))
      (core instance $ib (instantiate $b))
      (func (export "safe") (result u32) (canon lift (core func $ia "run")))
      (func (export "crash") (result u32) (canon lift (core func $ib "run"))))"#,
    )
    .unwrap();
    let statics = Statics::parse(&bytes).unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("two-modules.wasm")), bytes).unwrap();
    let run = app.run(&app.spec(app.export("crash").unwrap(), vec![], Plan::default(), 1));
    assert_ne!(statics.modules[0].id, statics.modules[1].id);
    assert_eq!(run.outcome.stack[0].module, statics.modules[1].id);
    let mut legacy = run.outcome.stack[0].clone();
    legacy.module = statics.modules[0].id.clone();
    assert_eq!(statics.frame_module(&legacy).unwrap().id, statics.modules[1].id);
}

#[test]
fn identical_module_interfaces_preserve_host_call_provenance() {
    let bytes = wat::parse_str(
        r#"(component
      (import "get" (func $get (result u32)))
      (core func $lower (canon lower (func $get)))
      (core instance $host (export "get" (func $lower)))
      (core module $a (import "host" "get" (func $get (result i32)))
        (func (export "run") (result i32) (drop (call $get)) (i32.const 7)))
      (core module $b (import "host" "get" (func $get (result i32)))
        (func (export "run") (result i32) (drop (call $get)) (i32.const 9)))
      (core instance $ia (instantiate $a (with "host" (instance $host))))
      (core instance $ib (instantiate $b (with "host" (instance $host))))
      (func (export "first") (result u32) (canon lift (core func $ia "run")))
      (func (export "second") (result u32) (canon lift (core func $ib "run"))))"#,
    )
    .unwrap();
    let statics = Statics::parse(&bytes).unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("two-modules.wasm")), bytes).unwrap();
    for (index, export, result) in [(0, "first", 7), (1, "second", 9)] {
        let run = app.run(&app.spec(app.export(export).unwrap(), vec![], Plan::default(), 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        assert_eq!(run.result, Some(json!(result)));
        assert_eq!(run.events.len(), 1);
        assert_eq!(run.events[0].stack[0].module, statics.modules[index].id);
        let frame = &run.events[0].stack[0];
        let module = statics.module(&frame.module).unwrap();
        let offset = frame.offset.unwrap() as u64;
        assert!(module.start <= offset && offset < module.end);
    }
}

#[test]
fn nested_components_keep_absolute_crash_module_locations() {
    let bytes = wat::parse_str(
        r#"(component
      (component $child
        (core module $a (func (export "run") (result i32) (i32.const 7)))
        (core module $b (func (export "run") (result i32) unreachable))
        (core instance $ia (instantiate $a))
        (core instance $ib (instantiate $b))
        (func (export "safe") (result u32) (canon lift (core func $ia "run")))
        (func (export "crash") (result u32) (canon lift (core func $ib "run"))))
      (instance $child-instance (instantiate $child))
      (alias export $child-instance "crash" (func $crash))
      (export "crash" (func $crash)))"#,
    )
    .unwrap();
    let statics = Statics::parse(&bytes).unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("nested-modules.wasm")), bytes).unwrap();
    let run = app.run(&app.spec(app.export("crash").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Unreachable);
    assert_ne!(statics.modules[0].id, statics.modules[1].id);
    assert_eq!(run.outcome.stack[0].module, statics.modules[1].id);
    let offset = run.outcome.stack[0].offset.unwrap() as u64;
    assert!(statics.modules[1].start <= offset && offset < statics.modules[1].end);
}

const WIT: &str = r#"
package test:app@0.1.0;

interface db {
    get: func(id: u32) -> u32;
}

world app {
    import db;
    export run: func(n: u32) -> u32;
    export spin: func(n: u32) -> u32;
    export crash: func(n: u32) -> u32;
}
"#;

const WAT: &str = r#"
(module
  (import "test:app/db@0.1.0" "get" (func $get (param i32) (result i32)))
  (memory (export "memory") 1)
  ;; Calls db.get once per item: a textbook n+1.
  (func (export "run") (param $n i32) (result i32) (local $i i32) (local $acc i32)
    (block $done
      (loop $next
        (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
        (local.set $acc (i32.add (local.get $acc) (call $get (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $next)))
    (local.get $acc))
  (func (export "spin") (param i32) (result i32)
    (loop $forever (br $forever))
    (unreachable))
  (func (export "crash") (param i32) (result i32)
    (unreachable))
)
"#;

fn component() -> Vec<u8> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("test.wit", WIT).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(WAT).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}

fn app() -> App {
    let mut m = Manifest::for_wasm(std::path::Path::new("test.wasm"));
    m.limits.fuel = 1_000_000;
    m.limits.wall_timeout_ms = 2_000;
    App::from_bytes(m, component()).unwrap()
}

#[test]
fn invalid_timing_contracts_are_rejected_before_execution() {
    for limits in ["max_latency_ms=nan", "max_latency_ms=inf", "max_latency_ms=-1", "default_host_latency_ms=-1", "ns_per_fuel=nan", "ns_per_fuel=-1"] {
        let manifest = toml::from_str(&format!("[app]\nwasm='test.wasm'\n[limits]\n{limits}\n")).unwrap();
        assert!(App::from_bytes(manifest, component()).is_err(), "accepted {limits}");
    }
    for declaration in ["latency_ms=nan", "latency_ms=-1", "rules=[{when={},return=1,latency_ms=inf}]"] {
        let manifest = toml::from_str(&format!("[app]\nwasm='test.wasm'\n[functions.\"test:app/db#get\"]\n{declaration}\n")).unwrap();
        assert!(App::from_bytes(manifest, component()).is_err(), "accepted {declaration}");
    }
    let app = app();
    for rate in [f64::NAN, f64::INFINITY, -1.0] {
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(1)], Plan::default(), 1);
        spec.ns_per_fuel = rate;
        assert_eq!(app.run(&spec).outcome.kind, OutcomeKind::Error);
    }
}

#[test]
fn huge_guest_sleeps_do_not_wrap_the_virtual_clock() {
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_str("io.wit", "package wasi:io@0.2.12; interface poll { resource pollable { block:func(); } }").unwrap();
    resolve.push_str("clocks.wit", "package wasi:clocks@0.2.12; interface monotonic-clock { use wasi:io/poll@0.2.12.{pollable}; subscribe-duration:func(when:u64)->pollable; now:func()->u64; }").unwrap();
    let pkg = resolve
        .push_str(
            "sleep.wit",
            "package test:sleep; world app { import wasi:io/poll@0.2.12; import wasi:clocks/monotonic-clock@0.2.12; export run:func()->u64; }",
        )
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(
        r#"(module
        (import "wasi:clocks/monotonic-clock@0.2.12" "subscribe-duration" (func $sleep (param i64) (result i32)))
        (import "wasi:clocks/monotonic-clock@0.2.12" "now" (func $now (result i64)))
        (import "wasi:io/poll@0.2.12" "[method]pollable.block" (func $block (param i32)))
        (func (export "run") (result i64)
            (call $block (call $sleep (i64.const -1)))
            (call $block (call $sleep (i64.const 1)))
            (call $now)))"#,
    )
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("sleep.wasm")), bytes).unwrap();
    let spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(u64::MAX)));
    assert_eq!(record.totals.sleep_ns, u64::MAX);
    assert_eq!(record.totals.virtual_ns, u64::MAX);
    assert_eq!(record.totals.clock_reads, 1);
}

#[test]
fn huge_host_latency_and_cost_remain_over_budget_without_overflow() {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("test.wasm"));
    manifest.limits.max_latency_ms = Some(200.0);
    manifest.limits.cost_per_request = Some(100);
    let app = App::from_bytes(manifest, component()).unwrap();
    let plan = Plan::parse(r#"{"test:app/db#get":{"return":1,"latency_ms":1e30,"cost":18446744073709551615}}"#).unwrap();
    let spec = app.spec(app.export("run").unwrap(), vec![json!(10)], plan, 1);
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(10)));
    assert_eq!(record.totals.virtual_ns, u64::MAX);
    assert_eq!(record.totals.cost, u64::MAX);
    assert_eq!(record.events.len(), 10);
    let findings = appfuzz_core::detect::per_run(&record, &app.manifest);
    assert!(findings.iter().any(|f| f.kind == "over_budget"), "{findings:?}");
    assert!(findings.iter().any(|f| f.kind == "serial_chain"), "{findings:?}");
}

#[test]
fn records_every_host_call() {
    let app = app();
    let run = app.export("run").unwrap().clone();
    let plan = Plan::parse(r#"{"test:app/db#get": {"rules": [{"when": {"id": 2}, "return": 100}], "default": {"return": 1}}}"#).unwrap();
    let r = app.run(&app.spec(&run, vec![json!(5)], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result, Some(json!(104)));
    assert_eq!(r.totals.host_calls, 5);
    assert_eq!(r.events[2].args["id"], json!(2));
    assert_eq!(r.events[2].source, "rule 0");
    // 5 calls at the default 1ms latency.
    assert_eq!(r.totals.host_ns, 5_000_000);
    // The stack points into the main module's `run`.
    let st = Statics::parse(&app.bytes).unwrap();
    let f = st.app_frame(&r.events[0].stack).unwrap();
    assert_eq!(st.module(&f.module).unwrap().role, "main");
}

#[test]
fn same_spec_same_record() {
    let app = app();
    let run = app.export("run").unwrap().clone();
    let spec = app.spec(&run, vec![json!(7)], Plan::default(), 3);
    let (a, b) = (app.run(&spec), app.run(&spec));
    assert_eq!(a.id, b.id);
    assert_eq!(serde_json::to_value(&a.events).unwrap(), serde_json::to_value(&b.events).unwrap());
    assert_eq!(a.totals.fuel, b.totals.fuel);
}

#[test]
fn classifies_failures() {
    let app = app();
    let spin = app.export("spin").unwrap().clone();
    let r = app.run(&app.spec(&spin, vec![json!(0)], Plan::default(), 1));
    assert_eq!(r.outcome.kind, OutcomeKind::OutOfFuel);
    let crash = app.export("crash").unwrap().clone();
    let r = app.run(&app.spec(&crash, vec![json!(0)], Plan::default(), 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Unreachable);
    let run = app.export("run").unwrap().clone();
    let trap = Plan::parse(r#"{"test:app/db#get": {"on_call": {"3": {"trap": "gone"}}}}"#).unwrap();
    let r = app.run(&app.spec(&run, vec![json!(5)], trap, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::HostTrap);
    assert_eq!(r.totals.host_calls, 3);
    let bad = Plan::parse(r#"{"test:app/db#get": {"return": "nope"}}"#).unwrap();
    let r = app.run(&app.spec(&run, vec![json!(1)], bad, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::PlanError);
}

#[test]
fn statics_find_the_loop() {
    let app = app();
    let st = Statics::parse(&app.bytes).unwrap();
    let main = st.main().unwrap();
    let reach = main.host_reach();
    let looping: Vec<_> = main.funcs.iter().flat_map(|f| f.loops.iter()).filter(|l| l.calls.iter().any(|(c, _)| reach.contains_key(c))).collect();
    assert_eq!(looping.len(), 1);
}

#[test]
fn binary_feedback_preserves_execution_and_reports_internal_paths() {
    let app = app();
    let guide = appfuzz_core::feedback::Guide::new(&app).unwrap();
    let export = app.export("run").unwrap();
    let a = app.spec(export, vec![json!(0)], Plan::default(), 1);
    let b = app.spec(export, vec![json!(7)], Plan::default(), 1);
    let fa = guide.collect(&a).unwrap();
    let fb = guide.collect(&b).unwrap();
    assert!(!fa.hits.is_empty());
    assert_ne!(fa.hits, fb.hits);
    assert!(!fb.comparisons.is_empty());
    assert_eq!(app.run(&b).spec, b);
}
