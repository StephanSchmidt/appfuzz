//! End-to-end tests of the harness on small components built from WAT.

use appfuzz_core::harness::App;
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use appfuzz_core::record::OutcomeKind;
use appfuzz_core::statics::Statics;
use serde_json::json;

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
    let looping: Vec<_> = main
        .funcs
        .iter()
        .flat_map(|f| f.loops.iter())
        .filter(|l| l.calls.iter().any(|(c, _)| reach.contains_key(c)))
        .collect();
    assert_eq!(looping.len(), 1);
}

#[test]
fn binary_feedback_preserves_execution_and_reports_internal_paths() {
    let app=app();
    let guide=appfuzz_core::feedback::Guide::new(&app).unwrap();
    let export=app.export("run").unwrap();
    let a=app.spec(export,vec![json!(0)],Plan::default(),1);
    let b=app.spec(export,vec![json!(7)],Plan::default(),1);
    let fa=guide.collect(&a).unwrap();
    let fb=guide.collect(&b).unwrap();
    assert!(!fa.hits.is_empty());
    assert_ne!(fa.hits,fb.hits);
    assert!(!fb.comparisons.is_empty());
    assert_eq!(app.run(&b).spec,b);
}
