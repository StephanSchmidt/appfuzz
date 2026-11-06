use appfuzz_core::{harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
fn app(cleanup: &str) -> App {
    let bytes = wat::parse_str(format!(
        r#"(component
        (core module $m
            (func (export "run") (result i32) (i32.const 7))
            (func (export "cleanup") (param i32) {cleanup}))
        (core instance $m (instantiate $m))
        (func (export "run") (result u32) (canon lift (core func $m "run") (post-return (core func $m "cleanup")))))"#
    ))
    .unwrap();
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("cleanup.wasm")), bytes).unwrap()
}
#[test]
fn automatic_component_cleanup_receives_the_returned_value() {
    let app = app("(if (i32.ne (local.get 0) (i32.const 7)) (then unreachable))");
    let record = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(serde_json::json!(7)));
}
#[test]
fn automatic_component_cleanup_traps_are_detected() {
    let app = app("unreachable");
    let record = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
}

#[test]
fn automatic_component_cleanup_spends_the_runs_fuel() {
    let app = app("(loop $forever (br $forever))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.fuel = 1000;
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::OutOfFuel, "{:?}", record.outcome);
    assert_eq!(record.totals.fuel, 1000);
}
