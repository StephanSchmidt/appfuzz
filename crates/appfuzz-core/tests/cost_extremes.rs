use appfuzz_core::{
    check::Property,
    detect,
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;

fn app(calls: u32) -> App {
    app_body(&"(drop (call $get))".repeat(calls as usize))
}

fn app_body(body: &str) -> App {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("costs.wasm"));
    manifest.limits.cost_per_request = Some(u64::MAX);
    let bytes = wat::parse_str(format!(
        r#"(component
        (import "test:costs/host" (instance $host (export "get" (func (result u32)))))
        (core func $get (canon lower (func $host "get")))
        (core module $m (import "host" "get" (func $get (result i32)))
            (func (export "run") (result i32) (local $i i32) {body} (i32.const 7)))
        (core instance $m (instantiate $m (with "host" (instance (export "get" (func $get))))))
        (func (export "run") (result u32) (canon lift (core func $m "run"))))"#
    ))
    .unwrap();
    App::from_bytes(manifest, bytes).unwrap()
}

fn run(app: &App) -> RunRecord {
    let plan = Plan::parse(r#"{"test:costs/host#get":{"return":1,"cost":18446744073709551615,"latency_ms":0}}"#).unwrap();
    app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1))
}

#[test]
fn a_cost_limit_at_u64_max_does_not_hide_a_second_charge() {
    let app = app(2);
    let record = run(&app);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok);
    assert_eq!(record.result, Some(json!(7)));
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "cost"));
}

#[test]
fn totals_keep_every_charge_beyond_u64_and_roundtrip_as_json() {
    let app = app(2);
    let record = run(&app);
    let expected = 2 * u128::from(u64::MAX);
    assert_eq!(record.totals.cost, expected);
    let bytes = serde_json::to_vec(&record).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["totals"]["cost"].as_str(), Some(expected.to_string().as_str()));
    let restored: RunRecord = serde_json::from_value(value).unwrap();
    assert_eq!(restored.totals.cost, expected);
    let property = Property::parse(&["max".into(), "cost".into(), u64::MAX.to_string()]).unwrap();
    assert!(property.broken(&record, &app.manifest).is_some());
}

#[test]
fn a_single_charge_equal_to_u64_max_is_still_within_budget() {
    let app = app(1);
    let record = run(&app);
    assert_eq!(record.totals.cost, u128::from(u64::MAX));
    assert!(!detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "over_budget"));
}

#[test]
fn trace_envelope_scaling_and_search_keep_the_exact_cost() {
    let app = app(2);
    let record = run(&app);
    let expected = 2 * u128::from(u64::MAX);
    let trace: appfuzz_core::envelope::Trace = serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();
    assert_eq!(trace.to_record().totals.cost, expected);
    let point = appfuzz_core::scale::Point::of(1, &record);
    assert_eq!(serde_json::to_value(point).unwrap()["cost"], expected.to_string());
    let metrics = appfuzz_core::fuzz::metrics(&record);
    assert_eq!(metrics.iter().find(|(name, _)| name == "cost").unwrap().1, expected);
    let envelope = appfuzz_core::envelope::Envelope::build(std::slice::from_ref(&record), &app.manifest);
    let restored: appfuzz_core::envelope::Envelope = serde_json::from_value(serde_json::to_value(envelope).unwrap()).unwrap();
    assert_eq!(restored.budget.cost, expected);
}

#[test]
fn envelope_cost_margins_do_not_round_away_the_first_excess_charge() {
    let app = app(1);
    let record = run(&app);
    let envelope = appfuzz_core::envelope::Envelope::build(std::slice::from_ref(&record), &app.manifest);
    let mut totals = record.totals.clone();
    totals.cost = 2 * u128::from(u64::MAX);
    assert!(!envelope.check_budget(&totals).iter().any(|v| v.key == "cost"));
    totals.cost += 1;
    assert!(envelope.check_budget(&totals).iter().any(|v| v.key == "cost"));
}

#[test]
fn envelope_integer_margins_preserve_large_boundary_values() {
    let mut envelope = appfuzz_core::envelope::Envelope { margin: 2.0, ..Default::default() };
    envelope.budget.fuel = 1 << 53;
    let mut totals = appfuzz_core::record::Totals { fuel: (1 << 54) + 1, ..Default::default() };
    assert!(envelope.check_budget(&totals).iter().any(|v| v.key == "fuel"));
    totals.fuel -= 1;
    assert!(!envelope.check_budget(&totals).iter().any(|v| v.key == "fuel"));
    envelope.budget.cost = 10;
    envelope.margin = 1.25;
    totals.cost = 12;
    assert!(!envelope.check_budget(&totals).iter().any(|v| v.key == "cost"));
    totals.cost = 13;
    assert!(envelope.check_budget(&totals).iter().any(|v| v.key == "cost"));
}

#[test]
fn capture_guards_keep_a_proven_cost_overrun_at_the_maximum_limit() {
    let app = app_body(
        r#"(loop $again (drop (call $get))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (i32.const 65537))))"#,
    );
    let record = run(&app);
    assert_eq!(record.outcome.kind, OutcomeKind::BudgetExceeded, "{:?}", record.outcome);
    assert!(!record.capture_limited);
    assert!(record.totals.cost > u128::from(u64::MAX));
    assert_eq!(record.totals.cost, record.events.len() as u128 * u128::from(u64::MAX));
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "cost"));
}

#[test]
fn exact_cost_wire_values_preserve_boundaries_and_reject_lossy_inputs() {
    for value in [0, 1, u128::from(u64::MAX), u128::from(u64::MAX) + 1, u128::MAX] {
        let totals = appfuzz_core::record::Totals { cost: value, ..Default::default() };
        let serialized = serde_json::to_value(&totals).unwrap();
        assert_eq!(serialized["cost"].is_number(), value <= u128::from(u64::MAX));
        assert_eq!(serde_json::from_value::<appfuzz_core::record::Totals>(serialized).unwrap().cost, value);
    }
    for invalid in [json!(-1), json!(1.5), json!("-1"), json!("1.5"), json!("1e20"), json!("340282366920938463463374607431768211456")] {
        let mut serialized = serde_json::to_value(appfuzz_core::record::Totals::default()).unwrap();
        serialized["cost"] = invalid;
        assert!(serde_json::from_value::<appfuzz_core::record::Totals>(serialized).is_err());
    }
}
