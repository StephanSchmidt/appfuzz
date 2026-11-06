use appfuzz_core::{detect, harness::App, manifest::Manifest, plan::Plan};

fn build(body: &str, limit_ms: f64) -> App {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("latency.wasm"));
    manifest.limits.max_latency_ms = Some(limit_ms);
    let bytes = wat::parse_str(format!(
        r#"(component
        (import "test:latency/host" (instance $host (export "get" (func (result u32)))))
        (core func $get (canon lower (func $host "get")))
        (core module $m (import "host" "get" (func $get (result i32)))
            (func (export "run") (result i32) (local $i i32) {body} (i32.const 7)))
        (core instance $m (instantiate $m (with "host" (instance (export "get" (func $get))))))
        (func (export "run") (result u32) (canon lift (core func $m "run"))))"#
    ))
    .unwrap();
    App::from_bytes(manifest, bytes).unwrap()
}

fn run(calls: usize, latency_ms: f64, limit_ms: f64) -> (appfuzz_core::record::RunRecord, Manifest) {
    let app = build(&"(drop (call $get))".repeat(calls), limit_ms);
    let plan = Plan::parse(&serde_json::json!({"test:latency/host#get":{"return":1,"latency_ms":latency_ms}}).to_string()).unwrap();
    let mut spec = app.spec(app.export("run").unwrap(), vec![], plan, 1);
    spec.ns_per_fuel = 0.0;
    (app.run(&spec), app.manifest.clone())
}

#[test]
fn a_single_huge_host_latency_cannot_hide_above_the_clock_range() {
    let (record, manifest) = run(1, 1e30, 1e20);
    assert!(detect::per_run(&record, &manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "latency_ms"), "{:?}", record.totals);
}

#[test]
fn accumulated_host_latency_cannot_hide_above_the_clock_range() {
    let (record, manifest) = run(2, 1e13, 1.9e13);
    assert!(detect::per_run(&record, &manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "latency_ms"), "{:?}", record.totals);
}

#[test]
fn all_finite_latency_rates_preserve_totals_and_equal_limits() {
    use appfuzz_core::natural::Natural;
    for latency in [0.0, 0.000_000_1, 0.000_001, 1.234_567, 1e13, 1e30, 1e200, f64::MAX] {
        let (record, manifest) = run(1, latency, latency);
        let expected = Natural::from_scaled_f64(latency, 1_000_000);
        assert_eq!(record.events[0].latency_ns, expected);
        assert_eq!(record.totals.host_ns, expected);
        assert_eq!(record.totals.virtual_ns, expected);
        assert!(!detect::per_run(&record, &manifest).iter().any(|f| f.kind == "over_budget"), "{latency}");
        let wire = serde_json::to_value(&record).unwrap();
        let restored: appfuzz_core::record::RunRecord = serde_json::from_value(wire.clone()).unwrap();
        let trace: appfuzz_core::envelope::Trace = serde_json::from_value(wire).unwrap();
        assert_eq!(restored.totals.virtual_ns, expected);
        assert_eq!(trace.to_record().totals.host_ns, expected);
        let point = appfuzz_core::scale::Point::of(1, &record);
        assert_eq!(point.virtual_ns, expected);
        assert_eq!(appfuzz_core::fuzz::metrics(&record).iter().find(|(name, _)| name == "virtual_ns").unwrap().1, expected);
    }
}

#[test]
fn latency_checks_keep_the_first_nanosecond_above_a_huge_boundary() {
    let (mut record, manifest) = run(1, 1e30, 1e30);
    record.totals.virtual_ns += 1u64.into();
    assert!(detect::per_run(&record, &manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "latency_ms"));
    let property = appfuzz_core::check::Property::parse(&["max".into(), "virtual_ms".into(), "1e30".into()]).unwrap();
    let broken = property.broken(&record, &manifest).unwrap();
    assert!(broken.1["value"].is_string(), "{broken:?}");
}

#[test]
fn fuel_time_rates_keep_full_products_and_replay_deterministically() {
    use appfuzz_core::natural::Natural;
    let app = build("(drop (call $get))", 1e300);
    let plan = Plan::parse(r#"{"test:latency/host#get":{"return":1,"latency_ms":0}}"#).unwrap();
    let mut spec = app.spec(app.export("run").unwrap(), vec![], plan, 1);
    spec.ns_per_fuel = f64::MAX;
    let record = app.run(&spec);
    assert_eq!(record.totals.guest_ns, Natural::from_scaled_f64(f64::MAX, record.totals.fuel));
    assert!(record.totals.virtual_ns.exceeds_ms(1e300));
    assert_eq!(app.run(&spec).totals.virtual_ns, record.totals.virtual_ns);
    assert!(serde_json::to_value(&record).unwrap()["totals"]["guest_ns"].is_string());
}

#[test]
fn envelope_latency_margins_are_exact_for_new_and_legacy_budgets() {
    use appfuzz_core::{envelope::Envelope, natural::Natural};
    let (record, manifest) = run(1, 1e200, f64::MAX);
    let envelope = Envelope::build(std::slice::from_ref(&record), &manifest);
    let mut totals = record.totals.clone();
    totals.virtual_ns = totals.virtual_ns.clone() * 2;
    assert!(!envelope.check_budget(&totals).iter().any(|v| v.key == "virtual_ms"));
    totals.virtual_ns += 1u64.into();
    assert!(envelope.check_budget(&totals).iter().any(|v| v.key == "virtual_ms"));
    let restored: Envelope = serde_json::from_value(serde_json::to_value(envelope).unwrap()).unwrap();
    assert!(restored.check_budget(&totals).iter().any(|v| v.key == "virtual_ms"));
    let mut legacy = Envelope::default();
    legacy.budget.virtual_ms = 0.000_000_5;
    legacy.margin = 2.0;
    totals.virtual_ns = Natural::from(1u64);
    assert!(!legacy.check_budget(&totals).iter().any(|v| v.key == "virtual_ms"));
    totals.virtual_ns = Natural::from(2u64);
    assert!(legacy.check_budget(&totals).iter().any(|v| v.key == "virtual_ms"));
}

#[test]
fn timings_beyond_the_float_range_remain_exact_in_envelopes() {
    let (record, manifest) = run(2, f64::MAX, f64::MAX);
    assert!(record.totals.virtual_ns.ms_json().is_string());
    let envelope = appfuzz_core::envelope::Envelope::build(std::slice::from_ref(&record), &manifest);
    let restored: appfuzz_core::envelope::Envelope = serde_json::from_value(serde_json::to_value(envelope).unwrap()).unwrap();
    assert_eq!(restored.budget.virtual_ns, Some(record.totals.virtual_ns.clone()));
    assert!(!restored.check_budget(&record.totals).iter().any(|v| v.key == "virtual_ms"));
}

#[test]
fn capture_guards_preserve_a_measured_latency_budget_violation() {
    let app = build(
        r#"(loop $again (drop (call $get))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (i32.const 65537))))"#,
        1e20,
    );
    let plan = Plan::parse(r#"{"test:latency/host#get":{"return":1,"latency_ms":1e30}}"#).unwrap();
    let record = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
    assert_eq!(record.outcome.kind, appfuzz_core::record::OutcomeKind::BudgetExceeded, "{:?}", record.outcome);
    assert!(!record.capture_limited);
    assert!(record.totals.virtual_ns.exceeds_ms(1e20));
}

#[test]
fn slow_host_comparisons_keep_a_nanosecond_over_a_large_limit() {
    use appfuzz_core::metamorphic::{self, Change, Variant};
    let app = build("(drop (call $get))", 1e30);
    let plan = Plan::parse(r#"{"test:latency/host#get":{"return":1,"latency_ms":1e29}}"#).unwrap();
    let spec = app.spec(app.export("run").unwrap(), vec![], plan, 1);
    let base = app.run(&spec);
    let mut variant = Variant { change: Change::Slow, func: Some("test:latency/host#get".into()), call: None, spec };
    variant.spec.plan.0.get_mut("test:latency/host#get").unwrap().response.latency_ms = Some(1e30);
    let slow = app.run(&variant.spec);
    assert!(slow.totals.virtual_ns.exceeds_ms(1e30));
    assert!(metamorphic::compare(&app, &base, &variant, &slow).iter().any(|f| f.kind == "slow_host_sensitivity"));
}

#[test]
fn slow_host_search_does_not_overflow_when_averaging_finite_latencies() {
    use appfuzz_core::metamorphic::{self, Change};
    let app = build(&"(drop (call $get))".repeat(10_000), 1e307);
    let plan = Plan::parse(r#"{"test:latency/host#get":{"return":1,"latency_ms":1e305}}"#).unwrap();
    let spec = app.spec(app.export("run").unwrap(), vec![], plan, 1);
    let record = app.run(&spec);
    let variants = metamorphic::variants(&app, &record);
    let slow = variants.iter().find(|v| v.change == Change::Slow).unwrap();
    let latency = slow.spec.plan.0["test:latency/host#get"].response.latency_ms.unwrap();
    assert_eq!(latency, 1e305 * 10.0);
    assert!(latency < f64::MAX);
}
