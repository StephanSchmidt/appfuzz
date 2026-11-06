use appfuzz_core::{
    envelope::Trace,
    growth::{self, Class, Law},
    harness::App,
    manifest::Manifest,
    scale::{self, Knob, Point},
};

fn app(limit: u64) -> App {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("scaling.wasm"));
    manifest.limits.cost_per_request = Some(limit);
    let bytes = wat::parse_str(r#"(component (core module $m (func (export "run") (result i32) (i32.const 0))) (core instance $m (instantiate $m)) (func (export "run") (result u32) (canon lift (core func $m "run"))))"#).unwrap();
    App::from_bytes(manifest, bytes).unwrap()
}
fn costs(app: &App, values: &[u128]) -> scale::ScaleReport {
    let points = values
        .iter()
        .enumerate()
        .map(|(i, cost)| {
            let mut record = Trace::default().to_record();
            record.totals.cost = *cost;
            Point::of((i + 1) as u64, &record)
        })
        .collect();
    scale::analyze(app, Knob::Field("n".into()), points)
}

#[test]
fn measured_cost_breaks_survive_rounding_at_large_limits() {
    let app = app(i64::MAX as u64);
    let limit = i64::MAX as u128;
    let report = costs(&app, &[limit / 3, 2 * (limit / 3), limit + 1, limit + 1]);
    let growth = report.growth.iter().find(|g| g.metric == "cost").unwrap();
    assert_eq!(growth.law.class, Class::Capped);
    assert_eq!(growth.breaks_at, Some(3));
}

#[test]
fn measured_points_override_a_fitted_break_they_disprove() {
    let report = costs(&app(3), &[1, 2, 3, 5]);
    let growth = report.growth.iter().find(|g| g.metric == "cost").unwrap();
    assert_eq!(growth.breaks_at, Some(4), "{:?}", growth.law);
}

#[test]
fn large_finite_linear_measurements_still_produce_a_law() {
    let points: Vec<_> = [1.0, 2.0, 4.0, 8.0, 16.0].into_iter().map(|n| (n, 1e200 * n)).collect();
    let law = growth::fit(&points).expect("large finite measurements must not overflow fitting");
    assert_eq!(law.class, Class::Linear);
    for (n, y) in points {
        assert!((law.eval(n) / y - 1.0).abs() < 1e-12);
    }
}

#[test]
fn large_coefficients_are_not_clipped_to_signed_integers_in_text() {
    let points: Vec<_> = [1.0, 2.0, 4.0, 8.0, 16.0].into_iter().map(|n| (n, 1e30 * n)).collect();
    let law = growth::fit(&points).unwrap();
    assert!(!law.text.contains("9223372036854775807"), "{}", law.text);
}

#[test]
fn predicted_breaks_respect_a_zero_search_bound() {
    let law = Law { class: Class::Linear, a: 0.0, b: 1.0, text: "n".into(), fit: 1.0, normalization: None, time_scale_ns: None };
    assert_eq!(law.breaking_point(0.0, 0), None);
}

#[test]
fn coefficient_normalization_keeps_finite_curves_with_unrepresentable_intercepts() {
    let points = [(10.0, 0.0), (11.0, 2e307), (12.0, 4e307), (14.0, 8e307), (16.0, 1.2e308)];
    let law = growth::fit(&points).unwrap();
    assert_eq!(law.class, Class::Linear);
    assert!(law.normalization.is_some());
    assert!(law.eval(f64::NAN).is_nan());
    for (n, y) in points {
        assert!(law.eval(n).is_finite());
        assert!((law.eval(n) - y).abs() / 1.2e308 < 1e-12);
    }
    let wire = serde_json::to_value(&law).unwrap();
    assert!(wire["a"].is_string(), "{wire}");
    assert!(!wire["b"].is_null());
}

#[test]
fn very_small_linear_measurements_keep_nonzero_laws_and_text() {
    let points: Vec<_> = [1.0, 2.0, 4.0, 8.0, 16.0].into_iter().map(|n| (n, 1e-300 * n)).collect();
    let law = growth::fit(&points).unwrap();
    assert_eq!(law.class, Class::Linear);
    assert!(!law.text.starts_with("0·"), "{}", law.text);
    for (n, y) in points {
        assert!((law.eval(n) / y - 1.0).abs() < 1e-12);
    }
}

#[test]
fn prediction_search_does_not_wrap_at_the_largest_size_bound() {
    let law = Law { class: Class::Linear, a: 0.0, b: 1.0, text: "n".into(), fit: 1.0, normalization: None, time_scale_ns: None };
    assert_eq!(law.breaking_point(1e30, u64::MAX), None);
    assert_eq!(law.breaking_point(4.0, 3), None);
    assert_eq!(law.breaking_point(-1.0, 0), Some(0));
}

#[test]
fn measured_and_predicted_breaks_are_reported_separately() {
    let app = app(3);
    let points = [1u64, 2, 8]
        .into_iter()
        .map(|n| {
            let mut record = Trace::default().to_record();
            record.totals.cost = u128::from(n);
            Point::of(n, &record)
        })
        .collect();
    let report = scale::analyze(&app, Knob::Field("n".into()), points);
    let growth = report.growth.iter().find(|g| g.metric == "cost").unwrap();
    assert_eq!(growth.breaks_at, Some(8));
    assert_eq!(growth.predicted_breaks_at, Some(4));
    assert_eq!(growth.break_evidence, Some("measured"));
}

#[test]
fn failed_runs_do_not_disprove_an_inferred_budget_break() {
    let app = app(4);
    let mut points = Vec::new();
    for n in [1u64, 2, 3, 100] {
        let mut record = Trace::default().to_record();
        if n == 100 {
            record.outcome.kind = appfuzz_core::record::OutcomeKind::Error;
        } else {
            record.totals.cost = u128::from(n);
        }
        points.push(Point::of(n, &record));
    }
    let report = scale::analyze(&app, Knob::Field("n".into()), points);
    let growth = report.growth.iter().find(|g| g.metric == "cost").unwrap();
    assert_eq!(growth.breaks_at, Some(5));
    assert_eq!(growth.break_evidence, Some("inferred"));
}

#[test]
fn time_growth_keeps_measurements_beyond_the_float_millisecond_range() {
    use appfuzz_core::natural::Natural;
    let mut app = app(u64::MAX);
    app.manifest.limits.max_latency_ms = Some(f64::MAX);
    let unit = Natural::from_scaled_f64(1e308, 1_000_000);
    let points = [1u64, 2, 4, 8]
        .into_iter()
        .map(|n| {
            let mut record = Trace::default().to_record();
            record.totals.virtual_ns = unit.clone() * n;
            Point::of(n, &record)
        })
        .collect();
    let report = scale::analyze(&app, Knob::Field("n".into()), points);
    let growth = report.growth.iter().find(|g| g.metric == "virtual_ms").unwrap();
    assert_eq!(growth.law.class, Class::Linear);
    assert_eq!(growth.breaks_at, Some(2));
    assert_eq!(growth.break_evidence, Some("measured"));
    assert!((growth.law.eval(1.0) / 1e308 - 1.0).abs() < 1e-12);
    assert!(growth.law.eval(2.0).is_infinite());
    assert!(growth.law.eval(1e6).is_infinite());
    let wire = serde_json::to_value(growth).unwrap();
    assert!(wire["law"]["time_scale_ns"].is_string());
    assert!(wire["law"]["fit"].is_number());
}

#[test]
fn measured_fuel_memory_and_latency_breaks_use_exact_boundaries() {
    use appfuzz_core::natural::Natural;
    let mut app = app(u64::MAX);
    let integer_limit = 1u64 << 53;
    app.manifest.limits.fuel = integer_limit;
    app.manifest.limits.memory = integer_limit;
    app.manifest.limits.max_latency_ms = Some(1e30);
    let ns_limit = Natural::from_scaled_f64(1e30, 1_000_000);
    let points = (0..4)
        .map(|i| {
            let mut record = Trace::default().to_record();
            let value = match i {
                0 => integer_limit / 3,
                1 => 2 * (integer_limit / 3),
                _ => integer_limit + 1,
            };
            record.totals.fuel = value;
            record.totals.peak_memory = value;
            record.totals.virtual_ns = match i {
                0 => ns_limit.clone() / 3,
                1 => (ns_limit.clone() * 2) / 3,
                _ => ns_limit.clone() + Natural::from(1u64),
            };
            Point::of(i + 1, &record)
        })
        .collect();
    let report = scale::analyze(&app, Knob::Field("n".into()), points);
    for metric in ["fuel", "peak_memory", "virtual_ms"] {
        let growth = report.growth.iter().find(|g| g.metric == metric).unwrap();
        assert_eq!(growth.breaks_at, Some(3), "{metric}");
        assert_eq!(growth.break_evidence, Some("measured"));
    }
}
