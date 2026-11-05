//! Explicit performance checks: keep wall-clock assertions out of ordinary CI.
use std::time::{Duration, Instant};

use appfuzz_core::{
    envelope::{Envelope, Trace, TraceCall},
    manifest::Manifest,
    record::RunRecord,
};
use serde_json::json;

fn fixture(calls: usize, urls: bool) -> (Manifest, RunRecord) {
    let manifest: Manifest = toml::from_str("[app]\nwasm='fixture.wasm'\n[functions.\"a/http#fetch\"]\nparams={url='url'}\n").unwrap();
    let event = TraceCall {
        func: "a/http#fetch".into(),
        args: if urls { json!({"url":"https://api.example.com/data"}) } else { json!({"id":1}) }.as_object().unwrap().clone(),
        result: Some(json!("unrelated-value")),
        ..Default::default()
    };
    let run =
        Trace { component: "fixture".into(), contract: manifest.fingerprint(), export: "x#handle".into(), events: vec![event; calls], ..Default::default() }
            .to_record();
    (manifest, run)
}

fn fast(start: Instant) {
    let elapsed = start.elapsed();
    eprintln!("envelope operation took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "large trace validation rescans earlier calls: {elapsed:?}");
}

#[test]
#[ignore = "performance regression; run explicitly in release mode"]
fn counts_at_trace_capacity() {
    let (manifest, run) = fixture(65_536, false);
    let envelope = Envelope::build(std::slice::from_ref(&run), &manifest);
    let start = Instant::now();
    assert!(envelope.check(&run, &manifest).is_empty());
    fast(start);
}

#[test]
#[ignore = "performance regression; run explicitly in release mode"]
fn repeated_destinations_check() {
    let (manifest, run) = fixture(16_384, true);
    let (_, reviewed) = fixture(1, true);
    let mut envelope = Envelope::build(&[reviewed], &manifest);
    envelope.functions.get_mut("a/http#fetch").unwrap().max_calls = run.totals.host_calls;
    envelope.budget.host_calls = run.totals.host_calls;
    let start = Instant::now();
    assert!(envelope.check(&run, &manifest).is_empty());
    fast(start);
}

#[test]
#[ignore = "performance regression; run explicitly in release mode"]
fn repeated_destinations_build() {
    let (manifest, run) = fixture(16_384, true);
    let start = Instant::now();
    let envelope = Envelope::build(&[run], &manifest);
    fast(start);
    assert_eq!(envelope.functions["a/http#fetch"].max_calls, 16_384);
    assert!(envelope.functions["a/http#fetch"].destinations.contains("api.example.com:443"));
    assert!(!envelope.functions["a/http#fetch"].destinations_from_input);
}
