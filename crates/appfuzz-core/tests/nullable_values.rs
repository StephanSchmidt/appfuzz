use appfuzz_core::{
    dataset::Query,
    envelope::{Trace, TraceCall},
    plan::{Decision, Plan},
    record::RunRecord,
};
use serde_json::{Value, json};

#[test]
fn stored_export_and_host_results_distinguish_null_from_absence() {
    for result in [None, Some(Value::Null), Some(json!(7))] {
        let trace = Trace {
            result: result.clone(),
            events: vec![TraceCall { func: "host#call".into(), result: result.clone(), ..Default::default() }],
            ..Default::default()
        };
        let record = trace.to_record();
        let restored: RunRecord = serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        assert_eq!(restored.result, result, "export result");
        assert_eq!(restored.events[0].result, result, "host result");
    }
}
#[test]
fn trace_roundtrips_distinguish_null_returns_and_missing_results() {
    for result in [None, Some(Value::Null), Some(json!(7))] {
        let trace = Trace { result: result.clone(), events: vec![TraceCall { result: result.clone(), ..Default::default() }], ..Default::default() };
        let restored: Trace = serde_json::from_slice(&serde_json::to_vec(&trace).unwrap()).unwrap();
        assert_eq!(restored.result, result);
        assert_eq!(restored.events[0].result, result);
    }
}
#[test]
fn explicit_null_plan_responses_keep_their_precedence_and_roundtrip() {
    for entry in [
        json!({"return":null}),
        json!({"return":1,"on_call":{"1":{"return":null}}}),
        json!({"return":1,"rules":[{"when":{},"return":null}]}),
        json!({"return":1,"default":{"return":null}}),
    ] {
        let p = Plan::parse(&json!({"host#get":entry}).to_string()).unwrap();
        assert!(matches!(p.resolve("host#get", 1, &[]).decision, Decision::Return(Value::Null)), "{p:?}");
        let restored: Plan = serde_json::from_slice(&serde_json::to_vec(&p).unwrap()).unwrap();
        assert!(matches!(restored.resolve("host#get", 1, &[]).decision, Decision::Return(Value::Null)));
    }
    assert!(matches!(Plan::default().resolve("host#get", 1, &[]).decision, Decision::Generate(_)));
}
#[test]
fn a_null_dataset_missing_response_does_not_fall_back_to_wrapping() {
    let q: Query = serde_json::from_value(json!({"dataset":"rows","one":true,"wrap":"ok","missing":null})).unwrap();
    let world = std::collections::BTreeMap::from([("rows".into(), vec![])]);
    assert_eq!(q.resolve(&world, &[]).unwrap(), Value::Null);
    let restored: Query = serde_json::from_slice(&serde_json::to_vec(&q).unwrap()).unwrap();
    assert_eq!(restored.resolve(&world, &[]).unwrap(), Value::Null);
}
