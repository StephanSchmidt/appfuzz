//! Client-visible output remains evidence when execution fails after sending it.
use appfuzz_core::{
    auth, detect,
    envelope::Trace,
    manifest::Manifest,
    record::{HostCall, OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn record(body: &str, headers: Value) -> (RunRecord, Manifest) {
    let mut r = Trace::default().to_record();
    r.spec.export = "run".into();
    r.spec.args = vec![json!({"method":"GET","uri":"https://app.example/","headers":[["origin","https://attacker.example"]],"body":""})];
    r.outcome.kind = OutcomeKind::Unreachable;
    r.result = Some(json!({"status":200,"headers":headers,"body":body}));
    let mut m = Manifest::for_wasm(std::path::Path::new("sent.wasm"));
    m.entry = Some(
        serde_json::from_value(
            json!({"export":"run","output":{"status":"status","headers":"headers","body":"body","body_format":"html"},"result":{"body":"html:safe"}}),
        )
        .unwrap(),
    );
    (r, m)
}
fn event(n: u32, func: &str, result: Value) -> HostCall {
    serde_json::from_value(
        json!({"n":n,"func":func,"call":1,"args":{},"result":result,"source":"plan","granted":true,"latency_ns":0,"cost":0,"fuel_before":0,"t_ns":0}),
    )
    .unwrap()
}
#[test]
fn failed_execution_does_not_exempt_sent_markup_or_destinations() {
    let (r, m) = record("<script>alert(1)</script><img src='http://127.0.0.1/admin'>", json!([]));
    let f = detect::per_run(&r, &m);
    assert!(f.iter().any(|f| f.kind == "script_in_output"), "{f:?}");
    assert!(f.iter().any(|f| f.kind == "unexpected_destination"), "{f:?}");
}
#[test]
fn failed_execution_does_not_exempt_sent_cors_headers() {
    let (r, m) = record("private page", json!([["access-control-allow-origin", "https://attacker.example"], ["access-control-allow-credentials", "true"]]));
    let f = detect::per_run(&r, &m);
    assert!(f.iter().any(|f| f.kind == "permissive_cors"), "{f:?}");
}
#[test]
fn failed_execution_cannot_hide_someone_elses_record_already_sent() {
    let (mut r, mut m) = record("foreign record contents", json!([]));
    m.functions.insert("who".into(), serde_json::from_value(json!({"result":"identity"})).unwrap());
    m.functions.insert("records".into(), serde_json::from_value(json!({"result":{"owner":"owner"}})).unwrap());
    r.events = vec![event(1, "who", json!("caller")), event(2, "records", json!({"owner":"other","text":"foreign record contents"}))];
    let f = detect::per_run(&r, &m);
    assert!(f.iter().any(|f| f.kind == "missing_owner_check"), "{f:?}");
}
#[test]
fn failed_execution_cannot_hide_success_response_after_partial_writes() {
    let (mut r, mut m) = record("Saved", json!([]));
    for function in ["save", "charge"] {
        m.functions.insert(function.into(), serde_json::from_value(json!({"effect":"write"})).unwrap());
    }
    r.events = vec![event(1, "save", json!({"ok":null})), event(2, "charge", json!({"err":"charge declined"}))];
    let f = detect::per_run(&r, &m);
    assert!(f.iter().any(|f| f.kind == "partial_write"), "{f:?}");
}
#[test]
fn failed_execution_keeps_sent_authentication_statuses_and_tokens() {
    let (mut anon, m) = record("Sign in", json!([]));
    anon.result.as_mut().unwrap()["status"] = json!(401);
    let (accepted, _) = record("Welcome", json!([["set-cookie", "session=fixed-session-token; HttpOnly"]]));
    assert_eq!(auth::rejected(&anon, &m), Some(401));
    let forged = auth::forged(&anon.spec.args[0]);
    assert!(!forged.is_empty());
    assert!(auth::check(&anon, &[(&forged[0], &accepted)], &m).is_some());
    assert!(auth::tokens(&accepted, &m).iter().any(|(_, s)| s == "fixed-session-token"));
}
#[test]
fn a_trap_without_sent_output_does_not_invent_client_evidence() {
    let (mut r, m) = record("", json!([]));
    r.result = None;
    assert_eq!(auth::rejected(&r, &m), None);
    assert!(auth::tokens(&r, &m).is_empty());
    let f = detect::per_run(&r, &m);
    for kind in ["script_in_output", "unexpected_destination", "permissive_cors", "missing_owner_check", "partial_write"] {
        assert!(!f.iter().any(|f| f.kind == kind), "{f:?}");
    }
}

#[test]
fn an_error_status_does_not_authorize_showing_another_users_record() {
    let (mut r, mut m) = record("foreign record contents", json!([]));
    r.outcome.kind = OutcomeKind::Ok;
    r.result.as_mut().unwrap()["status"] = json!(403);
    m.functions.insert("who".into(), serde_json::from_value(json!({"result":"identity"})).unwrap());
    m.functions.insert("records".into(), serde_json::from_value(json!({"result":{"owner":"owner"}})).unwrap());
    r.events = vec![event(1, "who", json!("caller")), event(2, "records", json!({"owner":"other","text":"foreign record contents"}))];
    assert!(detect::per_run(&r, &m).iter().any(|f| f.kind == "missing_owner_check"));
}
