use appfuzz_core::{
    detect::Severity,
    envelope::Trace,
    harness::App,
    labels::{self, Label},
    manifest::Manifest,
    plan::Plan,
    record::{HostCall, OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

const SECRET: &str = "sk_private_output_0123456789";
const SOURCE: &str = "test:payload/config#key";
const SINK: &str = "test:payload/report#send";

fn manifest(label: &str) -> Manifest {
    serde_json::from_value(json!({
        "app":{"wasm":"a.wasm"},
        "entry":{"export":"run","output":{"body":"body","headers":"headers","status":"status","body_format":"text"}},
        "functions":{SOURCE:{"result":label},SINK:{"effect":"external"}}
    }))
    .unwrap()
}

fn event(n: u32, func: &str, args: Value, result: Value) -> HostCall {
    serde_json::from_value(
        json!({"n":n,"func":func,"call":1,"args":args,"result":result,"source":"plan","granted":true,"latency_ns":0,"cost":0,"fuel_before":0,"t_ns":0}),
    )
    .unwrap()
}

fn record() -> RunRecord {
    let mut r = Trace::default().to_record();
    r.spec.export = "run".into();
    r.spec.args = vec![json!({"query":[["value",SECRET]]})];
    r.events = vec![event(1, SOURCE, json!({}), json!(SECRET))];
    r.result = Some(json!({"status":200,"headers":[["x-echo",SECRET]],"body":SECRET,"extra":SECRET}));
    r
}

#[test]
fn native_request_match_cannot_hide_a_host_secret_sent_to_an_external_function() {
    let mut m = manifest("secret");
    m.entry.as_mut().unwrap().output.status = None;
    m.entry.as_mut().unwrap().output.headers = None;
    let app = App::from_bytes(m, wat::parse_str(include_str!("fixtures/request_echo.wat")).unwrap()).unwrap();
    let plan = Plan::parse(&json!({SOURCE:{"return":SECRET}}).to_string()).unwrap();
    let runs: Vec<_> =
        ["public input", SECRET].into_iter().map(|input| app.run(&app.spec(app.default_export().unwrap(), vec![json!(input)], plan.clone(), 1))).collect();
    for r in &runs {
        assert_eq!(r.outcome.kind, OutcomeKind::Ok);
        assert_eq!(r.events[1].func, SINK);
        assert_eq!(r.events[1].args["value"], SECRET);
        assert_eq!(r.result.as_ref().unwrap()["metadata"], SECRET);
        let findings = labels::check(r, &app.manifest);
        assert!(findings.iter().any(|f| f.kind == "secret_leak" && f.severity == Severity::Fail && f.detail["n"] == 2), "{findings:?}");
    }
    assert_eq!(serde_json::to_value(&runs[0].events).unwrap(), serde_json::to_value(&runs[1].events).unwrap());
    assert_eq!(runs[0].result, runs[1].result);
}

#[test]
fn request_matches_still_fail_in_logs_and_guest_errors() {
    for label in ["pii", "secret"] {
        let mut r = record();
        r.stdout = SECRET.into();
        r.stderr = SECRET.into();
        r.guest_error = Some(SECRET.into());
        let f = labels::check(&r, &manifest(label));
        for place in ["the log (stdout)", "the log (stderr)", "the guest error"] {
            assert!(f.iter().any(|f| f.severity == Severity::Fail && f.detail["place"] == place), "{label} {place}: {f:?}");
        }
    }
}

#[test]
fn request_matches_preserve_response_echoes_but_obey_no_pii() {
    let r = record();
    for label in ["pii", "secret"] {
        let mut m = manifest(label);
        assert!(labels::check(&r, &m).is_empty());
        m.entry.as_mut().unwrap().no_pii = true;
        let f = labels::check(&r, &m);
        if label == "pii" {
            assert_eq!(f.len(), 3, "{f:?}");
            assert!(f.iter().all(|f| f.kind == "pii_leak" && f.severity == Severity::Fail));
        } else {
            assert!(f.is_empty(), "no_pii does not change the policy for secrets: {f:?}");
        }
    }
}

#[test]
fn request_matches_do_not_change_which_parameters_may_receive_private_values() {
    for (name, label, other) in [("secret", Label::Secret, Label::Pii), ("pii", Label::Pii, Label::Secret)] {
        let mut r = record();
        r.events.push(event(2, SINK, json!({"value":SECRET}), Value::Null));
        let mut m = manifest(name);
        for allowed in [None, Some(other), Some(label)] {
            m.functions.get_mut(SINK).unwrap().params = allowed.map(|l| [("value".into(), l)].into()).unwrap_or_default();
            let f = labels::check(&r, &m);
            assert_eq!(f.iter().any(|f| f.detail["n"] == 2 && f.severity == Severity::Fail), allowed != Some(label), "{name} {allowed:?}: {f:?}");
        }
        m.functions.get_mut(SOURCE).unwrap().result = None;
        m.functions.get_mut(SINK).unwrap().params.clear();
        assert!(labels::check(&r, &m).is_empty(), "text shape alone does not make a value private");
    }
}

#[test]
fn conditional_only_result_labels_are_checked_without_an_unconditional_label() {
    let mut r = record();
    r.spec.args = vec![json!("public input")];
    r.events[0].args.insert("name".into(), json!("api-token"));
    r.events.push(event(2, SINK, json!({"value":SECRET}), Value::Null));
    let mut m = manifest("secret");
    let source = m.functions.get_mut(SOURCE).unwrap();
    source.result = None;
    source.rules.push(serde_json::from_value(json!({"when":{"name":"api-token"},"result":"secret"})).unwrap());
    assert_eq!(m.call_result_labels(SOURCE, &r.events[0].args), vec![(String::new(), Label::Secret)]);
    let f = labels::check(&r, &m);
    assert!(f.iter().any(|f| f.kind == "secret_leak" && f.detail["n"] == 2), "{f:?}");
    r.events[0].args.insert("name".into(), json!("public-setting"));
    assert!(labels::check(&r, &m).is_empty(), "unmatched conditional labels must remain inactive");
}
