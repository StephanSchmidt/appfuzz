//! Sensitive values retain their origin through browser-triggered requests.
use appfuzz_core::{
    browser::{self, Session},
    detect,
    envelope::Trace,
    labels,
    manifest::Manifest,
    record::{HostCall, RunRecord},
};
use serde_json::{Value, json};
fn event(n: u32, func: &str, args: Value, result: Value) -> HostCall {
    serde_json::from_value(
        json!({"n":n,"func":func,"call":1,"args":args,"result":result,"source":"plan","granted":true,"latency_ns":0,"cost":0,"fuel_before":0,"t_ns":0}),
    )
    .unwrap()
}
fn run(id: &str, status: u32, body: &str) -> RunRecord {
    let mut r = Trace::default().to_record();
    r.id = id.into();
    r.spec.export = "handle".into();
    r.spec.args = vec![json!({"method":"GET","uri":"https://app.example/","headers":[],"body":""})];
    r.result = Some(json!({"status":status,"headers":[],"body":body}));
    r
}
fn fixture() -> (RunRecord, Session, Manifest) {
    let page = run("page", 200, "<script>fetch('/api')</script>");
    let session =
        Session { browser: run("visit", 200, ""), nested: vec![], report: json!({"url":"https://app.example/","errors":[]}), fragment: String::new() };
    let m=toml::from_str("[app]\nwasm='a.wasm'\n[entry]\nexport='handle'\noutput={status='status',headers='headers',body='body',body_format='html'}\n[functions.\"config#key\"]\nresult='secret'\n[functions.\"users#email\"]\nresult='pii'\n[functions.\"store#save\"]\nparams={auth='secret'}\n").unwrap();
    (page, session, m)
}
const SECRET: &str = "sk_private_backend_012345";
const EMAIL: &str = "person@mail.example";
#[test]
fn inherited_secrets_in_request_fields_still_fail_in_api_logs() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    let mut api = run("api", 200, "ok");
    api.spec.args[0]["body"] = json!(SECRET);
    api.stdout = SECRET.into();
    s.nested.push(api);
    let f = browser::check(&p, &s, &m);
    assert!(f.iter().any(|f| f.kind == "secret_leak" && f.detail["nested_run"] == "api"), "{f:?}");
}
#[test]
fn inherited_pii_is_allowed_in_a_page_but_not_a_later_error_page() {
    let (p, mut s, m) = fixture();
    let mut first = run("first", 200, EMAIL);
    first.events.push(event(1, "users#email", json!({}), json!(EMAIL)));
    s.nested.push(first);
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "pii_leak"));
    let mut error = run("error", 500, EMAIL);
    error.spec.args[0]["body"] = json!(EMAIL);
    s.nested.push(error);
    let f = browser::check(&p, &s, &m);
    assert!(f.iter().any(|f| f.kind == "pii_leak" && f.detail["nested_run"] == "error"), "{f:?}");
}
#[test]
fn inherited_values_obey_host_parameter_labels_and_output_policy() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    let mut api = run("api", 200, "ok");
    api.events.push(event(1, "store#save", json!({"auth":SECRET}), Value::Null));
    s.nested.push(api);
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "secret_leak"));
    s.nested[0].events[0].args.insert("other".into(), json!(SECRET));
    assert!(browser::check(&p, &s, &m).iter().any(|f| f.kind == "secret_leak"));
    s.nested[0].events.clear();
    s.nested[0].result.as_mut().unwrap()["body"] = json!(SECRET);
    assert!(browser::check(&p, &s, &m).iter().any(|f| f.kind == "secret_leak"));
}
#[test]
fn later_sources_do_not_taint_earlier_unrelated_server_logs() {
    let (p, mut s, m) = fixture();
    let mut first = run("first", 200, "ok");
    first.stdout = SECRET.into();
    s.nested.push(first);
    let mut later = run("later", 200, "ok");
    later.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    s.nested.push(later);
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "secret_leak"));
}
#[test]
fn host_values_already_judged_in_the_request_are_not_reported_twice() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    let mut api = run("api", 200, "ok");
    api.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    api.stdout = SECRET.into();
    s.nested.push(api);
    let mut f = browser::check(&p, &s, &m);
    f.extend(detect::per_run(&s.nested[0], &m));
    assert_eq!(f.iter().filter(|f| f.kind == "secret_leak").count(), 1, "{f:?}");
}
#[test]
fn a_secret_label_is_not_erased_by_an_earlier_pii_label_on_the_same_value() {
    let (mut p, s, m) = fixture();
    p.events = vec![event(1, "users#email", json!({}), json!(SECRET)), event(2, "config#key", json!({}), json!(SECRET))];
    p.result.as_mut().unwrap()["body"] = json!(SECRET);
    let f = labels::check(&p, &m);
    assert!(f.iter().any(|f| f.kind == "secret_leak"), "{f:?}");
    let mut s = s;
    s.nested.push(run("api", 200, SECRET));
    assert!(browser::check(&p, &s, &m).iter().any(|f| f.kind == "secret_leak"));
}

#[test]
fn conditional_labels_on_one_function_keep_the_secret_classification() {
    let (mut p, _, mut m) = fixture();
    m.functions.insert("profiles#read".into(), serde_json::from_value(json!({"result":"pii","rules":[{"when":{"private":true},"result":"secret"}]})).unwrap());
    p.events = vec![event(1, "profiles#read", json!({"private":false}), json!(SECRET)), event(2, "profiles#read", json!({"private":true}), json!(SECRET))];
    p.result.as_mut().unwrap()["body"] = json!(SECRET);
    assert!(labels::check(&p, &m).iter().any(|f| f.kind == "secret_leak"));
}
