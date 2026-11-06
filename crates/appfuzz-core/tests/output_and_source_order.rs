use appfuzz_core::{
    browser::{self, Session},
    detect::Severity,
    envelope::Trace,
    harness::App,
    labels,
    manifest::Manifest,
    payload,
    plan::Plan,
    record::{HostCall, OutcomeKind, RunRecord},
};
use serde_json::{Value, json};
const SECRET: &str = "sk_private_output_0123456789";
const EMAIL: &str = "person@mail.example";
fn event(n: u32, func: &str, args: Value, result: Value) -> HostCall {
    serde_json::from_value(
        json!({"n":n,"func":func,"call":1,"args":args,"result":result,"source":"plan","granted":true,"latency_ns":0,"cost":0,"fuel_before":0,"t_ns":0}),
    )
    .unwrap()
}
fn record(id: &str) -> RunRecord {
    let mut r = Trace::default().to_record();
    r.id = id.into();
    r.spec.export = "run".into();
    r.spec.args = vec![json!({"method":"GET","uri":"https://app.example/","headers":[],"body":""})];
    r.result = Some(json!({"status":200,"headers":[],"body":"ok"}));
    r
}
fn manifest() -> Manifest {
    serde_json::from_value(json!({"app":{"wasm":"a.wasm"},"entry":{"export":"run","output":{"status":"status","headers":"headers","body":"body"}},"functions":{"test:payload/config#key":{"result":"secret"},"users#email":{"result":"pii"},"data#trusted":{"result":"html"}}})).unwrap()
}
fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}
fn session() -> Session {
    Session { browser: record("browser"), nested: vec![], report: json!({"url":"https://app.example/","errors":[]}), fragment: String::new() }
}
#[test]
fn native_encoded_secret_in_an_unmapped_result_field_is_detected() {
    let mut m = manifest();
    m.entry.as_mut().unwrap().output.status = None;
    m.entry.as_mut().unwrap().output.headers = None;
    let bytes = wat::parse_str(include_str!("fixtures/encoded_result.wat")).unwrap();
    let app = App::from_bytes(m, bytes).unwrap();
    let plan = Plan::parse(&json!({"test:payload/config#key":{"return":SECRET}}).to_string()).unwrap();
    let r = app.run(&app.spec(app.default_export().unwrap(), vec![], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok);
    assert_eq!(r.result.as_ref().unwrap()["metadata"], hex(SECRET));
    let f = payload::check(&r, &app.manifest);
    assert!(
        f.iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail && f.detail["place"] == "the result" && f.detail["at"] == "metadata"),
        "{f:?}"
    );
}
#[test]
fn encoded_pii_in_extra_result_fields_obeys_no_pii() {
    let mut r = record("r");
    let mut m = manifest();
    r.events = vec![event(1, "users#email", json!({}), json!(EMAIL))];
    r.result.as_mut().unwrap()["extra"] = json!({"rows":[hex(EMAIL)]});
    assert!(payload::check(&r, &m).iter().all(|f| f.kind != "encoded_flow"));
    m.entry.as_mut().unwrap().no_pii = true;
    let f = payload::check(&r, &m);
    assert!(f.iter().any(|f| f.kind == "encoded_flow" && f.severity == Severity::Fail && f.detail["at"] == "extra.rows[0]"), "{f:?}");
}
#[test]
fn mapped_pair_list_output_is_checked_once_and_equal_extra_values_are_not_skipped() {
    let mut r = record("r");
    let mut m = manifest();
    m.entry.as_mut().unwrap().output.body = Some("payload.body".into());
    m.entry.as_mut().unwrap().output.headers = Some("payload.headers".into());
    r.events = vec![event(1, "test:payload/config#key", json!({}), json!(SECRET))];
    for encoded in [false, true] {
        let value = if encoded { hex(SECRET) } else { SECRET.into() };
        r.result = Some(json!({"payload":[["body",value],["headers",[["x-key",value]]]],"extra":"ok"}));
        let f = if encoded { payload::check(&r, &m) } else { labels::check(&r, &m) };
        assert_eq!(f.len(), 2, "{encoded}: {f:?}");
        r.result.as_mut().unwrap()["extra"] = json!(value);
        let f = if encoded { payload::check(&r, &m) } else { labels::check(&r, &m) };
        assert_eq!(f.len(), 3, "{encoded}: {f:?}");
    }
}
#[test]
fn later_api_canaries_do_not_taint_earlier_dom_changes() {
    let p = record("page");
    let m = manifest();
    let mut s = session();
    let canary = appfuzz_core::output::canary(123);
    let mut api = record("api");
    api.events = vec![event(1, "data#text", json!({}), json!(canary))];
    s.nested.push(api);
    s.browser.events = vec![
        event(1, browser::HTML, json!({"sink":"innerHTML","value":canary}), Value::Null),
        event(2, browser::FETCH_OWN, json!({"path":"/api"}), json!({"ok":{"status":200,"headers":[],"body":canary}})),
        event(3, browser::HTML, json!({"sink":"innerHTML","value":canary}), Value::Null),
    ];
    let f = browser::check(&p, &s, &m);
    let leaks: Vec<_> = f.iter().filter(|f| f.kind == "html_injection").collect();
    assert_eq!(leaks.len(), 1, "{f:?}");
    assert_eq!(leaks[0].detail["n"], 3, "{f:?}");
}
#[test]
fn later_trusted_html_does_not_hide_earlier_untrusted_dom_markup() {
    let mut p = record("page");
    let m = manifest();
    let mut s = session();
    let canary = appfuzz_core::output::canary(123);
    p.spec.args[0]["body"] = json!(canary);
    let mut api = record("api");
    api.events = vec![event(1, "data#trusted", json!({}), json!(canary))];
    s.nested.push(api);
    s.browser.events = vec![
        event(1, browser::HTML, json!({"sink":"innerHTML","value":canary}), Value::Null),
        event(2, browser::FETCH_OWN, json!({"path":"/api"}), json!({"ok":{"status":200,"headers":[],"body":canary}})),
        event(3, browser::HTML, json!({"sink":"innerHTML","value":canary}), Value::Null),
    ];
    let f = browser::check(&p, &s, &m);
    let leaks: Vec<_> = f.iter().filter(|f| f.kind == "html_injection").collect();
    assert_eq!(leaks.len(), 1, "{f:?}");
    assert_eq!(leaks[0].detail["n"], 1, "{f:?}");
}
#[test]
fn remote_code_only_comes_from_an_earlier_fetch() {
    let p = record("page");
    let m = manifest();
    let mut s = session();
    let text = "remote body used as code";
    s.browser.events = vec![
        event(1, browser::CODE, json!({"sink":"eval","value":text}), Value::Null),
        event(
            2,
            browser::FETCH_OTHER,
            json!({"url":"https://evil.example/remote","kind":"fetch","method":"GET"}),
            json!({"ok":{"status":200,"headers":[],"body":text}}),
        ),
        event(3, browser::CODE, json!({"sink":"eval","value":text}), Value::Null),
    ];
    let f = browser::check(&p, &s, &m);
    let leaks: Vec<_> = f.iter().filter(|f| f.kind == "remote_code").collect();
    assert_eq!(leaks.len(), 1, "{f:?}");
    assert_eq!(leaks[0].detail["n"], 3, "{f:?}");
}
#[test]
fn platform_form_mime_uses_an_exact_case_insensitive_essence() {
    let base = json!({"method":"GET","path":"/","query":[],"form":[],"headers":[]});
    let mut outcomes = Vec::new();
    for (mime, want) in [
        ("application/x-www-form-urlencoded", true),
        ("Application/X-WWW-Form-Urlencoded; Charset=UTF-8", true),
        ("application/x-www-form-urlencoded-evil", false),
        ("application/json;note=x-www-form-urlencoded", false),
        ("TEXT/PLAIN; charset=UTF-8", true),
        ("text/plainish", false),
    ] {
        let r = browser::request_for(&base, "POST", "/api", &[("content-type".into(), mime.into())], Some("name=A%26B")).unwrap();
        let parsed = !r["form"].as_array().unwrap().is_empty();
        outcomes.push((mime, parsed, want));
    }
    assert!(outcomes.iter().all(|(_, got, want)| got == want), "{outcomes:?}");
}

#[test]
fn native_invalid_output_mappings_cannot_hide_plain_or_encoded_secrets() {
    let source = include_str!("fixtures/encoded_result.wat");
    let plain = source
        .replace("(i32.store (i32.const 8) (i32.const 8192))", "(i32.store (i32.const 8) (i32.load (i32.const 1024)))")
        .replace("(i32.store (i32.const 12) (i32.mul (local.get $n) (i32.const 2)))", "(i32.store (i32.const 12) (local.get $n))");
    let mut results = Vec::new();
    for encoded in [false, true] {
        for headers in [false, true] {
            let mut m = manifest();
            let output = &mut m.entry.as_mut().unwrap().output;
            output.status = None;
            output.body = Some(if headers { "body" } else { "" }.into());
            output.headers = headers.then(|| "metadata".into());
            let app = App::from_bytes(m, wat::parse_str(if encoded { source } else { &plain }).unwrap()).unwrap();
            let plan = Plan::parse(&json!({"test:payload/config#key":{"return":SECRET}}).to_string()).unwrap();
            let r = app.run(&app.spec(app.default_export().unwrap(), vec![], plan, 1));
            assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
            let findings = if encoded { payload::check(&r, &app.manifest) } else { labels::check(&r, &app.manifest) };
            let kind = if encoded { "encoded_flow" } else { "secret_leak" };
            results.push((encoded, headers, findings.iter().any(|f| f.kind == kind && f.severity == Severity::Fail && f.detail["at"] == "metadata")));
        }
    }
    assert!(results.iter().all(|(_, _, found)| *found), "{results:?}");
}

#[test]
fn partially_parsed_headers_do_not_hide_other_returned_fields() {
    let mut r = record("r");
    let m = manifest();
    r.events = vec![event(1, "test:payload/config#key", json!({}), json!(SECRET))];
    let mut results = Vec::new();
    for encoded in [false, true] {
        let value = if encoded { hex(SECRET) } else { SECRET.into() };
        for header in [
            json!(["x-extra", value, "third field"]),
            json!({"name":"x-good","value":"ok","debug":value}),
            json!({"name":"x-good","key":value,"value":"ok"}),
            json!({"name":"x-no-value","other":value}),
            json!(value),
        ] {
            r.result.as_mut().unwrap()["headers"] = json!([header]);
            let findings = if encoded { payload::check(&r, &m) } else { labels::check(&r, &m) };
            results.push((encoded, header, findings.iter().any(|f| f.severity == Severity::Fail && f.detail["place"] == "the result")));
        }
    }
    assert!(results.iter().all(|(_, _, found)| *found), "{results:?}");
}

#[test]
fn response_header_names_are_checked_for_private_data() {
    let mut r = record("r");
    let m = manifest();
    r.events = vec![event(1, "test:payload/config#key", json!({}), json!(SECRET))];
    let mut results = Vec::new();
    for encoded in [false, true] {
        let value = if encoded { hex(SECRET) } else { SECRET.into() };
        r.result.as_mut().unwrap()["headers"] = json!([[value, "ok"]]);
        let findings = if encoded { payload::check(&r, &m) } else { labels::check(&r, &m) };
        results.push((encoded, findings.iter().any(|f| f.severity == Severity::Fail && f.detail["place"] == "a response header name")));
    }
    assert!(results.iter().all(|(_, found)| *found), "{results:?}");

    let pii = "private_customer_12345";
    r.events = vec![event(1, "users#email", json!({}), json!(pii))];
    r.result.as_mut().unwrap()["headers"] = json!([[pii, "ok"]]);
    for no_pii in [false, true] {
        let mut m = m.clone();
        m.entry.as_mut().unwrap().no_pii = no_pii;
        let findings = labels::check(&r, &m);
        let severity = if no_pii { Severity::Fail } else { Severity::Warn };
        assert!(findings.iter().any(|f| f.kind == "pii_leak" && f.severity == severity), "{findings:?}");
    }
}

#[test]
fn native_header_names_preserve_private_host_values_and_their_encodings() {
    let source = include_str!("fixtures/encoded_result.wat");
    for encoded in [false, true] {
        let pointer = if encoded { "(i32.const 8192)" } else { "(i32.load (i32.const 1024))" };
        let length = if encoded { "(i32.mul (local.get $n) (i32.const 2))" } else { "(local.get $n)" };
        let row = format!(
            "(i32.store (i32.const 16384) {pointer}) (i32.store (i32.const 16388) {length})\n(i32.store (i32.const 16392) (i32.const 128)) (i32.store (i32.const 16396) (i32.const 2))\n(i32.store (i32.const 8) (i32.const 16384))"
        );
        let wat = source
            .replace("(i32.store (i32.const 8) (i32.const 8192))", &row)
            .replace("(i32.store (i32.const 12) (i32.mul (local.get $n) (i32.const 2)))", "(i32.store (i32.const 12) (i32.const 1))")
            .replace(
                "(type $out (record (field \"body\" string) (field \"metadata\" string)))",
                "(type $pair (tuple string string))\n(type $headers (list $pair))\n(type $out (record (field \"body\" string) (field \"metadata\" $headers)))",
            );
        let mut m = manifest();
        m.entry.as_mut().unwrap().output.headers = Some("metadata".into());
        m.entry.as_mut().unwrap().output.status = None;
        let app = App::from_bytes(m, wat::parse_str(wat).unwrap()).unwrap();
        let plan = Plan::parse(&json!({"test:payload/config#key":{"return":SECRET}}).to_string()).unwrap();
        let r = app.run(&app.spec(app.default_export().unwrap(), vec![], plan, 1));
        assert_eq!(r.outcome.kind, OutcomeKind::Ok);
        assert_eq!(r.result.as_ref().unwrap()["metadata"][0][0], if encoded { hex(SECRET) } else { SECRET.into() });
        let findings = appfuzz_core::detect::per_run(&r, &app.manifest);
        assert!(findings.iter().all(|f| f.kind != "invalid_response"), "{findings:?}");
        let kind = if encoded { "encoded_flow" } else { "secret_leak" };
        assert!(findings.iter().any(|f| f.kind == kind && f.severity == Severity::Fail && f.detail["place"] == "a response header name"), "{findings:?}");
    }
}

#[test]
fn valid_text_and_binary_bodies_and_headers_are_only_checked_once() {
    let mut r = record("r");
    let m = manifest();
    r.events = vec![event(1, "test:payload/config#key", json!({}), json!(SECRET))];
    for body in [json!(SECRET), json!(SECRET.as_bytes()), json!([vec![255], SECRET.as_bytes().to_vec()].concat())] {
        r.result = Some(json!({"status":200,"body":body,"headers":[["x-first",SECRET],{"name":"x-second","value":SECRET,"public":"ok"}]}));
        let findings = labels::check(&r, &m);
        assert_eq!(findings.len(), 3, "{findings:?}");
        assert!(findings.iter().all(|f| f.detail["place"] != "the result"), "{findings:?}");
    }
}
