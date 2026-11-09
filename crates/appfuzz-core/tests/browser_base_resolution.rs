//! Native base URL reflection, API requests and classic/module resource loads.
//! Firefox158/Chromium128 agree except malformed-base fallback, which follows
//! current HTML rules and Firefox. https://html.spec.whatwg.org/#the-base-element
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, GO, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/base_resolution.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], network_plan(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

fn network_plan() -> Plan {
    let mut rules = vec![];
    for prefix in ["/", "/nested/", "/changed/", "/headers/"] {
        for (name, body) in [
            ("data", json!({"path":format!("{prefix}data")}).to_string()),
            ("part.js", format!("globalThis.externalPath={};", json!(format!("{prefix}part.js")))),
            ("part.mjs", format!("import './dep.mjs';globalThis.modulePath={};", json!(format!("{prefix}part.mjs")))),
            ("dep.mjs", format!("globalThis.dependencyPath={};", json!(format!("{prefix}dep.mjs")))),
        ] {
            rules.push(json!({"when":{"path":format!("{prefix}{name}")},"return":{"ok":{"status":200,"headers":[],"body":body.as_bytes()}}}));
        }
    }
    Plan::parse(&json!({FETCH_OWN:{"rules":rules,"default":{"return":{"ok":{"status":404,"headers":[],"body":[]}}}}}).to_string()).unwrap()
}

#[test]
fn base_request_constructor() {
    visit("base-request-constructor", &["request /nested/child", "changed /changed/child"]);
}

#[test]
fn base_anchor_reflection() {
    visit("base-anchor-reflection", &["anchor /nested/child", "changed /changed/child"]);
}

#[test]
fn base_script_reflection() {
    visit("base-script-reflection", &["script /nested/child.js", "changed /changed/child.js"]);
}

#[test]
fn inert_anchor_base() {
    visit("inert-anchor-base", &["inert https://owned.example/nested/child", "changed https://owned.example/changed/child"]);
}

#[test]
fn api_redirect_base() {
    visit("api-redirect-base", &["redirect /nested/child"]);
}

#[test]
fn base_history_frozen() {
    visit("base-history-frozen", &["history /nested/next /nested/ /nested/child", "reset /nested/fresh/"]);
}

#[test]
fn base_history_security() {
    visit("base-history-security", &["security SecurityError /"]);
}

#[test]
fn base_invalid_schemes() {
    visit("base-invalid-schemes", &["data:text/plain,x / /child", "javascript:void(0) / /child", "http://[ / /child"]);
}

#[test]
fn url_empty_attributes() {
    visit(
        "url-empty-attributes",
        &[
            "a missing empty",
            "a empty /nested/",
            "script missing empty",
            "script empty /nested/",
            "link missing empty",
            "link empty /nested/",
            "form missing /",
            "form empty /",
            "button missing /",
            "button empty /",
            "input missing /",
            "input empty /",
        ],
    );
}

#[test]
fn anchor_components() {
    visit("anchor-components", &["parts true /nested/child ?q=1 #x true true", "set /other ?q=2 #z true"]);
}

#[test]
fn anchor_missing_components() {
    visit("anchor-missing-components", &["missing :  ", "hash  ", "invalid http://[ : "]);
}

#[test]
fn url_adoption() {
    visit("url-adoption", &["before https://owned.example/nested/child", "after /child"]);
}

#[test]
fn url_reflection_private() {
    visit("url-reflection-private", &["private /nested/child 0", "set /nested/next 0"]);
}

#[test]
fn base_fetch_network() {
    visit("base-fetch-network", &["fetch /nested/data"]);
}

#[test]
fn base_xhr_network() {
    visit("base-xhr-network", &["xhr /nested/data /nested/data"]);
}

#[test]
fn base_script_network() {
    visit("base-script-network", &["loaded /nested/part.js"]);
}

#[test]
fn base_script_connected_src() {
    visit("base-script-connected-src", &["loaded /nested/part.js"]);
}

#[test]
fn request_captures_base() {
    visit("request-captures-base", &["capture /nested/child /nested/child /changed/child"]);
}

#[test]
fn request_reentrant_base() {
    visit("request-reentrant-base", &["conversion /changed/child", "headers /headers/next"]);
}

#[test]
fn base_form_reflection() {
    visit("base-form-reflection", &["action /nested/submit /nested/other", "missing /"]);
}

#[test]
fn element_url_interfaces() {
    visit(
        "element-url-interfaces",
        &[
            "area /nested/child child",
            "link /nested/child child",
            "source /nested/child child",
            "track /nested/child child",
            "embed /nested/child child",
            "object /nested/child child",
            "q /nested/child child",
            "blockquote /nested/child child",
        ],
    );
}

#[test]
fn url_idl_and_brands() {
    visit(
        "url-idl-and-brands",
        &[
            "href get href set href true TypeError TypeError",
            "src get src set src true TypeError TypeError",
            "action get action set action true TypeError TypeError",
            "src get src set src true TypeError TypeError",
        ],
    );
}

#[test]
fn base_script_module_network() {
    visit("base-script-module-network", &["module /nested/part.mjs /nested/dep.mjs"]);
}

#[test]
fn base_inline_module_network() {
    visit("base-inline-module-network", &["inline /nested/dep.mjs /nested/"]);
}

#[test]
fn request_fragment_url() {
    visit("request-fragment-url", &["fragment /nested/child #request", "copy #request"]);
}

#[test]
fn fetch_fragment_transport() {
    visit("fetch-fragment-transport", &["transport /nested/data  /nested/data"]);
}

#[test]
fn form_method_reflection() {
    visit("form-method-reflection", &["default get \"\"", "POST post POST post POST", "dialog dialog dialog dialog dialog", "bad get bad get bad"]);
}

fn navigate(script: &str) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":format!("<body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], network_plan(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert!(run.events.iter().any(|event| event.func == GO), "{:?}", run.events);
    (run, report)
}
#[test]
fn link_activation_uses_private_owner_base() {
    let (_, r) = navigate(
        "const b=document.createElement('base');b.href='/nested/';document.head.append(b);const a=document.createElement('a');a.href='next';document.body.append(a);a.click()",
    );
    assert_eq!(r["navigations"][0]["url"], "https://app.example/nested/next");
}
#[test]
fn form_post_uses_base_and_keeps_its_encoded_body() {
    let (_, r) = navigate(
        "const b=document.createElement('base');b.href='/nested/';document.head.append(b);const f=document.createElement('form'),i=document.createElement('input');i.name='k';i.value='v';f.append(i);f.method='post';f.action='submit';document.body.append(f);f.submit()",
    );
    assert_eq!(r["navigations"][0]["url"], "https://app.example/nested/submit");
    assert_eq!(r["navigations"][0]["method"], "POST");
    assert_eq!(r["navigations"][0]["body"], "k=v");
}
#[test]
fn empty_submitter_action_overrides_form_action_with_document_url() {
    let (_, r) = navigate(
        "const b=document.createElement('base');b.href='/nested/';document.head.append(b);const f=document.createElement('form'),i=document.createElement('input'),button=document.createElement('button');i.name='k';i.value='v';button.formAction='';f.action='submit';f.append(i,button);document.body.append(f);f.requestSubmit(button)",
    );
    assert_eq!(r["navigations"][0]["url"], "https://app.example/?k=v");
}
