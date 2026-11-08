//! Request/Response bytes and Body methods. Native Chrome/Firefox references;
//! Blob MIME serialization follows Fetch and Firefox.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/bodies.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["requests"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn body_byte_sources() {
    assert_eq!(
        visit("body-byte-sources"),
        ["true 255,0,128", "false 255,0,128", "true 195,169", "false 195,169", "true 239,187,191,120", "false 239,187,191,120"]
    );
}

#[test]
fn body_blob_sources() {
    assert_eq!(visit("body-blob-sources"), ["255,0,128", "255,0,128"]);
}

#[test]
fn body_clone_snapshots() {
    assert_eq!(visit("body-clone-snapshots"), ["255,0,128 255,0,128", "255,0,128 255,0,128"]);
}

#[test]
fn body_text_bom() {
    assert_eq!(visit("body-text-bom"), ["\"hello\"", "\"hi\"", "1"]);
}

#[test]
fn body_response_blob_type() {
    assert_eq!(visit("body-response-blob-type"), ["text/plain;charset=utf-8 3 255,0,128", "application/octet-stream 3 255,0,128", " 3 255,0,128"]);
}

#[test]
fn body_promise_brands() {
    assert_eq!(
        visit("body-promise-brands"),
        [
            "Response text promise true",
            "Response text TypeError",
            "Response arrayBuffer promise true",
            "Response arrayBuffer TypeError",
            "Response json promise true",
            "Response json TypeError",
            "Response blob promise true",
            "Response blob TypeError",
            "Request text promise true",
            "Request text TypeError",
            "Request arrayBuffer promise true",
            "Request arrayBuffer TypeError",
            "Request json promise true",
            "Request json TypeError",
            "Request blob promise true",
            "Request blob TypeError"
        ]
    );
}

#[test]
fn body_view_range() {
    assert_eq!(visit("body-view-range"), ["255,0,128", "255,0,128"]);
}

#[test]
fn body_option_mutation() {
    assert_eq!(visit("body-option-mutation"), ["9,2", "9,2"]);
}

#[test]
fn body_cross_brands() {
    assert_eq!(visit("body-cross-brands"), ["Response TypeError", "Request TypeError"]);
}

#[test]
fn body_buffer_validation() {
    assert_eq!(
        visit("body-buffer-validation"),
        ["detached buffer ", "resizable buffer TypeError 0", "detached typed ", "resizable typed TypeError 0", "detached view ", "resizable view TypeError 0"]
    );
}

#[test]
fn body_response_mime() {
    assert_eq!(
        visit("body-response-mime"),
        [
            "\"TeXt/Plain ; X=\\\"A B\\\"; charset=UTF-8\" \"text/plain;x=\\\"a b\\\";charset=utf-8\"",
            "\"text/plain; x=a; x=b\" \"text/plain;x=a\"",
            "\"text/plain; x=\\\"a\\\\b\\\"\" \"text/plain;x=ab\"",
            "\"text/plain; x=\\\"é\\\"\" \"\"",
            "\"*/*\" \"\"",
            "\"text/plain;empty=\" \"text/plain\"",
            "\"text/plain;charset=\\\"UTF-8\\\"\" \"text/plain;charset=utf-8\"",
            "\"invalid\" \"\""
        ]
    );
}

#[test]
fn body_response_init() {
    assert_eq!(
        visit("body-response-init"),
        [
            "number 200 200 default",
            "number 201.9 201 default",
            "number 0 RangeError",
            "number 65737 201 default",
            "number Infinity RangeError",
            "object null RangeError",
            "bigint 1 TypeError",
            "\"OK\" \"OK\"",
            "\"a\\tb\" \"a\\tb\"",
            "\"a\\nb\" TypeError",
            "\"a\\u0000b\" TypeError",
            "\"é\" \"é\"",
            "\"€\" TypeError",
            "204 TypeError",
            "205 TypeError",
            "304 TypeError"
        ]
    );
}

#[test]
fn body_private_header_arrays() {
    assert_eq!(visit("body-private-header-arrays"), ["v w x 0"]);
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
