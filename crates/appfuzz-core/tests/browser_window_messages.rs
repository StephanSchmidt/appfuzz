//! Same-window postMessage follows HTML structured messaging, with native
//! Chrome/Firefox references. Invalid-origin ordering follows HTML/Firefox.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/window_messages.js");
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
fn window_copy() {
    assert_eq!(visit("window-copy"), ["true true 1 true true true true 0"]);
}

#[test]
fn window_target_origin() {
    assert_eq!(visit("window-target-origin"), ["0"]);
}

#[test]
fn window_default() {
    assert_eq!(visit("window-default"), ["true true true"]);
}

#[test]
fn window_options() {
    assert_eq!(visit("window-options"), ["transfer,origin,data,return,message 1"]);
}

#[test]
fn window_invalid_origin() {
    assert_eq!(visit("window-invalid-origin"), ["SyntaxError 0", "SyntaxError 0", "SyntaxError 0"]);
}

#[test]
fn window_buffer_transfer() {
    assert_eq!(visit("window-buffer-transfer"), ["detached 0", "true true 7"]);
}

#[test]
fn window_wrong_origin_transfer() {
    assert_eq!(visit("window-wrong-origin-transfer"), ["detached 0", "0"]);
}

#[test]
fn window_errors() {
    assert_eq!(visit("window-errors"), ["TypeError", "TypeError", "DataCloneError", "TypeError", "DataCloneError"]);
}

#[test]
fn window_overloads() {
    assert_eq!(
        visit("window-overloads"),
        [
            "undefined 2 ok data",
            "received 1",
            "undefined 3 SyntaxError ",
            "received 0",
            "null 2 ok data",
            "received 1",
            "null 3 SyntaxError ",
            "received 0",
            "false 2 SyntaxError ",
            "received 0",
            "false 3 SyntaxError ",
            "received 0",
            "zero 2 SyntaxError ",
            "received 0",
            "zero 3 SyntaxError ",
            "received 0",
            "string 2 ok data",
            "received 1",
            "string 3 ok data",
            "received 1",
            "boxed 2 ok data",
            "received 1",
            "boxed 3 ok data",
            "received 1",
            "array 2 ok data",
            "received 1",
            "array 3 SyntaxError ",
            "received 0",
            "function 2 ok data",
            "received 1",
            "function 3 SyntaxError ",
            "received 0"
        ]
    );
}

#[test]
fn window_receivers() {
    assert_eq!(
        visit("window-receivers"),
        ["undefined ok", "null ok", "window ok", "document TypeError", "proxy TypeError", "number TypeError", "metadata postMessage 1 false"]
    );
}

#[test]
fn window_port_transfer() {
    assert_eq!(visit("window-port-transfer"), ["true 1 true true", "reply"]);
}

#[test]
fn window_listener_microtasks() {
    assert_eq!(visit("window-listener-microtasks"), ["true true 2", "during true", "after true"]);
}

#[test]
fn window_private_factories() {
    assert_eq!(visit("window-private-factories"), ["true 1 0"]);
}

#[test]
fn window_origin_canonical() {
    assert_eq!(visit("window-origin-canonical"), ["true true", "true true", "true true", "true true", "opaque 0"]);
}

#[test]
fn window_private_iterator_symbol() {
    assert_eq!(visit("window-private-iterator-symbol"), ["1 0", "true", "true", "reply"]);
}

#[test]
fn window_transfer_validation() {
    assert_eq!(visit("window-transfer-validation"), ["TypeError", "TypeError", "DataCloneError", "SyntaxError", "SyntaxError 2"]);
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
