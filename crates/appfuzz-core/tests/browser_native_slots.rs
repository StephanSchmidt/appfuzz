//! Native Firefox/Chromium references for frozen DOM wrappers and private
//! backend slots. Page reflection must expose only author-created symbols.
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/native_slots.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert!(run.events.iter().all(|event| event.func == HTML), "{:?}", run.events);
    assert_eq!(report["requests"], json!([]), "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

#[test]
fn frozen_text_removal() {
    visit("frozen-text-removal", &["remove true 0 true"]);
}

#[test]
fn frozen_text_split() {
    visit("frozen-text-split", &["split ok ab cd 2 true"]);
}

#[test]
fn frozen_parent_append() {
    visit("frozen-parent-append", &["append true 1 true"]);
}

#[test]
fn frozen_element_removal() {
    visit("frozen-element-removal", &["remove true 0 true"]);
}

#[test]
fn node_symbols() {
    visit("node-symbols", &["symbols 0 0"]);
}

#[test]
fn frozen_parent_text() {
    visit("frozen-parent-text", &["replace ok new 1"]);
}

#[test]
fn frozen_attribute_value() {
    visit("frozen-attribute-value", &["attr ok new new true"]);
}

#[test]
fn frozen_comment_edit() {
    visit("frozen-comment-edit", &["comment ok old! true 0"]);
}

#[test]
fn frozen_clone() {
    visit("frozen-clone", &["clone ok <div x=\"1\">hello<b></b></div> true <div x=\"1\">hello<b></b></div>"]);
}

#[test]
fn frozen_adoption() {
    visit("frozen-adoption", &["adopt true true true 0 true"]);
}

#[test]
fn frozen_template() {
    visit("frozen-template", &["template ok hello hello"]);
}

#[test]
fn user_symbol_slots() {
    visit("user-symbol-slots", &["symbols true ok abc abc true true 0"]);
}

#[test]
fn frozen_style_cache() {
    visit("frozen-style-cache", &["style ok red color:red"]);
}

#[test]
fn node_symbols_all() {
    visit("node-symbols-all", &["own symbols 0,0,0,0,0,0,0"]);
}

#[test]
fn frozen_sibling_insert() {
    visit("frozen-sibling-insert", &["insert true ac 3 true true"]);
}
