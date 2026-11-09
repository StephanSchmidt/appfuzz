//! Document.body replacement uses native tree and Web IDL semantics.
//! Firefox 158 and Chromium 128 agree on 22 groups. Self-assignment follows
//! the HTML standard no-op (Chromium agrees; Firefox emits extra records).
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/body_setter.js");
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
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

#[test]
fn body_replacement() {
    visit("body-replacement", &["true true true true"]);
}

#[test]
fn body_setter_invalid_values() {
    visit(
        "body-setter-invalid-values",
        &["HierarchyRequestError true", "HierarchyRequestError true", "TypeError true", "TypeError true", "HierarchyRequestError true", "TypeError true"],
    );
}

#[test]
fn body_self_setter() {
    visit("body-self-setter", &["true 0"]);
}

#[test]
fn body_setter_frameset() {
    visit("body-setter-frameset", &["true true true", "true true"]);
}

#[test]
fn body_setter_cross_document() {
    visit("body-setter-cross-document", &["true true true true"]);
}

#[test]
fn body_setter_without_existing_body() {
    visit("body-setter-without-existing-body", &["true true true"]);
}

#[test]
fn body_setter_without_root() {
    visit("body-setter-without-root", &["HierarchyRequestError true true"]);
}

#[test]
fn body_setter_non_html_root() {
    visit("body-setter-non-html-root", &["ok true true true"]);
}

#[test]
fn body_setter_observer_record() {
    visit("body-setter-observer-record", &["1 true true true true"]);
}

#[test]
fn body_setter_private_identity() {
    visit("body-setter-private-identity", &["ok true 0"]);
}

#[test]
fn body_setter_descriptor_and_brands() {
    visit("body-setter-descriptor-and-brands", &["function function true true 1 set body", "TypeError true", "TypeError true", "TypeError true"]);
}

#[test]
fn body_setter_method_override_isolation() {
    visit("body-setter-method-override-isolation", &["ok true true 0"]);
}

#[test]
fn body_setter_private_document_tree() {
    visit("body-setter-private-document-tree", &["ok true 0"]);
}

#[test]
fn body_setter_adopts_descendants() {
    visit("body-setter-adopts-descendants", &["true true true"]);
}

#[test]
fn body_setter_descendant_replacement() {
    visit("body-setter-descendant-replacement", &["true true true 2 true true true"]);
}

#[test]
fn body_setter_invalid_foreign_node_preserves_source() {
    visit("body-setter-invalid-foreign-node-preserves-source", &["HierarchyRequestError true true true"]);
}

#[test]
fn body_setter_script_execution() {
    visit("body-setter-script-execution", &["script replacement 2 true", "returned true true"]);
}

#[test]
fn body_setter_custom_element_reactions() {
    visit("body-setter-custom-element-reactions", &["disconnected old true true", "connected new true true", "returned"]);
}

#[test]
fn body_setter_cross_document_reactions() {
    visit("body-setter-cross-document-reactions", &["adopted true true true", "connected true", "true"]);
}

#[test]
fn body_setter_callback_reentry() {
    visit("body-setter-callback-reentry", &["connected true", "disconnected true", "nested true", "returned true true"]);
}

#[test]
fn body_setter_current_script_removal() {
    visit("body-setter-current-script-removal", &["true false true"]);
}

#[test]
fn body_setter_svg_document_root() {
    visit("body-setter-svg-document-root", &["true true true"]);
}

#[test]
fn body_setter_no_string_conversion() {
    visit("body-setter-no-string-conversion", &["TypeError 0", "true"]);
}
