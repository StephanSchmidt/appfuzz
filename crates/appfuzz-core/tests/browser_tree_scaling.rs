//! Native tree relationships and privacy remain intact as parent/child
//! lookup becomes constant time. Local Firefox158/Chromium128 agree on rows.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/tree_scaling.js");
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
fn tree_insert_remove() {
    visit("tree-insert-remove", &["true true true true true true true true", "true true true false true", "true true true true true false"]);
}

#[test]
fn tree_fragment_moves() {
    visit("tree-fragment-moves", &["true true", "true true true true true", "true true"]);
}

#[test]
fn tree_fragment_reactions() {
    visit("tree-fragment-reactions", &["a true", "b true"]);
}

#[test]
fn tree_reparent_siblings() {
    visit("tree-reparent-siblings", &["true", "true true true true", "true true true true"]);
}

#[test]
fn tree_replace_child() {
    visit("tree-replace-child", &["2 true true true true true", "true true true true true"]);
}

#[test]
fn tree_replace_children() {
    visit("tree-replace-children", &["true true 3 3 3", "true true true"]);
}

#[test]
fn tree_text_mutations() {
    visit("tree-text-mutations", &["true true true true true", "true 1 abcd", "true true true tail"]);
}

#[test]
fn tree_clone_deep() {
    visit("tree-clone-deep", &["true true true true true true true", "true true"]);
}

#[test]
fn tree_document_clone() {
    visit("tree-document-clone", &["true true true true true true"]);
}

#[test]
fn tree_adopt_subtree() {
    visit("tree-adopt-subtree", &["true true true true true", "true true true"]);
}

#[test]
fn tree_import_subtree() {
    visit("tree-import-subtree", &["true true true true", "true true"]);
}

#[test]
fn tree_shadow_parents() {
    visit("tree-shadow-parents", &["true true true true true", "true true true true", "true true true"]);
}

#[test]
fn tree_template_parents() {
    visit("tree-template-parents", &["true true true", "true true", "true true true"]);
}

#[test]
fn tree_attribute_boundaries() {
    visit("tree-attribute-boundaries", &["true true true", "true true true true", "true true"]);
}

#[test]
fn tree_adjacent_html() {
    visit("tree-adjacent-html", &["true true true", "true em true"]);
}

#[test]
fn tree_frozen_private_metadata() {
    visit("tree-frozen-private-metadata", &["true true 0"]);
}

#[test]
fn tree_event_path_after_move() {
    visit("tree-event-path-after-move", &["new true true", "true true"]);
}

#[test]
fn tree_owner_documents_private() {
    visit("tree-owner-documents-private", &["true true true 0"]);
}

#[test]
fn tree_sibling_methods_private_parents() {
    visit("tree-sibling-methods-private-parents", &["3 true true true 0"]);
}

#[test]
fn tree_observer_single_insert_siblings() {
    visit("tree-observer-single-insert-siblings", &["2 true true true true", "true true true true"]);
}

fn parse_page(elements: usize, fuel: u64) -> RunRecord {
    let browser = Browser::shared().unwrap();
    let html = format!("<!doctype html><body>{}<script>console.log('count',document.querySelectorAll('b').length)</script>", "<b>x</b>".repeat(elements));
    let input = json!({"url":"https://app.example/","html":html});
    let mut spec = browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1);
    spec.fuel = fuel;
    let run = browser.app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{} elements: {:?}", elements, run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["console"][0]["text"], format!("count {elements}"), "{report}");
    run
}
#[test]
fn parser_work_grows_linearly_for_flat_sibling_lists() {
    let small = parse_page(128, 10_000_000_000).totals.fuel;
    let large = parse_page(512, 10_000_000_000).totals.fuel;
    assert!(large <= small * 5, "quadrupling input must not restore quadratic work: {small} -> {large}");
}
#[test]
fn a_thousand_siblings_fit_within_a_bounded_browser_budget() {
    parse_page(1024, 3_000_000_000);
}
