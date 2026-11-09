//! DOM conversion, insertion and replacement regressions measured in local
//! Firefox 158 and Chromium 128. Both browsers agree on the expected rows.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/multi_node.js");
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
fn append_conversion_before_moving() {
    visit("append-conversion-before-moving", &["convert true 0", "final true 2 tail"]);
}

#[test]
fn append_failed_conversion_keeps_parents() {
    visit("append-failed-conversion-keeps-parents", &["TypeError true 0"]);
}

#[test]
fn replace_children_failed_conversion_keeps_tree() {
    visit("replace-children-failed-conversion-keeps-tree", &["TypeError true 1"]);
}

#[test]
fn prepend_resolves_reference_after_conversion() {
    visit("prepend-resolves-reference-after-conversion", &["ok 2 3 true"]);
}

#[test]
fn fragment_removal_and_addition_records() {
    visit("fragment-removal-and-addition-records", &["source 1 2 target 1 2"]);
}

#[test]
fn before_failed_conversion_keeps_parents() {
    visit("before-failed-conversion-keeps-parents", &["TypeError true true"]);
}

#[test]
fn after_failed_conversion_keeps_parents() {
    visit("after-failed-conversion-keeps-parents", &["TypeError true true"]);
}

#[test]
fn replace_with_failed_conversion_keeps_parents() {
    visit("replace-with-failed-conversion-keeps-parents", &["TypeError true true"]);
}

#[test]
fn append_atomic_record() {
    visit("append-atomic-record", &["a,b p|a,b||-|-"]);
}

#[test]
fn replace_children_record() {
    visit("replace-children-record", &["c,d p|c,d|a,b|-|-"]);
}

#[test]
fn replace_children_existing_record() {
    visit("replace-children-existing-record", &["b p|b|a,b,c|-|-"]);
}

#[test]
fn replace_child_existing_record() {
    visit("replace-child-existing-record", &["true", "b,a p||a|-|b;p|a|c|b|-"]);
}

#[test]
fn replace_child_self_record() {
    visit("replace-child-self-record", &["true", "a,b p||a|-|b;p|a||-|b"]);
}

#[test]
fn insert_before_self_record() {
    visit("insert-before-self-record", &["true", "a,b p||a|-|b;p|a||-|b"]);
}

#[test]
fn replace_child_fragment_record() {
    visit("replace-child-fragment-record", &["c,d,b p|c,d|a|-|b #document-fragment||c,d|-|-"]);
}

#[test]
fn sibling_viable_references() {
    visit("sibling-viable-references", &["before a,b,c,d true", "after a,b,c,d true", "replaceWith a,b,c,d true"]);
}

#[test]
fn sibling_duplicate_arguments() {
    visit("sibling-duplicate-arguments", &["before a,c,b true", "after b,a,c true", "replaceWith a,c false"]);
}

#[test]
fn detached_sibling_conversion() {
    visit("detached-sibling-conversion", &["before 1 true", "after 1 true", "replaceWith 1 true"]);
}

#[test]
fn symbol_conversion_and_argument_order() {
    visit("symbol-conversion-and-argument-order", &["TypeError 1 a", "TypeError a"]);
}

#[test]
fn coercion_reentrant_parent_change() {
    visit("coercion-reentrant-parent-change", &["before a #text,c,b true", "after a b,#text,c true", "replaceWith a #text,c false"]);
}

#[test]
fn coercion_reentrant_script() {
    visit("coercion-reentrant-script", &["inner,convert,x"]);
}

#[test]
fn native_method_override_isolation() {
    visit("native-method-override-isolation", &["a,b 0 true"]);
}

#[test]
fn hierarchy_invalid_reference_preserves_owner() {
    visit("hierarchy-invalid-reference-preserves-owner", &["NotFoundError true true 0"]);
}

#[test]
fn hierarchy_cycles_and_brands() {
    visit("hierarchy-cycles-and-brands", &["HierarchyRequestError true true", "TypeError", "TypeError", "HierarchyRequestError", "HierarchyRequestError"]);
}

#[test]
fn hierarchy_error_after_node_conversion() {
    visit("hierarchy-error-after-node-conversion", &["HierarchyRequestError false 11 0"]);
}

#[test]
fn document_insertion_constraints() {
    visit(
        "document-insertion-constraints",
        &[
            "HierarchyRequestError true",
            "HierarchyRequestError true",
            "HierarchyRequestError",
            "HierarchyRequestError",
            "HierarchyRequestError 2",
            "true true",
            "HierarchyRequestError 2",
        ],
    );
}

#[test]
fn fragment_shadow_root_insertion() {
    visit("fragment-shadow-root-insertion", &["ok a,b 0 #document-fragment||a,b|-|-", "ok true"]);
}

#[test]
fn fragment_custom_element_complete_tree() {
    visit("fragment-custom-element-complete-tree", &["connected a true 2", "connected b true 2"]);
}

#[test]
fn append_script_observes_all_nodes() {
    visit("append-script-observes-all-nodes", &["script 3", "3"]);
}

#[test]
fn fragment_transient_observer() {
    visit("fragment-transient-observer", &["fragment:2,child:1"]);
}

#[test]
fn cross_document_custom_reactions() {
    visit("cross-document-custom-reactions", &["disconnected true true", "adopted true true true", "connected true true", "2"]);
}

#[test]
fn connected_custom_reactions() {
    visit("connected-custom-reactions", &["disconnect a true 2", "connect a true 2", "disconnect b true 2", "connect b true 2"]);
}

#[test]
fn argument_required_and_node_method_brands() {
    visit("argument-required-and-node-method-brands", &["TypeError TypeError TypeError HierarchyRequestError", "true true"]);
}

#[test]
fn convenience_method_interface_brands() {
    visit("convenience-method-interface-brands", &["TypeError", "TypeError", "TypeError", "TypeError", "TypeError", "TypeError"]);
}

#[test]
fn frozen_node_multi_replacement() {
    visit("frozen-node-multi-replacement", &["true true true 0"]);
}

#[test]
fn fragment_empty_no_destination_record() {
    visit("fragment-empty-no-destination-record", &["0 0"]);
}

#[test]
fn replace_child_invalid_reference_preserves_tree() {
    visit("replace-child-invalid-reference-preserves-tree", &["NotFoundError c a,b", "HierarchyRequestError c"]);
}

#[test]
fn replace_with_self_record() {
    visit("replace-with-self-record", &["a,b,c p||b|a|c;p|b||a|c"]);
}

#[test]
fn before_after_self_records() {
    visit("before-after-self-records", &["before a,b,c p||b|a|c;p|b||a|c", "after a,b,c p||b|a|c;p|b||a|c"]);
}

#[test]
fn foreign_fragment_ownership_by_method() {
    visit(
        "foreign-fragment-ownership-by-method",
        &[
            "append true true 0",
            "prepend true true 0",
            "appendChild true true 0",
            "insertBefore true true 0",
            "replaceChild true true 0",
            "before true true 0",
            "after true true 0",
            "replaceWith true true 0",
            "replaceChildren true true 0",
        ],
    );
}
