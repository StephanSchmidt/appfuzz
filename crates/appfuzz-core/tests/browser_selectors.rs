//! Independent Chrome/Firefox synthetic references. SVG type names remain case
//! sensitive, and explicit attribute `s` flags follow the HTML standard/Firefox.
//! https://html.spec.whatwg.org/multipage/semantics-other.html#case-sensitivity-of-selectors
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/selectors.js");
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
fn query_interface_brands() {
    visit(
        "query-interface-brands",
        &[
            "querySelector TypeError TypeError TypeError",
            "querySelectorAll TypeError TypeError TypeError",
            "getElementsByTagName TypeError TypeError TypeError",
            "getElementsByClassName TypeError TypeError TypeError",
            "getElementsByTagNameNS TypeError TypeError TypeError",
        ],
    );
}

#[test]
fn query_invalid_selectors() {
    visit(
        "query-invalid-selectors",
        &[
            ":contains(synthetic) SyntaxError",
            ":icontains(SYNTHETIC) SyntaxError",
            ":unknown SyntaxError",
            "[ SyntaxError",
            ":is(.a,:unknown) 1",
            ":where(.a,:unknown) 1",
        ],
    );
}

#[test]
fn query_private_attributes() {
    visit("query-private-attributes", &["1 1 1 0"]);
}

#[test]
fn query_private_node_type() {
    visit("query-private-node-type", &["1 1 1 0"]);
}

#[test]
fn query_private_parent() {
    visit("query-private-parent", &["1 1 0"]);
}

#[test]
fn query_empty_forgiving() {
    visit(
        "query-empty-forgiving",
        &[
            ":is() 0",
            ":where() 0",
            ":is(.a,) 1",
            ":is(,.a) 1",
            ":is(.a,:not()) 1",
            ":is(.a,[) 1",
            ":is(.a,:not(.b,)) 1",
            ":where(:unknown) 0",
            ":not() SyntaxError",
            ":has() SyntaxError",
            ":has(:has(b)) SyntaxError",
            ":has(:is(::before,b)) 0",
        ],
    );
}

#[test]
fn query_pseudo_elements() {
    visit(
        "query-pseudo-elements",
        &[
            "::before 0",
            ":before 0",
            "b::after 0",
            ".a,::before 1",
            ":is(.a,::before) 1",
            ":not(::before) SyntaxError",
            ":has(::before) SyntaxError",
            "::unknown SyntaxError",
            "::part(x) 0",
            "::slotted(b) 0",
        ],
    );
}

#[test]
fn query_namespace_types() {
    visit(
        "query-namespace-types",
        &[
            "linearGradient 1",
            "lineargradient 0",
            "svg linearGradient 1",
            "SVG linearGradient 0",
            "*|linearGradient 1",
            "|linearGradient 0",
            "p|linearGradient SyntaxError",
            "item 3",
            "*|item 3",
            "|item 1",
            "p|item SyntaxError",
            "item:first-of-type 3",
            "item:nth-of-type(1) 3",
        ],
    );
}

#[test]
fn query_attribute_namespaces() {
    visit(
        "query-attribute-namespaces",
        &["[x] true", "[|x] true", "[*|x] true", "[p|x] SyntaxError", "[x=\"A\"] false", "[*|x=\"A\"] true", "[x!=\"plain\"] SyntaxError"],
    );
}

#[test]
fn query_detached_structural() {
    visit(
        "query-detached-structural",
        &[
            ":root false",
            ":scope true",
            ":first-child true",
            ":last-child true",
            ":only-child true",
            ":nth-child(1) true",
            ":nth-last-child(1) true",
            ":first-of-type true",
            ":nth-of-type(1) true",
            "\"\" true",
            "\" \" false",
            "\"\\n\" false",
            "\"synthetic\" false",
        ],
    );
}

#[test]
fn query_matches_closest_private() {
    visit(
        "query-matches-closest-private",
        &["true true true 0", "matches TypeError TypeError TypeError TypeError", "closest TypeError TypeError TypeError TypeError"],
    );
}

#[test]
fn query_live_states() {
    visit(
        "query-live-states",
        &[
            ":checked INPUT:checkbox,OPTION",
            ":indeterminate INPUT:radio",
            ":disabled FIELDSET,INPUT:text",
            ":enabled INPUT:checkbox,INPUT:radio,SELECT,OPTION,OPTION,INPUT:text",
        ],
    );
}

#[test]
fn query_scope_relations() {
    visit(
        "query-scope-relations",
        &[
            ":scope 0",
            ":scope > b 2",
            "body b 2",
            "b:has(> i) 1",
            "b:has(+ b) 1",
            "b:has(~ span) 2",
            "b:is(:first-child,:last-child) 1",
            "b:nth-child(1 of b) 1",
            "b:nth-last-child(1 of b) 1",
            "b:not(:has(i)) 1",
            "true true",
        ],
    );
}

#[test]
fn query_attribute_rules() {
    visit(
        "query-attribute-rules",
        &[
            "[TYPE=text] true",
            "[type=text s] false",
            "[type=\"TEXT\" s] true",
            "[data-value^=\"Alpha\"] true",
            "[data-value$=\"end\"] true",
            "[data-value*=\"beta\"] true",
            "[data-value~=\"beta-end\"] true",
            "[data-value|=\"Alpha\"] false",
            "[data-value^=\"\"] false",
            ".A true",
            ".a false",
            "#Mixed true",
            "#mixed false",
            "quirks 1 1 0",
        ],
    );
}

#[test]
fn query_conversion_order() {
    visit(
        "query-conversion-order",
        &[
            "querySelector TypeError 0",
            "querySelectorAll TypeError 0",
            "matches TypeError 0",
            "closest TypeError 0",
            "getElementsByTagName TypeError 0",
            "1",
            "querySelector TypeError TypeError",
            "querySelectorAll TypeError TypeError",
            "matches TypeError TypeError",
            "closest TypeError TypeError",
        ],
    );
}

#[test]
fn query_syntax_escapes() {
    visit(
        "query-syntax-escapes",
        &[
            "#a\\:b 1",
            ".\\61 1",
            ":\\69s(.a,:unknown) 1",
            ":IS(.a,:unknown) 1",
            ":where(.a,[broken) 1",
            ":is(.a,> b) 1",
            ":not(> b) SyntaxError",
            "> b SyntaxError",
            "b < i SyntaxError",
            "b || i SyntaxError",
            ":first-child() SyntaxError",
            ":nth-child(nope) SyntaxError",
            ":nth-child(1 of :unknown) SyntaxError",
            ":nth-child(1 of :is(.a,:unknown)) 1",
        ],
    );
}

#[test]
fn query_private_attr_slots() {
    visit("query-private-attr-slots", &["true 0"]);
}

#[test]
fn query_private_name_slots() {
    visit("query-private-name-slots", &["1 true true 0"]);
}

#[test]
fn query_private_text_slots() {
    visit("query-private-text-slots", &["false 0"]);
}

#[test]
fn query_private_library_intrinsics() {
    visit("query-private-library-intrinsics", &["1 0"]);
}

#[test]
fn query_private_array_operations() {
    visit("query-private-array-operations", &["1 0"]);
}

#[test]
fn query_private_string_operations() {
    visit("query-private-string-operations", &["1 0"]);
}

#[test]
fn query_private_regexp_operations() {
    visit("query-private-regexp-operations", &["1 0"]);
}

#[test]
fn query_private_tables() {
    visit("query-private-tables", &["1 0"]);
}

#[test]
fn query_private_record_setters() {
    visit("query-private-record-setters", &["1 0"]);
}

#[test]
fn query_native_child_traversal() {
    visit("query-native-child-traversal", &["true true true true 2 true 0", "true true true 0"]);
}

#[test]
fn query_native_parent_siblings() {
    visit("query-native-parent-siblings", &["true true true true true true true true true true 0"]);
}

#[test]
fn query_native_shadow_roots() {
    visit("query-native-shadow-roots", &["open true true true  0", "closed true true true  0", "TypeError 0 TypeError", "true true true true 1"]);
}
