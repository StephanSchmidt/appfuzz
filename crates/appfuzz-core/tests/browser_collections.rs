//! Isolated Chrome and Firefox loopback references. Read-only indexed and
//! named writes follow Web IDL / Firefox; keys exclude hidden names and
//! duplicates as required by https://webidl.spec.whatwg.org/#legacy-platform-objects.
//! Existing attribute prefixes follow Chrome and the DOM attribute algorithm.
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/collections.js");
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
fn attributes_live_identity() {
    visit("attributes-live-identity", &["true 1 false [object NamedNodeMap]", "2 b", "1 b "]);
}

#[test]
fn attributes_namespace_methods() {
    visit("attributes-namespace-methods", &["A ", " 2 B", "A 1 NotFoundError"]);
}

#[test]
fn attributes_owner_shadow() {
    visit("attributes-owner-shadow", &["synthetic"]);
}

#[test]
fn attributes_indexes() {
    visit("attributes-indexes", &["false 1 false a false a false 1"]);
}

#[test]
fn attributes_method_brands() {
    visit(
        "attributes-method-brands",
        &[
            "item TypeError",
            "getNamedItem TypeError",
            "getNamedItemNS TypeError",
            "setNamedItem TypeError",
            "setNamedItemNS TypeError",
            "removeNamedItem TypeError",
            "removeNamedItemNS TypeError",
        ],
    );
}

#[test]
fn childnodes_live() {
    visit("childnodes-live", &["true 1", "2 SPAN", "1 SPAN"]);
}

#[test]
fn children_live() {
    visit("children-live", &["true 1 false [object HTMLCollection]", "2 B", "1 B"]);
}

#[test]
fn querylist_static() {
    visit("querylist-static", &["1 false   TypeError"]);
}

#[test]
fn collection_iterators() {
    visit(
        "collection-iterators",
        &[
            "NodeList 0 [object NodeList] true TypeError",
            "item item 1 false",
            "forEach forEach 1 true",
            "keys keys 0 true",
            "values values 0 true",
            "entries entries 0 true",
            "iterator function values true",
            "HTMLCollection 0 [object HTMLCollection] true TypeError",
            "item item 1 false",
            "namedItem namedItem 1 false",
            "iterator function values true",
            "NamedNodeMap 0 [object NamedNodeMap] true TypeError",
            "item item 1 false",
            "iterator function values true",
            "callback synthetic",
            "forEach ok",
            "values {\"value\":\"synthetic\",\"done\":false}",
            "keys {\"value\":0,\"done\":false}",
            "entries {\"value\":[0,\"synthetic\"],\"done\":false}",
        ],
    );
}

#[test]
fn collection_descriptors() {
    visit(
        "collection-descriptors",
        &[
            "[object NamedNodeMap] 0 true false true true",
            "[object NamedNodeMap] a true false false true",
            "[object NamedNodeMap] length false   ",
            "keys 0 0,a",
            "unsupported false  false true",
            "extensible false true",
            "[object NodeList] 0 true false true true",
            "[object NodeList] a false   ",
            "[object NodeList] length false   ",
            "keys 0 0",
            "unsupported false  false true",
            "extensible false true",
            "[object HTMLCollection] 0 true false true true",
            "[object HTMLCollection] a false   ",
            "[object HTMLCollection] length false   ",
            "keys 0 0",
            "unsupported false  false true",
            "extensible false true",
        ],
    );
}

#[test]
fn htmlcollection_names() {
    visit("htmlcollection-names", &["true true true true true true 0,1,2,3 0,1,2,3,x,one,y", "true true  "]);
}

#[test]
fn query_collections_live() {
    visit(
        "query-collections-live",
        &["getElementsByTagName [object HTMLCollection] true 1", "2", "1 true", "getElementsByClassName [object HTMLCollection] true 1", "2", "1 true"],
    );
}

#[test]
fn query_namespace_collections() {
    visit(
        "query-namespace-collections",
        &[
            "urn:a item [object HTMLCollection] 1 true false",
            "* item [object HTMLCollection] 2 true false",
            "urn:b * [object HTMLCollection] 1 false true",
            " item [object HTMLCollection] 0 false false",
            "live 2",
        ],
    );
}

#[test]
fn collection_prototype_shadows() {
    visit("collection-prototype-shadows", &["1 B synthetic synthetic 0"]);
}

#[test]
fn collection_conversions() {
    visit(
        "collection-conversions",
        &[
            "TypeError true true true TypeError TypeError",
            "TypeError true true true TypeError TypeError",
            "TypeError true true true TypeError TypeError",
            "true 1",
            "TypeError TypeError TypeError TypeError TypeError",
        ],
    );
}

#[test]
fn collection_mutation_paths() {
    visit("collection-mutation-paths", &["3 2 1 3", "3 2 0 3", "3 2 1 3", "3 1 1 2", "1 0 0 0", "3 2 0 2", "3 2 0 2", "0 0 0 0"]);
}

#[test]
fn collection_iterator_live() {
    visit("collection-iterator-live", &["B", "I true", "B,I 2 3", "B,I,U 4"]);
}

#[test]
fn collection_named_mutations() {
    visit("collection-named-mutations", &["true true", " true", "true", " true", "", "true  b"]);
}

#[test]
fn collection_namespace_case() {
    visit("collection-namespace-case", &["Item 1", "item 1", "p:Item 1", "* 3", "1 2", "B 1", "b 1", "linearGradient 1", "lineargradient 0"]);
}

#[test]
fn collection_brand_prototype() {
    visit(
        "collection-brand-prototype",
        &[
            "NodeList TypeError TypeError TypeError true",
            "HTMLCollection TypeError TypeError TypeError true",
            "NamedNodeMap TypeError TypeError TypeError true",
            "getElementsByTagName TypeError",
            "getElementsByClassName TypeError",
            "getElementsByTagNameNS TypeError",
            "querySelectorAll TypeError",
        ],
    );
}

#[test]
fn collection_numeric_names() {
    visit(
        "collection-numeric-names",
        &[
            "9 undefined false true",
            "01 object true false",
            "4294967295 object true false",
            "__proto__ object false true",
            "constructor function false true",
            "item function false true",
            "keys 0,1,2,3,4,5,9,01,4294967295",
            " true false 0,9",
        ],
    );
}

#[test]
fn collection_private_backend() {
    visit("collection-private-backend", &["1 1 1 1", "<b>synthetic</b><i>value</i> 2 0"]);
}

#[test]
fn collection_generic_shadows() {
    visit("collection-generic-shadows", &["0 true 0 0 false", "1 1", "true ordinary true large"]);
}

#[test]
fn collection_adoption() {
    visit("collection-adoption", &["0", "0 1 false", "0 1 0 false"]);
}

#[test]
fn collection_document_fragment() {
    visit("collection-document-fragment", &["1 1 true 4 true", "1 0 1 1", "1 1 0 0"]);
}

#[test]
fn collection_cached_iteration() {
    visit("collection-cached-iteration", &["1024 256 256 256", "255 255 255"]);
}

#[test]
fn collection_private_intrinsics() {
    visit("collection-private-intrinsics", &["2,2,synthetic,1,1,2 0"]);
}

#[test]
fn collection_private_doctype() {
    visit("collection-private-doctype", &["html 0"]);
}
