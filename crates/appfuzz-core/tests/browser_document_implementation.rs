//! Native Document factories/adoption, metadata and private title/base URL state.
//! Firefox158 and Chromium128 agree except doctype names; those follow current
//! DOM valid-doctype-name rules and Firefox. https://dom.spec.whatwg.org/#namespaces
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/document_implementation.js");
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
fn implementation_identity() {
    visit("implementation-identity", &["identity function true true 0", "constructor TypeError", "borrowed true TypeError"]);
}

#[test]
fn create_html_document() {
    visit(
        "create-html-document",
        &[
            "html text/html UTF-8 CSS1Compat about:blank hello html <html><head><title>hello</title></head><body></body></html> true true",
            "titles  null TypeError",
        ],
    );
}

#[test]
fn create_document_type() {
    visit("create-document-type", &["doctype 10 p:q pub sys true true", " ", "a b InvalidCharacterError", "a::b a::b", "arguments TypeError"]);
}

#[test]
fn create_xml_document() {
    visit("create-xml-document", &["xml application/xml UTF-8 p:root urn:test true true true", "empty 0 true", "bad NamespaceError"]);
}

#[test]
fn adopt_node_explicit() {
    visit("adopt-node-explicit", &["adopt true true true true true 0", "document NotSupportedError", "brand TypeError"]);
}

#[test]
fn adopt_attribute() {
    visit("adopt-attribute", &["attr true true true 0 one"]);
}

#[test]
fn implementation_brands() {
    visit(
        "implementation-brands",
        &[
            "createDocumentType TypeError",
            "createDocument TypeError",
            "createHTMLDocument TypeError",
            "hasFeature TypeError",
            "feature true [object DOMImplementation] 0",
        ],
    );
}

#[test]
fn html_title_options() {
    visit(
        "html-title-options",
        &[
            "title undefined 0   true",
            "title  1  <title></title> true",
            "title null 1 null <title>null</title> true",
            "title <b>&x 1 <b>&x <title>&lt;b&gt;&amp;x</title> true",
            "distinct true",
        ],
    );
}

#[test]
fn factory_conversion_order() {
    visit("factory-conversion-order", &["doctype InvalidCharacterError name,public,system", "document TypeError namespace,name", "missing TypeError 0"]);
}

#[test]
fn xml_namespace_types() {
    visit(
        "xml-namespace-types",
        &[
            "type null application/xml root null true",
            "type  application/xml root null true",
            "type urn:x application/xml root urn:x true",
            "type http://www.w3.org/1999/xhtml application/xhtml+xml root http://www.w3.org/1999/xhtml true",
            "type http://www.w3.org/2000/svg image/svg+xml root http://www.w3.org/2000/svg true",
            "null-name 0",
        ],
    );
}

#[test]
fn doctype_transfer() {
    visit("doctype-transfer", &["moved true true true 2 1 true"]);
}

#[test]
fn doctype_current_names() {
    visit(
        "doctype-current-names",
        &["\"\" ", "\"a::b\" a::b", "\"a/b\" a/b", "\"a>b\" InvalidCharacterError", "\"a\\tb\" InvalidCharacterError", "\"a\\u0000b\" InvalidCharacterError"],
    );
}

#[test]
fn adopt_shadow_root() {
    visit("adopt-shadow-root", &["shadow HierarchyRequestError true", "missing TypeError TypeError TypeError"]);
}

#[test]
fn adopt_observer_record() {
    visit("adopt-observer-record", &["records [[\"childList\",true,false,null,1],[\"characterData\",false,true,\"hello\",0]] true true"]);
}

#[test]
fn adopt_custom_callbacks() {
    visit("adopt-custom-callbacks", &["callbacks [[\"disconnected\",true,false],[\"adopted\",true,true,true,false]] true"]);
}

#[test]
fn adopt_property_shadows() {
    visit("adopt-property-shadows", &["adopt true true true 0"]);
}

#[test]
fn adopt_fragment() {
    visit("adopt-fragment", &["fragment true true true true true 1"]);
}

#[test]
fn adopt_attribute_record() {
    visit("adopt-attribute-record", &["attribute false true true 1 attributes x old"]);
}

#[test]
fn factory_private_methods() {
    visit("factory-private-methods", &["factories hello root 0"]);
}

#[test]
fn xml_document_interface() {
    visit("xml-document-interface", &["interface function true true true [object XMLDocument] TypeError"]);
}

#[test]
fn factory_base_metadata() {
    visit(
        "factory-base-metadata",
        &[
            "metadata about:blank about:blank true false UTF-8 CSS1Compat",
            "metadata about:blank about:blank true false UTF-8 CSS1Compat",
            "base https://base.example/path/",
            "changed https://other.example/",
        ],
    );
}

#[test]
fn html_title_whitespace() {
    visit("html-title-whitespace", &["title \"A B C\" \" \\tA\\n B \\r C \"", "set \"X Y\" \"  X\\t Y  \""]);
}

#[test]
fn implementation_descriptors() {
    visit("implementation-descriptors", &["methods createDocument,createDocumentType,createHTMLDocument,hasFeature true 0 3 2 0 0", "xml-prototype true true"]);
}

#[test]
fn adopt_shadow_and_template() {
    visit("adopt-shadow-and-template", &["tree true true true true true true true"]);
}

#[test]
fn svg_document_title() {
    visit("svg-document-title", &["empty \"\"", "svg X Y title 2 \" X\\t Y \"", "again Z 2"]);
}

#[test]
fn title_private_accessors() {
    visit("title-private-accessors", &["get A B 0", "set X Y 1 0 TypeError"]);
}

#[test]
fn base_href_reflection() {
    visit(
        "base-href-reflection",
        &[
            "missing \"\" false",
            "relative relative relative",
            "absolute https://base.example/x https://base.example/x https://base.example/x",
            "private true 0",
        ],
    );
}

#[test]
fn xml_template_private_constructor() {
    visit("xml-template-private-constructor", &["template child text true true 0"]);
}

#[test]
fn base_cache_invalidation() {
    visit(
        "base-cache-invalidation",
        &[
            "first https://one.example/",
            "remove https://two.example/",
            "missing https://two.example/",
            "attribute https://three.example/",
            "unset https://two.example/",
        ],
    );
}
