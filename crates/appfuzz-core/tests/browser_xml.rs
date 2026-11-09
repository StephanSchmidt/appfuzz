//! Isolated Chrome and Firefox loopback fixtures. Standard choices: preserve
//! existing attribute prefixes (Chrome), report the actual document encoding
//! and reject malformed XML bytes (Firefox), use normative hex attribute
//! escapes (Firefox), and generate ns1 prefixes without doctype padding
//! (Chrome). Simulated echo responses are paired with byte-exact assertions
//! on the real guest-to-host request, rather than serving as serializer proof.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn request_bodies(case: &str, expected: &[&str]) -> Vec<(String, String)> {
    if !case.starts_with("xml-body-") && case != "xhr-document-body" {
        return vec![];
    }
    expected
        .iter()
        .map(|row| {
            let raw = row.strip_prefix("0 ").unwrap_or(row);
            let (body, mime) = raw.rsplit_once(' ').unwrap();
            let body = if case == "xml-body-attribute-escaping" { serde_json::from_str(body).unwrap() } else { body.to_owned() };
            (body, mime.to_owned())
        })
        .collect()
}
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/xml.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|s| s.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let bodies = request_bodies(case, expected);
    let mut plan: Value = serde_json::from_str(include_str!("fixtures/xml-plan.json")).unwrap();
    if !bodies.is_empty() {
        let mut answers = serde_json::Map::new();
        for (i, (body, mime)) in bodies.iter().enumerate() {
            let payload = json!({"method":"POST","body":body,"headers":{"content-type":mime}}).to_string();
            answers
                .insert((i + 1).to_string(), json!({"return":{"ok":{"status":200,"headers":[["content-type","application/json"]],"body":payload.as_bytes()}}}));
        }
        plan[FETCH_OWN]["on_call"] = Value::Object(answers);
    }
    let plan: Plan = serde_json::from_value(plan).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert!(run.events.iter().all(|e| e.func == FETCH_OWN), "{:?}", run.events);
    if !bodies.is_empty() {
        assert_eq!(run.events.len(), bodies.len());
        for (event, (body, mime)) in run.events.iter().zip(&bodies) {
            assert_eq!(event.args["path"], "/echo");
            assert_eq!(event.args["method"], "POST");
            assert_eq!(event.args["body"], json!({"some":body.as_bytes()}), "{case}");
            assert!(event.args["headers"].as_array().unwrap().contains(&json!(["content-type", mime])), "{:?}", event.args);
        }
    }
    if case == "xml-private-array-iterator" {
        assert_eq!(run.events.len(), 1);
        assert_eq!(run.events[0].args["body"], json!({"some":"<root xmlns:p=\"urn:p\" p:id=\"synthetic\"/>".as_bytes()}));
    }
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

#[test]
fn xml_attribute_create() {
    visit(
        "xml-attribute-create",
        &[
            "id id    false id ",
            "p:id id p urn:a  false p:id ",
            "id id    false id ",
            "xmlns:p p xmlns http://www.w3.org/2000/xmlns/  false xmlns:p ",
            "xml:lang lang xml http://www.w3.org/XML/1998/namespace  false xml:lang ",
        ],
    );
}

#[test]
fn xml_attribute_coexist() {
    visit("xml-attribute-coexist", &["plain A A B  id:id:::plain|p:id:id:p:urn:a:A|q:id:id:q:urn:b:B", "id:id:::plain|q:id:id:q:urn:b:B"]);
}

#[test]
fn xml_attribute_prefix() {
    visit("xml-attribute-prefix", &["true p:id p id B B ", "urn:a B"]);
}

#[test]
fn xml_attribute_nodes() {
    visit("xml-attribute-nodes", &[" true InUseAttributeError", "true  true q:id:id:q:urn:a:B", "true  NotFoundError"]);
}

#[test]
fn xml_attribute_conversion() {
    visit(
        "xml-attribute-conversion",
        &["InvalidCharacterError ns,name,value", "NamespaceError", "NamespaceError", "NamespaceError", "NamespaceError", "TypeError"],
    );
}

#[test]
fn xml_attribute_case() {
    visit("xml-attribute-case", &["upper:upper:::a|UPPER:UPPER:::b a b", "upper UPPER"]);
}

#[test]
fn xml_attribute_order() {
    visit("xml-attribute-order", &["a,b,p:id", "a,b,p:id a:a:::4|b:b:::2|p:id:id:p:urn:a:A", "a,p:id,b"]);
}

#[test]
fn xml_attribute_class() {
    visit("xml-attribute-class", &["true a b a b", "x x", " ", "  hidden"]);
}

#[test]
fn xml_attribute_shadow() {
    visit("xml-attribute-shadow", &["A", "B 0", "false 0"]);
}

#[test]
fn xml_attribute_clone() {
    visit("xml-attribute-clone", &["urn:root A p:id:id:p:urn:a:A", "p:id id p urn:a A "]);
}

#[test]
fn xml_attribute_observer() {
    visit("xml-attribute-observer", &["id urn:a ", "id urn:a A", "id urn:a B"]);
}

#[test]
fn xml_attribute_reaction() {
    visit("xml-attribute-reaction", &["id::A:urn:a|id:A:B:urn:a|id:B::urn:a"]);
}

#[test]
fn xml_body_basic() {
    visit(
        "xml-body-basic",
        &[
            "0 <root><value>synthetic</value></root> application/xml;charset=UTF-8",
            "0 <root><empty/></root> application/xml;charset=UTF-8",
            "0 <root xmlns=\"urn:r\" xmlns:p=\"urn:p\" p:id=\"A&amp;B\"><p:item>text</p:item></root> application/xml;charset=UTF-8",
            "0 <!DOCTYPE root><root><![CDATA[synthetic]]><!--comment--></root> application/xml;charset=UTF-8",
        ],
    );
}

#[test]
fn xml_body_html() {
    visit(
        "xml-body-html",
        &[
            "<!DOCTYPE html><html><head><title>A&amp;B</title></head><body><input value=\"&quot;\"><script>const x=\"<\"</script></body></html> text/html;charset=UTF-8",
        ],
    );
}

#[test]
fn xml_body_native_state() {
    visit("xml-body-native-state", &["0 <root><value>synthetic</value></root> application/xml;charset=UTF-8"]);
}

#[test]
fn xml_response_fidelity() {
    visit("xml-response-fidelity", &["/xml-cdata true synthetic  4:synthetic", "/xml-doctype true synthetic root 3:synthetic", "/xml-latin true café  3:café"]);
}

#[test]
fn xml_attribute_namespaces() {
    visit("xml-attribute-namespaces", &["synthetic true ", "xmlns:p p xmlns http://www.w3.org/2000/xmlns/ urn:p", "p:id id p urn:p synthetic"]);
}

#[test]
fn xhr_document_body() {
    visit("xhr-document-body", &["0 <root><value>synthetic</value></root> application/xml;charset=UTF-8"]);
}

#[test]
fn xml_cdata_sections() {
    visit("xml-cdata-sections", &["/xml-cdata-mixed ab\ncd&e true 3:a|4:b\nc|3:d&e|4:", "/xml-cdata-empty  true 4:", "/xml-entity synthetic true 1:synthetic"]);
}

#[test]
fn xml_doctype_ids() {
    visit("xml-doctype-ids", &["root -//synthetic//EN synthetic.dtd root false"]);
}

#[test]
fn xml_processing_instructions() {
    visit("xml-processing-instructions", &["7:before:data|1:root:", "7:after:data"]);
}

#[test]
fn xml_declared_encodings() {
    visit(
        "xml-declared-encodings",
        &[
            "/xml-latin true café windows-1252",
            "/xml-shift-jis true あ Shift_JIS",
            "/xml-utf16 true synthetic UTF-16LE",
            "/xml-http-latin true cafÃ© windows-1252",
        ],
    );
}

#[test]
fn xml_invalid_encoding() {
    visit("xml-invalid-encoding", &["/xml-bad-bytes true", "/xml-unknown-encoding false", "/xml-bom-unknown false"]);
}

#[test]
fn xml_text_vs_document() {
    visit(
        "xml-text-vs-document",
        &[
            " <?xml version=\"1.0\" encoding=\"windows-1252\"?><root>café</root>",
            "text <?xml version=\"1.0\" encoding=\"windows-1252\"?><root>caf�</root>",
            "document café",
        ],
    );
}

#[test]
fn xml_parser_public() {
    visit(
        "xml-parser-public",
        &[
            "application/xml application/xml urn:r p r /",
            "text/xml text/xml urn:r p r /",
            "application/xhtml+xml application/xhtml+xml urn:r p r /",
            "image/svg+xml image/svg+xml urn:r p r /",
            "true",
            "TypeError TypeError",
        ],
    );
}

#[test]
fn xml_observer_filter() {
    visit("xml-observer-filter", &["id  "]);
}

#[test]
fn xml_body_generated_prefix() {
    visit("xml-body-generated-prefix", &["<root xmlns:ns1=\"urn:a\" ns1:id=\"A\"/> application/xml;charset=UTF-8"]);
}

#[test]
fn xml_body_attribute_escaping() {
    visit(
        "xml-body-attribute-escaping",
        &["\"<root value=\\\"&#9;&#xA;&#xD;&quot;&lt;&amp;&gt;\\\">text\\r&lt;&amp;&gt;</root>\" application/xml;charset=UTF-8"],
    );
}

#[test]
fn xml_attribute_adopt() {
    visit("xml-attribute-adopt", &["true true", "true urn:a A"]);
}

#[test]
fn xml_attribute_value_shadows() {
    visit("xml-attribute-value-shadows", &["B 0", "0 "]);
}

#[test]
fn xml_attribute_name_validation() {
    visit(
        "xml-attribute-name-validation",
        &[
            "\"1a\" v 1a",
            "\"a=b\" InvalidCharacterError InvalidCharacterError",
            "\"a\\\"b\" v a\"b",
            "\"a<b\" v a<b",
            "\":x\" v :x",
            "\"é\" v é",
            "\"a\\u0000b\" InvalidCharacterError InvalidCharacterError",
            "\"a/b\" InvalidCharacterError InvalidCharacterError",
            "\"a b\" InvalidCharacterError InvalidCharacterError",
        ],
    );
}

#[test]
fn xml_attribute_constructor_hooks() {
    visit("xml-attribute-constructor-hooks", &["0"]);
}

#[test]
fn xml_private_array_iterator() {
    visit("xml-private-array-iterator", &["0"]);
}

#[test]
fn xml_wide_attribute_order() {
    visit("xml-wide-attribute-order", &["512 p:a0 p:a511 255", "p:last"]);
}

#[test]
fn xml_document_root_shadows() {
    visit("xml-document-root-shadows", &["true 0", "TypeError"]);
}
