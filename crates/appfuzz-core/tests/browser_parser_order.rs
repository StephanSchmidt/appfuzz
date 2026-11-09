//! Incremental parser visibility and preparation, checked against agreeing
//! local Firefox158 and Chromium128 references. Parser prototypes are private.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/parser_order.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let prefixes: Value = serde_json::from_str(include_str!("fixtures/parser_prefixes.json")).unwrap();
    let prefix = prefixes.get(case).and_then(Value::as_str).unwrap_or("");
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html>{prefix}<body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], network_plan(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

fn network_plan() -> Plan {
    let mut rules = vec![];
    for prefix in ["/", "/nested/", "/changed/", "/headers/"] {
        for (name, body) in [
            ("data", json!({"path":format!("{prefix}data")}).to_string()),
            ("part.js", format!("globalThis.externalPath={};", json!(format!("{prefix}part.js")))),
            ("part.mjs", format!("import './dep.mjs';globalThis.modulePath={};", json!(format!("{prefix}part.mjs")))),
            ("dep.mjs", format!("globalThis.dependencyPath={};", json!(format!("{prefix}dep.mjs")))),
        ] {
            rules.push(json!({"when":{"path":format!("{prefix}{name}")},"return":{"ok":{"status":200,"headers":[],"body":body.as_bytes()}}}));
        }
    }
    Plan::parse(&json!({FETCH_OWN:{"rules":rules,"default":{"return":{"ok":{"status":404,"headers":[],"body":[]}}}}}).to_string()).unwrap()
}

#[test]
fn parser_policy_after_script() {
    visit("parser-policy-after-script", &["before /nested/ after /nested/"]);
}

#[test]
fn head_blocking_visibility() {
    visit("head-blocking-visibility", &["true true true"]);
}

#[test]
fn blocking_script_and_microtask() {
    visit("blocking-script-and-microtask", &["script true dynamic true microtask true"]);
}

#[test]
fn removed_open_ancestor() {
    visit("removed-open-ancestor", &["tail true"]);
}

#[test]
fn native_parser_intrinsics() {
    visit("native-parser-intrinsics", &["0"]);
}

#[test]
fn native_parser_methods() {
    visit("native-parser-methods", &["0"]);
}

#[test]
fn deferred_script_base_preparation() {
    visit("deferred-script-base-preparation", &["/nested/part.js"]);
}

#[test]
fn inline_module_base_preparation() {
    visit("inline-module-base-preparation", &["/nested/"]);
}

#[test]
fn svg_parser_script() {
    visit("svg-parser-script", &["true"]);
}

#[test]
fn parser_custom_element_timing() {
    visit("parser-custom-element-timing", &["construct 0 0 true;connected 0;"]);
}

#[test]
fn parser_template_isolation() {
    visit("parser-template-isolation", &["false false"]);
}

#[test]
fn native_parser_table_fostering() {
    visit("native-parser-table-fostering", &["before cell"]);
}

#[test]
fn native_parser_private_node_metadata() {
    visit("native-parser-private-node-metadata", &["0 tail"]);
}

#[test]
fn native_parser_string_intrinsics() {
    visit("native-parser-string-intrinsics", &["0"]);
}

#[test]
fn parser_head_body_descriptors() {
    visit("parser-head-body-descriptors", &["false false"]);
}

#[test]
fn svg_owner_live() {
    visit("svg-owner-live", &["true false", "true", "true"]);
}

#[test]
fn svg_owner_private_parent() {
    visit("svg-owner-private-parent", &["true 0"]);
}
