//! JSON serialization must not expose private engine lists to page callbacks.
//! Expected results independently agree in Chrome and Firefox.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/json_serialization.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = Plan::default();
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
fn json_private_stack() {
    assert_eq!(visit("json-private-stack"), ["{\"x\":1} 0"]);
}

#[test]
fn response_json_private_stack() {
    assert_eq!(visit("response-json-private-stack"), ["{\"x\":1} 0"]);
}

#[test]
fn json_private_replacer_list() {
    assert_eq!(visit("json-private-replacer-list"), ["{\"x\":1} 0"]);
}

#[test]
fn json_private_stack_depth() {
    assert_eq!(visit("json-private-stack-depth"), ["{\"x\":[{\"y\":2}]} 0"]);
}

#[test]
fn json_public_inherited_index() {
    assert_eq!(visit("json-public-inherited-index"), ["[\"inherited\"] 1"]);
}

#[test]
fn json_public_callbacks() {
    assert_eq!(visit("json-public-callbacks"), ["{\"x\":3} 1 1 2"]);
}

#[test]
fn json_cycles_and_shared() {
    assert_eq!(visit("json-cycles-and-shared"), ["[{\"x\":1},{\"x\":1}]", "TypeError", "true"]);
}

#[test]
fn json_inherited_tojson() {
    assert_eq!(visit("json-inherited-tojson"), ["{\"x\":{\"y\":2}} 2"]);
}
