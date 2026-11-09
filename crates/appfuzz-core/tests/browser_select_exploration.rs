//! Select exploration checked with real Chromium keyboard and control-click
//! input on local synthetic pages. The controller must use private DOM state,
//! choose enabled options, and send native select input/change events.
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(name: &str, expected: &[&str]) {
    let cases: Value = serde_json::from_str(include_str!("fixtures/select_exploration.json")).unwrap();
    let c = &cases[name];
    let script = format!("{};setTimeout(()=>{{for(const row of finish())console.log(row)}},2000)", c["script"].as_str().unwrap());
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body>{}<script>{script}</script>",c["html"].as_str().unwrap())});
    let browser = Browser::shared().unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["requests"], json!([]), "{report}");
    assert!(run.events.iter().all(|event| event.func == HTML), "{:?}", run.events);
    assert_eq!(report["actions"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["actions"][0]["kind"], "select", "{report}");
    assert_eq!(report["actions"][0]["id"], "target", "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{name}");
}

#[test]
fn ordinary() {
    visit(
        "ordinary",
        &["input [1,\"b\",true,true,true,false,\"[object Event]\"]", "change [1,\"b\",true,true,false,false,\"[object Event]\"]", "final 1 b [\"b\"] 0"],
    );
}

#[test]
fn disabled_option() {
    visit(
        "disabled-option",
        &["input [2,\"c\",true,true,true,false,\"[object Event]\"]", "change [2,\"c\",true,true,false,false,\"[object Event]\"]", "final 2 c [\"c\"] 0"],
    );
}

#[test]
fn disabled_group() {
    visit(
        "disabled-group",
        &["input [2,\"c\",true,true,true,false,\"[object Event]\"]", "change [2,\"c\",true,true,false,false,\"[object Event]\"]", "final 2 c [\"c\"] 0"],
    );
}

#[test]
fn one_enabled() {
    visit("one-enabled", &["final 0 a [\"a\"] 0"]);
}

#[test]
fn empty() {
    visit("empty", &["final -1  [] 0"]);
}

#[test]
fn only_disabled() {
    visit("only-disabled", &["final -1  [] 0"]);
}

#[test]
fn wrap_choice() {
    visit(
        "wrap-choice",
        &["input [0,\"a\",true,true,true,false,\"[object Event]\"]", "change [0,\"a\",true,true,false,false,\"[object Event]\"]", "final 0 a [\"a\"] 0"],
    );
}

#[test]
fn private_hooks() {
    visit(
        "private-hooks",
        &["input [1,\"b\",true,true,true,false,\"[object Event]\"]", "change [1,\"b\",true,true,false,false,\"[object Event]\"]", "final 1 b [\"b\"] 0"],
    );
}

#[test]
fn focus_disables() {
    visit("focus-disables", &["final 0 a [\"a\"] 0"]);
}

#[test]
fn focus_removes() {
    visit("focus-removes", &["final 0 a [\"a\"] 0"]);
}

#[test]
fn focus_replaces_options() {
    visit(
        "focus-replaces-options",
        &["input [1,\"d\",true,true,true,false,\"[object Event]\"]", "change [1,\"d\",true,true,false,false,\"[object Event]\"]", "final 1 d [\"d\"] 0"],
    );
}

#[test]
fn multiple_toggle() {
    visit(
        "multiple-toggle",
        &["input [0,\"a\",true,true,true,false,\"[object Event]\"]", "change [0,\"a\",true,true,false,false,\"[object Event]\"]", "final 0 a [\"a\",\"b\"] 0"],
    );
}

#[test]
fn multiple_unselect() {
    visit(
        "multiple-unselect",
        &["input [0,\"a\",true,true,true,false,\"[object Event]\"]", "change [0,\"a\",true,true,false,false,\"[object Event]\"]", "final 0 a [\"a\"] 0"],
    );
}

#[test]
fn private_number() {
    visit(
        "private-number",
        &["input [1,\"b\",true,true,true,false,\"[object Event]\"]", "change [1,\"b\",true,true,false,false,\"[object Event]\"]", "final 1 b [\"b\"] 0"],
    );
}
