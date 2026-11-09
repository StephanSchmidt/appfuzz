//! Synthetic Firefox/Chromium references for private select/option state.
//! Cross-browser disagreements follow the HTML selectedness, dirtiness, size
//! and disabled-attribute mutation algorithms rather than legacy browser bugs:
//! https://html.spec.whatwg.org/multipage/form-elements.html#the-select-element
//! In particular every chosen option becomes dirty even when already selected;
//! size/disabled changes reset selection, and clean default changes clear peers.
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/select_state.js");
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
fn select_defaults() {
    visit(
        "select-defaults",
        &[
            "<option>A</option><option>B</option>  {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "<option disabled>A</option><option>B</option>  {\"index\":1,\"value\":\"B\",\"flags\":[false,true],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "<option selected>A</option><option selected>B</option>  {\"index\":1,\"value\":\"B\",\"flags\":[false,true],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "<option>A</option><option>B</option> size=2 {\"index\":-1,\"value\":\"\",\"flags\":[false,false],\"checked\":[],\"entries\":[]}",
            "<option>A</option><option>B</option> multiple {\"index\":-1,\"value\":\"\",\"flags\":[false,false],\"checked\":[],\"entries\":[]}",
            "<optgroup disabled><option>A</option></optgroup><option>B</option>  {\"index\":1,\"value\":\"B\",\"flags\":[false,true],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
        ],
    );
}

#[test]
fn select_selected_index() {
    visit(
        "select-selected-index",
        &[
            "-1 {\"index\":-1,\"value\":\"\",\"flags\":[false,false],\"checked\":[],\"entries\":[]}",
            "1 {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "0 {\"index\":0,\"value\":\"a\",\"flags\":[true,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            "2 {\"index\":-1,\"value\":\"\",\"flags\":[false,false],\"checked\":[],\"entries\":[]}",
            "1 {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "1.8 {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "null {\"index\":0,\"value\":\"a\",\"flags\":[true,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            "undefined {\"index\":0,\"value\":\"a\",\"flags\":[true,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            "4294967297 {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
        ],
    );
}

#[test]
fn select_value() {
    visit(
        "select-value",
        &[
            " a {\"index\":0,\"value\":\"a\",\"flags\":[true,false,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            " b {\"index\":2,\"value\":\"b\",\"flags\":[false,false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            " missing {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
            " a {\"index\":0,\"value\":\"a\",\"flags\":[true,false,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            "multiple a {\"index\":0,\"value\":\"a\",\"flags\":[true,false,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            "multiple b {\"index\":2,\"value\":\"b\",\"flags\":[false,false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "multiple missing {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
            "multiple a {\"index\":0,\"value\":\"a\",\"flags\":[true,false,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
        ],
    );
}

#[test]
fn option_setter() {
    visit(
        "option-setter",
        &[
            " 1 true {\"index\":1,\"value\":\"B\",\"flags\":[false,true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            " 2 true {\"index\":2,\"value\":\"C\",\"flags\":[false,false,true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
            " 2 false {\"index\":0,\"value\":\"A\",\"flags\":[true,false,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            " 0 false {\"index\":0,\"value\":\"A\",\"flags\":[true,false,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            " 1 false {\"index\":0,\"value\":\"A\",\"flags\":[true,false,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "multiple 1 true {\"index\":1,\"value\":\"B\",\"flags\":[false,true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "multiple 2 true {\"index\":1,\"value\":\"B\",\"flags\":[false,true,true],\"checked\":[\"B\",\"C\"],\"entries\":[[\"s\",\"B\"],[\"s\",\"C\"]]}",
            "multiple 2 false {\"index\":1,\"value\":\"B\",\"flags\":[false,true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "multiple 0 false {\"index\":1,\"value\":\"B\",\"flags\":[false,true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "multiple 1 false {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
            "size=2 1 true {\"index\":1,\"value\":\"B\",\"flags\":[false,true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "size=2 2 true {\"index\":2,\"value\":\"C\",\"flags\":[false,false,true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
            "size=2 2 false {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
            "size=2 0 false {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
            "size=2 1 false {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
        ],
    );
}

#[test]
fn option_attribute() {
    visit(
        "option-attribute",
        &[
            "initial {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "set B {\"index\":1,\"value\":\"B\",\"flags\":[false,true],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "set A {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "remove A {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "dirty B {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "dirty B attribute {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "reset {\"index\":1,\"value\":\"B\",\"flags\":[false,true],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
        ],
    );
}

#[test]
fn select_mutation() {
    visit(
        "select-mutation",
        &[
            "none {\"index\":-1,\"value\":\"\",\"flags\":[false,false],\"checked\":[],\"entries\":[]}",
            "append C {\"index\":0,\"value\":\"A\",\"flags\":[true,false,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "B {\"index\":1,\"value\":\"B\",\"flags\":[false,true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "remove A {\"index\":0,\"value\":\"B\",\"flags\":[true,false],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"]]}",
            "remove B {\"index\":0,\"value\":\"C\",\"flags\":[true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
            "prepend selected D {\"index\":0,\"value\":\"D\",\"flags\":[true,false],\"checked\":[\"D\"],\"entries\":[[\"s\",\"D\"]]}",
            "multiple {\"index\":0,\"value\":\"D\",\"flags\":[true,false],\"checked\":[\"D\"],\"entries\":[[\"s\",\"D\"]]}",
            "C true {\"index\":0,\"value\":\"D\",\"flags\":[true,true],\"checked\":[\"D\",\"C\"],\"entries\":[[\"s\",\"D\"],[\"s\",\"C\"]]}",
            "single {\"index\":0,\"value\":\"D\",\"flags\":[true,false],\"checked\":[\"D\"],\"entries\":[[\"s\",\"D\"]]}",
        ],
    );
}

#[test]
fn select_copy() {
    visit(
        "select-copy",
        &[
            "original {\"index\":1,\"value\":\"B\",\"flags\":[false,true],\"checked\":[\"B\"],\"entries\":[[\"s\",\"B\"],[\"s\",\"A\"]]}",
            "copy {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"B\"],[\"s\",\"A\"]]}",
            "original reset {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"],[\"s\",\"A\"]]}",
            "copy reset {\"index\":0,\"value\":\"A\",\"flags\":[true,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"],[\"s\",\"A\"]]}",
        ],
    );
}

#[test]
fn option_text_value() {
    visit(
        "option-text-value",
        &[
            "text {\"index\":0,\"value\":\"A B\",\"flags\":[true,false],\"checked\":[\"A B\"],\"entries\":[[\"s\",\"A B\"]]}",
            "script text {\"index\":1,\"value\":\"X Y\",\"flags\":[false,true],\"checked\":[\"X Y\"],\"entries\":[[\"s\",\"X Y\"]]}",
            "option values [\"X Y\",\"X Y\",\"L\",false,1,true]",
            "new value {\"index\":1,\"value\":\"new\",\"flags\":[false,true],\"checked\":[\"new\"],\"entries\":[[\"s\",\"new\"]]}",
        ],
    );
}

#[test]
fn selected_options_live() {
    visit(
        "selected-options-live",
        &["collection true [object HTMLCollection] true false 1 a a", "index 1 b  b", "empty 0 ", "multiple 2 a,b", "single 1 a", "remove 1 b"],
    );
}

#[test]
fn select_private_state() {
    visit("select-private-state", &["get 0 a 1", "set 1 b [[\"s\",\"b\"]] 0"]);
}

#[test]
fn select_brand_conversion() {
    visit(
        "select-brand-conversion",
        &[
            "selectedIndex get TypeError",
            "selectedIndex set TypeError",
            "value get TypeError",
            "value set TypeError",
            "selectedOptions get TypeError",
            "selected get TypeError",
            "selected set TypeError",
            "value get TypeError",
            "value set TypeError",
            "text get TypeError",
            "text set TypeError",
            "label get TypeError",
            "label set TypeError",
            "defaultSelected get TypeError",
            "defaultSelected set TypeError",
            "index get TypeError",
            "form get TypeError",
            "index conversion symbol TypeError",
            "index conversion bigint TypeError",
            "value null null",
            "value symbol TypeError",
            "label null null",
            "label symbol TypeError",
            "text null null",
            "text symbol TypeError",
        ],
    );
}

#[test]
fn select_reentrant_conversion() {
    visit(
        "select-reentrant-conversion",
        &[
            "index 1 {\"index\":1,\"value\":\"d\",\"flags\":[false,true],\"checked\":[\"d\"],\"entries\":[[\"s\",\"d\"]]}",
            "value 2 {\"index\":1,\"value\":\"f\",\"flags\":[false,true],\"checked\":[\"f\"],\"entries\":[[\"s\",\"f\"]]}",
            "text 3 One Two   One\n Two   e",
            "value text One Two",
            "empty label ",
            "default true true true",
        ],
    );
}

#[test]
fn option_owner_index() {
    visit("option-owner-index", &["external 1 true", "detached 0 ", "group 0 true"]);
}

#[test]
fn select_bulk_mutation() {
    visit(
        "select-bulk-mutation",
        &[
            "prepend two selected {\"index\":1,\"value\":\"b\",\"flags\":[false,true,false],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "append group {\"index\":4,\"value\":\"d\",\"flags\":[false,false,false,false,true],\"checked\":[\"d\"],\"entries\":[[\"s\",\"d\"]]}",
            "old owner {\"index\":0,\"value\":\"a\",\"flags\":[true,false,false],\"checked\":[\"a\"],\"entries\":[[\"s\",\"a\"]]}",
            "new owner {\"index\":2,\"value\":\"d\",\"flags\":[false,false,true],\"checked\":[\"d\"],\"entries\":[[\"s\",\"d\"]]}",
            "empty {\"index\":-1,\"value\":\"\",\"flags\":[],\"checked\":[],\"entries\":[]}",
        ],
    );
}

#[test]
fn select_size_disabled() {
    visit(
        "select-size-disabled",
        &[
            "default {\"index\":2,\"value\":\"C\",\"flags\":[false,false,true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
            "size2 {\"index\":-1,\"value\":\"\",\"flags\":[false,false,false],\"checked\":[],\"entries\":[]}",
            "size1 {\"index\":2,\"value\":\"C\",\"flags\":[false,false,true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
            "enable A {\"index\":0,\"value\":\"A\",\"flags\":[true,false,false],\"checked\":[\"A\"],\"entries\":[[\"s\",\"A\"]]}",
            "disable selected A {\"index\":0,\"value\":\"A\",\"flags\":[true,false,false],\"checked\":[\"A\"],\"entries\":[]}",
            "size prefix {\"index\":2,\"value\":\"C\",\"flags\":[false,false,true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
            "size missing {\"index\":2,\"value\":\"C\",\"flags\":[false,false,true],\"checked\":[\"C\"],\"entries\":[[\"s\",\"C\"]]}",
        ],
    );
}

#[test]
fn select_dirty_defaults() {
    visit(
        "select-dirty-defaults",
        &[
            "index default false false false",
            "index remove default {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "index default true true true",
            "index add default {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "index reset {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "value default false false false",
            "value remove default {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "value default true true true",
            "value add default {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "value reset {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "option default false false false",
            "option remove default {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "option default true true true",
            "option add default {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
            "option reset {\"index\":1,\"value\":\"b\",\"flags\":[false,true],\"checked\":[\"b\"],\"entries\":[[\"s\",\"b\"]]}",
        ],
    );
}

#[test]
fn option_text_mutation() {
    visit(
        "option-text-mutation",
        &[
            "literal <b> Plain </b> <b> Plain </b> &lt;b&gt; Plain &lt;/b&gt; 0",
            "submission {\"index\":0,\"value\":\"<b> Plain </b>\",\"flags\":[true],\"checked\":[\"<b> Plain </b>\"],\"entries\":[[\"s\",\"<b> Plain </b>\"]]}",
            "label L <b> Plain </b>",
            "empty   0 0",
        ],
    );
}

#[test]
fn option_disabled_selectors() {
    visit("option-disabled-selectors", &["0 false true false", "1 true false false", "disabled select true 0 []"]);
}
