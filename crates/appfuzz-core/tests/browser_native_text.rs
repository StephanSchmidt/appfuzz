//! Synthetic native Firefox/Chromium references for private character data,
//! text edits, Node metadata, mutation records, observer queues and microtasks.
//! Results agree across both browsers except script text edits, which follow
//! the current DOM children-changed rules and Firefox (Chromium 128 differs).
//! https://dom.spec.whatwg.org/#concept-cd-replace
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/native_text.js");
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
fn character_data_shadows() {
    visit("character-data-shadows", &["reads native native 6 0", "append native! native! 7 0"]);
}

#[test]
fn option_text_child_hooks() {
    visit("option-text-child-hooks", &["option new new 1 0"]);
}

#[test]
fn textarea_default_child_hooks() {
    visit("textarea-default-child-hooks", &["textarea new new 1 0"]);
}

#[test]
fn remove_child_parent_shadow() {
    visit("remove-child-parent-shadow", &["remove true 0 0"]);
}

#[test]
fn character_data_ranges() {
    visit(
        "character-data-ranges",
        &[
            "substringData [0,2] [\"ab\",\"abcd\"]",
            "substringData [4,2] [\"\",\"abcd\"]",
            "substringData [5,1] IndexSizeError",
            "substringData [-1,1] IndexSizeError",
            "substringData [1.8,2.9] [\"bc\",\"abcd\"]",
            "substringData [1] TypeError",
            "appendData [] TypeError",
            "insertData [2] TypeError",
            "deleteData [5,1] IndexSizeError",
            "deleteData [-1,2] IndexSizeError",
            "replaceData [5,1,\"x\"] IndexSizeError",
            "replaceData [2,999,\"x\"] [null,\"abx\"]",
        ],
    );
}

#[test]
fn character_data_conversion() {
    visit(
        "character-data-conversion",
        &[
            "data object [\"\",\"\",\"\"]",
            "data undefined [\"undefined\",\"undefined\",\"undefined\"]",
            "data symbol TypeError",
            "nodeValue object [\"\",\"\",\"\"]",
            "nodeValue undefined [\"\",\"\",\"\"]",
            "nodeValue symbol TypeError",
            "textContent object [\"\",\"\",\"\"]",
            "textContent undefined [\"\",\"\",\"\"]",
            "textContent symbol TypeError",
            "offset bigint TypeError",
            "offset symbol TypeError",
        ],
    );
}

#[test]
fn character_data_reentrant_conversion() {
    visit("character-data-reentrant-conversion", &["offset mutation IndexSizeError x 1", "data mutation X-Z 2", "required count TypeError 2"]);
}

#[test]
fn text_whole_text_shadows() {
    visit("text-whole-text-shadows", &["whole abc abc abc 0"]);
}

#[test]
fn text_split() {
    visit("text-split", &["0 [\"\",\"abcd\",2,true]", "2 [\"ab\",\"cd\",2,true]", "4 [\"abcd\",\"\",2,true]", "5 IndexSizeError", "-1 IndexSizeError"]);
}

#[test]
fn character_data_observer() {
    visit("character-data-observer", &["observed [[\"characterData\",true,\"old\",0,0],[\"characterData\",true,\"new\",0,0]]"]);
}

#[test]
fn character_data_unicode() {
    visit("character-data-unicode", &["utf16 4 \"\\ud83d\" \"😀\"", "insert \"a\\ud83d-\\ude00b\"", "wrap b", "append null abcdnull"]);
}

#[test]
fn character_data_frozen() {
    visit("character-data-frozen", &["frozen old! old! old! 4"]);
}

#[test]
fn text_split_owner_shadows() {
    visit("text-split-owner-shadows", &["split ab cd true true 2 0"]);
}

#[test]
fn observer_options() {
    visit(
        "observer-options",
        &[
            " TypeError",
            "null TypeError",
            "{} TypeError",
            "false TypeError",
            "{\"attributeOldValue\":false} ok",
            "{\"attributes\":false,\"attributeFilter\":[]} TypeError",
            "{\"characterDataOldValue\":false} ok",
            "{\"characterData\":false,\"characterDataOldValue\":true} TypeError",
            "{\"childList\":true,\"attributes\":false,\"attributeOldValue\":false} ok",
            "frozen options  true",
        ],
    );
}

#[test]
fn observer_dictionary_order() {
    visit(
        "observer-dictionary-order",
        &["order attributeFilter,filter string,attributeOldValue,attributes,characterData,characterDataOldValue,childList,subtree"],
    );
}

#[test]
fn observer_record_shape() {
    visit(
        "observer-record-shape",
        &[
            "record [\"childList\",true,1,0,false,false,null,null,null,true,true,false,false]",
            "record [\"childList\",true,1,0,true,false,null,null,null,true,true,false,false]",
            "record [\"childList\",true,0,1,false,true,null,null,null,true,true,false,false]",
            "record [\"attributes\",true,0,0,false,false,\"x\",null,null,true,true,false,false]",
            "observer keys ",
        ],
    );
}

#[test]
fn observer_overlap() {
    visit("observer-overlap", &["overlap [[\"attributes\",true,\"old\"]]"]);
}

#[test]
fn observer_transient() {
    visit(
        "observer-transient",
        &[
            "transient [[\"childList\",true,false,false,null,null],[\"attributes\",false,true,false,\"x\",null],[\"characterData\",false,false,true,null,\"old\"]]",
        ],
    );
}

#[test]
fn observer_delivery_order() {
    visit("observer-delivery-order", &["delivery first,second"]);
}

#[test]
fn observer_private_state() {
    visit("observer-private-state", &["private 1 0"]);
}

#[test]
fn observer_take_disconnect() {
    visit("observer-take-disconnect", &["take 1  0 0", "again 1"]);
}

#[test]
fn observer_character_subtree() {
    visit("observer-character-subtree", &["subtree [[\"characterData\",true,\"old\",0,0],[\"characterData\",true,\"new\",0,0]]"]);
}

#[test]
fn text_replace_record() {
    visit("text-replace-record", &["replace [[\"childList\",true,1,2,null,null]] new"]);
}

#[test]
fn borrowed_node_getters() {
    visit("borrowed-node-getters", &["borrowed true true B 0", "names #text x #document"]);
}

#[test]
fn observer_private_promise() {
    visit("observer-private-promise", &["promise 1 0"]);
}

#[test]
fn observer_brands_and_callback() {
    visit(
        "observer-brands-and-callback",
        &[
            "brand TypeError",
            "brand TypeError",
            "brand TypeError",
            "brand TypeError",
            "constructor TypeError TypeError",
            "callback true true 1 [object MutationRecord] get type",
        ],
    );
}

#[test]
fn observer_callback_error() {
    visit("observer-callback-error", &["caught true", "second 1"]);
}

#[test]
fn microtask_private_promise() {
    visit("microtask-private-promise", &["microtask 1 0"]);
}

#[test]
fn script_character_edits() {
    visit("script-character-edits", &["ran data", "after data", "ran appendData", "after appendData", "ran nodeValue", "after nodeValue"]);
}

#[test]
fn text_split_records() {
    visit(
        "text-split-records",
        &["split records [[\"characterData\",true,false,false,false,false,\"abcd\"],[\"childList\",false,true,true,true,true,null]] ab cd"],
    );
}
