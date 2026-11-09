//! Local Chrome/Firefox fixtures, with explicit current-standard corrections:
//! HTML SameObject, ASCII MIME normalization, replacement order, disabled items,
//! File API clone memory, Web IDL readonly indexed properties, DOM NodeRange,
//! and Touch Events draft fields/coordinate doubles. Chromium and Firefox do
//! not implement all of these identically; the expectations below preserve the
//! documented standard choices instead of silently copying engine defects.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/event_payloads.js");
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
fn payload_producers() {
    assert_eq!(
        visit("payload-producers"),
        ["DataTransfer function", "StaticRange function", "Touch function", "data synthetic marker 1 0", "range true true 0"]
    );
}

#[test]
fn document_accessor_metadata() {
    assert_eq!(visit("document-accessor-metadata"), ["Document activeElement get activeElement 0", "ShadowRoot activeElement get activeElement 0"]);
}

#[test]
fn payload_constructor_metadata() {
    assert_eq!(
        visit("payload-constructor-metadata"),
        [
            "DataTransfer DataTransfer 0  TypeError false clearData,constructor,dropEffect,effectAllowed,files,getData,items,setData,setDragImage,types",
            "DataTransferItem DataTransferItem 0  TypeError false constructor,getAsFile,getAsString,kind,type",
            "DataTransferItemList DataTransferItemList 0  TypeError false add,clear,constructor,length,remove",
            "FileList FileList 0  TypeError false constructor,item,length",
            "StaticRange StaticRange 1 NodeRange TypeError false constructor",
            "AbstractRange AbstractRange 0  TypeError false collapsed,constructor,endOffset,startOffset",
            "Touch Touch 1  TypeError false altitudeAngle,azimuthAngle,clientX,clientY,constructor,force,identifier,pageX,pageY,radiusX,radiusY,rotationAngle,screenX,screenY,target,touchType"
        ]
    );
}

#[test]
fn static_range_conversion() {
    assert_eq!(
        visit("static-range-conversion"),
        [
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "4294967295 3 false",
            "0 0 true",
            "1 3 false",
            "10 0 false",
            "node 2 InvalidNodeTypeError",
            "node 10 InvalidNodeTypeError",
            "node 8 ok",
            "node 11 ok"
        ]
    );
}

#[test]
fn static_range_dictionary() {
    assert_eq!(visit("static-range-dictionary"), ["endContainer,endOffset,endNumber,startContainer,startOffset,startNumber true true false", "parent true"]);
}

#[test]
fn static_range_private_state() {
    assert_eq!(
        visit("static-range-private-state"),
        [
            "1 2 false true",
            "startContainer false get startContainer 0 TypeError",
            "startOffset false get startOffset 0 TypeError",
            "endContainer false get endContainer 0 TypeError",
            "endOffset false get endOffset 0 TypeError",
            "collapsed false get collapsed 0 TypeError",
            "clone DataCloneError"
        ]
    );
}

#[test]
fn input_range_payloads() {
    assert_eq!(visit("input-range-payloads"), ["copies 1 2", "invalid TypeError", "invalid TypeError", "invalid TypeError", "invalid TypeError", "empty 0"]);
}

#[test]
fn data_transfer_storage() {
    assert_eq!(
        visit("data-transfer-storage"),
        [
            "defaults none none 0 0 ",
            "same true true true true",
            "types text/html,text/plain,text/uri-list,x-É 0",
            "Text \"replacement\"",
            "text/plain \"replacement\"",
            "TEXT/HTML \"<b>synthetic</b>\"",
            "url \"https://app.example/one\"",
            "text/uri-list \"# comment\\r\\nhttps://app.example/one\\r\\nhttps://app.example/two\"",
            "x-É \"custom\"",
            "x-é \"\"",
            "missing \"\"",
            "items string:text/html|string:text/plain|string:text/uri-list|string:x-É",
            "clear text/html,text/uri-list,x-É",
            "empty 0 0 "
        ]
    );
}

#[test]
fn data_transfer_effects() {
    assert_eq!(
        visit("data-transfer-effects"),
        [
            "dropEffect copy copy",
            "dropEffect move move",
            "dropEffect link link",
            "dropEffect copyMove link",
            "dropEffect all link",
            "dropEffect uninitialized link",
            "dropEffect invalid link",
            "dropEffect NONE link",
            "dropEffect null link",
            "dropEffect undefined link",
            "dropEffect symbol TypeError",
            "effectAllowed copy copy",
            "effectAllowed move move",
            "effectAllowed link link",
            "effectAllowed copyMove copyMove",
            "effectAllowed all all",
            "effectAllowed uninitialized uninitialized",
            "effectAllowed invalid uninitialized",
            "effectAllowed NONE uninitialized",
            "effectAllowed null uninitialized",
            "effectAllowed undefined uninitialized",
            "effectAllowed symbol TypeError",
            "image  TypeError TypeError TypeError"
        ]
    );
}

#[test]
fn data_transfer_item_lifetime() {
    assert_eq!(
        visit("data-transfer-item-lifetime"),
        ["true string text/plain  NotSupportedError", "replace false  ", "remove     1 text/html", "outOfRange 1", "clear 0 "]
    );
}

#[test]
fn data_transfer_files() {
    assert_eq!(
        visit("data-transfer-files"),
        [
            "file file application/x-synthetic true true true true 1 true  1 Files",
            "dup 3 2 text/plain,Files",
            "clearText 2 2 Files",
            "removeFile 1   ",
            "empty 0"
        ]
    );
}

#[test]
fn data_transfer_file_private() {
    assert_eq!(
        visit("data-transfer-file-private"),
        [
            "file text/plain 0 true 115,121,110,116,104,101,116,105,99",
            "fake TypeError",
            "fake TypeError",
            "fake TypeError",
            "arity TypeError TypeError TypeError TypeError TypeError TypeError"
        ]
    );
}

#[test]
fn data_transfer_collections() {
    assert_eq!(
        visit("data-transfer-collections"),
        [
            "list [object DataTransferItemList] false 0,1 0,1 false true",
            "assign false true false true false true",
            "other true 1",
            "iter values 2 TypeError",
            "list [object FileList] false 0 0 false true",
            "assign false true false true false true",
            "other true 1",
            "iter values 1 TypeError",
            "frozen TypeError TypeError"
        ]
    );
}

#[test]
fn data_transfer_clone() {
    assert_eq!(
        visit("data-transfer-clone"),
        [
            "clone [object FileList] true true true true a.txt synthetic 0",
            "snapshot 1",
            "serial DataCloneError",
            "serial DataCloneError",
            "serial DataCloneError",
            "serial [object FileList]"
        ]
    );
}

#[test]
fn data_transfer_async() {
    assert_eq!(visit("data-transfer-async"), ["sync,micro,snapshot true", "args TypeError TypeError "]);
}

#[test]
fn data_transfer_events() {
    assert_eq!(
        visit("data-transfer-events"),
        ["DragEvent true synthetic false TypeError", "ClipboardEvent true synthetic false TypeError", "InputEvent true synthetic false TypeError"]
    );
}

#[test]
fn data_transfer_parents() {
    assert_eq!(visit("data-transfer-parents"), ["native 2 1 0"]);
}

#[test]
fn data_transfer_member_metadata() {
    assert_eq!(
        visit("data-transfer-member-metadata"),
        [
            "DataTransfer dropEffect get dropEffect 0 false true true",
            "DataTransfer dropEffect set dropEffect 1 false true true",
            "DataTransfer effectAllowed get effectAllowed 0 false true true",
            "DataTransfer effectAllowed set effectAllowed 1 false true true",
            "DataTransfer items get items 0 false true true",
            "DataTransfer types get types 0 false true true",
            "DataTransfer files get files 0 false true true",
            "DataTransfer getData getData 1 false true true",
            "DataTransfer setData setData 2 false true true",
            "DataTransfer clearData clearData 0 false true true",
            "DataTransfer setDragImage setDragImage 3 false true true",
            "DataTransferItemList length get length 0 false true true",
            "DataTransferItemList add add 1 false true true",
            "DataTransferItemList remove remove 1 false true true",
            "DataTransferItemList clear clear 0 false true true",
            "DataTransferItem kind get kind 0 false true true",
            "DataTransferItem type get type 0 false true true",
            "DataTransferItem getAsFile getAsFile 0 false true true",
            "DataTransferItem getAsString getAsString 1 false true true",
            "FileList length get length 0 false true true",
            "FileList item item 1 false true true"
        ]
    );
}

#[test]
fn data_transfer_private_hooks() {
    assert_eq!(visit("data-transfer-private-hooks"), ["2 1 synthetic true 0"]);
}

#[test]
fn touch_conversion() {
    assert_eq!(
        visit("touch-conversion"),
        [
            "identifier:3|clientX:1.9|clientY:0|screenX:0|screenY:0|pageX:0|pageY:0|radiusX:1.2345678806304932|radiusY:0|rotationAngle:0|force:-1 true",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "negative -1"
        ]
    );
}

#[test]
fn touch_dictionary() {
    assert_eq!(
        visit("touch-dictionary"),
        [
            "altitudeAngle,azimuthAngle,clientX,clientY,force,identifier,pageX,pageY,radiusX,radiusY,rotationAngle,screenX,screenY,target,touchType",
            " [object Touch] false 0 DataCloneError",
            "parent 2"
        ]
    );
}

#[test]
fn touch_event_payloads() {
    assert_eq!(
        visit("touch-event-payloads"),
        [
            "touches 1 true true  true 1 false true",
            "targetTouches 1 true true  true 1 false true",
            "changedTouches 1 true true  true 1 false true",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError",
            "invalid TypeError"
        ]
    );
}

#[test]
fn file_input_selection() {
    assert_eq!(
        visit("file-input-selection"),
        [
            "nonfile ",
            "empty [object FileList] true 0 ",
            "selected true 2 true C:\\fakepath\\one.txt",
            "live 0 ",
            "null 0",
            "invalid TypeError TypeError",
            "brand TypeError TypeError"
        ]
    );
}

#[test]
fn file_input_values() {
    assert_eq!(
        visit("file-input-values"),
        ["path C:\\fakepath\\one.txt InvalidStateError 1", "clear 0 false 1 1", "same 1", "text  ", "return 0 ", "sameType 1", "changed 0"]
    );
}

#[test]
fn file_input_form() {
    assert_eq!(visit("file-input-form"), ["submit 2 one.bin application/synthetic 0,255,65 two.txt", "reset 0  0 application/octet-stream"]);
}

#[test]
fn file_input_clone() {
    assert_eq!(visit("file-input-clone"), ["clone 1 true true C:\\fakepath\\a.txt", "independent 1 0"]);
}

#[test]
fn data_transfer_uri_and_undefined() {
    assert_eq!(
        visit("data-transfer-uri-and-undefined"),
        [
            "\"https://app.example/path\"",
            "\"https://app.example/path\"",
            "\"https://app.example/path\"",
            "\"\"",
            "undefined 0",
            "domstring TypeError TypeError",
            "overload string:undefined"
        ]
    );
}

#[test]
fn data_transfer_strict_callback() {
    assert_eq!(visit("data-transfer-strict-callback"), ["receiver true false"]);
}

#[test]
fn data_transfer_messages() {
    assert_eq!(visit("data-transfer-messages"), ["[object FileList] 1 a.txt synthetic"]);
}

#[test]
fn payload_public_hooks() {
    assert_eq!(visit("payload-public-hooks"), ["end,endOffset,number,start,startOffset,type,value synthetic"]);
}

#[test]
fn payload_target_prototypes() {
    assert_eq!(visit("payload-target-prototypes"), ["brand true x 1", "clone true x", "proxy TypeError"]);
}

#[test]
fn file_input_empty_identity() {
    assert_eq!(visit("file-input-empty-identity"), ["emptyClear true", "null true", "ignore TypeError ", "emptyReset true"]);
}

#[test]
fn file_input_private_metadata() {
    assert_eq!(visit("file-input-private-metadata"), ["value C:\\fakepath\\a.txt 0", "data 1 true synthetic 0"]);
}

#[test]
fn payload_collection_brand() {
    assert_eq!(
        visit("payload-collection-brand"),
        [
            "DataTransferItemList TypeError TypeError",
            "FileList TypeError TypeError",
            "TouchList TypeError TypeError",
            "getData TypeError",
            "setData TypeError",
            "clearData TypeError",
            "setDragImage TypeError",
            "add TypeError",
            "remove TypeError",
            "clear TypeError"
        ]
    );
}

#[test]
fn payload_clone_private_hooks() {
    assert_eq!(visit("payload-clone-private-hooks"), ["1 a.txt synthetic 0"]);
}
