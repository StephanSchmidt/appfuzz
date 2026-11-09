//! Isolated Chrome/Firefox constructor references. Web IDL/Firefox supply
//! the interface prototype when newTarget.prototype is primitive and reject
//! illegal constructors before prototype lookup. Chrome currently differs on
//! those two paths. Legal construction preserves common native lookup and
//! conversion order, branding, inheritance, metadata, and private allocation.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/constructors.js");
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
fn constructor_events_base() {
    assert_eq!(
        visit("constructor-events-base"),
        [
            "EventTarget EventTarget true 1",
            "Event Event true 1",
            "CustomEvent CustomEvent true 1",
            "UIEvent UIEvent true 1",
            "MouseEvent MouseEvent true 1",
            "PointerEvent PointerEvent true 1",
            "WheelEvent WheelEvent true 1"
        ]
    );
}

#[test]
fn constructor_events_keys() {
    assert_eq!(
        visit("constructor-events-keys"),
        [
            "KeyboardEvent KeyboardEvent true 1",
            "FocusEvent FocusEvent true 1",
            "InputEvent InputEvent true 1",
            "SubmitEvent SubmitEvent true 1",
            "ProgressEvent ProgressEvent true 1",
            "HashChangeEvent HashChangeEvent true 1",
            "PopStateEvent PopStateEvent true 1"
        ]
    );
}

#[test]
fn constructor_events_extra() {
    assert_eq!(
        visit("constructor-events-extra"),
        [
            "ErrorEvent ErrorEvent true 1",
            "PromiseRejectionEvent PromiseRejectionEvent true 1",
            "ToggleEvent ToggleEvent true 1",
            "StorageEvent StorageEvent true 1",
            "TransitionEvent TransitionEvent true 1",
            "AnimationEvent AnimationEvent true 1",
            "CompositionEvent CompositionEvent true 1"
        ]
    );
}

#[test]
fn constructor_events_payloads() {
    assert_eq!(
        visit("constructor-events-payloads"),
        [
            "ClipboardEvent ClipboardEvent true 1",
            "TouchEvent TouchEvent true 1",
            "DragEvent DragEvent true 1",
            "MessageEvent MessageEvent true 1",
            "FormDataEvent FormDataEvent true 1"
        ]
    );
}

#[test]
fn constructor_binary_fetch() {
    assert_eq!(
        visit("constructor-binary-fetch"),
        [
            "Blob Blob true 1",
            "File File true 1",
            "Headers Headers true 1",
            "Request Request true 1",
            "Response Response true 1",
            "FormData FormData true 1",
            "FileReader FileReader true 1"
        ]
    );
}

#[test]
fn constructor_stateful() {
    assert_eq!(
        visit("constructor-stateful"),
        [
            "URL URL true 1",
            "URLSearchParams URLSearchParams true 1",
            "DOMException DOMException true 1",
            "DataTransfer DataTransfer true 1",
            "StaticRange StaticRange true 1",
            "Touch Touch true 1",
            "AbortController AbortController true 1",
            "MessageChannel MessageChannel true 1",
            "DOMParser DOMParser true 1",
            "XMLHttpRequest XMLHttpRequest true 1"
        ]
    );
}

#[test]
fn constructor_primitive_prototypes() {
    assert_eq!(
        visit("constructor-primitive-prototypes"),
        [
            "kind undefined",
            "Event Event true 1",
            "kind undefined",
            "Blob Blob true 1",
            "kind undefined",
            "DOMException DOMException true 1",
            "kind undefined",
            "Headers Headers true 1",
            "kind undefined",
            "AbortController AbortController true 1",
            "kind undefined",
            "MessageEvent MessageEvent true 1",
            "kind object",
            "Event Event true 1",
            "kind object",
            "Blob Blob true 1",
            "kind object",
            "DOMException DOMException true 1",
            "kind object",
            "Headers Headers true 1",
            "kind object",
            "AbortController AbortController true 1",
            "kind object",
            "MessageEvent MessageEvent true 1",
            "kind number",
            "Event Event true 1",
            "kind number",
            "Blob Blob true 1",
            "kind number",
            "DOMException DOMException true 1",
            "kind number",
            "Headers Headers true 1",
            "kind number",
            "AbortController AbortController true 1",
            "kind number",
            "MessageEvent MessageEvent true 1",
            "kind string",
            "Event Event true 1",
            "kind string",
            "Blob Blob true 1",
            "kind string",
            "DOMException DOMException true 1",
            "kind string",
            "Headers Headers true 1",
            "kind string",
            "AbortController AbortController true 1",
            "kind string",
            "MessageEvent MessageEvent true 1",
            "kind boolean",
            "Event Event true 1",
            "kind boolean",
            "Blob Blob true 1",
            "kind boolean",
            "DOMException DOMException true 1",
            "kind boolean",
            "Headers Headers true 1",
            "kind boolean",
            "AbortController AbortController true 1",
            "kind boolean",
            "MessageEvent MessageEvent true 1",
            "kind symbol",
            "Event Event true 1",
            "kind symbol",
            "Blob Blob true 1",
            "kind symbol",
            "DOMException DOMException true 1",
            "kind symbol",
            "Headers Headers true 1",
            "kind symbol",
            "AbortController AbortController true 1",
            "kind symbol",
            "MessageEvent MessageEvent true 1"
        ]
    );
}

#[test]
fn constructor_custom_prototypes() {
    assert_eq!(
        visit("constructor-custom-prototypes"),
        [
            "Event true 1",
            "Blob true 1",
            "File true 1",
            "DOMException true 1",
            "Headers true 1",
            "URL true 1",
            "URLSearchParams true 1",
            "Request true 1",
            "Response true 1",
            "FormData true 1",
            "AbortController true 1",
            "MessageEvent true 1",
            "MessageChannel true 1",
            "DataTransfer true 1",
            "StaticRange true 1",
            "Touch true 1",
            "FileReader true 1"
        ]
    );
}

#[test]
fn constructor_prototype_throws() {
    assert_eq!(
        visit("constructor-prototype-throws"),
        [
            "Event RangeError 1 0",
            "Blob RangeError 1 0",
            "Headers RangeError 1 0",
            "DOMException RangeError 1 0",
            "Request RangeError 1 0",
            "FormData RangeError 1 0",
            "AbortController RangeError 1 0",
            "MessageChannel RangeError 1 0"
        ]
    );
}

#[test]
fn constructor_conversion_order() {
    assert_eq!(
        visit("constructor-conversion-order"),
        [
            "Event prototype,argument",
            "DOMException prototype,argument",
            "URL prototype,argument",
            "Request prototype,argument",
            "Blob prototype,argument",
            "File prototype,argument"
        ]
    );
}

#[test]
fn constructor_invalid_argument_prototype() {
    assert_eq!(
        visit("constructor-invalid-argument-prototype"),
        ["Event TypeError prototype", "URL TypeError prototype", "Blob TypeError prototype", "File TypeError prototype", "FormData TypeError prototype"]
    );
}

#[test]
fn constructor_illegal_prototypes() {
    assert_eq!(
        visit("constructor-illegal-prototypes"),
        [
            "AbortSignal AbortSignal 0 TypeError 0 TypeError false",
            "MessagePort MessagePort 0 TypeError 0 TypeError false",
            "DataTransferItem DataTransferItem 0 TypeError 0 TypeError false",
            "DataTransferItemList DataTransferItemList 0 TypeError 0 TypeError false",
            "FileList FileList 0 TypeError 0 TypeError false",
            "TouchList TouchList 0 TypeError 0 TypeError false",
            "AbstractRange AbstractRange 0 TypeError 0 TypeError false",
            "NodeRange NodeRange 0 TypeError 0 TypeError false",
            "NodeList NodeList 0 TypeError 0 TypeError false"
        ]
    );
}

#[test]
fn constructor_metadata() {
    assert_eq!(
        visit("constructor-metadata"),
        [
            "EventTarget EventTarget 0 true false false false",
            "Event Event 1 true false false false",
            "CustomEvent CustomEvent 1 true false false false",
            "UIEvent UIEvent 1 true false false false",
            "MouseEvent MouseEvent 1 true false false false",
            "PointerEvent PointerEvent 1 true false false false",
            "KeyboardEvent KeyboardEvent 1 true false false false",
            "ProgressEvent ProgressEvent 1 true false false false",
            "PromiseRejectionEvent PromiseRejectionEvent 2 true false false false",
            "MessageEvent MessageEvent 1 true false false false",
            "Blob Blob 0 true false false false",
            "File File 2 true false false false",
            "Headers Headers 0 true false false false",
            "Request Request 1 true false false false",
            "Response Response 0 true false false false",
            "URL URL 1 true false false false",
            "URLSearchParams URLSearchParams 0 true false false false",
            "FormData FormData 0 true false false false",
            "FormDataEvent FormDataEvent 2 true false false false",
            "FileReader FileReader 0 true false false false",
            "AbortController AbortController 0 true false false false",
            "DataTransfer DataTransfer 0 true false false false",
            "StaticRange StaticRange 1 true false false false",
            "Touch Touch 1 true false false false",
            "MessageChannel MessageChannel 0 true false false false",
            "DOMException DOMException 0 true false false false",
            "DOMParser DOMParser 0 true false false false",
            "XMLHttpRequest XMLHttpRequest 0 true false false false"
        ]
    );
}

#[test]
fn constructor_dom_names() {
    assert_eq!(
        visit("constructor-dom-names"),
        [
            "Node Node",
            "Element Element",
            "HTMLElement HTMLElement",
            "Document Document",
            "DocumentFragment DocumentFragment",
            "DocumentType DocumentType",
            "Text Text",
            "Comment Comment",
            "Attr Attr",
            "CDATASection CDATASection",
            "SVGElement SVGElement",
            "ShadowRoot ShadowRoot",
            "DOMParser DOMParser",
            "NodeList NodeList",
            "HTMLInputElement HTMLInputElement",
            "HTMLDivElement HTMLDivElement",
            "HTMLButtonElement HTMLButtonElement",
            "HTMLFormElement HTMLFormElement",
            "HTMLTableColElement HTMLTableColElement",
            "HTMLTableSectionElement HTMLTableSectionElement",
            "HTMLDialogElement HTMLDialogElement",
            "HTMLTemplateElement HTMLTemplateElement",
            "input HTMLInputElement",
            "div HTMLDivElement",
            "form HTMLFormElement",
            "template HTMLTemplateElement",
            "table HTMLTableElement",
            "tbody HTMLTableSectionElement",
            "dialog HTMLDialogElement"
        ]
    );
}

#[test]
fn constructor_html_metadata() {
    assert_eq!(
        visit("constructor-html-metadata"),
        [
            "HTMLElement HTMLElement 0 true",
            "HTMLInputElement HTMLInputElement 0 true",
            "HTMLDivElement HTMLDivElement 0 true",
            "HTMLTableColElement HTMLTableColElement 0 true",
            "HTMLTableSectionElement HTMLTableSectionElement 0 true",
            "HTMLDialogElement HTMLDialogElement 0 true"
        ]
    );
}

#[test]
fn constructor_parents() {
    assert_eq!(
        visit("constructor-parents"),
        [
            "Blob ok 0",
            "File ok 0",
            "Event ok 0",
            "CustomEvent ok 0",
            "MouseEvent ok 0",
            "Headers ok 0",
            "FormData ok 0",
            "DOMException ok 0",
            "DataTransfer ok 0",
            "AbortController ok 0",
            "Request ok 0",
            "Response ok 0",
            "MessageEvent ok 0",
            "MessageChannel ok 0",
            "XMLHttpRequest ok 0"
        ]
    );
}

#[test]
fn constructor_inheritance() {
    assert_eq!(
        visit("constructor-inheritance"),
        [
            "EventTarget true true",
            "Event true true",
            "CustomEvent true true",
            "UIEvent true true",
            "MouseEvent true true",
            "PointerEvent true true",
            "KeyboardEvent true true",
            "MessageEvent true true",
            "FormDataEvent true true",
            "File true true",
            "AbortSignal true true",
            "MessagePort true true",
            "StaticRange true true"
        ]
    );
}

#[test]
fn constructor_subclasses() {
    assert_eq!(
        visit("constructor-subclasses"),
        [
            "Event true true true",
            "Blob true true true",
            "Headers true true true",
            "Request true true true",
            "Response true true true",
            "FormData true true true",
            "DataTransfer true true true",
            "URL true true true",
            "AbortController true true true",
            "MessageChannel true true true"
        ]
    );
}

#[test]
fn constructor_native_allocations() {
    assert_eq!(
        visit("constructor-native-allocations"),
        ["Blob 0", "File 0", "Headers 0", "Request 0", "Response 0", "FormData 0", "AbortSignal 0", "MessageEvent 0", "FileReader 0"]
    );
}

#[test]
fn constructor_reentrant_prototypes() {
    assert_eq!(
        visit("constructor-reentrant-prototypes"),
        ["Event true true 1 1", "Blob true true 1 1", "File true true 1 1", "DOMException true true 1 1", "URL true true 1 1", "Request true true 1 1"]
    );
}

#[test]
fn constructor_reentrant_errors() {
    assert_eq!(
        visit("constructor-reentrant-errors"),
        [
            "Event RangeError true",
            "Blob RangeError true",
            "File RangeError true",
            "DOMException RangeError true",
            "URL RangeError true",
            "Request RangeError true"
        ]
    );
}

#[test]
fn constructor_private_array_hooks() {
    assert_eq!(visit("constructor-private-array-hooks"), ["0"]);
}

#[test]
fn constructor_private_descriptor_hooks() {
    assert_eq!(visit("constructor-private-descriptor-hooks"), ["0"]);
}

#[test]
fn constructor_private_intrinsics() {
    assert_eq!(visit("constructor-private-intrinsics"), ["0"]);
}

#[test]
fn constructor_private_constructor_properties() {
    assert_eq!(visit("constructor-private-constructor-properties"), ["0"]);
}

#[test]
fn constructor_nodelist_array_operations() {
    assert_eq!(visit("constructor-nodelist-array-operations"), ["true 1 true true BODY true"]);
}

#[test]
fn constructor_nodelist_array_identity() {
    assert_eq!(visit("constructor-nodelist-array-identity"), ["false false 1 [object NodeList]", "true 1 true"]);
}

#[test]
fn constructor_nodelist_species_hooks() {
    assert_eq!(visit("constructor-nodelist-species-hooks"), ["1 true 0"]);
}
