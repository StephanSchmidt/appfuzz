//! DOMException state, legacy constants, branding and native error paths.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let script = format!("const CASE={};{};for(const line of lines)console.log(line)", json!(case), include_str!("fixtures/dom_exceptions.js"));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn exception_defaults() {
    assert_eq!(
        visit("exception-defaults"),
        [
            "exception-defaults [\"Error\",\"\",0,\"Error\",true,true]",
            "exception-defaults [\"Error\",\"boom\",0,\"Error: boom\",true,true]",
            "exception-defaults [\"InvalidStateError\",\"boom\",11,\"InvalidStateError: boom\",true,true]",
            "exception-defaults [\"null\",\"null\",0,\"null: null\",true,true]",
            "exception-defaults [\"Error\",\"\",0,\"Error\",true,true]"
        ]
    );
}

#[test]
fn exception_codes() {
    assert_eq!(
        visit("exception-codes"),
        [
            "exception-codes IndexSizeError 1",
            "exception-codes DOMStringSizeError 0",
            "exception-codes HierarchyRequestError 3",
            "exception-codes WrongDocumentError 4",
            "exception-codes InvalidCharacterError 5",
            "exception-codes NoDataAllowedError 0",
            "exception-codes NoModificationAllowedError 7",
            "exception-codes NotFoundError 8",
            "exception-codes NotSupportedError 9",
            "exception-codes InUseAttributeError 10",
            "exception-codes InvalidStateError 11",
            "exception-codes SyntaxError 12",
            "exception-codes InvalidModificationError 13",
            "exception-codes NamespaceError 14",
            "exception-codes InvalidAccessError 15",
            "exception-codes ValidationError 0",
            "exception-codes TypeMismatchError 17",
            "exception-codes SecurityError 18",
            "exception-codes NetworkError 19",
            "exception-codes AbortError 20",
            "exception-codes URLMismatchError 21",
            "exception-codes QuotaExceededError 22",
            "exception-codes TimeoutError 23",
            "exception-codes InvalidNodeTypeError 24",
            "exception-codes DataCloneError 25",
            "exception-codes EncodingError 0",
            "exception-codes NotAllowedError 0",
            "exception-codes unknown 0",
            "exception-codes invalidstateerror 0"
        ]
    );
}

#[test]
fn exception_constants() {
    assert_eq!(
        visit("exception-constants"),
        [
            "exception-constants INDEX_SIZE_ERR [1,1,false,true,false]",
            "exception-constants DOMSTRING_SIZE_ERR [2,2,false,true,false]",
            "exception-constants HIERARCHY_REQUEST_ERR [3,3,false,true,false]",
            "exception-constants WRONG_DOCUMENT_ERR [4,4,false,true,false]",
            "exception-constants INVALID_CHARACTER_ERR [5,5,false,true,false]",
            "exception-constants NO_DATA_ALLOWED_ERR [6,6,false,true,false]",
            "exception-constants NO_MODIFICATION_ALLOWED_ERR [7,7,false,true,false]",
            "exception-constants NOT_FOUND_ERR [8,8,false,true,false]",
            "exception-constants NOT_SUPPORTED_ERR [9,9,false,true,false]",
            "exception-constants INUSE_ATTRIBUTE_ERR [10,10,false,true,false]",
            "exception-constants INVALID_STATE_ERR [11,11,false,true,false]",
            "exception-constants SYNTAX_ERR [12,12,false,true,false]",
            "exception-constants INVALID_MODIFICATION_ERR [13,13,false,true,false]",
            "exception-constants NAMESPACE_ERR [14,14,false,true,false]",
            "exception-constants INVALID_ACCESS_ERR [15,15,false,true,false]",
            "exception-constants VALIDATION_ERR [16,16,false,true,false]",
            "exception-constants TYPE_MISMATCH_ERR [17,17,false,true,false]",
            "exception-constants SECURITY_ERR [18,18,false,true,false]",
            "exception-constants NETWORK_ERR [19,19,false,true,false]",
            "exception-constants ABORT_ERR [20,20,false,true,false]",
            "exception-constants URL_MISMATCH_ERR [21,21,false,true,false]",
            "exception-constants QUOTA_EXCEEDED_ERR [22,22,false,true,false]",
            "exception-constants TIMEOUT_ERR [23,23,false,true,false]",
            "exception-constants INVALID_NODE_TYPE_ERR [24,24,false,true,false]",
            "exception-constants DATA_CLONE_ERR [25,25,false,true,false]"
        ]
    );
}

#[test]
fn exception_readonly() {
    assert_eq!(
        visit("exception-readonly"),
        [
            "exception-readonly [\"InvalidStateError\",\"message\",11,[],\"[object DOMException]\"]",
            "exception-readonly descriptor name {\"get\":\"function\",\"set\":\"undefined\",\"enumerable\":true,\"configurable\":true}",
            "exception-readonly descriptor message {\"get\":\"function\",\"set\":\"undefined\",\"enumerable\":true,\"configurable\":true}",
            "exception-readonly descriptor code {\"get\":\"function\",\"set\":\"undefined\",\"enumerable\":true,\"configurable\":true}"
        ]
    );
}

#[test]
fn exception_brand() {
    assert_eq!(
        visit("exception-brand"),
        [
            "exception-brand name TypeError",
            "exception-brand message TypeError",
            "exception-brand code TypeError",
            "exception-brand shadow shadow 11",
            "exception-brand original InvalidStateError"
        ]
    );
}

#[test]
fn exception_conversion() {
    assert_eq!(
        visit("exception-conversion"),
        ["exception-conversion [[\"message\",\"name\"],\"M\",\"InvalidStateError\",11]", "exception-conversion TypeError", "exception-conversion TypeError"]
    );
}

#[test]
fn exception_native_api() {
    assert_eq!(
        visit("exception-native-api"),
        [
            "exception-native-api [\"InvalidStateError\",11,true]",
            "exception-native-api [\"InvalidStateError\",11,true]",
            "exception-native-api [\"InvalidCharacterError\",5,true]",
            "exception-native-api [\"NamespaceError\",14,true]"
        ]
    );
}

#[test]
fn exception_interface() {
    assert_eq!(
        visit("exception-interface"),
        [
            "exception-interface [\"DOMException\",0,true,true,false,false,false,\"DOMException\",false,false,true]",
            "exception-interface new-required TypeError",
            "exception-interface subclass true true true 20"
        ]
    );
}

#[test]
fn exception_allocation_order() {
    assert_eq!(
        visit("exception-allocation-order"),
        ["exception-allocation-order [[\"prototype\",\"message\",\"name\",\"prototype\"],true]", "exception-allocation-order fallback true AbortError 20"]
    );
}

#[test]
fn exception_private_construction() {
    assert_eq!(visit("exception-private-construction"), ["exception-private-construction AbortError M 20 0 true"]);
}

#[test]
fn exception_native_constructor() {
    assert_eq!(
        visit("exception-native-constructor"),
        ["exception-native-constructor 0 [[\"InvalidCharacterError\",5,true],[\"InvalidCharacterError\",5,true],[\"SecurityError\",18,true]]"]
    );
}

#[test]
fn exception_getter_functions() {
    assert_eq!(
        visit("exception-getter-functions"),
        [
            "exception-getter-functions name [\"get name\",0,false,\"TypeError\"]",
            "exception-getter-functions message [\"get message\",0,false,\"TypeError\"]",
            "exception-getter-functions code [\"get code\",0,false,\"TypeError\"]"
        ]
    );
}

#[test]
fn exception_proxy_brand() {
    assert_eq!(
        visit("exception-proxy-brand"),
        [
            "exception-proxy-brand name TypeError",
            "exception-proxy-brand message TypeError",
            "exception-proxy-brand code TypeError",
            "exception-proxy-brand prototype TypeError"
        ]
    );
}

#[test]
fn exception_fallback_slots() {
    assert_eq!(visit("exception-fallback-slots"), ["exception-fallback-slots true AbortError 20 true"]);
}

#[test]
fn exception_map_keys() {
    assert_eq!(
        visit("exception-map-keys"),
        [
            "exception-map-keys __proto__ 0",
            "exception-map-keys constructor 0",
            "exception-map-keys toString 0",
            "exception-map-keys hasOwnProperty 0",
            "exception-map-keys INVALID_STATE_ERR 0",
            "exception-map-keys InvalidStateError 11"
        ]
    );
}

#[test]
fn exception_private_intrinsics() {
    assert_eq!(visit("exception-private-intrinsics"), ["exception-private-intrinsics [\"InvalidStateError\",\"M\",11,true,0]"]);
}

#[test]
fn exception_error_predicate() {
    assert_eq!(
        visit("exception-error-predicate"),
        [
            "exception-error-predicate true",
            "exception-error-predicate true",
            "exception-error-predicate true",
            "exception-error-predicate true",
            "exception-error-predicate false",
            "exception-error-predicate false",
            "exception-error-predicate false",
            "exception-error-predicate false",
            "exception-error-predicate false",
            "exception-error-predicate false",
            "exception-error-predicate shape [\"isError\",1,false,true,false,true] 0"
        ]
    );
}

#[test]
fn exception_native_paths() {
    assert_eq!(
        visit("exception-native-paths"),
        [
            "exception-native-paths AbortError 20 true true",
            "exception-native-paths InvalidStateError 11 true true",
            "exception-native-paths SyntaxError 12 true true",
            "exception-native-paths NotSupportedError 9 true true",
            "exception-native-paths NotSupportedError 9 true true"
        ]
    );
}

#[test]
fn exception_abrupt_conversion() {
    assert_eq!(
        visit("exception-abrupt-conversion"),
        ["exception-abrupt-conversion true 0", "exception-abrupt-conversion true 0", "exception-abrupt-conversion true [\"prototype\"]"]
    );
}

fn report(script: &str) -> Value {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let result: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(result.get("fatal").is_none(), "{result}");
    result
}
#[test]
fn native_dom_exception_diagnostics_preserve_identity_and_stack() {
    let report =
        report("const e=new DOMException('original message','AbortError');console.log(e.stack);Error.isError=()=>false;queueMicrotask(()=>{throw e});");
    let errors = report["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{report}");
    assert_eq!(errors[0]["name"], "AbortError");
    assert_eq!(errors[0]["message"], "original message");
    // QuickJS names evaluated source eval_script; retain its native stack
    // rather than assuming a browser URL or synthesizing an author getter.
    let stack = errors[0]["stack"].as_str().unwrap();
    assert!(!stack.is_empty(), "{report}");
    assert_eq!(stack, report["console"][0]["text"].as_str().unwrap(), "{report}");
}
#[test]
fn dom_exception_diagnostics_do_not_read_author_stack_getters() {
    let report = report(
        "let calls=0;const e=new DOMException('original message','InvalidStateError');Object.defineProperty(e,'stack',{get(){calls++;throw Error('author stack')}});queueMicrotask(()=>{throw e});queueMicrotask(()=>console.log('stack-reads',calls));",
    );
    assert_eq!(report["console"][0]["text"], "stack-reads 0", "{report}");
    let errors = report["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{report}");
    assert_eq!(errors[0]["name"], "InvalidStateError");
    assert_eq!(errors[0]["message"], "original message");
    assert_eq!(errors[0]["stack"], "");
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
