//! Isolated Chrome/Firefox FileReader reference pages. Explicit File API
//! corrections clear DONE results on abort, keep LOADING progress cancellable,
//! suppress old loadend after callback/microtask read chaining, apply MIME
//! charset fallback/first-parameter parsing, and recover malformed UTF-16.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/file_reader.js");
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
fn reader_defaults() {
    assert_eq!(visit("reader-defaults"), ["0   0 1 2", "readyState true false 0", "result true false ", "error true false "]);
}

#[test]
fn reader_loading() {
    assert_eq!(
        visit("reader-loading"),
        ["immediate 1   InvalidStateError", "finished 2 abc  loadstart:1:0:3:true|progress:1:3:3:true|load:2:3:3:true|loadend:2:3:3:true"]
    );
}

#[test]
fn reader_abort() {
    assert_eq!(visit("reader-abort"), ["immediate 2::AbortError abort,loadend", "later 2::AbortError abort,loadend"]);
}

#[test]
fn reader_encoding() {
    assert_eq!(visit("reader-encoding"), ["windows-1252 \"é\"", " \"A\"", "windows-1252 \"A\""]);
}

#[test]
fn reader_private_method() {
    assert_eq!(visit("reader-private-method"), ["synthetic 0"]);
}

#[test]
fn reader_constructor_parent() {
    assert_eq!(visit("reader-constructor-parent"), ["0 0"]);
}

#[test]
fn reader_metadata() {
    assert_eq!(
        visit("reader-metadata"),
        [
            "FileReader 0 true true false [object FileReader]  TypeError",
            "readAsText readAsText 1 false true true",
            "readAsArrayBuffer readAsArrayBuffer 1 false true true",
            "readAsDataURL readAsDataURL 1 false true true",
            "readAsBinaryString readAsBinaryString 1 false true true",
            "abort abort 0 false true true",
            "readyState get readyState 0 false true true",
            "result get result 0 false true true",
            "error get error 0 false true true",
            "onload get onload 0 false true true",
            "onload set onload 1 false true true",
            "onloadend get onloadend 0 false true true",
            "onloadend set onloadend 1 false true true",
            "onloadstart get onloadstart 0 false true true",
            "onloadstart set onloadstart 1 false true true",
            "onprogress get onprogress 0 false true true",
            "onprogress set onprogress 1 false true true",
            "onabort get onabort 0 false true true",
            "onabort set onabort 1 false true true",
            "onerror get onerror 0 false true true",
            "onerror set onerror 1 false true true",
            "EMPTY 0 false true false",
            "EMPTY 0 false true false",
            "LOADING 1 false true false",
            "LOADING 1 false true false",
            "DONE 2 false true false",
            "DONE 2 false true false"
        ]
    );
}

#[test]
fn reader_brand_arguments() {
    assert_eq!(
        visit("reader-brand-arguments"),
        [
            "readAsText TypeError",
            "readAsText TypeError",
            "readAsText TypeError",
            "readAsText TypeError",
            "readAsText TypeError",
            "receiver readAsText TypeError TypeError",
            "readAsArrayBuffer TypeError",
            "readAsArrayBuffer TypeError",
            "readAsArrayBuffer TypeError",
            "readAsArrayBuffer TypeError",
            "readAsArrayBuffer TypeError",
            "receiver readAsArrayBuffer TypeError TypeError",
            "readAsDataURL TypeError",
            "readAsDataURL TypeError",
            "readAsDataURL TypeError",
            "readAsDataURL TypeError",
            "readAsDataURL TypeError",
            "receiver readAsDataURL TypeError TypeError",
            "readAsBinaryString TypeError",
            "readAsBinaryString TypeError",
            "readAsBinaryString TypeError",
            "readAsBinaryString TypeError",
            "readAsBinaryString TypeError",
            "receiver readAsBinaryString TypeError TypeError",
            "get readyState TypeError TypeError",
            "get result TypeError TypeError",
            "get error TypeError TypeError",
            "get onload TypeError TypeError",
            "abort TypeError"
        ]
    );
}

#[test]
fn reader_empty_blob() {
    assert_eq!(visit("reader-empty-blob"), ["2:: loadstart:0:0:true|load:0:0:true|loadend:0:0:true"]);
}

#[test]
fn reader_abort_idle_done() {
    assert_eq!(visit("reader-abort-idle-done"), ["idle 0:: 0", "done 2:: loadstart,progress,load,loadend", "again 2:: loadstart,progress,load,loadend"]);
}

#[test]
fn reader_abort_start() {
    assert_eq!(visit("reader-abort-start"), ["2::AbortError loadstart:0:4:true|abort:0:0:false|loadend:0:0:false"]);
}

#[test]
fn reader_abort_progress() {
    assert_eq!(visit("reader-abort-progress"), ["2::AbortError loadstart:0:4:true|progress:4:4:true|abort:0:0:false|loadend:0:0:false"]);
}

#[test]
fn reader_read_chain() {
    assert_eq!(
        visit("reader-read-chain"),
        ["loaded first", "loaded second", "loadstart:1:5|progress:1:5|load:2:5|loadstart:1:6|progress:1:6|load:2:6|loadend:2:6 2:second:"]
    );
}

#[test]
fn reader_abort_chain() {
    assert_eq!(visit("reader-abort-chain"), ["abort:2:0|loadstart:1:6|progress:1:6|load:2:6|loadend:2:6 2:second:"]);
}

#[test]
fn reader_abort_in_load() {
    assert_eq!(visit("reader-abort-in-load"), ["2:: loadstart:0:9|progress:9:9|load:9:9|loadend:9:9"]);
}

#[test]
fn reader_listener_microtasks() {
    assert_eq!(visit("reader-listener-microtasks"), ["listener,micro,handler,end"]);
}

#[test]
fn reader_microtask_read_chain() {
    assert_eq!(visit("reader-microtask-read-chain"), ["second loadstart,progress,load,loadstart,progress,load,loadend"]);
}

#[test]
fn reader_microtask_abort_order() {
    assert_eq!(visit("reader-microtask-abort-order"), ["abort,end,sync,micro"]);
}

#[test]
fn reader_loadend_chain() {
    assert_eq!(visit("reader-loadend-chain"), ["first,second 2"]);
}

#[test]
fn reader_binary() {
    assert_eq!(visit("reader-binary"), ["binary 0,255,128,65", "buffer 0,255,128,65", "immutable 0,255,128,65"]);
}

#[test]
fn reader_data_url() {
    assert_eq!(
        visit("reader-data-url"),
        [
            " data:application/octet-stream;base64,",
            " data:application/octet-stream;base64,AA==",
            " data:application/octet-stream;base64,/4AAQQ==",
            "text/plain data:text/plain;base64,",
            "text/plain data:text/plain;base64,AA==",
            "text/plain data:text/plain;base64,/4AAQQ==",
            "application/x-synthetic data:application/x-synthetic;base64,",
            "application/x-synthetic data:application/x-synthetic;base64,AA==",
            "application/x-synthetic data:application/x-synthetic;base64,/4AAQQ=="
        ]
    );
}

#[test]
fn reader_legacy_encodings() {
    assert_eq!(
        visit("reader-legacy-encodings"),
        [
            "latin1 \"é\"",
            "shift_jis \"あ\"",
            "gb18030 \"你\"",
            "big5 \"中\"",
            "iso-2022-jp \"あ\"",
            "koi8-r \"Пр\"",
            "utf-16be \"A\"",
            "utf-16le \"A\"",
            "x-user-defined \"\"",
            "iso-2022-kr \"�\"",
            "utf-8 \"�A\""
        ]
    );
}

#[test]
fn reader_mime_encodings() {
    assert_eq!(
        visit("reader-mime-encodings"),
        [
            "text/plain;charset=windows-1252  \"é\"",
            "text/plain;charset=windows-1252 invalid \"é\"",
            "text/plain;charset=windows-1252 utf-8 \"�\"",
            "text/plain;charset=windows-1252  \"é\"",
            "text/plain;charset=bad invalid \"�\"",
            "text/plain; charset=\"windows-1252\"  \"é\"",
            "text/plain; charset=windows-1252;charset=utf-8  \"é\""
        ]
    );
}

#[test]
fn reader_bom_encodings() {
    assert_eq!(visit("reader-bom-encodings"), ["239,187,191,195,169 \"é\"", "255,254,65,0 \"A\"", "254,255,0,65 \"A\"", "239,187 \"ï»\"", "255,254,0 \"�\""]);
}

#[test]
fn reader_encoding_conversion() {
    assert_eq!(visit("reader-encoding-conversion"), ["busy InvalidStateError encoding", "symbol TypeError", "blobFirst TypeError encoding"]);
}

#[test]
fn reader_private_blob() {
    assert_eq!(visit("reader-private-blob"), ["synthetic 0", "synthetic 0"]);
}

#[test]
fn reader_private_state() {
    assert_eq!(visit("reader-private-state"), ["synthetic 2  0"]);
}

#[test]
fn reader_constructor_hooks() {
    assert_eq!(visit("reader-constructor-hooks"), ["0 0"]);
}

#[test]
fn reader_result_identity() {
    assert_eq!(visit("reader-result-identity"), ["true true", "cleared   1", "two 111,110,101"]);
}

#[test]
fn reader_abort_state_reset() {
    assert_eq!(visit("reader-abort-state-reset"), ["AbortError 20 true", "1  ", "2:second: AbortError"]);
}

#[test]
fn reader_shared_bytes() {
    assert_eq!(visit("reader-shared-bytes"), ["true 0,255,128,65 0,255,128,65"]);
}

#[test]
fn reader_clone_brand() {
    assert_eq!(visit("reader-clone-brand"), ["DataCloneError [object FileReader]", "DataCloneError", "0 TypeError"]);
}

#[test]
fn reader_prototype_fallback() {
    assert_eq!(visit("reader-prototype-fallback"), ["true 0 1", "true 0 2"]);
}

#[test]
fn reader_subclasses() {
    assert_eq!(visit("reader-subclasses"), ["true true true 0 [object FileReader]", "synthetic 2"]);
}

#[test]
fn reader_native_options_private() {
    assert_eq!(visit("reader-native-options-private"), ["synthetic 0"]);
}

#[test]
fn reader_prototype_index_private() {
    assert_eq!(visit("reader-prototype-index-private"), ["synthetic 0"]);
}

#[test]
fn reader_cancel_private() {
    assert_eq!(visit("reader-cancel-private"), ["2  AbortError 0"]);
}

#[test]
fn reader_reentrant_encoding() {
    assert_eq!(visit("reader-reentrant-encoding"), ["InvalidStateError inner 2"]);
}

#[test]
fn reader_clear_result_after_done() {
    assert_eq!(visit("reader-clear-result-after-done"), ["2  "]);
}

#[test]
fn reader_abort_restart_start() {
    assert_eq!(visit("reader-abort-restart-start"), ["second loadstart,abort,loadend,loadstart,progress,load,loadend"]);
}

#[test]
fn reader_handler_values() {
    assert_eq!(
        visit("reader-handler-values"),
        [
            "object object true true",
            "undefined object false true",
            "boolean object false true",
            "number object false true",
            "string object false true",
            "object object true false",
            "function function true false"
        ]
    );
}

#[test]
fn reader_handler_private_construction() {
    assert_eq!(visit("reader-handler-private-construction"), ["0 0"]);
}
