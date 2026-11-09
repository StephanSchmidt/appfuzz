//! Chrome/Firefox references over synthetic loopback responses. The JSON
//! response object follows the standard and Firefox's cached identity; Chrome
//! currently returns a fresh object on that path. Invalid responseText reads
//! follow the standard and Chrome even before a response is available.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/xhr.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|s| s.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan: Plan = serde_json::from_str(include_str!("fixtures/xhr-plan.json")).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert!(run.events.iter().all(|e| e.func == FETCH_OWN), "{:?}", run.events);
    assert!(run.events.iter().all(|e| e.args["path"] != "/unexpected"), "{:?}", run.events);
    if case == "xhr-private-routing" {
        assert_eq!(run.events.len(), 1);
        let a = &run.events[0].args;
        assert_eq!(a["method"], "GET");
        assert_eq!(a["path"], "/synthetic");
        assert_eq!(a["headers"], json!([]));
        assert_eq!(a["body"], Value::Null);
    }
    if case == "xhr-request-headers" || case == "xhr-request-charset" {
        assert_eq!(run.events.len(), 1);
        let a = &run.events[0].args;
        assert_eq!(a["method"], "POST");
        assert_eq!(a["body"], json!({"some":b"synthetic"}));
        let h = a["headers"].as_array().unwrap();
        assert!(h.contains(&json!(["content-type", "text/plain;charset=UTF-8"])), "{a:?}");
        assert!(!h.iter().any(|p| p[0] == "host" || p[0] == "cookie"));
        if case == "xhr-request-headers" {
            assert!(h.contains(&json!(["x-test", "one, two"])));
        }
    }
    if case == "xhr-get-body-conversion" {
        assert_eq!(run.events.len(), 1);
        assert_eq!(run.events[0].args["body"], Value::Null);
        assert_eq!(run.events[0].args["headers"], json!([]));
    }
    if case == "xhr-abort-loadstart" || case == "xhr-send-conversion-order" {
        assert!(run.events.is_empty(), "{:?}", run.events);
    }
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn xhr_readonly_state() {
    assert_eq!(
        visit("xhr-readonly-state"),
        [
            "readyState true false 0",
            "status true false 0",
            "statusText true false ",
            "responseText true false ",
            "responseURL true false ",
            "responseXML true false ",
            "response true false ",
            "upload true false true"
        ]
    );
}

#[test]
fn xhr_constructor_setters() {
    assert_eq!(visit("xhr-constructor-setters"), ["0 0"]);
}

#[test]
fn xhr_brand_checks() {
    assert_eq!(
        visit("xhr-brand-checks"),
        [
            "readyState TypeError readonly",
            "status TypeError readonly",
            "statusText TypeError readonly",
            "responseText TypeError readonly",
            "responseURL TypeError readonly",
            "responseXML TypeError readonly",
            "response TypeError readonly",
            "responseType TypeError TypeError",
            "timeout TypeError TypeError",
            "withCredentials TypeError TypeError",
            "upload TypeError readonly",
            "open TypeError",
            "send TypeError",
            "abort TypeError",
            "setRequestHeader TypeError",
            "getResponseHeader TypeError",
            "getAllResponseHeaders TypeError",
            "overrideMimeType TypeError"
        ]
    );
}

#[test]
fn xhr_interface_hierarchy() {
    assert_eq!(
        visit("xhr-interface-hierarchy"),
        [
            "XMLHttpRequest 0 [object XMLHttpRequest] false",
            "XMLHttpRequestEventTarget 0 [object XMLHttpRequestEventTarget] false",
            "XMLHttpRequestUpload 0 [object XMLHttpRequestUpload] false",
            "true true true true true [object XMLHttpRequest] [object XMLHttpRequestUpload]",
            "XMLHttpRequestEventTarget TypeError",
            "XMLHttpRequestUpload TypeError",
            "UNSENT 0 false true false",
            "OPENED 1 false true false",
            "HEADERS_RECEIVED 2 false true false",
            "LOADING 3 false true false",
            "DONE 4 false true false"
        ]
    );
}

#[test]
fn xhr_native_helper() {
    assert_eq!(visit("xhr-native-helper"), ["1 0", "1 0"]);
}

#[test]
fn xhr_native_event_interface() {
    assert_eq!(visit("xhr-native-event-interface"), ["Event false true 1"]);
}

#[test]
fn xhr_open_arguments() {
    assert_eq!(
        visit("xhr-open-arguments"),
        [
            "0 TypeError 0",
            "1 TypeError 0",
            "2 SyntaxError 0",
            "2 SyntaxError 0",
            "2 TypeError 0",
            "2 SecurityError 0",
            "2 SecurityError 0",
            "2 SecurityError 0",
            "2 SyntaxError 0",
            "2 TypeError 0",
            "2 ok 1"
        ]
    );
}

#[test]
fn xhr_open_conversion_order() {
    assert_eq!(visit("xhr-open-conversion-order"), ["SyntaxError method,url,username,password", "InvalidStateError name,value"]);
}

#[test]
fn xhr_field_setters() {
    assert_eq!(
        visit("xhr-field-setters"),
        [
            "timeout 1",
            "timeout 4294967295",
            "timeout 0",
            "timeout 0",
            "timeout 1",
            "false",
            "true",
            "type ok   ",
            "type ok   ",
            "type ok text  InvalidStateError",
            "type ok json InvalidStateError InvalidStateError",
            "type ok arraybuffer InvalidStateError InvalidStateError",
            "type ok blob InvalidStateError InvalidStateError",
            "type ok document InvalidStateError ",
            "type ok   "
        ]
    );
}

#[test]
fn xhr_sync_configuration() {
    assert_eq!(visit("xhr-sync-configuration"), ["InvalidAccessError 0", "InvalidAccessError 0", "InvalidAccessError InvalidAccessError", "0 "]);
}

#[test]
fn xhr_header_validation() {
    assert_eq!(
        visit("xhr-header-validation"),
        [
            "InvalidStateError",
            "\"\" SyntaxError",
            "\"bad name\" SyntaxError",
            "\"x\" SyntaxError",
            "\"x\" SyntaxError",
            "\"☃\" TypeError",
            "\"x\" TypeError",
            "\"x\" ok",
            "\"cookie\" ok",
            "\"Host\" ok",
            " TypeError "
        ]
    );
}

#[test]
fn xhr_private_routing() {
    assert_eq!(visit("xhr-private-routing"), ["200 synthetic  /synthetic"]);
}

#[test]
fn xhr_state_visibility() {
    assert_eq!(
        visit("xhr-state-visibility"),
        [
            "state 1 0 \"\" false Event true",
            "sent 1 0 \"\"",
            "state 2 200 \"\" true Event true",
            "state 3 200 \"synthetic\" true Event true",
            "state 4 200 \"synthetic\" true Event true",
            "done true "
        ]
    );
}

#[test]
fn xhr_progress_events() {
    assert_eq!(
        visit("xhr-progress-events"),
        [
            "loadstart true true true true false 0 0",
            "progress true true true true true 9 9",
            "load true true true true true 9 9",
            "loadend true true true true true 9 9"
        ]
    );
}

#[test]
fn xhr_send_state() {
    assert_eq!(
        visit("xhr-send-state"),
        ["unsent InvalidStateError", "again InvalidStateError InvalidStateError InvalidStateError", "done InvalidStateError InvalidStateError 4"]
    );
}

#[test]
fn xhr_abort_states() {
    assert_eq!(
        visit("xhr-abort-states"),
        ["unsent 0 ", "opened 1 ", "active 0 0 readystatechange:4,abort:4,loadend:4", "later 0 readystatechange:4,abort:4,loadend:4"]
    );
}

#[test]
fn xhr_abort_loadstart() {
    assert_eq!(visit("xhr-abort-loadstart"), ["readystatechange:1,loadstart:1,readystatechange:4,abort:4,loadend:4 0"]);
}

#[test]
fn xhr_open_replaces_operation() {
    assert_eq!(visit("xhr-open-replaces-operation"), ["different 4 different"]);
}

#[test]
fn xhr_response_types() {
    assert_eq!(
        visit("xhr-response-types"),
        [
            " 200 {\"synthetic\":true,\"count\":3} true {\"synthetic\":true,\"count\":3} ",
            "text 200 {\"synthetic\":true,\"count\":3} true {\"synthetic\":true,\"count\":3} InvalidStateError",
            "json 200 {\"synthetic\":true,\"count\":3} true InvalidStateError InvalidStateError",
            "arraybuffer 200 123,34,115,121,110,116,104,101,116,105,99,34,58,116,114,117,101,44,34,99,111,117,110,116,34,58,51,125 true InvalidStateError InvalidStateError",
            "blob 200 application/json:{\"synthetic\":true,\"count\":3} true InvalidStateError InvalidStateError"
        ]
    );
}

#[test]
fn xhr_response_type_locks() {
    assert_eq!(visit("xhr-response-type-locks"), ["2 ok ok json", "3 InvalidStateError InvalidStateError json", "4 InvalidStateError InvalidStateError json"]);
}

#[test]
fn xhr_response_headers() {
    assert_eq!(
        visit("xhr-response-headers"),
        [
            "Content-Type text/plain",
            "X-TEST one, two",
            "set-cookie ",
            "Set-Cookie2 ",
            "missing ",
            "bad name ",
            "sorted content-type: text/plain|x-alpha: a|x-test: one, two"
        ]
    );
}

#[test]
fn xhr_text_decoding() {
    assert_eq!(visit("xhr-text-decoding"), ["/latin café", "/bom cafe", "/broken �A", "override ÿA"]);
}

#[test]
fn xhr_json_errors() {
    assert_eq!(visit("xhr-json-errors"), ["/synthetic null 200", "/bom-json {\"synthetic\":true} 200", "/empty null 200"]);
}

#[test]
fn xhr_native_intrinsics() {
    assert_eq!(visit("xhr-native-intrinsics"), ["true 3"]);
}

#[test]
fn xhr_timeout() {
    assert_eq!(visit("xhr-timeout"), ["0 \"\" readystatechange:1,readystatechange:4,timeout:4,loadend:4"]);
}

#[test]
fn xhr_upload_events() {
    assert_eq!(visit("xhr-upload-events"), ["loadstart:true:0:9:true|progress:true:9:9:true|load:true:9:9:true|loadend:true:9:9:true", "200 synthetic"]);
}

#[test]
fn xhr_request_headers() {
    assert_eq!(visit("xhr-request-headers"), ["POST synthetic one, two text/plain;charset=UTF-8 true none"]);
}

#[test]
fn xhr_get_body_conversion() {
    assert_eq!(visit("xhr-get-body-conversion"), ["1 GET \"\" none"]);
}

#[test]
fn xhr_send_conversion_order() {
    assert_eq!(visit("xhr-send-conversion-order"), ["InvalidStateError 1", "TypeError 1"]);
}

#[test]
fn xhr_instance_shadows() {
    assert_eq!(
        visit("xhr-instance-shadows"),
        ["readyState 4", "status 200", "responseType ", "responseText synthetic", "timeout 0", "withCredentials false", "shadow 99 999 shadow"]
    );
}

#[test]
fn xhr_abort_at_headers() {
    assert_eq!(visit("xhr-abort-at-headers"), ["s1,s2,s4,abort:4,loadend:4 0 0 "]);
}

#[test]
fn xhr_microtask_abort() {
    assert_eq!(visit("xhr-microtask-abort"), ["s1,s2,s4,abort:4,loadend:4 0 0"]);
}

#[test]
fn xhr_empty_responses() {
    assert_eq!(visit("xhr-empty-responses"), [" 4 200 \"\"", "json 4 200 null", "arraybuffer 4 200 0", "blob 4 200 0:text/plain"]);
}

#[test]
fn xhr_sync_send() {
    assert_eq!(visit("xhr-sync-send"), ["200 synthetic readystatechange:1,readystatechange:4,load:4,loadend:4"]);
}

#[test]
fn xhr_timeout_update() {
    assert_eq!(visit("xhr-timeout-update"), ["timeout 4 0"]);
}

#[test]
fn xhr_timeout_remove() {
    assert_eq!(visit("xhr-timeout-remove"), ["load 4 200"]);
}

#[test]
fn xhr_public_intrinsics() {
    assert_eq!(visit("xhr-public-intrinsics"), ["0  synthetic"]);
}

#[test]
fn xhr_request_charset() {
    assert_eq!(visit("xhr-request-charset"), ["text/plain;charset=UTF-8"]);
}

#[test]
fn xhr_invalid_mime() {
    assert_eq!(visit("xhr-invalid-mime"), ["application/octet-stream text/plain"]);
}

#[test]
fn xhr_document_response() {
    assert_eq!(
        visit("xhr-document-response"),
        [
            "/xml  true root urn:synthetic application/xml true /xml synthetic true",
            "/xml document true root urn:synthetic application/xml true /xml synthetic true",
            "/html  false    false   true",
            "/html document true html http://www.w3.org/1999/xhtml text/html true /html synthetic true",
            "/invalid-xml document false    false   true"
        ]
    );
}

#[test]
fn xhr_network_error() {
    assert_eq!(visit("xhr-network-error"), ["0 \"\" true  \"\" readystatechange:1:true,readystatechange:4:true,error:4:true,loadend:4:true"]);
}

#[test]
fn xhr_reopen_on_abort() {
    assert_eq!(visit("xhr-reopen-on-abort"), ["abort:4,different 4 200 different"]);
}

#[test]
fn xhr_upload_abort() {
    assert_eq!(visit("xhr-upload-abort"), ["u-loadstart,u-progress,u-abort,u-loadend,r-abort,r-loadend 0 0"]);
}

#[test]
fn xhr_document_private_helpers() {
    assert_eq!(visit("xhr-document-private-helpers"), ["0 urn:synthetic synthetic"]);
}
