//! Structured clone graph identity, type data, callbacks and transfers.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let script = format!("const CASE={};{};for(const line of lines)console.log(line)", json!(case), include_str!("fixtures/structured_clone.js"));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    let unsupported = if case == "clone-no-stack-hooks" || case == "clone-rejection-stack-hooks" { json!(["Error.prepareStackTrace"]) } else { json!([]) };
    assert_eq!(report["unmodelled"], unsupported, "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

// Reference: Chrome157 except native Error stack and late detached transfer
// handling, which follow HTML/Web IDL and Firefox158. AggregateError falls back
// to Error as specified by HTML's current name whitelist.
#[test]
fn clone_primitives() {
    assert_eq!(
        visit("clone-primitives"),
        [
            "clone-primitives undefined undefined undefined true",
            "clone-primitives object null object true",
            "clone-primitives boolean false boolean true",
            "clone-primitives boolean true boolean true",
            "clone-primitives number 0 number true",
            "clone-primitives number 0 number true",
            "clone-primitives number NaN number true",
            "clone-primitives number Infinity number true",
            "clone-primitives number -Infinity number true",
            "clone-primitives bigint 17 bigint true",
            "clone-primitives string text string true"
        ]
    );
}

#[test]
fn clone_cycles() {
    assert_eq!(visit("clone-cycles"), ["clone-cycles true true 3"]);
}

#[test]
fn clone_aliases() {
    assert_eq!(visit("clone-aliases"), ["clone-aliases true true true true"]);
}

#[test]
fn clone_arrays() {
    assert_eq!(visit("clone-arrays"), ["clone-arrays 4 2,extra false true 7 true"]);
}

#[test]
fn clone_date() {
    assert_eq!(visit("clone-date"), ["clone-date true true 0", "clone-date true true 0", "clone-date true true 0", "clone-date true true 0"]);
}

#[test]
fn clone_regexp() {
    assert_eq!(visit("clone-regexp"), ["clone-regexp true a+b dgimsuy 0 0"]);
}

#[test]
fn clone_map_set() {
    assert_eq!(visit("clone-map-set"), ["clone-map-set true true true true true true true"]);
}

#[test]
fn clone_boxed() {
    assert_eq!(
        visit("clone-boxed"),
        [
            "clone-boxed [object Number] true true",
            "clone-boxed [object Number] true true",
            "clone-boxed [object Boolean] true true",
            "clone-boxed [object String] true true",
            "clone-boxed [object BigInt] true true"
        ]
    );
}

#[test]
fn clone_errors() {
    assert_eq!(
        visit("clone-errors"),
        [
            "clone-errors Error true Error M 1 true false",
            "clone-errors TypeError true TypeError M 1 true false",
            "clone-errors RangeError true RangeError M 1 true false",
            "clone-errors SyntaxError true SyntaxError M 1 true false",
            "clone-errors ReferenceError true ReferenceError M 1 true false",
            "clone-errors URIError true URIError M 1 true false",
            "clone-errors EvalError true EvalError M 1 true false",
            "clone-errors AggregateError true Error M 1 true false"
        ]
    );
}

#[test]
fn clone_domexception() {
    assert_eq!(visit("clone-domexception"), ["clone-domexception true true AbortError M 20 0"]);
}

#[test]
fn clone_buffers() {
    assert_eq!(visit("clone-buffers"), ["clone-buffers true true true true true 2 3 1 4 1,2,3", "clone-buffers independent 1 9"]);
}

#[test]
fn clone_transfer() {
    assert_eq!(visit("clone-transfer"), ["clone-transfer 0 0 4 7"]);
}

#[test]
fn clone_transfer_failures() {
    assert_eq!(visit("clone-transfer-failures"), ["clone-transfer-failures DataCloneError 25 4", "clone-transfer-failures DataCloneError 25 4"]);
}

#[test]
fn clone_no_tojson() {
    assert_eq!(visit("clone-no-tojson"), ["clone-no-tojson 0 1  id"]);
}

#[test]
fn clone_rejections() {
    assert_eq!(
        visit("clone-rejections"),
        [
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25",
            "clone-rejections DataCloneError 25"
        ]
    );
}

#[test]
fn clone_descriptors() {
    assert_eq!(visit("clone-descriptors"), ["clone-descriptors true a true true true"]);
}

#[test]
fn clone_getters() {
    assert_eq!(visit("clone-getters"), ["clone-getters a a 1  "]);
}

#[test]
fn clone_options() {
    assert_eq!(
        visit("clone-options"),
        [
            "clone-options accepted",
            "clone-options TypeError ",
            "clone-options TypeError ",
            "clone-options DataCloneError 25",
            "clone-options DataCloneError 25",
            "clone-options missing TypeError"
        ]
    );
}

#[test]
fn clone_private_json() {
    assert_eq!(visit("clone-private-json"), ["clone-private-json 0 1"]);
}

#[test]
fn clone_getter_order() {
    assert_eq!(visit("clone-getter-order"), ["clone-getter-order a,inner,b"]);
}

#[test]
fn clone_collection_snapshots() {
    assert_eq!(visit("clone-collection-snapshots"), ["clone-collection-snapshots 2 2 false 1 true"]);
}

#[test]
fn clone_native_iterators() {
    assert_eq!(visit("clone-native-iterators"), ["clone-native-iterators 0 1 true"]);
}

#[test]
fn clone_special_keys() {
    assert_eq!(visit("clone-special-keys"), ["clone-special-keys true true 1 2 3 3"]);
}

#[test]
fn clone_abrupt_getters() {
    assert_eq!(visit("clone-abrupt-getters"), ["clone-abrupt-getters true", "clone-abrupt-getters options true"]);
}

#[test]
fn clone_error_descriptors() {
    assert_eq!(visit("clone-error-descriptors"), ["clone-error-descriptors 0 true Error  false false"]);
}

#[test]
fn clone_error_name_cause() {
    assert_eq!(
        visit("clone-error-name-cause"),
        ["clone-error-name-cause true TypeError M true true false true", "clone-error-name-cause undefined undefined true"]
    );
}

#[test]
fn clone_domexception_slots() {
    assert_eq!(visit("clone-domexception-slots"), ["clone-domexception-slots 0 AbortError M 20 true"]);
}

#[test]
fn clone_fake_brands() {
    assert_eq!(visit("clone-fake-brands"), ["clone-fake-brands true 0", "clone-fake-brands true 0", "clone-fake-brands true 0", "clone-fake-brands true 0"]);
}

#[test]
fn clone_proxy_traps() {
    assert_eq!(visit("clone-proxy-traps"), ["clone-proxy-traps DataCloneError 25 0", "clone-proxy-traps DataCloneError 25 0"]);
}

#[test]
fn clone_private_intrinsics() {
    assert_eq!(visit("clone-private-intrinsics"), ["clone-private-intrinsics 0 0 gi 2 true 4 5"]);
}

#[test]
fn clone_buffer_shadows() {
    assert_eq!(visit("clone-buffer-shadows"), ["clone-buffer-shadows 0 8 true 2 2 7 8"]);
}

#[test]
fn clone_buffer_snapshot_timing() {
    assert_eq!(visit("clone-buffer-snapshot-timing"), ["clone-buffer-snapshot-timing false 1 1 2", "clone-buffer-snapshot-timing true 9 0 2"]);
}

#[test]
fn clone_transfer_order() {
    assert_eq!(visit("clone-transfer-order"), ["clone-transfer-order transfer,iterator,value 0", "clone-transfer-order duplicate DataCloneError 0 1"]);
}

#[test]
fn clone_iterator_close() {
    assert_eq!(visit("clone-iterator-close"), ["clone-iterator-close TypeError 0"]);
}

#[test]
fn clone_detached_transfer() {
    assert_eq!(
        visit("clone-detached-transfer"),
        ["clone-detached-transfer getter true", "clone-detached-transfer late DataCloneError 0 0", "clone-detached-transfer clone DataCloneError 25"]
    );
}

#[test]
fn clone_plain_classes() {
    assert_eq!(visit("clone-plain-classes"), ["clone-plain-classes 1 2 false true"]);
}

#[test]
fn clone_platform_rejections() {
    assert_eq!(
        visit("clone-platform-rejections"),
        [
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25",
            "clone-platform-rejections DataCloneError 25"
        ]
    );
}

#[test]
fn clone_blob_file() {
    assert_eq!(visit("clone-blob-file"), ["clone-blob-file true false true true true true 3 text/plain 3 text/plain sample.txt 123"]);
}

#[test]
fn clone_shape() {
    assert_eq!(
        visit("clone-shape"),
        ["clone-shape structuredClone 1 false true true true", "clone-shape construct TypeError", "clone-shape receiver TypeError"]
    );
}

#[test]
fn clone_error_accessors() {
    assert_eq!(
        visit("clone-error-accessors"),
        [
            "clone-error-accessors message cloned 0 false string",
            "clone-error-accessors cause cloned 0 false undefined",
            "clone-error-accessors stack cloned 0 native string"
        ]
    );
}

#[test]
fn clone_valid_receivers() {
    assert_eq!(
        visit("clone-valid-receivers"),
        ["clone-valid-receivers 1", "clone-valid-receivers 1", "clone-valid-receivers 1", "clone-valid-receivers 1", "clone-valid-receivers TypeError"]
    );
}

#[test]
fn clone_platform_collections() {
    assert_eq!(
        visit("clone-platform-collections"),
        [
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25",
            "clone-platform-collections DataCloneError 25"
        ]
    );
}

#[test]
fn clone_no_stack_hooks() {
    assert_eq!(visit("clone-no-stack-hooks"), ["clone-no-stack-hooks 0 true true M D 20"]);
}

#[test]
fn clone_error_roundtrip() {
    assert_eq!(visit("clone-error-roundtrip"), ["clone-error-roundtrip 0 TypeError M  true false", "clone-error-roundtrip 0 InvalidStateError D 11 true true"]);
}

#[test]
fn clone_resizable_buffer() {
    assert_eq!(
        visit("clone-resizable-buffer"),
        ["clone-resizable-buffer true 16 4 1,2,3,4", "clone-resizable-buffer resize 8 4", "clone-resizable-buffer transfer true 16 4 0"]
    );
}

#[test]
fn clone_out_of_bounds_view() {
    assert_eq!(visit("clone-out-of-bounds-view"), ["clone-out-of-bounds-view DataCloneError 25", "clone-out-of-bounds-view DataCloneError 25"]);
}

#[test]
fn clone_collection_allocation_privacy() {
    assert_eq!(visit("clone-collection-allocation-privacy"), ["clone-collection-allocation-privacy 0 1"]);
}

#[test]
fn clone_deep_graph() {
    assert_eq!(visit("clone-deep-graph"), ["clone-deep-graph 1500 1"]);
}

#[test]
fn clone_prototype_setters() {
    assert_eq!(visit("clone-prototype-setters"), ["clone-prototype-setters 0 3"]);
}

#[test]
fn clone_rejection_stack_hooks() {
    assert_eq!(visit("clone-rejection-stack-hooks"), ["clone-rejection-stack-hooks 0 DataCloneError 25 true true"]);
}

#[test]
fn clone_typed_array_kinds() {
    assert_eq!(
        visit("clone-typed-array-kinds"),
        [
            "clone-typed-array-kinds Uint8ClampedArray true true 3 1,2,3",
            "clone-typed-array-kinds Uint8Array true true 3 1,2,3",
            "clone-typed-array-kinds Int8Array true true 3 1,2,3",
            "clone-typed-array-kinds Int16Array true true 3 1,2,3",
            "clone-typed-array-kinds Uint16Array true true 3 1,2,3",
            "clone-typed-array-kinds Int32Array true true 3 1,2,3",
            "clone-typed-array-kinds Uint32Array true true 3 1,2,3",
            "clone-typed-array-kinds BigInt64Array true true 3 1,2,3",
            "clone-typed-array-kinds BigUint64Array true true 3 1,2,3",
            "clone-typed-array-kinds Float16Array true true 3 1.25,2.5,3.75",
            "clone-typed-array-kinds Float32Array true true 3 1.25,2.5,3.75",
            "clone-typed-array-kinds Float64Array true true 3 1.25,2.5,3.75"
        ]
    );
}

#[test]
fn clone_domexception_copy_slots() {
    assert_eq!(
        visit("clone-domexception-copy-slots"),
        ["clone-domexception-copy-slots AbortError M 20 true true", "clone-domexception-copy-slots proxy TypeError"]
    );
}

fn report(script: &str) -> Value {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let result: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(result.get("fatal").is_none(), "{result}");
    assert_eq!(result["errors"], json!([]), "{result}");
    result
}
#[test]
fn transferring_message_ports_preserves_identity_and_completes() {
    let report = report(
        "const channel=new MessageChannel();const copy=structuredClone(channel.port1,{transfer:[channel.port1]});console.log(copy!==channel.port1,copy instanceof MessagePort);channel.port1.close();channel.port2.close();copy.close();",
    );
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["console"][0]["text"], "true true", "{report}");
}
#[test]
fn resizable_view_length_tracking_is_explicitly_incomplete() {
    let report = report("const buffer=new ArrayBuffer(4,{maxByteLength:8});const view=new Uint8Array(buffer);structuredClone(view);");
    assert_eq!(report["unmodelled"], json!(["structuredClone resizable ArrayBuffer view length tracking"]), "{report}");
}
#[test]
fn unsupported_stack_formatters_do_not_run_at_extra_exception_sites() {
    let report = report("Error.prepareStackTrace=()=>console.log('unexpected-hook');try{structuredClone(()=>{})}catch(e){console.log('caught',e.name,e.code)}");
    assert_eq!(report["unmodelled"], json!(["Error.prepareStackTrace"]), "{report}");
    assert_eq!(report["console"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["console"][0]["text"], "caught DataCloneError 25", "{report}");
}
