//! Channel messaging, transfer queues, private routing and message events.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    // Execute one case without paying the browser CPU budget for compiling
    // all the unrelated asynchronous fixtures before its first task.
    let fixture = include_str!("fixtures/message_ports.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of lines)console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

// Chrome157 references except HTML/Web IDL + Firefox158 for close(),
// self-transfer validation, cached overload iterators, and onmessageerror.
// Native engines agree on reentrant link resolution after serialization and
// paused-queue activation order. Cross-channel interleavings are not fixed;
// each channel must preserve its own FIFO ordering.
#[test]
fn port_interface() {
    assert_eq!(
        visit("port-interface"),
        [
            "port-interface MessageChannel 0 false",
            "port-interface MessagePort 0 false",
            "port-interface parents true true true",
            "port-interface keys   [object MessageChannel] [object MessagePort]",
            "port-interface TypeError",
            "port-interface TypeError",
            "port-interface TypeError",
            "port-interface port1 function undefined true true",
            "port-interface port2 function undefined true true"
        ]
    );
}

#[test]
fn port_channel_slots() {
    assert_eq!(visit("port-channel-slots"), ["port-channel-slots true true true true true", "port-channel-slots TypeError"]);
}

#[test]
fn port_method_brands() {
    assert_eq!(
        visit("port-method-brands"),
        [
            "port-method-brands postMessage postMessage 1 false true true true",
            "port-method-brands TypeError",
            "port-method-brands TypeError",
            "port-method-brands TypeError",
            "port-method-brands start start 0 false true true true",
            "port-method-brands TypeError",
            "port-method-brands TypeError",
            "port-method-brands TypeError",
            "port-method-brands close close 0 false true true true",
            "port-method-brands TypeError",
            "port-method-brands TypeError",
            "port-method-brands TypeError"
        ]
    );
}

#[test]
fn port_copy() {
    assert_eq!(visit("port-copy"), ["port-copy true true 1 2"]);
}

#[test]
fn port_primitives() {
    assert_eq!(
        visit("port-primitives"),
        [
            "port-primitives undefined undefined true",
            "port-primitives object object true",
            "port-primitives boolean boolean true",
            "port-primitives number number true",
            "port-primitives number number true",
            "port-primitives number number true",
            "port-primitives number number true",
            "port-primitives bigint bigint true"
        ]
    );
}

#[test]
fn port_native_values() {
    assert_eq!(visit("port-native-values"), ["port-native-values true true 0 true true"]);
}

#[test]
fn port_sync_clone() {
    assert_eq!(visit("port-sync-clone"), ["port-sync-clone getter,returned"]);
}

#[test]
fn port_uncloneable() {
    assert_eq!(
        visit("port-uncloneable"),
        [
            "port-uncloneable DataCloneError 25",
            "port-uncloneable DataCloneError 25",
            "port-uncloneable DataCloneError 25",
            "port-uncloneable DataCloneError 25",
            "port-uncloneable DataCloneError 25"
        ]
    );
}

#[test]
fn port_start() {
    assert_eq!(visit("port-start"), ["port-start before 0", "port-start after one", "port-start again one,two"]);
}

#[test]
fn port_handler_start() {
    assert_eq!(visit("port-handler-start"), ["port-handler-start next"]);
}

#[test]
fn port_messageerror_does_not_start() {
    assert_eq!(visit("port-messageerror-does-not-start"), ["port-messageerror-does-not-start 0", "port-messageerror-does-not-start one"]);
}

#[test]
fn port_close() {
    assert_eq!(
        visit("port-close"),
        ["port-close 0", "port-close DataCloneError 25", "port-close accepted", "port-close detached 0", "port-close DataCloneError 25"]
    );
}

#[test]
fn port_close_queued() {
    assert_eq!(visit("port-close-queued"), ["port-close-queued before"]);
}

#[test]
fn port_close_sender_queued() {
    assert_eq!(visit("port-close-sender-queued"), ["port-close-sender-queued before"]);
}

#[test]
fn port_private_routing() {
    assert_eq!(visit("port-private-routing"), ["port-private-routing right:one"]);
}

#[test]
fn port_private_routing_getter() {
    assert_eq!(visit("port-private-routing-getter"), ["port-private-routing-getter 0 one"]);
}

#[test]
fn port_event() {
    assert_eq!(visit("port-event"), ["port-event true message true false true false false false   true 0 true true"]);
}

#[test]
fn port_fifo() {
    assert_eq!(visit("port-fifo"), ["port-fifo 0,1,2,3,4"]);
}

#[test]
fn port_buffer_transfer() {
    assert_eq!(
        visit("port-buffer-transfer"),
        ["port-buffer-transfer sync 0", "port-buffer-transfer true true 1 2 7 8", "port-buffer-transfer sync 0", "port-buffer-transfer true true 1 2 7 8"]
    );
}

#[test]
fn port_transfer_self() {
    assert_eq!(visit("port-transfer-self"), ["port-transfer-self DataCloneError 25 0", "port-transfer-self duplicate DataCloneError 25"]);
}

#[test]
fn port_transfer_structured() {
    assert_eq!(
        visit("port-transfer-structured"),
        [
            "port-transfer-structured identity true true",
            "port-transfer-structured one",
            "port-transfer-structured reply",
            "port-transfer-structured DataCloneError 25"
        ]
    );
}

#[test]
fn port_transfer_queue() {
    assert_eq!(visit("port-transfer-queue"), ["port-transfer-queue before 0", "port-transfer-queue after new:queued"]);
}

#[test]
fn port_transfer_enabled_queue() {
    assert_eq!(visit("port-transfer-enabled-queue"), ["port-transfer-enabled-queue before 0", "port-transfer-enabled-queue after new:queued"]);
}

#[test]
fn port_transfer_both() {
    assert_eq!(visit("port-transfer-both"), ["port-transfer-both x"]);
}

#[test]
fn port_transfer_message() {
    assert_eq!(visit("port-transfer-message"), ["port-transfer-message 1 true true true true", "port-transfer-message ready"]);
}

#[test]
fn port_transfer_unused() {
    assert_eq!(visit("port-transfer-unused"), ["port-transfer-unused x 1 true", "port-transfer-unused ready"]);
}

#[test]
fn port_transfer_before_receive() {
    assert_eq!(visit("port-transfer-before-receive"), ["port-transfer-before-receive queued"]);
}

#[test]
fn port_transfer_target_doomed() {
    assert_eq!(visit("port-transfer-target-doomed"), ["port-transfer-target-doomed 0", "port-transfer-target-doomed DataCloneError 25"]);
}

#[test]
fn port_transfer_errors_atomic() {
    assert_eq!(visit("port-transfer-errors-atomic"), ["port-transfer-errors-atomic DataCloneError 25", "port-transfer-errors-atomic still live"]);
}

#[test]
fn port_detached_old_send() {
    assert_eq!(visit("port-detached-old-send"), ["port-detached-old-send new"]);
}

#[test]
fn port_args() {
    assert_eq!(
        visit("port-args"),
        [
            "port-args TypeError ",
            "port-args TypeError ",
            "port-args TypeError ",
            "port-args TypeError ",
            "port-args TypeError ",
            "port-args DataCloneError 25",
            "port-args accepted"
        ]
    );
}

#[test]
fn port_overload_conversion() {
    assert_eq!(visit("port-overload-conversion"), ["port-overload-conversion iterator,called,data", "port-overload-conversion transfer,data"]);
}

#[test]
fn port_private_constructors() {
    assert_eq!(visit("port-private-constructors"), ["port-private-constructors 0 x"]);
}

#[test]
fn port_private_cloner() {
    assert_eq!(visit("port-private-cloner"), ["port-private-cloner 0 1"]);
}

#[test]
fn message_event_fields() {
    assert_eq!(
        visit("message-event-fields"),
        [
            "message-event-fields 0 https://app.example 17 true 1 true true true true true false",
            "message-event-fields readonly 0 https://app.example 1",
            "message-event-fields data function undefined true true",
            "message-event-fields brand TypeError",
            "message-event-fields origin function undefined true true",
            "message-event-fields brand TypeError",
            "message-event-fields lastEventId function undefined true true",
            "message-event-fields brand TypeError",
            "message-event-fields source function undefined true true",
            "message-event-fields brand TypeError",
            "message-event-fields ports function undefined true true",
            "message-event-fields brand TypeError"
        ]
    );
}

#[test]
fn message_event_conversion() {
    assert_eq!(
        visit("message-event-conversion"),
        ["message-event-conversion type,bubbles,cancelable,composed,data,lastEventId,origin,ports,source true X Y 1"]
    );
}

#[test]
fn message_event_invalid_init() {
    assert_eq!(
        visit("message-event-invalid-init"),
        [
            "message-event-invalid-init TypeError",
            "message-event-invalid-init TypeError",
            "message-event-invalid-init TypeError",
            "message-event-invalid-init TypeError",
            "message-event-invalid-init TypeError",
            "message-event-invalid-init TypeError",
            "message-event-invalid-init TypeError"
        ]
    );
}

#[test]
fn message_event_legacy() {
    assert_eq!(
        visit("message-event-legacy"),
        [
            "message-event-legacy initial   0",
            "message-event-legacy hello true true 0 origin last true true true",
            "message-event-legacy base changed 0 origin 1"
        ]
    );
}

#[test]
fn port_global_fifo() {
    assert_eq!(visit("port-global-fifo"), ["port-global-fifo a1,a2,a3 b1,b2"]);
}

#[test]
fn port_enable_order() {
    assert_eq!(visit("port-enable-order"), ["port-enable-order b,a"]);
}

#[test]
fn port_nested_post() {
    assert_eq!(visit("port-nested-post"), ["port-nested-post inner,outer"]);
}

#[test]
fn port_close_in_getter() {
    assert_eq!(visit("port-close-in-getter"), ["port-close-in-getter "]);
}

#[test]
fn port_close_source_in_getter() {
    assert_eq!(visit("port-close-source-in-getter"), ["port-close-source-in-getter "]);
}

#[test]
fn port_options_before_target() {
    assert_eq!(visit("port-options-before-target"), ["port-options-before-target 0 0"]);
}

#[test]
fn port_transfer_target_in_getter() {
    assert_eq!(visit("port-transfer-target-in-getter"), ["port-transfer-target-in-getter new"]);
}

#[test]
fn port_microtasks_between_listeners() {
    assert_eq!(visit("port-microtasks-between-listeners"), ["port-microtasks-between-listeners first,micro"]);
}

#[test]
fn port_nested_synthetic_microtasks() {
    assert_eq!(visit("port-nested-synthetic-microtasks"), ["port-nested-synthetic-microtasks outer1,nested1,nested2,returned,micro,outer2"]);
}

#[test]
fn port_start_shadow() {
    assert_eq!(visit("port-start-shadow"), ["port-start-shadow 0 x"]);
}

#[test]
fn port_private_intrinsics() {
    assert_eq!(visit("port-private-intrinsics"), ["port-private-intrinsics 0 1"]);
}

#[test]
fn message_event_conversion_interleaving() {
    assert_eq!(
        visit("message-event-conversion-interleaving"),
        ["message-event-conversion-interleaving get-last,convert-last,get-origin,convert-origin,get-source true true"]
    );
}

#[test]
fn message_event_init_dispatch() {
    assert_eq!(visit("message-event-init-dispatch"), ["message-event-init-dispatch 1 before 1 false false 0"]);
}

#[test]
fn port_close_paused_queue() {
    assert_eq!(visit("port-close-paused-queue"), ["port-close-paused-queue before"]);
}

#[test]
fn port_channel_custom_prototype() {
    assert_eq!(
        visit("port-channel-custom-prototype"),
        ["port-channel-custom-prototype true true true", "port-channel-custom-prototype subclass true true true"]
    );
}

#[test]
fn port_microtask_error_report() {
    assert_eq!(visit("port-microtask-error-report"), ["port-microtask-error-report error:message job,second"]);
}

#[test]
fn port_paused_transfer_pair() {
    assert_eq!(visit("port-paused-transfer-pair"), ["port-paused-transfer-pair to-one to-two"]);
}

#[test]
fn port_private_array_setters() {
    assert_eq!(visit("port-private-array-setters"), ["port-private-array-setters 0 1"]);
}

#[test]
fn port_composed_path_array_setters() {
    assert_eq!(visit("port-composed-path-array-setters"), ["port-composed-path-array-setters 0 1"]);
}

#[test]
fn port_private_descriptor_fields() {
    assert_eq!(visit("port-private-descriptor-fields"), ["port-private-descriptor-fields 0 1"]);
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
