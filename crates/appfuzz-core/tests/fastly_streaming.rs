use appfuzz_core::{
    detect,
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;
use std::sync::Arc;

fn app(body: &str) -> App {
    let wat = format!(
        r#"(module
        (import "fastly_http_resp" "new" (func $response (param i32) (result i32)))
        (import "fastly_http_resp" "status_set" (func $status (param i32 i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $raw_write (param i32 i32 i32 i32 i32) (result i32)))
        (import "fastly_http_body" "read" (func $read (param i32 i32 i32 i32) (result i32)))
        (import "fastly_http_body" "append" (func $append (param i32 i32) (result i32)))
        (import "fastly_http_body" "close" (func $close (param i32) (result i32)))
        (import "fastly_http_body" "abandon" (func $abandon (param i32) (result i32)))
        (import "fastly_http_body" "trailer_append" (func $trailer (param i32 i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 64) "before") (data (i32.const 80) "after")
        (data (i32.const 160) "x-tail") (data (i32.const 176) "ready")
        (data (i32.const 96) "<script>alert(1)</script>") (data (i32.const 128) "\ff\00\fe")
        (func $check (param i32 i32) (if (i32.ne (local.get 0) (local.get 1)) (then unreachable)))
        (func $write (param $h i32) (param $ptr i32) (param $len i32)
            (call $check (call $raw_write (local.get $h) (local.get $ptr) (local.get $len) (i32.const 0) (i32.const 16)) (i32.const 0)))
        (func (export "_start") (local $resp i32) (local $b i32) (local $src i32)
            (call $check (call $response (i32.const 0)) (i32.const 0))
            (call $check (call $body (i32.const 4)) (i32.const 0))
            (local.set $resp (i32.load (i32.const 0))) (local.set $b (i32.load (i32.const 4)))
            {body}))"#
    );
    let host = HostManifest::resolve("fastly", std::path::Path::new("")).unwrap();
    let mut m = merge(&host, Manifest::for_wasm(std::path::Path::new("stream.wasm")), &Default::default()).unwrap();
    m.host = Some(Arc::new(host));
    m.entry.as_mut().unwrap().result.insert("body".into(), serde_json::from_value(json!("html:safe")).unwrap());
    App::from_bytes(m, wat::parse_str(wat).unwrap()).unwrap()
}
fn run(app: &App) -> RunRecord {
    let ex = app.export("entry#handle").unwrap();
    let args = app.default_args(ex, "2026-11-02T10:00:00").unwrap();
    app.run(&app.spec(ex, args, Plan::default(), 1))
}
const START: &str =
    "(call $write (local.get $b) (i32.const 64) (i32.const 6)) (call $check (call $send (local.get $resp) (local.get $b) (i32.const 1)) (i32.const 0))";
const TAIL: &str = "(call $write (local.get $b) (i32.const 80) (i32.const 5))";
#[test]
fn streaming_response_keeps_writes_after_headers_are_sent() {
    let r = run(&app(&format!("{START} {TAIL} (drop (call $close (local.get $b)))")));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], "beforeafter");
    assert!(r.result.as_ref().unwrap().get("body_complete").is_none());
}
#[test]
fn appending_a_body_to_a_sent_stream_preserves_its_bytes() {
    let r = run(&app(&format!(
        "{START}
        (drop (call $body (i32.const 8))) (local.set $src (i32.load (i32.const 8)))
        (call $write (local.get $src) (i32.const 80) (i32.const 5))
        (call $check (call $append (local.get $b) (local.get $src)) (i32.const 0))
        (call $check (call $close (local.get $src)) (i32.const 3))
        (drop (call $close (local.get $b)))"
    )));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], "beforeafter");
}
#[test]
fn abandoned_and_unfinished_streams_do_not_pass_as_completed_responses() {
    for end in ["", "(drop (call $abandon (local.get $b)))"] {
        let r = run(&app(&format!("{START} {TAIL} {end}")));
        assert_eq!(r.outcome.kind, OutcomeKind::Trap, "{:?}", r.outcome);
        assert_eq!(r.result.as_ref().unwrap()["body"], "beforeafter");
        assert_eq!(r.result.as_ref().unwrap()["body_complete"], false);
    }
}
#[test]
fn a_later_trap_keeps_the_streamed_prefix_and_original_failure() {
    let r = run(&app(&format!("{START} {TAIL} unreachable")));
    assert_eq!(r.outcome.kind, OutcomeKind::Unreachable, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], "beforeafter");
    assert_eq!(r.result.as_ref().unwrap()["body_complete"], false);
}
#[test]
fn nonstreaming_send_consumes_the_response_and_body_handles() {
    let r = run(&app(r#"
        (call $write (local.get $b) (i32.const 64) (i32.const 6))
        (call $check (call $send (local.get $resp) (local.get $b) (i32.const 0)) (i32.const 0))
        (call $check (call $status (local.get $resp) (i32.const 201)) (i32.const 3))
        (call $check (call $raw_write (local.get $b) (i32.const 80) (i32.const 5) (i32.const 0) (i32.const 16)) (i32.const 3))"#));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], "before");
}
#[test]
fn binary_fastly_output_is_lossless() {
    let r = run(&app(r#"(call $write (local.get $b) (i32.const 128) (i32.const 3))
        (drop (call $send (local.get $resp) (local.get $b) (i32.const 0)))"#));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], json!([255, 0, 254]));
}
#[test]
fn front_writes_and_reads_are_rejected_on_streaming_bodies() {
    let r = run(&app(&format!(
        "{START}
        (call $check (call $raw_write (local.get $b) (i32.const 80) (i32.const 5) (i32.const 1) (i32.const 16)) (i32.const 5))
        (call $check (call $read (local.get $b) (i32.const 512) (i32.const 4) (i32.const 16)) (i32.const 3))
        (drop (call $close (local.get $b)))"
    )));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], "before");
}
#[test]
fn output_checks_see_markup_written_after_streaming_headers() {
    let app = app("(call $check (call $send (local.get $resp) (local.get $b) (i32.const 1)) (i32.const 0))
        (call $write (local.get $b) (i32.const 96) (i32.const 25)) (drop (call $close (local.get $b)))");
    let r = run(&app);
    assert!(detect::per_run(&r, &app.manifest).iter().any(|f| f.kind == "script_in_output"));
}

#[test]
fn normal_send_keeps_only_the_unread_body_and_unsent_bodies_stay_private() {
    let r = run(&app(
        "(call $write (local.get $b) (i32.const 64) (i32.const 6)) (drop (call $read (local.get $b) (i32.const 512) (i32.const 2) (i32.const 16))) (drop (call $send (local.get $resp) (local.get $b) (i32.const 0)))",
    ));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], "fore");
    let r = run(&app("(call $write (local.get $b) (i32.const 64) (i32.const 6))"));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result, None);
}

#[test]
fn completed_streams_send_trailers_and_abandoned_streams_do_not() {
    for (end, complete) in [("close", true), ("abandon", false)] {
        let r = run(&app(&format!(
            "{START}
            (call $check (call $trailer (local.get $b) (i32.const 160) (i32.const 6) (i32.const 176) (i32.const 5)) (i32.const 0))
            (drop (call ${end} (local.get $b)))"
        )));
        assert_eq!(r.outcome.kind, if complete { OutcomeKind::Ok } else { OutcomeKind::Trap }, "{:?}", r.outcome);
        if complete {
            assert_eq!(r.result.as_ref().unwrap()["trailers"], json!([["x-tail", "ready"]]));
        } else {
            assert!(r.result.as_ref().unwrap().get("trailers").is_none());
            assert_eq!(r.result.as_ref().unwrap()["body_complete"], false);
        }
    }
}
#[test]
fn closed_streams_return_bad_handle_for_front_writes_and_reads() {
    let r = run(&app(&format!(
        "{START} (drop (call $close (local.get $b)))
        (call $check (call $raw_write (local.get $b) (i32.const 80) (i32.const 5) (i32.const 1) (i32.const 16)) (i32.const 3))
        (call $check (call $read (local.get $b) (i32.const 512) (i32.const 4) (i32.const 16)) (i32.const 3))"
    )));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
}
#[test]
fn failed_calls_preserve_native_handle_consumption_order() {
    let r = run(&app(r#"
        (call $check (call $append (i32.const 999) (local.get $b)) (i32.const 3))
        (call $check (call $close (local.get $b)) (i32.const 3))
        (drop (call $body (i32.const 4))) (local.set $b (i32.load (i32.const 4)))
        (call $check (call $send (local.get $resp) (i32.const 999) (i32.const 0)) (i32.const 3))
        (call $check (call $status (local.get $resp) (i32.const 201)) (i32.const 3))"#));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result, None);
}
#[test]
fn completed_streams_preserve_binary_bytes_and_lossless_trace_output() {
    let r = run(&app(r#"(drop (call $send (local.get $resp) (local.get $b) (i32.const 1)))
        (call $write (local.get $b) (i32.const 128) (i32.const 3)) (drop (call $close (local.get $b)))"#));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.result.as_ref().unwrap()["body"], json!([255, 0, 254]));
    let trace: appfuzz_core::envelope::Trace = serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
    assert_eq!(trace.to_record().result, r.result);
}
