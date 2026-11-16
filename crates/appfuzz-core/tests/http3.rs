//! wasi:http 0.3 handlers (Spin 4's `http-rust` template) end to end. Each
//! handler is a core module in WAT that uses the component-model async ABI
//! the way wit-bindgen's callback mode does: `handle` is lifted async with a
//! callback, `client.send` is lowered async, and bodies are streams and
//! futures copied asynchronously. The WIT is the wasi:http 0.3.0 that
//! wasmtime-wasi-http provides (tests/fixtures/wasi-http-0.3).

use appfuzz_core::{
    detect,
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
    wasi_http::CLIENT_KEY,
};
use serde_json::{Value, json};

const HTTP: &str = include_str!("fixtures/wasi-http-0.3/http.wit");
const CLOCKS: &str = include_str!("fixtures/wasi-http-0.3/clocks.wit");

/// A handler whose `handle` runs `body`, straight-line code that ends with
/// the callback code (0: the task is done). Helpers:
///
/// - `$respond(status)`: returns a response whose body and trailers follow.
/// - `$write(at, len)`: sends body bytes; `$finish(trailers)`: ends the body
///   with the trailers future's value at `trailers` (768: `ok(none)`, 832:
///   `err(DNS-timeout)`, 896: `ok(some(t))` once `$trailers` made `t`).
/// - `$begin(slot, path, len, body, body len, first-byte timeout, abort)`:
///   starts `GET https://api.example{path}` (body len -1: no body; timeout
///   0: none; abort: the request body ends in an error); `$status(slot)`
///   waits for it and is the answer's status, or 500 + the error code's case.
///
/// Texts: "hello" at 0, " world" at 8, "api.example" at 16, "/v1/items" at
/// 32, the bytes ff fe at 48, "ping" at 56, "ftp" at 64, "x-checksum" at 72,
/// "abc" at 88. `secret` (a plain host function) answers at 1300.
fn component(body: &str) -> Vec<u8> {
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_str("clocks.wit", CLOCKS).unwrap();
    resolve.push_str("http.wit", HTTP).unwrap();
    let pkg = resolve
        .push_str(
            "app.wit",
            "package test:http3; world app {
                import wasi:http/types@0.3.0; import wasi:http/client@0.3.0; import secret: func() -> string;
                export wasi:http/handler@0.3.0;
            }",
        )
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let wat = format!(
        r#"(module
        (import "wasi:http/types@0.3.0" "[constructor]fields" (func $fields (result i32)))
        (import "wasi:http/types@0.3.0" "[method]fields.append" (func $append (param i32 i32 i32 i32 i32 i32)))
        (import "wasi:http/types@0.3.0" "[static]response.new" (func $response-new (param i32 i32 i32 i32 i32)))
        (import "wasi:http/types@0.3.0" "[method]response.set-status-code" (func $set-status (param i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[method]response.get-status-code" (func $get-status (param i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[resource-drop]response" (func $response-drop (param i32)))
        (import "wasi:http/types@0.3.0" "[stream-new-0][static]response.new" (func $body-new (result i64)))
        (import "wasi:http/types@0.3.0" "[async-lower][stream-write-0][static]response.new" (func $body-write (param i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[stream-drop-writable-0][static]response.new" (func $body-close (param i32)))
        (import "wasi:http/types@0.3.0" "[future-new-1][static]response.new" (func $trailers-new (result i64)))
        (import "wasi:http/types@0.3.0" "[async-lower][future-write-1][static]response.new" (func $trailers-write (param i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[future-drop-writable-1][static]response.new" (func $trailers-close (param i32)))
        (import "wasi:http/types@0.3.0" "[future-drop-readable-2][static]response.new" (func $sent-drop (param i32)))
        (import "wasi:http/types@0.3.0" "[method]request.get-authority" (func $authority (param i32 i32)))
        (import "wasi:http/types@0.3.0" "[static]request.new" (func $request-new (param i32 i32 i32 i32 i32 i32 i32)))
        (import "wasi:http/types@0.3.0" "[method]request.set-authority" (func $set-authority (param i32 i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[method]request.set-path-with-query" (func $set-path (param i32 i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[method]request.set-scheme" (func $set-scheme (param i32 i32 i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[constructor]request-options" (func $options-new (result i32)))
        (import "wasi:http/types@0.3.0" "[method]request-options.set-first-byte-timeout" (func $first-byte (param i32 i32 i64 i32)))
        (import "wasi:http/types@0.3.0" "[stream-new-0][static]request.new" (func $out-body-new (result i64)))
        (import "wasi:http/types@0.3.0" "[async-lower][stream-write-0][static]request.new" (func $out-body-write (param i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[stream-drop-writable-0][static]request.new" (func $out-body-close (param i32)))
        (import "wasi:http/types@0.3.0" "[future-new-1][static]request.new" (func $out-trailers-new (result i64)))
        (import "wasi:http/types@0.3.0" "[async-lower][future-write-1][static]request.new" (func $out-trailers-write (param i32 i32) (result i32)))
        (import "wasi:http/types@0.3.0" "[future-drop-writable-1][static]request.new" (func $out-trailers-close (param i32)))
        (import "wasi:http/types@0.3.0" "[future-drop-readable-2][static]request.new" (func $out-sent-drop (param i32)))
        (import "wasi:http/client@0.3.0" "[async-lower]send" (func $send (param i32 i32) (result i32)))
        (import "$root" "secret" (func $secret (param i32)))
        (import "[export]wasi:http/handler@0.3.0" "[task-return]handle" (func $return (param i32 i32 i32 i64 i32 i32 i32 i32)))
        (import "$root" "[waitable-set-new]" (func $set-new (result i32)))
        (import "$root" "[waitable-set-wait]" (func $set-wait (param i32 i32) (result i32)))
        (import "$root" "[waitable-set-drop]" (func $set-drop (param i32)))
        (import "$root" "[waitable-join]" (func $join (param i32 i32)))
        (import "$root" "[subtask-drop]" (func $subtask-drop (param i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "hello")
        (data (i32.const 8) " world")
        (data (i32.const 16) "api.example")
        (data (i32.const 32) "/v1/items")
        (data (i32.const 48) "\ff\fe")
        (data (i32.const 56) "ping")
        (data (i32.const 64) "ftp")
        (data (i32.const 72) "x-checksum")
        (data (i32.const 88) "abc")
        (data (i32.const 832) "\01")
        (global $heap (mut i32) (i32.const 4096))
        (global $body (mut i64) (i64.const 0))
        (global $trailers (mut i64) (i64.const 0))
        (func (export "cabi_realloc") (param i32 i32 i32) (param $n i32) (result i32) (local $p i32)
            (local.set $p (global.get $heap)) (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
        ;; Of a `stream.new`/`future.new` pair, the low half reads and the high half writes.
        (func $hi (param i64) (result i32) (i32.wrap_i64 (i64.shr_u (local.get 0) (i64.const 32))))
        (func $lo (param i64) (result i32) (i32.wrap_i64 (local.get 0)))
        ;; The payload of the next event on waitable $w.
        (func $wait (param $w i32) (result i32) (local $set i32)
            (local.set $set (call $set-new))
            (call $join (local.get $w) (local.get $set))
            (drop (call $set-wait (local.get $set) (i32.const 1024)))
            (call $join (local.get $w) (i32.const 0))
            (call $set-drop (local.get $set))
            (i32.load (i32.const 1028)))
        ;; The result of an async copy on end $w that returned $rc.
        (func $await (param $w i32) (param $rc i32) (result i32)
            (if (result i32) (i32.eq (local.get $rc) (i32.const -1)) (then (call $wait (local.get $w))) (else (local.get $rc))))
        (func $respond (param $status i32) (local $res i32)
            (global.set $body (call $body-new))
            (global.set $trailers (call $trailers-new))
            (call $response-new (call $fields) (i32.const 1) (call $lo (global.get $body)) (call $lo (global.get $trailers)) (i32.const 512))
            (local.set $res (i32.load (i32.const 512)))
            (call $sent-drop (i32.load (i32.const 516)))
            (if (i32.ne (local.get $status) (i32.const 200)) (then (drop (call $set-status (local.get $res) (local.get $status)))))
            (call $return (i32.const 0) (local.get $res) (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
        (func $write (param $at i32) (param $len i32)
            (drop (call $await (call $hi (global.get $body)) (call $body-write (call $hi (global.get $body)) (local.get $at) (local.get $len)))))
        (func $finish (param $at i32)
            (call $body-close (call $hi (global.get $body)))
            (drop (call $await (call $hi (global.get $trailers)) (call $trailers-write (call $hi (global.get $trailers)) (local.get $at))))
            (call $trailers-close (call $hi (global.get $trailers))))
        (func $trailers (local $t i32)
            (local.set $t (call $fields))
            (call $append (local.get $t) (i32.const 72) (i32.const 10) (i32.const 88) (i32.const 3) (i32.const 1100))
            (if (i32.load8_u (i32.const 1100)) (then unreachable))
            (i32.store8 (i32.const 904) (i32.const 1))
            (i32.store (i32.const 908) (local.get $t)))
        ;; Slot $slot keeps its state at 1200 + 32 * slot and its answer at 640 + 64 * slot.
        (func $begin (param $slot i32) (param $path i32) (param $plen i32) (param $at i32) (param $len i32) (param $timeout i64) (param $abort i32)
            (local $s i32) (local $req i32) (local $opts i32) (local $body i64) (local $trailers i64)
            (local.set $s (i32.add (i32.const 1200) (i32.mul (local.get $slot) (i32.const 32))))
            (local.set $trailers (call $out-trailers-new))
            (if (i32.ge_s (local.get $len) (i32.const 0)) (then (local.set $body (call $out-body-new))))
            (if (i64.ne (local.get $timeout) (i64.const 0)) (then
                (local.set $opts (call $options-new))
                (call $first-byte (local.get $opts) (i32.const 1) (local.get $timeout) (i32.const 1100))
                (if (i32.load8_u (i32.const 1100)) (then unreachable))))
            (call $request-new (call $fields)
                (i32.ge_s (local.get $len) (i32.const 0)) (call $lo (local.get $body))
                (call $lo (local.get $trailers))
                (i64.ne (local.get $timeout) (i64.const 0)) (local.get $opts)
                (i32.const 512))
            (local.set $req (i32.load (i32.const 512)))
            (call $out-sent-drop (i32.load (i32.const 516)))
            (if (call $set-authority (local.get $req) (i32.const 1) (i32.const 16) (i32.const 11)) (then unreachable))
            (if (call $set-path (local.get $req) (i32.const 1) (local.get $path) (local.get $plen)) (then unreachable))
            {scheme}
            (i64.store (local.get $s) (local.get $trailers))
            (i64.store offset=8 (local.get $s) (local.get $body))
            (i32.store offset=28 (local.get $s) (i32.ge_s (local.get $len) (i32.const 0)))
            (if (i32.ge_s (local.get $len) (i32.const 0)) (then
                (i32.store offset=20 (local.get $s) (call $out-body-write (call $hi (local.get $body)) (local.get $at) (local.get $len)))))
            (i32.store offset=16 (local.get $s)
                (call $out-trailers-write (call $hi (local.get $trailers)) (select (i32.const 832) (i32.const 768) (local.get $abort))))
            (i32.store offset=24 (local.get $s) (call $send (local.get $req) (i32.add (i32.const 640) (i32.mul (local.get $slot) (i32.const 64))))))
        (func $status (param $slot i32) (result i32) (local $s i32) (local $rc i32) (local $sub i32) (local $at i32) (local $code i32)
            (local.set $s (i32.add (i32.const 1200) (i32.mul (local.get $slot) (i32.const 32))))
            (if (i32.load offset=28 (local.get $s)) (then
                (drop (call $await (call $hi (i64.load offset=8 (local.get $s))) (i32.load offset=20 (local.get $s))))
                (call $out-body-close (call $hi (i64.load offset=8 (local.get $s))))))
            (drop (call $await (call $hi (i64.load (local.get $s))) (i32.load offset=16 (local.get $s))))
            (call $out-trailers-close (call $hi (i64.load (local.get $s))))
            (local.set $rc (i32.load offset=24 (local.get $s)))
            (if (i32.ne (i32.and (local.get $rc) (i32.const 15)) (i32.const 2)) (then
                (local.set $sub (i32.shr_u (local.get $rc) (i32.const 4)))
                (loop $again (br_if $again (i32.ne (call $wait (local.get $sub)) (i32.const 2))))
                (call $subtask-drop (local.get $sub))))
            (local.set $at (i32.add (i32.const 640) (i32.mul (local.get $slot) (i32.const 64))))
            (if (result i32) (i32.load8_u (local.get $at))
                (then (i32.add (i32.const 500) (i32.load8_u offset=8 (local.get $at))))
                (else
                    (local.set $code (call $get-status (i32.load offset=8 (local.get $at))))
                    (call $response-drop (i32.load offset=8 (local.get $at)))
                    (local.get $code))))
        (func (export "[async-lift]wasi:http/handler@0.3.0#handle") (param $req i32) (result i32)
            {body})
        (func (export "[callback][async-lift]wasi:http/handler@0.3.0#handle") (param i32 i32 i32) (result i32) (i32.const 0)))"#,
        scheme = if body.contains(";; ftp") {
            "(if (call $set-scheme (local.get $req) (i32.const 1) (i32.const 2) (i32.const 64) (i32.const 3)) (then unreachable))"
        } else {
            ""
        },
    );
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}

fn app(body: &str) -> App {
    app_in(Manifest::for_wasm(std::path::Path::new("http3.wasm")), body)
}

fn app_in(manifest: Manifest, body: &str) -> App {
    App::from_bytes(manifest, component(body)).unwrap()
}

/// Runs the handler. Guest code takes no virtual time, so the host's is exact.
fn run(app: &App, request: Value, plan: &str) -> RunRecord {
    let export = app.export(&app.manifest.entry.as_ref().unwrap().export).unwrap();
    let mut spec = app.spec(export, vec![request], Plan::parse(plan).unwrap(), 1);
    spec.ns_per_fuel = 0.0;
    app.run(&spec)
}

fn get(uri: &str) -> Value {
    json!({"method": "GET", "uri": uri, "headers": [], "body": ""})
}

/// The upstream answers 201 after `ms` milliseconds.
fn created_after(ms: u32) -> String {
    format!(r#"{{"{CLIENT_KEY}": {{"return": {{"ok": {{"status": 201, "headers": [], "body": "made"}}}}, "latency_ms": {ms}}}}}"#)
}

const MS: u64 = 1_000_000;

#[test]
fn a_handler_answers_with_its_status_and_body() {
    let app = app("(call $respond (i32.const 201)) (call $write (i32.const 0) (i32.const 5)) (call $finish (i32.const 768)) (i32.const 0)");
    assert_eq!(app.manifest.entry.as_ref().unwrap().export, "wasi:http/handler#handle");
    let record = run(&app, get("https://app.example/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status": 201, "headers": [], "body": "hello"})));
    assert_eq!(record.totals.host_calls, 0);
}

#[test]
fn the_request_carries_the_platforms_origin() {
    // The body is the authority the handler sees.
    let app = app(r#"
        (call $authority (local.get $req) (i32.const 1100))
        (call $respond (i32.const 200))
        (if (i32.load8_u (i32.const 1100)) (then (call $write (i32.load (i32.const 1104)) (i32.load (i32.const 1108)))))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    let authority = |request: Value| {
        let record = run(&app, request, "{}");
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
        record.result.unwrap()["body"].as_str().unwrap().to_string()
    };
    assert_eq!(authority(get("https://shop.example/cart")), "shop.example");
    // A request target without a host: the client's Host, else the app's own.
    assert_eq!(authority(json!({"method": "GET", "uri": "/cart", "headers": [["host", "shop.example:8080"]], "body": ""})), "shop.example:8080");
    assert_eq!(authority(get("/cart")), "app.example");
    assert_eq!(authority(json!({"method": "GET", "uri": "/cart", "headers": [["host", "not a host"]], "body": ""})), "app.example");
}

#[test]
fn a_body_streamed_after_handle_returns_is_captured_with_its_trailers() {
    // Half the body, an outbound request, the other half, then trailers.
    let app = app(r#"
        (call $respond (i32.const 200))
        (call $write (i32.const 0) (i32.const 5))
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (if (i32.ne (call $status (i32.const 0)) (i32.const 201)) (then unreachable))
        (call $write (i32.const 8) (i32.const 6))
        (call $trailers)
        (call $finish (i32.const 896)) (i32.const 0)"#);
    let record = run(&app, get("https://app.example/"), &created_after(40));
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    let result = record.result.unwrap();
    assert_eq!(result["body"], "hello world");
    assert_eq!(result["trailers"], json!([["x-checksum", "abc"]]));
    assert!(result.get("body_complete").is_none());
    assert_eq!(record.totals.host_calls, 1);
    assert_eq!(record.totals.host_ns, 40 * MS);
}

#[test]
fn an_outgoing_request_is_one_simulated_host_call() {
    // The handler answers with the upstream's status.
    let app = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 56) (i32.const 4) (i64.const 0) (i32.const 0))
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    let record = run(&app, get("https://app.example/"), &created_after(25));
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["status"], 201);
    assert_eq!(record.events.len(), 1);
    let call = &record.events[0];
    assert_eq!(call.func, CLIENT_KEY);
    assert_eq!(call.args["method"], "GET");
    assert_eq!(call.args["url"], "https://api.example/v1/items");
    assert_eq!(call.args["body"], "ping");
    assert!(call.args["headers"].as_array().unwrap().iter().any(|h| h == &json!(["host", "api.example"])), "{:?}", call.args);
    assert_eq!(record.totals.host_ns, 25 * MS);
}

#[test]
fn a_binary_request_body_is_recorded_as_bytes() {
    let app = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 48) (i32.const 2) (i64.const 0) (i32.const 0))
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    let record = run(&app, get("https://app.example/"), &created_after(1));
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.events[0].args["body"], json!([255, 254]));
}

#[test]
fn requests_sent_together_overlap_in_virtual_time() {
    let together = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (call $begin (i32.const 1) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (drop (call $status (i32.const 0))) (drop (call $status (i32.const 1)))
        (call $respond (i32.const 200)) (call $finish (i32.const 768)) (i32.const 0)"#);
    let one_by_one = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (drop (call $status (i32.const 0)))
        (call $begin (i32.const 1) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (drop (call $status (i32.const 1)))
        (call $respond (i32.const 200)) (call $finish (i32.const 768)) (i32.const 0)"#);
    for (app, waited) in [(together, 60), (one_by_one, 120)] {
        let record = run(&app, get("https://app.example/"), &created_after(60));
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
        assert_eq!(record.totals.host_calls, 2);
        assert_eq!(record.totals.host_ns, waited * MS);
    }
}

#[test]
fn host_errors_reach_the_guest_as_error_codes() {
    let app = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    // 500 + the error code's case: connection-refused is case 6,
    // connection-timeout 8, HTTP-response-timeout 33, internal-error 38.
    for (err, status) in [("connection-refused", 506), ("connection-timeout", 508), ("http-response-timeout", 533), ("the upstream is on fire", 538)] {
        let record = run(&app, get("https://app.example/"), &format!(r#"{{"{CLIENT_KEY}": {{"return": {{"err": "{err}"}}}}}}"#));
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{err}: {:?}", record.outcome);
        assert_eq!(record.result.as_ref().unwrap()["status"], status, "{err}");
        assert_eq!(record.events.len(), 1);
    }
}

#[test]
fn a_request_the_client_cannot_send_fails_without_a_host_call() {
    // An unsupported scheme, and a request body that ends in an error: both
    // are HTTP-protocol-error (case 35) before anything is sent.
    let ftp = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0)) ;; ftp
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    let aborted = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 56) (i32.const 4) (i64.const 0) (i32.const 1))
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    for app in [ftp, aborted] {
        let record = run(&app, get("https://app.example/"), &created_after(10));
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
        assert_eq!(record.result.as_ref().unwrap()["status"], 535);
        assert_eq!(record.totals.host_calls, 0);
    }
}

#[test]
fn a_first_byte_timeout_cuts_a_slow_answer_short() {
    let app = app(r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 100000000) (i32.const 0))
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#);
    // Slower than the timeout: connection-read-timeout (case 9) at 100 ms.
    let record = run(&app, get("https://app.example/"), &created_after(500));
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["status"], 509);
    assert_eq!(record.events[0].source, "timeout");
    assert_eq!(record.totals.host_ns, 100 * MS);
    // Faster: the answer.
    let record = run(&app, get("https://app.example/"), &created_after(50));
    assert_eq!(record.result.as_ref().unwrap()["status"], 201);
    assert_eq!(record.totals.host_ns, 50 * MS);
}

#[test]
fn a_handler_that_returns_an_error_code_gets_a_500_without_a_body() {
    // err(internal-error(none))
    let app =
        app("(call $return (i32.const 1) (i32.const 38) (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)) (i32.const 0)");
    let record = run(&app, get("https://app.example/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status": 500, "headers": [], "body": ""})));
}

#[test]
fn a_trap_keeps_the_head_and_the_bytes_already_sent() {
    let app = app("(call $respond (i32.const 200)) (call $write (i32.const 0) (i32.const 5)) unreachable");
    let record = run(&app, get("https://app.example/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status": 200, "headers": [], "body": "hello", "body_complete": false})));
}

#[test]
fn a_trap_cannot_hide_a_secret_already_sent_to_the_client() {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("http3.wasm"));
    manifest.functions.insert("secret".into(), serde_json::from_value(json!({"result": "secret"})).unwrap());
    let app = app_in(
        manifest,
        "(call $secret (i32.const 1300)) (call $respond (i32.const 200)) (call $write (i32.load (i32.const 1300)) (i32.load (i32.const 1304))) unreachable",
    );
    let record = run(&app, get("https://app.example/"), r#"{"secret": {"return": "sk_test_private_value"}}"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body"], "sk_test_private_value");
    let findings = detect::per_run(&record, &app.manifest);
    assert!(findings.iter().any(|f| f.kind == "crash"), "{findings:?}");
    assert!(findings.iter().any(|f| f.kind == "secret_leak"), "{findings:?}");
}

#[test]
fn a_trap_before_the_response_leaves_no_result() {
    let app = app("unreachable");
    let record = run(&app, get("https://app.example/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result, None);
}

#[test]
fn a_body_left_open_is_a_deadlock_reported_as_a_timeout() {
    // The task ends without closing the body: nothing will ever finish it.
    let app = app("(call $respond (i32.const 200)) (call $write (i32.const 0) (i32.const 5)) (i32.const 0)");
    let record = run(&app, get("https://app.example/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Timeout, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status": 200, "headers": [], "body": "hello", "body_complete": false})));
}

#[test]
fn an_aborted_response_body_is_incomplete() {
    let app = app("(call $respond (i32.const 200)) (call $write (i32.const 0) (i32.const 5)) (call $finish (i32.const 832)) (i32.const 0)");
    let record = run(&app, get("https://app.example/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{:?}", record.outcome);
    assert!(record.outcome.message.as_deref().unwrap_or_default().contains("aborted its response body"), "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status": 200, "headers": [], "body": "hello", "body_complete": false})));
}

#[test]
fn an_answer_that_is_no_http_response_is_a_plan_error() {
    const FETCH: &str = r#"
        (call $begin (i32.const 0) (i32.const 32) (i32.const 9) (i32.const 0) (i32.const -1) (i64.const 0) (i32.const 0))
        (call $respond (call $status (i32.const 0)))
        (call $finish (i32.const 768)) (i32.const 0)"#;
    let status_42 = format!(r#"{{"{CLIENT_KEY}": {{"return": {{"ok": {{"status": 42, "headers": [], "body": ""}}}}}}}}"#);
    // The platform promises a status from 200 to 599: the host keeps it.
    let record = run(&app(FETCH), get("https://app.example/"), &status_42);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert!((200..600).contains(&record.result.unwrap()["status"].as_u64().unwrap()));
    // A manifest that promises nothing about it lets the plan's 42 through.
    let mut manifest = Manifest::for_wasm(std::path::Path::new("http3.wasm"));
    manifest.functions.insert(CLIENT_KEY.into(), serde_json::from_value(json!({"values": {"body": "len:0..100"}})).unwrap());
    let app = app_in(manifest, FETCH);
    let record = run(&app, get("https://app.example/"), &status_42);
    assert_eq!(record.outcome.kind, OutcomeKind::PlanError, "{:?}", record.outcome);
    assert!(record.outcome.message.as_deref().unwrap_or_default().contains("42 is not an HTTP status"), "{:?}", record.outcome);
    // The trap the plan asks for ends the run as the host's.
    let record = run(&app, get("https://app.example/"), &format!(r#"{{"{CLIENT_KEY}": {{"trap": "upstream gone"}}}}"#));
    assert_eq!(record.outcome.kind, OutcomeKind::HostTrap, "{:?}", record.outcome);
}

#[test]
fn a_request_the_platform_would_not_deliver_is_an_error() {
    let app = app("(call $respond (i32.const 200)) (call $finish (i32.const 768)) (i32.const 0)");
    let record = run(&app, json!({"method": "NOT A METHOD", "uri": "/", "headers": [], "body": ""}), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Error, "{:?}", record.outcome);
    let record = run(&app, get("/"), "{}");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status": 200, "headers": [], "body": ""})));
}
