use appfuzz_core::{
    detect,
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;

fn app(after: &str, finish: &str, send: bool, secret: bool) -> App {
    app_with_payload(after, finish, send, secret, b"<script>alert(1)</script>")
}
fn app_with_payload(after: &str, finish: &str, send: bool, secret: bool, bytes: &[u8]) -> App {
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/wit/http")).unwrap();
    let pkg =
        resolve.push_str("test.wit", "package test:completion; world app {import secret:func()->string;export wasi:http/incoming-handler@0.2.12;}").unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let payload = bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let write = if secret {
        "(call $secret (i32.const 1024)) (call $write (local.get $stream) (i32.load (i32.const 1024)) (i32.load (i32.const 1028)) (i32.const 1040))".to_string()
    } else {
        format!("(call $write (local.get $stream) (i32.const 0) (i32.const {}) (i32.const 1040))", bytes.len())
    };
    let mut module = wat::parse_str(format!(
        r#"(module
        (import "$root" "secret" (func $secret (param i32)))
        (import "wasi:http/types@0.2.12" "[constructor]fields" (func $fields (result i32)))
        (import "wasi:http/types@0.2.12" "[constructor]outgoing-response" (func $response (param i32) (result i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-response.body" (func $body (param i32 i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-body.write" (func $stream (param i32 i32)))
        (import "wasi:http/types@0.2.12" "[static]response-outparam.set" (func $set (param i32 i32 i32 i32 i64 i32 i32 i32 i32)))
        (import "wasi:http/types@0.2.12" "[static]outgoing-body.finish" (func $finish (param i32 i32 i32 i32)))
        (import "wasi:http/types@0.2.12" "[resource-drop]outgoing-body" (func $abort (param i32)))
        (import "wasi:io/streams@0.2.12" "[method]output-stream.blocking-write-and-flush" (func $write (param i32 i32 i32 i32)))
        (import "wasi:io/streams@0.2.12" "[resource-drop]output-stream" (func $drop (param i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "{payload}")
        (global $heap (mut i32) (i32.const 4096))
        (func (export "cabi_realloc") (param i32 i32 i32) (param $size i32) (result i32) (local $p i32)
            (local.set $p (global.get $heap)) (global.set $heap (i32.add (local.get $p) (local.get $size))) (local.get $p))
        (func (export "wasi:http/incoming-handler@0.2.12#handle") (param i32) (param $out i32)
            (local $response i32) (local $body i32) (local $stream i32)
            (local.set $response (call $response (call $fields)))
            (call $body (local.get $response) (i32.const 1000))
            (if (i32.load (i32.const 1000)) (then unreachable))
            (local.set $body (i32.load (i32.const 1004)))
            {send}
            (call $stream (local.get $body) (i32.const 1000))
            (if (i32.load (i32.const 1000)) (then unreachable))
            (local.set $stream (i32.load (i32.const 1004)))
            {write}
            (if (i32.load8_u (i32.const 1040)) (then unreachable))
            (call $drop (local.get $stream))
            {finish}
            {after}))"#,
        send = if send { "(call $set (local.get $out) (i32.const 0) (local.get $response) (i32.const 0) (i64.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))" } else { "" }
    ))
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    let mut manifest = Manifest::for_wasm(std::path::Path::new("http-completion.wasm"));
    manifest.functions.insert("secret".into(), serde_json::from_value(json!({"result":"secret"})).unwrap());
    manifest.entry = Some(serde_json::from_value(json!({"export":"wasi:http/incoming-handler#handle","result":{"body":"html:safe"}})).unwrap());
    App::from_bytes(manifest, bytes).unwrap()
}

const FINISH: &str = "(call $finish (local.get $body) (i32.const 0) (i32.const 0) (i32.const 1088))";
fn run(app: &App) -> RunRecord {
    let export = app.export("wasi:http/incoming-handler#handle").unwrap();
    let args = app.default_args(export, "2026-11-02T10:00:00").unwrap();
    let plan = Plan::parse(r#"{"secret":{"return":"sk_test_private_value"}}"#).unwrap();
    app.run(&app.spec(export, args, plan, 1))
}

#[test]
fn completed_response_survives_a_later_guest_trap() {
    let app = app("unreachable", FINISH, true, false);
    let record = run(&app);
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body"], "<script>alert(1)</script>");
    let findings = detect::per_run(&record, &app.manifest);
    assert!(findings.iter().any(|f| f.kind == "crash"));
    assert!(findings.iter().any(|f| f.kind == "script_in_output"), "{findings:?}");
}

#[test]
fn a_later_trap_cannot_hide_a_secret_already_sent_to_the_client() {
    let app = app("unreachable", FINISH, true, true);
    let record = run(&app);
    assert_eq!(record.events.len(), 1);
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "secret_leak"));
}

#[test]
fn an_aborted_response_keeps_the_bytes_already_written() {
    let app = app("", "(call $abort (local.get $body))", true, true);
    let record = run(&app);
    assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body"], "sk_test_private_value");
    assert_eq!(record.result.as_ref().unwrap()["body_complete"], false);
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "secret_leak"));
}

#[test]
fn a_normal_completed_response_is_unchanged() {
    let record = run(&app("", FINISH, true, false));
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"status":200,"headers":[],"body":"<script>alert(1)</script>"})));
}

#[test]
fn an_unsent_response_does_not_become_client_output_on_trap() {
    let record = run(&app("unreachable", FINISH, false, true));
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result, None);
}

#[test]
fn returning_with_an_open_body_is_not_a_complete_response() {
    let app = app("", "", true, true);
    let record = run(&app);
    assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body_complete"], false);
    assert_eq!(record.result.as_ref().unwrap()["body"], "sk_test_private_value");
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "secret_leak"));
}

#[test]
fn trapping_with_an_open_body_keeps_the_original_crash_and_partial_output() {
    let record = run(&app("unreachable", "", true, true));
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body_complete"], false);
    assert_eq!(record.result.as_ref().unwrap()["body"], "sk_test_private_value");
}

#[test]
fn binary_response_bytes_survive_a_later_trap_and_trace_roundtrip() {
    let app = app_with_payload("unreachable", FINISH, true, false, &[0xff, 0x00, 0x80]);
    let record = run(&app);
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body"], json!([255, 0, 128]));
    let wire = serde_json::to_value(&record).unwrap();
    let trace: appfuzz_core::envelope::Trace = serde_json::from_value(wire).unwrap();
    assert_eq!(trace.to_record().result, record.result);
}

#[test]
fn finished_response_trailers_survive_a_later_trap() {
    let record = run(&app("unreachable", "(call $finish (local.get $body) (i32.const 1) (call $fields) (i32.const 1088))", true, false));
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["trailers"], json!([]));
    assert!(record.result.as_ref().unwrap().get("body_complete").is_none());
}

#[test]
fn completed_response_survives_exhausting_fuel_after_sending() {
    let app = app("(loop $forever (br $forever))", FINISH, true, true);
    let export = app.export("wasi:http/incoming-handler#handle").unwrap();
    let args = app.default_args(export, "2026-11-02T10:00:00").unwrap();
    let mut spec = app.spec(export, args, Plan::parse(r#"{"secret":{"return":"sk_test_private_value"}}"#).unwrap(), 1);
    spec.fuel = 10000;
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::OutOfFuel, "{:?}", record.outcome);
    assert_eq!(record.result.as_ref().unwrap()["body"], "sk_test_private_value");
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "secret_leak"));
}
