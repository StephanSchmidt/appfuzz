use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;

const HOST: &str = "test:utf8/host#accept";
const INVALID: &[&[u8]] = &[&[0xff], &[0xc0, 0xaf], &[0xed, 0xa0, 0x80], &[0xe2, 0x82], &[0xf4, 0x90, 0x80, 0x80]];

fn app(bytes: &[u8], result: &str, action: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-utf8-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("plugin.wit"),
        format!("package test:utf8; interface host {{ accept: func(text: string); }} world plugin {{ import host; export run: func() -> {result}; }}"),
    )
    .unwrap();
    let host = HostManifest::parse("[platform]\nname='utf8'\nabi='extism'\nwit='plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("utf8.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let writes: String =
        bytes.iter().enumerate().map(|(i, byte)| format!("(call $write (i64.add (local.get $block) (i64.const {i})) (i32.const {byte}))")).collect();
    let wat = format!(
        r#"(module
        (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
        (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
        (import "extism:host/env" "output_set" (func $output (param i64 i64)))
        (import "extism:host/user" "accept" (func $accept (param i64)))
        (func (export "run") (result i32) (local $block i64)
            (local.set $block (call $alloc (i64.const {})))
            {writes} {action}
            (i32.const 0)))"#,
        bytes.len(),
    );
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

fn run(app: &App) -> RunRecord {
    app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1))
}

fn output(bytes: &[u8], result: &str) -> RunRecord {
    run(&app(bytes, result, &format!("(call $output (local.get $block) (i64.const {}))", bytes.len())))
}

#[test]
fn malformed_utf8_cannot_become_successful_string_output() {
    for bytes in INVALID {
        for result in ["string", "result<string, string>"] {
            let record = output(bytes, result);
            assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{bytes:?}, {result}: {:?}", record.outcome);
            assert!(record.result.is_none());
            assert!(record.outcome.message.unwrap().contains("utf-8"));
        }
    }
}

#[test]
fn malformed_utf8_cannot_be_replaced_before_a_host_call() {
    for bytes in INVALID {
        let record = run(&app(bytes, "string", "(call $accept (local.get $block))"));
        assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{bytes:?}: {:?}", record.outcome);
        assert!(record.events.is_empty(), "malformed text reached the host: {:?}", record.events);
        assert!(record.result.is_none());
        assert!(record.outcome.message.unwrap().contains("utf-8"));
    }
}

#[test]
fn valid_unicode_nuls_and_replacement_characters_remain_exact() {
    for text in ["", "a\0b", "é水🦀", "\u{fffd}"] {
        for result in ["string", "result<string, string>"] {
            let record = output(text.as_bytes(), result);
            assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
            assert_eq!(record.result, Some(if result == "string" { json!(text) } else { json!({"ok": text}) }));
        }
        let record = run(&app(text.as_bytes(), "string", "(call $accept (local.get $block))"));
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
        assert_eq!(record.events.len(), 1);
        assert_eq!(record.events[0].func, HOST);
        assert_eq!(record.events[0].args["text"], text);
    }
}

#[test]
fn binary_values_still_cross_as_explicit_byte_lists() {
    let record = output(b"[255,192,175,0]", "list<u8>");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!([255, 192, 175, 0])));
}
