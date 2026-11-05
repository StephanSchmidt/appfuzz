use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;

const PAGE: u64 = 65_536;
const KERNEL_MEMORY: u64 = 16 * PAGE;

// Ownership contracts: https://github.com/extism/extism/blob/main/runtime/src/pdk.rs
fn run(body: &str, memory: u64) -> RunRecord {
    run_with_start(body, memory, "")
}

fn run_with_start(body: &str, memory: u64, start: &str) -> RunRecord {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-ownership-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:ownership; world plugin { export run: func() -> string; }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'ownership'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("ownership.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let logs: String = ["trace", "debug", "info", "warn", "error"]
        .into_iter()
        .map(|level| format!(r#"(import "extism:host/env" "log_{level}" (func $log_{level} (param i64)))"#))
        .collect();
    let wat = format!(
        r#"(module
      (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
      (import "extism:host/env" "free" (func $free (param i64)))
      (import "extism:host/env" "length" (func $length (param i64) (result i64)))
      (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
      (import "extism:host/env" "load_u8" (func $read (param i64) (result i32)))
      (import "extism:host/env" "output_set" (func $output (param i64 i64)))
      (import "extism:host/env" "var_set" (func $set_var (param i64 i64)))
      (import "extism:host/env" "var_get" (func $get_var (param i64) (result i64)))
      (import "extism:host/env" "config_get" (func $get_config (param i64) (result i64)))
      {logs}
      (func $key (result i64) (local $p i64)
        (local.set $p (call $alloc (i64.const 1)))
        (call $write (local.get $p) (i32.const 107))
        (local.get $p))
      (func $value (result i64) (local $p i64)
        (local.set $p (call $alloc (i64.const 3)))
        (call $write (local.get $p) (i32.const 97))
        (call $write (i64.add (local.get $p) (i64.const 1)) (i32.const 98))
        (call $write (i64.add (local.get $p) (i64.const 2)) (i32.const 99))
        (local.get $p))
      (func $init (local $key i64) (local $value i64) {start}) (start $init)
      (func (export "run") (result i32)
        (local $key i64) (local $value i64) (local $other i64)
        {body} (i32.const 0)))"#
    );
    let app = App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap();
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    // These fixtures test ownership and the variable-store quota, not linear-memory OOM.
    spec.memory = KERNEL_MEMORY + memory.div_ceil(PAGE) * PAGE + PAGE;
    app.run(&spec)
}

const STORE: &str = r#"(local.set $key (call $key))
    (local.set $value (call $value))
    (call $set_var (local.get $key) (local.get $value))"#;

#[test]
fn setting_a_variable_consumes_both_handles_and_preserves_the_value() {
    let run = run(
        &format!(
            r#"{STORE}
            (if (i64.ne (call $length (local.get $key)) (i64.const 0)) (then unreachable))
            (if (i64.ne (call $length (local.get $value)) (i64.const 0)) (then unreachable))
            (call $output (call $get_var (call $key)) (i64.const 3))"#
        ),
        4,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn getting_a_variable_releases_its_key_before_allocating_the_result() {
    let run = run_with_start(
        r#"(local.set $other (call $key))
            (call $output (call $get_var (call $key)) (i64.const 3))
            (if (i64.ne (call $length (local.get $other)) (i64.const 1)) (then unreachable))"#,
        4,
        STORE,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn getting_a_missing_variable_consumes_the_key() {
    let run = run(
        r#"(local.set $key (call $key))
        (if (i64.ne (call $get_var (local.get $key)) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $length (local.get $key)) (i64.const 0)) (then unreachable))
        (call $output (call $value) (i64.const 3))"#,
        3,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn deleting_a_variable_consumes_the_key_and_removes_the_value() {
    let run = run_with_start(
        r#"(local.set $key (call $key))
            (call $set_var (local.get $key) (i64.const 0))
            (if (i64.ne (call $length (local.get $key)) (i64.const 0)) (then unreachable))
            (if (i64.ne (call $get_var (call $key)) (i64.const 0)) (then unreachable))"#,
        4,
        STORE,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn getting_missing_configuration_consumes_the_key() {
    let run = run(
        r#"(local.set $key (call $key))
        (if (i64.ne (call $get_config (local.get $key)) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $length (local.get $key)) (i64.const 0)) (then unreachable))
        (call $output (call $value) (i64.const 3))"#,
        3,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn every_log_level_consumes_its_message_without_losing_the_log() {
    let body: String = ["trace", "debug", "info", "warn", "error"]
        .into_iter()
        .map(|level| {
            format!(
                r#"(local.set $value (call $value))
                (call $log_{level} (local.get $value))
                (if (i64.ne (call $length (local.get $value)) (i64.const 0)) (then unreachable))"#
            )
        })
        .collect();
    let run = run(&body, 3);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
    for level in ["trace", "debug", "info", "warn", "error"] {
        assert!(run.stderr.contains(&format!("[{level}] abc")), "{}", run.stderr);
    }
}

#[test]
fn a_single_variable_cannot_exceed_the_sdk_default_store_limit() {
    let run = run(r#"(call $set_var (call $key) (call $alloc (i64.const 1048576)))"#, 2 * 1024 * 1024);
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains("Variable store is full"));
}

#[test]
fn the_variable_limit_applies_to_the_whole_store() {
    let run = run(
        r#"(call $set_var (call $key) (call $alloc (i64.const 524288)))
        (local.set $key (call $key))
        (call $write (local.get $key) (i32.const 122))
        (call $set_var (local.get $key) (call $alloc (i64.const 524288)))"#,
        1024 * 1024,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{:?}", run.outcome);
    assert!(run.outcome.message.unwrap().contains("Variable store is full"));
}

#[test]
fn deleting_a_variable_releases_space_in_the_store() {
    let run = run(
        r#"(call $set_var (call $key) (call $alloc (i64.const 700000)))
        (call $set_var (call $key) (i64.const 0))
        (call $set_var (call $key) (call $alloc (i64.const 700000)))
        (call $output (call $get_var (call $key)) (i64.const 0))"#,
        1024 * 1024,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY + 10 * PAGE);
}

fn key_bytes(bytes: &[u8]) -> String {
    let writes: String =
        bytes.iter().enumerate().map(|(i, byte)| format!("(call $write (i64.add (local.get $key) (i64.const {i})) (i32.const {byte}))")).collect();
    format!("(local.set $key (call $alloc (i64.const {}))) {writes}", bytes.len())
}

fn invalid_keys(operation: &str) {
    // Invalid leading byte, truncated sequence, overlong encoding, surrogate.
    for bytes in [&[0xff][..], &[0xc3], &[0xc0, 0xaf], &[0xed, 0xa0, 0x80]] {
        let run = run(&format!("{} {operation}", key_bytes(bytes)), 64);
        assert_eq!(run.outcome.kind, OutcomeKind::Trap, "key={bytes:x?}, operation={operation}: {:?}", run.outcome);
        assert!(run.outcome.message.as_deref().unwrap_or_default().contains("utf-8"), "{:?}", run.outcome);
    }
}

#[test]
fn getting_a_variable_rejects_invalid_utf8_keys() {
    invalid_keys("(drop (call $get_var (local.get $key)))");
}

#[test]
fn setting_and_deleting_variables_reject_invalid_utf8_keys() {
    invalid_keys("(call $set_var (local.get $key) (call $value))");
    invalid_keys("(call $set_var (local.get $key) (i64.const 0))");
}

#[test]
fn getting_configuration_rejects_invalid_utf8_keys() {
    invalid_keys("(drop (call $get_config (local.get $key)))");
}

#[test]
fn a_null_key_is_the_valid_empty_string() {
    let run = run(
        r#"(call $set_var (i64.const 0) (call $value))
        (local.set $value (call $get_var (i64.const 0)))
        (call $output (local.get $value) (i64.const 3))
        (if (i64.ne (call $get_config (i64.const 0)) (i64.const 0)) (then unreachable))
        (call $set_var (i64.const 0) (i64.const 0))
        (if (i64.ne (call $get_var (i64.const 0)) (i64.const 0)) (then unreachable))"#,
        3,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
}

#[test]
fn variable_values_are_opaque_bytes() {
    let run = run(
        r#"(local.set $value (call $value))
        (call $write (local.get $value) (i32.const 255))
        (call $set_var (call $key) (local.get $value))
        (local.set $value (call $get_var (call $key)))
        (if (i64.ne (call $length (local.get $value)) (i64.const 3)) (then unreachable))
        (if (i32.ne (call $read (local.get $value)) (i32.const 255)) (then unreachable))"#,
        4,
    );
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
}

#[test]
fn variable_keys_accept_unicode_and_embedded_nul() {
    for key in ["é", "\0", "💡"] {
        let key = key_bytes(key.as_bytes());
        let run = run(&format!("{key} (call $set_var (local.get $key) (call $value)) {key} (call $output (call $get_var (local.get $key)) (i64.const 3))"), 7);
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        assert_eq!(run.result, Some(json!("abc")));
    }
}
