use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::json;

const KERNEL_MEMORY: u64 = 16 * 65_536;

// Kernel ABI semantics: https://github.com/extism/extism/blob/main/kernel/src/lib.rs
fn app(body: &str) -> App {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-kernel-api-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:kernel; world plugin { export run: func(input: string) -> string; }").unwrap();
    let host = HostManifest::parse("[platform]\nname = 'kernel'\nabi = 'extism'\nwit = 'plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("kernel.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let wat = format!(
        r#"(module
      (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
      (import "extism:host/env" "free" (func $free (param i64)))
      (import "extism:host/env" "length" (func $length (param i64) (result i64)))
      (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
      (import "extism:host/env" "store_u64" (func $write64 (param i64 i64)))
      (import "extism:host/env" "load_u64" (func $load64 (param i64) (result i64)))
      (import "extism:host/env" "input_offset" (func $input_offset (result i64)))
      (import "extism:host/env" "input_length" (func $input_length (result i64)))
      (import "extism:host/env" "input_set" (func $input (param i64 i64)))
      (import "extism:host/env" "input_load_u8" (func $read (param i64) (result i32)))
      (import "extism:host/env" "input_load_u64" (func $read64 (param i64) (result i64)))
      (import "extism:host/env" "output_set" (func $output (param i64 i64)))
      (import "extism:host/env" "output_offset" (func $output_offset (result i64)))
      (import "extism:host/env" "output_length" (func $output_length (result i64)))
      (import "extism:host/env" "error_set" (func $error (param i64)))
      (import "extism:host/env" "error_get" (func $get_error (result i64)))
      (import "extism:host/env" "reset" (func $reset))
      (import "extism:host/env" "var_set" (func $set_var (param i64 i64)))
      (import "extism:host/env" "var_get" (func $get_var (param i64) (result i64)))
      (import "extism:host/env" "log_info" (func $log (param i64)))
      (func $abc (result i64) (local $p i64)
        (local.set $p (call $alloc (i64.const 3)))
        (call $write (local.get $p) (i32.const 97))
        (call $write (i64.add (local.get $p) (i64.const 1)) (i32.const 98))
        (call $write (i64.add (local.get $p) (i64.const 2)) (i32.const 99))
        (local.get $p))
      (func (export "run") (result i32) (local $block i64) (local $old i64)
        {body} (i32.const 0)))"#
    );
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn output_getters_start_at_zero() {
    let app = app(r#"(if (i64.ne (call $output_length) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $output_offset) (i64.const 0)) (then unreachable))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn output_getters_preserve_slice_offsets_and_explicit_empty_output() {
    let app = app(r#"(local.set $block (i64.add (call $input_offset) (i64.const 1)))
        (call $output (local.get $block) (i64.const 2))
        (if (i64.ne (call $output_offset) (local.get $block)) (then unreachable))
        (if (i64.ne (call $output_length) (i64.const 2)) (then unreachable))
        (call $output (i64.const 0) (i64.const 0))
        (if (i64.ne (call $output_offset) (local.get $block)) (then unreachable))
        (if (i64.ne (call $output_length) (i64.const 2)) (then unreachable))
        (call $output (local.get $block) (i64.const 0))
        (if (i64.ne (call $output_offset) (local.get $block)) (then unreachable))
        (if (i64.ne (call $output_length) (i64.const 0)) (then unreachable))
        (call $output (local.get $block) (i64.const 2))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("bc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn input_set_uses_the_live_block_without_allocating_or_freeing_the_old_input() {
    let app = app(r#"(local.set $old (call $input_offset))
        (local.set $block (call $alloc (i64.const 8)))
        (call $write64 (local.get $block) (i64.const 0x6867666564636261))
        (call $input (local.get $block) (i64.const 8))
        (if (i64.ne (call $input_offset) (local.get $block)) (then unreachable))
        (if (i64.ne (call $input_length) (i64.const 8)) (then unreachable))
        (if (i64.ne (call $length (local.get $old)) (i64.const 3)) (then unreachable))
        (if (i64.ne (call $read64 (i64.const 0)) (i64.const 0x6867666564636261)) (then unreachable))
        (call $write (local.get $block) (i32.const 90))
        (if (i32.ne (call $read (i64.const 0)) (i32.const 90)) (then unreachable))
        (call $output (call $input_offset) (call $input_length))"#);
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1);
    spec.memory = KERNEL_MEMORY;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("Zbcdefgh")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn freeing_a_replacement_input_clears_its_length_and_retains_its_offset() {
    let app = app(r#"(local.set $old (call $input_offset))
        (local.set $block (call $alloc (i64.const 8)))
        (call $input (local.get $block) (i64.const 8))
        (call $free (local.get $block))
        (if (i64.ne (call $input_offset) (local.get $block)) (then unreachable))
        (if (i64.ne (call $input_length) (i64.const 0)) (then unreachable))
        (call $output (local.get $old) (call $length (local.get $old)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn a_null_input_setter_preserves_the_previous_input() {
    let app = app(r#"(local.set $old (call $input_offset))
        (call $input (i64.const 0) (i64.const 0))
        (if (i64.ne (call $input_offset) (local.get $old)) (then unreachable))
        (if (i64.ne (call $input_length) (i64.const 3)) (then unreachable))
        (call $output (local.get $old) (call $length (local.get $old)))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn null_setters_ignore_nonzero_and_wrapped_lengths_without_trapping() {
    let mut body = String::from("(local.set $old (call $input_offset)) (call $output (local.get $old) (i64.const 3))");
    for length in [1, 8, -1] {
        body.push_str(&format!(
            r#"(call $input (i64.const 0) (i64.const {length}))
            (call $output (i64.const 0) (i64.const {length}))
            (if (i64.ne (call $input_offset) (local.get $old)) (then unreachable))
            (if (i64.ne (call $input_length) (i64.const 3)) (then unreachable))
            (if (i64.ne (call $output_offset) (local.get $old)) (then unreachable))
            (if (i64.ne (call $output_length) (i64.const 3)) (then unreachable))"#
        ));
    }
    let app = app(&body);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn out_of_bounds_byte_reads_return_zero_without_changing_input() {
    let app = app(r#"(if (i32.ne (call $read (i64.const 3)) (i32.const 0)) (then unreachable))
        (if (i32.ne (call $read (i64.const -1)) (i32.const 0)) (then unreachable))
        (if (i32.ne (call $read (i64.const 0)) (i32.const 97)) (then unreachable))
        (call $output (call $input_offset) (call $input_length))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn partial_u64_input_reads_return_zero_and_complete_reads_keep_all_bytes() {
    let app = app(r#"(if (i64.ne (call $read64 (i64.const 0)) (i64.const 0x6867666564636261)) (then unreachable))
        (if (i64.ne (call $read64 (i64.const 1)) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $read64 (i64.const 8)) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $read64 (i64.const 9223372036854775807)) (i64.const 0)) (then unreachable))
        (call $output (call $input_offset) (call $input_length))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abcdefgh")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abcdefgh")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn empty_and_short_inputs_return_zero_for_rejected_reads() {
    let app = app(r#"(if (i64.ne (call $read64 (i64.const 0)) (i64.const 0)) (then unreachable))
        (if (i32.ne (call $read (call $input_length)) (i32.const 0)) (then unreachable))"#);
    for input in ["", "abc"] {
        let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!(input)], Plan::default(), 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{input:?}: {:?}", run.outcome);
        assert_eq!(run.result, Some(json!("")));
        assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
    }
}

#[test]
fn reads_after_freeing_input_return_zero() {
    let app = app(r#"(call $free (call $input_offset))
        (if (i32.ne (call $read (i64.const 0)) (i32.const 0)) (then unreachable))
        (if (i64.ne (call $read64 (i64.const 0)) (i64.const 0)) (then unreachable))"#);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abcdefgh")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}

#[test]
fn reset_clears_allocations_and_metadata_but_preserves_variables_and_logs() {
    let app = app(r#"(local.set $old (call $input_offset))
        (call $output (local.get $old) (i64.const 3))
        (call $error (local.get $old))
        (local.set $block (call $alloc (i64.const 1)))
        (call $write (local.get $block) (i32.const 107))
        (call $set_var (local.get $block) (call $abc))
        (call $log (call $abc))
        (call $reset)
        (if (i64.ne (call $input_offset) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $input_length) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $output_offset) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $output_length) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $get_error) (i64.const 0)) (then unreachable))
        (if (i64.ne (call $length (local.get $old)) (i64.const 0)) (then unreachable))
        (local.set $block (call $alloc (i64.const 8)))
        (if (i64.eqz (local.get $block)) (then unreachable))
        (if (i64.ne (call $load64 (local.get $block)) (i64.const 0)) (then unreachable))
        (call $free (local.get $block))
        (local.set $block (call $alloc (i64.const 1)))
        (call $write (local.get $block) (i32.const 107))
        (call $output (call $get_var (local.get $block)) (i64.const 3))"#);
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1);
    spec.memory = KERNEL_MEMORY;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("abc")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
    assert!(run.stderr.contains("abc"), "{}", run.stderr);
}

#[test]
fn reset_preserves_the_peak_even_when_no_more_blocks_are_allocated() {
    let app = app("(call $reset)");
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![json!("abc")], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!("")));
    assert_eq!(run.totals.peak_memory, KERNEL_MEMORY);
}
