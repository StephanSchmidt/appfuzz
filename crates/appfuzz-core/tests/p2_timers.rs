use appfuzz_core::{
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;

fn app(body: &str, version: &str) -> App {
    let mut resolve = wit_parser::Resolve::new();
    resolve
        .push_str(
            "io.wit",
            &format!(
                r#"package wasi:io@{version};
        interface poll {{ resource pollable {{ ready:func()->bool; block:func(); }} poll:func(in:list<borrow<pollable>>)->list<u32>; }}
        interface streams {{ use poll.{{pollable}}; resource output-stream {{ subscribe:func()->pollable; }} }}"#
            ),
        )
        .unwrap();
    resolve
        .push_str(
            "clock.wit",
            &format!(
                r#"package wasi:clocks@{version}; interface monotonic-clock {{
        use wasi:io/poll@{version}.{{pollable}};
        now:func()->u64; subscribe-duration:func(when:u64)->pollable; subscribe-instant:func(when:u64)->pollable;
    }}"#
            ),
        )
        .unwrap();
    resolve
        .push_str(
            "cli.wit",
            &format!(
                r#"package wasi:cli@{version}; interface stdout {{ use wasi:io/streams@{version}.{{output-stream}}; get-stdout:func()->output-stream; }}"#
            ),
        )
        .unwrap();
    let pkg = resolve
        .push_str(
            "app.wit",
            &format!(
                r#"package test:timers; world app {{
        import wasi:io/poll@{version}; import wasi:io/streams@{version};
        import wasi:clocks/monotonic-clock@{version}; import wasi:cli/stdout@{version};
        export run:func()->u64;
    }}"#
            ),
        )
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(format!(r#"(module
        (import "wasi:clocks/monotonic-clock@{version}" "now" (func $now (result i64)))
        (import "wasi:clocks/monotonic-clock@{version}" "subscribe-duration" (func $sleep (param i64) (result i32)))
        (import "wasi:clocks/monotonic-clock@{version}" "subscribe-instant" (func $until (param i64) (result i32)))
        (import "wasi:io/poll@{version}" "[method]pollable.ready" (func $ready (param i32) (result i32)))
        (import "wasi:io/poll@{version}" "[method]pollable.block" (func $block (param i32)))
        (import "wasi:io/poll@{version}" "[resource-drop]pollable" (func $drop (param i32)))
        (import "wasi:io/poll@{version}" "poll" (func $poll (param i32 i32 i32)))
        (import "wasi:cli/stdout@{version}" "get-stdout" (func $stdout (result i32)))
        (import "wasi:io/streams@{version}" "[method]output-stream.subscribe" (func $subscribe (param i32) (result i32)))
        (memory (export "memory") 1)
        (global $heap (mut i32) (i32.const 4096))
        (func (export "cabi_realloc") (param i32 i32 i32) (param $n i32) (result i32) (local $p i32)
            (local.set $p (global.get $heap)) (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
        (func $mask (param $p i32) (param $n i32) (result i64) (local $i i32) (local $mask i64)
            (if (local.get $n) (then (loop $again
                (local.set $mask (i64.or (local.get $mask) (i64.shl (i64.const 1) (i64.extend_i32_u (i32.load (i32.add (local.get $p) (i32.mul (local.get $i) (i32.const 4))))))))
                (local.set $i (i32.add (local.get $i) (i32.const 1))) (br_if $again (i32.lt_u (local.get $i) (local.get $n))))))
            (local.get $mask))
        (func (export "run") (result i64) (local $a i32) (local $b i32) (local $c i32) (local $i i32) (local $before i64)
            {body}))"#)).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("timers.wasm")), bytes).unwrap()
}

fn run(body: &str) -> RunRecord {
    run_version(body, "0.2.12", 0.0)
}

fn run_version(body: &str, version: &str, rate: f64) -> RunRecord {
    let app = app(body, version);
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.ns_per_fuel = rate;
    app.run(&spec)
}

fn check(run: &RunRecord, sleep: u64, value: u64) {
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.sleep_ns, sleep);
    assert_eq!(run.result, Some(json!(value)));
}

#[test]
fn unused_and_dropped_timers_do_not_advance_time() {
    for drop in ["", "(call $drop (local.get $a))"] {
        check(
            &run(&format!("(local.set $before (call $now)) (local.set $a (call $sleep (i64.const 1000000))) {drop} (i64.sub (call $now) (local.get $before))")),
            0,
            1_000,
        );
    }
}

#[test]
fn readiness_checks_are_nonblocking() {
    check(&run("(local.set $a (call $sleep (i64.const 1000000))) (i64.extend_i32_u (call $ready (local.get $a)))"), 0, 0);
}

#[test]
fn blocking_overlapping_timers_waits_only_for_the_remaining_time() {
    check(
        &run(r#"(local.set $a (call $sleep (i64.const 1000000)))
        (local.set $b (call $sleep (i64.const 2000000)))
        (call $block (local.get $a))
        (if (call $ready (local.get $b)) (then unreachable))
        (call $block (local.get $b))
        (call $block (local.get $a)) (call $block (local.get $b))
        (i64.extend_i32_u (call $ready (local.get $b)))"#),
        2_000_000,
        1,
    );
}

#[test]
fn polling_waits_for_the_earliest_selected_timer_and_returns_duplicate_positions() {
    check(
        &run(r#"(local.set $a (call $sleep (i64.const 2000000)))
        (local.set $b (call $sleep (i64.const 1000000)))
        (local.set $c (call $sleep (i64.const 1000000)))
        (i32.store (i32.const 0) (local.get $a)) (i32.store (i32.const 4) (local.get $b))
        (i32.store (i32.const 8) (local.get $c)) (i32.store (i32.const 12) (local.get $b))
        (call $poll (i32.const 0) (i32.const 4) (i32.const 1024))
        (if (i32.ne (i32.load (i32.const 1028)) (i32.const 3)) (then unreachable))
        (call $mask (i32.load (i32.const 1024)) (i32.load (i32.const 1028)))"#),
        1_000_000,
        14,
    );
}

#[test]
fn unselected_timers_do_not_change_which_deadline_a_poll_waits_for() {
    check(
        &run(r#"(local.set $a (call $sleep (i64.const 1000)))
        (local.set $b (call $sleep (i64.const 1000000)))
        (i32.store (i32.const 0) (local.get $b))
        (call $poll (i32.const 0) (i32.const 1) (i32.const 1024))
        (i64.extend_i32_u (call $ready (local.get $a)))"#),
        1_000_000,
        1,
    );
}

#[test]
fn ready_output_does_not_wait_for_a_future_timer() {
    check(
        &run(r#"(local.set $a (call $sleep (i64.const 1000000)))
        (local.set $b (call $subscribe (call $stdout)))
        (i32.store (i32.const 0) (local.get $a)) (i32.store (i32.const 4) (local.get $b))
        (call $poll (i32.const 0) (i32.const 2) (i32.const 1024))
        (call $mask (i32.load (i32.const 1024)) (i32.load (i32.const 1028)))"#),
        0,
        2,
    );
}

#[test]
fn dropped_timer_metadata_does_not_affect_reused_resource_slots() {
    check(
        &run(r#"(local.set $a (call $sleep (i64.const 1000000))) (call $drop (local.get $a))
        (local.set $b (call $subscribe (call $stdout))) (call $block (local.get $b))
        (local.set $c (call $sleep (i64.const 2000000))) (call $block (local.get $c))
        (i64.extend_i32_u (call $ready (local.get $b)))"#),
        2_000_000,
        1,
    );
}

#[test]
fn past_deadlines_are_ready_without_a_wait() {
    check(&run("(local.set $a (call $until (i64.const 0))) (call $block (local.get $a)) (i64.extend_i32_u (call $ready (local.get $a)))"), 0, 1);
}

#[test]
fn absolute_future_deadlines_wait_only_when_blocked() {
    check(
        &run(r#"(local.set $before (call $now))
        (local.set $a (call $until (i64.add (local.get $before) (i64.const 1000000))))
        (if (call $ready (local.get $a)) (then unreachable))
        (call $block (local.get $a)) (i64.sub (call $now) (local.get $before))"#),
        1_000_000,
        1_001_000,
    );
}

#[test]
fn an_already_ready_timer_returns_without_waiting_for_other_timers() {
    check(
        &run(r#"(local.set $a (call $sleep (i64.const 1000000)))
        (local.set $b (call $sleep (i64.const 0)))
        (i32.store (i32.const 0) (local.get $a)) (i32.store (i32.const 4) (local.get $b))
        (call $poll (i32.const 0) (i32.const 2) (i32.const 1024))
        (call $mask (i32.load (i32.const 1024)) (i32.load (i32.const 1028)))"#),
        0,
        2,
    );
}

#[test]
fn polling_without_any_timer_keeps_native_readiness() {
    check(
        &run(r#"(local.set $a (call $subscribe (call $stdout)))
        (i32.store (i32.const 0) (local.get $a))
        (call $poll (i32.const 0) (i32.const 1) (i32.const 1024))
        (call $mask (i32.load (i32.const 1024)) (i32.load (i32.const 1028)))"#),
        0,
        1,
    );
}

#[test]
fn guest_work_can_make_a_timer_ready_without_sleeping() {
    let body = r#"(local.set $a (call $until (i64.add (call $now) (i64.const 1000000))))
        (loop $work (local.set $i (i32.add (local.get $i) (i32.const 1))) (br_if $work (i32.lt_u (local.get $i) (i32.const 10000))))
        (call $block (local.get $a)) (i64.extend_i32_u (call $ready (local.get $a)))"#;
    check(&run_version(body, "0.2.12", 100.0), 0, 1);
}

#[test]
fn older_wasi_versions_preserve_nonblocking_readiness() {
    check(&run_version("(local.set $a (call $sleep (i64.const 1000000))) (i64.extend_i32_u (call $ready (local.get $a)))", "0.2.9", 0.0), 0, 0);
}

#[test]
fn invalid_empty_poll_and_dropped_handles_still_trap() {
    for body in [
        "(call $poll (i32.const 0) (i32.const 0) (i32.const 1024)) (i64.const 0)",
        "(local.set $a (call $sleep (i64.const 0))) (call $drop (local.get $a)) (i64.extend_i32_u (call $ready (local.get $a)))",
    ] {
        let result = run(body);
        assert_eq!(result.outcome.kind, OutcomeKind::Trap, "{:?}", result.outcome);
    }
}

#[test]
fn relative_timers_keep_exact_waits_after_the_monotonic_abi_saturates() {
    let record = run(r#"(local.set $a (call $sleep (i64.const -1)))
        (call $block (local.get $a)) (call $drop (local.get $a))
        (local.set $b (call $sleep (i64.const 123)))
        (if (call $ready (local.get $b)) (then unreachable))
        (call $block (local.get $b)) (call $now)"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.totals.sleep_ns, u128::from(u64::MAX) + 123);
    assert_eq!(record.totals.virtual_ns, u128::from(u64::MAX) + 123 + 1000);
    assert_eq!(record.result, Some(json!(u64::MAX)));
}
