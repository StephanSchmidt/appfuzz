use std::sync::Arc;

use appfuzz_core::{
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};

fn run(body: &str, plugin: bool) -> RunRecord {
    run_at(body, plugin, None)
}
fn run_at(body: &str, plugin: bool, now: Option<&str>) -> RunRecord {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-p1-sleep-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.wit"), "package test:sleep; world plugin { export run:func()->string; }").unwrap();
    std::fs::write(dir.join("app.witx"), "(module $host (@interface func (export \"ping\")))").unwrap();
    let declaration = if plugin {
        "[platform]\nname='sleep'\nabi='extism'\nwit='app.wit'"
    } else {
        "[platform]\nname='sleep'\nwitx=['app.witx']\nstart='_start'\nentry_wit='run:func();'\n[entry]\nexport='entry#run'"
    };
    let host = HostManifest::parse(declaration, &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("sleep.wasm")), &Default::default()).unwrap();
    manifest.host = Some(Arc::new(host));
    let export = if plugin { "run" } else { "_start" };
    let result = if plugin { "(result i32)" } else { "" };
    let success = if plugin { "(i32.const 0)" } else { "" };
    let wat = format!(
        r#"(module
        (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
        (import "wasi_snapshot_preview1" "clock_time_get" (func $now (param i32 i64 i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
        (import "wasi_snapshot_preview1" "fd_renumber" (func $renumber (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func $read (param $id i32) (result i64)
            (if (call $now (local.get $id) (i64.const 1) (i32.const 4096)) (then unreachable))
            (i64.load (i32.const 4096)))
        (func (export "{export}") {result} (local $before i64)
            {body} {success}))"#
    );
    let app = App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap();
    let mut spec = app.spec(app.export(if plugin { "run" } else { "entry#run" }).unwrap(), vec![], Plan::default(), 1);
    // Isolate timer advancement from CPU time and keep failing old runs short.
    spec.ns_per_fuel = 0.0;
    if let Some(now) = now {
        spec.now = now.into();
    }
    app.run(&spec)
}

fn timer(index: usize, userdata: u64, clock: u32, timeout: &str, absolute: bool) -> String {
    let at = index * 48;
    format!(
        "(i64.store (i32.const {at}) (i64.const {userdata}))
        (i32.store8 (i32.const {}) (i32.const 0))
        (i32.store (i32.const {}) (i32.const {clock}))
        (i64.store (i32.const {}) {timeout})
        (i32.store16 (i32.const {}) (i32.const {}))",
        at + 8,
        at + 16,
        at + 24,
        at + 40,
        u8::from(absolute)
    )
}

fn fd(index: usize, userdata: u64, descriptor: u32, write: bool) -> String {
    let at = index * 48;
    format!(
        "(i64.store (i32.const {at}) (i64.const {userdata}))
        (i32.store8 (i32.const {}) (i32.const {}))
        (i32.store (i32.const {}) (i32.const {descriptor}))",
        at + 8,
        if write { 2 } else { 1 },
        at + 16
    )
}

fn poll(n: usize, expected_count: usize) -> String {
    format!(
        "(if (call $poll (i32.const 0) (i32.const 1024) (i32.const {n}) (i32.const 2048)) (then unreachable))
        (if (i32.ne (i32.load (i32.const 2048)) (i32.const {expected_count})) (then unreachable))"
    )
}

fn event(index: usize, userdata: u64, kind: u8) -> String {
    let at = 1024 + index * 32;
    format!(
        "(if (i64.ne (i64.load (i32.const {at})) (i64.const {userdata})) (then unreachable))
        (if (i32.load16_u (i32.const {})) (then unreachable))
        (if (i32.ne (i32.load8_u (i32.const {})) (i32.const {kind})) (then unreachable))",
        at + 8,
        at + 10
    )
}

fn ok(run: &RunRecord, sleep: u64) {
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.sleep_ns, sleep);
    assert!(run.events.is_empty());
}

#[test]
fn relative_timers_advance_virtual_time_for_modules_and_plugins() {
    for plugin in [false, true] {
        for clock in [0, 1] {
            let body = format!(
                "(local.set $before (call $read (i32.const {clock}))) {} {} {} (if (i64.lt_u (i64.sub (call $read (i32.const {clock})) (local.get $before)) (i64.const 1000000)) (then unreachable))",
                timer(0, 17, clock, "(i64.const 1000000)", false),
                poll(1, 1),
                event(0, 17, 0)
            );
            ok(&run(&body, plugin), 1_000_000);
        }
    }
}

#[test]
fn absolute_wall_and_monotonic_deadlines_use_the_virtual_clock() {
    for clock in [0, 1] {
        for future in [false, true] {
            let timeout = if future { format!("(i64.add (call $read (i32.const {clock})) (i64.const 1000000))") } else { "(i64.const 0)".into() };
            let body = format!("{} {} {}", timer(0, 99, clock, &timeout, true), poll(1, 1), event(0, 99, 0));
            ok(&run(&body, true), if future { 1_000_000 } else { 0 });
        }
    }
}

#[test]
fn multiple_timers_wait_for_the_earliest_and_return_all_ties_in_input_order() {
    let body = format!(
        "{} {} {} {} {} {}",
        timer(0, 70, 1, "(i64.const 2000000)", false),
        timer(1, 31, 0, "(i64.const 1000000)", false),
        timer(2, 42, 1, "(i64.const 1000000)", false),
        poll(3, 2),
        event(0, 31, 0),
        event(1, 42, 0)
    );
    ok(&run(&body, true), 1_000_000);
}

#[test]
fn ready_descriptors_win_over_future_timers_and_keep_duplicate_userdata() {
    let body = format!(
        "{} {} {} {} {} {} (if (i64.ne (i64.load (i32.const 1040)) (i64.const 1)) (then unreachable))",
        timer(0, 8, 1, "(i64.const 1000000)", false),
        fd(1, 8, 1, true),
        fd(2, 8, 0, false),
        poll(3, 2),
        event(0, 8, 2),
        event(1, 8, 1)
    );
    ok(&run(&body, true), 0);
}

#[test]
fn already_due_timers_and_ready_descriptors_preserve_input_order() {
    let body = format!(
        "{} {} {} (if (call $poll (i32.const 0) (i32.const 1024) (i32.const 3) (i32.const 2048)) (then unreachable)) {} (if (i32.eq (i32.load (i32.const 2048)) (i32.const 3)) (then {} {}) (else (if (i32.ne (i32.load (i32.const 2048)) (i32.const 2)) (then unreachable)) {}))",
        fd(0, 21, 2, true),
        timer(1, 22, 0, "(i64.const 0)", true),
        fd(2, 23, 0, false),
        event(0, 21, 2),
        event(1, 22, 0),
        event(2, 23, 1),
        event(1, 23, 1)
    );
    ok(&run(&body, true), 0);
}

#[test]
fn renumbered_and_closed_descriptors_use_the_sdk_table() {
    let body = format!(
        "(if (call $renumber (i32.const 1) (i32.const 2)) (then unreachable)) {} {} {} {} (if (call $close (i32.const 2)) (then unreachable)) (if (i32.ne (call $poll (i32.const 0) (i32.const 1024) (i32.const 2) (i32.const 2048)) (i32.const 8)) (then unreachable))",
        fd(0, 13, 2, true),
        timer(1, 14, 1, "(i64.const 1000000)", false),
        poll(2, 1),
        event(0, 13, 2)
    );
    ok(&run(&body, true), 0);
}

#[test]
fn invalid_subscriptions_do_not_advance_time() {
    for setup in
        [timer(0, 1, 9, "(i64.const 1000000)", true), "(i32.store8 (i32.const 8) (i32.const 99))".into(), "(i32.store16 (i32.const 40) (i32.const 2))".into()]
    {
        let body =
            format!("{setup} (if (i32.ne (call $poll (i32.const 0) (i32.const 1024) (i32.const 1) (i32.const 2048)) (i32.const 28)) (then unreachable))");
        ok(&run(&body, true), 0);
    }
}

#[test]
fn bad_descriptors_do_not_turn_into_timer_successes() {
    for descriptor in [fd(0, 1, 0, true), fd(0, 1, 1, false), fd(0, 1, 77, true)] {
        let body = format!(
            "{descriptor} {} (if (i32.ne (call $poll (i32.const 0) (i32.const 1024) (i32.const 2) (i32.const 2048)) (i32.const 8)) (then unreachable))",
            timer(1, 2, 1, "(i64.const 1000000)", false)
        );
        ok(&run(&body, true), 0);
    }
}

#[test]
fn empty_subscription_lists_return_invalid_even_with_invalid_pointers() {
    let body = "(if (i32.ne (call $poll (i32.const -1) (i32.const -1) (i32.const 0) (i32.const -1)) (i32.const 28)) (then unreachable))";
    ok(&run(body, true), 0);
}

#[test]
fn oversized_subscription_arrays_hit_the_sdk_quota_before_allocation() {
    let body = "(if (i32.ne (call $poll (i32.const 0) (i32.const 1024) (i32.const -1) (i32.const 2048)) (i32.const 48)) (then unreachable))";
    ok(&run(body, true), 0);
}

#[test]
fn invalid_poll_memory_traps_instead_of_panicking_or_succeeding() {
    let setup = timer(0, 4, 1, "(i64.const 0)", false);
    for call in [
        "(call $poll (i32.const -8) (i32.const 1024) (i32.const 1) (i32.const 2048))",
        "(call $poll (i32.const 1) (i32.const 1024) (i32.const 1) (i32.const 2048))",
        "(call $poll (i32.const 0) (i32.const 65528) (i32.const 1) (i32.const 2048))",
        "(call $poll (i32.const 0) (i32.const 1025) (i32.const 1) (i32.const 2048))",
        "(call $poll (i32.const 0) (i32.const 1024) (i32.const 1) (i32.const 65535))",
    ] {
        let run = run(&format!("{setup} (drop {call})"), true);
        assert_eq!(run.outcome.kind, OutcomeKind::Trap, "{call}: {:?}", run.outcome);
        assert!(!run.capture_limited);
    }
}

#[test]
fn repeated_polls_accumulate_only_the_elapsed_timer_and_keep_the_inputs() {
    let setup = format!("{} {}", timer(0, 50, 1, "(i64.const 1000000)", false), timer(1, 51, 1, "(i64.const 2000000)", false));
    let call = format!("{} {} (if (i64.ne (i64.load (i32.const 48)) (i64.const 51)) (then unreachable))", poll(2, 1), event(0, 50, 0));
    ok(&run(&format!("{setup} {call} {call}"), true), 2_000_000);
}

#[test]
fn a_guest_reusing_the_subscription_buffer_for_events_is_supported() {
    let setup = format!("{} {}", timer(0, 50, 1, "(i64.const 0)", false), timer(1, 51, 1, "(i64.const 0)", false));
    let body = format!(
        "{setup} (if (call $poll (i32.const 0) (i32.const 0) (i32.const 2) (i32.const 2048)) (then unreachable)) (if (i32.ne (i32.load (i32.const 2048)) (i32.const 2)) (then unreachable)) (if (i64.ne (i64.load (i32.const 0)) (i64.const 50)) (then unreachable)) (if (i64.ne (i64.load (i32.const 32)) (i64.const 51)) (then unreachable))"
    );
    ok(&run(&body, true), 0);
}

#[test]
fn wall_reads_outside_preview1_range_return_overflow_without_rewriting_memory() {
    let errno = u16::from(wasmtime_wasi::p1::types::Errno::Overflow);
    let body = format!(
        "(i64.store (i32.const 4096) (i64.const 77)) (if (i32.ne (call $now (i32.const 0) (i64.const 1) (i32.const 4096)) (i32.const {errno})) (then unreachable)) (if (i64.ne (i64.load (i32.const 4096)) (i64.const 77)) (then unreachable)) (drop (call $read (i32.const 1)))"
    );
    for plugin in [false, true] {
        for now in ["0001-01-01", "1969-12-31T23:59:59", "3000-01-01", "9999-12-31"] {
            let record = run_at(&body, plugin, Some(now));
            ok(&record, 0);
            assert_eq!(record.totals.clock_reads, 2);
        }
    }
}

#[test]
fn relative_wall_timers_can_cross_the_epoch_for_modules_and_plugins() {
    let body = format!(
        "{} {} {} (if (i64.ne (call $read (i32.const 0)) (i64.const 1000)) (then unreachable))",
        timer(0, 17, 0, "(i64.const 1000000000)", false),
        poll(1, 1),
        event(0, 17, 0)
    );
    for plugin in [false, true] {
        ok(&run_at(&body, plugin, Some("1969-12-31T23:59:59")), 1_000_000_000);
    }
}

#[test]
fn absolute_wall_timers_keep_signed_origins_and_waits_beyond_u64() {
    use appfuzz_core::natural::Natural;
    let errno = u16::from(wasmtime_wasi::p1::types::Errno::Overflow);
    let body = format!(
        "(if (i32.ne (call $now (i32.const 0) (i64.const 1) (i32.const 4096)) (i32.const {errno})) (then unreachable)) {} {} {} (if (i64.ne (call $read (i32.const 0)) (i64.const 1000)) (then unreachable))",
        timer(0, 17, 0, "(i64.const 0)", true),
        poll(1, 1),
        event(0, 17, 0)
    );
    for plugin in [false, true] {
        for now in ["0001-01-01", "1969-12-31T23:59:59"] {
            let record = run_at(&body, plugin, Some(now));
            assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{now}: {:?}", record.outcome);
            let expected = Natural::from(appfuzz_core::wasi::parse_datetime(now).unwrap().unsigned_abs()) * 1_000_000_000 - Natural::from(1000u64);
            assert_eq!(record.totals.sleep_ns, expected);
            assert_eq!(record.totals.clock_reads, 2);
        }
    }
}

#[test]
fn absolute_preview1_timestamps_before_a_future_wall_date_are_already_due() {
    let body = format!("{} {} {}", timer(0, 17, 0, "(i64.const -1)", true), poll(1, 1), event(0, 17, 0));
    for plugin in [false, true] {
        ok(&run_at(&body, plugin, Some("3000-01-01")), 0);
    }
}

#[test]
fn preview1_clock_ids_keep_native_errors_without_advancing_time() {
    let badf = u16::from(wasmtime_wasi::p1::types::Errno::Badf);
    let inval = u16::from(wasmtime_wasi::p1::types::Errno::Inval);
    let body = format!(
        "(if (i32.ne (call $now (i32.const 2) (i64.const 1) (i32.const 4096)) (i32.const {badf})) (then unreachable)) (if (i32.ne (call $now (i32.const 3) (i64.const 1) (i32.const 4096)) (i32.const {badf})) (then unreachable)) (if (i32.ne (call $now (i32.const -1) (i64.const 1) (i32.const -1)) (i32.const {inval})) (then unreachable))"
    );
    for plugin in [false, true] {
        let record = run(&body, plugin);
        ok(&record, 0);
        assert_eq!(record.totals.clock_reads, 0);
    }
}

#[test]
fn preview1_clock_bad_result_pointers_trap_for_both_clock_kinds() {
    for plugin in [false, true] {
        for id in [0, 1] {
            let record = run(&format!("(drop (call $now (i32.const {id}) (i64.const 1) (i32.const -1)))"), plugin);
            assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{:?}", record.outcome);
        }
    }
}
