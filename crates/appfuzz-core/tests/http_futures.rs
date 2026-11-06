use appfuzz_core::{
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
    wasi_http::CLIENT_KEY,
};
use serde_json::json;

fn app(body: &str) -> App {
    app_with_clock(body, true)
}

fn app_with_clock(body: &str, clock: bool) -> App {
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/wit/http")).unwrap();
    let pkg = resolve
        .push_str(
            "test.wit",
            &format!(
                r#"package test:futures; world app {{
        import wasi:http/types@0.2.12;
        import wasi:http/outgoing-handler@0.2.12;
        import wasi:io/poll@0.2.12;
        import wasi:io/streams@0.2.12;
        import wasi:cli/stdout@0.2.12;
        {}
        export run: func() -> u64;
    }}"#,
                if clock { "import wasi:clocks/monotonic-clock@0.2.12;" } else { "" }
            ),
        )
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let wat = format!(
        r#"(module
        (import "wasi:http/types@0.2.12" "[constructor]fields" (func $fields (result i32)))
        (import "wasi:http/types@0.2.12" "[constructor]outgoing-request" (func $request (param i32) (result i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-request.set-authority" (func $authority (param i32 i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.2.12" "[method]future-incoming-response.subscribe" (func $subscribe (param i32) (result i32)))
        (import "wasi:http/types@0.2.12" "[method]future-incoming-response.get" (func $get (param i32 i32)))
        (import "wasi:http/types@0.2.12" "[resource-drop]future-incoming-response" (func $drop-future (param i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-request.body" (func $body (param i32 i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-body.write" (func $write-body (param i32 i32)))
        (import "wasi:http/types@0.2.12" "[static]outgoing-body.finish" (func $finish (param i32 i32 i32 i32)))
        (import "wasi:http/types@0.2.12" "[constructor]request-options" (func $options (result i32)))
        (import "wasi:http/types@0.2.12" "[method]request-options.set-first-byte-timeout" (func $timeout (param i32 i32 i64) (result i32)))
        (import "wasi:http/outgoing-handler@0.2.12" "handle" (func $send (param i32 i32 i32 i32)))
        (import "wasi:io/poll@0.2.12" "[method]pollable.ready" (func $ready (param i32) (result i32)))
        (import "wasi:io/poll@0.2.12" "[method]pollable.block" (func $block (param i32)))
        (import "wasi:io/poll@0.2.12" "[resource-drop]pollable" (func $drop-poll (param i32)))
        (import "wasi:io/poll@0.2.12" "poll" (func $poll (param i32 i32 i32)))
        (import "wasi:cli/stdout@0.2.12" "get-stdout" (func $stdout (result i32)))
        (import "wasi:io/streams@0.2.12" "[method]output-stream.subscribe" (func $subscribe-stream (param i32) (result i32)))
        (import "wasi:io/streams@0.2.12" "[method]output-stream.blocking-write-and-flush" (func $write-stream (param i32 i32 i32 i32)))
        (import "wasi:io/streams@0.2.12" "[resource-drop]output-stream" (func $drop-stream (param i32)))
        (import "wasi:clocks/monotonic-clock@0.2.12" "now" (func $now (result i64)))
        (import "wasi:clocks/monotonic-clock@0.2.12" "subscribe-duration" (func $timer (param i64) (result i32)))
        (memory (export "memory") 1)
        (global $heap (mut i32) (i32.const 4096))
        (data (i32.const 0) "api.example")
        (data (i32.const 32) "hello")
        (func (export "cabi_realloc") (param i32 i32 i32) (param $n i32) (result i32) (local $p i32)
            (local.set $p (global.get $heap)) (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
        (func $new (result i32) (local $req i32)
            (local.set $req (call $request (call $fields)))
            (if (call $authority (local.get $req) (i32.const 1) (i32.const 0) (i32.const 11)) (then unreachable))
            (local.get $req))
        (func $start (result i32) (call $dispatch (call $new) (i32.const 0) (i32.const 0)))
        (func $dispatch (param $req i32) (param $some i32) (param $options i32) (result i32)
            (call $send (local.get $req) (local.get $some) (local.get $options) (i32.const 1024))
            (if (i32.load (i32.const 1024)) (then unreachable))
            (i32.load (i32.const 1032)))
        (func (export "run") (result i64) (local $a i32) (local $b i32) (local $p i32) (local $q i32) (local $body i32) (local $stream i32) (local $before i64)
            {body}))"#
    );
    let wat = wat.lines().filter(|line| clock || !line.contains("(import \"wasi:clocks/")).collect::<Vec<_>>().join("\n");
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("http-futures.wasm")), bytes).unwrap()
}

fn run(body: &str) -> RunRecord {
    let plan = Plan::parse(&format!(r#"{{"{CLIENT_KEY}": {{"return":{{"ok":{{"status":200,"headers":[],"body":"ok"}}}},"latency_ms":10}}}}"#)).unwrap();
    run_app(&app(body), plan, 0.0)
}

fn run_app(app: &App, plan: Plan, rate: f64) -> RunRecord {
    let mut spec = app.spec(app.export("run").unwrap(), vec![], plan, 1);
    spec.ns_per_fuel = rate;
    app.run(&spec)
}

#[test]
fn subscribing_does_not_wait_or_make_a_response_ready() {
    let record = run("(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a))) (i64.extend_i32_u (call $ready (local.get $p)))");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(0)));
    assert_eq!(record.totals.host_ns, 0);
}

#[test]
fn getting_a_pending_response_is_nonblocking() {
    let record = run("(local.set $a (call $start)) (call $get (local.get $a) (i32.const 2048)) (i64.extend_i32_u (i32.load (i32.const 2048)))");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(0)));
    assert_eq!(record.totals.host_ns, 0);
}

#[test]
fn blocking_a_response_charges_only_the_remaining_host_time() {
    let record = run(r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (local.set $q (call $timer (i64.const 3000000))) (call $block (local.get $q))
        (call $block (local.get $p)) (call $get (local.get $a) (i32.const 2048))
        (i64.extend_i32_u (i32.load (i32.const 2048)))"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.sleep_ns, 3_000_000);
    assert_eq!(record.totals.host_ns, 7_000_000);
}

#[test]
fn polling_a_response_and_an_earlier_timer_returns_the_timer() {
    let record = run(r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (local.set $q (call $timer (i64.const 3000000)))
        (i32.store (i32.const 2000) (local.get $p)) (i32.store (i32.const 2004) (local.get $q))
        (call $poll (i32.const 2000) (i32.const 2) (i32.const 2048))
        (if (i32.ne (i32.load (i32.const 2052)) (i32.const 1)) (then unreachable))
        (i64.extend_i32_u (i32.load (i32.load (i32.const 2048))))"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.sleep_ns, 3_000_000);
    assert_eq!(record.totals.host_ns, 0);
}

#[test]
fn overlapping_responses_wait_once_and_repeated_get_is_consumed() {
    let record = run(r#"(local.set $a (call $start)) (local.set $b (call $start))
        (local.set $p (call $subscribe (local.get $a))) (local.set $q (call $subscribe (local.get $b)))
        (call $block (local.get $q)) (call $block (local.get $p)) (call $block (local.get $q))
        (call $get (local.get $a) (i32.const 2048)) (if (i32.eqz (i32.load (i32.const 2048))) (then unreachable))
        (call $get (local.get $a) (i32.const 2048))
        (i64.extend_i32_u (i32.load (i32.const 2056)))"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 10_000_000);
    assert_eq!(record.totals.host_calls, 2);
}

#[test]
fn dropped_response_pollables_do_not_delay_reused_stream_slots() {
    let record = run(r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (call $drop-poll (local.get $p)) (call $drop-future (local.get $a))
        (local.set $p (call $subscribe-stream (call $stdout))) (call $block (local.get $p))
        (i64.extend_i32_u (call $ready (local.get $p)))"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 0);
    assert_eq!(record.totals.host_calls, 1);
}

#[test]
fn a_live_response_pollable_preserves_the_native_parent_drop_error() {
    let record = run(r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (call $drop-future (local.get $a)) (i64.const 0)"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{:?}", record.outcome);
    assert_eq!(record.totals.host_ns, 0);
}

#[test]
fn a_timeout_becomes_ready_at_its_deadline_without_eager_waiting() {
    let record = run(r#"(local.set $b (call $options))
        (if (call $timeout (local.get $b) (i32.const 1) (i64.const 4000000)) (then unreachable))
        (local.set $a (call $dispatch (call $new) (i32.const 1) (local.get $b)))
        (local.set $p (call $subscribe (local.get $a)))
        (if (call $ready (local.get $p)) (then unreachable))
        (call $block (local.get $p)) (call $get (local.get $a) (i32.const 2048))
        (i64.extend_i32_u (i32.load (i32.const 2048)))"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 4_000_000);
    assert_eq!(record.events[0].source, "timeout");
}

#[test]
fn readiness_after_guest_work_does_not_add_a_wait() {
    let app = app(r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (loop $again (local.set $b (i32.add (local.get $b) (i32.const 1)))
            (br_if $again (i32.lt_u (local.get $b) (i32.const 10000))))
        (i64.extend_i32_u (call $ready (local.get $p)))"#);
    let plan = Plan::parse(&format!(r#"{{"{CLIENT_KEY}":{{"return":{{"err":"connection-refused"}},"latency_ms":1}}}}"#)).unwrap();
    let record = run_app(&app, plan, 100.0);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 0);
}

#[test]
fn http_polling_also_works_without_importing_a_clock() {
    let app = app_with_clock(
        r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (if (call $ready (local.get $p)) (then unreachable)) (call $block (local.get $p))
        (i64.extend_i32_u (call $ready (local.get $p)))"#,
        false,
    );
    let plan = Plan::parse(&format!(r#"{{"{CLIENT_KEY}":{{"return":{{"err":"connection-refused"}},"latency_ms":1}}}}"#)).unwrap();
    let record = run_app(&app, plan, 0.0);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 1_000_000);
}

#[test]
fn nonblocking_probes_leave_request_bodies_writable() {
    for probe in ["", "(drop (call $ready (local.get $p)))", "(call $get (local.get $a) (i32.const 2048))"] {
        let record = run(&format!(
            r#"(local.set $a (call $new))
            (call $body (local.get $a) (i32.const 1024)) (local.set $body (i32.load (i32.const 1028)))
            (call $write-body (local.get $body) (i32.const 1024)) (local.set $stream (i32.load (i32.const 1028)))
            (local.set $a (call $dispatch (local.get $a) (i32.const 0) (i32.const 0)))
            (local.set $p (call $subscribe (local.get $a))) {probe}
            (call $write-stream (local.get $stream) (i32.const 32) (i32.const 5) (i32.const 2048))
            (call $drop-stream (local.get $stream))
            (call $finish (local.get $body) (i32.const 0) (i32.const 0) (i32.const 2048))
            (call $block (local.get $p)) (i64.const 1)"#
        ));
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{probe}: {:?}", record.outcome);
        assert_eq!(record.events.len(), 1);
        assert_eq!(record.events[0].args["body"], "hello", "{probe}");
        assert_eq!(record.totals.host_ns, 10_000_000);
    }
}

#[test]
fn unused_subscriptions_and_unobserved_requests_do_not_add_host_waits() {
    for tail in ["", "(local.set $p (call $subscribe (local.get $a)))", "(call $drop-future (local.get $a))"] {
        let record = run(&format!("(local.set $a (call $start)) {tail} (i64.const 0)"));
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
        assert_eq!(record.totals.host_ns, 0);
        assert_eq!(record.totals.host_calls, 1);
        assert_eq!(record.events[0].latency_ns, 10_000_000);
        assert_eq!(record.totals.cost, 1);
    }
}

#[test]
fn response_polling_chooses_the_earliest_selected_deadline_with_duplicates() {
    let app = app(r#"(local.set $a (call $start)) (local.set $b (call $start))
        (local.set $p (call $subscribe (local.get $a))) (local.set $q (call $subscribe (local.get $b)))
        (i32.store (i32.const 2000) (local.get $p)) (i32.store (i32.const 2004) (local.get $q))
        (i32.store (i32.const 2008) (local.get $q))
        (call $poll (i32.const 2000) (i32.const 3) (i32.const 2048))
        (if (i32.ne (i32.load (i32.const 2052)) (i32.const 2)) (then unreachable))
        (if (i32.ne (i32.load (i32.load (i32.const 2048))) (i32.const 1)) (then unreachable))
        (call $block (local.get $p)) (i64.const 1)"#);
    let plan = Plan::parse(&format!(r#"{{"{CLIENT_KEY}":{{"return":{{"err":"connection-refused"}},"latency_ms":10,"on_call":{{"2":{{"return":{{"err":"connection-refused"}},"latency_ms":3}}}}}}}}"#)).unwrap();
    let record = run_app(&app, plan, 0.0);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 10_000_000);
    assert_eq!(record.totals.sleep_ns, 0);
}

#[test]
fn ready_streams_win_without_waiting_for_http() {
    let record = run(r#"(local.set $a (call $start)) (local.set $p (call $subscribe (local.get $a)))
        (local.set $q (call $subscribe-stream (call $stdout)))
        (i32.store (i32.const 2000) (local.get $p)) (i32.store (i32.const 2004) (local.get $q))
        (call $poll (i32.const 2000) (i32.const 2) (i32.const 2048))
        (if (i32.ne (i32.load (i32.const 2052)) (i32.const 1)) (then unreachable))
        (i64.extend_i32_u (i32.load (i32.load (i32.const 2048))))"#);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1)));
    assert_eq!(record.totals.host_ns, 0);
    assert_eq!(record.totals.sleep_ns, 0);
}
