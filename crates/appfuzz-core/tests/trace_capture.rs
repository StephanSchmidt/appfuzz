use appfuzz_core::{
    detect,
    harness::App,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
    value::json_len,
};
use serde_json::json;

const CALLS: usize = 65_536;
const BYTES: usize = 32 << 20;

fn app(lists: bool, startup: usize) -> App {
    configured_app(lists, startup, |_| {})
}

fn configured_app(lists: bool, startup: usize, configure: impl FnOnce(&mut appfuzz_core::manifest::Manifest)) -> App {
    let result = if lists { "list<string>" } else { "u32" };
    let wit = format!("package test:trace; interface host {{ call:func(id:u32)->{result}; }} world app {{ import host; export run:func(n:u32)->u32; }}");
    let host = if lists { "(call $call (local.get $i) (i32.const 0))" } else { "(drop (call $call (local.get $i)))" };
    let signature = if lists { "(param i32 i32)" } else { "(param i32) (result i32)" };
    let wat = format!(
        r#"(module
        (import "test:trace/host" "call" (func $call {signature}))
        (memory (export "memory") 32)
        (global $heap (mut i32) (i32.const 4096))
        (func (export "cabi_realloc") (param i32 i32 i32) (param $size i32) (result i32) (local $p i32)
            (local.set $p (global.get $heap))
            (global.set $heap (i32.add (local.get $p) (local.get $size))) (local.get $p))
        (func $many (param $n i32) (local $i i32)
            (if (i32.ne (local.get $n) (i32.const 0)) (then
                (loop $again
                    (global.set $heap (i32.const 4096)) {host}
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))
                    (br_if $again (i32.lt_u (local.get $i) (local.get $n)))))))
        (func $init (call $many (i32.const {startup}))) (start $init)
        (func (export "run") (param $n i32) (result i32) (call $many (local.get $n)) (local.get $n)))"#
    );
    let mut resolve = wit_parser::Resolve::new();
    let package = resolve.push_str("trace.wit", &wit).unwrap();
    let world = resolve.select_world(&[package], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    let mut manifest =
        toml::from_str("[app]\nwasm='trace.wasm'\n[limits]\nwall_timeout_ms=30000\n[functions.\"test:trace/host#call\"]\nlatency_ms=3\ncost=2\n").unwrap();
    configure(&mut manifest);
    App::from_bytes(manifest, bytes).unwrap()
}

fn run(app: &App, n: usize, plan: Plan) -> RunRecord {
    app.run(&app.spec(app.export("run").unwrap(), vec![json!(n)], plan, 1))
}

fn numbers() -> Plan {
    Plan::parse(r#"{"test:trace/host#call":{"return":7}}"#).unwrap()
}

fn accounting(run: &RunRecord) {
    assert_eq!(run.totals.host_calls as usize, run.events.len());
    assert_eq!(run.totals.cost, run.events.len() as u64 * 2);
    assert_eq!(run.totals.host_ns, run.events.len() as u64 * 3_000_000);
    assert!(run.events.iter().enumerate().all(|(i, event)| event.n as usize == i + 1 && event.call as usize == i + 1));
}

#[test]
fn a_full_trace_at_the_call_boundary_is_complete() {
    let app = app(false, 0);
    let run = run(&app, CALLS, numbers());
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(CALLS)));
    assert_eq!(run.events.len(), CALLS);
    accounting(&run);
}

#[test]
fn a_call_beyond_capture_capacity_is_incomplete_and_keeps_accounting() {
    let app = app(false, 0);
    let run = run(&app, CALLS + 1, numbers());
    assert_eq!(run.outcome.kind, OutcomeKind::Error, "{:?}", run.outcome);
    assert!(run.capture_limited);
    assert!(run.outcome.message.as_ref().unwrap().contains("trace capture"));
    assert!(run.result.is_none());
    assert_eq!(run.events.len(), CALLS);
    assert_eq!(run.events.last().unwrap().args["id"], CALLS - 1);
    assert!(!detect::per_run(&run, &app.manifest).iter().any(|finding| finding.kind == "crash"));
    let trace: appfuzz_core::envelope::Trace = serde_json::from_value(serde_json::to_value(&run).unwrap()).unwrap();
    let roundtrip = trace.to_record();
    assert!(roundtrip.capture_limited);
    assert_eq!(roundtrip.outcome.kind, run.outcome.kind);
    assert_eq!(roundtrip.outcome.message, run.outcome.message);
    accounting(&run);
}

#[test]
fn large_results_stop_capture_without_losing_the_last_completed_call() {
    let app = app(true, 0);
    let plan = Plan::parse(&json!({"test:trace/host#call":{"generate":{"list_len":64,"strings":format!("={}", "x".repeat(1000))}}}).to_string()).unwrap();
    let run = run(&app, 1024, plan.clone());
    assert_eq!(run.outcome.kind, OutcomeKind::Error, "{:?}", run.outcome);
    assert!(run.outcome.message.as_ref().unwrap().contains("trace capture"));
    assert!(!run.events.is_empty() && run.events.len() < 1024);
    let size: usize = run.events.iter().map(json_len).sum();
    assert!(size > BYTES);
    assert!(size - json_len(run.events.last().unwrap()) <= BYTES);
    assert!(run.events.iter().all(|event| event.result.as_ref().unwrap().as_array().unwrap().len() == 64));
    accounting(&run);
    let crossing_call = run.events.len();
    drop(run);
    // Ending on the crossing call needs no truncated or invented event.
    let finished = app.run(&app.spec(app.export("run").unwrap(), vec![json!(crossing_call)], plan, 1));
    assert_eq!(finished.outcome.kind, OutcomeKind::Ok, "{:?}", finished.outcome);
    assert!(!finished.capture_limited);
    assert_eq!(finished.result, Some(json!(crossing_call)));
    accounting(&finished);
}

#[test]
fn initialization_and_entry_share_the_trace_capacity() {
    let app = app(false, CALLS / 2);
    let run = run(&app, CALLS / 2 + 1, numbers());
    assert_eq!(run.outcome.kind, OutcomeKind::Error, "{:?}", run.outcome);
    assert_eq!(run.events.len(), CALLS);
    accounting(&run);
}

#[test]
fn a_real_host_failure_at_the_last_allowed_call_is_preserved() {
    let app = app(false, 0);
    let plan = Plan::parse(&json!({"test:trace/host#call":{"return":7,"on_call":{CALLS.to_string():{"trap":"service failed"}}}}).to_string()).unwrap();
    let run = run(&app, CALLS, plan);
    assert_eq!(run.outcome.kind, OutcomeKind::HostTrap, "{:?}", run.outcome);
    assert_eq!(run.events.len(), CALLS);
    assert_eq!(run.events.last().unwrap().trap.as_deref(), Some("service failed"));
    accounting(&run);
}

#[test]
fn capture_limits_are_not_reported_as_app_size_failures() {
    let app = app(false, 0);
    let base = app.spec(app.export("run").unwrap(), vec![json!(1)], numbers(), 1);
    let report = appfuzz_core::scale::scale(&app, &base, appfuzz_core::scale::Knob::Field("@0".into()), &[1, (CALLS + 1) as u64], &|s| app.run(s)).unwrap();
    assert_eq!(report.points.last().unwrap().outcome, OutcomeKind::Error);
    assert!(!report.findings.iter().any(|finding| finding.kind == "fails_at_size"));
}

#[test]
fn fuzzing_cannot_discard_capture_failure_as_an_invalid_sample() {
    use appfuzz_core::fuzz::{Entry, FuzzOpts};
    let app = app(false, 0);
    let base = app.spec(app.export("run").unwrap(), vec![json!(1)], numbers(), 1);
    let mut oversized = base.clone();
    oversized.args = vec![json!(CALLS + 1)];
    let prior: Entry = serde_json::from_value(json!({"run":oversized.id(),"spec":oversized,"stage":"seed","reasons":[]})).unwrap();
    let saved = std::sync::atomic::AtomicBool::new(false);
    let on_run = |r: &RunRecord, keep: bool, _: &[detect::Finding]| {
        if r.capture_limited && keep {
            saved.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    };
    let opts = FuzzOpts { runs: Some(3), discover: false, ..Default::default() };
    let result = appfuzz_core::fuzz::fuzz(&app, &base, vec![prior], Default::default(), &opts, &on_run);
    assert!(result.is_err());
    assert!(result.err().unwrap().to_string().contains("trace capture"));
    assert!(saved.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn incomplete_capture_cannot_pass_the_library_envelope_check() {
    let app = app(false, 0);
    let mut record = run(&app, 1, numbers());
    let envelope = appfuzz_core::envelope::Envelope::build(&[record.clone()], &app.manifest);
    assert!(envelope.check(&record, &app.manifest).is_empty());
    record.capture_limited = true;
    record.outcome.kind = OutcomeKind::Error;
    record.outcome.message = Some("trace capture is incomplete".into());
    let findings = envelope.check(&record, &app.manifest);
    assert!(findings.iter().any(|f| f.severity == detect::Severity::Fail && f.detail["what"] == "evidence"));
}

#[test]
fn a_proven_budget_failure_is_preserved_when_trace_capacity_is_reached() {
    let app = configured_app(false, 0, |m| m.limits.cost_per_request = Some(10));
    let record = run(&app, CALLS + 1, numbers());
    assert_eq!(serde_json::to_value(record.outcome.kind).unwrap(), json!("budget_exceeded"));
    assert!(!record.capture_limited);
    assert_eq!(record.events.len(), CALLS);
    let findings = detect::per_run(&record, &app.manifest);
    assert!(findings.iter().any(|f| f.kind == "over_budget" && f.severity == detect::Severity::Fail));
    assert!(!findings.iter().any(|f| f.kind == "crash" || f.kind == "hang"));
    accounting(&record);
    let baseline = run(&app, 1, numbers());
    let envelope = appfuzz_core::envelope::Envelope::build(&[baseline], &app.manifest);
    assert!(envelope.check(&record, &app.manifest).iter().any(|f| f.severity == detect::Severity::Fail && f.detail["what"] == "production_budget"));
}

#[test]
fn reaching_a_budget_exactly_is_not_a_proven_violation() {
    let app = configured_app(false, 0, |m| m.limits.cost_per_request = Some((CALLS * 2) as u64));
    let record = run(&app, CALLS + 1, numbers());
    assert_eq!(record.outcome.kind, OutcomeKind::Error);
    assert!(record.capture_limited);
    assert_eq!(record.totals.cost, (CALLS * 2) as u64);
    assert!(!detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "over_budget"));
}

#[test]
fn capture_stops_recognize_proven_fuel_memory_and_time_failures() {
    for metric in ["fuel", "memory", "time"] {
        let app = configured_app(false, 0, |m| match metric {
            "fuel" => m.limits.fuel = 100,
            "memory" => m.limits.memory = 1 << 20,
            _ => m.limits.max_latency_ms = Some(1.0),
        });
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(CALLS + 1)], numbers(), 1);
        spec.fuel = 20_000_000;
        spec.memory = 8 << 20;
        let record = app.run(&spec);
        assert_eq!(serde_json::to_value(record.outcome.kind).unwrap(), json!("budget_exceeded"), "{metric}");
        assert!(!record.capture_limited);
        assert!(!detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "crash" || f.kind == "hang"));
        accounting(&record);
    }
}

#[test]
fn capture_limits_on_platform_excluded_requests_do_not_invalidate_fuzzing() {
    for declaration in ["values", "input_values"] {
        let app = configured_app(false, 0, |m| {
            m.entry = toml::from_str::<appfuzz_core::manifest::Manifest>(&format!(
                "[app]\nwasm='trace.wasm'\n[entry]\nexport='run'\nrequest=1\n{declaration}={{''='range:1..31'}}"
            ))
            .unwrap()
            .entry;
        });
        let base = app.spec(app.export("run").unwrap(), vec![json!(1)], numbers(), 1);
        let mut oversized = base.clone();
        oversized.args = vec![json!(CALLS + 1)];
        let prior = serde_json::from_value(json!({"run":oversized.id(),"spec":oversized,"stage":"seed","reasons":[]})).unwrap();
        let opts = appfuzz_core::fuzz::FuzzOpts { runs: Some(3), discover: false, ..Default::default() };
        let result = appfuzz_core::fuzz::fuzz(&app, &base, vec![prior], Default::default(), &opts, &|_, _, _| {});
        // Accepted input domains do not exclude invalid incoming requests.
        assert_eq!(result.is_ok(), declaration == "values", "{declaration}: {:?}", result.err());
    }
}
