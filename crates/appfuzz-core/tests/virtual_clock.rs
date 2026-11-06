use appfuzz_core::{harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
use serde_json::json;

const WORK: &str = r#"(func $work (param $n i32) (local $i i32)
    (if (local.get $n) (then (loop $again
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (local.get $n)))))))"#;

fn component(wall: bool, version: &str, body: &str) -> App {
    component_with_start(wall, version, body, "")
}

fn component_with_start(wall: bool, version: &str, body: &str, start: &str) -> App {
    let interface = if wall { "wall-clock" } else { "monotonic-clock" };
    let signature = if wall {
        "record datetime { seconds:u64, nanoseconds:u32 } now:func()->datetime;".to_string()
    } else {
        format!("use wasi:io/poll@{version}.{{pollable}}; now:func()->u64; subscribe-instant:func(when:u64)->pollable;")
    };
    let read = if wall {
        r#"(import "clock" "now" (func $now (param i32)))
        (func $read (result i64)
            (call $now (i32.const 0))
            (i64.add (i64.mul (i64.load (i32.const 0)) (i64.const 1000000000))
                (i64.extend_i32_u (i32.load (i32.const 8)))))"#
    } else {
        r#"(import "clock" "now" (func $read (result i64)))
        (import "clock" "subscribe-instant" (func $until (param i64) (result i32)))"#
    };
    let read = read.replace("\"clock\"", &format!("\"wasi:clocks/{interface}@{version}\""));
    let block = if wall { String::new() } else { format!(r#"(import "wasi:io/poll@{version}" "[method]pollable.block" (func $block (param i32)))"#) };
    let io = if wall { String::new() } else { format!("import wasi:io/poll@{version};") };
    let mut resolve = wit_parser::Resolve::new();
    if !wall {
        resolve.push_str("io.wit", &format!("package wasi:io@{version}; interface poll {{ resource pollable {{ block:func(); }} }}")).unwrap();
    }
    resolve.push_str("clock.wit", &format!("package wasi:clocks@{version}; interface {interface} {{ {signature} }}")).unwrap();
    let pkg = resolve
        .push_str("app.wit", &format!("package test:clock; world app {{ {io} import wasi:clocks/{interface}@{version}; export run:func(n:u32)->u64; }}"))
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(format!(
        r#"(module {read} {block}
        (memory (export "memory") 1)
        {WORK}
        (func $init {start}) (start $init)
        (func (export "run") (param $n i32) (result i64) (local $before i64)
            {body}))"#
    ))
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("clock.wasm")), bytes).unwrap()
}

fn check_component_clock(wall: bool, version: &str) {
    let app = component(wall, version, "(local.set $before (call $read)) (call $work (local.get $n)) (i64.sub (call $read) (local.get $before))");
    for n in [0, 10_000] {
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(n)], Plan::default(), 1);
        spec.ns_per_fuel = 100.0;
        let run = app.run(&spec);
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        assert!(run.events.is_empty());
        assert_eq!(run.totals.clock_reads, 2);
        let elapsed = run.result.unwrap().as_u64().unwrap();
        assert!(elapsed >= n as u64 * 100 + 1_000, "clock omitted guest work: n={n}, elapsed={elapsed}, fuel={}", run.totals.fuel);
        let again = app.run(&spec);
        assert_eq!(again.result, Some(json!(elapsed)));
        assert_eq!(again.totals.virtual_ns, run.totals.virtual_ns);
        assert_eq!(again.totals.fuel, run.totals.fuel);
    }
}

#[test]
fn component_monotonic_clock_observes_guest_work_without_platform_calls() {
    check_component_clock(false, "0.2.12");
}

#[test]
fn component_wall_clock_observes_guest_work_without_platform_calls() {
    check_component_clock(true, "0.2.12");
}

#[test]
fn older_wasi_clock_versions_observe_guest_work() {
    check_component_clock(false, "0.2.9");
    check_component_clock(true, "0.2.9");
}

#[test]
fn a_zero_fuel_time_rate_keeps_only_the_clock_read_steps() {
    let app = component(false, "0.2.12", "(local.set $before (call $read)) (call $work (local.get $n)) (i64.sub (call $read) (local.get $before))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!(10_000)], Plan::default(), 1);
    spec.ns_per_fuel = 0.0;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(1_000)));
    assert_eq!(run.totals.guest_ns, 0);
    assert_eq!(run.totals.virtual_ns, 2_000);
}

#[test]
fn startup_work_is_visible_to_the_first_clock_read() {
    let mut times = Vec::new();
    for start in ["", "(call $work (i32.const 10000))"] {
        let app = component_with_start(false, "0.2.12", "(call $read)", start);
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(0)], Plan::default(), 1);
        spec.ns_per_fuel = 100.0;
        let run = app.run(&spec);
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        times.push(run.result.unwrap().as_u64().unwrap());
    }
    assert!(times[1] >= times[0] + 1_000_000, "startup work was invisible: {times:?}");
}

#[test]
fn an_elapsed_deadline_does_not_add_a_sleep_after_guest_work() {
    let app = component(
        false,
        "0.2.12",
        "(local.set $before (call $read)) (call $work (local.get $n)) (call $block (call $until (i64.add (local.get $before) (i64.const 1000000)))) (i64.sub (call $read) (local.get $before))",
    );
    for n in [0, 10_000] {
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(n)], Plan::default(), 1);
        spec.ns_per_fuel = 100.0;
        let run = app.run(&spec);
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        if n == 0 {
            assert!(run.totals.sleep_ns > 0);
        } else {
            assert_eq!(run.totals.sleep_ns, 0, "the deadline passed during guest execution");
        }
    }
}

#[test]
fn preview1_clock_reads_observe_work_in_modules_and_plugins() {
    use appfuzz_core::host_manifest::{HostManifest, merge};
    let dir = std::env::temp_dir().join(format!("appfuzz-p1-clock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.wit"), "package test:clock; world plugin { export run:func()->string; }").unwrap();
    std::fs::write(dir.join("app.witx"), "(module $host (@interface func (export \"ping\")))").unwrap();
    for plugin in [false, true] {
        let declaration = if plugin {
            "[platform]\nname='clock'\nabi='extism'\nwit='app.wit'"
        } else {
            "[platform]\nname='clock'\nwitx=['app.witx']\nstart='_start'\nentry_wit='run:func();'\n[entry]\nexport='entry#run'"
        };
        let host = HostManifest::parse(declaration, &dir).unwrap();
        for clock_id in [0, 1] {
            let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("clock.wasm")), &Default::default()).unwrap();
            manifest.host = Some(std::sync::Arc::new(host.clone()));
            let export = if plugin { "run" } else { "_start" };
            let result = if plugin { "(result i32)" } else { "" };
            let success = if plugin { "(i32.const 0)" } else { "" };
            let wat = format!(
                r#"(module
                (import "wasi_snapshot_preview1" "clock_time_get" (func $now (param i32 i64 i32) (result i32)))
                (memory (export "memory") 1)
                {WORK}
                (func $read (result i64)
                    (if (call $now (i32.const {clock_id}) (i64.const 1) (i32.const 0)) (then unreachable))
                    (i64.load (i32.const 0)))
                (func (export "{export}") {result} (local $before i64)
                    (local.set $before (call $read))
                    (call $work (i32.const 10000))
                    (if (i64.lt_u (i64.sub (call $read) (local.get $before)) (i64.const 1001000)) (then unreachable))
                    {success}))"#
            );
            let app = App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap();
            let mut spec = app.spec(app.export(if plugin { "run" } else { "entry#run" }).unwrap(), vec![], Plan::default(), 1);
            spec.ns_per_fuel = 100.0;
            let run = app.run(&spec);
            assert_eq!(run.outcome.kind, OutcomeKind::Ok, "plugin={plugin}, clock_id={clock_id}: {:?}", run.outcome);
            assert_eq!(run.totals.clock_reads, 2);
            assert!(run.events.is_empty());
            // The SDK reports overflow for a Preview 1 realtime timestamp
            // outside u64 nanoseconds; monotonic timestamps saturate.
            let errno = if clock_id == 0 { u16::from(wasmtime_wasi::p1::types::Errno::Overflow) } else { 0 };
            let huge_wat = format!(
                r#"(module
                (import "wasi_snapshot_preview1" "clock_time_get" (func $now (param i32 i64 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "{export}") {result}
                    (if (i32.ne (call $now (i32.const {clock_id}) (i64.const 1) (i32.const 0)) (i32.const {errno})) (then unreachable))
                    {success}))"#
            );
            let huge_app = App::from_bytes(app.manifest.clone(), wat::parse_str(huge_wat).unwrap()).unwrap();
            let mut huge_spec = huge_app.spec(huge_app.export(if plugin { "run" } else { "entry#run" }).unwrap(), vec![], Plan::default(), 1);
            huge_spec.ns_per_fuel = 1e30;
            let huge = huge_app.run(&huge_spec);
            assert_eq!(huge.outcome.kind, OutcomeKind::Ok, "plugin={plugin}, clock_id={clock_id}: {:?}", huge.outcome);
            assert!(huge.totals.guest_ns > u64::MAX);
            assert_eq!(huge.totals.clock_reads, 1);
        }
    }
}

#[test]
fn component_wall_clock_keeps_seconds_past_the_nanosecond_counter_range() {
    let app = component(true, "0.2.12", "(drop (call $read)) (i64.load (i32.const 0))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!(0)], Plan::default(), 1);
    spec.ns_per_fuel = 1e20;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert!(run.result.unwrap().as_u64().unwrap() > u64::MAX / 1_000_000_000);
    assert!(run.totals.guest_ns > u64::MAX);
}

#[test]
fn component_wall_clock_accepts_future_dates_its_abi_can_represent() {
    let app = component(true, "0.2.12", "(drop (call $read)) (i64.load (i32.const 0))");
    for now in ["2555-01-01T00:00:00", "3000-01-01T00:00:00", "9999-12-31T23:59:59"] {
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(0)], Plan::default(), 1);
        spec.now = now.into();
        spec.ns_per_fuel = 0.0;
        let record = app.run(&spec);
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{now}: {:?}", record.outcome);
        let seconds = appfuzz_core::wasi::parse_datetime(now).unwrap() as u64;
        assert_eq!(record.result, Some(json!(seconds)));
    }
}

#[test]
fn dates_outside_u64_nanoseconds_still_work_without_wall_clock_reads() {
    let app = component(false, "0.2.12", "(i64.const 7)");
    for now in ["0001-01-01", "1969-12-31T23:59:59", "3000-01-01", "9999-12-31"] {
        let mut spec = app.spec(app.export("run").unwrap(), vec![json!(0)], Plan::default(), 1);
        spec.now = now.into();
        let record = app.run(&spec);
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{now}: {:?}", record.outcome);
        assert_eq!(record.result, Some(json!(7)));
    }
}

#[test]
fn negative_wall_times_cannot_be_silently_replaced_with_the_epoch() {
    let app = component(true, "0.2.12", "(drop (call $read)) (i64.load (i32.const 0))");
    let mut spec = app.spec(app.export("run").unwrap(), vec![json!(0)], Plan::default(), 1);
    spec.now = "1969-12-31T23:59:59".into();
    spec.ns_per_fuel = 0.0;
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::PlanError, "{:?} {:?}", record.outcome, record.result);
    assert!(!appfuzz_core::detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "crash"));
}

#[test]
fn a_component_may_cross_the_epoch_before_reading_its_wall_clock() {
    let version = "0.2.12";
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_str("io.wit", &format!("package wasi:io@{version}; interface poll {{resource pollable {{block:func();}}}}")).unwrap();
    resolve.push_str("clocks.wit",&format!("package wasi:clocks@{version}; interface wall-clock {{record datetime {{seconds:u64,nanoseconds:u32}} now:func()->datetime;}} interface monotonic-clock {{use wasi:io/poll@{version}.{{pollable}}; subscribe-duration:func(when:u64)->pollable;}}" )).unwrap();
    let pkg=resolve.push_str("app.wit",&format!("package test:epoch; world app {{import wasi:clocks/wall-clock@{version}; import wasi:clocks/monotonic-clock@{version}; import wasi:io/poll@{version}; export run:func()->u64;}}" )).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(format!(
        r#"(module
        (import "wasi:clocks/wall-clock@{version}" "now" (func $now (param i32)))
        (import "wasi:clocks/monotonic-clock@{version}" "subscribe-duration" (func $sleep (param i64) (result i32)))
        (import "wasi:io/poll@{version}" "[method]pollable.block" (func $block (param i32)))
        (memory (export "memory") 1)
        (func (export "run") (result i64)
            (call $block (call $sleep (i64.const 1000000000)))
            (call $now (i32.const 0))
            (if (i64.ne (i64.load (i32.const 0)) (i64.const 0)) (then unreachable))
            (i64.extend_i32_u (i32.load (i32.const 8)))))"#
    ))
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("epoch.wasm")), bytes).unwrap();
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.ns_per_fuel = 0.0;
    spec.now = "1969-12-31T23:59:59".into();
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!(1000)));
    assert_eq!(record.totals.sleep_ns, 1_000_000_000);
}

#[test]
fn unsupported_wall_dates_fail_during_startup_without_becoming_guest_crashes() {
    // Bind canonical memory before instantiating the module whose start calls
    // a record-returning import. An exported-memory trampoline is not ready
    // during that module's own start function.
    let bytes = wat::parse_str(
        r#"(component
        (type $wall-type (instance
            (type $datetime (record (field "seconds" u64) (field "nanoseconds" u32)))
            (export "datetime" (type $public-datetime (eq $datetime)))
            (export "now" (func (result $public-datetime)))))
        (import "wasi:clocks/wall-clock@0.2.12" (instance $wall (type $wall-type)))
        (core module $memory (memory (export "memory") 1))
        (core instance $memory (instantiate $memory))
        (alias core export $memory "memory" (core memory $mem))
        (core func $now (canon lower (func $wall "now") (memory $mem)))
        (core module $app
            (import "env" "memory" (memory 1))
            (import "wall" "now" (func $now (param i32)))
            (func $init (call $now (i32.const 0))) (start $init)
            (func (export "run") (result i64) (i64.const 7)))
        (core instance $app (instantiate $app
            (with "env" (instance (export "memory" (memory $mem))))
            (with "wall" (instance (export "now" (func $now))))))
        (func (export "run") (result u64) (canon lift (core func $app "run"))))"#,
    )
    .unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("startup-clock.wasm")), bytes).unwrap();
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.ns_per_fuel = 0.0;
    let control = app.run(&spec);
    assert_eq!(control.outcome.kind, OutcomeKind::Ok, "{:?}", control.outcome);
    assert_eq!(control.result, Some(json!(7)));
    spec.now = "0001-01-01".into();
    let record = app.run(&spec);
    assert_eq!(record.outcome.kind, OutcomeKind::PlanError, "{:?}", record.outcome);
    assert_eq!(record.totals.clock_reads, 1);
    assert_eq!(record.result, None);
}
