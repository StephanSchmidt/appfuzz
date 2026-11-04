//! Position sweeps must fail the intended call on the original binary.
use appfuzz_core::{
    faults::{self, Cursor, Mode, Recipe},
    fuzz::{self, FuzzOpts},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
    shrink::{self, Across},
};
use serde_json::json;

fn component(wit: &str, wat: &str) -> Vec<u8> {
    static POOL: std::sync::Once = std::sync::Once::new();
    POOL.call_once(|| rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap());
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("faults.wit", wit).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}

fn fixture(behavior: &str, rules: bool) -> App {
    let wit = r#"package test:faults;
      interface store { enum problem { unavailable, denied } save:func(id:u32) -> result<u32,problem>; }
      world app { import store; record response { status:u16,body:string } export run:func() -> response; }"#;
    let after_error = match behavior {
        "late-crash" => "(if (i32.eq (local.get $i) (i32.const 7)) (then unreachable))",
        "stop" => "(return (call $response (i32.const 500)))",
        "retry" => {
            r#"(local.set $retry (i32.const 0))
          (block $recovered (loop $again
            (call $save (local.get $i) (i32.const 0))
            (br_if $recovered (i32.eqz (i32.load (i32.const 0))))
            (local.set $retry (i32.add (local.get $retry) (i32.const 1)))
            (br_if $again (i32.lt_u (local.get $retry) (i32.const 3)))
            (return (call $response (i32.const 500)))))"#
        }
        _ => "",
    };
    let wat = format!(
        r#"(module
      (import "test:faults/store" "save" (func $save (param i32 i32)))
      (memory (export "memory") 4) (data (i32.const 8192) "done")
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
      (func $response (param $status i32) (result i32)
        (i32.store (i32.const 256) (local.get $status))
        (i32.store (i32.const 260) (i32.const 8192)) (i32.store (i32.const 264) (i32.const 4)) (i32.const 256))
      (func (export "run") (result i32) (local $i i32) (local $retry i32)
        (local.set $i (i32.const 1))
        (loop $next
          (call $save (local.get $i) (i32.const 0))
          (if (i32.load (i32.const 0)) (then {after_error}))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $next (i32.le_u (local.get $i) (i32.const 7))))
        (call $response (i32.const 200))))"#
    );
    let rule = if rules { "rules=[{when={},return={ok=1}}]" } else { "" };
    let manifest: Manifest = toml::from_str(&format!(
        r#"
      [app]
      wasm="faults.wasm"
      [entry]
      export="run"
      output={{status="status",body="body"}}
      [limits]
      fuel=100000
      [functions."test:faults/store#save"]
      effect="write"
      {rule}
    "#
    ))
    .unwrap();
    App::from_bytes(manifest, component(wit, &wat)).unwrap()
}

fn baseline(app: &App) -> RunRecord {
    let plan = Plan::parse(r#"{"test:faults/store#save":{"return":{"ok":1}}}"#).unwrap();
    let r = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    assert_eq!(r.events.len(), 7);
    r
}

#[test]
fn sweeps_every_occurrence_including_late_calls_with_typed_errors() {
    let app = fixture("late-crash", false);
    let base = baseline(&app);
    let (probes, found, complete) = faults::probe(&app, &base, None, 14, &|s| app.run(s));
    assert!(complete);
    assert_eq!(probes.len(), 14);
    assert!(probes.iter().all(|p| p.injected && p.outcome != OutcomeKind::PlanError));
    assert_eq!(
        probes.iter().map(|p| (p.fault.call, p.fault.mode)).collect::<Vec<_>>(),
        (1..=7).flat_map(|n| [(n, Mode::Once), (n, Mode::Outage)]).collect::<Vec<_>>()
    );
    assert!(found.iter().any(|f| f.kind == "crash"));
    assert!(probes.iter().filter(|p| p.fault.mode == Mode::Once && p.fault.call < 7).all(|p| p.outcome == OutcomeKind::Ok));
    let target = probes.iter().find(|p| p.fault.mode == Mode::Once && p.outcome == OutcomeKind::Unreachable).unwrap();
    assert_eq!(target.fault.call, 7);
    let original = target.fault.variant(&app, &base).unwrap();
    assert_eq!(app.run(&original.spec).outcome.kind, OutcomeKind::Unreachable);
    let (small, _) = shrink::minimise(&app, &original.spec, &[], &|r| r.outcome.kind == OutcomeKind::Unreachable, 80, &|s| app.run(s));
    assert_eq!(app.run(&small).outcome.kind, OutcomeKind::Unreachable);
    assert!(serde_json::to_vec(&small.plan).unwrap().len() < 300);
}

#[test]
fn transient_retry_recovers_but_outage_exposes_retry_storm() {
    let app = fixture("retry", false);
    let base = baseline(&app);
    let transient = Recipe { func: "test:faults/store#save".into(), call: 4, mode: Mode::Once };
    let v = transient.variant(&app, &base).unwrap();
    let r = app.run(&v.spec);
    assert!(faults::injected(&base, &transient, &r));
    assert_eq!(r.result.as_ref().unwrap()["status"], 200);
    assert!(!appfuzz_core::detect::per_run(&r, &app.manifest).iter().any(|f| matches!(f.kind.as_str(), "partial_write" | "retry_storm")));
    assert!(faults::compare(&app, &base, &transient, &v, &r).is_empty());
    let outage = Recipe { mode: Mode::Outage, ..transient };
    let v = outage.variant(&app, &base).unwrap();
    let r = app.run(&v.spec);
    assert!(faults::injected(&base, &outage, &r));
    assert_eq!(r.result.as_ref().unwrap()["status"], 500);
    assert!(appfuzz_core::detect::per_run(&r, &app.manifest).iter().any(|f| f.kind == "retry_storm"));
    assert!(r.events.iter().filter(|e| e.call >= 4).all(|e| e.result.as_ref().unwrap().get("err").is_some()));
}

#[test]
fn partial_writes_include_different_records_written_by_the_same_function() {
    let app = fixture("ignore", false);
    let base = baseline(&app);
    let recipe = Recipe { func: "test:faults/store#save".into(), call: 7, mode: Mode::Once };
    let r = app.run(&recipe.variant(&app, &base).unwrap().spec);
    assert!(appfuzz_core::effects::check(&r, &app.manifest).iter().any(|f| f.kind == "partial_write"));
    let app = fixture("stop", false);
    let base = baseline(&app);
    let (probes, found, complete) = faults::probe(&app, &base, None, 14, &|s| app.run(s));
    assert!(complete && probes.iter().all(|p| p.injected));
    assert!(!found.iter().any(|f| matches!(f.kind.as_str(), "partial_write" | "error_ignored" | "retry_storm" | "crash")));
}

#[test]
fn platform_overrides_are_reported_blocked_without_ignored_error_findings() {
    let app = fixture("ignore", true);
    let base = baseline(&app);
    let (probes, found, complete) = faults::probe(&app, &base, None, 14, &|s| app.run(s));
    assert!(complete);
    assert!(probes.iter().all(|p| !p.injected));
    assert!(!found.iter().any(|f| matches!(f.kind.as_str(), "error_ignored" | "partial_write" | "crash")));
}

#[test]
fn aliases_preserve_the_prefix_and_a_different_prefix_cannot_establish_causality() {
    let app = fixture("ignore", false);
    let mut spec = baseline(&app).spec;
    let definition = spec.plan.0.remove("test:faults/store#save").unwrap();
    spec.plan.0.insert("test:faults/store@0.1.0#save".into(), definition);
    let base = app.run(&spec);
    assert_eq!(base.outcome.kind, OutcomeKind::Ok);
    let recipe = Recipe { func: "test:faults/store#save".into(), call: 7, mode: Mode::Once };
    let mut variant = recipe.variant(&app, &base).unwrap();
    assert!(faults::injected(&base, &recipe, &app.run(&variant.spec)));
    variant
        .spec
        .plan
        .0
        .get_mut("test:faults/store#save")
        .unwrap()
        .on_call
        .insert("1".into(), appfuzz_core::plan::Response { ret: Some(json!({"ok":99})), ..Default::default() });
    let different = app.run(&variant.spec);
    assert!(!faults::injected(&base, &recipe, &different));
    assert!(faults::compare(&app, &base, &recipe, &variant, &different).is_empty());
}

#[test]
fn budget_filter_and_exact_comparison_recipe_replay_a_later_ignored_error() {
    let app = fixture("ignore", false);
    let base = baseline(&app);
    let (probes, _, complete) = faults::probe(&app, &base, None, 3, &|s| app.run(s));
    assert_eq!(probes.len(), 3);
    assert!(!complete);
    assert!(faults::probe(&app, &base, Some("unknown"), 14, &|s| app.run(s)).0.is_empty());
    let recipe = Recipe { func: "test:faults/store#save".into(), call: 7, mode: Mode::Outage };
    let v = recipe.variant(&app, &base).unwrap();
    let r = app.run(&v.spec);
    let finding = faults::compare(&app, &base, &recipe, &v, &r).into_iter().find(|f| f.kind == "error_ignored").unwrap();
    let across = Across::of(&finding).unwrap();
    let encoded = serde_json::to_vec(&across).unwrap();
    let replay: Across = serde_json::from_slice(&encoded).unwrap();
    assert!(replay.evaluate(&app, &finding.id, &base.spec, &|s| app.run(s)).unwrap().is_some());
    assert_eq!(replay.describe()["fault"]["call"], 7);
    let (report, _) = fuzz::fuzz(
        &app,
        &base.spec,
        vec![],
        Default::default(),
        &FuzzOpts { runs: Some(500), time: None, discover: false, internal_feedback: false, ..Default::default() },
        &|_, _, _| {},
    )
    .unwrap();
    assert!(report.runs <= 500);
    assert!(report.faults.attempted >= 14, "{report:?}");
    assert_eq!(report.faults.injected, report.faults.attempted);
}

#[test]
fn option_absence_and_unrecoverable_host_traps_are_not_misreported_as_guest_crashes() {
    for option in [true, false] {
        let wit = if option {
            "package test:faults; interface data { get:func() -> option<u32>; } world app { import data; export run:func() -> u32; }"
        } else {
            "package test:faults; interface data { get:func(); } world app { import data; export run:func() -> u32; }"
        };
        let signature = if option { "(param i32)" } else { "" };
        let argument = if option { "(i32.const 0)" } else { "" };
        let wat = format!(
            r#"(module (import "test:faults/data" "get" (func $get {signature}))
          (memory (export "memory") 1) (func (export "run") (result i32) (call $get {argument}) (i32.const 1)))"#
        );
        let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("option.wasm")), component(wit, &wat)).unwrap();
        let value = if option { json!(7) } else { json!(null) };
        let plan = Plan::parse(&json!({"test:faults/data#get":{"return":value}}).to_string()).unwrap();
        let base = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
        assert_eq!(base.outcome.kind, OutcomeKind::Ok);
        let mut cursor = Cursor::default();
        assert_eq!(std::iter::from_fn(|| cursor.next(&app, &base, None)).count(), if option { 2 } else { 1 });
        let (probes, found, complete) = faults::probe(&app, &base, None, 4, &|s| app.run(s));
        assert!(complete && probes.iter().all(|p| p.injected));
        assert!(!found.iter().any(|f| f.kind == "crash"));
        if !option {
            assert_eq!(probes[0].outcome, OutcomeKind::HostTrap);
        }
    }
}
