//! Black-box search tests: findings must execute on the original component.
use appfuzz_core::{
    fuzz::{self, FuzzOpts},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
fn component(wit: &str, wat: &str) -> Vec<u8> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("feedback.wit", wit).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}
fn app(wit: &str, wat: &str) -> App {
    static POOL: std::sync::Once = std::sync::Once::new();
    POOL.call_once(|| {
        rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap();
    });
    let mut manifest = Manifest::for_wasm(Path::new("test.wasm"));
    manifest.limits.fuel = 100_000;
    App::from_bytes(manifest, component(wit, wat)).unwrap()
}
fn numeric() -> App {
    app(
        "package test:feedback; world app { record input { x:u32, y:u32 } export run: func(request:input) -> u32; }",
        r#"
    (module (func (export "run") (param i32 i32) (result i32)
      (if (i32.eq (local.get 0) (i32.xor (i32.const 921837) (i32.const 312973)))
        (then (if (i32.eq (local.get 1) (i32.xor (i32.const 734873) (i32.const 198371))) (then unreachable))))
      (i32.const 0)))"#,
    )
}
fn text() -> App {
    let target = b"K7p";
    let mut body = String::new();
    body.push_str("(local.set 2 (i32.const 1))");
    for (offset, b) in target.iter().enumerate() {
        body.push_str(&format!(
            "(local.set 2 (i32.and (local.get 2) (i32.eq (i32.load8_u offset={offset} (local.get 0)) (i32.xor (i32.const {}) (i32.const 375841)))))",
            375841 ^ (*b as i32)
        ));
    }
    app(
        "package test:feedback; world app { export run: func(text:string) -> u32; }",
        &format!(
            r#"
    (module (memory (export "memory") 4)
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
      (func (export "run") (param i32 i32) (result i32) (local i32)
        (if (i32.eq (local.get 1) (i32.const 3)) (then {body} (if (local.get 2) (then unreachable))))
        (i32.const 0)))"#
        ),
    )
}
fn campaign(
    app: &App,
    args: Vec<Value>,
    internal: bool,
    seed: u64,
    runs: u64,
    time: Option<Duration>,
) -> (fuzz::FuzzReport, Vec<appfuzz_core::record::RunSpec>) {
    let base = app.spec(app.export("run").unwrap(), args, Plan::default(), 1);
    let hits = Mutex::new(Vec::new());
    let opts = FuzzOpts { runs: Some(runs), time, seed, discover: false, internal_feedback: internal, ..Default::default() };
    let on_run = |r: &appfuzz_core::record::RunRecord, _kept: bool, findings: &[appfuzz_core::detect::Finding]| {
        if findings.iter().any(|f| f.kind == "crash") {
            hits.lock().unwrap().push(r.spec.clone());
        }
    };
    let (report, _corpus) = fuzz::fuzz(app, &base, vec![], Default::default(), &opts, &on_run).unwrap();
    (report, hits.into_inner().unwrap())
}
#[test]
fn comparisons_find_computed_guards_and_original_binary_confirms_the_crash() {
    let app = numeric();
    let (report, hits) = campaign(&app, vec![json!({"x":0,"y":0})], true, 1, 500, None);
    assert_eq!(report.feedback.mode, "internal", "{:?}", report.feedback);
    assert_eq!(report.feedback.discarded_runs, 0, "{:?}", report.feedback);
    assert!(!hits.is_empty(), "{}", serde_json::to_string(&report).unwrap());
    for spec in hits {
        assert_eq!(spec.component, app.hash);
        assert_eq!(app.run(&spec).outcome.kind, OutcomeKind::Unreachable);
    }
}
#[test]
fn byte_comparisons_find_a_string_guard_without_an_embedded_keyword() {
    let app = text();
    let (report, hits) = campaign(&app, vec![json!("aaa")], true, 3, 2000, None);
    assert!(!hits.is_empty(), "{}", serde_json::to_string(&report).unwrap());
    assert!(hits.iter().all(|s| app.run(s).outcome.kind == OutcomeKind::Unreachable));
}
#[test]
#[ignore = "timed A/B experiment; run alone with --nocapture"]
fn compare_equal_budgets() {
    for (name, app, args) in [("computed-numeric", numeric(), vec![json!({"x":0,"y":0})]), ("computed-bytes", text(), vec![json!("aaa")])] {
        for seed in [1, 7, 19] {
            for internal in [false, true] {
                let start = Instant::now();
                let (report, hits) = campaign(&app, args.clone(), internal, seed, 1000, None);
                println!(
                    "{}",
                    json!({"fixture":name,"seed":seed,"internal":internal,"budget":"1000 evaluations","runs":report.runs,"crashes":hits.len(),"elapsed_ms":start.elapsed().as_millis(),"feedback":report.feedback})
                );
            }
        }
        for seed in [1, 7, 19] {
            for internal in [false, true] {
                let start = Instant::now();
                let (report, hits) = campaign(&app, args.clone(), internal, seed, 1_000_000, Some(Duration::from_secs(1)));
                println!(
                    "{}",
                    json!({"fixture":name,"seed":seed,"internal":internal,"budget":"1 second including feedback setup","runs":report.runs,"crashes":hits.len(),"elapsed_ms":start.elapsed().as_millis(),"feedback":report.feedback})
                );
            }
        }
    }
}

#[test]
fn opaque_nested_components_report_fallback_and_keep_fuzzing_original() {
    let bytes = wat::parse_str(
        r#"(component
      (component $inner
        (core module $m (func (export "run") (param i32) (result i32) local.get 0))
        (core instance $i (instantiate $m))
        (alias core export $i "run" (core func $run))
        (type $t (func (param "n" u32) (result u32)))
        (func (export "run") (type $t) (canon lift (core func $run))))
      (instance $instance (instantiate $inner))
      (alias export $instance "run" (func $run))
      (export "run" (func $run)))"#,
    )
    .unwrap();
    let app = App::from_bytes(Manifest::for_wasm(Path::new("nested.wasm")), bytes).unwrap();
    let (report, _) = campaign(&app, vec![json!(1)], true, 1, 10, None);
    assert_eq!(report.feedback.mode, "boundary");
    assert!(report.feedback.unavailable.as_deref().unwrap().contains("nested component"));
    assert!(report.runs > 0);
}
