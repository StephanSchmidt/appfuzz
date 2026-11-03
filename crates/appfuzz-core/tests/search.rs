//! Search improvements must produce evidence on the unmodified component.
use appfuzz_core::{
    fuzz::{self, FuzzOpts, Stage},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
    shrink,
};
use serde_json::{Value, json};

fn component(wit: &str, wat: &str) -> Vec<u8> {
    static POOL: std::sync::Once = std::sync::Once::new();
    POOL.call_once(|| rayon::ThreadPoolBuilder::new().num_threads(1).build_global().unwrap());

    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("search.wit", wit).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}

fn search(app: &App, args: Vec<Value>, plan: Plan, seed: u64, runs: u64) -> (fuzz::FuzzReport, fuzz::Corpus) {
    let base = app.spec(app.export("run").unwrap(), args, plan, 1);
    let opts = FuzzOpts { runs: Some(runs), time: None, discover: false, internal_feedback: false, seed, ..Default::default() };
    fuzz::fuzz(app, &base, vec![], Default::default(), &opts, &|_, _, _| {}).unwrap()
}

#[test]
fn structured_request_and_host_strings_reach_and_replay_the_original_crash() {
    // A small strict grammar accepts {"n":<one digit>}; only zero crashes.
    // The benchmark fixtures additionally exercise real serde_json/csv parsers.
    for from_host in [false, true] {
        let wit = if from_host {
            "package test:search; interface data { get:func() -> string; } world app { import data; export run:func() -> u32; }"
        } else {
            "package test:search; world app { export run:func(text:string) -> u32; }"
        };
        let import = if from_host { "(import \"test:search/data\" \"get\" (func $get (param i32)))" } else { "" };
        let signature = if from_host { "" } else { "(param i32 i32)" };
        let get = if from_host {
            "(call $get (i32.const 0)) (local.set $ptr (i32.load (i32.const 0))) (local.set $len (i32.load (i32.const 4)))"
        } else {
            "(local.set $ptr (local.get 0)) (local.set $len (local.get 1))"
        };
        let mut guard = "(i32.eq (local.get $len) (i32.const 7))".to_string();
        for (i, byte) in b"{\"n\":0}".iter().enumerate() {
            guard = format!("(i32.and {guard} (i32.eq (i32.load8_u offset={i} (local.get $ptr)) (i32.const {byte})))");
        }
        let wat = format!(
            r#"(module {import}
          (memory (export "memory") 4)
          (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
          (func (export "run") {signature} (result i32) (local $ptr i32) (local $len i32)
            {get} (if {guard} (then unreachable)) (i32.const 0)))"#
        );
        let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("payload.wasm")), component(wit, &wat)).unwrap();
        let text = r#"{"n":7}"#;
        let args = if from_host { vec![] } else { vec![json!(text)] };
        let plan = if from_host { Plan::parse(&json!({"test:search/data#get":{"return":text}}).to_string()).unwrap() } else { Plan::default() };
        // This checks discovery and replay, not a detection-rate target. Allow the
        // other scheduled stages their share of the campaign budget.
        let (report, corpus) = search(&app, args.clone(), plan, 7, 1000);
        let entry = corpus
            .entries
            .iter()
            .find(|e| e.stage == Stage::Structured && app.run(&e.spec).outcome.kind == OutcomeKind::Unreachable)
            .unwrap_or_else(|| panic!("structured stage must reach the crash: host={from_host}, stages={:?}", report.stages));
        let (small, _) = shrink::minimise(&app, &entry.spec, &args, &|r| r.outcome.kind == OutcomeKind::Unreachable, 100, &|s| app.run(s));
        let saved = serde_json::to_vec(&small).unwrap();
        let replay = serde_json::from_slice(&saved).unwrap();
        assert_eq!(app.run(&replay).outcome.kind, OutcomeKind::Unreachable);
        if from_host {
            assert!(app.run(&replay).events.iter().any(|e| e.result.as_ref().and_then(Value::as_str) == Some(r#"{"n":0}"#)));
        } else {
            assert_eq!(small.args, vec![json!(r#"{"n":0}"#)]);
        }
    }
}

#[test]
fn fuzz_finds_cost_above_every_individual_axis_and_shrinks_both() {
    let wit = "package test:search; interface data { get:func(id:u32) -> u32; } world app { import data; record axes { x:u32,y:u32 } export run:func(input:axes) -> u32; }";
    let wat = r#"(module
      (import "test:search/data" "get" (func $get (param i32) (result i32)))
      (func (export "run") (param $x i32) (param $y i32) (result i32) (local $i i32)
        (block $done (loop $loop
          (br_if $done (i32.ge_u (local.get $i) (i32.mul (local.get $x) (local.get $y))))
          (drop (call $get (local.get $i)))
          (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $loop)))
        (i32.const 0)))"#;
    let mut manifest = Manifest::for_wasm(std::path::Path::new("joint.wasm"));
    manifest.entry = Some(toml::from_str("export='run'\nrequest={x=1,y=1}\nvalues={x='range:1..16',y='range:1..16'}").unwrap());
    manifest.limits.cost_per_request = Some(100);
    manifest.limits.fuel = 50000;
    let app = App::from_bytes(manifest, component(wit, wat)).unwrap();
    for args in [json!({"x":16,"y":1}), json!({"x":1,"y":16})] {
        assert_eq!(app.run(&app.spec(app.export("run").unwrap(), vec![args], Plan::default(), 1)).totals.cost, 16);
    }
    for seed in [1, 7, 19] {
        let base = vec![json!({"x":1,"y":1})];
        let (report, corpus) = search(&app, base.clone(), Plan::default(), seed, 300);
        assert!(report.findings.iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "cost"));
        // Already-known failures need not be retained a second time by another stage.
        let entry =
            corpus.entries.iter().find(|e| appfuzz_core::constraints::broken_request(&e.spec.args, &app.manifest).is_empty() && app.run(&e.spec).totals.cost > 100).unwrap_or_else(
                || {
                    panic!(
                        "joint input missing seed={seed} stages={:?}",
                        report.stages
                    )
                },
            );
        let (small, _) = shrink::minimise(&app, &entry.spec, &base, &|r| r.totals.cost > 100 && r.outcome.kind == OutcomeKind::Ok, 300, &|s| app.run(s));
        assert!(app.run(&small).totals.cost > 100);
        for axis in ["x", "y"] {
            let mut lower = small.clone();
            let n = lower.args[0][axis].as_u64().unwrap();
            lower.args[0][axis] = json!(n - 1);
            assert!(app.run(&lower).totals.cost <= 100, "axis {axis} was not minimized: {:?}", small.args);
        }
    }
}

#[test]
fn fuzz_uses_original_fuel_and_memory_measurements() {
    let wit = "package test:search; world app { record axes { x:u32,y:u32 } export run:func(input:axes) -> u32; }";
    for metric in ["fuel", "memory"] {
        let body = if metric == "memory" {
            "(drop (memory.grow (i32.mul (local.get 0) (local.get 1))))"
        } else {
            "(local.set $i (i32.mul (local.get 0) (local.get 1))) (loop $spin (local.set $i (i32.sub (local.get $i) (i32.const 1))) (br_if $spin (local.get $i)))"
        };
        let wat = format!("(module (memory (export \"memory\") 1) (func (export \"run\") (param i32 i32) (result i32) (local $i i32) {body} (i32.const 0)))");
        let mut manifest = Manifest::for_wasm(std::path::Path::new("resources.wasm"));
        manifest.entry = Some(toml::from_str("export='run'\nrequest={x=1,y=1}\nvalues={x='range:1..8',y='range:1..8'}").unwrap());
        manifest.limits.fuel = if metric == "fuel" { 100 } else { 100_000 };
        manifest.limits.memory = 10 * 65536;
        let app = App::from_bytes(manifest, component(wit, &wat)).unwrap();
        let (report, corpus) = search(&app, vec![json!({"x":1,"y":1})], Plan::default(), 19, 300);
        assert!(report.findings.iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == metric), "{report:?}");
        assert!(corpus.entries.iter().any(|e| {
            let r = app.run(&e.spec);
            if metric == "fuel" { r.totals.fuel > 100 } else { r.totals.peak_memory > 10 * 65536 }
        }));
    }
}
