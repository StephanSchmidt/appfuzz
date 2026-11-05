use appfuzz_core::{detect, harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
use serde_json::json;

const TWO_MIB: u64 = 2 * 1024 * 1024;

fn app(oversize_after: bool) -> App {
    let next = if oversize_after { "(drop (array.new_default $bytes (i32.const -1)))" } else { "" };
    let wat = format!(
        r#"(component
      (core module $m
        (type $bytes (array (mut i8)))
        (global $hold (mut (ref null $bytes)) (ref.null $bytes))
        (func (export "run") (result i32)
          (global.set $hold (array.new_default $bytes (i32.const 2097152)))
          {next}
          (array.len (global.get $hold))))
      (core instance $m (instantiate $m))
      (func (export "run") (result u32) (canon lift (core func $m "run"))))"#
    );
    let mut manifest = Manifest::for_wasm(std::path::Path::new("gc-memory.wasm"));
    // Leave room for GC metadata and collector overhead.
    manifest.limits.memory = 2 * 1024 * 1024;
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn gc_heap_growth_is_counted_in_the_memory_budget() {
    let app = app(false);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(TWO_MIB)));
    assert!(run.totals.peak_memory >= TWO_MIB, "{:?}", run.totals);
    assert!(detect::per_run(&run, &app.manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "memory"));
}

#[test]
fn gc_heap_growth_respects_an_explicit_run_cap() {
    let app = app(false);
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = 32 * 1024;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::OutOfMemory, "{:?}", run.outcome);
    assert!(run.totals.peak_memory <= spec.memory);
}

#[test]
fn an_oversized_gc_array_does_not_erase_existing_memory_usage() {
    let app = app(true);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_ne!(run.outcome.kind, OutcomeKind::Ok);
    assert!(run.totals.peak_memory >= TWO_MIB, "{:?}; {:?}", run.outcome, run.totals);
}
