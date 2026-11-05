use appfuzz_core::{detect, harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
use serde_json::json;

const PAGE: u64 = 65_536;

fn app(wat: &str, memory: u64) -> App {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("resources.wasm"));
    manifest.limits.memory = memory;
    App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap()
}

fn two_memories(grow: bool) -> String {
    let grow = if grow { "(drop (memory.grow (i32.const 1)))" } else { "" };
    format!(
        r#"(component
          (core module $a (memory 1 2) (func (export "run") (result i32) {grow} (memory.size)))
          (core module $b (memory 1 2) (func (export "run") (result i32) {grow} (memory.size)))
          (core module $sum
            (import "a" "run" (func $a (result i32)))
            (import "b" "run" (func $b (result i32)))
            (func (export "run") (result i32) (i32.add (call $a) (call $b))))
          (core instance $a (instantiate $a))
          (core instance $b (instantiate $b))
          (core instance $sum (instantiate $sum (with "a" (instance $a)) (with "b" (instance $b))))
          (func (export "run") (result u32) (canon lift (core func $sum "run"))))"#,
    )
}

#[test]
fn peak_memory_counts_every_memory_in_the_component() {
    let app = app(&two_memories(false), PAGE);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(2)));
    assert_eq!(run.totals.peak_memory, 2 * PAGE);
    assert!(detect::per_run(&run, &app.manifest).iter().any(|f| f.kind == "over_budget" && f.detail["limit"] == "memory"));
}

#[test]
fn runtime_memory_cap_applies_to_the_sum_of_memories() {
    let app = app(&two_memories(true), 4 * PAGE);
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = 3 * PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(3)), "the second grow must fail once the component has three pages");
    assert_eq!(run.totals.peak_memory, 3 * PAGE);
}

#[test]
fn failed_growth_past_the_memory_maximum_does_not_inflate_peak_usage() {
    let app = app(
        r#"(component
          (core module $m (memory 1 1)
            (func (export "run") (result i32) (drop (memory.grow (i32.const 1))) (memory.size)))
          (core instance $m (instantiate $m))
          (func (export "run") (result u32) (canon lift (core func $m "run"))))"#,
        96 * 1024,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(1)));
    assert_eq!(run.totals.peak_memory, PAGE);
    assert!(!detect::per_run(&run, &app.manifest).iter().any(|f| f.kind == "over_budget"));
}

#[test]
fn successful_growth_is_preserved_when_a_later_growth_fails() {
    let app = app(
        r#"(component
          (core module $m (memory 1 2)
            (func (export "run") (result i32)
              (drop (memory.grow (i32.const 1)))
              (drop (memory.grow (i32.const 1))) (memory.size)))
          (core instance $m (instantiate $m))
          (func (export "run") (result u32) (canon lift (core func $m "run"))))"#,
        4 * PAGE,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(2)));
    assert_eq!(run.totals.peak_memory, 2 * PAGE);
}

#[test]
fn an_explicit_run_cap_can_exceed_the_default_pool_sizing() {
    let app = app(
        r#"(component
          (core module $m (memory 1 8)
            (func (export "run") (result i32) (drop (memory.grow (i32.const 5))) (memory.size)))
          (core instance $m (instantiate $m))
          (func (export "run") (result u32) (canon lift (core func $m "run"))))"#,
        PAGE,
    );
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = 8 * PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(6)));
    assert_eq!(run.totals.peak_memory, 6 * PAGE);
}

#[test]
fn memory64_allocations_are_metered() {
    let app = app(
        r#"(component
          (core module $m (memory i64 1 4)
            (func (export "run") (result i32) (drop (memory.grow (i64.const 1))) (i32.wrap_i64 (memory.size))))
          (core instance $m (instantiate $m))
          (func (export "run") (result u32) (canon lift (core func $m "run"))))"#,
        PAGE,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(2)));
    assert_eq!(run.totals.peak_memory, 2 * PAGE);
}

#[test]
fn imported_memory_aliases_are_counted_once() {
    let app = app(
        r#"(component
      (core module $owner (memory (export "memory") 1 4))
      (core module $user (import "owner" "memory" (memory 1 4))
        (func (export "run") (result i32) (drop (memory.grow (i32.const 1))) (memory.size)))
      (core module $sum
        (import "a" "run" (func $a (result i32)))
        (import "b" "run" (func $b (result i32)))
        (func (export "run") (result i32) (i32.add (call $a) (call $b))))
      (core instance $owner (instantiate $owner))
      (core instance $a (instantiate $user (with "owner" (instance $owner))))
      (core instance $b (instantiate $user (with "owner" (instance $owner))))
      (core instance $sum (instantiate $sum (with "a" (instance $a)) (with "b" (instance $b))))
      (func (export "run") (result u32) (canon lift (core func $sum "run"))))"#,
        2 * PAGE,
    );
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = 2 * PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(4)));
    assert_eq!(run.totals.peak_memory, 2 * PAGE);
}

#[test]
fn allocator_pooling_does_not_reject_multiple_memories_in_one_module() {
    let app = app(
        r#"(component
      (core module $m (memory $a 1) (memory $b 1)
        (func (export "run") (result i32) (i32.add (memory.size $a) (memory.size $b))))
      (core instance $m (instantiate $m))
      (func (export "run") (result u32) (canon lift (core func $m "run"))))"#,
        3 * PAGE,
    );
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(2)));
    assert_eq!(run.totals.peak_memory, 2 * PAGE);
}

#[test]
fn allocator_pooling_does_not_reject_nine_tiny_tables() {
    let mut wat = String::from("(component (core module $m");
    for _ in 0..9 {
        wat.push_str("(table 1 funcref)");
    }
    wat.push_str("(func (export \"run\") (result i32) (i32.const 9)))");
    wat.push_str("(core instance $m (instantiate $m)) (func (export \"run\") (result u32) (canon lift (core func $m \"run\"))))");
    let app = app(&wat, PAGE);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(9)));
}

#[test]
fn allocator_pooling_does_not_reject_twenty_tiny_core_instances() {
    let mut wat = String::from("(component");
    for index in 0..20 {
        wat.push_str(&format!("(core module $m{index} (func (export \"run\") (result i32) (i32.const {index})))"));
        wat.push_str(&format!("(core instance $i{index} (instantiate $m{index}))"));
    }
    wat.push_str("(func (export \"run\") (result u32) (canon lift (core func $i19 \"run\"))))");
    let app = app(&wat, PAGE);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(19)));
}

#[test]
fn allocator_pooling_does_not_reject_five_small_memories() {
    let mut wat = String::from("(component");
    for index in 0..5 {
        wat.push_str(&format!("(core module $m{index} (memory 1) (func (export \"run\") (result i32) (memory.size)))"));
        wat.push_str(&format!("(core instance $i{index} (instantiate $m{index}))"));
    }
    wat.push_str("(func (export \"run\") (result u32) (canon lift (core func $i4 \"run\"))))");
    let app = app(&wat, 8 * PAGE);
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.totals.peak_memory, 5 * PAGE);
}

#[test]
fn shared_memory_cannot_silently_bypass_the_runtime_cap() {
    let mut manifest = Manifest::for_wasm(std::path::Path::new("shared.wasm"));
    manifest.limits.memory = PAGE;
    let bytes = wat::parse_str(
        r#"(component
      (core module $m (memory 1 2 shared)
        (func (export "run") (result i32) (drop (memory.grow (i32.const 1))) (memory.size)))
      (core instance $m (instantiate $m))
      (func (export "run") (result u32) (canon lift (core func $m "run"))))"#,
    )
    .unwrap();
    let app = match App::from_bytes(manifest, bytes) {
        Ok(app) => app,
        Err(error) => {
            eprintln!("shared memory rejected: {error:#}");
            let message = format!("{error:#}");
            assert!(message.contains("shared") && (message.contains("cannot meter") || message.contains("not supported")), "{message}");
            return;
        }
    };
    let mut spec = app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1);
    spec.memory = PAGE;
    let run = app.run(&spec);
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    assert_eq!(run.result, Some(json!(1)), "shared growth must be bounded too");
    assert_eq!(run.totals.peak_memory, PAGE);
}
