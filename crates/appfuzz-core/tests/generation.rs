use appfuzz_core::{harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
use serde_json::json;

fn app() -> App {
    app_for("record answer {single:f32,double:f64,wide:u64}")
}

fn app_for(definition: &str) -> App {
    let mut resolve = wit_parser::Resolve::new();
    let package = resolve
        .push_str(
            "generation.wit",
            &format!("package test:generation; interface data {{{definition} sample:func()->answer;}} world app {{import data;use data.{{answer}};export run:func()->answer;}}"),
        )
        .unwrap();
    let world = resolve.select_world(&[package], Some("app")).unwrap();
    let mut module = wat::parse_str(
        r#"(module
          (import "test:generation/data" "sample" (func $sample (param i32)))
          (memory (export "memory") 1)
          (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 4096))
          (func (export "run") (result i32) (call $sample (i32.const 0)) (i32.const 0)))"#,
    )
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("generation.wasm")), bytes).unwrap()
}

#[test]
fn explicit_constant_casts_preserve_wasm_integer_bits() {
    let app = app();
    for number in [-1i64, -100, i64::MIN, i64::MAX] {
        let plan = Plan::parse(&json!({"_defaults":{"generate":{"numbers":format!("cast:{number}")}}}).to_string()).unwrap();
        let run = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        let result = run.result.unwrap();
        assert_eq!(result["single"].as_f64().unwrap(), number as f32 as f64);
        assert_eq!(result["double"].as_f64().unwrap(), number as f64);
        assert_eq!(result["wide"].as_u64().unwrap(), number as u64);
    }
}

#[test]
fn fixed_values_check_only_payloads_that_the_configuration_can_generate() {
    for (definition, options, expected) in [
        ("type answer=option<u8>;", json!({"numbers":"=256","options":"none"}), json!(null)),
        ("type answer=result<u8,u64>;", json!({"numbers":"=256","results":"err"}), json!({"err":256})),
        ("type answer=list<u8>;", json!({"numbers":"=256","list_len":0}), json!([])),
    ] {
        let app = app_for(definition);
        let plan = Plan::parse(&json!({"_defaults":{"generate":options}}).to_string()).unwrap();
        let run = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{definition}: {:?}", run.outcome);
        assert_eq!(run.result, Some(expected));
    }
}

#[test]
fn numeric_generation_plans_reach_the_guest_and_replay_exactly() {
    let app = app();
    for number in ["13", "18446744073709551615"] {
        let plan = Plan::parse(&json!({"test:generation/data#sample":{"generate":{"numbers":format!("={number}")}}}).to_string()).unwrap();
        let spec = app.spec(app.export("run").unwrap(), vec![], plan, 1);
        let run = app.run(&spec);
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        let result = run.result.as_ref().unwrap();
        assert_eq!(result["single"].as_f64().unwrap(), number.parse::<f32>().unwrap() as f64);
        assert_eq!(result["double"].as_f64().unwrap(), number.parse::<f64>().unwrap());
        assert_eq!(result["wide"].as_u64().unwrap(), number.parse::<u64>().unwrap());
        let saved = serde_json::to_vec(&spec).unwrap();
        let replayed = app.run(&serde_json::from_slice(&saved).unwrap());
        assert_eq!(replayed.outcome.kind, OutcomeKind::Ok);
        assert_eq!(replayed.result, run.result);
        assert_eq!(replayed.events[0].result, run.events[0].result);
    }
}

#[test]
fn fixed_numbers_that_cannot_fit_the_host_result_are_plan_errors() {
    let app = app();
    for number in ["-1", "13.5", "1e100"] {
        let plan = Plan::parse(&json!({"_defaults":{"generate":{"numbers":format!("={number}")}}}).to_string()).unwrap();
        let run = app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1));
        assert_eq!(run.outcome.kind, OutcomeKind::PlanError, "{number}: {:?}", run.outcome);
        assert!(run.result.is_none());
        assert_eq!(run.events.len(), 1);
        assert!(run.events[0].trap.is_some());
    }
}

#[test]
fn floating_point_edge_responses_reach_the_guest() {
    let app = app();
    let plan = Plan::parse(r#"{"_defaults":{"generate":{"numbers":"edge"}}}"#).unwrap();
    let mut singles = Vec::new();
    let mut doubles = Vec::new();
    for seed in 0..64 {
        let run = app.run(&app.spec(app.export("run").unwrap(), vec![], plan.clone(), seed));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        let result = run.result.unwrap();
        singles.push(result["single"].as_f64().unwrap());
        doubles.push(result["double"].as_f64().unwrap());
    }
    assert!(singles.contains(&(f32::MIN as f64)));
    assert!(singles.contains(&(f32::MAX as f64)));
    assert!(doubles.contains(&f64::MIN));
    assert!(doubles.contains(&f64::MAX));
}
