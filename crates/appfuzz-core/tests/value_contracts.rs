use appfuzz_core::{detect, harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
use serde_json::{Value, json};

fn component(wit: &str, wat: &str) -> Vec<u8> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("values.wit", wit).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}
const WIT: &str =
    "package test:values; interface store { put:func(text:string,n:u64)->u32; } world app { import store; export run:func(text:string,n:u64)->u32; }";
const WAT: &str = r#"(module (import "test:values/store" "put" (func $put (param i32 i32 i64) (result i32)))
    (memory (export "memory") 8) (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
    (func (export "run") (param i32 i32 i64) (result i32) (call $put (local.get 0) (local.get 1) (local.get 2))))"#;
fn app(rules: &str) -> App {
    let m: Manifest =
        toml::from_str(&format!("[app]\nwasm='test.wasm'\n[functions.\"test:values/store#put\"]\neffect='write'\nparam_values={rules}\n")).unwrap();
    App::from_bytes(m, component(WIT, WAT)).unwrap()
}
fn run(app: &App, text: &str, n: u64) -> appfuzz_core::record::RunRecord {
    let plan = Plan::parse(r#"{"test:values/store#put":{"return":7}}"#).unwrap();
    app.run(&app.spec(app.export("run").unwrap(), vec![json!(text), json!(n)], plan, 1))
}
#[test]
fn host_arguments_are_checked_without_repair_or_changing_host_behavior() {
    let app = app("{ text='format:date',n='range:1..6' }");
    let r = run(&app, "0.0.0000", 7);
    assert_eq!(r.outcome.kind, OutcomeKind::Ok);
    assert_eq!(r.result, Some(json!(7)));
    assert_eq!(r.events[0].args["text"], "0.0.0000");
    assert_eq!(r.events[0].args["n"], 7);
    let found = detect::per_run(&r, &app.manifest).into_iter().filter(|f| f.kind == "invalid_host_argument").collect::<Vec<_>>();
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|f| f.evidence() == "policy_violation"));
    let good = run(&app, "2028-02-29", 6);
    assert!(good.events[0].value_checks.as_ref().unwrap().violations.is_empty());
    let again = run(&app, "0.0.0000", 7);
    assert_eq!(serde_json::to_value(r.events).unwrap(), serde_json::to_value(again.events).unwrap());
    let plain = appfuzz_core::harness::App::from_bytes(Manifest::for_wasm(std::path::Path::new("test.wasm")), component(WIT, WAT)).unwrap();
    assert!(run(&plain, "0.0.0000", 7).events[0].value_checks.is_none());
}
#[test]
fn full_lengths_and_uuid_syntax_are_checked_before_trace_compaction() {
    let a = app("{ text='bytes:..1100' }");
    let r = run(&a, &"é".repeat(600), 1);
    assert!(r.events[0].args["text"].as_str().unwrap().len() < 1100);
    let bad = &r.events[0].value_checks.as_ref().unwrap().violations[0];
    assert_eq!(bad.bytes, Some(1200));
    assert_eq!(bad.constraint, "bytes:..1100");
    let a = app("{ text='format:uuid' }");
    assert_eq!(run(&a, "0000-0000-0000-0000", 1).events[0].value_checks.as_ref().unwrap().violations.len(), 1);
    assert!(run(&a, "00000000-0000-0000-0000-000000000000", 1).events[0].value_checks.as_ref().unwrap().violations.is_empty());
}
#[test]
fn numeric_parameter_bounds_use_all_u64_bits_and_bad_declarations_fail_loading() {
    let a = app("{ n='range:18446744073709551614..18446744073709551614' }");
    assert!(run(&a, "x", u64::MAX - 1).events[0].value_checks.as_ref().unwrap().violations.is_empty());
    assert!(!run(&a, "x", u64::MAX).events[0].value_checks.as_ref().unwrap().violations.is_empty());
    for rule in ["{missing='format:date'}", "{n='format:date'}", "{ 'text.missing'='format:date' }"] {
        let m = toml::from_str(&format!("[app]\nwasm='x'\n[functions.\"test:values/store#put\"]\nparam_values={rule}")).unwrap();
        assert!(App::from_bytes(m, component(WIT, WAT)).is_err(), "{rule}");
    }
}
#[test]
fn nested_lists_optional_values_and_conjunctions_have_concrete_witness_paths() {
    let wit = "package test:values; interface store { record row { value:string } put:func(rows:list<row>,maybe:option<string>)->u32; } world app { import store; use store.{row}; export run:func(rows:list<row>,maybe:option<string>)->u32; }";
    let wat = r#"(module (import "test:values/store" "put" (func $put (param i32 i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 8) (global $heap (mut i32) (i32.const 4096))
    (func (export "cabi_realloc") (param i32 i32) (param $align i32) (param $size i32) (result i32) (local $p i32)
    (local.set $p (i32.and (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1))) (i32.sub (i32.const 0) (local.get $align))))
    (global.set $heap (i32.add (local.get $p) (local.get $size))) (local.get $p))
    (func (export "run") (param i32 i32 i32 i32 i32) (result i32) (call $put (local.get 0) (local.get 1) (local.get 2) (local.get 3) (local.get 4))))"#;
    let m = toml::from_str(
        "[app]\nwasm='x'\n[functions.\"test:values/store#put\"]\nparam_values={ 'rows.value'=['format:int','range:1..6'], rows='len:..2',maybe='format:date' }",
    )
    .unwrap();
    let a = App::from_bytes(m, component(wit, wat)).unwrap();
    let spec = a.spec(a.export("run").unwrap(), vec![json!([{"value":"7"}]), Value::Null], Plan::default(), 1);
    let r = a.run(&spec);
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    let bad = &r.events[0].value_checks.as_ref().unwrap().violations;
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].path, "rows.0.value");
    assert_eq!(bad[0].declaration, "rows.value");
    let mut spec = spec;
    spec.args = vec![json!([{"value":"6"}]), json!({"some":"2028-02-29"})];
    let r = a.run(&spec);
    assert_eq!(r.outcome.kind, OutcomeKind::Ok);
    assert!(r.events[0].value_checks.as_ref().unwrap().violations.is_empty(), "{:?}", r.events[0].value_checks);
    let ty = a.imports.iter().flat_map(|i| &i.funcs).find(|f| f.key == "test:values/store#put").unwrap().ty.params().nth(1).unwrap().1;
    let mut input_domain = appfuzz_core::value_contract::Domain::parse(vec!["format:date".into()]).unwrap();
    input_domain.validate_input_type(&ty, "").unwrap();
    assert!(input_domain.holds(Some(&json!({"some":"2028-02-29"}))));
    assert!(!input_domain.holds(Some(&json!({"some":"0.0.0000"}))));
}

#[test]
fn absent_optional_inputs_do_not_hide_other_invalid_fields() {
    let wit = "package test:values; world app { record request { form:list<tuple<string,string>> } export run:func(req:request)->u32; }";
    let wat = r#"(module (memory (export "memory") 8) (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 4096)) (func (export "run") (param i32 i32) (result i32) (i32.const 400)))"#;
    let m:Manifest=toml::from_str("[app]\nwasm='x'\n[entry]\nexport='run'\ninput_values={'form.date'='format:date','form.note'='len:..80'}\n[acceptance]\nversion=1\n[acceptance.checks.reject]\norigin='marketing'\ninput_class='invalid'\nexpect={selector='$',equals=400}\n").unwrap();
    let a = App::from_bytes(m, component(wit, wat)).unwrap();
    let check = &a.manifest.acceptance.as_ref().unwrap().checks["reject"];
    let mut spec = a.spec(a.export("run").unwrap(), vec![json!({"form":[["date","0.0.0000"]]})], Plan::default(), 1);
    assert_eq!(appfuzz_core::acceptance::evaluate(&a, check, &spec).unwrap().status, "holds");
    spec.args = vec![json!({"form":[]})];
    assert_eq!(appfuzz_core::acceptance::evaluate(&a, check, &spec).unwrap().status, "not_exercised");
    spec.args = vec![json!({"form":[["date","2028-02-29"]]})];
    let mut valid = check.clone();
    valid.input_class = Some(appfuzz_core::acceptance::InputClass::Valid);
    assert_eq!(appfuzz_core::acceptance::evaluate(&a, &valid, &spec).unwrap().status, "holds");
}

#[test]
fn declared_uuid_host_results_supply_valid_values_to_guest_calls() {
    let wit = "package test:values; interface source { get:func()->string; } interface sink { put:func(id:string)->u32; } world app {import source;import sink;export run:func()->u32;}";
    let wat = r#"(module
      (import "test:values/source" "get" (func $get (param i32)))
      (import "test:values/sink" "put" (func $put (param i32 i32) (result i32)))
      (memory (export "memory") 8)
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
      (func (export "run") (result i32) (call $get (i32.const 0))
      (call $put (i32.load (i32.const 0)) (i32.load (i32.const 4)))))"#;
    let m=toml::from_str("[app]\nwasm='x'\n[functions.\"test:values/source#get\"]\nvalues={''='format:uuid'}\n[functions.\"test:values/sink#put\"]\nparam_values={id='format:uuid'}\n").unwrap();
    let a = App::from_bytes(m, component(wit, wat)).unwrap();
    for seed in [1, 7, u64::MAX] {
        let r = a.run(&a.spec(a.export("run").unwrap(), vec![], Plan::default(), seed));
        assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
        assert_eq!(r.events[0].result.as_ref().unwrap(), &r.events[1].args["id"]);
        assert!(r.events[1].value_checks.as_ref().unwrap().violations.is_empty());
        assert_eq!(r.events[1].args["id"].as_str().unwrap().len(), 36);
    }
}

#[test]
fn optional_host_guarantees_constrain_the_present_payload() {
    let wit = "package test:values; interface source { get:func()->option<string>; } interface sink { put:func(id:string)->u32; } world app {import source;import sink;export run:func()->u32;}";
    let wat = r#"(module
      (import "test:values/source" "get" (func $get (param i32)))
      (import "test:values/sink" "put" (func $put (param i32 i32) (result i32)))
      (memory (export "memory") 8)
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
      (func (export "run") (result i32) (call $get (i32.const 0))
      (if (result i32) (i32.load (i32.const 0))
        (then (call $put (i32.load (i32.const 4)) (i32.load (i32.const 8))))
        (else (i32.const 0)))))"#;
    for format in ["uuid", "date"] {
        let m=toml::from_str(&format!("[app]\nwasm='x'\n[functions.\"test:values/source#get\"]\nvalues={{''='format:{format}'}}\n[functions.\"test:values/sink#put\"]\nparam_values={{id='format:{format}'}}\n")).unwrap();
        let a = App::from_bytes(m, component(wit, wat)).unwrap();
        let plan = Plan::parse(r#"{"test:values/source#get":{"return":{"some":"invalid"}}}"#).unwrap();
        let r = a.run(&a.spec(a.export("run").unwrap(), vec![], plan, 1));
        assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
        assert_eq!(&r.events[0].result.as_ref().unwrap()["some"], &r.events[1].args["id"]);
        assert!(r.events[1].value_checks.as_ref().unwrap().violations.is_empty(), "{format}");
    }
}
