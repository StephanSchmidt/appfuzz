use appfuzz_core::{detect, harness::App, manifest::Manifest, plan::Plan};
use serde_json::json;

fn app(dynamic: bool, status: u16) -> App {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve
        .push_str(
            "test.wit",
            r#"package test:owner;
        interface host {record entry {owner:string,item:string} current:func()->string;get:func()->entry;}
        world app {import host;record response {status:u16,body:string} export run:func()->response;}"#,
        )
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let pointer = if dynamic { "(i32.load (i32.const 1032))" } else { "(i32.const 0)" };
    let len = if dynamic { "(i32.load (i32.const 1036))" } else { "(i32.const 20)" };
    let mut module = wat::parse_str(format!(
        r#"(module
        (import "test:owner/host" "current" (func $current (param i32)))
        (import "test:owner/host" "get" (func $get (param i32)))
        (memory (export "memory") 1)
        (data (i32.const 0) "<p>No such order</p>")
        (global $heap (mut i32) (i32.const 4096))
        (func (export "cabi_realloc") (param i32 i32 i32) (param $size i32) (result i32) (local $p i32)
            (local.set $p (global.get $heap)) (global.set $heap (i32.add (local.get $p) (local.get $size))) (local.get $p))
        (func (export "run") (result i32)
            (call $current (i32.const 1040)) (call $get (i32.const 1024))
            (i32.store16 (i32.const 2048) (i32.const {status}))
            (i32.store (i32.const 2052) {pointer}) (i32.store (i32.const 2056) {len})
            (i32.const 2048)))"#
    ))
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    let mut m = Manifest::for_wasm(std::path::Path::new("owner.wasm"));
    m.entry = Some(serde_json::from_value(json!({"export":"run","output":{"status":"status","body":"body"}})).unwrap());
    m.functions.insert("test:owner/host#current".into(), serde_json::from_value(json!({"result":"identity"})).unwrap());
    m.functions.insert("test:owner/host#get".into(), serde_json::from_value(json!({"result":{"owner":"owner"}})).unwrap());
    App::from_bytes(m, bytes).unwrap()
}
fn run(app: &App) -> appfuzz_core::record::RunRecord {
    let plan = Plan::parse(r#"{"test:owner/host#current":{"return":"1001"},"test:owner/host#get":{"return":{"owner":"1002","item":"order"}}}"#).unwrap();
    app.run(&app.spec(app.export("run").unwrap(), vec![], plan, 1))
}
#[test]
fn a_static_not_found_page_is_not_a_foreign_record_leak() {
    for status in [200, 404] {
        let app = app(false, status);
        let record = run(&app);
        assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "missing_owner_check"));
        assert!(!detect::per_run_checked(&app, &record).iter().any(|f| f.kind == "missing_owner_check"));
    }
}
#[test]
fn an_actual_foreign_record_stays_a_finding_in_success_and_error_pages() {
    for status in [200, 404] {
        let app = app(true, status);
        let record = run(&app);
        assert!(detect::per_run_checked(&app, &record).iter().any(|f| f.kind == "missing_owner_check"));
    }
}
