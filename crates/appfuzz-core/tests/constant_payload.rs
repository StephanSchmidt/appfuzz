//! A payload from the app's own binary does not need a request or host source.
use appfuzz_core::{detect, harness::App, manifest::Manifest, plan::Plan, record::OutcomeKind};
use serde_json::json;

const BLOB: &str = "ZXhmaWw6YWdlbnQtNDIgLT4gYWdlbnQtNzogaGFuZG9mZiByZWFkeQ";

#[test]
fn constant_external_payloads_do_not_depend_on_unrelated_request_text() {
    let bytes = wat::parse_str(format!(
        r#"(component
        (import "test:payload/store" (instance $store (export "send" (func (param "value" string)))))
        (core module $mem
            (memory (export "memory") 1)
            (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 4096)))
        (core instance $mem (instantiate $mem))
        (alias core export $mem "memory" (core memory $memory))
        (alias core export $mem "realloc" (core func $realloc))
        (core func $send (canon lower (func $store "send") (memory $memory)))
        (core module $guest
            (import "env" "memory" (memory 1))
            (import "env" "send" (func $send (param i32 i32)))
            (data (i32.const 128) "{BLOB}")
            (func (export "run") (param i32 i32) (call $send (i32.const 128) (i32.const {len}))))
        (core instance $guest (instantiate $guest (with "env" (instance (export "memory" (memory $memory)) (export "send" (func $send))))))
        (func (export "run") (param "input" string) (canon lift (core func $guest "run") (memory $memory) (realloc $realloc))))"#,
        len = BLOB.len()
    ))
    .unwrap();
    let manifest: Manifest = toml::from_str("[app]\nwasm='a.wasm'\n[functions.\"test:payload/store#send\"]\neffect='external'\n").unwrap();
    let app = App::from_bytes(manifest, bytes).unwrap();
    let mut outcomes = Vec::new();
    for (input, expected) in [("", true), ("ordinary-request", true), (BLOB, false)] {
        let r = app.run(&app.spec(app.export("run").unwrap(), vec![json!(input)], Plan::default(), 1));
        assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.events[0].args["value"], BLOB);
        let found = detect::per_run(&r, &app.manifest).iter().any(|f| f.kind == "constant_payload");
        outcomes.push((input, found, expected));
        let mut no_effect = app.manifest.clone();
        no_effect.functions.clear();
        assert!(detect::per_run(&r, &no_effect).iter().all(|f| f.kind != "constant_payload"));
    }
    assert!(outcomes.iter().all(|(_, found, expected)| found == expected), "{outcomes:?}");
}
