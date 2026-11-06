use appfuzz_core::{
    detect,
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::json;

fn app(version: &str, export: &str, body: &str, with_code: bool) -> App {
    app_with_start(version, export, body, with_code, "")
}
fn app_with_start(version: &str, export: &str, body: &str, with_code: bool, start: &str) -> App {
    let import = if with_code {
        "(export \"exit-with-code\" (func (param \"status-code\" u8)))"
    } else {
        "(type $status (result)) (export \"exit\" (func (param \"status\" $status)))"
    };
    let import_name = if with_code { "exit-with-code" } else { "exit" };
    let bytes = wat::parse_str(format!(
        r#"(component
        (import "wasi:cli/exit@{version}" (instance $exit {import}))
        (core func $exit (canon lower (func $exit "{import_name}")))
        (core module $m (import "host" "exit" (func $exit (param i32)))
            (func $init {start}) (start $init)
            (func (export "run") (result i32) {body}))
        (core instance $m (instantiate $m (with "host" (instance (export "exit" (func $exit))))))
        (func $run (result (result)) (canon lift (core func $m "run")))
        (instance $cli (export "run" (func $run)))
        (export "{export}" (instance $cli))
        (export "custom" (func $run)))"#
    ))
    .unwrap();
    App::from_bytes(Manifest::for_wasm(std::path::Path::new("command.wasm")), bytes).unwrap()
}
fn run(app: &App, export: &str) -> RunRecord {
    app.run(&app.spec(app.export(export).unwrap(), vec![], Plan::default(), 1))
}

#[test]
fn wasi_command_successful_exit_matches_a_successful_return() {
    for version in ["0.2.0", "0.2.9", "0.2.12"] {
        let app = app(version, &format!("wasi:cli/run@{version}"), "(call $exit (i32.const 0)) unreachable", false);
        let record = run(&app, "wasi:cli/run#run");
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{version}: {:?}", record.outcome);
        assert_eq!(record.result, Some(json!({"ok":null})));
        assert_eq!(record.command_exit_code, Some(0));
        assert!(!detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "crash"));
    }
}

#[test]
fn wasi_command_successful_exit_with_code_is_not_a_crash() {
    let app = app("0.2.12", "wasi:cli/run@0.2.12", "(call $exit (i32.const 0)) unreachable", true);
    let record = run(&app, "wasi:cli/run#run");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"ok":null})));
}

#[test]
fn an_arbitrary_export_still_owes_its_declared_return_value() {
    let app = app("0.2.12", "wasi:cli/run@0.2.12", "(call $exit (i32.const 0)) unreachable", false);
    let record = run(&app, "custom");
    assert_eq!(record.outcome.kind, OutcomeKind::Trap);
    assert_eq!(record.result, None);
}

#[test]
fn command_normal_return_keeps_its_typed_result() {
    for (body, result) in [("(i32.const 0)", json!({"ok":null})), ("(i32.const 1)", json!({"err":null}))] {
        let app = app("0.2.12", "wasi:cli/run@0.2.12", body, false);
        let record = run(&app, "wasi:cli/run#run");
        assert_eq!(record.outcome.kind, OutcomeKind::Ok);
        assert_eq!(record.command_exit_code, Some(if result.get("ok").is_some() { 0 } else { 1 }));
        let failures = detect::per_run(&record, &app.manifest).into_iter().filter(|f| f.kind == "command_failed").count();
        assert_eq!(failures, usize::from(result.get("err").is_some()));
        assert_eq!(record.result, Some(result));
    }
}

#[test]
fn wasi_command_failure_exit_keeps_the_declared_failure_channel() {
    let app = app("0.2.12", "wasi:cli/run@0.2.12", "(call $exit (i32.const 1)) unreachable", false);
    let record = run(&app, "wasi:cli/run#run");
    assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
    assert_eq!(record.result, Some(json!({"err":null})));
    let findings = detect::per_run(&record, &app.manifest);
    assert!(!findings.iter().any(|f| f.kind == "crash"));
    assert!(findings.iter().any(|f| f.kind == "command_failed"));
}

#[test]
fn command_exit_codes_and_typed_failures_survive_storage_and_trace_conversion() {
    for code in [0, 1, 7, 255] {
        let app = app("0.2.12", "wasi:cli/run@0.2.12", &format!("(call $exit (i32.const {code})) unreachable"), true);
        let record = run(&app, "wasi:cli/run#run");
        assert_eq!(record.command_exit_code, Some(code));
        assert_eq!(record.result, Some(if code == 0 { json!({"ok":null}) } else { json!({"err":null}) }));
        let wire = serde_json::to_value(&record).unwrap();
        let restored: RunRecord = serde_json::from_value(wire.clone()).unwrap();
        let trace: appfuzz_core::envelope::Trace = serde_json::from_value(wire).unwrap();
        assert_eq!(restored.command_exit_code, Some(code));
        assert_eq!(trace.to_record().command_exit_code, Some(code));
        let findings = detect::per_run(&trace.to_record(), &app.manifest);
        if code != 0 {
            let failure = findings.iter().find(|f| f.kind == "command_failed").unwrap();
            assert_eq!(failure.detail["exit_code"], code);
            assert_eq!(failure.evidence(), "measured");
        } else {
            assert!(!findings.iter().any(|f| f.kind == "command_failed"));
        }
    }
}

#[test]
fn a_command_exit_during_initialization_is_a_terminal_status() {
    for code in [0, 7] {
        let app = app_with_start("0.2.12", "wasi:cli/run@0.2.12", "unreachable", true, &format!("(call $exit (i32.const {code}))"));
        let record = run(&app, "wasi:cli/run#run");
        assert_eq!(record.outcome.kind, OutcomeKind::Ok, "{:?}", record.outcome);
        assert_eq!(record.command_exit_code, Some(code));
        assert_eq!(record.result, Some(if code == 0 { json!({"ok":null}) } else { json!({"err":null}) }));
    }
}

#[test]
fn ordinary_command_traps_are_still_crashes() {
    let app = app("0.2.12", "wasi:cli/run@0.2.12", "unreachable", false);
    let record = run(&app, "wasi:cli/run#run");
    assert_eq!(record.outcome.kind, OutcomeKind::Unreachable);
    assert_eq!(record.command_exit_code, None);
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "crash"));
}

#[test]
fn lookalike_interface_names_do_not_enable_command_exit_handling() {
    let app = app("0.2.12", "test:cli/run@0.2.12", "(call $exit (i32.const 0)) unreachable", false);
    let record = run(&app, "test:cli/run#run");
    assert_eq!(record.outcome.kind, OutcomeKind::Trap);
    assert_eq!(record.command_exit_code, None);
}

#[test]
fn command_names_with_the_wrong_signature_do_not_synthesize_results() {
    let bytes = wat::parse_str(
        r#"(component
        (import "wasi:cli/exit@0.2.12" (instance $exit (type $status (result)) (export "exit" (func (param "status" $status)))))
        (core func $exit (canon lower (func $exit "exit")))
        (core module $m (import "host" "exit" (func $exit (param i32))) (func (export "run") (result i32) (call $exit (i32.const 0)) unreachable))
        (core instance $m (instantiate $m (with "host" (instance (export "exit" (func $exit))))))
        (func $run (result u32) (canon lift (core func $m "run")))
        (instance $cli (export "run" (func $run))) (export "wasi:cli/run@0.2.12" (instance $cli)))"#,
    )
    .unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("wrong-command.wasm")), bytes).unwrap();
    let record = run(&app, "wasi:cli/run#run");
    assert_eq!(record.outcome.kind, OutcomeKind::Trap);
    assert_eq!(record.command_exit_code, None);
    assert_eq!(record.result, None);
}

#[test]
fn an_http_handler_exit_still_fails_without_a_response_even_if_a_command_is_exported() {
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/wit/http")).unwrap();
    let pkg = resolve
        .push_str("test.wit", "package test:exit; world app {import wasi:cli/exit@0.2.12;export wasi:http/incoming-handler@0.2.12;export wasi:cli/run@0.2.12;}")
        .unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(
        r#"(module
        (import "wasi:cli/exit@0.2.12" "exit" (func $exit (param i32)))
        (memory (export "memory") 1)
        (func (export "wasi:http/incoming-handler@0.2.12#handle") (param i32 i32) (call $exit (i32.const 0)) unreachable)
        (func (export "wasi:cli/run@0.2.12#run") (result i32) (i32.const 0)))"#,
    )
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    let app = App::from_bytes(Manifest::for_wasm(std::path::Path::new("handler-exit.wasm")), bytes).unwrap();
    let export = app.export("wasi:http/incoming-handler#handle").unwrap();
    let args = app.default_args(export, "2026-11-02T10:00:00").unwrap();
    let record = app.run(&app.spec(export, args, Plan::default(), 1));
    assert_eq!(record.outcome.kind, OutcomeKind::Trap, "{:?}", record.outcome);
    assert_eq!(record.result, None);
    assert_eq!(record.command_exit_code, None);
    assert!(detect::per_run(&record, &app.manifest).iter().any(|f| f.kind == "crash"));
}
