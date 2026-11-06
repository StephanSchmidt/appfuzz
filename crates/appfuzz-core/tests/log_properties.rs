use appfuzz_core::{
    check::Property,
    harness::App,
    host_manifest::{HostManifest, merge},
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};

fn run(writes: &[(u32, &str)]) -> RunRecord {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let index = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("appfuzz-log-properties-{}-{index}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), "package test:logs; world plugin { export run:func()->string; }").unwrap();
    let host = HostManifest::parse("[platform]\nname='logs'\nabi='extism'\nwit='plugin.wit'", &dir).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("logs.wasm")), &Default::default()).unwrap();
    manifest.host = Some(std::sync::Arc::new(host));
    let mut data = String::new();
    let mut body = String::new();
    let mut at = 64;
    for (fd, text) in writes {
        let bytes = text.as_bytes().iter().map(|byte| format!("\\{byte:02x}")).collect::<String>();
        data.push_str(&format!("(data (i32.const {at}) \"{bytes}\")"));
        body.push_str(&format!(
            r#"(i32.store (i32.const 0) (i32.const {at}))
            (i32.store (i32.const 4) (i32.const {}))
            (drop (call $write (i32.const {fd}) (i32.const 0) (i32.const 1) (i32.const 16)))"#,
            text.len()
        ));
        at += text.len();
    }
    let bytes = wat::parse_str(format!(
        r#"(module
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1) {data}
        (func (export "run") (result i32) {body} (i32.const 0)))"#
    ))
    .unwrap();
    let app = App::from_bytes(manifest, bytes).unwrap();
    let run = app.run(&app.spec(app.export("run").unwrap(), vec![], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    run
}

fn forbidden(pattern: &str) -> Property {
    Property::parse(&["not_contains".into(), pattern.into()]).unwrap()
}

#[test]
fn stdout_and_stderr_are_checked_even_with_an_empty_response() {
    for fd in [1, 2] {
        let record = run(&[(fd, "panicked")]);
        assert_eq!(if fd == 1 { &record.stdout } else { &record.stderr }, "panicked");
        assert!(forbidden("panicked").broken(&record, &Manifest::for_wasm(std::path::Path::new("logs.wasm"))).is_some(), "fd {fd}");
    }
}

#[test]
fn unicode_log_text_is_checked_without_changing_the_capture() {
    let record = run(&[(1, "note: ☃\n")]);
    assert_eq!(record.stdout, "note: ☃\n");
    assert!(forbidden("☃").broken(&record, &Manifest::for_wasm(std::path::Path::new("logs.wasm"))).is_some());
}

#[test]
fn separate_streams_cannot_form_a_match_that_neither_contains() {
    let record = run(&[(1, "panic"), (2, "ked")]);
    assert!(forbidden("panicked").broken(&record, &Manifest::for_wasm(std::path::Path::new("logs.wasm"))).is_none());
}
