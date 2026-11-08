//! Byte bodies cross the real browser component ABI and the app entry ABI.
use appfuzz_core::{
    browser::{Browser, FETCH_OTHER, FETCH_OWN, SESSION, request_for_bytes},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};
use std::sync::Arc;

fn report(run: &RunRecord) -> Value {
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    report
}
fn visit(script: &str, body: &[u8], headers: Value) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/", "html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = Plan::parse(
        &json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":headers,"body":body}}},FETCH_OTHER:{"return":{"ok":{"status":200,"headers":[],"body":[]}}}})
            .to_string(),
    )
    .unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    let report = report(&run);
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    (run, report)
}
fn logs(report: &Value) -> Vec<&str> {
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect()
}
#[test]
fn binary_fetch_body_and_response_preserve_every_byte_on_the_component_wire() {
    let bytes = [255, 0, 128, 195, 169];
    let (run, report) = visit(
        "fetch('/bytes',{method:'POST',body:new Uint8Array([255,0,128,195,169])}).then(async r=>{console.log(r.type,Array.from(new Uint8Array(await r.arrayBuffer())).join(','))})",
        &bytes,
        json!([]),
    );
    assert_eq!(logs(&report), ["basic 255,0,128,195,169"]);
    let event = run.events.iter().find(|event| event.func == FETCH_OWN).unwrap();
    assert_eq!(event.args["body"], json!({"some":bytes}));
    assert_eq!(event.result.as_ref().unwrap()["ok"]["body"], json!(bytes));
}
#[test]
fn multipart_file_bytes_are_not_utf8_reencoded() {
    let (run, report) = visit(
        "const form=new FormData();form.append('upload',new File([new Uint8Array([255,0,128])],'bytes.bin'));fetch('/upload',{method:'POST',body:form}).then(r=>r.text()).then(console.log)",
        b"ok",
        json!([]),
    );
    assert_eq!(logs(&report), ["ok"]);
    let event = run.events.iter().find(|event| event.func == FETCH_OWN).unwrap();
    let body = event.args["body"]["some"].as_array().unwrap();
    let bytes: Vec<u8> = body.iter().map(|n| n.as_u64().unwrap() as u8).collect();
    assert!(bytes.windows(3).any(|part| part == [255, 0, 128]), "{bytes:?}");
    assert!(bytes.windows(9).any(|part| part == b"bytes.bin"));
}
#[test]
fn response_decoding_and_blob_mime_use_the_fetched_bytes_and_headers() {
    let (_, report) = visit(
        "fetch('/bytes').then(async r=>{const clone=r.clone();console.log(JSON.stringify(await r.text()));const b=await clone.blob();console.log(b.type,b.size,Array.from(await b.bytes()).join(','))})",
        &[239, 187, 191, 104, 105],
        json!([["content-type", "TeXt/Plain ; charset=\"UTF-8\""]]),
    );
    assert_eq!(logs(&report), ["\"hi\"", "text/plain;charset=utf-8 5 239,187,191,104,105"]);
}
#[test]
fn http_request_mapping_preserves_zero_bytes_and_existing_byte_list_shapes() {
    for base in
        [json!({"method":"GET","uri":"https://app.example/","headers":[],"body":""}), json!({"method":"GET","path":"/","query":[],"headers":[],"body":""})]
    {
        let request = request_for_bytes(&base, "POST", "/upload", &[], Some(&[255, 0, 128])).unwrap();
        assert_eq!(request["body"], json!([255, 0, 128]));
        let request = request_for_bytes(&base, "POST", "/upload", &[], Some(b"a\0b")).unwrap();
        assert_eq!(request["body"], json!("a\0b"));
        let mut byte_base = base;
        byte_base["body"] = json!([]);
        assert_eq!(request_for_bytes(&byte_base, "POST", "/upload", &[], Some(b"ok")).unwrap()["body"], json!([111, 107]));
    }
}

// Both request body representations use the same canonical pointer/length ABI.
// The echo branch makes a real round trip through the selected WIT type.
fn component(body_type: &str, script: &str) -> Arc<App> {
    let html = format!("<!doctype html><body><script>{script}</script>");
    let encoded: String = html.as_bytes().iter().map(|byte| format!("\\{byte:02x}")).collect();
    let wat = format!(
        r#"(component
      (core module $m
        (memory (export "memory") 2)
        (global $heap (mut i32) (i32.const 32768))
        (func (export "realloc") (param i32 i32 i32) (param $size i32) (result i32)
          (local $ptr i32) (local.set $ptr (i32.and (i32.add (global.get $heap) (i32.const 7)) (i32.const -8)))
          (global.set $heap (i32.add (local.get $ptr) (local.get $size))) (local.get $ptr))
        (data (i32.const 4096) "{encoded}")
        (func (export "handle") (param i32 i32 i32) (param $uri_len i32) (param i32 i32) {option_tag} (param $body i32) (param $len i32) (result i32)
          (i32.store (i32.const 2048) (i32.const 200))
          (i32.store (i32.const 2052) (i32.const 0)) (i32.store (i32.const 2056) (i32.const 0))
          (if (i32.eq (local.get $uri_len) (i32.const 20))
            (then (i32.store (i32.const 2060) (i32.const 4096)) (i32.store (i32.const 2064) (i32.const {len})))
            (else (i32.store (i32.const 2060) (local.get $body)) (i32.store (i32.const 2064) (local.get $len))))
          (i32.const 2048)))
      (core instance $i (instantiate $m))
      (alias core export $i "memory" (core memory $memory))
      (alias core export $i "realloc" (core func $realloc))
      (type $headers (list (tuple string string)))
      (type $req (record (field "method" string) (field "uri" string) (field "headers" $headers) (field "body" {body_type})))
      (export $request "request" (type $req))
      (type $resp (record (field "status" u16) (field "headers" $headers) (field "body" (list u8))))
      (export $response "response" (type $resp))
      (func (export "handle") (param "request" $request) (result $response)
        (canon lift (core func $i "handle") (memory $memory) (realloc $realloc))))"#,
        len = html.len(),
        option_tag = if body_type.starts_with("(option") { "(param i32)" } else { "" }
    );
    let mut manifest = Manifest::for_wasm(std::path::Path::new("body-echo.wasm"));
    manifest.entry = Some(
        serde_json::from_value(json!({"export":"handle","output":{"status":"status","headers":"headers","body":"body"},"result":{"body":"html:scripts"}}))
            .unwrap(),
    );
    Arc::new(App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap())
}
#[test]
fn typed_byte_body_entry_round_trips_binary_and_text_without_string_coercion() {
    let app = component(
        "(list u8)",
        "(async()=>{for(const bytes of [new Uint8Array([255,0,128]),new Uint8Array([111,107])]){const r=await fetch('/upload',{method:'POST',body:bytes});console.log(Array.from(new Uint8Array(await r.arrayBuffer())).join(','))}})()",
    );
    let page = app.run(&app.spec(
        app.export("handle").unwrap(),
        vec![json!({"method":"GET","uri":"https://app.example/","headers":[],"body":[]})],
        Plan::default(),
        1,
    ));
    assert_eq!(page.outcome.kind, OutcomeKind::Ok, "{:?}", page.outcome);
    assert!(appfuzz_core::browser::has_scripts(&page, &app.manifest), "{:?}", page.result);
    let runner = |spec: &appfuzz_core::record::RunSpec| app.run(spec);
    let session = Browser::shared().unwrap().session(&app, &page, &runner).unwrap();
    assert_eq!(session.report["errors"], json!([]), "{}", session.report);
    assert_eq!(session.report["unmodelled"], json!([]), "{}", session.report);
    assert_eq!(logs(&session.report), ["255,0,128", "111,107"], "{}", session.report);
    assert_eq!(session.nested.len(), 2);
    for (run, bytes) in session.nested.iter().zip([json!([255, 0, 128]), json!([111, 107])]) {
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        assert_eq!(run.spec.args[0]["body"], bytes);
        assert_eq!(run.result.as_ref().unwrap()["body"], bytes);
    }
}
#[test]
fn text_body_entry_reports_unrepresentable_binary_requests_as_incomplete() {
    let app = component("string", "fetch('/upload',{method:'POST',body:new Uint8Array([255,0,128])}).catch(()=>console.log('rejected'))");
    let page = app.run(&app.spec(
        app.export("handle").unwrap(),
        vec![json!({"method":"GET","uri":"https://app.example/","headers":[],"body":""})],
        Plan::default(),
        1,
    ));
    assert_eq!(page.outcome.kind, OutcomeKind::Ok, "{:?}", page.outcome);
    assert!(appfuzz_core::browser::has_scripts(&page, &app.manifest), "{:?}", page.result);
    let runner = |spec: &appfuzz_core::record::RunSpec| app.run(spec);
    let session = Browser::shared().unwrap().session(&app, &page, &runner).unwrap();
    assert_eq!(session.report["errors"], json!([]), "{}", session.report);
    assert_eq!(session.report["unmodelled"], json!(["binary HTTP body cannot be represented by the entry's text body field"]));
    assert_eq!(logs(&session.report), ["rejected"]);
    assert!(session.nested.is_empty());
    assert!(session.browser.events.iter().any(|event| event.source == "browser: request mapping"));
}

#[test]
fn optional_body_fields_keep_absence_and_the_declared_present_body_type() {
    for (body_type, expected) in [("(option string)", json!("ok")), ("(option (list u8))", json!([111, 107]))] {
        let app = component(
            body_type,
            "(async()=>{for(const body of [undefined,'ok']){const r=await fetch('/upload',{method:'POST',body});console.log(JSON.stringify(await r.text()))}})()",
        );
        let page = app.run(&app.spec(
            app.export("handle").unwrap(),
            vec![json!({"method":"GET","uri":"https://app.example/","headers":[],"body":null})],
            Plan::default(),
            1,
        ));
        assert_eq!(page.outcome.kind, OutcomeKind::Ok, "{:?}", page.outcome);
        assert!(appfuzz_core::browser::has_scripts(&page, &app.manifest), "{:?}", page.result);
        let runner = |spec: &appfuzz_core::record::RunSpec| app.run(spec);
        let session = Browser::shared().unwrap().session(&app, &page, &runner).unwrap();
        assert_eq!(session.report["errors"], json!([]), "{}", session.report);
        assert_eq!(session.report["unmodelled"], json!([]), "{}", session.report);
        assert_eq!(logs(&session.report), ["\"\"", "\"ok\""], "{}", session.report);
        assert_eq!(session.nested.len(), 2);
        assert_eq!(session.nested[0].spec.args[0]["body"], Value::Null);
        assert_eq!(session.nested[1].spec.args[0]["body"], expected);
        for run in &session.nested {
            assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        }
    }
}

#[test]
fn native_fastly_request_validation_accepts_bytes_without_weakening_other_fields() {
    use appfuzz_core::host_manifest::{HostManifest, merge};
    let host = HostManifest::resolve("fastly", std::path::Path::new("")).unwrap();
    let mut manifest = merge(&host, Manifest::for_wasm(std::path::Path::new("echo.wasm")), &Default::default()).unwrap();
    manifest.host = Some(Arc::new(host));
    let wat = r#"(module
      (import "fastly_http_req" "body_downstream_get" (func $request (param i32 i32) (result i32)))
      (import "fastly_http_body" "read" (func $read (param i32 i32 i32 i32) (result i32)))
      (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
      (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
      (import "fastly_http_resp" "new" (func $response (param i32) (result i32)))
      (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "_start")
        (drop (call $request (i32.const 0) (i32.const 4)))
        (drop (call $read (i32.load (i32.const 4)) (i32.const 256) (i32.const 4096) (i32.const 16)))
        (drop (call $body (i32.const 8))) (drop (call $response (i32.const 12)))
        (drop (call $write (i32.load (i32.const 8)) (i32.const 256) (i32.load (i32.const 16)) (i32.const 0) (i32.const 20)))
        (drop (call $send (i32.load (i32.const 12)) (i32.load (i32.const 8)) (i32.const 0)))))"#;
    let app = App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap();
    let export = app.default_export().unwrap();
    for (body, expected) in
        [(json!([255, 0, 128]), json!([255, 0, 128])), (json!([111, 107]), json!("ok")), (json!("a\0b"), json!("a\0b")), (json!([]), json!(""))]
    {
        let request = json!({"method":"POST","uri":"https://app.example/upload","headers":[],"body":body});
        let run = app.run(&app.spec(export, vec![request.clone()], Plan::default(), 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
        assert_eq!(run.spec.args[0], request);
        assert_eq!(run.result.as_ref().unwrap()["body"], expected);
    }
    for request in [json!({"method":"POST","uri":"/","headers":[],"body":[256]}), json!({"method":3,"uri":"/","headers":[],"body":[255]})] {
        let run = app.run(&app.spec(export, vec![request], Plan::default(), 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Error);
        assert!(run.events.is_empty());
    }
}
