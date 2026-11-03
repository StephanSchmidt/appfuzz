//! Plain modules on a witx platform: arguments read from and results
//! written to the guest's memory, as the witx ABI lays them out.

use std::sync::Arc;

use appfuzz_core::harness::App;
use appfuzz_core::host_manifest::{HostManifest, merge};
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use appfuzz_core::record::OutcomeKind;

const WITX: &str = r#"
(typename $status (enum (@witx tag u32) $ok $error $inval $badf $buflen $unsupported $none))
(typename $req (handle))
(module $t_req
  (@interface func (export "pair")
    (result $err (expected (tuple $req $req) (error $status))))
  (@interface func (export "get_name")
    (param $h $req)
    (param $buf (@witx pointer (@witx char8)))
    (param $buf_len (@witx usize))
    (param $nwritten_out (@witx pointer (@witx usize)))
    (result $err (expected (error $status))))
  (@interface func (export "log")
    (param $msg string)
    (result $err (expected (error $status))))
  (@interface func (export "names")
    (param $h $req)
    (param $buf (@witx pointer (@witx char8)))
    (param $buf_len (@witx usize))
    (param $cursor u32)
    (param $ending_cursor_out (@witx pointer s64))
    (param $nwritten_out (@witx pointer (@witx usize)))
    (result $err (expected (error $status))))
)
"#;

const PLATFORM: &str = r#"
[platform]
name = "tiny"
witx = ["tiny.witx"]
start = "_start"
entry_wit = "run: func();"

[entry]
export = "entry#run"
"#;

/// Each check traps with `unreachable` when the host answered wrongly.
const WAT: &str = r#"
(module
  (import "t_req" "pair" (func $pair (param i32 i32) (result i32)))
  (import "t_req" "get_name" (func $get_name (param i32 i32 i32 i32) (result i32)))
  (import "t_req" "log" (func $log (param i32 i32) (result i32)))
  (import "t_req" "names" (func $names (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "t_other" "nope" (func $nope))
  (memory (export "memory") 1)
  (func $check (param i32 i32) (if (i32.ne (local.get 0) (local.get 1)) (then unreachable)))
  (func (export "_start")
    ;; a tuple of two handles through two output pointers
    (call $check (call $pair (i32.const 0) (i32.const 4)) (i32.const 0))
    (call $check (i32.load (i32.const 0)) (i32.const 7))
    (call $check (i32.load (i32.const 4)) (i32.const 9))
    ;; a buffer too small: buflen, and the length needed
    (call $check (call $get_name (i32.load (i32.const 0)) (i32.const 100) (i32.const 4) (i32.const 8)) (i32.const 4))
    (call $check (i32.load (i32.const 8)) (i32.const 9))
    (call $check (call $get_name (i32.load (i32.const 0)) (i32.const 100) (i32.const 64) (i32.const 8)) (i32.const 0))
    ;; the string read back is what the host wrote
    (call $check (call $log (i32.const 100) (i32.load (i32.const 8))) (i32.const 0))
    ;; a cursor list: all of it, then a page that ends at entry 2
    (call $check (call $names (i32.const 7) (i32.const 300) (i32.const 64) (i32.const 0) (i32.const 16) (i32.const 24)) (i32.const 0))
    (call $check (i32.load (i32.const 24)) (i32.const 9))
    (if (i64.ne (i64.load (i32.const 16)) (i64.const -1)) (then unreachable))
    (call $check (call $names (i32.const 7) (i32.const 300) (i32.const 5) (i32.const 0) (i32.const 16) (i32.const 24)) (i32.const 0))
    (call $check (i32.load (i32.const 24)) (i32.const 5))
    (if (i64.ne (i64.load (i32.const 16)) (i64.const 2)) (then unreachable))
    ;; a pointer outside memory: inval, not a crash
    (call $check (call $log (i32.const 0xFFFFFFF0) (i32.const 10)) (i32.const 2))
  )
)
"#;

fn app() -> App {
    let dir = std::env::temp_dir().join(format!("appfuzz-witx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tiny.witx"), WITX).unwrap();
    let host = HostManifest::parse(PLATFORM, &dir).unwrap();
    let mut m = merge(&host, Manifest::for_wasm(std::path::Path::new("tiny.wasm")), &Default::default()).unwrap();
    m.host = Some(Arc::new(host));
    m.limits.wall_timeout_ms = 2_000;
    App::from_bytes(m, wat::parse_str(WAT).unwrap()).unwrap()
}

#[test]
fn plain_module_reads_and_writes_guest_memory() {
    let app = app();
    assert_eq!(app.exports.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(), vec!["entry#run"]);
    let plan = Plan::parse(
        r#"{
        "t_req#pair": {"return": {"ok": {"req": 7, "req-2": 9}}},
        "t_req#get_name": {"return": {"ok": "Annabelle"}},
        "t_req#names": {"return": {"ok": ["a", "bb", "ccc"]}}
    }"#,
    )
    .unwrap();
    let export = app.export("entry#run").unwrap().clone();
    let r = app.run(&app.spec(&export, vec![], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome.message);
    let calls: Vec<&str> = r.events.iter().map(|e| e.func.as_str()).collect();
    // The out-of-bounds call is answered before the host sees it.
    assert_eq!(calls, ["t_req#pair", "t_req#get_name", "t_req#get_name", "t_req#log", "t_req#names", "t_req#names"]);
    assert_eq!(r.events[3].args["msg"], "Annabelle");
    assert_eq!(r.events[1].args["h"], 7);
}

#[test]
fn generated_results_fit_the_abi() {
    let app = app();
    let export = app.export("entry#run").unwrap().clone();
    // Without a plan, `pair` gets generated handles and the checks trap.
    let r = app.run(&app.spec(&export, vec![], Plan::default(), 1));
    assert_ne!(r.outcome.kind, OutcomeKind::Error, "{:?}", r.outcome.message);
    assert!(!r.events.is_empty());
}

/// On the bundled Fastly platform: the client request comes from the run's
/// request, the response sent is the run's result.
const FASTLY_WAT: &str = r#"
(module
  (import "fastly_http_req" "body_downstream_get" (func $downstream (param i32 i32) (result i32)))
  (import "fastly_http_req" "uri_get" (func $uri_get (param i32 i32 i32 i32) (result i32)))
  (import "fastly_http_resp" "new" (func $resp_new (param i32) (result i32)))
  (import "fastly_http_resp" "status_set" (func $status_set (param i32 i32) (result i32)))
  (import "fastly_http_resp" "header_insert" (func $header_insert (param i32 i32 i32 i32 i32) (result i32)))
  (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
  (import "fastly_http_body" "new" (func $body_new (param i32) (result i32)))
  (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 400) "x-app")
  (data (i32.const 410) "yes")
  (func $check (param i32 i32) (if (i32.ne (local.get 0) (local.get 1)) (then unreachable)))
  (func (export "_start")
    (call $check (call $downstream (i32.const 0) (i32.const 4)) (i32.const 0))
    (call $check (call $uri_get (i32.load (i32.const 0)) (i32.const 100) (i32.const 200) (i32.const 8)) (i32.const 0))
    ;; a handle the host never gave out: badf
    (call $check (call $uri_get (i32.const 99) (i32.const 100) (i32.const 200) (i32.const 8)) (i32.const 3))
    (call $check (call $resp_new (i32.const 12)) (i32.const 0))
    (call $check (call $body_new (i32.const 16)) (i32.const 0))
    (call $check (call $write (i32.load (i32.const 16)) (i32.const 100) (i32.load (i32.const 8)) (i32.const 0) (i32.const 20)) (i32.const 0))
    (call $check (call $status_set (i32.load (i32.const 12)) (i32.const 201)) (i32.const 0))
    (call $check (call $header_insert (i32.load (i32.const 12)) (i32.const 400) (i32.const 5) (i32.const 410) (i32.const 3)) (i32.const 0))
    (if (i32.eqz (i32.load (i32.const 24))) (then
      (call $check (call $send (i32.load (i32.const 12)) (i32.load (i32.const 16)) (i32.const 0)) (i32.const 0))))
  )
)
"#;

fn fastly_app(wat: &str) -> App {
    let host = HostManifest::resolve("fastly", std::path::Path::new("")).unwrap();
    let mut m = merge(&host, Manifest::for_wasm(std::path::Path::new("app.wasm")), &Default::default()).unwrap();
    m.host = Some(Arc::new(host));
    m.limits.wall_timeout_ms = 2_000;
    App::from_bytes(m, wat::parse_str(wat).unwrap()).unwrap()
}

#[test]
fn fastly_request_in_response_out() {
    let app = fastly_app(FASTLY_WAT);
    let export = app.export("entry#handle").unwrap().clone();
    let request = serde_json::json!({"method": "GET", "uri": "https://app.example/?name=Ann", "headers": [], "body": ""});
    let r = app.run(&app.spec(&export, vec![request.clone()], Plan::default(), 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome.message);
    assert_eq!(r.result, Some(serde_json::json!({"status": 201, "headers": [["x-app", "yes"]], "body": "https://app.example/?name=Ann"})));
    // Handle bookkeeping is free; the bad handle is answered, not generated.
    assert!(r.events.iter().all(|e| e.source == "handle" && e.cost == 0), "{:?}", r.events.iter().map(|e| (&e.func, &e.source)).collect::<Vec<_>>());
    // Replays are identical.
    assert_eq!(app.run(&r.spec).result, r.result);

    // Without send_downstream there is no response.
    let silent = FASTLY_WAT.replace("(i32.eqz (i32.load (i32.const 24)))", "(i32.const 0)");
    let app = fastly_app(&silent);
    let r = app.run(&app.spec(&export, vec![request], Plan::default(), 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome.message);
    assert_eq!(r.result, None);
    let findings = appfuzz_core::output::check(&r, &app.manifest);
    assert!(findings.iter().any(|f| f.kind == "invalid_response"), "{findings:?}");
}
