//! Extism plugins: JSON through the kernel, typed by the platform's WIT.

use std::sync::Arc;

use appfuzz_core::harness::App;
use appfuzz_core::host_manifest::{HostManifest, merge};
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use appfuzz_core::record::OutcomeKind;
use serde_json::json;

const WIT: &str = r#"
package extism:host;
interface user {
  record query { org-id: string, user-name: string }
  record found { org-id: string, user-name: string }
  record answer { ok: option<found>, error: option<string> }
  lookup: func(input: query) -> result<found, string>;
}
world plugin {
  import user;
  use user.{query, found, answer};
  export relay: func(input: query) -> answer;
  export fail: func(input: query) -> result<found, string>;
}
"#;

const PLATFORM: &str = r#"
[platform]
name = "plugins"
abi = "extism"
wit = "plugin.wit"

[platform.json]
err = "error"
rename = { "found.user-name" = "UserName" }
"#;

/// `relay` hands its input to `lookup` and outputs the answer as it is;
/// `fail` sets an error.
const WAT: &str = r#"
(module
  (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
  (import "extism:host/env" "length" (func $length (param i64) (result i64)))
  (import "extism:host/env" "store_u8" (func $store_u8 (param i64 i32)))
  (import "extism:host/env" "input_length" (func $input_length (result i64)))
  (import "extism:host/env" "input_load_u8" (func $input_load_u8 (param i64) (result i32)))
  (import "extism:host/env" "output_set" (func $output_set (param i64 i64)))
  (import "extism:host/env" "error_set" (func $error_set (param i64)))
  (import "extism:host/user" "lookup" (func $lookup (param i64) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 0) "boom")
  (func $copy (param $from i32) (param $n i64) (result i64) (local $b i64) (local $i i64)
    (local.set $b (call $alloc (local.get $n)))
    (block $done (loop $l
      (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
      (call $store_u8 (i64.add (local.get $b) (local.get $i))
        (if (result i32) (i32.lt_s (local.get $from) (i32.const 0))
          (then (call $input_load_u8 (local.get $i)))
          (else (i32.load8_u (i32.add (local.get $from) (i32.wrap_i64 (local.get $i)))))))
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $l)))
    (local.get $b))
  (func (export "relay") (result i32) (local $out i64)
    (local.set $out (call $lookup (call $copy (i32.const -1) (call $input_length))))
    (call $output_set (local.get $out) (call $length (local.get $out)))
    (i32.const 0))
  (func (export "fail") (result i32)
    (call $error_set (call $copy (i32.const 0) (i64.const 4)))
    (i32.const 1))
)
"#;

fn app() -> App {
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), WIT).unwrap();
    let host = HostManifest::parse(PLATFORM, &dir).unwrap();
    let mut m = merge(&host, Manifest::for_wasm(std::path::Path::new("plugin.wasm")), &Default::default()).unwrap();
    m.host = Some(Arc::new(host));
    m.limits.wall_timeout_ms = 2_000;
    App::from_bytes(m, wat::parse_str(WAT).unwrap()).unwrap()
}

#[test]
fn json_crosses_the_kernel_both_ways() {
    let app = app();
    let mut keys: Vec<&str> = app.exports.iter().map(|e| e.key.as_str()).collect();
    keys.sort();
    assert_eq!(keys, ["fail", "relay"]);
    let export = app.export("relay").unwrap().clone();
    let plan = Plan::parse(r#"{"extism:host/user#lookup": {"return": {"ok": {"org-id": "o2", "user-name": "Ann"}}}}"#).unwrap();
    let request = json!({"org-id": "o1", "user-name": "x"});
    let r = app.run(&app.spec(&export, vec![request.clone()], plan, 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome.message);
    // The host saw the request the plugin passed on, as WIT values.
    assert_eq!(r.events.len(), 1);
    assert_eq!(r.events[0].func, "extism:host/user#lookup");
    assert_eq!(r.events[0].args["input"], request);
    // The plugin echoed the host's JSON ({"ok": {"org_id", "UserName"}}), read back by the WIT.
    assert_eq!(r.result, Some(json!({"ok": {"some": {"org-id": "o2", "user-name": "Ann"}}, "error": null})));
    assert_eq!(app.run(&r.spec).result, r.result);

    // A failing host answers {"error": …}.
    let plan = Plan::parse(r#"{"extism:host/user#lookup": {"return": {"err": "down"}}}"#).unwrap();
    let r = app.run(&app.spec(&export, vec![request.clone()], plan, 1));
    assert_eq!(r.result, Some(json!({"ok": null, "error": {"some": "down"}})));

    // Generated answers fit too.
    let r = app.run(&app.spec(&export, vec![request], Plan::default(), 7));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome.message);
}

#[test]
fn an_error_is_the_err_of_a_result_export() {
    let app = app();
    let export = app.export("fail").unwrap().clone();
    let r = app.run(&app.spec(&export, vec![json!({"org-id": "o", "user-name": "u"})], Plan::default(), 1));
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome.message);
    assert_eq!(r.result, Some(json!({"err": "boom"})));
}

#[test]
fn imports_the_wit_lacks_are_refused() {
    let dir = std::env::temp_dir().join(format!("appfuzz-extism-missing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plugin.wit"), WIT).unwrap();
    let host = HostManifest::parse(PLATFORM, &dir).unwrap();
    let mut m = merge(&host, Manifest::for_wasm(std::path::Path::new("plugin.wasm")), &Default::default()).unwrap();
    m.host = Some(Arc::new(host));
    let wat = WAT.replace(r#""extism:host/user" "lookup""#, r#""extism:host/user" "unknown_fn""#);
    let err = App::from_bytes(m, wat::parse_str(&wat).unwrap()).err().expect("refused").to_string();
    assert!(err.contains("unknown_fn"), "{err}");
}
