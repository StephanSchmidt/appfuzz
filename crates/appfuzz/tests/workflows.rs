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
        let dir = std::env::temp_dir().join(format!("appfuzz-workflow-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
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

#[test]
fn semantic_host_argument_violations_confirm_replay_and_regress() {
    let f=Fixture::new(false);
    f.edit("\nrequest = 1\n","\nrequest = 7\n");
    let mut text=std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str("\n[functions.\"test:workflow/db#get\"]\nparam_values={id='range:1..6'}\nvalue_source='test platform specification'\n");
    std::fs::write(&f.manifest,text).unwrap();
    let (_,r)=f.cli(&["run"]);
    let bad=r["findings"].as_array().unwrap().iter().find(|v|v["kind"]=="invalid_host_argument").unwrap();
    assert_eq!(bad["evidence"],"policy_violation");
    let (_,confirmed)=f.cli(&["confirm",bad["id"].as_str().unwrap(),"--max-runs","30"]);
    assert_eq!(confirmed["confirmed"],true,"{confirmed}");
    assert_eq!(confirmed["spec"]["args"][0],7,"shrinking must keep an upper-bound violation above six");
    let case=confirmed["case"].as_str().unwrap();assert_eq!(f.cli(&["replay",case]).0,0);
    let bytes=component("package test:workflow; interface db { get:func(id:u32)->u32; } world app {import db;export run:func(n:u32)->u32;}",
        r#"(module (import "test:workflow/db" "get" (func $get (param i32) (result i32))) (func (export "run") (param i32) (result i32) (call $get (i32.const 1))))"#);
    std::fs::write(f.dir.join("app.wasm"),bytes).unwrap();
    let (code,replayed)=f.cli(&["replay",case,"--against-current"]);assert_eq!(code,0,"{replayed}");assert_eq!(replayed["reproduced"],false);
}

#[test]
fn guest_input_domains_do_not_filter_out_invalid_requests() {
    let f=Fixture::new(true);
    f.edit("request = \"safe\"","request = \"0.0.0000\"\ninput_values={''=['required','format:date']}");
    let mut text=std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str("\n[acceptance]\nversion=1\n[acceptance.checks.reject]\norigin='marketing'\nsearch=false\ninput_class='invalid'\nexpect={selector='$',equals='rejected'}\n");
    std::fs::write(&f.manifest,text).unwrap();
    let (code,r)=f.cli(&["acceptance","run"]);assert_eq!(code,2,"{r}");assert_eq!(r["checks"][0]["status"],"broken");
    let case=r["checks"][0]["case"].as_str().unwrap();assert_eq!(f.cli(&["replay",case]).0,0);
    f.edit("input_class='invalid'","input_class='valid'");
    let (code,r)=f.cli(&["acceptance","run"]);assert_eq!(code,3,"{r}");assert_eq!(r["checks"][0]["matches"],0);
    f.edit("input_class='valid'","input_class='invalid'");
    f.edit("input_values=", "values={''='format:date'}\ninput_values=");
    let (code,r)=f.cli(&["acceptance","run"]);assert_eq!(code,3,"{r}");assert_eq!(r["checks"][0]["status"],"not_exercised");
}

#[test]
fn rejected_input_must_obey_declared_effect_restrictions() {
    let f=Fixture::new(false);f.edit("\nrequest = 1\n","\nrequest = 7\ninput_values={''='range:1..6'}\n");
    let mut text=std::fs::read_to_string(&f.manifest).unwrap();
    text.push_str("\n[functions.\"test:workflow/db#get\"]\neffect='write'\n[acceptance]\nversion=1\n[acceptance.checks.reject]\norigin='marketing'\nsearch=false\ninput_class='invalid'\nproperty=['no_crash']\nforbid_effects=['write','delete','external']\n");
    std::fs::write(&f.manifest,text).unwrap();
    let (code,r)=f.cli(&["acceptance","run"]);assert_eq!(code,2,"{r}");assert!(r["checks"][0]["evidence"]["why"].as_str().unwrap().contains("forbidden effect"));
    let case=r["checks"][0]["case"].as_str().unwrap();
    f.edit("effect='write'\n","");
    let (code,unknown)=f.cli(&["acceptance","run"]);assert_eq!(code,3,"{unknown}");
    f.edit("[functions.\"test:workflow/db#get\"]\n","[functions.\"test:workflow/db#get\"]\neffect='write'\n");
    let bytes=component("package test:workflow; world app {export run:func(n:u32)->u32;}",r#"(module (func (export "run") (param i32) (result i32) (i32.const 7)))"#);
    std::fs::write(f.dir.join("app.wasm"),bytes).unwrap();
    let (code,r)=f.cli(&["replay",case,"--against-current"]);assert_eq!(code,0,"{r}");assert_eq!(r["reproduced"],false);
}

fn fault_fixture(crash: bool) -> Fixture {
    let f=Fixture::new(false);
    let wit="package test:workflow; interface db { save:func(id:u32) -> result<u32,u32>; } world app { import db; export run:func(n:u32) -> u32; }";
    let guard=if crash {"(if (i32.and (i32.load (i32.const 0)) (i32.eq (local.get $i) (i32.const 7))) (then unreachable))"}else{""};
    let wat=format!(r#"(module (import "test:workflow/db" "save" (func $save (param i32 i32)))
      (memory (export "memory") 1)
      (func (export "run") (param i32) (result i32) (local $i i32)
        (local.set $i (i32.const 1)) (loop $next
          (call $save (local.get $i) (i32.const 0)) {guard}
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br_if $next (i32.le_u (local.get $i) (i32.const 7))))
        (i32.const 42)))"#);
    std::fs::write(f.dir.join("app.wasm"),component(wit,&wat)).unwrap();
    f
}

#[test]
fn fault_probe_budgets_filter_and_replay_late_crashes_and_ignored_errors() {
    let plan=r#"{"test:workflow/db#save":{"return":{"ok":1}}}"#;
    let f=fault_fixture(true);
    let (code,p)=f.cli(&["probe","faults","--plan",plan,"--runs","3"]);
    assert_eq!(code,3,"{p}"); assert_eq!(p["attempted"],3); assert_eq!(p["complete"],false);
    let (code,p)=f.cli(&["probe","faults","--plan",plan,"--fn","missing"]);
    assert_eq!(code,3,"{p}"); assert_eq!(p["attempted"],0);
    let (code,p)=f.cli(&["probe","faults","--plan",plan,"--runs","14"]);
    assert_eq!(code,0,"{p}"); assert_eq!(p["complete"],true); assert_eq!(p["injected"],14);
    let crash=p["findings"].as_array().unwrap().iter().find(|f|f["kind"]=="crash").unwrap();
    let (_,confirmed)=f.cli(&["confirm",crash["id"].as_str().unwrap()]);
    assert_eq!(confirmed["confirmed"],true,"{confirmed}");
    let case=confirmed["case"].as_str().unwrap();
    let (code,replay)=f.cli(&["replay",case]); assert_eq!(code,0,"{replay}"); assert_eq!(replay["reproduced"],true);

    let f=fault_fixture(false);
    let (_,p)=f.cli(&["probe","faults","--plan",plan,"--runs","14"]);
    let ignored=p["findings"].as_array().unwrap().iter().find(|f|f["kind"]=="error_ignored").unwrap();
    let (_,confirmed)=f.cli(&["confirm",ignored["id"].as_str().unwrap()]);
    assert_eq!(confirmed["confirmed"],true,"{confirmed}");
    let case=confirmed["case"].as_str().unwrap();
    let saved:Value=serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
    assert!(!saved["recipe"]["fault"]["fault"].is_null(),"{saved}");
    let (code,replay)=f.cli(&["replay",case]); assert_eq!(code,0,"{replay}"); assert_eq!(replay["reproduced"],true);
    let (_,r)=f.cli(&["fuzz","--plan",plan,"--fresh","--runs","160"]);
    assert!(r["faults"]["attempted"].as_u64().unwrap()>0,"{r}");
    assert!(r["runs"].as_u64().unwrap()<=160);
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
fn nonexecuting_reviews_are_incomplete() {
    let f = Fixture::new(false);
    f.edit("export = \"run\"", "export = \"missing\"");
    let (code, v) = f.review();
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["verdict"], "incomplete");
    f.edit("export = \"missing\"", "export = \"run\"");
    f.edit("request = 1", "request = \"wrong type\"");
    let (code, v) = f.review();
    assert_eq!(code, 3, "{v}");
    assert_eq!(v["verdict"], "incomplete");
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
    f.edit("request = 1", "request = 2");
    assert_eq!(f.cli(&["envelope", "check", "last", "--envelope", path]).0, 3);
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
    let files: Vec<_> = std::fs::read_dir(f.dir.join("state/findings")).unwrap().map(|e| e.unwrap().path()).collect();
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
    let path = scenario_file(
        &f,
        json!({"steps":[{"args":[0,7],"plan":{"test:workflow/db#create":{"commit_then_trap":"response lost"}}},{"args":[0,7]}],"checks":[{"kind":"unique","dataset":"bookings","fields":["slot"]}]}),
    );
    let (code, report) = f.cli(&["sequence", "run", &path]);
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["records"][0]["outcome"]["kind"], "host_trap");
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
origin = "marketing"
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
    assert_eq!(availability["origin"], "marketing");
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
origin = "marketing"
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
origin = "marketing"
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
origin = "marketing"
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
origin = "marketing"
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
