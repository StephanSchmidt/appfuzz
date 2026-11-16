//! `appfuzz wasm …` and the commands that dig into stored runs (check, eval,
//! bindings, sweep, diff, provenance, profile, explain, unexplored, wasi),
//! run as the real binary against tiny components built from WAT.
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

const LIMITS: &str = "[limits]\nfuel = 1000000\ncost_per_request = 100\nmax_latency_ms = 200\n";

/// Host calls for request n: get(n)…get(2n-1) through `fetch`, lookup(777)
/// through the shim, put(n*1000+3), get(9), put(what get(9) returned).
/// n = 42 also runs `save_all`, which calls put through `hidden` in a nested loop.
/// Functions: get 0, put 1, lookup 2, fetch 3, countdown 4, spin 5, hidden 6, save_all 7, run 8.
const NUM_WIT: &str = "package test:dig;
interface db { get: func(id: u32) -> u32; put: func(id: u32) -> u32; lookup: func(id: u32) -> result<u32>; }
world app { import db; export run: func(n: u32) -> u32; }";
const NUM_WAT: &str = r#"(module
  (import "test:dig/db" "get" (func $get (param i32) (result i32)))
  (import "test:dig/db" "put" (func $put (param i32) (result i32)))
  (import "test:dig/db" "lookup" (func $lookup (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "hello-from-data")
  (func $fetch (param $i i32) (result i32) (call $get (local.get $i)))
  (func $countdown (param $n i32) (result i32)
    (if (result i32) (i32.eqz (local.get $n)) (then (i32.const 0))
      (else (call $countdown (i32.sub (local.get $n) (i32.const 1))))))
  (func $spin (param $n i32) (result i32) (local $acc i32)
    (loop $again
      (local.set $acc (i32.add (local.get $acc) (call $countdown (local.get $n))))
      (local.set $n (i32.sub (local.get $n) (i32.const 1)))
      (br_if $again (i32.gt_s (local.get $n) (i32.const 0))))
    (local.get $acc))
  (func $hidden (param $x i32) (result i32) (call $put (local.get $x)))
  (func $save_all (param $n i32) (result i32) (local $i i32) (local $j i32)
    (loop $outer
      (local.set $j (i32.const 0))
      (loop $inner
        (drop (call $hidden (i32.const 0x6b636162)))
        (local.set $j (i32.add (local.get $j) (i32.const 1)))
        (br_if $inner (i32.lt_u (local.get $j) (i32.const 2))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $outer (i32.lt_u (local.get $i) (local.get $n))))
    (local.get $i))
  (func $run (export "run") (param $n i32) (result i32) (local $i i32) (local $acc i32)
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
      (local.set $acc (i32.add (local.get $acc) (call $fetch (i32.add (local.get $n) (local.get $i)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (if (i32.eq (local.get $n) (i32.const 42)) (then (local.set $acc (call $save_all (local.get $n)))))
    (if (i32.eq (local.get $n) (i32.const 0x3759df13)) (then (local.set $acc (i32.const 7))))
    (drop (call $spin (i32.const 2)))
    (call $lookup (i32.const 777) (i32.const 512))
    (if (i32.eq (local.get $n) (i32.const 777)) (then (local.set $acc (i32.const 1))))
    (drop (call $put (i32.add (i32.mul (local.get $n) (i32.const 1000)) (i32.const 3))))
    (drop (call $put (call $get (i32.const 9))))
    (i32.add (local.get $acc) (i32.load (i32.const 516)))))"#;

/// Returns `q` as an HTML page. Host calls: find(q, day), find("id=" + q,
/// "2026-11-05"), find("select-all", "select-all"). Traps when limit > 1000.
const STR_WIT: &str = "package test:dig;
interface search { find: func(q: string, day: string) -> u32; }
world app {
  import search;
  record req { q: string, day: string, limit: u32, tags: list<tuple<string, string>> }
  export run: func(r: req) -> string;
}";
const STR_WAT: &str = r#"(module
  (import "test:dig/search" "find" (func $find (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 4)
  (global $bump (mut i32) (i32.const 8192))
  (data (i32.const 256) "id=")
  (data (i32.const 272) "2026-11-05")
  (data (i32.const 288) "select-all")
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (local.get $p) (i32.and (i32.add (local.get 3) (i32.const 7)) (i32.const -8))))
    (local.get $p))
  (func (export "run") (param $q i32) (param $ql i32) (param $d i32) (param $dl i32) (param $limit i32) (param $t i32) (param $tl i32) (result i32)
    (drop (call $find (local.get $q) (local.get $ql) (local.get $d) (local.get $dl)))
    (memory.copy (i32.const 131072) (i32.const 256) (i32.const 3))
    (memory.copy (i32.const 131075) (local.get $q) (local.get $ql))
    (drop (call $find (i32.const 131072) (i32.add (local.get $ql) (i32.const 3)) (i32.const 272) (i32.const 10)))
    (drop (call $find (i32.const 288) (i32.const 10) (i32.const 288) (i32.const 10)))
    (if (i32.gt_u (local.get $limit) (i32.const 1000)) (then unreachable))
    (i32.store (i32.const 0) (local.get $q))
    (i32.store (i32.const 4) (local.get $ql))
    (i32.const 0)))"#;

/// Reads the clock once (twice when n > 1) and 8 random bytes.
const WASI_WIT: &str = "package test:dig;
package wasi:clocks@0.2.12 { interface wall-clock { record datetime { seconds: u64, nanoseconds: u32 } now: func() -> datetime; } }
package wasi:random@0.2.12 { interface random { get-random-u64: func() -> u64; } }
world app {
  import wasi:clocks/wall-clock@0.2.12;
  import wasi:random/random@0.2.12;
  export run: func(n: u32) -> u64;
  export ping: func() -> u32;
}";
const WASI_WAT: &str = r#"(module
  (import "wasi:clocks/wall-clock@0.2.12" "now" (func $now (param i32)))
  (import "wasi:random/random@0.2.12" "get-random-u64" (func $rand (result i64)))
  (memory (export "memory") 1)
  (func (export "run") (param $n i32) (result i64)
    (call $now (i32.const 0))
    (if (i32.gt_u (local.get $n) (i32.const 1)) (then (call $now (i32.const 0))))
    (i64.add (i64.load (i32.const 0)) (call $rand)))
  (func (export "ping") (result i32) (i32.const 1)))"#;

const GET: &str = "test:dig/db#get";
const PUT: &str = "test:dig/db#put";
const LOOKUP: &str = "test:dig/db#lookup";
const FIND: &str = "test:dig/search#find";

impl Fixture {
    fn new(wit: &str, wat: &str, entry: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let candidate = std::env::temp_dir().join(format!("appfuzz-dig-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("creating {}: {e}", candidate.display()),
            }
        };
        let manifest = dir.join("appfuzz.toml");
        std::fs::write(dir.join("app.wasm"), component(wit, wat)).unwrap();
        std::fs::write(&manifest, format!("[app]\nwasm = \"app.wasm\"\n[entry]\nexport = \"run\"\n{entry}\n{LIMITS}")).unwrap();
        Self { dir, manifest }
    }
    fn numbers() -> Self {
        Self::new(NUM_WIT, NUM_WAT, "request = 2\nvalues = { \"\" = \"range:0..100\" }")
    }
    fn strings() -> Self {
        Self::new(
            STR_WIT,
            STR_WAT,
            "request = { q = \"hello\", day = \"2026-11-02\", limit = 5, tags = [[\"color\", \"red\"]] }\noutput = { body = \"\", body_format = \"html\" }",
        )
    }
    fn wasi() -> Self {
        Self::new(WASI_WIT, WASI_WAT, "request = 1\n[grants]\nwasi = [\"wasi:clocks\"]")
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
    /// A command that succeeds.
    fn ok(&self, args: &[&str]) -> Value {
        let (code, v) = self.cli(args);
        assert_eq!(code, 0, "{args:?}: {v}");
        assert!(v.get("error").is_none(), "{args:?}: {v}");
        v
    }
    /// A command that fails: its error text.
    fn fails(&self, args: &[&str]) -> String {
        let (code, v) = self.cli(args);
        assert_eq!(code, 3, "{args:?}: {v}");
        assert_eq!(v["exit_code"], 3, "{args:?}: {v}");
        v["error"].as_str().unwrap_or_else(|| panic!("{args:?}: {v}")).to_string()
    }
    /// `run` with these options: the run id.
    fn run(&self, args: &[&str]) -> String {
        let (_, v) = self.cli(&[&["run"][..], args].concat());
        v["run"].as_str().unwrap_or_else(|| panic!("run {args:?}: {v}")).to_string()
    }
    fn edit(&self, from: &str, to: &str) {
        let s = std::fs::read_to_string(&self.manifest).unwrap();
        assert!(s.contains(from), "{from:?} not in {s}");
        std::fs::write(&self.manifest, s.replace(from, to)).unwrap();
    }
    fn main_module(&self) -> String {
        self.ok(&["wasm", "info"])["modules"][0]["id"].as_str().unwrap().to_string()
    }
}

/// The element of a list whose `key` is `value`.
fn find<'a>(list: &'a Value, key: &str, value: impl Into<Value>) -> &'a Value {
    let value = value.into();
    list.as_array().unwrap_or_else(|| panic!("not a list: {list}")).iter().find(|x| x[key] == value).unwrap_or_else(|| panic!("no {key} = {value} in {list}"))
}

/// One field of each element of a list.
fn each<'a>(list: &'a Value, key: &str) -> Vec<&'a Value> {
    list.as_array().unwrap_or_else(|| panic!("not a list: {list}")).iter().map(|x| &x[key]).collect()
}

fn str_request(q: &str, tags: Value) -> String {
    json!({"q": q, "day": "2026-11-02", "limit": 5, "tags": tags}).to_string()
}

// ---------------------------------------------------------------- wasm

#[test]
fn wasm_info_lists_main_shim_and_fixup_modules() {
    let f = Fixture::numbers();
    let info = f.ok(&["wasm", "info"]);
    let mods = info["modules"].as_array().unwrap();
    assert_eq!(each(&info["modules"], "role"), ["main", "shim", "fixup"], "{info}");
    assert_eq!(each(&info["modules"], "index"), [0, 1, 2]);
    let main = &mods[0];
    assert_eq!((&main["funcs"], &main["func_imports"], &main["has_names"]), (&json!(6), &json!(3), &json!(true)));
    assert_eq!(main["host_imports"], json!([GET, PUT, LOOKUP]));
    assert_eq!(main["other_imports"], json!([]));
    assert_eq!(main["exports"], json!(["run"]));
    assert!(main["bytes"].as_u64().unwrap() > 0);
    // The shim forwards lookup (which returns through memory) by call_indirect.
    assert_eq!((&mods[1]["funcs"], &mods[1]["exports"]), (&json!(1), &json!(["0"])));
    assert_eq!(mods[2]["funcs"], 0);
    assert_eq!(mods[2]["host_imports"], json!([]));
    assert_ne!(mods[0]["id"], mods[1]["id"]);
}

#[test]
fn wasm_funcs_filter_by_host_reach_name_and_module() {
    let f = Fixture::numbers();
    let main = f.main_module();
    let all = f.ok(&["wasm", "funcs"]);
    assert_eq!(all["module"], main);
    assert_eq!(all["count"], 6);
    assert_eq!(each(&all["funcs"], "name"), ["fetch", "countdown", "spin", "hidden", "save_all", "run"]);
    let fetch = find(&all["funcs"], "name", "fetch");
    assert_eq!((&fetch["func"], &fetch["calls"], &fetch["loops"], &fetch["call_indirect"]), (&json!(3), &json!(1), &json!(0), &json!(0)));
    assert_eq!(fetch["reaches_host"], json!([GET]));
    assert_eq!(find(&all["funcs"], "name", "run")["reaches_host"], json!([GET, LOOKUP, PUT]));
    assert_eq!(find(&all["funcs"], "name", "save_all")["loops"], 2);
    assert_eq!(find(&all["funcs"], "name", "spin")["reaches_host"], json!([]));

    let host = f.ok(&["wasm", "funcs", "--host"]);
    assert_eq!(each(&host["funcs"], "name"), ["fetch", "hidden", "save_all", "run"]);
    let grep = f.ok(&["wasm", "funcs", "--grep", "^s"]);
    assert_eq!(each(&grep["funcs"], "name"), ["spin", "save_all"]);
    assert_eq!(grep["count"], 2);
    let both = f.ok(&["wasm", "funcs", "--host", "--grep", "^s"]);
    assert_eq!(each(&both["funcs"], "name"), ["save_all"]);

    // Another module, by index or by id.
    let shim = f.ok(&["wasm", "funcs", "--module", "1"]);
    assert_eq!(shim["count"], 1);
    assert_ne!(shim["module"], main);
    let by_id = f.ok(&["wasm", "funcs", "--module", shim["module"].as_str().unwrap()]);
    assert_eq!(by_id["funcs"], shim["funcs"]);
    assert_eq!(shim["funcs"][0]["call_indirect"], 1);

    assert_eq!(f.fails(&["wasm", "funcs", "--module", "nope"]), "no module nope; see `appfuzz wasm info`");
    assert!(f.fails(&["wasm", "funcs", "--grep", "("]).starts_with("regex parse error"));
}

#[test]
fn wasm_callgraph_walks_down_to_imports_recursion_and_depth() {
    let f = Fixture::numbers();
    let main = f.main_module();
    let cg = f.ok(&["wasm", "callgraph", "run", "--depth", "1"]);
    assert_eq!(cg["module"], main);
    assert_eq!(
        cg["callgraph"],
        json!([{"func": 8, "name": "run", "calls": [
            {"func": 0, "name": GET, "import": GET},
            {"func": 1, "name": PUT, "import": PUT},
            {"func": 2, "name": LOOKUP, "import": LOOKUP},
            {"func": 3, "name": "fetch", "more_callees": 1},
            {"func": 5, "name": "spin", "more_callees": 1},
            {"func": 7, "name": "save_all", "more_callees": 1},
        ]}])
    );
    // Default depth 2: spin → countdown → countdown again.
    let spin = f.ok(&["wasm", "callgraph", "spin"]);
    assert_eq!(
        spin["callgraph"],
        json!([{"func": 5, "name": "spin", "calls": [{"func": 4, "name": "countdown", "calls": [{"func": 4, "name": "countdown", "recursive": true}]}]}])
    );
    // `module:index`, as the dormant_code hint prints it.
    let save = f.ok(&["wasm", "callgraph", &format!("{main}:7"), "--depth", "3"]);
    assert_eq!(
        save["callgraph"],
        json!([{"func": 7, "name": "save_all", "calls": [{"func": 6, "name": "hidden", "calls": [{"func": 1, "name": PUT, "import": PUT}]}]}])
    );
    // A regex may name several roots; a host key names the import.
    let two = f.ok(&["wasm", "callgraph", "^(fetch|hidden)$", "--depth", "0"]);
    assert_eq!(two["callgraph"], json!([{"func": 3, "name": "fetch", "more_callees": 1}, {"func": 6, "name": "hidden", "more_callees": 1}]));
    let host = f.ok(&["wasm", "callgraph", LOOKUP]);
    assert_eq!(host["callgraph"], json!([{"func": 2, "name": LOOKUP, "import": LOOKUP}]));
    // The shim calls through its table.
    let shim = f.ok(&["wasm", "callgraph", "0", "--module", "1"]);
    assert_eq!(shim["callgraph"][0]["call_indirect"], 1, "{shim}");
    assert_eq!(shim["callgraph"][0]["calls"], json!([]));

    assert_eq!(f.fails(&["wasm", "callgraph", "99"]), format!("{main} has no function 99 (it has 9, numbered from 0); see `appfuzz wasm funcs`"));
    assert_eq!(f.fails(&["wasm", "callgraph", "nosuch"]), "no function matches \"nosuch\"");
    assert_eq!(f.fails(&["wasm", "callgraph", "run", "--module", "7"]), "no module 7; see `appfuzz wasm info`");
}

#[test]
fn wasm_xrefs_walk_up_to_exports_recursion_and_depth() {
    let f = Fixture::numbers();
    let put = f.ok(&["wasm", "xrefs", PUT, "--depth", "3"]);
    assert_eq!(
        put["xrefs"],
        json!([{"func": 1, "name": PUT, "called_by": [
            {"func": 6, "name": "hidden", "called_by": [{"func": 7, "name": "save_all", "called_by": [{"func": 8, "name": "run", "exported": true}]}]},
            {"func": 8, "name": "run", "exported": true},
        ]}])
    );
    let countdown = f.ok(&["wasm", "xrefs", "countdown"]);
    assert_eq!(
        countdown["xrefs"],
        json!([{"func": 4, "name": "countdown", "called_by": [
            {"func": 4, "name": "countdown", "recursive": true},
            {"func": 5, "name": "spin", "called_by": [{"func": 8, "name": "run", "exported": true}]},
        ]}])
    );
    assert_eq!(f.ok(&["wasm", "xrefs", "fetch", "--depth", "0"])["xrefs"], json!([{"func": 3, "name": "fetch", "more_callers": 1}]));
    assert!(f.fails(&["wasm", "xrefs", "99"]).contains("has no function 99"));
    assert!(f.fails(&["wasm", "xrefs", "("]).starts_with("regex parse error"));
}

#[test]
fn wasm_loops_are_the_ones_that_reach_the_host() {
    let f = Fixture::numbers();
    let l = f.ok(&["wasm", "loops"]);
    assert!(l["note"].as_str().unwrap().contains("direct calls only"));
    let loops = l["loops"].as_array().unwrap();
    assert_eq!(loops.len(), 3, "{l}");
    // spin's loop calls countdown, which reaches no host function.
    assert!(loops.iter().all(|x| x["name"] != "spin"), "{l}");
    let run = find(&l["loops"], "name", "run");
    assert_eq!((&run["func"], &run["nesting"], &run["hosts"], &run["via"]), (&json!(8), &json!(0), &json!([GET]), &json!(["fetch"])));
    assert_eq!(run["indirect_calls_in_loop"], 0);
    let save: Vec<&Value> = loops.iter().filter(|x| x["name"] == "save_all").collect();
    assert_eq!(save.iter().map(|x| x["nesting"].as_u64().unwrap()).collect::<Vec<_>>(), [0, 1]);
    for x in save {
        assert_eq!((&x["hosts"], &x["via"]), (&json!([PUT]), &json!(["hidden"])));
        assert!(x["loop_at"].as_str().is_some_and(|a| u64::from_str_radix(a, 16).is_ok()));
    }
    assert_eq!(f.ok(&["wasm", "loops", "--module", "1"])["loops"], json!([]));
}

#[test]
fn wasm_strings_come_from_data_and_code() {
    let f = Fixture::numbers();
    let main = f.main_module();
    let all = f.ok(&["wasm", "strings"]);
    assert_eq!(all["count"].as_u64().unwrap() as usize, all["strings"].as_array().unwrap().len());
    let data = find(&all["strings"], "text", "hello-from-data");
    assert_eq!((&data["in"], &data["module"]), (&json!("data"), &json!(main)));
    // 0x6b636162, a number in save_all, reads as "back".
    assert_eq!(find(&all["strings"], "text", "back")["in"], "code");

    let grep = f.ok(&["wasm", "strings", "--grep", "^hello"]);
    assert_eq!(each(&grep["strings"], "text"), ["hello-from-data"]);
    assert_eq!(grep["count"], 1);
    let long = f.ok(&["wasm", "strings", "--min", "5"]);
    assert!(each(&long["strings"], "text").iter().all(|t| *t != "back"), "{long}");
    assert!(each(&long["strings"], "text").contains(&&json!("hello-from-data")));
    assert_eq!(f.ok(&["wasm", "strings", "--module", "1"])["count"], 0);
    assert_eq!(f.ok(&["wasm", "strings", "--module", &main])["count"], all["count"]);
    assert_eq!(f.fails(&["wasm", "strings", "--module", "nope"]), "no module nope; see `appfuzz wasm info`");
    assert!(f.fails(&["wasm", "strings", "--grep", "["]).starts_with("regex parse error"));
}

fn code_text(v: &Value) -> String {
    match &v["code"] {
        Value::Array(lines) => lines.iter().map(|l| l.as_str().unwrap()).collect::<Vec<_>>().join("\n"),
        other => other.as_str().unwrap_or_else(|| panic!("code: {v}")).to_string(),
    }
}

#[test]
fn wasm_disasm_prints_a_function_with_call_targets() {
    let f = Fixture::numbers();
    let main = f.main_module();
    let hidden = f.ok(&["wasm", "disasm", "hidden"]);
    assert_eq!((&hidden["module"], &hidden["func"], &hidden["name"]), (&json!(main), &json!(6), &json!("hidden")));
    let code = code_text(&hidden);
    assert!(code.contains(&format!("call 1 ;; {PUT}")), "{code}");
    assert!(code.trim_end().ends_with("End"), "{code}");
    let countdown = code_text(&f.ok(&["wasm", "disasm", "countdown"]));
    assert!(countdown.contains("If"), "{countdown}");
    assert!(countdown.contains("call 4 ;; countdown"), "{countdown}");
    // The form `unexplored` prints in its hint.
    assert_eq!(f.ok(&["wasm", "disasm", &format!("{main}:7")])["name"], "save_all");
    let shim = f.ok(&["wasm", "disasm", "0", "--module", "1"]);
    assert!(code_text(&shim).contains("call_indirect") || code_text(&shim).contains("CallIndirect"), "{shim}");

    // Imports have no code; numbers past the end are no functions.
    assert!(f.fails(&["wasm", "disasm", "0"]).contains("has no defined function 0"));
    assert!(f.fails(&["wasm", "disasm", GET]).contains("has no defined function 0"));
    assert_eq!(f.fails(&["wasm", "disasm", "nosuch"]), "no function matches \"nosuch\"");
    assert!(f.fails(&["wasm", "disasm", "99"]).starts_with(&format!("{main} has no function 99")));
}

fn sources_by_name(host: &Value) -> Vec<String> {
    let mut v: Vec<String> = host["static_sites"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect();
    v.sort();
    v
}

#[test]
fn wasm_sites_join_static_call_sites_with_stored_runs() {
    let f = Fixture::numbers();
    let before = f.ok(&["wasm", "sites"]);
    assert_eq!(before["runs_used"], 0);
    let hosts = &before["host_functions"];
    // In the order the app imports them.
    assert_eq!(hosts.as_object().unwrap().keys().collect::<Vec<_>>(), [GET, PUT, LOOKUP]);
    assert_eq!(sources_by_name(&hosts[GET]), ["fetch", "run"]);
    assert_eq!(sources_by_name(&hosts[PUT]), ["hidden", "run", "run"]);
    assert_eq!(sources_by_name(&hosts[LOOKUP]), ["run"]);
    assert!(hosts[GET].get("called_from_in_runs").is_none());

    f.run(&[]);
    let after = f.ok(&["wasm", "sites"]);
    assert_eq!(after["runs_used"], 1);
    let hosts = &after["host_functions"];
    assert_eq!(hosts[GET]["called_from_in_runs"], json!({"fetch": 2, "run": 1}));
    assert_eq!(hosts[PUT]["called_from_in_runs"], json!({"run": 2}));
    // Through the shim, the app frame is still `run`.
    assert_eq!(hosts[LOOKUP]["called_from_in_runs"], json!({"run": 1}));

    // Runs under another contract don't count.
    f.edit(LIMITS, &format!("{LIMITS}[functions.\"{GET}\"]\ncost = 2\n"));
    let other = f.ok(&["wasm", "sites"]);
    assert_eq!(other["runs_used"], 0);
    assert!(other["host_functions"][GET].get("called_from_in_runs").is_none());
}

// ---------------------------------------------------------------- provenance, profile, diff

#[test]
fn provenance_traces_numbers_to_the_request_host_results_and_constants() {
    let f = Fixture::numbers();
    let id = f.run(&["--request", "4", "--plan", &json!({GET: {"return": 5}, LOOKUP: {"return": {"ok": 5}}}).to_string()]);
    let at = |n: &str| f.ok(&["provenance", &id, "--call", n]);
    let first = at("1");
    assert_eq!((&first["run"], &first["n"], &first["func"]), (&json!(id), &json!(1), &json!(GET)));
    assert_eq!(first["args"], json!([{"arg": "id", "value": 4, "sources": [{"from": "request", "field": "", "how": "equal"}]}]));
    assert!(first["note"].as_str().unwrap().starts_with("heuristic"));
    // 777 is no request value and no earlier result, but the code compares with it.
    assert_eq!(at("5")["args"], json!([{"arg": "id", "value": 777, "sources": [{"from": "binary", "how": "number the code compares with"}]}]));
    assert_eq!(at("6")["args"], json!([{"arg": "id", "value": 4003, "sources": "unknown (computed)"}]));
    // put(5): every earlier result was 5; five sources at most.
    let last = at("8");
    assert_eq!(last["func"], PUT);
    let sources = &last["args"][0]["sources"];
    assert_eq!(sources.as_array().unwrap().len(), 5, "{last}");
    assert_eq!(sources[0], json!({"from": "host_result", "call": 1, "func": GET, "path": ""}));
    assert_eq!(sources[4], json!({"from": "host_result", "call": 5, "func": LOOKUP, "path": "ok"}));

    assert_eq!(f.fails(&["provenance", &id, "--call", "99"]), format!("run {id} has no host call 99"));
    assert_eq!(f.fails(&["provenance", &id, "--call", "0"]), format!("run {id} has no host call 0"));
}

#[test]
fn provenance_traces_strings_to_fields_pairs_dates_and_constants() {
    let f = Fixture::strings();
    let id = f.run(&["--request", &str_request("red", json!([["color", "red"]]))]);
    let at = |n: &str| f.ok(&["provenance", &id, "--call", n])["args"].clone();
    assert_eq!(
        at("1"),
        json!([
            {"arg": "q", "value": "red", "sources": [
                {"from": "request", "field": "q", "how": "equal"},
                {"from": "request", "field": "tags.color", "how": "equal"},
            ]},
            {"arg": "day", "value": "2026-11-02", "sources": [{"from": "request", "field": "day", "how": "equal"}]},
        ])
    );
    assert_eq!(
        at("2"),
        json!([
            {"arg": "q", "value": "id=red", "sources": [
                {"from": "request", "field": "q", "how": "contained"},
                {"from": "request", "field": "tags.color", "how": "contained"},
            ]},
            {"arg": "day", "value": "2026-11-05", "sources": [{"from": "request", "field": "day", "how": "date +3 days"}]},
        ])
    );
    assert_eq!(
        at("3"),
        json!([
            {"arg": "q", "value": "select-all", "sources": [{"from": "binary", "how": "string constant"}]},
            {"arg": "day", "value": "select-all", "sources": [{"from": "binary", "how": "string constant"}]},
        ])
    );
}

#[test]
fn profile_splits_fuel_between_host_calls() {
    let f = Fixture::numbers();
    let id = f.run(&["--request", "3"]);
    let p = f.ok(&["profile", &id, "--top", "50"]);
    assert_eq!((&p["run"], &p["host_calls"]), (&json!(id), &json!(7)));
    assert_eq!((&p["measurement"], &p["function_cpu_profile"]), (&json!("host_boundary_fuel_estimate"), &json!(false)));
    let fuel = p["fuel"].as_u64().unwrap();
    let own = &p["before_host_calls"]["self"];
    let charged: u64 = own.as_array().unwrap().iter().map(|x| x["fuel"].as_u64().unwrap()).sum();
    let tail = p["after_last_host_call"]["fuel"].as_u64().unwrap();
    assert_eq!(charged + tail, fuel, "{p}");
    let mut names: Vec<&str> = own.as_array().unwrap().iter().map(|x| x["func"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["fetch", "run"], "{p}");
    // Every stack holds `run`; the shim, never the app frame, shows only inclusively.
    let incl = &p["before_host_calls"]["inclusive"];
    assert_eq!(find(incl, "func", "run")["fuel"], charged);
    let mut inclusive: Vec<&str> = incl.as_array().unwrap().iter().map(|x| x["func"].as_str().unwrap()).collect();
    inclusive.retain(|n| !names.contains(n));
    assert_eq!(inclusive.len(), 1, "{p}");
    assert!(tail > 0, "{p}");

    let top = f.ok(&["profile", "last", "--top", "1"]);
    assert_eq!(top["before_host_calls"]["self"].as_array().unwrap().len(), 1);
    assert_eq!(top["before_host_calls"]["inclusive"], json!([incl[0].clone()]));
    assert_eq!(incl[0]["func"], "run");
}

#[test]
fn diff_names_what_differs_first() {
    let f = Fixture::numbers();
    let two = f.run(&["--request", "2"]);
    let three = f.run(&["--request", "3"]);
    let d = f.ok(&["diff", &two, &three]);
    assert_eq!((&d["a"], &d["b"]), (&json!(two), &json!(three)));
    assert_eq!(d["input"], json!([{"path": "args[0]", "before": 2, "after": 3}]));
    assert_eq!(d["outcome"], json!({"a": "ok", "b": "ok"}));
    assert_eq!(d["status"], json!({"a": null, "b": null}));
    assert_eq!(d["calls"], json!([{"func": GET, "a": 3, "b": 4}]));
    let first = &d["first_different_call"];
    assert_eq!((&first["n"], &first["differs_in"]), (&json!(1), &json!("arguments")));
    assert_eq!((&first["a"]["args"], &first["b"]["args"]), (&json!({"id": 2}), &json!({"id": 3})));
    assert_eq!((&first["a"]["func"], &first["b"]["func"]), (&json!(GET), &json!(GET)));
    assert_eq!(d["totals"]["host_calls"], json!({"a": 6, "b": 7, "delta": 1}));
    // Without a page, the results are compared.
    assert_eq!(d["output"]["only_in_a"], json!([]));
    assert_eq!(each(&d["output"]["result"], "path"), [""]);
    assert_eq!(d["same_output"], false);

    // The other way round, the deltas are negative.
    let back = f.ok(&["diff", &three, &two]);
    assert_eq!(back["totals"]["host_calls"]["delta"], -1);
    for metric in ["cost", "virtual_ms", "fuel"] {
        let t = &back["totals"][metric];
        let (a, b, delta) = (t["a"].as_f64().unwrap(), t["b"].as_f64().unwrap(), t["delta"].as_f64().unwrap());
        assert!((delta - (b - a)).abs() < 0.01, "{metric}: {t}");
        assert!(delta <= 0.0, "{metric}: {t}");
    }

    // A different function, a different result, a shorter run.
    let zero = f.run(&["--request", "0"]);
    let one = f.run(&["--request", "1"]);
    let d = f.ok(&["diff", &zero, &one]);
    assert_eq!((&d["first_different_call"]["differs_in"], &d["first_different_call"]["n"]), (&json!("function"), &json!(1)));
    assert_eq!((&d["first_different_call"]["a"]["func"], &d["first_different_call"]["b"]["func"]), (&json!(LOOKUP), &json!(GET)));

    let pinned = f.run(&["--request", "2", "--plan", &json!({GET: {"return": 123456789}}).to_string()]);
    let d = f.ok(&["diff", &two, &pinned]);
    assert_eq!((&d["first_different_call"]["differs_in"], &d["first_different_call"]["n"]), (&json!("result"), &json!(1)));
    assert_eq!(d["first_different_call"]["b"]["result"], 123456789);
    assert!(each(&d["input"], "path").iter().all(|p| p.as_str().unwrap().starts_with("plan")), "{d}");

    let starved = f.run(&["--request", "3", "--fuel", "40"]);
    let d = f.ok(&["diff", &three, &starved]);
    assert_eq!(d["outcome"], json!({"a": "ok", "b": "out_of_fuel"}));
    assert_eq!(d["input"], json!([{"path": "fuel", "before": 5000000, "after": 40}]));
    let diverges = &d["first_different_call"];
    assert_eq!((&diverges["differs_in"], &diverges["a_calls"]), (&json!("length"), &json!(7)), "{d}");
    let b_calls = diverges["b_calls"].as_u64().unwrap();
    assert!(b_calls < 7);
    assert_eq!(diverges["n"], b_calls + 1);
    assert_eq!(d["output"]["result"][0]["after"], Value::Null);

    let same = f.ok(&["diff", &two, &two]);
    assert_eq!((&same["input"], &same["calls"], &same["first_different_call"]), (&json!([]), &json!([]), &Value::Null));
    assert_eq!((&same["same_output"], &same["output"]["result"]), (&json!(true), &json!([])));
}

#[test]
fn diff_of_pages_lists_the_lines_only_in_one() {
    let f = Fixture::strings();
    let a = f.run(&["--request", &str_request("<ul><li>a</li><li>b</li></ul>", json!([]))]);
    let b = f.run(&["--request", &str_request("<ul><li>a</li><li>c</li></ul>", json!([]))]);
    let d = f.ok(&["diff", &a, &b]);
    assert_eq!(d["output"], json!({"only_in_a": ["<li>b</li>"], "only_in_b": ["<li>c</li>"], "result": []}));
    assert_eq!(d["first_different_call"]["differs_in"], "arguments");
    assert_eq!(d["input"], json!([{"path": "args[0].q", "before": "<ul><li>a</li><li>b</li></ul>", "after": "<ul><li>a</li><li>c</li></ul>"}]));
}

#[test]
fn unknown_runs_are_errors() {
    let f = Fixture::numbers();
    assert_eq!(f.fails(&["explain", "last"]), "no runs yet: run `appfuzz run` or `appfuzz review` first");
    let id = f.run(&[]);
    let id = id.as_str();
    for args in [
        vec!["diff", "nosuch", id],
        vec!["diff", id, "nosuch"],
        vec!["provenance", "nosuch", "--call", "1"],
        vec!["profile", "nosuch"],
        vec!["explain", "nosuch"],
        vec!["eval", "nosuch", "true"],
    ] {
        assert_eq!(f.fails(&args), "no run \"nosuch\"", "{args:?}");
    }
    // A unique prefix is enough.
    assert_eq!(f.ok(&["profile", &id[..8]])["run"], id);
}

// ---------------------------------------------------------------- explain

#[test]
fn explain_compares_a_run_with_the_median_stored_run() {
    let f = Fixture::numbers();
    f.run(&["--request", "1"]);
    let two = f.run(&["--request", "2"]);
    let many = f.run(&["--request", "30"]);
    let e = f.ok(&["explain", &many]);
    assert_eq!((&e["run"], &e["export"], &e["outcome"], &e["seed"]), (&json!(many), &json!("run"), &json!("ok"), &json!(1)));
    assert_eq!(e["input_vs_default"], json!([{"path": "[0]", "before": 2, "after": 30}]));
    assert_eq!(e["calls"], json!({GET: 31, LOOKUP: 1, PUT: 2}));
    assert_eq!(e["host_plan_for"], json!([]));
    assert_eq!(e["vs_stored_runs"]["runs"], 3);
    // host calls 5, 6 and 34: the median is 6.
    assert_eq!(e["vs_stored_runs"]["metrics"]["host_calls"], json!({"this": 34, "median": 6, "ratio": 5.67}));
    assert!(e["vs_stored_runs"]["unusual"].as_array().unwrap().contains(&json!("host_calls is 5.67× the median")), "{e}");
    assert!(e.get("invalid_request").is_none());

    let typical = f.ok(&["explain", &two]);
    assert_eq!(typical["input_vs_default"], json!([]));
    assert_eq!(typical["vs_stored_runs"]["unusual"], json!([]));
    assert_eq!(typical["vs_stored_runs"]["metrics"]["host_calls"]["ratio"], 1.0);
}

#[test]
fn explain_lists_failed_calls_plans_and_invalid_requests() {
    let f = Fixture::numbers();
    let ok = f.run(&["--plan", &json!({LOOKUP: {"return": {"ok": 1}}}).to_string()]);
    assert_eq!(f.ok(&["explain", &ok])["failed_calls"], json!([]));
    let err = f.run(&["--plan", &json!({"_defaults": {"latency_ms": 1}, LOOKUP: {"return": {"err": null}}}).to_string()]);
    let e = f.ok(&["explain", &err]);
    assert_eq!(e["failed_calls"], json!([{"n": 3, "func": LOOKUP}]));
    // `_defaults` is no host function.
    assert_eq!(e["host_plan_for"], json!([LOOKUP]));

    let trap = f.run(&["--plan", &json!({PUT: {"trap": "db gone"}}).to_string()]);
    let e = f.ok(&["explain", &trap]);
    assert_eq!(e["outcome"], "host_trap");
    assert!(e["message"].as_str().unwrap().contains("db gone"), "{e}");
    assert!(!e["message"].as_str().unwrap().contains('\n'));
    assert_eq!(e["failed_calls"], json!([{"n": 4, "func": PUT}]));
    // Only runs that end well are the yardstick.
    assert_eq!(e["vs_stored_runs"]["runs"], 2);

    // The platform never sends 101: the findings are only hints.
    let out_of_range = f.run(&["--request", "101"]);
    let e = f.ok(&["explain", &out_of_range]);
    assert_eq!(e["invalid_request"], json!([{"field": "", "constraint": "range:0..100", "value": 101}]));
    assert!(!e["findings"].as_array().unwrap().is_empty(), "{e}");
    assert!(each(&e["findings"], "severity").iter().all(|s| *s == "info"), "{e}");
}

#[test]
fn explain_shows_the_markup_around_a_canary() {
    let f = Fixture::strings();
    let page = format!("{}cnry12ab1<i>x</i>{}", "A".repeat(45), "B".repeat(45));
    let id = f.run(&["--request", &str_request(&page, json!([]))]);
    let e = f.ok(&["explain", &id]);
    assert_eq!(e["text"], format!("{}cnry12ab1 x {}", "A".repeat(45), "B".repeat(45)));
    let reflection = find(&e["findings"], "kind", "reflection");
    assert_eq!(reflection["excerpt"], format!("…{}cnry12ab1<i>x</i>{}…", "A".repeat(40), "B".repeat(32)), "{e}");

    // A sink shows the host argument, not the page.
    f.edit(LIMITS, &format!("{LIMITS}[functions.\"{FIND}\"]\nparams = {{ q = \"sql\" }}\n"));
    let payload = "cnry12ab1<i>'\"../;$(x)";
    let id = f.run(&["--request", &str_request(payload, json!([]))]);
    let e = f.ok(&["explain", &id]);
    assert_eq!(find(&e["findings"], "kind", "sql_injection")["excerpt"], payload, "{e}");
    assert_eq!(find(&e["findings"], "kind", "reflection")["excerpt"], payload, "{e}");
    for x in e["findings"].as_array().unwrap().iter().filter(|x| x["kind"] == "input_passthrough") {
        assert!(x.get("excerpt").is_none(), "{x}");
    }
}

// ---------------------------------------------------------------- unexplored, wasi

#[test]
fn unexplored_lists_call_sites_until_a_run_reaches_them() {
    let f = Fixture::numbers();
    let main = f.main_module();
    let none = f.ok(&["unexplored"]);
    assert_eq!((&none["runs_used"], &none["static_sites"], &none["unreached"]), (&json!(0), &json!(6), &json!(6)));

    f.run(&[]);
    let u = f.ok(&["unexplored"]);
    assert_eq!((&u["runs_used"], &u["static_sites"], &u["unreached"]), (&json!(1), &json!(6), &json!(1)), "{u}");
    let site = &u["sites"][0];
    assert_eq!((&site["host"], &site["module"], &site["func"], &site["name"]), (&json!(PUT), &json!(main), &json!(7), &json!("save_all")));
    assert_eq!((&site["via"], &site["called_via"], &site["function_runs"]), (&json!(["hidden"]), &json!(["run"]), &json!(false)));
    // What save_all and its caller compare with: 2 (the inner loop), 42 and 777;
    // not 0x3759df13, which is too large to be a hint.
    assert_eq!((&site["texts"], &site["compares_with"]), (&json!(["back"]), &json!([2, 42, 777])));
    let dormant = find(&u["findings"], "kind", "dormant_code");
    assert_eq!(dormant["severity"], "info");
    assert_eq!(dormant["title"], format!("save_all calls {PUT} from code no run reached; nearby code compares with 0x3759df13"));

    // The hint leads there.
    f.run(&["--request", "42"]);
    let all = f.ok(&["unexplored"]);
    assert_eq!((&all["runs_used"], &all["unreached"], &all["sites"]), (&json!(2), &json!(0), &json!([])));
}

#[test]
fn wasi_lists_grants_and_what_runs_used() {
    let f = Fixture::wasi();
    let before = f.ok(&["wasi"]);
    assert_eq!(
        before["imports"],
        json!([
            {"interface": "wasi:clocks/wall-clock@0.2.12", "granted": true, "funcs": 1},
            {"interface": "wasi:random/random@0.2.12", "granted": false, "funcs": 1},
        ])
    );
    assert_eq!(before["runs_used"], 0);
    assert_eq!(before["usage"]["clock_reads"], json!({"runs": 0, "max": 0, "total": 0}));

    f.run(&["--request", "1"]);
    f.run(&["--request", "2"]);
    let after = f.ok(&["wasi"]);
    assert_eq!(after["runs_used"], 2);
    let usage = &after["usage"];
    assert_eq!(usage["clock_reads"], json!({"runs": 2, "max": 2, "total": 3}));
    assert_eq!(usage["random_bytes"], json!({"runs": 2, "max": 8, "total": 16}));
    assert_eq!(usage["sleep_ms"], json!({"runs": 0, "max": 0, "total": 0}));
    assert_eq!(usage["stdout_bytes"], json!({"runs": 0, "max": 0, "total": 0}));
    assert_eq!(usage["stderr_bytes"], json!({"runs": 0, "max": 0, "total": 0}));

    // Nothing to sweep in an export without parameters.
    assert_eq!(f.fails(&["sweep", "-f", "x", "--export", "ping"]), "the export takes no arguments");
}

// ---------------------------------------------------------------- sweep

#[test]
fn sweep_groups_values_that_behave_alike() {
    let f = Fixture::strings();
    let s = f.ok(&["sweep", "-f", "limit"]);
    assert_eq!((&s["field"], &s["values"]), (&json!("limit"), &json!(18)));
    assert_eq!(s["table"].as_array().unwrap().len(), 18);
    // Values a u32 can't hold don't run at all; above 1000 the app traps.
    assert_eq!(
        s["behaviours"],
        json!([
            {"behaviour": "error - ", "values": ["-2147483648", "-1", "9007199254740993"]},
            {"behaviour": format!("ok - {FIND}=3"), "values": ["0", "1", "2", "7", "10", "99", "100", "101", "255", "256", "1000"]},
            {"behaviour": format!("unreachable - {FIND}=3"), "values": ["65535", "65536", "2147483647", "2147483648"]},
        ])
    );
    let seven = find(&s["table"], "value", "7");
    assert_eq!((&seven["outcome"], &seven["host_calls"], &seven["text"]), (&json!("ok"), &json!(3), &json!("hello")));
    assert!(seven["run"].as_str().is_some());
    assert!(find(&s["table"], "value", "65536")["findings"].as_array().unwrap().contains(&json!("crash")));
    assert!(s["findings"].as_array().unwrap().iter().any(|x| x["kind"] == "crash" && x["severity"] == "fail"), "{s}");

    // Exactly these values; the text is what a reader sees.
    let q = f.ok(&["sweep", "-f", "q", "--values", "a,<b>bold</b>,hello"]);
    assert_eq!(each(&q["table"], "value"), ["a", "<b>bold</b>", "hello"]);
    assert_eq!(each(&q["table"], "text"), ["a", "bold", "hello"]);
    assert_eq!(q["behaviours"].as_array().unwrap().len(), 1);

    // A field in a list of pairs.
    let tag = f.ok(&["sweep", "-f", "tags.color", "--values", "blue"]);
    let run = tag["table"][0]["run"].as_str().unwrap();
    assert_eq!(f.ok(&["eval", run, "c", "--let", "c=request.tags.color"])["value"], "blue");
}

#[test]
fn sweep_generators_and_errors() {
    let f = Fixture::strings();
    let lengths = f.ok(&["sweep", "-f", "q", "--gen", "lengths"]);
    let values = each(&lengths["table"], "value");
    assert_eq!(values.len(), 8);
    assert_eq!((values[0], values[2]), (&json!(""), &json!("aaaaaaaa")));
    assert_eq!(values[3], &json!(format!("{}…[64 bytes]", "a".repeat(20))));
    assert_eq!(values[7], &json!(format!("{}…[65536 bytes]", "a".repeat(20))));
    // The page text is cut at 100 characters.
    assert_eq!(lengths["table"][7]["text"], "a".repeat(100));

    for (field, generator, count) in [("day", "dates", 13), ("day", "times", 11), ("q", "strings", 16)] {
        let s = f.ok(&["sweep", "-f", field, "--gen", generator]);
        assert_eq!((&s["values"], &s["field"]), (&json!(count), &json!(field)), "{generator}");
    }
    let words = f.ok(&["sweep", "-f", "q", "--gen", "words"]);
    assert!(each(&words["table"], "value").contains(&&json!("select-all")), "{words}");

    assert_eq!(f.fails(&["sweep", "-f", "q", "--gen", "bogus"]), "--gen must be numbers, dates, times, strings, words or lengths, not \"bogus\"");
    assert_eq!(f.fails(&["sweep", "-f", "nosuch.x", "--values", "1"]), "no field nosuch");
}

// ---------------------------------------------------------------- check, eval, bindings

#[test]
fn check_fuzzes_then_reuses_stored_counterexamples() {
    let f = Fixture::strings();
    let (code, c) = f.cli(&["check", "max_calls", "search#find", "2", "--runs", "50", "--time", "30s"]);
    assert_eq!(code, 2, "{c}");
    assert_eq!((&c["holds"], &c["status"], &c["exit_code"]), (&json!(false), &json!("broken"), &json!(2)));
    assert_eq!(c["property"], "max_calls search#find 2");
    assert!(c["searched"]["fuzz_runs"].as_u64().unwrap() >= 1, "{c}");
    let ce = &c["counterexample"];
    assert_eq!(ce["why"], "3 calls to search#find, at most 2 allowed");
    assert_eq!(ce["detail"], json!({"calls": 3, "max": 2}));
    assert!(ce["run"].as_str().is_some() && ce["original_run"].as_str().is_some());
    assert_eq!(each(&ce["host_results"], "n"), [1, 2, 3]);
    assert!(c["findings"].as_array().unwrap().iter().any(|x| x["kind"] == "check_failed"), "{c}");

    // The counterexample is stored now: no fuzzing.
    let (code, again) = f.cli(&["check", "max_calls", "search#find", "2", "--runs", "50", "--time", "30s"]);
    assert_eq!(code, 2, "{again}");
    assert_eq!(again["searched"], json!({"stored_runs": true}));

    let (code, holds) = f.cli(&["check", "max_calls", "search#find", "3", "--runs", "20", "--time", "30s"]);
    assert_eq!(code, 0, "{holds}");
    assert_eq!((&holds["holds"], &holds["status"], &holds["exit_code"]), (&json!(true), &json!("holds"), &json!(0)));
    assert!(holds["matches"].as_u64().unwrap() > 0);
    assert!(holds.get("counterexample").is_none());

    // A selector that selects nothing proves nothing.
    let (code, none) = f.cli(&["check", "value_range", "$.missing", "0", "1", "--runs", "10", "--time", "30s"]);
    assert_eq!(code, 3, "{none}");
    assert_eq!((&none["holds"], &none["status"], &none["matches"]), (&Value::Null, &json!("not_exercised"), &json!(0)));
}

#[test]
fn check_rejects_bad_properties() {
    let f = Fixture::strings();
    assert!(f.fails(&["check", "value_range", "!!", "0", "1"]).starts_with("bad selector \"!!\""));
    assert!(f.fails(&["check", "bogus"]).starts_with("unknown property \"bogus\""));
    assert_eq!(f.fails(&["check", "max_calls", "search#find", "-1"]), "max_calls requires a non-negative u32 integer");
    assert_eq!(f.fails(&["check", "value_range", ".x", "low", "1"]), "\"low\" is not a finite decimal number");
    assert!(f.fails(&["check", "no_crash", "--time", "soon"]).starts_with("bad duration \"soon\""));
}

#[test]
fn eval_evaluates_expressions_over_a_stored_run() {
    let f = Fixture::strings();
    assert_eq!(f.fails(&["eval", "last", "true"]), "no runs yet: run `appfuzz run` or `appfuzz review` first");
    let id = f.run(&[]);
    let e = f.ok(&["eval", "last", "q + \"!\"", "--let", "q=request.q"]);
    assert_eq!((&e["run"], &e["expression"], &e["value"]), (&json!(id), &json!("q + \"!\""), &json!("hello!")));
    assert_eq!(e["bindings"]["q"], json!({"path": "request.q", "value": "hello"}));
    assert_eq!(e["assume"], Value::Null);

    let calls = f.ok(&["eval", &id, "size(calls)", "--let", "calls=host.search#find.calls"]);
    assert_eq!(calls["value"], 3, "{calls}");
    // Three calls: no single result.
    let one = f.ok(&["eval", &id, "r > 0", "--let", "r=host.search#find.result"]);
    assert_eq!(one["value"], Value::Null);
    assert!(one["bindings"]["r"]["undefined"].as_str().is_some(), "{one}");
    let div = f.ok(&["eval", &id, "n / 0", "--let", "n=request.limit"]);
    assert!(div["value"]["error"].as_str().is_some(), "{div}");
    let assumed = f.ok(&["eval", &id, "n > 1", "--let", "n=request.limit", "--assume", "n > 100"]);
    assert_eq!((&assumed["assume"], &assumed["value"]), (&json!("n > 100"), &json!(true)));
    assert_ne!(assumed["status"], f.ok(&["eval", &id, "n > 1", "--let", "n=request.limit"])["status"], "{assumed}");

    assert_eq!(f.fails(&["eval", &id, "true", "--let", "bad"]), "--let needs name=path, got \"bad\"");
    assert_eq!(f.fails(&["eval", &id, "a", "--let", "a=request.q", "--let", "a=request.day"]), "--let binds a twice");
    assert_eq!(f.fails(&["eval", &id, "x", "--let", "x=host.nosuch.calls"]), "let x: host bindings name a function as interface#function (items#all)");
    assert_eq!(f.fails(&["eval", &id, "x", "--let", "x=host.nosuch#fn.calls"]), "let x = \"host.nosuch#fn.calls\": the app imports no host function nosuch#fn");
}

#[test]
fn bindings_list_paths_with_examples() {
    let f = Fixture::strings();
    let fresh = f.ok(&["bindings"]);
    assert_eq!(fresh["run"], Value::Null);
    // Without a run the request comes from the manifest, without examples.
    assert_eq!(
        fresh["request"],
        json!([
            {"path": "request.q", "example": null}, {"path": "request.day", "example": null},
            {"path": "request.limit", "example": null}, {"path": "request.tags.color", "example": null},
        ])
    );

    let id = f.run(&[]);
    let b = f.ok(&["bindings"]);
    assert_eq!(b["run"], id);
    assert_eq!(
        b["request"],
        json!([
            {"path": "request.q", "example": "hello"}, {"path": "request.day", "example": "2026-11-02"},
            {"path": "request.limit", "example": 5}, {"path": "request.tags.color", "example": "red"},
        ])
    );
    let host = &b["host"][0];
    assert_eq!(host["func"], FIND);
    assert_eq!(
        each(&host["paths"], "path"),
        ["host.search#find.calls", "host.search#find.results", "host.search#find.result", "host.search#find.args.q", "host.search#find.args.day"]
    );
    assert!(find(&host["paths"], "path", "host.search#find.result")["example"]["undefined"].as_str().is_some(), "{host}");
    assert_eq!(
        find(&host["paths"], "path", "host.search#find.args.q")["example"],
        json!({"undefined": "search#find was called 3 times; bind .results or .calls"})
    );
    assert_eq!(each(&b["output"], "path"), ["out.status", "out.body", "out.headers", "out.result", "out.json"]);
    assert_eq!(find(&b["output"], "path", "out.body")["example"], "hello");
    assert!(!b["sources"].as_array().unwrap().is_empty() && !b["functions"].as_array().unwrap().is_empty());

    // An unknown run gives no examples; an empty list of pairs a placeholder.
    assert_eq!(f.ok(&["bindings", "--run", "nosuch"])["run"], Value::Null);
    f.run(&["--request", &str_request("x", json!([]))]);
    let empty = f.ok(&["bindings"]);
    assert_eq!(find(&empty["request"], "path", "request.tags.<name>")["example"], Value::Null);
}
