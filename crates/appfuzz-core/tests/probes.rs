//! The probes: each asks one question with targeted runs. `values`: odd
//! host values; `times`: calendar edges; `web`: foreign origins and hosts;
//! `auth`: missing, forged and guessed credentials.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use appfuzz_core::{
    auth::Recipe,
    detect::{Finding, Severity},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    probe,
    record::{OutcomeKind, RunRecord, RunSpec},
};
use serde_json::{Value, json};

fn component(wit: &str, wat: &str) -> Vec<u8> {
    static POOL: std::sync::Once = std::sync::Once::new();
    POOL.call_once(|| rayon::ThreadPoolBuilder::new().num_threads(2).build_global().unwrap());
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("probes.wit", wit).unwrap();
    let world = resolve.select_world(&[pkg], Some("app")).unwrap();
    let mut module = wat::parse_str(wat).unwrap();
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
    wit_component::ComponentEncoder::default().module(&module).unwrap().validate(true).encode().unwrap()
}

fn app(manifest: &str, wit: &str, wat: &str) -> App {
    let manifest: Manifest = toml::from_str(manifest).unwrap();
    App::from_bytes(manifest, component(wit, wat)).unwrap()
}

/// The manifest's request at its time, with `plan`.
fn base(app: &App, plan: &str) -> RunSpec {
    let export = app.default_export().unwrap();
    let args = app.default_args(export, &app.manifest.start_time()).unwrap();
    app.spec(export, args, Plan::parse(plan).unwrap(), 1)
}

/// Runs specs and keeps the records, to look at after a probe.
struct Runs<'a> {
    app: &'a App,
    kept: Mutex<BTreeMap<String, RunRecord>>,
}

impl<'a> Runs<'a> {
    fn new(app: &'a App) -> Self {
        Runs { app, kept: Mutex::default() }
    }

    fn run(&self, spec: &RunSpec) -> RunRecord {
        let r = self.app.run(spec);
        self.kept.lock().unwrap().insert(r.id.clone(), r.clone());
        r
    }

    fn get(&self, id: &str) -> RunRecord {
        self.kept.lock().unwrap().get(id).unwrap_or_else(|| panic!("no run {id}")).clone()
    }

    fn all(&self) -> Vec<RunRecord> {
        self.kept.lock().unwrap().values().cloned().collect()
    }
}

fn of<'a>(findings: &'a [Finding], kind: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.kind == kind).collect()
}

fn hangs(kind: OutcomeKind) -> bool {
    matches!(kind, OutcomeKind::OutOfFuel | OutcomeKind::Timeout)
}

/// A bump allocator, and `$same`: whether two texts are equal, compared a
/// byte at a time.
const COMMON: &str = r#"
  (global $heap (mut i32) (i32.const 4096))
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.and (i32.add (i32.add (global.get $heap) (local.get 3)) (i32.const 7)) (i32.const -8)))
    (local.get $p))
  (func $same (param $a i32) (param $al i32) (param $b i32) (param $bl i32) (result i32)
    (local $i i32)
    (if (i32.ne (local.get $al) (local.get $bl)) (then (return (i32.const 0))))
    (block $done (loop $next
      (br_if $done (i32.ge_u (local.get $i) (local.get $al)))
      (if (i32.ne (i32.load8_u (i32.add (local.get $a) (local.get $i))) (i32.load8_u (i32.add (local.get $b) (local.get $i))))
        (then (return (i32.const 0))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $next)))
    (i32.const 1))"#;

// ---------------------------------------------------------------- values

const VALUES_WIT: &str = r#"package test:values;
  interface host {
    items: func() -> list<u32>;
    count: func() -> result<u32, string>;
    flag: func() -> option<u32>;
    note: func(msg: string);
  }
  world app { import host; export run: func() -> u32; }"#;

const ITEMS: &str = "test:values/host#items";
const COUNT: &str = "test:values/host#count";

/// Traps on an empty list of items, waits forever for a count that is an
/// error.
fn values_app(manifest: &str) -> App {
    let wat = format!(
        r#"(module
      (import "test:values/host" "items" (func $items (param i32)))
      (import "test:values/host" "count" (func $count (param i32)))
      (import "test:values/host" "flag" (func $flag (param i32)))
      (import "test:values/host" "note" (func $note (param i32 i32)))
      (memory (export "memory") 16)
      (data (i32.const 0) "seen")
      {COMMON}
      (func (export "run") (result i32)
        (call $items (i32.const 512))
        (if (i32.eqz (i32.load (i32.const 516))) (then unreachable))
        (call $count (i32.const 528))
        (if (i32.load8_u (i32.const 528)) (then (loop $forever (br $forever))))
        (call $flag (i32.const 544))
        (call $note (i32.const 0) (i32.const 4))
        (i32.load (i32.const 516))))"#
    );
    let manifest = format!("[app]\nwasm = \"values.wasm\"\n[entry]\nexport = \"run\"\n[limits]\nfuel = 1_000_000\n{manifest}");
    app(&manifest, VALUES_WIT, &wat)
}

fn tried(probes: &[probe::ValueProbe]) -> BTreeSet<(String, String)> {
    probes.iter().map(|p| (p.func.rsplit('#').next().unwrap().to_string(), p.variant.clone())).collect()
}

fn pairs(list: &[(&str, &str)]) -> BTreeSet<(String, String)> {
    list.iter().map(|(f, v)| (f.to_string(), v.to_string())).collect()
}

const STRINGS: [&str; 7] = ["empty strings", "unicode strings", "2-byte chars", "3-byte chars", "3-byte chars after 1 byte", "4-byte chars", "long strings"];

#[test]
fn values_names_the_host_value_that_breaks_the_app() {
    let app = values_app("");
    let runs = Runs::new(&app);
    let (probes, findings) = probe::values(&app, &base(&app, "{}"), None, &|s| runs.run(s));
    // Every class of every function with a result; `note` returns nothing to vary.
    let mut expect = vec![("items", "empty list"), ("items", "long list"), ("items", "edge numbers"), ("count", "err"), ("count", "edge numbers")];
    expect.extend(STRINGS.iter().map(|s| ("count", *s)));
    expect.extend([("flag", "none"), ("flag", "edge numbers")]);
    assert_eq!(tried(&probes), pairs(&expect));
    assert_eq!(probes.len(), expect.len());
    for p in &probes {
        let r = runs.get(&p.run);
        assert_eq!(p.outcome, r.outcome.kind);
        assert_eq!(p.host_calls, r.totals.host_calls);
        match (p.func.as_str(), p.variant.as_str()) {
            (ITEMS, "empty list") => assert_eq!((p.outcome, p.host_calls), (OutcomeKind::Unreachable, 1)),
            (COUNT, "err") => assert!(hangs(p.outcome) && p.host_calls == 2, "{p:?}"),
            // The other functions take the happy path meanwhile.
            _ => assert_eq!((p.outcome, p.host_calls), (OutcomeKind::Ok, 4), "{p:?}"),
        }
    }
    let crash = of(&findings, "crash_on_host_value");
    assert_eq!(crash.len(), 1, "{findings:#?}");
    let empty = probes.iter().find(|p| p.func == ITEMS && p.variant == "empty list").unwrap();
    assert_eq!(crash[0].severity, Severity::Fail);
    assert_eq!(crash[0].run.as_deref(), Some(empty.run.as_str()));
    assert_eq!((&crash[0].detail["func"], &crash[0].detail["variant"]), (&json!(ITEMS), &json!("empty list")));
    assert!(crash[0].detail["cause"].is_object());
    assert!(crash[0].title.starts_with(&format!("crash when {ITEMS} returns empty list: ")), "{}", crash[0].title);
    let hang = of(&findings, "hang_on_host_value");
    assert_eq!(hang.len(), 1, "{findings:#?}");
    assert_eq!((&hang[0].detail["func"], &hang[0].detail["variant"]), (&json!(COUNT), &json!("err")));
    // Renamed, not reported twice.
    assert!(of(&findings, "crash").is_empty() && of(&findings, "hang").is_empty());
}

#[test]
fn values_keeps_the_plans_latency_and_cost() {
    let app = values_app("");
    let runs = Runs::new(&app);
    let plan = format!(r#"{{"{ITEMS}": {{"return": [1, 2], "latency_ms": 7, "cost": 3}}}}"#);
    let (probes, _) = probe::values(&app, &base(&app, &plan), Some("#items"), &|s| runs.run(s));
    assert_eq!(tried(&probes), pairs(&[("items", "empty list"), ("items", "long list"), ("items", "edge numbers")]));
    let long = probes.iter().find(|p| p.variant == "long list").unwrap();
    let r = runs.get(&long.run);
    let call = r.events.iter().find(|e| e.func == ITEMS).unwrap();
    // The class replaced the plan's answer, not its timing or price.
    assert_eq!(call.result.as_ref().unwrap().as_array().unwrap().len(), 50);
    assert_eq!(call.latency_ns, 7_000_000);
    assert_eq!(call.cost, 3);
}

#[test]
fn values_tries_only_what_is_asked_and_what_can_happen() {
    // The platform says `count` never fails: it gets every odd value but
    // the error, which alone made it hang.
    let app = values_app(&format!("[functions.\"{COUNT}\"]\nfails = false"));
    let (probes, findings) = probe::values(&app, &base(&app, "{}"), None, &|s| app.run(s));
    let count: BTreeSet<&str> = probes.iter().filter(|p| p.func == COUNT).map(|p| p.variant.as_str()).collect();
    assert_eq!(count, ["edge numbers"].into_iter().chain(STRINGS).collect(), "{probes:?}");
    assert!(of(&findings, "hang_on_host_value").is_empty());
    assert_eq!(of(&findings, "crash_on_host_value").len(), 1);
    // `only` picks functions by a part of their name.
    let (probes, findings) = probe::values(&app, &base(&app, "{}"), Some("flag"), &|s| app.run(s));
    assert_eq!(tried(&probes), pairs(&[("flag", "none"), ("flag", "edge numbers")]));
    assert!(findings.iter().all(|f| !f.kind.ends_with("_on_host_value")));
    let (probes, findings) = probe::values(&app, &base(&app, "{}"), Some("no such function"), &|s| app.run(s));
    assert!(probes.is_empty() && findings.is_empty());
}

#[test]
fn values_resizes_a_modeled_collection_instead_of_generating_a_list() {
    let app = values_app(&format!(
        "[datasets.items]\nrows = 3\nkey = \"id\"\ntemplate = {{ id = 1 }}\n[functions.\"{ITEMS}\"]\nquery = {{ dataset = \"items\", select = \"id\" }}"
    ));
    let runs = Runs::new(&app);
    let (probes, findings) = probe::values(&app, &base(&app, "{}"), Some("#items"), &|s| runs.run(s));
    // Edge numbers would break the collection's keys: only its size changes.
    assert_eq!(tried(&probes), pairs(&[("items", "empty list"), ("items", "long list")]));
    for p in &probes {
        let r = runs.get(&p.run);
        let rows = r.spec.plan.0["_defaults"].dataset_rows["items"];
        let ids = r.events[0].result.as_ref().unwrap().as_array().unwrap().clone();
        match p.variant.as_str() {
            "empty list" => assert_eq!((rows, ids.len(), p.outcome), (0, 0, OutcomeKind::Unreachable)),
            _ => {
                assert_eq!((rows, p.outcome), (50, OutcomeKind::Ok));
                assert_eq!(ids, (1..=50).map(|i| json!(i)).collect::<Vec<_>>());
            }
        }
        assert!(!r.spec.plan.0.contains_key(ITEMS), "the collection answers, not a plan entry");
    }
    assert_eq!(of(&findings, "crash_on_host_value").len(), 1);
}

// ----------------------------------------------------------------- times

const TIMES_WIT: &str = r#"package test:times;
  world app {
    record request { today: string }
    export run: func(req: request) -> string;
  }"#;

/// Traps on a leap day and never returns in the 22nd century; with
/// `always`, traps at any time.
fn times_app(always: bool, clock_field: bool) -> App {
    let wat = format!(
        r#"(module
      (memory (export "memory") 1)
      (data (i32.const 0) "02-29")
      (data (i32.const 8) "21")
      (data (i32.const 16) "ok")
      {COMMON}
      (func (export "run") (param $p i32) (param $l i32) (result i32)
        {always}
        (if (i32.eq (local.get $l) (i32.const 10)) (then
          (if (call $same (i32.add (local.get $p) (i32.const 5)) (i32.const 5) (i32.const 0) (i32.const 5)) (then unreachable))
          (if (call $same (local.get $p) (i32.const 2) (i32.const 8) (i32.const 2)) (then (loop $forever (br $forever))))))
        (i32.store (i32.const 32) (i32.const 16))
        (i32.store (i32.const 36) (i32.const 2))
        (i32.const 32)))"#,
        always = if always { "unreachable" } else { "" }
    );
    let fields = if clock_field { "fields = { today = \"clock.date\" }" } else { "" };
    let manifest = format!(
        "[app]\nwasm = \"times.wasm\"\n[entry]\nexport = \"run\"\nrequest = {{ today = \"\" }}\n{fields}\nnow = \"2026-11-02T10:00:00\"\n[limits]\nfuel = 1_000_000"
    );
    app(&manifest, TIMES_WIT, &wat)
}

#[test]
fn times_names_the_time_that_breaks_the_app() {
    let app = times_app(false, true);
    let runs = Runs::new(&app);
    let base = base(&app, "{}");
    assert_eq!(base.args[0]["today"], "2026-11-02");
    let (probes, findings) = probe::times(&app, &base, &|s| runs.run(s));
    assert_eq!(probes.len(), probe::EDGE_TIMES.len());
    for (p, (now, what)) in probes.iter().zip(probe::EDGE_TIMES) {
        assert_eq!((p.now.as_str(), p.what.as_str()), (*now, *what));
        let r = runs.get(&p.run);
        // The request's clock field follows the time.
        assert_eq!((r.spec.now.as_str(), &r.spec.args[0]["today"]), (*now, &json!(&now[..10])));
        match *what {
            "leap day" => assert_eq!(p.outcome, OutcomeKind::Unreachable),
            "February of a non-leap century" | "far future" => assert!(hangs(p.outcome), "{p:?}"),
            _ => assert_eq!(p.outcome, OutcomeKind::Ok, "{p:?}"),
        }
    }
    // The edge times and the request's own: a hang ends at twice the
    // production limit, not at the five times of an ordinary run.
    assert_eq!(base.fuel, 5_000_000);
    let all = runs.all();
    assert_eq!(all.len(), probe::EDGE_TIMES.len() + 1);
    assert!(all.iter().all(|r| r.spec.fuel == 2_000_000));
    let crash = of(&findings, "crash_at_time");
    assert_eq!(crash.len(), 1, "{findings:#?}");
    assert_eq!((&crash[0].detail["now"], &crash[0].detail["what"]), (&json!("2028-02-29T12:00:00"), &json!("leap day")));
    assert_eq!(crash[0].severity, Severity::Fail);
    assert!(crash[0].title.starts_with("crash at 2028-02-29T12:00:00 (leap day): "), "{}", crash[0].title);
    let hang: BTreeSet<&str> = of(&findings, "hang_at_time").iter().map(|f| f.detail["now"].as_str().unwrap()).collect();
    assert_eq!(hang, BTreeSet::from(["2100-02-28T12:00:00", "2199-12-31T23:59:59"]));
    assert!(of(&findings, "crash").is_empty() && of(&findings, "hang").is_empty());
}

#[test]
fn a_crash_at_every_time_is_not_the_times_fault() {
    let app = times_app(true, true);
    let (probes, findings) = probe::times(&app, &base(&app, "{}"), &|s| app.run(s));
    assert!(probes.iter().all(|p| p.outcome == OutcomeKind::Unreachable));
    assert!(!of(&findings, "crash").is_empty());
    assert!(findings.iter().all(|f| !f.kind.ends_with("_at_time")), "{findings:#?}");
}

#[test]
fn only_declared_clock_fields_follow_the_time() {
    let app = times_app(false, false);
    let runs = Runs::new(&app);
    let (probes, findings) = probe::times(&app, &base(&app, "{}"), &|s| runs.run(s));
    for p in &probes {
        let r = runs.get(&p.run);
        assert_eq!((r.spec.now.as_str(), &r.spec.args[0]["today"]), (p.now.as_str(), &json!("")));
        assert_eq!(p.outcome, OutcomeKind::Ok);
    }
    assert!(findings.iter().all(|f| !f.kind.ends_with("_at_time")));
}

// ---------------------------------------------------------- web and auth

const HTTP_WIT: &str = r#"package test:http;
  interface host {
    secret: func() -> string;
    lookup: func(token: string) -> bool;
    fetch: func(url: string) -> string;
  }
  world app {
    import host;
    record request { method: string, uri: string, headers: list<tuple<string, string>>, body: string, now: string }
    record response { status: u16, headers: list<tuple<string, string>>, body: string }
    export handle: func(req: request) -> response;
  }"#;

/// Texts in the handler's memory, 64 bytes apart; `[name]` in its code is
/// the address and length of one.
const TEXTS: [(&str, &str); 18] = [
    ("origin", "origin"),
    ("acao", "access-control-allow-origin"),
    ("acac", "access-control-allow-credentials"),
    ("true", "true"),
    ("authorization", "authorization"),
    ("bearer", "Bearer "),
    ("set-cookie", "set-cookie"),
    ("session", "session=0123456789abcdef; HttpOnly; Secure"),
    ("x-forwarded-host", "x-forwarded-host"),
    ("host", "host"),
    ("link", "<a href=\"https://"),
    ("reset", "/reset\">reset</a>"),
    ("https", "https://"),
    ("ping", "/v1/ping"),
    ("session-t", "session=t"),
    ("flags", "; HttpOnly; Secure"),
    ("location", "location"),
    ("login", "/login"),
];

/// Turns away a request without an Authorization header.
const LOGIN: &str = "(if (i32.eqz (call $header [authorization])) (then (return (call $respond (i32.const 401)))))";
/// Sends a request without one to the login page.
const LOGIN_PAGE: &str = "(if (i32.eqz (call $header [authorization])) (then (call $add [location] [login]) (return (call $respond (i32.const 302)))))";
/// Lets in a request with `Bearer <secret>`, compared a byte at a time,
/// and gives it a session.
const COMPARE: &str = r#"
  (local.set $h (call $header [authorization]))
  (if (i32.eqz (local.get $h)) (then (return (call $respond (i32.const 401)))))
  (call $secret (i32.const 2304))
  (if (call $bearer (i32.load offset=8 (local.get $h)) (i32.load offset=12 (local.get $h)) (i32.load (i32.const 2304)) (i32.load (i32.const 2308)))
    (then (call $add [set-cookie] [session]) (return (call $respond (i32.const 200)))))
  (call $respond (i32.const 401))"#;
/// Lets in whatever token the host's lookup accepts.
const LOOKUP: &str = r#"
  (local.set $h (call $header [authorization]))
  (if (i32.eqz (local.get $h)) (then (return (call $respond (i32.const 401)))))
  (if (call $lookup (i32.load offset=8 (local.get $h)) (i32.load offset=12 (local.get $h)))
    (then (return (call $respond (i32.const 200)))))
  (call $respond (i32.const 401))"#;
/// The same session for everyone.
const SESSION: &str = "(call $add [set-cookie] [session]) (call $respond (i32.const 200))";
/// A session made from the time of the request.
const CLOCK_SESSION: &str = r#"
  (call $start) (call $put [session-t]) (call $put (local.get $np) (local.get $nl)) (call $put [flags])
  (call $add [set-cookie] (call $done) (global.get $len))
  (call $respond (i32.const 200))"#;
/// Repeats the Origin with credentials, links to the X-Forwarded-Host and
/// fetches from the Host.
const WEB: &str = r#"
  (local.set $h (call $header [origin]))
  (if (local.get $h) (then
    (call $add [acao] (i32.load offset=8 (local.get $h)) (i32.load offset=12 (local.get $h)))
    (call $add [acac] [true])))
  (local.set $h (call $header [x-forwarded-host]))
  (if (local.get $h) (then
    (call $start) (call $put [link]) (call $put (i32.load offset=8 (local.get $h)) (i32.load offset=12 (local.get $h))) (call $put [reset])
    (global.set $bp (call $done)) (global.set $bl (global.get $len))))
  (local.set $h (call $header [host]))
  (if (local.get $h) (then
    (call $start) (call $put [https]) (call $put (i32.load offset=8 (local.get $h)) (i32.load offset=12 (local.get $h))) (call $put [ping])
    (call $fetch (call $done) (global.get $len) (i32.const 2304))))
  (call $respond (i32.const 200))"#;

const SECRET: &str = "test:http/host#secret";

/// An HTTP handler as a record export (the response at 2048, its headers
/// at 2112) whose code is `body`.
fn http_app(body: &str) -> App {
    let mut wat = format!(
        r#"(module
      (import "test:http/host" "secret" (func $secret (param i32)))
      (import "test:http/host" "lookup" (func $lookup (param i32 i32) (result i32)))
      (import "test:http/host" "fetch" (func $fetch (param i32 i32 i32)))
      (memory (export "memory") 16)
      (global $req_h (mut i32) (i32.const 0))
      (global $req_n (mut i32) (i32.const 0))
      (global $n (mut i32) (i32.const 0))
      (global $bp (mut i32) (i32.const 0))
      (global $bl (mut i32) (i32.const 0))
      (global $len (mut i32) (i32.const 0))
      [texts]
      {COMMON}
      (func $header (param $p i32) (param $l i32) (result i32)
        (local $e i32) (local $end i32)
        (local.set $e (global.get $req_h))
        (local.set $end (i32.add (global.get $req_h) (i32.mul (global.get $req_n) (i32.const 16))))
        (block $none (loop $next
          (br_if $none (i32.ge_u (local.get $e) (local.get $end)))
          (if (call $same (i32.load (local.get $e)) (i32.load offset=4 (local.get $e)) (local.get $p) (local.get $l))
            (then (return (local.get $e))))
          (local.set $e (i32.add (local.get $e) (i32.const 16)))
          (br $next)))
        (i32.const 0))
      (func $add (param $np i32) (param $nl i32) (param $vp i32) (param $vl i32)
        (local $e i32)
        (local.set $e (i32.add (i32.const 2112) (i32.mul (global.get $n) (i32.const 16))))
        (i32.store (local.get $e) (local.get $np))
        (i32.store offset=4 (local.get $e) (local.get $nl))
        (i32.store offset=8 (local.get $e) (local.get $vp))
        (i32.store offset=12 (local.get $e) (local.get $vl))
        (global.set $n (i32.add (global.get $n) (i32.const 1))))
      (func $start (global.set $len (i32.const 0)))
      (func $put (param $p i32) (param $l i32)
        (memory.copy (i32.add (global.get $heap) (global.get $len)) (local.get $p) (local.get $l))
        (global.set $len (i32.add (global.get $len) (local.get $l))))
      (func $done (result i32)
        (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.and (i32.add (i32.add (global.get $heap) (global.get $len)) (i32.const 7)) (i32.const -8)))
        (local.get $p))
      (func $bearer (param $vp i32) (param $vl i32) (param $sp i32) (param $sl i32) (result i32)
        (if (i32.ne (local.get $vl) (i32.add (local.get $sl) (i32.const 7))) (then (return (i32.const 0))))
        (if (i32.eqz (call $same (local.get $vp) (i32.const 7) [bearer])) (then (return (i32.const 0))))
        (call $same (i32.add (local.get $vp) (i32.const 7)) (local.get $sl) (local.get $sp) (local.get $sl)))
      (func $respond (param $status i32) (result i32)
        (i32.store16 (i32.const 2048) (local.get $status))
        (i32.store (i32.const 2052) (i32.const 2112))
        (i32.store (i32.const 2056) (global.get $n))
        (i32.store (i32.const 2060) (global.get $bp))
        (i32.store (i32.const 2064) (global.get $bl))
        (i32.const 2048))
      (func (export "handle") (param $mp i32) (param $ml i32) (param $up i32) (param $ul i32) (param $hp i32) (param $hl i32)
          (param $bodyp i32) (param $bodyl i32) (param $np i32) (param $nl i32) (result i32)
        (local $h i32)
        (global.set $req_h (local.get $hp))
        (global.set $req_n (local.get $hl))
        {body}))"#
    );
    let mut data = String::new();
    for (i, (name, text)) in TEXTS.iter().enumerate() {
        wat = wat.replace(&format!("[{name}]"), &format!("(i32.const {}) (i32.const {})", i * 64, text.len()));
        data += &format!("(data (i32.const {}) \"{}\")\n", i * 64, text.replace('"', "\\\""));
    }
    let wat = wat.replace("[texts]", &data);
    assert!(!wat.contains('['), "a text without a name in TEXTS");
    let manifest = format!(
        r#"[app]
        wasm = "http.wasm"
        [entry]
        export = "handle"
        request = {{ method = "GET", uri = "https://app.example/account", headers = [["host", "app.example"]], body = "", now = "" }}
        fields = {{ now = "clock.datetime" }}
        output = {{ status = "status", headers = "headers", body = "body" }}
        now = "2026-11-02T10:00:00"
        [limits]
        fuel = 10_000_000
        [functions."{SECRET}"]
        result = "secret""#
    );
    app(&manifest, HTTP_WIT, &wat)
}

fn status(r: &RunRecord) -> &Value {
    &r.result.as_ref().unwrap()["status"]
}

fn header<'a>(req: &'a Value, name: &str) -> Option<&'a str> {
    req["headers"].as_array()?.iter().find(|h| h[0].as_str().is_some_and(|k| k.eq_ignore_ascii_case(name)))?[1].as_str()
}

#[test]
fn web_finds_a_repeated_origin_and_a_trusted_host() {
    let app = http_app(WEB);
    let runs = Runs::new(&app);
    let (probes, findings) = probe::web(&app, &base(&app, "{}"), &|s| runs.run(s));
    let origins = ["https://attacker.example", "null", "https://app.example.attacker.example", "https://notapp.example"];
    let mut whats: Vec<String> = origins.iter().flat_map(|o| [format!("Origin: {o}"), format!("preflight from {o}")]).collect();
    whats.extend(["the URI's host", "Host header", "X-Forwarded-Host header", "Forwarded header"].map(String::from));
    assert_eq!(probes.iter().map(|p| p.what.clone()).collect::<Vec<_>>(), whats);
    assert!(probes.iter().all(|p| p.outcome == OutcomeKind::Ok));
    let preflight = runs.get(&probes[1].run);
    assert_eq!(preflight.spec.args[0]["method"], "OPTIONS");
    assert_eq!(header(&preflight.spec.args[0], "access-control-request-method"), Some("POST"));
    // Every foreign origin, in a preflight too, may read the response with cookies.
    let cors = of(&findings, "permissive_cors");
    assert_eq!(cors.len(), 8, "{cors:#?}");
    assert!(cors.iter().all(|f| f.severity == Severity::Fail));
    let cors_origins: BTreeSet<&str> = cors.iter().map(|f| f.detail["origin"].as_str().unwrap()).collect();
    assert_eq!(cors_origins, BTreeSet::from(origins));
    let run_of = |what: &str| probes.iter().find(|p| p.what == what).unwrap().run.clone();
    let hosts = of(&findings, "host_header_injection");
    let seen: Vec<(&str, &str, Severity, String)> =
        hosts.iter().map(|f| (f.detail["from"].as_str().unwrap(), f.detail["place"].as_str().unwrap(), f.severity, f.run.clone().unwrap())).collect();
    assert_eq!(
        seen,
        [
            ("the Host header", "the URL of test:http/host#fetch", Severity::Fail, run_of("Host header")),
            ("the X-Forwarded-Host header", "a link in the response", Severity::Warn, run_of("X-Forwarded-Host header")),
        ]
    );
}

#[test]
fn web_reports_nothing_the_app_does_not_do() {
    let app = http_app("(call $respond (i32.const 200))");
    let (probes, findings) = probe::web(&app, &base(&app, "{}"), &|s| app.run(s));
    assert_eq!(probes.len(), 12);
    assert!(findings.iter().all(|f| !matches!(f.kind.as_str(), "permissive_cors" | "host_header_injection")), "{findings:#?}");
    // Not an HTTP request: no uri and headers, or no argument at all.
    for app in [times_app(false, true), values_app("")] {
        let runs = Runs::new(&app);
        let (probes, findings) = probe::web(&app, &base(&app, "{}"), &|s| runs.run(s));
        assert!(probes.is_empty() && findings.is_empty() && runs.all().is_empty());
    }
}

#[test]
fn auth_finds_credentials_that_are_only_looked_at() {
    let app = http_app(&format!("{LOGIN} (call $respond (i32.const 200))"));
    let runs = Runs::new(&app);
    let base = base(&app, "{}");
    let at = |uri: &str| {
        let mut s = base.clone();
        s.args[0]["uri"] = json!(uri);
        s
    };
    let mut signed_in = at("https://app.example/account?page=2");
    signed_in.args[0]["headers"].as_array_mut().unwrap().push(json!(["Authorization", "Bearer real"]));
    let bases = [
        RunSpec { args: vec![], ..base.clone() },
        RunSpec { args: vec![json!({"path": "/account"})], ..base.clone() },
        base.clone(),
        signed_in,
        at("https://app.example/other"),
    ];
    let (probes, findings) = probe::auth(&app, &bases, &|s| runs.run(s));
    // Each method and path once; what is no HTTP request not at all.
    let anon: Vec<&probe::AuthProbe> = probes.iter().filter(|p| p.what == "no credentials").collect();
    assert_eq!(anon.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(), ["/account", "/other"]);
    assert!(anon.iter().all(|p| header(&runs.get(&p.run).spec.args[0], "authorization").is_none()));
    assert_eq!(probes.len(), 2 * 9, "{probes:#?}");
    // One finding for the export, from the first path.
    let bypass = of(&findings, "auth_bypass");
    assert_eq!(bypass.len(), 1, "{findings:#?}");
    let f = bypass[0];
    assert_eq!((f.severity, &f.detail["path"], &f.detail["anonymous_status"]), (Severity::Fail, &json!("/account"), &json!(401)));
    let accepted: BTreeSet<&str> = f.detail["accepted"].as_array().unwrap().iter().map(|a| a["what"].as_str().unwrap()).collect();
    let in_authorization = ["a made-up bearer token", "Bearer null", "an unsigned JWT (alg none)", "a JWT with a wrong signature", "Basic admin:admin"];
    assert_eq!(accepted, BTreeSet::from(in_authorization));
    assert_eq!(f.detail["auth"], json!({"check": "bypass", "forged": "a made-up bearer token"}));
    assert_eq!(f.detail["base_run"], f.detail["anonymous_run"]);
    let shown = runs.get(f.run.as_deref().unwrap());
    assert_eq!(header(&shown.spec.args[0], "authorization"), Some("Bearer afz-forged-token-0000"));
    assert_eq!(status(&shown), 200);
    assert!(of(&findings, "timing_unsafe_compare").is_empty() && of(&findings, "predictable_token").is_empty());

    // Again from the run it started from, with that credential alone.
    let again = probe::auth_again(&app, &Recipe::Bypass { forged: "a made-up bearer token".into() }, &base, &|s| runs.run(s));
    assert_eq!(again.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), [f.id.as_str()]);
    assert_eq!(again[0].detail["accepted"].as_array().unwrap().len(), 1);
    // A credential the app does not read gets nowhere.
    assert!(probe::auth_again(&app, &Recipe::Bypass { forged: "a made-up API key".into() }, &base, &|s| runs.run(s)).is_empty());
}

#[test]
fn auth_counts_a_redirect_to_the_login_as_turned_away() {
    let app = http_app(&format!("{LOGIN_PAGE} (call $respond (i32.const 200))"));
    let (_, findings) = probe::auth(&app, &[base(&app, "{}")], &|s| app.run(s));
    let bypass = of(&findings, "auth_bypass");
    assert_eq!(bypass.len(), 1, "{findings:#?}");
    assert_eq!(bypass[0].detail["anonymous_status"], 302);
}

#[test]
fn auth_leaves_the_decision_to_the_host_that_checked_the_credential() {
    let app = http_app(LOOKUP);
    // The token service accepts every forged token it is shown.
    let plan = r#"{"test:http/host#lookup": {"rules": [{"when": {"token": "Bearer null"}, "return": false}], "return": true}}"#;
    let runs = Runs::new(&app);
    let (probes, findings) = probe::auth(&app, &[base(&app, plan)], &|s| runs.run(s));
    let let_in: Vec<&str> = probes.iter().filter(|p| status(&runs.get(&p.run)) == 200).map(|p| p.what.as_str()).collect();
    assert_eq!(let_in, ["a made-up bearer token", "an unsigned JWT (alg none)", "a JWT with a wrong signature", "Basic admin:admin"]);
    assert!(of(&findings, "auth_bypass").is_empty(), "{findings:#?}");
}

#[test]
fn auth_leaves_bearer_null_to_the_host_that_checked_it() {
    let app = http_app(LOOKUP);
    let plan = r#"{"test:http/host#lookup": {"return": true}}"#;
    let runs = Runs::new(&app);
    let (_, findings) = probe::auth(&app, &[base(&app, plan)], &|s| runs.run(s));
    // The app sent `Bearer null` to the token service, as it did the other forged tokens.
    assert!(of(&findings, "auth_bypass").is_empty(), "{findings:#?}");
}

#[test]
fn auth_finds_a_secret_compared_one_character_at_a_time() {
    let app = http_app(COMPARE);
    let runs = Runs::new(&app);
    let secret = "sk_live_9f8e7d6c5b4a";
    let base = base(&app, &format!(r#"{{"{SECRET}": {{"return": "{secret}"}}}}"#));
    let (probes, findings) = probe::auth(&app, std::slice::from_ref(&base), &|s| runs.run(s));
    let timing = of(&findings, "timing_unsafe_compare");
    assert_eq!(timing.len(), 1, "{findings:#?}");
    let f = timing[0];
    assert_eq!((f.severity, &f.detail["credential"]), (Severity::Warn, &json!("the bearer token")));
    assert_eq!(f.detail["prefix_lengths"], json!((0..secret.len()).collect::<Vec<_>>()));
    let fuel: Vec<u64> = f.detail["fuel"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
    assert!(fuel.windows(2).all(|w| w[0] <= w[1]) && fuel[0] < fuel[fuel.len() - 1], "{fuel:?}");
    assert_eq!(runs.get(f.detail["control_run"].as_str().unwrap()).totals.fuel, fuel[0]);
    assert_eq!(f.detail["auth"], json!({"check": "timing", "forged": "a made-up bearer token"}));
    // It starts from the run with the made-up token, which read the secret.
    let started = runs.get(f.detail["base_run"].as_str().unwrap());
    assert_eq!(header(&started.spec.args[0], "authorization"), Some("Bearer afz-forged-token-0000"));
    let prefixes: Vec<&probe::AuthProbe> = probes.iter().filter(|p| p.what.starts_with("the bearer token: ")).collect();
    assert_eq!(prefixes.len(), secret.len());
    let last = runs.get(&prefixes[prefixes.len() - 1].run);
    assert_eq!(header(&last.spec.args[0], "authorization").unwrap().len(), "Bearer ".len() + secret.len());
    // The app checks the token: no bypass. Its session comes with the
    // secret, so it is not guessable, though the same with every seed.
    assert!(of(&findings, "auth_bypass").is_empty());
    assert_eq!(probes.iter().filter(|p| p.what.starts_with("the session token with ")).count(), 3);
    assert!(of(&findings, "predictable_token").is_empty(), "{findings:#?}");

    let again = probe::auth_again(&app, &Recipe::Timing { forged: "a made-up bearer token".into() }, &started.spec, &|s| runs.run(s));
    assert_eq!(again.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(), [f.id.as_str()]);
    // Only a credential the app compares has prefixes to try.
    assert!(probe::auth_again(&app, &Recipe::Timing { forged: "Bearer null".into() }, &started.spec, &|s| runs.run(s)).is_empty());
}

#[test]
fn auth_finds_a_session_anyone_can_guess() {
    let app = http_app(SESSION);
    let runs = Runs::new(&app);
    let base = base(&app, "{}");
    let (probes, findings) = probe::auth(&app, std::slice::from_ref(&base), &|s| runs.run(s));
    // Nothing is turned away, so nothing is forged.
    let whats: Vec<&str> = probes.iter().map(|p| p.what.as_str()).collect();
    assert_eq!(
        whats,
        ["no credentials", "the session token with another random seed", "the session token with a third random seed", "the session token with a second later"]
    );
    let token = of(&findings, "predictable_token");
    assert_eq!(token.len(), 1, "{findings:#?}");
    let f = token[0];
    assert_eq!(f.severity, Severity::Fail);
    assert_eq!(
        (&f.detail["place"], &f.detail["value"], &f.detail["clock_dependent"]),
        (&json!("the cookie session"), &json!("0123456789abcdef"), &json!(false))
    );
    assert!(f.title.contains("it is the same every time"), "{}", f.title);
    let seeds: Vec<u64> = f.detail["seed_runs"].as_array().unwrap().iter().map(|id| runs.get(id.as_str().unwrap()).spec.seed).collect();
    assert_eq!(seeds, [base.seed + 1, base.seed + 2]);
    assert_eq!(f.detail["auth"], json!({"check": "token"}));
    assert!(of(&findings, "auth_bypass").is_empty());

    let again = probe::auth_again(&app, &Recipe::Token, &base, &|s| runs.run(s));
    assert_eq!(again.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(), [f.id.as_str()]);
    // Nothing turned away: no bypass to repeat.
    assert!(probe::auth_again(&app, &Recipe::Bypass { forged: "Bearer null".into() }, &base, &|s| runs.run(s)).is_empty());
}

#[test]
fn auth_finds_a_session_made_from_the_clock() {
    let app = http_app(CLOCK_SESSION);
    let runs = Runs::new(&app);
    let base = base(&app, "{}");
    assert_eq!(base.args[0]["now"], "2026-11-02T10:00:00");
    let (_, findings) = probe::auth(&app, &[base], &|s| runs.run(s));
    let token = of(&findings, "predictable_token");
    assert_eq!(token.len(), 1, "{findings:#?}");
    let f = token[0];
    assert_eq!((&f.detail["value"], &f.detail["clock_dependent"]), (&json!("t2026-11-02T10:00:00"), &json!(true)));
    assert!(f.title.contains("made from the clock"), "{}", f.title);
    // A second later, in the clock and in the request's clock field.
    let later = runs.get(f.detail["clock_run"].as_str().unwrap());
    assert_eq!((later.spec.now.as_str(), &later.spec.args[0]["now"]), ("2026-11-02T10:00:01", &json!("2026-11-02T10:00:01")));
}

#[test]
fn auth_has_nothing_to_try_without_an_http_request() {
    let app = times_app(false, true);
    let runs = Runs::new(&app);
    let base = base(&app, "{}");
    let (probes, findings) = probe::auth(&app, std::slice::from_ref(&base), &|s| runs.run(s));
    assert!(probes.is_empty() && findings.is_empty());
    for recipe in [Recipe::Bypass { forged: "a made-up bearer token".into() }, Recipe::Timing { forged: "a made-up bearer token".into() }] {
        assert!(probe::auth_again(&app, &recipe, &base, &|s| runs.run(s)).is_empty());
    }
    // Timing runs the spec once to find the secret it read; bypass not even that.
    assert_eq!(runs.all().len(), 1);
}
