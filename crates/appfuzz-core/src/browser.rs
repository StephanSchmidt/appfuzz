//! The page's scripts, run: a browser guest (QuickJS with a DOM shim, in
//! `assets/browser/`) loads the page an app served, runs its scripts in a
//! browser's order, clicks what can be clicked and lets virtual time pass.
//! appfuzz's own harness runs the guest, so fuel, the virtual clock and
//! records work for scripts as they do for apps.
//!
//! What the page does crosses into the host as calls of the
//! `appfuzz:browser` world: requests to its own origin go to the app under
//! test (each one a run of the app, sharing one dataset world), requests to
//! other origins get generated answers, and markup, code and navigations
//! the page makes are recorded. The findings here judge those calls: who
//! wrote what the page's scripts did, the app's own code, the visitor's
//! request or host data.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock, mpsc};

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::harness::{App, Routed, Router};
use crate::labels::Label;
use crate::manifest::Manifest;
use crate::output::CANARY;
use crate::par::Runner;
use crate::plan::Plan;
use crate::record::{HostCall, OutcomeKind, RunRecord};

/// The browser guest, built by `make browser` (see `PROVENANCE.txt`).
pub const GUEST: &[u8] = include_bytes!("../assets/browser/browser.wasm");

/// The origin pages are served from.
pub const ORIGIN: &str = "https://app.example";

pub const SESSION: &str = "appfuzz:browser/page#session";
pub const FETCH_OWN: &str = "appfuzz:browser/net#fetch-own";
pub const FETCH_OTHER: &str = "appfuzz:browser/net#fetch-other";
pub const GO: &str = "appfuzz:browser/nav#go";
pub const HTML: &str = "appfuzz:browser/sink#html";
pub const CODE: &str = "appfuzz:browser/sink#code";

/// Requests to the app one session may make; later ones fail.
const MAX_FETCHES: usize = 64;
/// The cookie the page gets with a secret in it: readable by scripts, so
/// sending it to another host is a `secret_leak`.
pub const COOKIE: &str = "af_session";
/// The share of the idle CPU a page may use (timers that poll, animations).
const IDLE_CPU_MAX: f64 = 0.1;
/// Requests of one shape (`/items/{n}`) that make a request per item.
const PER_ITEM_MIN: usize = 3;

/// The browser guest as an app: one page session per call.
pub struct Browser {
    pub app: App,
}

/// One page session and the app runs it made.
pub struct Session {
    pub browser: RunRecord,
    /// The app's runs for the page's requests to its own origin, in order.
    pub nested: Vec<RunRecord>,
    /// What the guest reported: errors, console, requests, navigations,
    /// unmodelled APIs, the page's text.
    pub report: Value,
    /// The canary in the page URL's fragment.
    pub fragment: String,
}

impl Session {
    /// Whether the visit can be judged. A measured fuel/time failure is
    /// a finding; an engine, plan or capture error leaves the analysis
    /// incomplete, as does a missing report from an otherwise ok guest.
    pub fn ensure_executed(&self) -> Result<()> {
        let b = &self.browser;
        let budget = matches!(b.outcome.kind, OutcomeKind::OutOfFuel | OutcomeKind::Timeout | OutcomeKind::BudgetExceeded);
        if b.capture_limited || (b.outcome.kind != OutcomeKind::Ok && !budget) {
            anyhow::bail!("browser visit {}: {}", b.id, b.outcome.message.as_deref().unwrap_or("the page session could not execute"));
        }
        if !budget && (!self.report["url"].is_string() || !self.report["errors"].is_array() || self.report.get("fatal").is_some()) {
            anyhow::bail!("browser visit {}: no complete session report ({})", b.id, self.report.get("fatal").unwrap_or(&Value::Null));
        }
        for r in &self.nested {
            if r.capture_limited || matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
                anyhow::bail!("browser visit {}, app request {}: {}", b.id, r.id, r.outcome.message.as_deref().unwrap_or("the request could not execute"));
            }
        }
        Ok(())
    }
}

// ns_per_fuel: QuickJS interprets the scripts a browser compiles. A
// browser runs them about 25 times faster than QuickJS does, so a unit of
// the guest's fuel counts 0.02 ns of the page's CPU (appfuzz's default,
// 0.5, is for code compiled to Wasm).
const MANIFEST: &str = r#"
[app]
wasm = "browser.wasm"
name = "appfuzz-browser"

[entry]
export = "appfuzz:browser/page#session"

[limits]
fuel = 2_000_000_000
memory = "256MiB"
wall_timeout_ms = 120_000
ns_per_fuel = 0.02

[functions."appfuzz:browser/net#fetch-other"]
latency_ms = 50.0
[functions."appfuzz:browser/nav#go"]
latency_ms = 0.0
cost = 0
[functions."appfuzz:browser/sink#html"]
latency_ms = 0.0
cost = 0
[functions."appfuzz:browser/sink#code"]
latency_ms = 0.0
cost = 0
"#;

static SHARED: OnceLock<std::result::Result<Browser, String>> = OnceLock::new();

impl Browser {
    pub fn new() -> Result<Self> {
        let m: Manifest = toml::from_str(MANIFEST)?;
        Ok(Browser { app: App::from_bytes(m, GUEST.to_vec())? })
    }

    /// The browser, compiled once per process.
    pub fn shared() -> Result<&'static Browser> {
        SHARED.get_or_init(|| Browser::new().map_err(|e| format!("{e:#}"))).as_ref().map_err(|e| anyhow!("the browser guest: {e}"))
    }

    /// Runs the page an app run served. `page` is a run of `target` whose
    /// response is HTML; `run` runs the app for the page's requests to its
    /// own origin.
    pub fn session(&self, target: &App, page: &RunRecord, run: Runner) -> Result<Session> {
        let m = &target.manifest;
        let resp = crate::output::response(page, m);
        let req = page.spec.args.first().cloned().unwrap_or(Value::Null);
        let fragment = crate::output::canary(page.spec.seed.wrapping_mul(7919).wrapping_add(4242) % 1_000_000 + 900_000);
        let url = format!("{}#{}", page_url(&req), fragment);
        let request_cookies: Vec<String> = pairs(req.get("headers")).into_iter().filter(|(k, _)| k.eq_ignore_ascii_case("cookie")).map(|(_, v)| v).collect();
        let set_cookies: Vec<&str> = resp.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.as_str()).collect();
        // Keep response attributes intact for the browser's cookie jar.
        // The readable probe cookie gets an unused name so real credentials
        // named af_session are preserved.
        let input = json!({
            "url": url, "html": resp.body.unwrap_or_default(),
            "request_cookies": request_cookies, "set_cookies": set_cookies,
            "probe_cookie": {"name": COOKIE, "value": secret_cookie(page.spec.seed)},
            "page_run": page.id,
        });
        let export = self.app.default_export()?.clone();
        let mut spec = self.app.spec(&export, vec![Value::String(input.to_string())], Plan::default(), page.spec.seed);
        spec.now.clone_from(&page.spec.now);

        let (tx, rx) = mpsc::channel::<(Value, mpsc::Sender<Routed>)>();
        let base = req.clone();
        let router: Router = Arc::new(move |key: &str, args: &[(String, Value)]| {
            let arg = |n: &str| args.iter().find(|(k, _)| k == n).map(|(_, v)| v);
            if key == FETCH_OTHER {
                return Some(other_origin(arg("kind")?.as_str()?, arg("url")?.as_str()?));
            }
            if key != FETCH_OWN {
                return None;
            }
            let method = arg("method")?.as_str()?;
            let path = arg("path")?.as_str()?;
            let headers = pairs(arg("headers"));
            let body = arg("body").and_then(Value::as_str);
            let request = request_for(&base, method, path, &headers, body)?;
            let (back, answer) = mpsc::channel();
            tx.send((request, back)).ok()?;
            answer.recv().ok()
        });
        let (browser, nested) = std::thread::scope(|s| {
            let spec = &spec;
            let worker = s.spawn(move || self.app.run_routed(spec, router));
            let mut nested: Vec<RunRecord> = Vec::new();
            for (request, back) in rx {
                let routed = if nested.len() >= MAX_FETCHES {
                    Routed { value: json!({"err": "appfuzz: too many requests in one page session"}), latency_ms: 0.0, source: "browser: request limit".into() }
                } else {
                    let mut s = page.spec.clone();
                    if let Some(first) = s.args.first_mut() {
                        *first = request;
                    }
                    // Each request is a run of its own, as the fuzzer's are:
                    // repeatable and confirmable alone. (Writes one request
                    // makes don't reach the next.)
                    let r = run(&s);
                    let routed = answer(&r, m);
                    nested.push(r);
                    routed
                };
                let _ = back.send(routed);
            }
            worker.join().map(|b| (b, nested)).map_err(|_| anyhow!("the browser session panicked"))
        })?;
        let report = browser.result.as_ref().and_then(Value::as_str).and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
        Ok(Session { browser, nested, report, fragment })
    }
}

/// The page's session and its findings: the scripts' (attributed to the
/// page's run) and those of the app's runs for the page's requests.
pub fn evaluate(target: &App, page: &RunRecord, run: Runner) -> Result<(Session, Vec<Finding>)> {
    let s = Browser::shared()?.session(target, page, run)?;
    let mut found = check(page, &s, &target.manifest);
    for r in &s.nested {
        found.extend(crate::detect::per_run_checked(target, r));
    }
    Ok((s, found))
}

/// One page `probe scripts` ran.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PageProbe {
    pub page: String,
    pub what: &'static str,
    /// The app's run that served the page.
    pub run: String,
    pub browser_run: String,
    pub outcome: OutcomeKind,
    /// Requests the page's scripts made, to its own origin and to others.
    pub requests: usize,
    pub errors: usize,
}

/// The page requests `probe scripts` tries for a base request: as it is,
/// with markup in every text host functions return (stored text the
/// scripts may put into the page), and with every host list empty (a new
/// user, an empty shop).
pub fn variants(base: &crate::record::RunSpec) -> Vec<(&'static str, crate::record::RunSpec)> {
    let with = |strings: Option<&str>, list_len: Option<usize>| {
        let mut s = base.clone();
        let d = s.plan.0.entry("_defaults".into()).or_default();
        let g = d.response.generate.get_or_insert_with(Default::default);
        if let Some(t) = strings {
            g.strings = Some(t.into());
        }
        if let Some(n) = list_len {
            g.list_len = Some(n);
        }
        s
    };
    vec![("as given", base.clone()), ("host text with markup", with(Some("canary"), Some(4))), ("empty host lists", with(None, Some(0)))]
}

/// `probe scripts`: each base request's page, in the variants above, with
/// its scripts run. Requests whose response has no script are skipped.
pub fn probe(target: &App, bases: &[crate::record::RunSpec], run: Runner) -> Result<(Vec<PageProbe>, Vec<Session>, Vec<Finding>)> {
    let m = &target.manifest;
    let specs: Vec<(&'static str, crate::record::RunSpec)> = bases.iter().flat_map(variants).collect();
    let results = crate::par::map(&specs, |(what, spec)| {
        let page = run(spec);
        if page.capture_limited || matches!(page.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            anyhow::bail!("page request {}: {}", page.id, page.outcome.message.as_deref().unwrap_or("the request could not execute"));
        }
        if !has_scripts(&page, m) {
            return Ok(None);
        }
        evaluate(target, &page, run).map(|(s, found)| Some((*what, page, s, found)))
    });
    let (mut probes, mut sessions, mut findings) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen = BTreeSet::new();
    for r in results {
        let Some((what, page, s, found)) = r? else { continue };
        probes.push(PageProbe {
            page: page.spec.args.first().map(page_url).unwrap_or_default().trim_start_matches(ORIGIN).to_string(),
            what,
            run: page.id.clone(),
            browser_run: s.browser.id.clone(),
            outcome: s.browser.outcome.kind,
            requests: s.browser.events.iter().filter(|e| e.func == FETCH_OWN || e.func == FETCH_OTHER).count(),
            errors: s.report["errors"].as_array().map_or(0, Vec::len),
        });
        findings.extend(found.into_iter().filter(|f| seen.insert(f.id.clone())));
        sessions.push(s);
    }
    Ok((probes, sessions, findings))
}

/// Whether a run served HTML that can run scripts, including inline
/// handlers and script URLs. A response already sent still reaches the
/// visitor when the guest subsequently fails.
pub fn has_scripts(r: &RunRecord, m: &Manifest) -> bool {
    let resp = crate::output::response(r, m);
    resp.html && resp.body.as_deref().is_some_and(|b| !crate::markup::scripts(b).is_empty())
}

/// The answer from another origin. A script, module or style needs the
/// file itself, which appfuzz doesn't have (coverage: `unsupported`); a
/// request for data gets text that says where it came from, so code built
/// from it shows as `remote_code`. The text is a JSON string, which is
/// also a JavaScript expression: parsing or running it doesn't throw.
fn other_origin(kind: &str, url: &str) -> Routed {
    let source = "browser: another origin".to_string();
    if matches!(kind, "script" | "module" | "style" | "serviceWorker") {
        return Routed { value: json!({"err": "appfuzz has no copy of this file"}), latency_ms: 50.0, source };
    }
    let body = Value::String(format!("remote text from {}", host(url))).to_string();
    Routed { value: json!({"ok": {"status": 200, "headers": [["content-type", "application/json"]], "body": body}}), latency_ms: 50.0, source }
}

/// A readable session cookie with a secret in it.
fn secret_cookie(seed: u64) -> String {
    format!("sk_{:016x}", seed.wrapping_add(0xb0b).wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn pairs(v: Option<&Value>) -> Vec<(String, String)> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))).collect())
        .unwrap_or_default()
}

/// The page's URL: the origin, and the request's path and query.
pub fn page_url(req: &Value) -> String {
    if let Some(uri) = req.get("uri").and_then(Value::as_str) {
        let rest = uri.split_once("://").map_or(uri, |(_, r)| &r[r.find(['/', '?', '#']).unwrap_or(r.len())..]);
        let rest = rest.split('#').next().unwrap_or_default();
        return format!("{ORIGIN}{}{rest}", if rest.starts_with('/') { "" } else { "/" });
    }
    let path = req.get("path").or_else(|| req.get("url")).and_then(Value::as_str).unwrap_or("/");
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    let query = pairs(req.get("query"));
    if query.is_empty() {
        return format!("{ORIGIN}{path}");
    }
    let q: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", encode(k), encode(v))).collect();
    format!("{ORIGIN}{path}?{}", q.join("&"))
}

fn encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn decode_pairs(s: &str) -> Vec<Value> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let d = |x: &str| crate::effects::percent_decode(&x.replace('+', " "));
            json!([d(k), d(v)])
        })
        .collect()
}

/// The app's request for a page's request to its own origin, in the shape
/// of the page's request: wasi:http's `{method, uri, headers, body}`, or a
/// platform request with fields such as `method`, `path`, `query`, `form`
/// and `body`. `None` when the request has no place for a path.
pub fn request_for(base: &Value, method: &str, target: &str, headers: &[(String, String)], body: Option<&str>) -> Option<Value> {
    let mut v = base.clone();
    let o = v.as_object_mut()?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if let Some(uri) = o.get("uri").and_then(Value::as_str) {
        let origin = uri.split_once("://").map(|(s, r)| format!("{s}://{}", &r[..r.find(['/', '?', '#']).unwrap_or(r.len())]));
        o.insert("uri".into(), json!(format!("{}{target}", origin.unwrap_or_default())));
        if o.contains_key("headers") {
            o.insert("headers".into(), json!(headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()));
        }
        if o.contains_key("body") {
            o.insert("body".into(), json!(body.unwrap_or_default()));
        }
    } else if o.contains_key("path") || o.contains_key("url") {
        let key = if o.contains_key("path") { "path" } else { "url" };
        let whole = key == "url" && !o.contains_key("query");
        o.insert(key.into(), json!(if whole { target } else { path }));
        if o.get("query").is_some_and(Value::is_array) {
            o.insert("query".into(), Value::Array(decode_pairs(query)));
        }
        let form = body.filter(|_| {
            headers.iter().all(|(k, v)| !k.eq_ignore_ascii_case("content-type") || v.contains("x-www-form-urlencoded") || v.contains("text/plain"))
        });
        if o.get("form").is_some_and(Value::is_array) {
            o.insert("form".into(), Value::Array(form.map(decode_pairs).unwrap_or_default()));
        }
        if o.get("body").is_some_and(Value::is_string) {
            o.insert("body".into(), json!(body.unwrap_or_default()));
        }
        if o.get("headers").is_some_and(Value::is_array) {
            o.insert("headers".into(), json!(headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>()));
        }
    } else {
        return None;
    }
    if o.contains_key("method") {
        o.insert("method".into(), json!(method));
    }
    Some(v)
}

/// The browser's answer from the app's run: the response it sent, or a
/// server error when it failed without sending a response.
fn answer(r: &RunRecord, m: &Manifest) -> Routed {
    let source = format!("app run {}", r.id);
    let latency_ms = r.totals.virtual_ns.ms();
    if r.result.is_none() && r.outcome.kind != OutcomeKind::Ok {
        return Routed { value: json!({"ok": {"status": 500, "headers": [], "body": ""}}), latency_ms, source };
    }
    let resp = crate::output::response(r, m);
    let status = resp.status.filter(|s| (100..600).contains(s)).unwrap_or(200);
    let headers: Vec<Value> = resp.headers.iter().map(|(k, v)| json!([k, v])).collect();
    Routed { value: json!({"ok": {"status": status, "headers": headers, "body": resp.body.unwrap_or_default()}}), latency_ms, source }
}

/// Whether the body is labelled `html:scripts`: its scripts are meant to run.
pub fn runs_scripts(m: &Manifest, export: &str) -> bool {
    m.entry
        .as_ref()
        .filter(|e| crate::harness::fn_key_eq(&e.export, export))
        .is_some_and(|e| e.result.values().any(|l| *l == crate::markup::OutputLabel::HtmlScripts))
}

fn arg<'a>(e: &'a HostCall, name: &str) -> &'a str {
    e.args.get(name).and_then(Value::as_str).unwrap_or_default()
}

fn gesture(e: &HostCall) -> bool {
    e.args.get("gesture").and_then(Value::as_bool).unwrap_or(false)
}

fn host(url: &str) -> String {
    crate::web::host_of(url).unwrap_or_default()
}

fn own(url: &str) -> bool {
    host(url) == host(ORIGIN) || !url.contains("://")
}

/// Where each canary came from, as a developer names it, and as the
/// finding's key has it.
struct Sources {
    from: BTreeMap<String, (String, String)>,
    tails: BTreeMap<String, String>,
    /// Canaries a host result labelled `html` (trusted markup) carries.
    trusted: BTreeSet<String>,
}

impl Sources {
    fn new(page: &RunRecord, s: &Session, m: &Manifest) -> Self {
        let mut from = BTreeMap::new();
        let mut req = BTreeSet::new();
        for (i, a) in page.spec.args.iter().enumerate() {
            crate::output::canary_paths(a, format!("@{i}"), &mut req);
        }
        for (c, p) in req {
            let place = crate::output::request_place(m, &page.spec.args, &p, &c);
            from.insert(c, (place, format!("request {}", crate::output::strip_index(&p))));
        }
        if let Some(c) = CANARY.find(&s.fragment) {
            from.insert(c.as_str().to_string(), ("the page URL's fragment (location.hash)".into(), "fragment".into()));
        }
        let mut texts: BTreeSet<String> = BTreeSet::new();
        let mut trusted = BTreeSet::new();
        for r in std::iter::once(page).chain(&s.nested) {
            for a in &r.spec.args {
                crate::output::strings(a, &mut texts);
            }
            trusted.extend(crate::labels::trusted_html(r, m));
            for e in &r.events {
                let Some(v) = &e.result else { continue };
                let mut ss = BTreeSet::new();
                crate::output::strings(v, &mut ss);
                for t in &ss {
                    for c in CANARY.find_iter(t) {
                        from.entry(c.as_str().to_string()).or_insert_with(|| {
                            let f = format!("a string {} returned", e.func);
                            (f.clone(), f)
                        });
                    }
                }
                texts.extend(ss);
            }
        }
        texts.insert(s.fragment.clone());
        let tails = crate::labels::tails_in(texts.iter().map(String::as_str));
        Sources { from, tails, trusted }
    }

    fn sent(&self, c: &str) -> &str {
        self.tails.get(c).map_or("", String::as_str)
    }
}

struct TracedValue {
    value: String,
    label: Label,
    place: String,
    /// Stable finding identity, independent of how the source is described.
    key: String,
}

/// Traced personal data and secrets: values at `pii` and `secret` result
/// paths of the app's runs, and the session cookie.
fn traced(page: &RunRecord, s: &Session, m: &Manifest) -> Vec<TracedValue> {
    let mut out = vec![TracedValue {
        value: secret_cookie(page.spec.seed),
        label: Label::Secret,
        place: "the browser's readable session cookie".into(),
        key: format!("the session cookie {COOKIE}"),
    }];
    let mut seen: BTreeSet<(String, Label)> = out.iter().map(|t| (t.value.clone(), t.label)).collect();
    for r in std::iter::once(page).chain(&s.nested) {
        for e in &r.events {
            let Some(v) = &e.result else { continue };
            for (p, l) in m.call_result_labels(&e.func, &e.args) {
                if matches!(l, Label::Pii | Label::Secret) {
                    for x in crate::labels::values_at(v, &p) {
                        if x.chars().count() >= 4 && seen.insert((x.clone(), l)) {
                            let at = if p.is_empty() { e.func.clone() } else { format!("{} ({p})", e.func) };
                            out.push(TracedValue { value: x, label: l, key: at.clone(), place: at });
                        }
                    }
                }
            }
        }
    }
    out
}

/// Carries sensitive values through the browser's sequence of server
/// requests. A value becomes known only after its source request; locally
/// labelled leaks keep their existing single-run finding and recipe.
fn server_flows(page: &RunRecord, session: &Session, m: &Manifest) -> Vec<Finding> {
    const COOKIE_SOURCE: &str = "browser:cookie";
    let mut known = vec![crate::labels::Traced {
        value: secret_cookie(page.spec.seed),
        label: Label::Secret,
        func: COOKIE_SOURCE.into(),
        path: String::new(),
        response_owner: Some(ORIGIN.into()),
    }];
    known.extend(crate::labels::sensitive(page, m));
    let origin_key = |v: &crate::labels::Traced| (v.value.clone(), v.label, v.func.clone(), v.path.clone());
    let mut origins: BTreeMap<_, String> = known.iter().map(|v| (origin_key(v), page.id.clone())).collect();
    let mut seen: BTreeSet<_> = known.iter().map(|v| (v.value.clone(), v.label, v.response_owner.clone())).collect();
    let mut out = Vec::new();
    for r in &session.nested {
        let local: BTreeSet<String> = crate::labels::check(r, m).into_iter().map(|f| f.id).collect();
        for mut f in crate::labels::leaks_from(r, m, &known) {
            if local.contains(&f.id) {
                continue;
            }
            let cookie = f.detail["func"].as_str() == Some(COOKIE_SOURCE);
            if let Some(value) = f.detail["value"].as_str()
                && let Some(origin) = origins.get(&(
                    value.to_string(),
                    if f.kind == "secret_leak" { Label::Secret } else { Label::Pii },
                    f.detail["func"].as_str().unwrap_or_default().to_string(),
                    f.detail["path"].as_str().unwrap_or_default().to_string(),
                ))
            {
                f.detail["source_run"] = json!(origin);
            }
            if cookie {
                f.title = format!("the browser's readable session cookie ends up in {}", f.detail["place"].as_str().unwrap_or("the server"));
                f.detail.as_object_mut().unwrap().remove("func");
                f.detail["source"] = json!("the browser's readable session cookie");
            }
            f.title.push_str(" in a request made by the page's scripts");
            f.detail["browser_run"] = json!(session.browser.id);
            f.detail["nested_run"] = json!(r.id);
            out.push(Finding::new(&f.kind, &format!("{}\0browser\0server\0{}", page.spec.export, f.id), f.severity, f.title, f.detail, Some(&page.id)));
        }
        for value in crate::labels::sensitive(r, m) {
            if seen.insert((value.value.clone(), value.label, value.response_owner.clone())) {
                origins.insert(origin_key(&value), r.id.clone());
                known.push(value);
            }
        }
    }
    out
}

/// The findings of one page session. `page` is the app's run that served
/// the page.
pub fn check(page: &RunRecord, s: &Session, m: &Manifest) -> Vec<Finding> {
    let b = &s.browser;
    let run = Some(page.id.as_str());
    let ex = &page.spec.export;
    let full = page.spec.args.first().map(page_url).unwrap_or_default();
    let full = full.strip_prefix(ORIGIN).unwrap_or(&full).to_string();
    // For titles: a fuzzed path can be long.
    let path = clip_to(&full, 80);
    let mut out = Vec::new();
    let detail = |mut d: Value| {
        d["page"] = json!(full);
        d["browser_run"] = json!(b.id);
        d
    };

    match b.outcome.kind {
        OutcomeKind::Ok => {}
        OutcomeKind::OutOfFuel | OutcomeKind::Timeout | OutcomeKind::BudgetExceeded => {
            out.push(Finding::new(
                "hang",
                &format!("{ex}\0browser\0{path}"),
                Severity::Fail,
                format!(
                    "the scripts of the page {path} never stop: the page session ran out of its budget ({:.1}G fuel). A loop that doesn't end, or a miner",
                    b.spec.fuel as f64 / 1e9
                ),
                detail(json!({"outcome": b.outcome.kind, "fuel": b.totals.fuel})),
                run,
            ));
        }
        _ => {}
    }

    // Requests, markup and code recorded before a hang or crash remain
    // evidence, even when the guest couldn't finish its session report.
    let src = Sources::new(page, s, m);
    let traced = traced(page, s, m);
    let grants_listed = m.grants.lists_hosts();
    let mut destinations: BTreeSet<String> = BTreeSet::new();
    let mut per_item: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let other_bodies: Vec<(String, String)> = b
        .events
        .iter()
        .filter(|e| e.func == FETCH_OTHER)
        .filter_map(|e| {
            let body = e.result.as_ref()?.get("ok")?.get("body")?.as_str()?;
            (body.trim().len() >= 8).then(|| (body.trim().to_string(), host(arg(e, "url"))))
        })
        .collect();

    for e in &b.events {
        match e.func.as_str() {
            HTML => {
                let (sink, value) = (arg(e, "sink"), arg(e, "value"));
                for c in CANARY.find_iter(value) {
                    let Some((from, key)) = src.from.get(c.as_str()) else { continue };
                    if src.trusted.contains(c.as_str()) {
                        continue;
                    }
                    if crate::labels::sink_problem(Label::Html, value, c.start(), c.end(), src.sent(c.as_str())).is_none() {
                        continue;
                    }
                    out.push(Finding::new(
                        "html_injection",
                        &format!("{ex}\0browser\0{sink}\0{key}"),
                        Severity::Fail,
                        format!("{from} reaches {sink} in the page's scripts with markup intact (DOM XSS, page {path}): set textContent, or escape it"),
                        detail(json!({"sink": sink, "source": from, "canary": c.as_str(), "value": clip(value), "n": e.n})),
                        run,
                    ));
                }
            }
            CODE => {
                let (sink, value) = (arg(e, "sink"), arg(e, "value"));
                for c in CANARY.find_iter(value) {
                    let Some((from, key)) = src.from.get(c.as_str()) else { continue };
                    let sent = src.sent(c.as_str());
                    let t = crate::labels::tail(value, c.end());
                    let breaks_out = c.start() == 0
                        || (sent.contains('\'') && crate::labels::unescaped(t, "'"))
                        || (sent.contains('"') && crate::labels::unescaped(t, "\""));
                    if !breaks_out {
                        continue;
                    }
                    out.push(Finding::new(
                        "code_injection",
                        &format!("{ex}\0browser\0{sink}\0{key}"),
                        Severity::Fail,
                        format!("{from} becomes code in the page's scripts ({sink}, page {path}): anyone who can set it runs JavaScript as the visitor"),
                        detail(json!({"sink": sink, "source": from, "canary": c.as_str(), "code": clip(value), "n": e.n})),
                        run,
                    ));
                }
                if let Some((_, from)) = other_bodies.iter().find(|(body, _)| value.contains(body.as_str())) {
                    out.push(Finding::new(
                        "remote_code",
                        &format!("{ex}\0browser\0{sink}\0{from}"),
                        Severity::Fail,
                        format!("the page's scripts run code they fetched from {from} ({sink}, page {path}): that host decides what runs, after the review"),
                        detail(json!({"sink": sink, "host": from, "code": clip(value), "n": e.n})),
                        run,
                    ));
                }
            }
            FETCH_OTHER => {
                let url = arg(e, "url");
                let kind = arg(e, "kind");
                let to = host(url);
                if let Some(d) = crate::dest::destination(url, m) {
                    destinations.insert(d.endpoint.clone());
                    let sev = if d.class == crate::dest::Class::Internal || grants_listed { Severity::Fail } else { Severity::Info };
                    let title = if sev == Severity::Info {
                        format!(
                            "the page's scripts send a request ({kind}) to {to}: add `[grants] hosts = [\"{to}\"]` if the platform allows it, so that other hosts are reported"
                        )
                    } else {
                        format!("the page's scripts send a request ({kind}, {}) to {to}, which `[grants] hosts` doesn't list", arg(e, "method"))
                    };
                    out.push(Finding::new(
                        "unexpected_destination",
                        &format!("{ex}\0browser\0{}\0{}", d.class.name(), d.target),
                        sev,
                        title,
                        detail(json!({"url": url, "class": d.class.name(), "target": d.target, "kind": kind, "gesture": gesture(e), "n": e.n})),
                        run,
                    ));
                }
                leaks(e, &traced, &to, &path, ex, run, &detail, &mut out);
            }
            GO => {
                let (how, url) = (arg(e, "how"), arg(e, "url"));
                let to = host(url);
                if let Some(c) = CANARY.find(url)
                    && let Some((from, key)) = src.from.get(c.as_str())
                    && !own(url)
                {
                    out.push(Finding::new(
                        "open_redirect",
                        &format!("{ex}\0browser\0{key}"),
                        Severity::Fail,
                        format!("the page's scripts send the visitor to a URL from {from} ({how}, page {path}): check it is a path on this site"),
                        detail(json!({"how": how, "url": url, "source": from, "n": e.n})),
                        run,
                    ));
                } else if !own(url) && !gesture(e) && !url.starts_with("about:") {
                    // When, after the page loaded: a time bomb waits days.
                    let at = s.report["navigations"].as_array().into_iter().flatten().find(|n| n["url"].as_str() == Some(url)).and_then(|n| n["at"].as_f64());
                    let when = at.filter(|ms| *ms >= 60_000.0).map(|ms| format!(", {} after the page loaded", span(ms))).unwrap_or_default();
                    out.push(Finding::new(
                        "auto_navigation",
                        &format!("{ex}\0browser\0{to}"),
                        Severity::Fail,
                        format!(
                            "the page {path} sends the visitor to {to} by itself ({how}{when}), with no click: a page that leaves for another site on its own"
                        ),
                        detail(json!({"how": how, "url": url, "n": e.n, "at_ms": at})),
                        run,
                    ));
                }
                if !own(url) {
                    leaks(e, &traced, &to, &path, ex, run, &detail, &mut out);
                }
                if own(url) && !gesture(e) {
                    sensitive(m, url, "navigates to", e, ex, &path, run, &detail, &mut out);
                }
            }
            FETCH_OWN => {
                let target = arg(e, "path");
                if !gesture(e) {
                    sensitive(m, target, &format!("calls ({})", arg(e, "method")), e, ex, &path, run, &detail, &mut out);
                }
                let shape: String = target
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .split('/')
                    .map(|seg| if seg.chars().any(|c| c.is_ascii_digit()) { "{n}" } else { seg })
                    .collect::<Vec<_>>()
                    .join("/");
                if shape.contains("{n}") {
                    per_item.entry(format!("{} {shape}", arg(e, "method"))).or_default().insert(target.to_string());
                }
            }
            _ => {}
        }
    }

    for (shape, paths) in per_item {
        if paths.len() >= PER_ITEM_MIN {
            out.push(Finding::new(
                "n_plus_1",
                &format!("{ex}\0browser\0{shape}"),
                Severity::Warn,
                format!("the page's scripts request {shape} once per item ({} requests on page {path}): fetch the items in one request", paths.len()),
                detail(json!({"shape": shape, "requests": paths.len(), "examples": paths.iter().take(4).collect::<Vec<_>>()})),
                run,
            ));
        }
    }
    if destinations.len() >= crate::dest::PROBE_MIN {
        let list: Vec<&String> = destinations.iter().take(12).collect();
        out.push(Finding::new(
            "probing",
            &format!("{ex}\0browser"),
            Severity::Fail,
            format!(
                "the page's scripts contact {} hosts in one visit ({})",
                destinations.len(),
                list.iter().take(4).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ),
            detail(json!({"destinations": destinations.len(), "examples": list})),
            run,
        ));
    }

    // Script errors: one finding per message. On load, with the request
    // and host data as given, every visitor gets it.
    let generate = page.spec.plan.0.get("_defaults").and_then(|d| d.response.generate.as_ref());
    let fuzzed = !src.from.keys().all(|c| s.fragment.contains(c.as_str())) || generate.is_some_and(|g| g.strings.is_some() || g.list_len == Some(0));
    // Request text that reached the page's markup with a quote or `<`
    // intact breaks the inline script or handler it lands in: that is the
    // page's reflection finding, not an error of its own.
    let body = crate::output::response(page, m).body.unwrap_or_default();
    let reflected = crate::labels::tails_in(std::iter::once(body.as_str()))
        .iter()
        .any(|(c, t)| !s.fragment.contains(c.as_str()) && src.from.contains_key(c) && ["<", "'", "\""].iter().any(|q| crate::labels::unescaped(t, q)));
    let inline = |place: &str| place.starts_with("handler:") || place.strip_prefix("script:").is_some_and(|u| u.contains(&format!("#{}", s.fragment)));
    // The same for code the input became (a handler decodes `&#39;`).
    let injected: BTreeSet<String> = out.iter().filter(|f| f.kind == "code_injection").filter_map(|f| f.detail["sink"].as_str().map(str::to_string)).collect();
    let mut messages = BTreeSet::new();
    for err in s.report["errors"].as_array().into_iter().flatten() {
        let place = err["where"].as_str().unwrap_or_default();
        let message = format!("{}: {}", err["name"].as_str().unwrap_or("Error"), err["message"].as_str().unwrap_or_default());
        if not_loaded(place) || (reflected && inline(place)) || injected.contains(place) || !messages.insert(message.clone()) {
            continue;
        }
        let on_load = err["at"].as_f64().is_some_and(|at| at <= 1000.0);
        let sev = if on_load && !fuzzed { Severity::Fail } else { Severity::Warn };
        let when = if on_load { "while the page loads" } else { "after a click or a timer" };
        // One finding per message, whatever page and input showed it.
        let key = CANARY.replace_all(&message, "cnry");
        out.push(Finding::new(
            "script_error",
            &format!("{ex}\0browser\0{key}"),
            sev,
            format!("the page's scripts throw {when} (page {path}, {place}): {}", clip_to(&message, 160)),
            detail(json!({"where": place, "message": message, "stack": err["stack"], "at_ms": err["at"]})),
            run,
        ));
    }

    let idle = &s.report["idle"];
    if let (Some(cpu), Some(ms)) = (idle["cpu_ms"].as_f64(), idle["ms"].as_f64())
        && cpu > 0.0
        && cpu / ms.max(cpu) > IDLE_CPU_MAX
    {
        out.push(Finding::new(
            "over_budget",
            &format!("{ex}\0browser\0idle_cpu\0{path}"),
            Severity::Fail,
            format!(
                "the scripts of the page {path} keep the CPU {:.0}% busy while nobody uses the page: a visitor's device works for the page all the time, as with a miner",
                100.0 * cpu / ms.max(cpu)
            ),
            detail(json!({"idle_cpu_ms": cpu, "idle_ms": ms, "limit": IDLE_CPU_MAX})),
            run,
        ));
    }

    out.extend(server_flows(page, s, m));
    let mut seen = BTreeSet::new();
    out.retain(|f| seen.insert(f.id.clone()));
    out
}

/// An error that only says a script from another origin wasn't loaded:
/// no file was given for it (coverage, not a bug in the page).
fn not_loaded(place: &str) -> bool {
    place.split_once(':').is_some_and(|(k, url)| matches!(k, "script" | "module") && url.contains("://") && !own(url))
}

/// Unloaded scripts from other origins, Web APIs the guest doesn't model,
/// and pages cut short for the CPU they used: what the sessions couldn't
/// judge.
pub fn unsupported(sessions: &[Session]) -> Value {
    let mut apis = BTreeSet::new();
    let mut unloaded = BTreeSet::new();
    // Pages that used up the CPU the session allows before all actions
    // were tried, or the CPU the late wait allows before 30 days passed.
    let mut actions = BTreeSet::new();
    let mut later = BTreeSet::new();
    for s in sessions {
        let path = || s.report["url"].as_str().map(|u| u.split('#').next().unwrap_or(u).trim_start_matches(ORIGIN).to_string());
        if s.report["busy"]["cut"].as_bool() == Some(true) {
            actions.extend(path());
        }
        if s.report["later"]["cut"].as_bool() == Some(true) {
            later.extend(path());
        }
        apis.extend(s.report["unmodelled"].as_array().into_iter().flatten().filter_map(Value::as_str));
        unloaded.extend(
            s.report["errors"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e["where"].as_str())
                .filter(|w| not_loaded(w))
                .filter_map(|w| w.split_once(':').map(|(_, u)| u)),
        );
    }
    json!({"apis": apis, "scripts_not_loaded": unloaded, "actions_not_all_tried": actions, "not_followed_30_days": later})
}

#[allow(clippy::too_many_arguments)]
fn leaks(e: &HostCall, traced: &[TracedValue], to: &str, path: &str, ex: &str, run: Option<&str>, detail: &dyn Fn(Value) -> Value, out: &mut Vec<Finding>) {
    let mut texts = BTreeSet::new();
    for v in e.args.values() {
        crate::output::strings(v, &mut texts);
    }
    for TracedValue { value, label, place: at, key } in traced {
        if !texts.iter().any(|t| t.contains(value.as_str())) {
            continue;
        }
        let (kind, what) = if *label == Label::Secret { ("secret_leak", "a secret") } else { ("pii_leak", "personal data") };
        out.push(Finding::new(
            kind,
            &format!("{ex}\0browser\0{key}\0{to}"),
            Severity::Fail,
            format!("the page's scripts send {what} ({at}) to {to} (page {path})"),
            detail(json!({"value": value, "from": at, "host": to, "call": e.func, "n": e.n})),
            run,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn sensitive(
    m: &Manifest,
    target: &str,
    how: &str,
    e: &HostCall,
    ex: &str,
    path: &str,
    run: Option<&str>,
    detail: &dyn Fn(Value) -> Value,
    out: &mut Vec<Finding>,
) {
    let Some(entry) = m.entry.as_ref() else { return };
    let p = target.strip_prefix(ORIGIN).unwrap_or(target);
    let p = p.split(['?', '#']).next().unwrap_or_default();
    let Some(s) = entry.sensitive_paths.iter().find(|s| p == s.as_str() || p.starts_with(&format!("{}/", s.trim_end_matches('/')))) else { return };
    out.push(Finding::new(
        "unsafe_action",
        &format!("{ex}\0browser\0{s}\0{how}"),
        Severity::Fail,
        format!("the page's scripts {how} {p} by themselves, with no click (page {path}); {s} is a sensitive route"),
        detail(json!({"target": target, "sensitive": s, "n": e.n})),
        run,
    ));
}

/// A span of virtual time in the largest whole unit: "7 days", "2 hours".
fn span(ms: f64) -> String {
    let (n, unit) = [(86_400_000.0, "day"), (3_600_000.0, "hour"), (60_000.0, "minute")]
        .into_iter()
        .find(|(u, _)| ms >= *u)
        .map_or((ms / 1000.0, "second"), |(u, name)| (ms / u, name));
    let n = n.floor() as u64;
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn clip(s: &str) -> String {
    clip_to(s, 300)
}

fn clip_to(s: &str, n: usize) -> String {
    if s.chars().count() > n { format!("{}…", s.chars().take(n).collect::<String>()) } else { s.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_take_the_page_requests_shape() {
        let http = json!({"method": "GET", "uri": "https://app.example/?q=1", "headers": [["accept", "text/html"]], "body": ""});
        let r = request_for(&http, "POST", "/api/items?x=1", &[("content-type".into(), "application/json".into())], Some("{}")).unwrap();
        assert_eq!(r, json!({"method": "POST", "uri": "https://app.example/api/items?x=1", "headers": [["content-type", "application/json"]], "body": "{}"}));

        let bench = json!({"method": "GET", "path": "/", "query": [], "form": [], "today": "2026-11-02", "now": "10:00"});
        let r = request_for(&bench, "POST", "/save?id=4&tag=a+b", &[], Some("name=x%20y")).unwrap();
        assert_eq!(
            r,
            json!({"method": "POST", "path": "/save", "query": [["id", "4"], ["tag", "a b"]], "form": [["name", "x y"]], "today": "2026-11-02", "now": "10:00"})
        );
        // A JSON body isn't a form.
        let r = request_for(&bench, "POST", "/save", &[("Content-Type".into(), "application/json".into())], Some("{\"a\":1}")).unwrap();
        assert_eq!(r["form"], json!([]));

        assert!(request_for(&json!({"name": "x"}), "GET", "/", &[], None).is_none());
    }

    #[test]
    fn spans() {
        assert_eq!(span(7.0 * 86_400_000.0), "7 days");
        assert_eq!(span(86_400_000.0 + 1.0), "1 day");
        assert_eq!(span(2.5 * 3_600_000.0), "2 hours");
        assert_eq!(span(90_000.0), "1 minute");
        assert_eq!(span(5_000.0), "5 seconds");
    }

    #[test]
    fn page_urls() {
        assert_eq!(page_url(&json!({"uri": "https://shop.example/a?b=1#c"})), "https://app.example/a?b=1");
        assert_eq!(page_url(&json!({"uri": "/x"})), "https://app.example/x");
        assert_eq!(page_url(&json!({"path": "/s", "query": [["q", "a b<"]]})), "https://app.example/s?q=a%20b%3C");
        assert_eq!(page_url(&json!({"path": "/"})), "https://app.example/");
    }

    #[test]
    fn unloaded_scripts_are_coverage() {
        assert!(not_loaded("script:https://cdn.example.net/lit.js"));
        assert!(not_loaded("module:https://cdn.example.net/lit.js"));
        assert!(!not_loaded("script:https://app.example/app.js"));
        assert!(!not_loaded("onload"));
    }
}
