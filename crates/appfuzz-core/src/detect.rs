//! Findings, and the detectors that look at a single run or at the binary.
//!
//! Detectors only see what crosses the boundary (arguments, results, host
//! calls, fuel, memory, time). They say what happened, not what it means;
//! the agent decides that.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::manifest::{Manifest, strip_version};
use crate::record::{OutcomeKind, RunRecord};
use crate::statics::Statics;
use crate::wit::{ImportKind, Interface};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable id: the same problem found again gets the same id.
    pub id: String,
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    #[serde(default)]
    pub detail: Value,
    /// A run that shows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// Case file written by `confirm` (replayed, and minimised when it
    /// shows in a single run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<String>,
}

impl Finding {
    /// The nature of the evidence is independent of its policy severity.
    pub fn evidence(&self) -> &'static str {
        match self.kind.as_str() {
            "crash"
            | "stack_overflow"
            | "hang"
            | "over_budget"
            | "check_failed"
            | "crash_on_host_value"
            | "hang_on_host_value"
            | "crash_at_time"
            | "hang_at_time"
            | "big_output"
            | "big_payload"
            | "redundant_calls"
            | "busy_wait"
            | "sleeps" => "measured",
            "invalid_host_argument"
            | "acceptance_failed"
            | "sequence_check_failed"
            | "ungranted_import"
            | "ungranted_call"
            | "write_on_safe_method"
            | "script_in_output"
            | "non_local_url"
            | "open_redirect"
            | "outside_envelope" => "policy_violation",
            _ => "heuristic",
        }
    }

    pub fn experimental(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "agent_directed_text"
                | "hidden_text"
                | "encoded_flow"
                | "constant_payload"
                | "unexpected_destination"
                | "probing"
                | "dormant_code"
                | "outside_envelope"
        )
    }

    pub fn new(kind: &str, key: &str, severity: Severity, title: String, detail: Value, run: Option<&str>) -> Self {
        let h = blake3::hash(format!("{kind}\0{key}").as_bytes()).to_hex();
        Finding { id: format!("f{}", &h[..8]), kind: kind.to_string(), severity, title, detail, run: run.map(str::to_string), confirmed: None }
    }
}

/// Thresholds for per-run detectors.
pub const REDUNDANT_MIN: u32 = 2;
pub const RETRY_MIN: u32 = 3;
pub const PAYLOAD_MAX: usize = 64 * 1024;
pub const OUTPUT_MAX: usize = 1 << 20;
pub const CLOCK_READS_MAX: u64 = 50;
/// Host calls before a run counts as a serial chain.
pub const SERIAL_MIN: u32 = 10;

/// Everything one run shows on its own.
pub fn per_run(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = per_run_fast(r, m);
    out.extend(per_run_text(r, m));
    out
}

/// `per_run`, then one more run when the output shows a host error text
/// (a text the page shows anyway is not a leak), or for a `partial_write`
/// (an app that passes a changed error text on tells the user).
pub fn per_run_checked(app: &crate::harness::App, r: &RunRecord) -> Vec<Finding> {
    let mut out = per_run(r, &app.manifest);
    crate::output::drop_echoes(app, r, &mut out);
    crate::effects::drop_told(app, r, &mut out);
    out
}

/// The checks that read every byte of the output, the logs and the host
/// arguments for destinations, encoded payloads and text aimed at agents.
/// Content can change without a new host call site: check every valid run.
pub fn per_run_text(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = crate::dest::check(r, m);
    out.extend(crate::payload::check(r, m));
    out.extend(crate::agents::check(r, m));
    out
}

/// Every check of `per_run` but the text checks.
pub fn per_run_fast(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    let run = Some(r.id.as_str());
    let ex = &r.spec.export;
    let o = &r.outcome;
    let panic = panic_text(&r.stderr);
    match o.kind {
        OutcomeKind::Ok | OutcomeKind::HostTrap | OutcomeKind::PlanError | OutcomeKind::Error => {}
        OutcomeKind::OutOfFuel | OutcomeKind::Timeout => out.push(Finding::new(
            "hang",
            ex,
            Severity::Fail,
            format!("{ex} does not return ({})", kind_name(o.kind)),
            json!({"outcome": o.kind, "fuel": r.totals.fuel, "virtual_ms": ms(r.totals.virtual_ns)}),
            run,
        )),
        OutcomeKind::StackOverflow => out.push(Finding::new(
            "stack_overflow",
            &format!("{ex}\0{}", crash_site(panic.as_deref(), o, "")),
            Severity::Fail,
            format!("{ex} overflows its stack{}", backtrace_func(o.message.as_deref().unwrap_or("")).map(|n| format!(" (in {n})")).unwrap_or_default()),
            json!({"outcome": o.kind, "depth": o.stack.len(), "after_host_calls": r.totals.host_calls,
                   "frames": o.stack.iter().take(8).map(|f| f.name.clone().unwrap_or_else(|| format!("{}:{}", f.module, f.func))).collect::<Vec<_>>()}),
            run,
        )),
        kind => {
            let msg = panic.clone().or(o.message.clone()).unwrap_or_default();
            out.push(Finding::new(
                "crash",
                &format!("{ex}\0{kind:?}\0{}", crash_site(panic.as_deref(), o, &msg)),
                Severity::Fail,
                format!("{ex} crashes: {}", first_line(&msg)),
                json!({"outcome": kind, "message": msg, "after_host_calls": r.totals.host_calls,
                       "last_host_call": r.events.last().map(|e| json!({"n": e.n, "func": e.func, "result": e.result}))}),
                run,
            ));
        }
    }
    let l = &m.limits;
    let t = &r.totals;
    let mut over = |what: &str, used: f64, limit: f64| {
        if used > limit {
            out.push(Finding::new(
                "over_budget",
                &format!("{ex}\0{what}"),
                Severity::Fail,
                format!("{ex} uses {} {what}, the limit is {}", fmt(used), fmt(limit)),
                json!({"limit": what, "used": used, "limit_value": limit, "host_calls": t.host_calls}),
                run,
            ));
        }
    };
    over("fuel", t.fuel as f64, l.fuel as f64);
    over("memory", t.peak_memory as f64, l.memory as f64);
    if let Some(c) = l.cost_per_request {
        over("cost", t.cost as f64, c as f64);
    }
    if let Some(ml) = l.max_latency_ms {
        over("latency_ms", ms(t.virtual_ns), ml);
    }

    // Redundant calls: same function, same arguments.
    // Arguments as JSON, once per call: the key here, the size below.
    let arg_text: Vec<String> = r.events.iter().map(|e| serde_json::to_string(&e.args).unwrap_or_default()).collect();
    let mut same: BTreeMap<(&str, &str), u32> = BTreeMap::new();
    for (e, a) in r.events.iter().zip(&arg_text) {
        for v in e.value_checks.iter().flat_map(|c| &c.violations) {
            out.push(Finding::new("invalid_host_argument", &format!("{}\0{}\0{}\0{}",e.func,v.declaration,v.constraint,v.reason), Severity::Fail,
                format!("{} parameter {} violates {}",e.func,v.path,v.constraint),
                json!({"func":e.func,"parameter":v.declaration,"path":v.path,"constraint":v.constraint,"reason":v.reason,"value":v.value,"bytes":v.bytes,"n":e.n,"call":e.call,"source":m.function(&e.func).and_then(|f|f.value_source.as_deref())}),run));
        }
        *same.entry((e.func.as_str(), a.as_str())).or_default() += 1;
    }
    let mut redundant: BTreeMap<&str, (u32, u32, &str)> = BTreeMap::new();
    for (&(f, args), &n) in &same {
        if n > 1 {
            let x = redundant.entry(f).or_insert((0, 0, args));
            x.0 += n - 1;
            if n > x.1 {
                x.1 = n;
                x.2 = args;
            }
        }
    }
    for (f, (extra, worst, args)) in redundant {
        // A repeated change is `repeated_write` (effects).
        if extra >= REDUNDANT_MIN && !m.unrepeatable(f) {
            let total = r.events.iter().filter(|e| e.func == f).count();
            out.push(Finding::new(
                "redundant_calls",
                &format!("{ex}\0{f}"),
                Severity::Warn,
                format!("{f}: {extra} of {total} calls repeat earlier calls with the same arguments"),
                json!({"func": f, "calls": total, "repeated": extra, "worst_args": serde_json::from_str::<Value>(args).unwrap_or(Value::Null), "worst_count": worst}),
                run,
            ));
        }
    }

    out.extend(chatty(r, m));

    // Retry storms: the same failing call made again and again.
    let mut i = 0;
    while i < r.events.len() {
        let e = &r.events[i];
        if is_err(e.result.as_ref()) {
            let mut j = i + 1;
            while j < r.events.len() && r.events[j].func == e.func && r.events[j].args == e.args {
                j += 1;
            }
            let retries = (j - i - 1) as u32;
            if retries >= RETRY_MIN && !duplicates_explain(&r.events[..i], &e.args, retries + 1) && !crate::effects::duplicate_host_data(&r.events, e.n) {
                // A failed change may have happened anyway: each retry
                // can make it again.
                let write = m.unrepeatable(&e.func);
                out.push(Finding::new(
                    "retry_storm",
                    &format!("{ex}\0{}", e.func),
                    if write { Severity::Fail } else { Severity::Warn },
                    format!(
                        "{} is called {retries} more times in a row after it failed{}",
                        e.func,
                        if write { "; it changes something and is not idempotent, so each retry may do it again" } else { "" }
                    ),
                    json!({"func": e.func, "first_call": e.n, "retries": retries, "args": e.args, "unrepeatable": write}),
                    run,
                ));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    for (e, a) in r.events.iter().zip(&arg_text) {
        let size = a.len();
        if size > PAYLOAD_MAX {
            out.push(Finding::new(
                "big_payload",
                &format!("{ex}\0{}", e.func),
                Severity::Warn,
                format!("{} gets {size} bytes of arguments in one call", e.func),
                json!({"func": e.func, "n": e.n, "bytes": size}),
                run,
            ));
            break;
        }
        if !e.granted {
            out.push(Finding::new(
                "ungranted_call",
                &e.func,
                Severity::Fail,
                format!("calls {} without a grant", e.func),
                json!({"func": e.func, "n": e.n}),
                run,
            ));
        }
    }
    let out_bytes = r.result.as_ref().map(crate::value::json_len).unwrap_or(0);
    if out_bytes > OUTPUT_MAX {
        out.push(Finding::new("big_output", ex, Severity::Warn, format!("{ex} returns {out_bytes} bytes"), json!({"bytes": out_bytes}), run));
    }
    if t.clock_reads >= CLOCK_READS_MAX {
        out.push(Finding::new(
            "busy_wait",
            ex,
            Severity::Warn,
            format!("{ex} reads the clock {} times", t.clock_reads),
            json!({"clock_reads": t.clock_reads}),
            run,
        ));
    }
    // Serial chains: many calls one after another whose latencies add up.
    if let Some(ml) = l.max_latency_ms
        && t.host_calls >= SERIAL_MIN
        && ms(t.host_ns) >= ml * 0.5
    {
        let mut per: BTreeMap<&str, (u32, u64)> = BTreeMap::new();
        for e in &r.events {
            let x = per.entry(&e.func).or_default();
            x.0 += 1;
            x.1 += e.latency_ns;
        }
        let (f, (n, ns)) = per.iter().max_by_key(|(_, (_, ns))| *ns).map(|(f, x)| (*f, *x)).unwrap_or_default();
        out.push(Finding::new(
            "serial_chain",
            &format!("{ex}\0{f}"),
            Severity::Warn,
            format!(
                "{ex} waits {} ms for {} host calls in a row ({n} × {f}: {} ms), the latency limit is {} ms",
                fmt(ms(t.host_ns)),
                t.host_calls,
                fmt(ms(ns)),
                fmt(ml)
            ),
            json!({"host_ms": ms(t.host_ns), "host_calls": t.host_calls, "slowest_func": f, "slowest_calls": n, "slowest_ms": ms(ns), "limit_ms": ml}),
            run,
        ));
    }
    // Carries on after a failed call as if nothing happened.
    if o.kind == OutcomeKind::Ok
        && let Some(i) = r.events.iter().position(|e| is_err(e.result.as_ref()))
    {
        let failed = &r.events[i].func;
        let after: BTreeSet<&str> = r.events[i + 1..].iter().map(|e| e.func.as_str()).filter(|f| f != failed).collect();
        if !after.is_empty() {
            out.push(Finding::new(
                "continues_after_error",
                &format!("{ex}\0{failed}"),
                Severity::Info,
                format!("{ex} goes on calling {} after {failed} failed", after.iter().copied().collect::<Vec<_>>().join(", ")),
                json!({"failed": failed, "n": r.events[i].n, "later": after}),
                run,
            ));
        }
    }
    out.extend(crate::output::check(r, m));
    out.extend(crate::labels::check(r, m));
    out.extend(crate::effects::check(r, m));
    out.extend(crate::identity::check(r, m));
    out.extend(crate::markup::check(r, m));
    if t.sleep_ns > 0 {
        out.push(Finding::new(
            "sleeps",
            ex,
            Severity::Warn,
            format!("{ex} sleeps {} ms in a request", fmt(ms(t.sleep_ns))),
            json!({"sleep_ms": ms(t.sleep_ns)}),
            run,
        ));
    }
    // A request the platform would reject never reaches the app.
    let broken = crate::constraints::broken_request(&r.spec.args, m);
    if !broken.is_empty() {
        let why: Vec<Value> = broken.iter().map(|(p, c, v)| json!({"field": p, "constraint": c, "value": v})).collect();
        for f in &mut out {
            f.severity = Severity::Info;
            if let Value::Object(d) = &mut f.detail {
                d.insert("invalid_request".into(), json!(why));
            }
        }
    }
    dedupe(out)
}

/// A function called once per element of a list another call returned.
fn chatty(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    // Argument scalars per event, computed once.
    let arg_scalars: Vec<BTreeSet<String>> = r.events.iter().map(|e| e.args.values().flat_map(scalars).collect()).collect();
    let mut reported: BTreeSet<&str> = BTreeSet::new();
    for (i, e) in r.events.iter().enumerate() {
        if reported.contains(e.func.as_str()) {
            continue;
        }
        let Some(list) = e.result.as_ref().and_then(list_in) else { continue };
        if list.len() < 2 {
            continue;
        }
        // Scalar values of each element.
        let elems: Vec<BTreeSet<String>> = list.iter().map(scalars).collect();
        let mut per_func: BTreeMap<&str, (BTreeSet<usize>, u32)> = BTreeMap::new();
        // Per-element calls follow the list; a window keeps this linear.
        let end = r.events.len().min(i + 1 + 8 * list.len() + 16);
        for (later, args) in r.events[i + 1..end].iter().zip(&arg_scalars[i + 1..end]) {
            if later.func == e.func {
                continue;
            }
            let hit: Vec<usize> = elems.iter().enumerate().filter(|(_, s)| !s.is_disjoint(args)).map(|(k, _)| k).collect();
            // Only a call that names one element (an id), not one that
            // matches several (a shared value like a date).
            if hit.len() == 1 {
                let x = per_func.entry(later.func.as_str()).or_default();
                x.0.insert(hit[0]);
                x.1 += 1;
            }
        }
        for (f, (elements, calls)) in per_func {
            if elements.len() >= 2 && elements.len() * 5 >= list.len() * 4 {
                reported.insert(e.func.as_str());
                let batch = m.batch_for(f);
                let hint = batch.as_ref().map(|b| format!("; {b} does it in one call")).unwrap_or_default();
                out.push(Finding::new(
                    "chatty",
                    &format!("{}\0{}\0{f}", r.spec.export, e.func),
                    Severity::Warn,
                    format!("{f} is called for each element {} returned ({calls} calls for {} elements){hint}", e.func, list.len()),
                    json!({"list_from": e.func, "list_call": e.n, "elements": list.len(), "func": f, "calls": calls, "batch": batch}),
                    Some(&r.id),
                ));
            }
        }
    }
    out
}

/// The list in a host result: `[…]`, `{"ok": […]}` or `{"some": […]}`.
pub fn list_in(v: &Value) -> Option<&Vec<Value>> {
    match v {
        Value::Array(a) => Some(a),
        Value::Object(o) if o.len() == 1 => o.get("ok").or(o.get("some")).and_then(list_in),
        _ => None,
    }
}

fn scalars(v: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    fn walk(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Number(n) => {
                out.insert(n.to_string());
            }
            Value::String(s) if s.len() >= 2 => {
                out.insert(s.clone());
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    walk(v, &mut out);
    out
}

fn is_err(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Object(o)) if o.len() == 1 && o.contains_key("err"))
}

/// Findings from the binary and the manifest alone.
pub fn static_findings(m: &Manifest, imports: &[Interface], st: &Statics) -> Vec<Finding> {
    let mut out = Vec::new();
    for i in imports.iter().filter(|i| !i.funcs.is_empty()) {
        let granted = match i.kind {
            ImportKind::Platform => i.name.is_empty() || m.grants_interface(&i.name),
            ImportKind::Wasi => m.grants_wasi(&i.name),
        };
        if !granted {
            out.push(Finding::new(
                "ungranted_import",
                &i.name,
                Severity::Fail,
                format!("imports {} but the manifest does not grant it", i.name),
                json!({"interface": i.name, "funcs": i.funcs.iter().map(|f| &f.name).collect::<Vec<_>>()}),
                None,
            ));
        }
    }
    let imported: Vec<&str> = imports.iter().map(|i| strip_version(&i.name)).collect();
    for g in m.grants.imports.iter().flatten() {
        if !imported.contains(&strip_version(g)) {
            out.push(Finding::new(
                "unused_grant",
                g,
                Severity::Info,
                format!("the manifest grants {g} but the code never imports it"),
                json!({"interface": g}),
                None,
            ));
        }
    }
    let strings: Vec<(u64, String)> = st.modules.iter().flat_map(|m| m.strings.iter().cloned()).collect();
    out.extend(crate::agents::check_static(m, &strings));
    for m in st.modules.iter().filter(|m| m.role == "main" || m.role == "other") {
        let reach = m.host_reach();
        let mut seen = BTreeSet::new();
        for f in &m.funcs {
            for l in &f.loops {
                let hosts: BTreeSet<&String> = l.calls.iter().filter_map(|(c, _)| reach.get(c)).flatten().collect();
                for h in hosts {
                    if seen.insert((f.index, h.clone())) {
                        out.push(Finding::new(
                            "host_call_in_loop",
                            &format!("{}\0{}\0{h}", m.id, f.index),
                            Severity::Info,
                            format!("{} calls {h} inside a loop (static; check with `scale`)", m.label(f.index)),
                            json!({"module": m.id, "func": f.index, "name": m.label(f.index), "loop_at": format!("{:x}", l.start), "host": h}),
                            None,
                        ));
                    }
                }
            }
        }
    }
    out
}

fn dedupe(v: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    v.into_iter().filter(|f| seen.insert(f.id.clone())).collect()
}

/// The panic message a Rust guest printed to stderr, if any.
/// Where a crash happened, so one bug is one finding whatever values it
/// shows: the panic location, else the innermost guest frame, else the
/// message with numbers masked.
fn crash_site(panic: Option<&str>, o: &crate::record::Outcome, msg: &str) -> String {
    static AT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"panicked at ([^\s]+:\d+:\d+)").unwrap());
    static NUM: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"[0-9]+").unwrap());
    if let Some(c) = panic.and_then(|p| AT.captures(p)) {
        return c[1].to_string();
    }
    if let Some(f) = o.stack.first() {
        return format!("{}:{}:{:x}", f.module, f.func, f.offset.unwrap_or(0));
    }
    NUM.replace_all(&first_line(msg), "N").into_owned()
}

/// The innermost function of a wasmtime backtrace message
/// (`0: 0xeba - app.wasm!app[ce18…]::tree` → `app::tree`).
fn backtrace_func(msg: &str) -> Option<String> {
    static HASH: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"\[[0-9a-f]{16}\]").unwrap());
    let line = msg.lines().find(|l| l.trim_start().starts_with("0:"))?;
    let name = line.split_once('!')?.1.trim();
    Some(crate::statics::demangle(&HASH.replace_all(name, "")))
}

pub fn panic_text(stderr: &str) -> Option<String> {
    let i = stderr.find("panicked at")?;
    Some(stderr[i..].lines().take(3).collect::<Vec<_>>().join(" ").chars().take(400).collect())
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(160).collect()
}

/// `out_of_fuel`, `stack_overflow`, …
/// Whether every argument of a repeated call occurs at least `times` times
/// in earlier host results: a loop over duplicate elements, not a retry.
fn duplicates_explain(earlier: &[crate::record::HostCall], args: &serde_json::Map<String, Value>, times: u32) -> bool {
    fn leaves<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
        match v {
            Value::Array(a) => a.iter().for_each(|x| leaves(x, out)),
            Value::Object(o) => o.values().for_each(|x| leaves(x, out)),
            x => out.push(x),
        }
    }
    let mut want = Vec::new();
    args.values().for_each(|a| leaves(a, &mut want));
    let mut have = Vec::new();
    for e in earlier {
        if let Some(r) = &e.result {
            leaves(r, &mut have);
        }
    }
    !want.is_empty() && want.iter().all(|w| have.iter().filter(|h| *h == w).count() as u32 >= times)
}

pub fn kind_name(k: OutcomeKind) -> String {
    serde_json::to_value(k).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

pub fn ms(ns: u64) -> f64 {
    (ns as f64 / 1e4).round() / 100.0
}

fn fmt(x: f64) -> String {
    if x.fract() == 0.0 { format!("{}", x as i64) } else { format!("{x:.2}") }
}

/// Stored findings, merged by id.
pub struct FindingStore {
    path: std::path::PathBuf,
}

impl FindingStore {
    /// Findings of one component (by hash).
    pub fn new(state: &std::path::Path, component: &str) -> Self {
        FindingStore { path: state.join("findings").join(format!("{component}.json")) }
    }

    pub fn all(&self) -> anyhow::Result<Vec<Finding>> {
        use anyhow::Context;
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        serde_json::from_slice(&bytes).with_context(|| format!("invalid findings in {}", self.path.display()))
    }

    /// Replaces a stored finding (same id).
    pub fn update(&self, f: &Finding) -> anyhow::Result<()> {
        let mut all = self.all()?;
        match all.iter_mut().find(|x| x.id == f.id) {
            Some(x) => *x = f.clone(),
            None => all.push(f.clone()),
        }
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        crate::store::write_atomic(&self.path, &serde_json::to_vec_pretty(&all)?)?;
        Ok(())
    }

    /// Adds findings; returns the ids that were new.
    pub fn add(&self, new: &[Finding]) -> anyhow::Result<Vec<String>> {
        let mut all = self.all()?;
        let mut added = Vec::new();
        for f in new {
            if !all.iter().any(|x| x.id == f.id) {
                all.push(f.clone());
                added.push(f.id.clone());
            }
        }
        for f in new {
            if let Some(old) = all.iter_mut().find(|x| x.id == f.id)
                && (f.severity > old.severity || (f.severity == old.severity && old.run != f.run && old.confirmed.is_none()))
            {
                *old = f.clone();
            }
        }
        if !new.is_empty() {
            if let Some(d) = self.path.parent() {
                std::fs::create_dir_all(d)?;
            }
            crate::store::write_atomic(&self.path, &serde_json::to_vec_pretty(&all)?)?;
        }
        Ok(added)
    }
}
