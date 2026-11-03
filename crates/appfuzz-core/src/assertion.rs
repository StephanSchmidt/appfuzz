//! `let` + `assert`: properties over one run's request, host calls and output,
//! written in CEL. `let` names the values (bindings); expressions see only them.
//!
//! appfuzz adds three things to plain CEL: strict errors (CEL lets `||` and
//! `&&` swallow an error in one operand; here any error is an error), a static
//! check of every name before a run, and evidence when a property breaks: the
//! failing conjunct, both sides of a comparison, the first element `all()`
//! rejects, and every binding's value.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock};

use anyhow::{Context as _, Result, anyhow, bail};
use cel::common::ast::{Expr, IdedExpr};
use cel::extractors::This;
use cel::objects::{Key, Map};
use cel::{Context, Env, ExecutionError, Program, Value as Cel, extensions};
use regex::Regex;
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::check::Selector;
use crate::harness::field;
use crate::manifest::Manifest;
use crate::output::response;
use crate::record::{HostCall, OutcomeKind, RunRecord};
use crate::wit::{FuncInfo, ImportKind, Interface};

/// Longest expression accepted.
pub const MAX_EXPRESSION: usize = 2048;
/// Deepest nesting of macros (`all`, `exists`, `map`, `filter`, ...).
pub const MAX_NESTING: usize = 2;

/// Functions appfuzz adds to CEL.
pub const FUNCTIONS: &[(&str, &str)] = &[
    ("sum(list)", "sum of numbers; ints stay ints"),
    ("num(text)", "the one number in a text (`1,234.50 €` → 1234.5); ints stay ints"),
    ("approx(a, b, eps)", "|a − b| ≤ eps"),
    ("is_ok(r) / is_err(r)", "a WIT result is {ok: …} / {err: …}"),
    ("ok(r) / err(r)", "the payload of a WIT result; an error if it is the other case"),
    ("some(o)", "the payload of a WIT option ({some: v}); an error for none"),
    ("html_escaped(s)", "s with & < > \" ' escaped as HTML"),
    ("in_domain(v, \"range:1..31\")", "v satisfies a manifest value domain (range, len, enum, format, bytes)"),
    ("same_items(a, b)", "the lists hold the same items, in any order (multiset equality)"),
    ("date(s) / time(s)", "a YYYY-MM-DD date as a timestamp / an HH:MM[:SS] time as a duration since midnight"),
];

const NAMES: &[&str] = &["sum", "num", "approx", "is_ok", "is_err", "ok", "err", "some", "html_escaped", "in_domain", "same_items", "date", "time"];

static ENV: LazyLock<Arc<Env>> = LazyLock::new(|| {
    let mut env = Env::stdlib();
    env.add_extension(extensions::strings).expect("CEL strings extension");
    env.add_extension(extensions::math).expect("CEL math extension");
    env.add_extension(extensions::lists).expect("CEL lists extension");
    Arc::new(env)
});

static COMPACTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"…\[\d+ bytes #[0-9a-f]{8}\]$").unwrap());

// ---------------------------------------------------------------- bindings

/// Where a binding's value comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    Request(String),
    Arg(usize, String),
    HostCalls(String),
    HostResults(String),
    HostResult(String, String),
    HostArgs(String, String),
    Status,
    Body,
    Headers(Option<String>),
    Result(String),
    Json(String),
    Select(String),
    Calls,
    Totals(Option<String>),
    Clock(String),
    Logs,
    Outcome,
}

/// One `let` entry: `name = "path"`. A trailing `?` makes a missing value `null`.
#[derive(Debug, Clone)]
pub struct Binding {
    pub name: String,
    pub path: String,
    pub source: Source,
    pub optional: bool,
    selector: Option<Selector>,
}

/// Every binding source with what it gives, for docs and `appfuzz bindings`.
pub const SOURCES: &[(&str, &str)] = &[
    ("request.<path>", "a request field (query and form by key: request.query.days)"),
    ("args.<i>.<path>", "an export argument, for exports without a request"),
    ("host.<fn>.calls", "every call of a host function: [{n, call, args, result, trap}]; [] when not called"),
    ("host.<fn>.results", "the results of every call, in order"),
    ("host.<fn>.result.<path>", "the result of the one call; undefined when it was called 0 or several times"),
    ("host.<fn>.args.<param>.<path>", "an argument of the one call"),
    ("out.status", "the response status"),
    ("out.body", "the response body"),
    ("out.headers.<name>", "a response header (case-insensitive); out.headers is a map"),
    ("out.result.<path>", "the raw export result (what `$.path` selects)"),
    ("out.json.<path>", "the body parsed as JSON"),
    ("select <selector>", "texts a selector picks (.class, #id, tag, /regex/, $.path): a list"),
    ("calls", "every host call in order, with func"),
    ("totals.<metric>", "fuel, peak_memory, virtual_ns, host_calls, cost, clock_reads, ..."),
    ("clock.now / clock.today / clock.time", "the run's virtual start time"),
    ("logs", "stdout and stderr"),
    ("outcome", "how the run ended: ok, trap, out_of_fuel, ..."),
];

fn split_fn(rest: &str) -> Result<(String, &str)> {
    let hash = rest.find('#').ok_or_else(|| anyhow!("host bindings name a function as interface#function (items#all)"))?;
    let end = rest[hash..].find('.').map_or(rest.len(), |i| hash + i);
    let f = rest[..end].to_string();
    Ok((f, rest[end..].strip_prefix('.').unwrap_or("")))
}

impl Binding {
    pub fn parse(name: &str, path: &str) -> Result<Self> {
        if !ident(name) {
            bail!("binding name {name:?} must be an identifier (letters, digits, _)");
        }
        if NAMES.contains(&name) || RESERVED.contains(&name) {
            bail!("binding name {name:?} is a reserved word or function");
        }
        let text = path.trim();
        let (body, optional) = match text.strip_suffix('?') {
            Some(b) if !text.starts_with("select ") => (b, true),
            _ => (text, false),
        };
        let seg = |p: &str| p.strip_prefix('.').unwrap_or(p).to_string();
        let mut selector = None;
        let source = if let Some(sel) = body.strip_prefix("select ") {
            selector = Some(Selector::parse(sel.trim())?);
            Source::Select(sel.trim().to_string())
        } else if body == "request" || body.starts_with("request.") {
            Source::Request(seg(&body["request".len()..]))
        } else if let Some(rest) = body.strip_prefix("args.") {
            let (i, p) = rest.split_once('.').unwrap_or((rest, ""));
            Source::Arg(i.parse().map_err(|_| anyhow!("args.<i> needs an argument index: {path:?}"))?, p.to_string())
        } else if let Some(rest) = body.strip_prefix("host.") {
            let (f, part) = split_fn(rest)?;
            let (kind, p) = part.split_once('.').unwrap_or((part, ""));
            match kind {
                "calls" if p.is_empty() => Source::HostCalls(f),
                "results" if p.is_empty() => Source::HostResults(f),
                "result" => Source::HostResult(f, p.to_string()),
                "args" if !p.is_empty() => Source::HostArgs(f, p.to_string()),
                _ => bail!("{path:?}: after host.<fn> comes .calls, .results, .result[.<path>] or .args.<param>[.<path>]"),
            }
        } else if body == "out.status" {
            Source::Status
        } else if body == "out.body" {
            Source::Body
        } else if body == "out.headers" || body.starts_with("out.headers.") {
            Source::Headers(body.strip_prefix("out.headers.").map(str::to_ascii_lowercase))
        } else if body == "out.result" || body.starts_with("out.result.") {
            Source::Result(seg(&body["out.result".len()..]))
        } else if body == "out.json" || body.starts_with("out.json.") {
            Source::Json(seg(&body["out.json".len()..]))
        } else if body == "calls" {
            Source::Calls
        } else if body == "totals" || body.starts_with("totals.") {
            Source::Totals(body.strip_prefix("totals.").map(str::to_string))
        } else if matches!(body, "clock.now" | "clock.today" | "clock.time") {
            Source::Clock(body["clock.".len()..].to_string())
        } else if body == "logs" {
            Source::Logs
        } else if body == "outcome" {
            Source::Outcome
        } else {
            bail!("unknown binding source {path:?}. Sources: {}", SOURCES.iter().map(|(s, _)| *s).collect::<Vec<_>>().join(", "));
        };
        if let Source::Totals(Some(k)) = &source
            && !TOTALS.contains(&k.as_str())
        {
            bail!("unknown total {k:?}; one of {}", TOTALS.join(", "));
        }
        Ok(Binding { name: name.to_string(), path: text.to_string(), source, optional, selector })
    }

    fn host_fn(&self) -> Option<&str> {
        match &self.source {
            Source::HostCalls(f) | Source::HostResults(f) | Source::HostResult(f, _) | Source::HostArgs(f, _) => Some(f),
            _ => None,
        }
    }

    /// The binding's value in a run, or why it has none.
    pub fn resolve(&self, r: &RunRecord, m: &Manifest) -> Result<Value, String> {
        let v = self.resolve_raw(r, m);
        let v = match v {
            Err(_) if self.optional => Ok(Value::Null),
            v => v,
        }?;
        if (self.host_fn().is_some() || self.source == Source::Calls) && compacted(&v) {
            return Err("a host string over 1 KiB was shortened in the record; the value is not complete".into());
        }
        Ok(v)
    }

    fn resolve_raw(&self, r: &RunRecord, m: &Manifest) -> Result<Value, String> {
        let at = |v: &Value, p: &str, what: &str| field(v, p).cloned().ok_or_else(|| format!("{what} has no {p:?}"));
        match &self.source {
            Source::Request(p) => {
                let req = r.spec.args.first().ok_or("the export has no request argument")?;
                at(req, p, "the request")
            }
            Source::Arg(i, p) => {
                let a = r.spec.args.get(*i).ok_or_else(|| format!("the export has no argument {i}"))?;
                at(a, p, &format!("argument {i}"))
            }
            Source::HostCalls(f) => Ok(Value::Array(calls_of(r, f).map(call_json).collect())),
            Source::HostResults(f) => Ok(Value::Array(calls_of(r, f).map(|e| e.result.clone().unwrap_or(Value::Null)).collect())),
            Source::HostResult(f, p) | Source::HostArgs(f, p) => {
                let calls: Vec<&HostCall> = calls_of(r, f).collect();
                let e = match calls.as_slice() {
                    [] => return Err(format!("{f} was not called")),
                    [e] => *e,
                    _ => return Err(format!("{f} was called {} times; bind .results or .calls", calls.len())),
                };
                if let Source::HostResult(..) = &self.source {
                    if let Some(t) = &e.trap {
                        return Err(format!("{f} trapped: {t}"));
                    }
                    at(e.result.as_ref().unwrap_or(&Value::Null), p, &format!("the result of {f}"))
                } else {
                    let (param, rest) = p.split_once('.').unwrap_or((p, ""));
                    let a = e.args.get(param).or_else(|| e.args.get(&param.replace('_', "-"))).ok_or_else(|| format!("{f} has no argument {param}"))?;
                    at(a, rest, &format!("argument {param} of {f}"))
                }
            }
            Source::Status => response(r, m).status.map(Value::from).ok_or_else(|| "the response has no status".into()),
            Source::Body => response(r, m).body.map(Value::String).ok_or_else(|| "the response has no body".into()),
            Source::Headers(name) => {
                let hs = response(r, m).headers;
                match name {
                    Some(n) => {
                        hs.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| Value::String(v.clone())).ok_or_else(|| format!("no header {n}"))
                    }
                    None => Ok(Value::Object(hs.into_iter().rev().map(|(k, v)| (k.to_ascii_lowercase(), Value::String(v))).collect())),
                }
            }
            Source::Result(p) => at(r.result.as_ref().ok_or("the run has no result")?, p, "the result"),
            Source::Json(p) => {
                let body = response(r, m).body.ok_or("the response has no body")?;
                let v: Value = serde_json::from_str(&body).map_err(|e| format!("the body is not JSON: {e}"))?;
                at(&v, p, "the JSON body")
            }
            Source::Select(_) => Ok(Value::Array(self.selector.as_ref().map(|s| s.selected(r, m)).unwrap_or_default())),
            Source::Calls => Ok(Value::Array(
                r.events
                    .iter()
                    .map(|e| {
                        let mut v = call_json(e);
                        v["func"] = json!(e.func);
                        v
                    })
                    .collect(),
            )),
            Source::Totals(k) => {
                let t = serde_json::to_value(&r.totals).map_err(|e| e.to_string())?;
                match k {
                    Some(k) => t.get(k).cloned().ok_or_else(|| format!("no total {k}")),
                    None => Ok(t),
                }
            }
            Source::Clock(which) => {
                let now = &r.spec.now;
                Ok(Value::String(match which.as_str() {
                    "today" => now.get(..10).unwrap_or(now).to_string(),
                    "time" => now.split_once('T').map_or("", |(_, t)| t).to_string(),
                    _ => now.clone(),
                }))
            }
            Source::Logs => Ok(Value::String(format!("{}{}", r.stdout, r.stderr))),
            Source::Outcome => serde_json::to_value(r.outcome.kind).map_err(|e| e.to_string()),
        }
    }
}

const TOTALS: &[&str] = &["fuel", "peak_memory", "virtual_ns", "guest_ns", "host_ns", "sleep_ns", "host_calls", "cost", "clock_reads", "random_bytes"];

/// Words CEL reserves, which can't name a binding.
const RESERVED: &[&str] = &[
    "true",
    "false",
    "null",
    "in",
    "as",
    "break",
    "const",
    "continue",
    "else",
    "for",
    "function",
    "if",
    "import",
    "let",
    "loop",
    "package",
    "namespace",
    "return",
    "var",
    "void",
    "while",
    "has",
    "all",
    "exists",
    "exists_one",
    "map",
    "filter",
    "size",
    "int",
    "uint",
    "double",
    "string",
    "bytes",
    "bool",
    "list",
    "type",
    "dyn",
    "duration",
    "timestamp",
    "math",
    "strings",
    "lists",
    "optional",
];

fn ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// A host function name in a binding matches a recorded call: the full key
/// or a suffix after the package (`items#all` for `acme:web/items#all`).
pub fn fn_matches(func: &str, f: &str) -> bool {
    let f = match f.split_once('@') {
        Some((i, rest)) => rest.split_once('#').map_or_else(|| i.to_string(), |(_, g)| format!("{i}#{g}")),
        None => f.to_string(),
    };
    func == f || func.ends_with(&format!("/{f}")) || func.ends_with(&format!(":{f}"))
}

fn calls_of<'a>(r: &'a RunRecord, f: &'a str) -> impl Iterator<Item = &'a HostCall> + 'a {
    r.events.iter().filter(move |e| fn_matches(&e.func, f))
}

fn call_json(e: &HostCall) -> Value {
    json!({"n": e.n, "call": e.call, "args": e.args, "result": e.result, "trap": e.trap})
}

fn compacted(v: &Value) -> bool {
    match v {
        Value::String(s) => COMPACTED.is_match(s),
        Value::Array(a) => a.iter().any(compacted),
        Value::Object(o) => o.values().any(compacted),
        _ => false,
    }
}

// ---------------------------------------------------------- WIT validation

/// Checks host functions, parameters and paths against the component's WIT.
pub fn validate_wit(bindings: &[Binding], imports: &[Interface], exports: &[FuncInfo], export: Option<&str>) -> Result<()> {
    let funcs: Vec<&FuncInfo> = imports.iter().filter(|i| i.kind == ImportKind::Platform).flat_map(|i| &i.funcs).collect();
    let entry = export.and_then(|x| exports.iter().find(|e| crate::harness::fn_key_eq(x, &e.key))).or(exports.first());
    for b in bindings {
        let what = || format!("let {} = {:?}", b.name, b.path);
        if let Some(f) = b.host_fn() {
            let hits: Vec<&&FuncInfo> = funcs.iter().filter(|x| fn_matches(&x.key, f)).collect();
            let info = match hits.as_slice() {
                [one] => *one,
                [] => {
                    let near = suggest(f, funcs.iter().map(|x| x.key.as_str()));
                    bail!("{}: the app imports no host function {f}{near}", what());
                }
                _ => bail!("{}: {f} matches {}; name it in full", what(), hits.iter().map(|x| x.key.as_str()).collect::<Vec<_>>().join(", ")),
            };
            match &b.source {
                Source::HostResult(_, p) => {
                    let t = info.ty.results().next().ok_or_else(|| anyhow!("{}: {} returns nothing", what(), info.signature()))?;
                    wit_path(&t, p).with_context(|| format!("{}: in the result of {}", what(), info.signature()))?;
                }
                Source::HostArgs(_, p) => {
                    let (param, rest) = p.split_once('.').unwrap_or((p, ""));
                    let t = info.ty.params().find(|(n, _)| *n == param || n.replace('-', "_") == param).map(|(_, t)| t);
                    let t = t.ok_or_else(|| anyhow!("{}: {} has no parameter {param}", what(), info.signature()))?;
                    wit_path(&t, rest).with_context(|| format!("{}: in parameter {param} of {}", what(), info.signature()))?;
                }
                _ => {}
            }
        }
        let Some(e) = entry else { continue };
        match &b.source {
            Source::Request(p) if !b.optional => {
                let (_, t) = e.ty.params().next().ok_or_else(|| anyhow!("{}: {} takes no request", what(), e.signature()))?;
                wit_path(&t, p).with_context(|| format!("{}: in the request of {}", what(), e.signature()))?;
            }
            Source::Arg(i, p) if !b.optional => {
                let (_, t) = e.ty.params().nth(*i).ok_or_else(|| anyhow!("{}: {} has no argument {i}", what(), e.signature()))?;
                wit_path(&t, p).with_context(|| format!("{}: in argument {i} of {}", what(), e.signature()))?;
            }
            Source::Result(p) => {
                let t = e.ty.results().next().ok_or_else(|| anyhow!("{}: {} returns nothing", what(), e.signature()))?;
                wit_path(&t, p).with_context(|| format!("{}: in the result of {}", what(), e.signature()))?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// A dot path through WIT-shaped JSON exists in the type. Lists of
/// `(string, T)` pairs (query, form, headers) take any key.
fn wit_path(ty: &Type, path: &str) -> Result<()> {
    let segs: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    let mut t = ty.clone();
    for (i, s) in segs.iter().enumerate() {
        t = match &t {
            Type::Record(r) => match r.fields().find(|f| f.name == *s || f.name.replace('-', "_") == *s) {
                Some(f) => f.ty,
                None => bail!("no field {s:?} (fields: {})", r.fields().map(|f| f.name.to_string()).collect::<Vec<_>>().join(", ")),
            },
            Type::Result(r) => match *s {
                "ok" => r.ok().ok_or_else(|| anyhow!("the ok case has no value"))?,
                "err" => r.err().ok_or_else(|| anyhow!("the err case has no value"))?,
                _ => bail!("{s:?} is inside a result: write .ok.{s} or .err.{s}"),
            },
            Type::Option(o) => match *s {
                "some" => o.ty(),
                _ => bail!("{s:?} is inside an option: write .some.{s}, or bind the option and use some()"),
            },
            Type::Variant(v) => match v.cases().find(|c| c.name == *s) {
                Some(c) => c.ty.ok_or_else(|| anyhow!("case {s} has no value"))?,
                None => bail!("no case {s:?}"),
            },
            Type::List(l) => match l.ty() {
                Type::Tuple(tp) if tp.types().len() == 2 && matches!(tp.types().next(), Some(Type::String)) => tp.types().nth(1).unwrap(),
                _ => bail!("{} is a list; bind the list and use map() or [i] in the expression", segs[..i].join(".")),
            },
            _ => bail!("{} holds no fields", if i == 0 { "the value".to_string() } else { segs[..i].join(".") }),
        };
    }
    Ok(())
}

fn suggest<'a>(word: &str, candidates: impl Iterator<Item = &'a str>) -> String {
    let best = candidates.map(|c| (distance(word, c), c)).filter(|(d, c)| *d <= 2.max(c.len() / 3)).min();
    best.map_or_else(String::new, |(_, c)| format!(" (did you mean {c}?)"))
}

fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + usize::from(ca != *cb)).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

// ------------------------------------------------------------- expressions

/// A compiled expression, split into its top-level conjuncts.
#[derive(Clone)]
pub struct Expression {
    pub text: String,
    conjuncts: Vec<(String, Arc<Program>)>,
    /// Free variables (binding names) the expression uses.
    pub uses: BTreeSet<String>,
}

impl std::fmt::Debug for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Expression({})", self.text)
    }
}

impl Expression {
    pub fn compile(text: &str, names: &BTreeSet<String>) -> Result<Self> {
        if text.trim().is_empty() {
            bail!("empty expression");
        }
        if text.len() > MAX_EXPRESSION {
            bail!("expression longer than {MAX_EXPRESSION} bytes");
        }
        let whole = ENV.compile(text).map_err(|e| anyhow!("{}", e.to_string().trim()))?;
        let mut uses = BTreeSet::new();
        let mut funcs = BTreeSet::new();
        scan(whole.expression(), &mut Vec::new(), &mut uses, &mut funcs, 0)?;
        for u in &uses {
            if !names.contains(u) {
                let near = suggest(u, names.iter().map(String::as_str));
                bail!("unknown name {u:?} in {text:?}{near}; expressions see only the let bindings ({})", names.iter().cloned().collect::<Vec<_>>().join(", "));
            }
        }
        for f in &funcs {
            if !known_function(f) {
                let near = suggest(f, NAMES.iter().copied());
                bail!("unknown function {f:?} in {text:?}{near}");
            }
        }
        let parts = split_and(text);
        let conjuncts = if parts.len() > 1 && parts.len() == count_and(whole.expression()) {
            let mut v = Vec::new();
            for p in &parts {
                match ENV.compile(p) {
                    Ok(prog) => v.push((p.trim().to_string(), Arc::new(prog))),
                    Err(_) => {
                        v.clear();
                        break;
                    }
                }
            }
            if v.is_empty() { vec![(text.trim().to_string(), Arc::new(whole))] } else { v }
        } else {
            vec![(text.trim().to_string(), Arc::new(whole))]
        };
        Ok(Expression { text: text.trim().to_string(), conjuncts, uses })
    }
}

/// Collects free variables and called functions, and enforces nesting.
fn scan(e: &IdedExpr, bound: &mut Vec<String>, uses: &mut BTreeSet<String>, funcs: &mut BTreeSet<String>, depth: usize) -> Result<()> {
    match &e.expr {
        Expr::Ident(n) => {
            if !n.starts_with('@') && !bound.iter().any(|b| b == n) {
                uses.insert(n.clone());
            }
        }
        Expr::Call(c) => {
            if !c.func_name.starts_with('_') && !c.func_name.starts_with('@') && !c.func_name.contains('@') && c.func_name != "!_" && c.func_name != "-_" {
                funcs.insert(c.func_name.clone());
            }
            if let Some(t) = &c.target {
                scan(t, bound, uses, funcs, depth)?;
            }
            for a in &c.args {
                scan(a, bound, uses, funcs, depth)?;
            }
        }
        Expr::Select(s) => scan(&s.operand, bound, uses, funcs, depth)?,
        Expr::List(l) => {
            for x in &l.elements {
                scan(x, bound, uses, funcs, depth)?;
            }
        }
        Expr::Map(m) => {
            for entry in &m.entries {
                match &entry.expr {
                    cel::common::ast::EntryExpr::MapEntry(me) => {
                        scan(&me.key, bound, uses, funcs, depth)?;
                        scan(&me.value, bound, uses, funcs, depth)?;
                    }
                    cel::common::ast::EntryExpr::StructField(f) => scan(&f.value, bound, uses, funcs, depth)?,
                }
            }
        }
        Expr::Comprehension(c) => {
            if depth >= MAX_NESTING {
                bail!("macros (all, exists, map, filter) nest deeper than {MAX_NESTING}");
            }
            scan(&c.iter_range, bound, uses, funcs, depth)?;
            scan(&c.accu_init, bound, uses, funcs, depth)?;
            let n = bound.len();
            bound.push(c.iter_var.clone());
            if let Some(v) = &c.iter_var2 {
                bound.push(v.clone());
            }
            bound.push(c.accu_var.clone());
            scan(&c.loop_cond, bound, uses, funcs, depth + 1)?;
            scan(&c.loop_step, bound, uses, funcs, depth + 1)?;
            scan(&c.result, bound, uses, funcs, depth + 1)?;
            bound.truncate(n);
        }
        _ => {}
    }
    Ok(())
}

/// A function CEL or appfuzz declares. CEL's environment can only be asked
/// whether adding a function would conflict with a declared one.
fn known_function(name: &str) -> bool {
    static KNOWN: LazyLock<std::sync::Mutex<HashMap<String, bool>>> = LazyLock::new(Default::default);
    if NAMES.contains(&name) {
        return true;
    }
    let mut cache = KNOWN.lock().unwrap_or_else(|p| p.into_inner());
    *cache.entry(name.to_string()).or_insert_with(|| Context::with_env(ENV.clone()).add_function(name, |a: i64| a).is_err())
}

/// Splits at top-level `&&` (outside brackets and strings), unless a
/// top-level `||` or `?` makes `&&` not the root.
fn split_and(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let (mut depth, mut quote, mut i, mut start) = (0i32, None::<u8>, 0, 0);
    let mut parts = Vec::new();
    while i < b.len() {
        let c = b[i];
        if let Some(q) = quote {
            if c == b'\\' {
                i += 1;
            } else if c == q {
                quote = None;
            }
        } else {
            match c {
                b'\'' | b'"' => quote = Some(c),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b'|' if depth == 0 && b.get(i + 1) == Some(&b'|') => return vec![text.to_string()],
                b'?' if depth == 0 => return vec![text.to_string()],
                b'&' if depth == 0 && b.get(i + 1) == Some(&b'&') => {
                    parts.push(text[start..i].to_string());
                    start = i + 2;
                    i += 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    parts.push(text[start..].to_string());
    parts
}

fn count_and(e: &IdedExpr) -> usize {
    match &e.expr {
        Expr::Call(c) if c.func_name == "_&&_" => c.args.iter().map(count_and).sum(),
        _ => 1,
    }
}

// -------------------------------------------------------------- evaluation

/// One property: bindings, an optional precondition and the assertion.
#[derive(Clone, Debug)]
pub struct Assertion {
    pub bindings: Vec<Binding>,
    pub assume: Option<Expression>,
    pub expr: Expression,
}

/// What one run says about a property.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Held. `vacuous`: every list the property reads was empty.
    Holds {
        vacuous: bool,
    },
    Broken {
        conjunct: String,
        evidence: Value,
    },
    /// `assume` was false.
    Rejected,
    /// A binding has no value in this run.
    Undefined {
        binding: String,
        reason: String,
    },
    /// Evaluation failed (a type error, a missing key, int("abc")).
    Error {
        conjunct: String,
        message: String,
    },
}

pub struct Evaluated {
    pub verdict: Verdict,
    /// Binding values, shortened, for evidence.
    pub values: BTreeMap<String, Value>,
}

impl Assertion {
    pub fn new(lets: &BTreeMap<String, String>, assert: &str, assume: Option<&str>) -> Result<Self> {
        let bindings: Vec<Binding> = lets.iter().map(|(k, v)| Binding::parse(k, v).with_context(|| format!("let {k}"))).collect::<Result<_>>()?;
        let names: BTreeSet<String> = lets.keys().cloned().collect();
        let expr = Expression::compile(assert, &names).context("assert")?;
        let assume = assume.map(|a| Expression::compile(a, &names).context("assume")).transpose()?;
        Ok(Assertion { bindings, assume, expr })
    }

    /// Names this property reads (assert and assume).
    pub fn uses(&self) -> BTreeSet<String> {
        let mut u = self.expr.uses.clone();
        if let Some(a) = &self.assume {
            u.extend(a.uses.iter().cloned());
        }
        u
    }

    /// The binding values of a run, or the first that has none.
    pub fn values(&self, r: &RunRecord, m: &Manifest) -> Result<BTreeMap<String, Value>, (String, String)> {
        let uses = self.uses();
        let mut out = BTreeMap::new();
        for b in self.bindings.iter().filter(|b| uses.contains(&b.name)) {
            out.insert(b.name.clone(), b.resolve(r, m).map_err(|e| (b.name.clone(), e))?);
        }
        Ok(out)
    }

    pub fn evaluate(&self, r: &RunRecord, m: &Manifest) -> Evaluated {
        let values = match self.values(r, m) {
            Ok(v) => v,
            Err((binding, reason)) => return Evaluated { verdict: Verdict::Undefined { binding, reason }, values: BTreeMap::new() },
        };
        let verdict = self.judge(&values);
        Evaluated { verdict, values: values.iter().map(|(k, v)| (k.clone(), shorten(v))).collect() }
    }

    /// The verdict for given binding values.
    pub fn judge(&self, values: &BTreeMap<String, Value>) -> Verdict {
        let ctx = context(values);
        if let Some(a) = &self.assume {
            for (text, p) in &a.conjuncts {
                match strict(p.expression(), &ctx) {
                    Ok(Cel::Bool(true)) => {}
                    Ok(Cel::Bool(false)) => return Verdict::Rejected,
                    Ok(v) => return Verdict::Error { conjunct: text.clone(), message: format!("assume must be true or false, not {}", show(&v)) },
                    Err(e) => return Verdict::Error { conjunct: text.clone(), message: e },
                }
            }
        }
        for (text, p) in &self.expr.conjuncts {
            match strict(p.expression(), &ctx) {
                Ok(Cel::Bool(true)) => {}
                Ok(Cel::Bool(false)) => return Verdict::Broken { conjunct: text.clone(), evidence: explain(p.expression(), &ctx) },
                Ok(v) => return Verdict::Error { conjunct: text.clone(), message: format!("an assertion must be true or false, not {}", show(&v)) },
                Err(e) => return Verdict::Error { conjunct: text.clone(), message: e },
            }
        }
        let lists: Vec<&Value> = values.values().filter(|v| v.is_array()).collect();
        Verdict::Holds { vacuous: !lists.is_empty() && lists.iter().all(|v| v.as_array().is_some_and(Vec::is_empty)) }
    }

    /// The value of the whole assert expression, for `eval`.
    pub fn value(&self, values: &BTreeMap<String, Value>) -> Result<Value, String> {
        let ctx = context(values);
        let whole = ENV.compile(&self.expr.text).map_err(|e| e.to_string())?;
        strict(whole.expression(), &ctx).map(|v| to_json(&v))
    }

    /// A property that still holds when its values are changed (a number +1,
    /// a row dropped or doubled, two rows swapped) may restate the code or
    /// test nothing. `None`: no mutation applied.
    pub fn weak(&self, values: &BTreeMap<String, Value>) -> Option<bool> {
        let mut tried = 0;
        for (name, v) in values {
            for m in mutations(v) {
                let mut changed = values.clone();
                changed.insert(name.clone(), m);
                match self.judge(&changed) {
                    Verdict::Holds { .. } => tried += 1,
                    Verdict::Rejected => {}
                    _ => return Some(false),
                }
            }
        }
        (tried > 0).then_some(true)
    }
}

fn mutations(v: &Value) -> Vec<Value> {
    match v {
        Value::Number(n) => n.as_i64().map(|i| json!(i.saturating_add(1))).or_else(|| n.as_f64().map(|f| json!(f + 1.0))).into_iter().collect(),
        Value::String(s) => vec![match s.trim().parse::<i64>() {
            Ok(i) => json!((i + 1).to_string()),
            Err(_) => json!(format!("{s}x")),
        }],
        Value::Bool(b) => vec![json!(!b)],
        Value::Array(a) if !a.is_empty() => {
            let mut out = vec![];
            out.push(Value::Array(a[..a.len() - 1].to_vec()));
            let mut doubled = a.clone();
            doubled.push(a[0].clone());
            out.push(Value::Array(doubled));
            for m in mutations(&a[0]).into_iter().take(4) {
                let mut x = a.clone();
                x[0] = m;
                out.push(Value::Array(x));
            }
            if a.len() >= 2 && a[0] != a[1] {
                let mut x = a.clone();
                x.swap(0, 1);
                out.push(Value::Array(x));
            }
            out
        }
        Value::Object(o) => o
            .iter()
            .take(8)
            .flat_map(|(k, x)| {
                mutations(x).into_iter().take(1).map(move |m| {
                    let mut c = o.clone();
                    c.insert(k.clone(), m);
                    Value::Object(c)
                })
            })
            .collect(),
        _ => vec![],
    }
}

/// Evaluates with CEL, but `&&`, `||`, `!` and `?:` outside macros are
/// evaluated here, so an error in either operand is an error.
fn strict(e: &IdedExpr, ctx: &Context) -> Result<Cel, String> {
    let bool_of = |v: Cel, what: &str| match v {
        Cel::Bool(b) => Ok(b),
        v => Err(format!("{what} needs true or false, not {}", show(&v))),
    };
    if let Expr::Call(c) = &e.expr
        && c.target.is_none()
    {
        match (c.func_name.as_str(), c.args.as_slice()) {
            ("_&&_", [a, b]) => {
                let (x, y) = (bool_of(strict(a, ctx)?, "&&")?, bool_of(strict(b, ctx)?, "&&")?);
                return Ok(Cel::Bool(x && y));
            }
            ("_||_", [a, b]) => {
                let (x, y) = (bool_of(strict(a, ctx)?, "||")?, bool_of(strict(b, ctx)?, "||")?);
                return Ok(Cel::Bool(x || y));
            }
            ("!_", [a]) => return Ok(Cel::Bool(!bool_of(strict(a, ctx)?, "!")?)),
            ("_?_:_", [c, t, f]) => return if bool_of(strict(c, ctx)?, "?:")? { strict(t, ctx) } else { strict(f, ctx) },
            _ => {}
        }
    }
    ctx.resolve(e).map_err(|e| e.to_string())
}

/// Why a conjunct is false: both sides of a comparison, or the first
/// element `all()` rejects.
fn explain(e: &IdedExpr, ctx: &Context) -> Value {
    match &e.expr {
        Expr::Call(c) if c.target.is_none() && c.args.len() == 2 && ["_==_", "_!=_", "_<_", "_<=_", "_>_", "_>=_", "@in"].contains(&c.func_name.as_str()) => {
            let side = |x: &IdedExpr| ctx.resolve(x).map_or_else(|e| json!({"error": e.to_string()}), |v| to_json(&v));
            json!({"left": side(&c.args[0]), "right": side(&c.args[1])})
        }
        Expr::Call(c) if c.func_name == "!_" && c.args.len() == 1 => explain(&c.args[0], ctx),
        Expr::Comprehension(c) => {
            let Expr::Call(step) = &c.loop_step.expr else { return json!({}) };
            let first_is_accu = matches!(step.args.first().map(|a| &a.expr), Some(Expr::Ident(n)) if *n == c.accu_var);
            if step.func_name != "_&&_" || !first_is_accu || step.args.len() != 2 || c.iter_var2.is_some() {
                return json!({});
            }
            let Ok(Cel::List(items)) = ctx.resolve(&c.iter_range) else { return json!({}) };
            for (i, item) in items.iter().enumerate() {
                let mut inner = ctx.new_inner_scope();
                inner.add_variable_from_value(c.iter_var.clone(), item.clone());
                match inner.resolve(&step.args[1]) {
                    Ok(Cel::Bool(true)) => {}
                    other => {
                        let mut out = json!({"index": i, "element": shorten(&to_json(item))});
                        if let Err(e) = other {
                            out["error"] = json!(e.to_string());
                        } else if let ev @ Value::Object(_) = explain(&step.args[1], &inner)
                            && ev.as_object().is_some_and(|o| !o.is_empty())
                        {
                            out["because"] = ev;
                        }
                        return out;
                    }
                }
            }
            json!({})
        }
        _ => json!({}),
    }
}

fn context(values: &BTreeMap<String, Value>) -> Context<'static, 'static> {
    let mut ctx = Context::with_env(ENV.clone());
    for (k, v) in values {
        ctx.add_variable_from_value(k.clone(), to_cel(v));
    }
    let numbers = |v: &Cel| match v {
        Cel::Int(i) => Some(*i as f64),
        Cel::UInt(u) => Some(*u as f64),
        Cel::Float(f) => Some(*f),
        _ => None,
    };
    let _ = ctx.add_function("sum", move |This(list): This<Arc<Vec<Cel>>>| -> Result<Cel, ExecutionError> {
        let mut int: Option<i64> = Some(0);
        let mut float = 0.0;
        for x in list.iter() {
            match x {
                Cel::Int(i) => int = int.and_then(|s| s.checked_add(*i)),
                Cel::UInt(u) => int = int.and_then(|s| i64::try_from(*u).ok().and_then(|u| s.checked_add(u))),
                Cel::Float(_) => int = None,
                v => return Err(ExecutionError::function_error("sum", format!("sum needs numbers, not {}; use num() on texts", show(v)))),
            }
            float += numbers(x).unwrap_or(0.0);
        }
        Ok(int.map_or(Cel::Float(float), Cel::Int))
    });
    let _ = ctx.add_function("num", |This(v): This<Cel>| -> Result<Cel, ExecutionError> {
        let n = match &v {
            Cel::Int(_) | Cel::Float(_) => return Ok(v),
            Cel::UInt(u) => return Ok(i64::try_from(*u).map_or(Cel::Float(*u as f64), Cel::Int)),
            Cel::String(s) => crate::check::scalar_number(&Value::String(s.to_string())),
            _ => None,
        };
        let n = n.ok_or_else(|| ExecutionError::function_error("num", format!("{} holds no single number", show(&v))))?;
        Ok(if n.fract() == 0.0 && n.abs() < 9e15 { Cel::Int(n as i64) } else { Cel::Float(n) })
    });
    let _ = ctx.add_function("approx", move |a: Cel, b: Cel, eps: Cel| -> Result<Cel, ExecutionError> {
        match (numbers(&a), numbers(&b), numbers(&eps)) {
            (Some(a), Some(b), Some(e)) => Ok(Cel::Bool((a - b).abs() <= e)),
            _ => Err(ExecutionError::function_error("approx", "approx(a, b, eps) needs numbers")),
        }
    });
    let case = |v: &Cel, k: &str| match v {
        Cel::Map(m) => m.map.get(&Key::String(Arc::new(k.to_string()))).cloned(),
        _ => None,
    };
    let _ = ctx.add_function("is_ok", move |This(v): This<Cel>| Cel::Bool(case(&v, "ok").is_some()));
    let _ = ctx.add_function("is_err", move |This(v): This<Cel>| Cel::Bool(case(&v, "err").is_some()));
    let _ = ctx.add_function("ok", move |This(v): This<Cel>| -> Result<Cel, ExecutionError> {
        case(&v, "ok").ok_or_else(|| ExecutionError::function_error("ok", format!("not ok: {}", show(&v))))
    });
    let _ = ctx.add_function("err", move |This(v): This<Cel>| -> Result<Cel, ExecutionError> {
        case(&v, "err").ok_or_else(|| ExecutionError::function_error("err", format!("not an error: {}", show(&v))))
    });
    let _ = ctx.add_function("some", move |This(v): This<Cel>| -> Result<Cel, ExecutionError> {
        match &v {
            Cel::Null => Err(ExecutionError::function_error("some", "the option is none")),
            _ => Ok(case(&v, "some").unwrap_or(v)),
        }
    });
    let _ = ctx.add_function("html_escaped", |This(s): This<Arc<String>>| {
        Cel::String(Arc::new(s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")))
    });
    let _ = ctx.add_function("in_domain", |v: Cel, spec: Arc<String>| -> Result<Cel, ExecutionError> {
        let d = crate::value_contract::Domain::parse(vec![spec.to_string()]).map_err(|e| ExecutionError::function_error("in_domain", e))?;
        let j = to_json(&v);
        Ok(Cel::Bool(d.holds(Some(&j))))
    });
    let _ = ctx.add_function("same_items", |a: Arc<Vec<Cel>>, b: Arc<Vec<Cel>>| {
        let key = |l: &[Cel]| {
            let mut k: Vec<String> = l.iter().map(|x| to_json(x).to_string()).collect();
            k.sort();
            k
        };
        Cel::Bool(key(&a) == key(&b))
    });
    let _ = ctx.add_function("date", |This(s): This<Arc<String>>| -> Result<Cel, ExecutionError> {
        let d = chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d").map_err(|e| ExecutionError::function_error("date", format!("{s:?}: {e}")))?;
        Ok(Cel::Timestamp(d.and_hms_opt(0, 0, 0).unwrap().and_utc().fixed_offset()))
    });
    let _ = ctx.add_function("time", |This(s): This<Arc<String>>| -> Result<Cel, ExecutionError> {
        let t = chrono::NaiveTime::parse_from_str(s.trim(), "%H:%M:%S")
            .or_else(|_| chrono::NaiveTime::parse_from_str(s.trim(), "%H:%M"))
            .map_err(|e| ExecutionError::function_error("time", format!("{s:?}: {e}")))?;
        Ok(Cel::Duration(t.signed_duration_since(chrono::NaiveTime::MIN)))
    });
    ctx
}

/// JSON to CEL. Integers become `int` when they fit (never `uint`, whose
/// arithmetic with literals fails), else `double`.
pub fn to_cel(v: &Value) -> Cel {
    match v {
        Value::Null => Cel::Null,
        Value::Bool(b) => Cel::Bool(*b),
        Value::Number(n) => n.as_i64().map_or_else(|| Cel::Float(n.as_f64().unwrap_or(f64::NAN)), Cel::Int),
        Value::String(s) => Cel::String(Arc::new(s.clone())),
        Value::Array(a) => Cel::List(Arc::new(a.iter().map(to_cel).collect())),
        Value::Object(o) => Cel::Map(Map { map: Arc::new(o.iter().map(|(k, v)| (Key::String(Arc::new(k.clone())), to_cel(v))).collect()) }),
    }
}

pub fn to_json(v: &Cel) -> Value {
    match v {
        Cel::Null => Value::Null,
        Cel::Bool(b) => json!(b),
        Cel::Int(i) => json!(i),
        Cel::UInt(u) => json!(u),
        Cel::Float(f) if f.is_finite() => json!(f),
        Cel::Float(f) => json!(f.to_string()),
        Cel::String(s) => json!(s.as_str()),
        Cel::List(l) => Value::Array(l.iter().map(to_json).collect()),
        Cel::Map(m) => {
            let mut entries: Vec<(String, Value)> = m
                .map
                .iter()
                .map(|(k, v)| {
                    let k = match k {
                        Key::String(s) => s.to_string(),
                        Key::Int(i) => i.to_string(),
                        Key::Uint(u) => u.to_string(),
                        Key::Bool(b) => b.to_string(),
                    };
                    (k, to_json(v))
                })
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().collect())
        }
        Cel::Timestamp(t) => json!(t.to_rfc3339()),
        Cel::Duration(d) => json!(format!("{}s", d.num_milliseconds() as f64 / 1000.0)),
        other => json!(format!("{other:?}")),
    }
}

fn show(v: &Cel) -> String {
    let s = to_json(v).to_string();
    if s.len() > 80 { format!("{}…", &s[..s.char_indices().nth(80).map_or(s.len(), |(i, _)| i)]) } else { s }
}

/// Evidence values: long strings cut, long lists cut with a count.
pub fn shorten(v: &Value) -> Value {
    match v {
        Value::String(s) if s.chars().count() > 200 => json!(format!("{}… ({} chars)", s.chars().take(200).collect::<String>(), s.chars().count())),
        Value::Array(a) if a.len() > 20 => {
            let mut out: Vec<Value> = a.iter().take(20).map(shorten).collect();
            out.push(json!(format!("… {} more", a.len() - 20)));
            Value::Array(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(shorten).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), shorten(v))).collect()),
        v => v.clone(),
    }
}

/// The evaluation of a run against an assertion, as an acceptance status
/// (holds, broken, not_exercised, error), match count and detail.
pub fn status(a: &Assertion, r: &RunRecord, m: &Manifest) -> (&'static str, usize, Value) {
    if r.outcome.kind != OutcomeKind::Ok {
        return ("not_exercised", 0, json!({"reason": format!("the run ended with {:?}; assertions apply to completed runs", r.outcome.kind)}));
    }
    let e = a.evaluate(r, m);
    let bindings = json!(e.values);
    match e.verdict {
        Verdict::Holds { vacuous: false } => ("holds", 1, json!({})),
        Verdict::Holds { vacuous: true } => ("not_exercised", 0, json!({"reason": "vacuous: every list it reads was empty", "vacuous": true})),
        Verdict::Rejected => ("not_exercised", 0, json!({"reason": "rejected by assume", "rejected": true})),
        Verdict::Undefined { binding, reason } => ("not_exercised", 0, json!({"reason": format!("{binding}: {reason}"), "undefined": binding})),
        Verdict::Broken { conjunct, evidence } => {
            ("broken", 1, json!({"why": format!("{conjunct} is false"), "failing": conjunct, "evidence": {"bindings": bindings, "explained": evidence}}))
        }
        Verdict::Error { conjunct, message } => {
            ("error", 0, json!({"reason": format!("{conjunct}: {message}"), "expression_error": message, "failing": conjunct, "bindings": bindings}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lets(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn values(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs.iter().map(|(a, b)| (a.to_string(), b.clone())).collect()
    }

    fn a(assert: &str) -> Assertion {
        Assertion::new(&lets(&[("rows", "select .row"), ("items", "host.items#all.result"), ("n", "out.status"), ("q", "request.query.q")]), assert, None)
            .unwrap()
    }

    #[test]
    fn bindings_parse() {
        assert_eq!(
            Binding::parse("x", "host.acme:web/items@1.0.0#get.result.ok.name").unwrap().source,
            Source::HostResult("acme:web/items@1.0.0#get".into(), "ok.name".into())
        );
        assert_eq!(Binding::parse("x", "request.query.days").unwrap().source, Source::Request("query.days".into()));
        assert_eq!(Binding::parse("x", "out.headers.Location").unwrap().source, Source::Headers(Some("location".into())));
        assert!(Binding::parse("x", "request.form.hour?").unwrap().optional);
        assert!(Binding::parse("x", "host.items#all.nope").is_err());
        assert!(Binding::parse("x", "out.nope").is_err());
        assert!(Binding::parse("size", "out.status").is_err());
        assert!(Binding::parse("x", "totals.speed").is_err());
    }

    #[test]
    fn function_names_match_by_suffix() {
        assert!(fn_matches("acme:web/items#all", "items#all"));
        assert!(fn_matches("acme:web/items#all", "acme:web/items#all"));
        assert!(fn_matches("acme:web/items#all", "acme:web/items@0.1.0#all"));
        assert!(!fn_matches("acme:web/other-items#all", "items#all"));
    }

    #[test]
    fn names_are_checked_before_a_run() {
        let e = Assertion::new(&lets(&[("items", "out.status")]), "size(item) > 0", None).unwrap_err();
        assert!(format!("{e:#}").contains("did you mean items"), "{e:#}");
        let e = Assertion::new(&lets(&[("items", "out.status")]), "summ(items) > 0", None).unwrap_err();
        assert!(format!("{e:#}").contains("unknown function"), "{e:#}");
        assert!(Assertion::new(&lets(&[("items", "select .x")]), "items.all(i, i.size() > 0) && items.map(i, int(i)).sum() >= 0", None).is_ok());
        assert!(Assertion::new(&lets(&[("x", "select .x")]), "x.all(a, x.all(b, x.all(c, true)))", None).is_err());
        for f in [
            "size(x) > 0",
            "x.distinct().size() >= 0",
            "x.sort() == x",
            "x.all(s, s.matches('^a'))",
            "string(1) == '1'",
            "math.greatest([1]) == 1",
            "timestamp('2026-01-01T00:00:00Z') < date('2026-02-01')",
            "x.exists(s, s.startsWith('a') || s.endsWith('b'))",
            "double(1) == 1.0",
            "x.map(s, s.split(',')).size() >= 0",
            "'a'.lowerAscii() == 'a'",
        ] {
            assert!(Assertion::new(&lets(&[("x", "select .x")]), f, None).is_ok(), "{f}");
        }
    }

    #[test]
    fn evidence_names_the_conjunct_and_both_sides() {
        let p = a("n == 200 && size(rows) == size(items)");
        let v = values(&[("n", json!(200)), ("rows", json!(["a"])), ("items", json!([{"id": 1}, {"id": 2}]))]);
        let Verdict::Broken { conjunct, evidence } = p.judge(&v) else { panic!() };
        assert_eq!(conjunct, "size(rows) == size(items)");
        assert_eq!(evidence, json!({"left": 1, "right": 2}));
    }

    #[test]
    fn all_reports_the_first_failing_element() {
        let p = a("rows.all(r, int(r) <= n)");
        let Verdict::Broken { evidence, .. } = p.judge(&values(&[("rows", json!(["1", "500", "2"])), ("n", json!(200))])) else { panic!() };
        assert_eq!(evidence["index"], 1);
        assert_eq!(evidence["element"], "500");
        assert_eq!(evidence["because"], json!({"left": 500, "right": 200}));
    }

    #[test]
    fn errors_are_never_absorbed() {
        let p = a("rows[5] == 'x' || true");
        assert!(matches!(p.judge(&values(&[("rows", json!([]))])), Verdict::Error { .. }));
        let p = a("int(q) > 0");
        assert!(matches!(p.judge(&values(&[("q", json!("abc"))])), Verdict::Error { .. }));
        let p = a("n");
        assert!(matches!(p.judge(&values(&[("n", json!(3))])), Verdict::Error { .. }));
    }

    #[test]
    fn numbers_are_ints_not_uints() {
        let p = a("n + 1 == 201 && sum(items) == 6 && num(q) * 2 == 2468 && approx(sum([0.1, 0.2]), 0.3, 1e-9)");
        assert!(matches!(p.judge(&values(&[("n", json!(200)), ("items", json!([1, 2, 3])), ("q", json!("1,234 €"))])), Verdict::Holds { vacuous: false }));
    }

    #[test]
    fn wit_helpers() {
        let p = a("is_ok(items) && ok(items).size() == 2 && !is_err(items) && same_items(rows, ['b', 'a']) && html_escaped(q) == '&lt;i&gt;'");
        let v = values(&[("items", json!({"ok": [1, 2]})), ("rows", json!(["a", "b"])), ("q", json!("<i>"))]);
        assert!(matches!(p.judge(&v), Verdict::Holds { .. }), "{:?}", p.judge(&v));
        let p = a("in_domain(n, 'range:1..31') && !in_domain(q, 'format:date') && time('10:30') > time('09:00')");
        assert!(matches!(p.judge(&values(&[("n", json!(7)), ("q", json!("2026-13-01"))])), Verdict::Holds { .. }));
    }

    #[test]
    fn vacuous_and_weak() {
        let p = a("rows.all(r, size(r) > 0)");
        assert!(matches!(p.judge(&values(&[("rows", json!([]))])), Verdict::Holds { vacuous: true }));
        let tautology = a("size(rows) >= 0");
        assert_eq!(tautology.weak(&values(&[("rows", json!(["a", "b"]))])), Some(true));
        let real = a("size(rows) == size(items)");
        assert_eq!(real.weak(&values(&[("rows", json!(["a", "b"])), ("items", json!([1, 2]))])), Some(false));
    }

    #[test]
    fn assume_rejects() {
        let p = Assertion::new(&lets(&[("n", "out.status")]), "n == 200", Some("n < 400")).unwrap();
        assert!(matches!(p.judge(&values(&[("n", json!(404))])), Verdict::Rejected));
        assert!(matches!(p.judge(&values(&[("n", json!(201))])), Verdict::Broken { .. }));
    }

    #[test]
    fn split_respects_brackets_strings_and_or() {
        assert_eq!(split_and("a && f(b && c) && 'x && y' == s").len(), 3);
        assert_eq!(split_and("a && b || c").len(), 1);
        assert_eq!(split_and("a ? b && c : d").len(), 1);
    }
}
