//! Labels: what the manifest says host function parameters and results
//! mean. A parameter label names a sink (`sql`, `path`, `shell`, `url`,
//! `html`, `regex`) or says the parameter may receive personal data or
//! secrets (`pii`, `secret`). A result label says what a host function
//! returns: `untrusted` text (the default), trusted `html`, personal data
//! (`pii`) or a `secret`.
//!
//! Sinks are checked with canaries: a request field or host string whose
//! canary tail (`<i>'"../;$(x)`) reaches a labelled parameter intact. Personal
//! data and secrets are traced by value.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::output::{CANARY, canary_paths, strings, strip_index};
use crate::record::RunRecord;
use crate::wit::Interface;

/// The version of the label vocabulary (`LABELS.md`) this appfuzz implements.
pub const VOCABULARY: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Label {
    Sql,
    Path,
    Shell,
    Url,
    Html,
    Regex,
    Untrusted,
    Pii,
    Secret,
    /// A result: who the caller is (a user id).
    Identity,
    /// A parameter: names a user; must be the caller.
    #[serde(rename = "user-id")]
    UserId,
    /// A result field: who a record belongs to.
    Owner,
}

impl Label {
    pub fn name(self) -> &'static str {
        match self {
            Label::Sql => "sql",
            Label::Path => "path",
            Label::Shell => "shell",
            Label::Url => "url",
            Label::Html => "html",
            Label::Regex => "regex",
            Label::Untrusted => "untrusted",
            Label::Pii => "pii",
            Label::Secret => "secret",
            Label::Identity => "identity",
            Label::UserId => "user-id",
            Label::Owner => "owner",
        }
    }

    /// A parameter that interprets text: a canary tail must not reach it intact.
    pub fn is_sink(self) -> bool {
        matches!(self, Label::Sql | Label::Path | Label::Shell | Label::Url | Label::Html | Label::Regex)
    }

    fn for_param(self) -> bool {
        self.is_sink() || matches!(self, Label::Pii | Label::Secret | Label::UserId)
    }

    fn for_result(self) -> bool {
        matches!(self, Label::Untrusted | Label::Html | Label::Pii | Label::Secret | Label::Identity | Label::Owner)
    }

    /// Labels on ids, which may be numbers as well as text.
    pub fn is_id(self) -> bool {
        matches!(self, Label::Identity | Label::UserId | Label::Owner)
    }
}

/// `result = "secret"` labels the whole result; `result = { email = "pii" }`
/// labels fields by dot-separated path. Paths walk through lists, options
/// and the `ok` side of results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResultLabels {
    Whole(Label),
    Fields(BTreeMap<String, Label>),
}

impl ResultLabels {
    pub fn paths(&self) -> Vec<(String, Label)> {
        match self {
            ResultLabels::Whole(l) => vec![(String::new(), *l)],
            ResultLabels::Fields(m) => m.iter().map(|(p, l)| (p.clone(), *l)).collect(),
        }
    }
}

/// Checks that labels sit where they make sense (sinks on parameters,
/// `untrusted` on results).
pub fn check_positions(m: &Manifest) -> Result<()> {
    if let Some(v) = &m.app.labels
        && v != VOCABULARY
    {
        bail!("[app] labels = {v:?}: this appfuzz knows the label vocabulary {VOCABULARY:?} (LABELS.md)");
    }
    for (k, f) in &m.functions {
        if f.idempotent && !f.effect.is_some_and(crate::manifest::Effect::changes) {
            bail!("[functions.\"{k}\"] idempotent = true needs effect = \"write\", \"delete\" or \"external\"");
        }
        if let Some(b) = &f.batch_of
            && strip_key(b) == strip_key(k)
        {
            bail!("[functions.\"{k}\"] batch_of names the function itself");
        }
        for (p, l) in &f.params {
            if !l.for_param() {
                bail!(
                    "[functions.\"{k}\"] params.{p} = \"{}\": a parameter label is one of sql, path, shell, url, html, regex, pii, secret, user-id",
                    l.name()
                );
            }
        }
        for (p, l) in f.result.iter().flat_map(ResultLabels::paths) {
            if !l.for_result() {
                let at = if p.is_empty() { "result".to_string() } else { format!("result.{p}") };
                bail!("[functions.\"{k}\"] {at} = \"{}\": a result label is one of untrusted, html, pii, secret, identity, owner", l.name());
            }
        }
    }
    Ok(())
}

/// Checks labels against the component's imports: a labelled parameter
/// exists and holds text, a labelled result path exists. Functions the app
/// does not import are skipped (a platform labels all of its functions).
pub fn check_wit(m: &Manifest, imports: &[Interface]) -> Result<()> {
    for (k, spec) in &m.functions {
        if spec.params.is_empty() && spec.result.is_none() && spec.values.is_empty() && spec.rules.is_empty() {
            continue;
        }
        let Some(f) = imports.iter().flat_map(|i| &i.funcs).find(|f| f.key == strip_key(k)) else { continue };
        for (p, l) in &spec.params {
            match f.ty.params().find(|(n, _)| n == p) {
                None => bail!("[functions.\"{k}\"] labels the parameter {p}, but {} has no such parameter", f.signature()),
                Some((_, t)) if !l.is_id() && !crate::fuzz::has_string(&t) => {
                    bail!("[functions.\"{k}\"] labels the parameter {p}, which holds no text")
                }
                _ => {}
            }
        }
        for (p, l) in spec.result.iter().flat_map(ResultLabels::paths) {
            let Some(t) = f.ty.results().next() else { bail!("[functions.\"{k}\"] labels a result, but {} returns nothing", f.signature()) };
            if !path_ok(&t, &segs(&p), l.is_id()) {
                bail!(
                    "[functions.\"{k}\"] labels the result path {p:?}, which {} does not have (or it holds no {})",
                    f.signature(),
                    if l.is_id() { "id" } else { "text" }
                );
            }
        }
        for (i, r) in spec.rules.iter().enumerate() {
            crate::plan::check_rule(r).with_context(|| format!("[functions.\"{k}\"] rule {i}"))?;
            if !r.response.decides() {
                bail!("[functions.\"{k}\"] rule {i} needs a `return`, `generate` or `trap`");
            }
            for p in r.when.keys() {
                let named = f.ty.params().any(|(n, _)| n == p || n.replace('-', "_") == *p);
                let indexed = p.parse::<usize>().is_ok_and(|n| n < f.ty.params().count());
                if !named && !indexed {
                    bail!("[functions.\"{k}\"] rule {i} matches the parameter {p}, but {} has no such parameter", f.signature());
                }
            }
        }
        for p in spec.values.keys() {
            let Some(t) = f.ty.results().next() else { bail!("[functions.\"{k}\"] constrains a result, but {} returns nothing", f.signature()) };
            if !path_exists(&t, &segs(p)) {
                bail!("[functions.\"{k}\"] constrains the result path {p:?}, which {} does not have", f.signature());
            }
        }
    }
    Ok(())
}

fn strip_key(k: &str) -> String {
    let (i, f) = k.split_once('#').unwrap_or(("", k));
    crate::manifest::fn_key(i, f)
}

fn segs(p: &str) -> Vec<&str> {
    p.split('.').filter(|s| !s.is_empty()).collect()
}

fn path_ok(ty: &Type, segs: &[&str], id: bool) -> bool {
    match ty {
        Type::List(l) => path_ok(&l.ty(), segs, id),
        Type::Option(o) => path_ok(&o.ty(), segs, id),
        Type::Result(r) => r.ok().is_some_and(|t| path_ok(&t, segs, id)),
        _ if segs.is_empty() && id => is_scalar_id(ty),
        _ if segs.is_empty() => crate::fuzz::has_string(ty),
        Type::Record(r) => r.fields().find(|f| f.name == segs[0]).is_some_and(|f| path_ok(&f.ty, &segs[1..], id)),
        _ => false,
    }
}

fn path_exists(ty: &Type, segs: &[&str]) -> bool {
    match ty {
        _ if segs.is_empty() => true,
        Type::List(l) => path_exists(&l.ty(), segs),
        Type::Option(o) => path_exists(&o.ty(), segs),
        Type::Result(r) => r.ok().is_some_and(|t| path_exists(&t, segs)),
        Type::Record(r) => r.fields().find(|f| f.name == segs[0]).is_some_and(|f| path_exists(&f.ty, &segs[1..])),
        _ => false,
    }
}

fn is_scalar_id(ty: &Type) -> bool {
    matches!(ty, Type::String | Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::S8 | Type::S16 | Type::S32 | Type::S64)
}

/// The strings at a result path, in WIT-shaped JSON.
pub fn values_at(v: &Value, path: &str) -> Vec<String> {
    let mut out = Vec::new();
    walk(v, &segs(path), &mut |s| out.push(s.clone()));
    out
}

fn walk(v: &Value, segs: &[&str], f: &mut dyn FnMut(&mut String)) {
    let mut v = v.clone();
    walk_mut(&mut v, segs, f);
}

fn walk_mut(v: &mut Value, segs: &[&str], f: &mut dyn FnMut(&mut String)) {
    walk_leaves_mut(v, segs, &mut |x| {
        if let Value::String(s) = x {
            f(s)
        }
    })
}

/// Calls `f` on every scalar at the path (strings, numbers, booleans).
pub fn walk_leaves_mut(v: &mut Value, segs: &[&str], f: &mut dyn FnMut(&mut Value)) {
    match v {
        Value::Array(a) => a.iter_mut().for_each(|x| walk_leaves_mut(x, segs, f)),
        Value::Object(o) if o.len() == 1 && o.contains_key("ok") && segs.first() != Some(&"ok") => {
            walk_leaves_mut(o.get_mut("ok").expect("checked"), segs, f)
        }
        Value::Object(o) if o.len() == 1 && o.contains_key("err") && segs.first() != Some(&"err") => {}
        Value::Object(o) if segs.is_empty() => o.values_mut().for_each(|x| walk_leaves_mut(x, segs, f)),
        Value::Object(o) => {
            if let Some(x) = o.get_mut(segs[0]) {
                walk_leaves_mut(x, &segs[1..], f)
            }
        }
        Value::Null => {}
        x if segs.is_empty() => f(x),
        _ => {}
    }
}

/// The scalars at a result path, as text (`7` and `"7"` are the same id).
pub fn ids_at(v: &Value, path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut v = v.clone();
    walk_leaves_mut(&mut v, &segs(path), &mut |x| out.push(id_text(x)));
    out
}

/// A scalar as text: strings without quotes.
pub fn id_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        x => x.to_string(),
    }
}

/// Replaces generated strings at `pii` and `secret` result paths with
/// traceable values (`p1a2b3c4d@mail.example`, `sk_…`), and ids at
/// `identity` and `owner` paths with the run's caller (`identity`) or,
/// for about half the owners, someone else (`identity + 1`).
pub fn mark(v: &mut Value, labels: &[(String, Label)], seed: u64, identity: &str) {
    let mut n = 0u64;
    let other = identity.parse::<u64>().map(|k| (k + 1).to_string()).unwrap_or_else(|_| format!("{identity}x"));
    for (p, l) in labels.iter().filter(|(_, l)| l.is_id()) {
        walk_leaves_mut(v, &segs(p), &mut |x| {
            n += 1;
            let mine = *l == Label::Identity || (seed.wrapping_add(n).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 63) == 0;
            let id = if mine { identity } else { other.as_str() };
            *x = match x {
                Value::Number(_) => id.parse::<u64>().map(Value::from).unwrap_or(Value::from(0)),
                _ => Value::String(id.to_string()),
            };
        });
    }
    for (p, l) in labels {
        let mut f = |s: &mut String| {
            n += 1;
            let h = seed.wrapping_add(n).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            match l {
                Label::Pii => *s = format!("p{:08x}@mail.example", h >> 32),
                Label::Secret => *s = format!("sk_{h:016x}"),
                _ => {}
            }
        };
        walk_mut(v, &segs(p), &mut f);
    }
}

/// A traced value: personal data or a secret a host function returned.
struct Traced {
    value: String,
    label: Label,
    func: String,
    path: String,
}

/// Canaries in strings an `html` result label marks as trusted markup.
pub fn trusted_html(r: &RunRecord, m: &Manifest) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        for (p, l) in m.result_labels(&e.func) {
            if l == Label::Html {
                for s in values_at(v, &p) {
                    out.extend(CANARY.find_iter(&s).map(|c| c.as_str().to_string()));
                }
            }
        }
    }
    out
}

/// Sink and leak findings of one run.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let labelled = m.functions.values().any(|f| !f.params.is_empty() || f.result.is_some());
    if !labelled {
        return Vec::new();
    }
    let mut out = sinks(r, m);
    out.extend(leaks(r, m));
    let mut seen = BTreeSet::new();
    out.retain(|f| seen.insert(f.id.clone()));
    out
}

/// Where a canary came from.
fn sources(r: &RunRecord) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut req = BTreeSet::new();
    for (i, a) in r.spec.args.iter().enumerate() {
        canary_paths(a, format!("@{i}"), &mut req);
    }
    for (c, p) in req {
        out.insert(c, format!("the request field {}", strip_index(&p)));
    }
    for e in &r.events {
        if let Some(v) = &e.result {
            let mut s = BTreeSet::new();
            strings(v, &mut s);
            for t in s {
                for c in CANARY.find_iter(&t) {
                    out.entry(c.as_str().to_string()).or_insert_with(|| format!("a string {} returned", e.func));
                }
            }
        }
    }
    out
}

/// What follows a canary in a sink argument, up to the end of its tail.
fn tail(s: &str, end: usize) -> &str {
    let rest = &s[end..];
    let limit = rest.char_indices().nth(60).map(|(i, _)| i).unwrap_or(rest.len());
    let window = &rest[..limit];
    let window = CANARY.find(window).map(|c| &window[..c.start()]).unwrap_or(window);
    match window.find("x)") {
        Some(i) => &window[..i + 2],
        None => &window[..window.char_indices().nth(20).map(|(i, _)| i).unwrap_or(window.len())],
    }
}

fn unescaped(t: &str, pat: &str) -> bool {
    t.match_indices(pat).any(|(i, _)| !t[..i].ends_with('\\'))
}

/// The finding a canary at `start..end` of `s` makes in a parameter with
/// this label: (kind, severity, what is intact).
fn sink_problem(label: Label, s: &str, start: usize, end: usize) -> Option<(&'static str, Severity, &'static str)> {
    let t = tail(s, end);
    match label {
        Label::Sql if t.contains("''") || t.contains("\\'") => Some(("escaped_by_hand", Severity::Warn, "quotes escaped by hand")),
        Label::Sql if t.contains('\'') => Some(("sql_injection", Severity::Fail, "a quote")),
        Label::Path if t.contains("../") => Some(("path_traversal", Severity::Fail, "../")),
        Label::Shell if t.contains("'\\''") => Some(("escaped_by_hand", Severity::Warn, "quotes escaped by hand")),
        Label::Shell if unescaped(t, ";") || unescaped(t, "$(") => Some(("command_injection", Severity::Fail, "; and $(")),
        Label::Html if t.starts_with("<i>") => Some(("html_injection", Severity::Fail, "markup")),
        Label::Regex if unescaped(t, "(") => Some(("regex_injection", Severity::Warn, "(")),
        Label::Url => {
            let host = match s.find("://") {
                None => start == 0,
                Some(i) if start < i + 3 => true,
                Some(i) => {
                    let auth_end = s[i + 3..].find(['/', '?', '#']).map(|j| i + 3 + j).unwrap_or(s.len());
                    start < auth_end
                }
            };
            host.then_some(("ssrf", Severity::Fail, "the scheme or host"))
        }
        _ => None,
    }
}

fn sinks(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let src = sources(r);
    if src.is_empty() {
        return out;
    }
    let trusted = trusted_html(r, m);
    for e in &r.events {
        for (p, v) in &e.args {
            let Some(label) = m.param_label(&e.func, p).filter(|l| l.is_sink()) else { continue };
            let mut texts = BTreeSet::new();
            strings(v, &mut texts);
            for s in texts {
                for c in CANARY.find_iter(&s) {
                    let Some(from) = src.get(c.as_str()) else { continue };
                    if label == Label::Html && trusted.contains(c.as_str()) {
                        continue;
                    }
                    let Some((kind, sev, intact)) = sink_problem(label, &s, c.start(), c.end()) else { continue };
                    let noun = match label {
                        Label::Sql => "SQL text",
                        Label::Path => "file path",
                        Label::Shell => "shell command",
                        Label::Url => "URL",
                        Label::Html => "HTML",
                        _ => "regular expression",
                    };
                    let title = if kind == "escaped_by_hand" {
                        format!("{from} goes into the {noun} of {} (parameter {p}) with {intact}; pass it as a parameter or use a library", e.func)
                    } else {
                        format!("{from} goes into the {noun} of {} (parameter {p}) with {intact} intact", e.func)
                    };
                    out.push(Finding::new(
                        kind,
                        &format!("{ex}\0{}\0{p}\0{from}", e.func),
                        sev,
                        title,
                        json!({"func": e.func, "param": p, "label": label.name(), "source": from, "n": e.n, "canary": c.as_str(), "arg": s}),
                        run,
                    ));
                }
            }
        }
    }
    out
}

static URL_ATTR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(?:href|src|action|formaction)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))"#).unwrap());

fn leaks(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut traced = Vec::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        for (p, l) in m.result_labels(&e.func) {
            if matches!(l, Label::Pii | Label::Secret) {
                for s in values_at(v, &p) {
                    if s.chars().count() >= 4 && !traced.iter().any(|t: &Traced| t.value == s) {
                        traced.push(Traced { value: s, label: l, func: e.func.clone(), path: p.clone() });
                    }
                }
            }
        }
    }
    if traced.is_empty() {
        return Vec::new();
    }
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let resp = crate::output::response(r, m);
    let body = resp.body.as_deref().unwrap_or_default();
    let error_page = resp.status.is_some_and(|s| s >= 400);
    let urls: Vec<&str> = URL_ATTR
        .captures_iter(body)
        .filter_map(|c| c.get(1).or(c.get(2)).or(c.get(3)).map(|x| x.as_str()))
        .collect();
    let mut out = Vec::new();
    for t in &traced {
        let what = if t.path.is_empty() { format!("{} returned", t.func) } else { format!("{} returned in {}", t.func, t.path) };
        let (kind, noun) = match t.label {
            Label::Secret => ("secret_leak", "the secret"),
            _ => ("pii_leak", "the personal data"),
        };
        let mut push = |place: String, sev: Severity, extra: Value| {
            let mut d = json!({"func": t.func, "path": t.path, "label": t.label.name(), "value": t.value, "place": place});
            if let (Value::Object(d), Value::Object(x)) = (&mut d, extra) {
                d.extend(x);
            }
            out.push(Finding::new(kind, &format!("{ex}\0{}\0{}\0{place}", t.func, t.path), sev, format!("{noun} {what} ends up in {place}"), d, run));
        };
        let v = t.value.as_str();
        for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
            if text.contains(v) {
                push(format!("the log ({name})"), Severity::Fail, json!({}));
            }
        }
        for e in &r.events {
            for (p, a) in &e.args {
                if m.param_label(&e.func, p) == Some(t.label) {
                    continue;
                }
                let mut texts = BTreeSet::new();
                strings(a, &mut texts);
                if texts.iter().any(|s| s.contains(v)) {
                    push(format!("the parameter {p} of {}", e.func), Severity::Fail, json!({"n": e.n}));
                }
            }
        }
        for (h, hv) in &resp.headers {
            if hv.contains(v) {
                let sev = if t.label == Label::Secret { Severity::Fail } else { Severity::Warn };
                push(format!("the response header {h}"), sev, json!({}));
            }
        }
        if body.contains(v) {
            if t.label == Label::Secret {
                push("the response body".into(), Severity::Fail, json!({}));
            } else if error_page {
                push("an error page".into(), Severity::Fail, json!({"status": resp.status}));
            } else if urls.iter().any(|u| u.contains(v)) {
                push("a URL in the page".into(), Severity::Warn, json!({}));
            }
        }
    }
    out
}

/// Labels guessed for one host function.
#[derive(Debug, Clone, Default)]
pub struct Suggestion {
    pub params: BTreeMap<String, Label>,
    pub results: BTreeMap<String, Label>,
    pub effect: Option<crate::manifest::Effect>,
}

impl Suggestion {
    fn is_empty(&self) -> bool {
        self.params.is_empty() && self.results.is_empty() && self.effect.is_none()
    }

    /// Drops what the manifest already says about the function.
    pub fn without(mut self, f: Option<&crate::manifest::FunctionSpec>) -> Option<Self> {
        if let Some(f) = f {
            if !f.params.is_empty() || f.result.is_some() {
                self.params.clear();
                self.results.clear();
            }
            if f.effect.is_some() {
                self.effect = None;
            }
        }
        (!self.is_empty()).then_some(self)
    }
}

/// Suggested labels per function.
pub type Suggestions = BTreeMap<String, Suggestion>;

/// Labels a WIT name suggests, as a guess for `inspect`.
pub fn suggest(imports: &[Interface]) -> Suggestions {
    let mut out = BTreeMap::new();
    for f in imports.iter().filter(|i| i.kind == crate::wit::ImportKind::Platform).flat_map(|i| &i.funcs) {
        let mut params = BTreeMap::new();
        for (n, t) in f.ty.params() {
            if crate::fuzz::has_string(&t)
                && let Some(l) = param_guess(n)
            {
                params.insert(n.to_string(), l);
            }
        }
        let mut results = BTreeMap::new();
        if let Some(t) = f.ty.results().next() {
            if crate::fuzz::has_string(&t) && matches!(name_guess(&f.name), Some(Label::Secret)) && !is_record_like(&t) {
                results.insert(String::new(), Label::Secret);
            }
            fields_guess(&t, String::new(), &mut results);
        }
        let s = Suggestion { params, results, effect: effect_guess(&f.name) };
        if !s.is_empty() {
            out.insert(f.key.clone(), s);
        }
    }
    out
}

fn is_record_like(t: &Type) -> bool {
    match t {
        Type::Record(_) => true,
        Type::List(l) => is_record_like(&l.ty()),
        Type::Option(o) => is_record_like(&o.ty()),
        Type::Result(r) => r.ok().is_some_and(|t| is_record_like(&t)),
        _ => false,
    }
}

fn fields_guess(t: &Type, path: String, out: &mut BTreeMap<String, Label>) {
    match t {
        Type::List(l) => fields_guess(&l.ty(), path, out),
        Type::Option(o) => fields_guess(&o.ty(), path, out),
        Type::Result(r) => {
            if let Some(t) = r.ok() {
                fields_guess(&t, path, out)
            }
        }
        Type::Record(r) => {
            for f in r.fields() {
                let p = if path.is_empty() { f.name.to_string() } else { format!("{path}.{}", f.name) };
                if crate::fuzz::has_string(&f.ty)
                    && let Some(l) = name_guess(f.name)
                {
                    out.insert(p, l);
                } else {
                    fields_guess(&f.ty, p, out);
                }
            }
        }
        _ => {}
    }
}

/// The effect a function name suggests: the first word is the verb.
fn effect_guess(n: &str) -> Option<crate::manifest::Effect> {
    use crate::manifest::Effect;
    let w = words(n);
    let verb = w.first()?.as_str();
    match verb {
        "get" | "list" | "all" | "load" | "find" | "read" | "fetch" | "search" | "count" | "current" | "lookup" | "show" => Some(Effect::Read),
        "save" | "create" | "insert" | "update" | "put" | "set" | "write" | "store" | "add" | "upsert" | "book" | "cancel" | "edit" => Some(Effect::Write),
        "delete" | "remove" | "drop" | "purge" | "clear" | "erase" => Some(Effect::Delete),
        "send" | "post" | "notify" | "charge" | "pay" | "publish" | "email" | "sms" | "refund" | "enqueue" => Some(Effect::External),
        _ => None,
    }
}

fn words(n: &str) -> Vec<String> {
    n.to_ascii_lowercase().split(['-', '_']).map(str::to_string).collect()
}

fn param_guess(n: &str) -> Option<Label> {
    let w = words(n);
    let has = |xs: &[&str]| w.iter().any(|x| xs.contains(&x.as_str()));
    if has(&["sql", "statement", "stmt"]) {
        Some(Label::Sql)
    } else if has(&["cmd", "command", "shell"]) {
        Some(Label::Shell)
    } else if has(&["url", "uri", "endpoint", "href"]) {
        Some(Label::Url)
    } else if has(&["path", "file", "filename", "dir"]) {
        Some(Label::Path)
    } else if has(&["html", "markup"]) {
        Some(Label::Html)
    } else if has(&["regex", "pattern"]) {
        Some(Label::Regex)
    } else {
        name_guess(n)
    }
}

fn name_guess(n: &str) -> Option<Label> {
    let w = words(n);
    let has = |xs: &[&str]| w.iter().any(|x| xs.contains(&x.as_str()));
    if has(&["secret", "token", "password", "passwd", "apikey", "auth", "credential", "credentials"]) || n.contains("api-key") {
        Some(Label::Secret)
    } else if has(&["email", "phone", "address", "birthday", "ssn", "iban"]) {
        Some(Label::Pii)
    } else if has(&["html"]) {
        Some(Label::Html)
    } else {
        None
    }
}

/// The suggestions as a TOML snippet.
pub fn suggest_toml(s: &Suggestions) -> String {
    let mut t = String::new();
    for (k, Suggestion { params, results, effect }) in s {
        if !t.is_empty() {
            t.push('\n');
        }
        t.push_str(&format!("[functions.\"{k}\"]\n"));
        if let Some(e) = effect {
            t.push_str(&format!("effect = \"{}\"\n", e.name()));
        }
        if !params.is_empty() {
            let ps: Vec<String> = params.iter().map(|(p, l)| format!("{} = \"{}\"", toml_key(p), l.name())).collect();
            t.push_str(&format!("params = {{ {} }}\n", ps.join(", ")));
        }
        if let Some(l) = results.get("") {
            t.push_str(&format!("result = \"{}\"\n", l.name()));
        } else if !results.is_empty() {
            let rs: Vec<String> = results.iter().map(|(p, l)| format!("{} = \"{}\"", toml_key(p), l.name())).collect();
            t.push_str(&format!("result = {{ {} }}\n", rs.join(", ")));
        }
    }
    t
}

fn toml_key(k: &str) -> String {
    if k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') { k.to_string() } else { format!("\"{k}\"") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_results() {
        let v = json!({"ok": [{"name": "a", "email": "x@y.z"}, {"name": "b", "email": "q@r.s"}]});
        assert_eq!(values_at(&v, "email"), vec!["x@y.z", "q@r.s"]);
        assert!(values_at(&json!({"err": "nope"}), "").is_empty());
        let mut v = json!({"ok": {"token": "abc", "user": {"email": "e"}}});
        mark(&mut v, &[("token".into(), Label::Secret), ("user.email".into(), Label::Pii)], 1, "1000");
        assert!(v["ok"]["token"].as_str().unwrap().starts_with("sk_"));
        assert!(v["ok"]["user"]["email"].as_str().unwrap().ends_with("@mail.example"));
    }

    #[test]
    fn sink_tails() {
        let c = "cnry12ab7";
        let sql = format!("SELECT * FROM t WHERE n = '{c}<i>'\"../;$(x)' AND x = 'y'");
        let s = sql.find(c).unwrap();
        assert_eq!(sink_problem(Label::Sql, &sql, s, s + c.len()).unwrap().0, "sql_injection");
        let esc = format!("n = '{c}<i>''\"../;$(x)'");
        let s = esc.find(c).unwrap();
        assert_eq!(sink_problem(Label::Sql, &esc, s, s + c.len()).unwrap().0, "escaped_by_hand");
        let url = format!("https://api.example/items?q={c}<i>'\"../;$(x)");
        let s = url.find(c).unwrap();
        assert!(sink_problem(Label::Url, &url, s, s + c.len()).is_none());
        let url = format!("https://{c}<i>'\"../;$(x)/items");
        let s = url.find(c).unwrap();
        assert_eq!(sink_problem(Label::Url, &url, s, s + c.len()).unwrap().0, "ssrf");
        let sh = format!("grep '{c}<i>'\\''\"../;$(x)' f");
        let s = sh.find(c).unwrap();
        assert_eq!(sink_problem(Label::Shell, &sh, s, s + c.len()).unwrap().0, "escaped_by_hand");
        let re = format!("{c}<i>'\"\\.\\./;\\$\\(x\\)");
        assert!(sink_problem(Label::Regex, &re, 0, c.len()).is_none());
    }

    #[test]
    fn guesses() {
        assert_eq!(param_guess("sql"), Some(Label::Sql));
        assert_eq!(param_guess("api-key"), Some(Label::Secret));
        assert_eq!(name_guess("bio-html"), Some(Label::Html));
        assert_eq!(name_guess("name"), None);
        assert_eq!(effect_guess("save"), Some(crate::manifest::Effect::Write));
        assert_eq!(effect_guess("list-for-day"), Some(crate::manifest::Effect::Read));
        assert_eq!(effect_guess("send"), Some(crate::manifest::Effect::External));
        assert_eq!(effect_guess("frobnicate"), None);
    }
}
