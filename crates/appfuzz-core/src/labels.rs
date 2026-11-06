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

use aho_corasick::{AhoCorasick, AhoCorasickKind};
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::output::{CANARY, canary_paths, strings};
use crate::record::RunRecord;
use crate::wit::Interface;

/// The version of the label vocabulary (`LABELS.md`) this appfuzz implements.
pub const VOCABULARY: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
        for (p, l) in f.result.iter().chain(f.rules.iter().filter_map(|r| r.result.as_ref())).flat_map(ResultLabels::paths) {
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
        for (p, l) in spec.result.iter().chain(spec.rules.iter().filter_map(|r| r.result.as_ref())).flat_map(ResultLabels::paths) {
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
            if !r.response.decides() && r.result.is_none() {
                bail!("[functions.\"{k}\"] rule {i} needs a `return`, `generate`, `trap` or `result` labels");
            }
            if let Some(p) = r.when.keys().find(|p| !names_param(f, p)) {
                bail!("[functions.\"{k}\"] rule {i} matches the parameter {p}, but {} has no such parameter", f.signature());
            }
        }
        for (p, constraint) in &spec.values {
            let Some(t) = f.ty.results().next() else { bail!("[functions.\"{k}\"] constrains a result, but {} returns nothing", f.signature()) };
            if !path_exists(&t, &segs(p)) {
                bail!("[functions.\"{k}\"] constrains the result path {p:?}, which {} does not have", f.signature());
            }
            crate::constraints::validate_type(&t, p, constraint).with_context(|| format!("[functions.\"{k}\"] values {p:?}"))?;
        }
    }
    Ok(())
}

/// Whether a rule's `when` key names a parameter of `f`: by name (`user-id`
/// or `user_id`) or by position.
pub(crate) fn names_param(f: &crate::wit::FuncInfo, p: &str) -> bool {
    f.ty.params().any(|(n, _)| n == p || n.replace('-', "_") == p) || p.parse::<usize>().is_ok_and(|n| n < f.ty.params().count())
}

/// Refuses a `[functions]` key that is a misspelling of a function the app
/// imports: its labels, rules and effects would apply to nothing. `keys`
/// are the keys as written, before built-in labels are added.
pub fn check_names(keys: &[String], imports: &[Interface]) -> Result<()> {
    match misspelling(keys, imports) {
        Some((k, real)) => bail!("[functions.\"{k}\"] names no function the app imports: did you mean {real}?"),
        None => Ok(()),
    }
}

/// The first key that names no import but is a misspelling of one that no
/// key names, with that import. A key near no import is fine: a platform
/// (or a plan for its apps) describes all of its functions, and an app
/// imports only those it calls.
pub(crate) fn misspelling(keys: &[String], imports: &[Interface]) -> Option<(String, String)> {
    let funcs: Vec<&str> = imports.iter().flat_map(|i| &i.funcs).map(|f| f.key.as_str()).collect();
    let written: Vec<String> = keys.iter().map(|k| strip_key(k)).collect();
    keys.iter().zip(&written).filter(|(_, w)| !funcs.contains(&w.as_str())).find_map(|(k, w)| {
        let real = funcs.iter().find(|f| !written.iter().any(|x| x == *f) && misspelt(w, f))?;
        Some((k.clone(), (*real).to_string()))
    })
}

/// Whether `written` is the key `real` written wrongly: in other case, with
/// `_` for `-`, without its package or in another one, or one edit off in
/// an interface or in a function name of five or more letters (`get` and
/// `set` are both real names).
fn misspelt(written: &str, real: &str) -> bool {
    let norm = |s: &str| s.to_lowercase().replace('_', "-");
    let (w, r) = (norm(written), norm(real));
    let (wi, wf) = w.split_once('#').unwrap_or(("", &w));
    let (ri, rf) = r.split_once('#').unwrap_or(("", &r));
    let base = |i: &'_ str| i.rsplit(['/', ':']).next().unwrap_or_default().to_string();
    let close = |a: &str, b: &str| b.chars().count() >= 5 && crate::assertion::distance(a, b) <= 1;
    if wf == rf { wi.is_empty() || base(wi) == base(ri) || close(wi, ri) } else { wi == ri && close(wf, rf) }
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
        Type::FixedLengthList(l) => path_exists(&l.ty(), segs),
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
        Value::Object(o) if o.len() == 1 && o.contains_key("ok") && segs.first() != Some(&"ok") => walk_leaves_mut(o.get_mut("ok").expect("checked"), segs, f),
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
#[derive(Clone)]
pub(crate) struct Traced {
    pub value: String,
    pub label: Label,
    pub func: String,
    pub path: String,
    /// Browser-owned credentials may return to that browser. Logs and
    /// undeclared host parameters still cannot receive them.
    pub response_owner: Option<String>,
}

/// Canaries in strings an `html` result label marks as trusted markup.
pub fn trusted_html(r: &RunRecord, m: &Manifest) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        for (p, l) in m.call_result_labels(&e.func, &e.args) {
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

/// Where a canary came from: as the title says it, and as the finding's
/// key has it (by field, so one finding per field and sink).
fn sources(r: &RunRecord, m: &Manifest) -> BTreeMap<String, (String, String)> {
    let mut out = BTreeMap::new();
    let mut req = BTreeSet::new();
    for (i, a) in r.spec.args.iter().enumerate() {
        canary_paths(a, format!("@{i}"), &mut req);
    }
    for (c, p) in req {
        let place = crate::output::request_place(m, &r.spec.args, &p, &c);
        out.insert(c, (place, format!("the request field {}", crate::output::strip_index(&p))));
    }
    for e in &r.events {
        if let Some(v) = &e.result {
            let mut s = BTreeSet::new();
            strings(v, &mut s);
            for t in s {
                for c in CANARY.find_iter(&t) {
                    out.entry(c.as_str().to_string()).or_insert_with(|| {
                        let from = format!("a string {} returned", e.func);
                        (from.clone(), from)
                    });
                }
            }
        }
    }
    out
}

/// What follows a canary in a sink argument, up to the end of its tail.
pub(crate) fn tail(s: &str, end: usize) -> &str {
    let rest = &s[end..];
    let limit = rest.char_indices().nth(60).map(|(i, _)| i).unwrap_or(rest.len());
    let window = &rest[..limit];
    let window = CANARY.find(window).map(|c| &window[..c.start()]).unwrap_or(window);
    match window.find("x)") {
        Some(i) => &window[..i + 2],
        None => &window[..window.char_indices().nth(20).map(|(i, _)| i).unwrap_or(window.len())],
    }
}

/// What follows each canary where the request or a host gave it, as sent
/// and percent-decoded: the characters it can bring into a sink. A canary
/// cut short brings none, whatever the app writes after it.
fn source_tails(r: &RunRecord) -> BTreeMap<String, String> {
    let mut texts = BTreeSet::new();
    for a in &r.spec.args {
        strings(a, &mut texts);
    }
    for e in &r.events {
        if let Some(v) = &e.result {
            strings(v, &mut texts);
        }
    }
    tails_in(texts.iter().map(String::as_str))
}

pub(crate) fn tails_in<'a>(texts: impl Iterator<Item = &'a str>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for s in texts {
        for c in CANARY.find_iter(s) {
            let rest = &s[c.end()..];
            let rest = &rest[..rest.char_indices().nth(200).map(|(i, _)| i).unwrap_or(rest.len())];
            let t = out.entry(c.as_str().to_string()).or_default();
            t.push_str(tail(s, c.end()));
            t.push('\n');
            t.push_str(tail(&crate::effects::percent_decode(rest), 0));
            t.push('\n');
        }
    }
    out
}

pub(crate) fn unescaped(t: &str, pat: &str) -> bool {
    t.match_indices(pat).any(|(i, _)| !t[..i].ends_with('\\'))
}

/// The finding a canary at `start..end` of `s` makes in a parameter with
/// this label: (kind, severity, what is intact). `sent` is what followed
/// the canary where it came from ([`source_tails`]): a quote after it in
/// the sink counts only if the request or host sent one.
pub(crate) fn sink_problem(label: Label, s: &str, start: usize, end: usize, sent: &str) -> Option<(&'static str, Severity, &'static str)> {
    let t = tail(s, end);
    let quote = sent.contains('\'');
    match label {
        Label::Sql if quote && (t.contains("''") || t.contains("\\'")) => Some(("escaped_by_hand", Severity::Warn, "quotes escaped by hand")),
        Label::Sql if quote && t.contains('\'') => Some(("sql_injection", Severity::Fail, "a quote")),
        Label::Path if sent.contains("../") && t.contains("../") => Some(("path_traversal", Severity::Fail, "../")),
        Label::Shell if quote && t.contains("'\\''") => Some(("escaped_by_hand", Severity::Warn, "quotes escaped by hand")),
        Label::Shell if (sent.contains(';') && unescaped(t, ";")) || (sent.contains("$(") && unescaped(t, "$(")) => {
            Some(("command_injection", Severity::Fail, "; and $("))
        }
        Label::Html if sent.contains("<i>") && t.starts_with("<i>") => Some(("html_injection", Severity::Fail, "markup")),
        Label::Regex if sent.contains('(') && unescaped(t, "(") => Some(("regex_injection", Severity::Warn, "(")),
        Label::Url => {
            let auth_end = match s.find("://") {
                None => 0,
                Some(i) => s[i + 3..].find(['/', '?', '#']).map(|j| i + 3 + j).unwrap_or(s.len()),
            };
            let host = match s.find("://") {
                None => start == 0,
                Some(i) => start < i + 3 || start < auth_end,
            };
            // In the path, an intact `../` reaches other endpoints of the
            // same API: `/items/../admin` is `/admin`.
            let path_end = s[auth_end..].find(['?', '#']).map_or(s.len(), |j| auth_end + j);
            if host {
                Some(("ssrf", Severity::Fail, "the scheme or host"))
            } else if start < path_end && sent.contains("../") && t.contains("../") {
                Some(("url_path_injection", Severity::Fail, "../"))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn sinks(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let src = sources(r, m);
    if src.is_empty() {
        return out;
    }
    let tails = source_tails(r);
    let trusted = trusted_html(r, m);
    for e in &r.events {
        for (p, v) in e.text_args().iter() {
            let Some(label) = m.param_label(&e.func, p).filter(|l| l.is_sink()) else { continue };
            let mut texts = BTreeSet::new();
            strings(v, &mut texts);
            for s in texts {
                for c in CANARY.find_iter(&s) {
                    let Some((from, from_key)) = src.get(c.as_str()) else { continue };
                    if label == Label::Html && trusted.contains(c.as_str()) {
                        continue;
                    }
                    let sent = tails.get(c.as_str()).map_or("", String::as_str);
                    let Some((kind, mut sev, intact)) = sink_problem(label, &s, c.start(), c.end(), sent) else { continue };
                    // The platform refused the request (Spin's
                    // allowed_outbound_hosts): only the allowed hosts are
                    // within reach, and none when nothing is allowed.
                    let denied = kind == "ssrf" && e.result.as_ref().and_then(|v| v.get("err")).and_then(Value::as_str) == Some("http-request-denied");
                    if denied {
                        if m.grants.hosts.as_ref().is_none_or(Vec::is_empty) {
                            continue;
                        }
                        sev = Severity::Warn;
                    }
                    let noun = match label {
                        Label::Sql => "SQL text",
                        Label::Path => "file path",
                        Label::Shell => "shell command",
                        Label::Url => "URL",
                        Label::Html => "HTML",
                        _ => "regular expression",
                    };
                    let noun = if kind == "url_path_injection" { "URL path" } else { noun };
                    let title = if kind == "url_path_injection" {
                        format!(
                            "{from} goes into the {noun} of {} (parameter {p}) with ../ intact: it reaches other endpoints of that API; percent-encode it",
                            e.func
                        )
                    } else if denied {
                        format!(
                            "{from} decides the host of the URL of {} (parameter {p}); the platform refused this request, but the client can still send it to any allowed host ({}) with a path of its choice: build the URL from a fixed host",
                            e.func,
                            m.grants.hosts.iter().flatten().cloned().collect::<Vec<_>>().join(", ")
                        )
                    } else if kind == "escaped_by_hand" {
                        format!("{from} goes into the {noun} of {} (parameter {p}) with {intact}; pass it as a parameter or use a library", e.func)
                    } else {
                        format!("{from} goes into the {noun} of {} (parameter {p}) with {intact} intact", e.func)
                    };
                    out.push(Finding::new(
                        kind,
                        &format!("{ex}\0{}\0{p}\0{from_key}", e.func),
                        sev,
                        title,
                        json!({"func": e.func, "param": p, "label": label.name(), "source": from, "n": e.n, "canary": c.as_str(), "arg": s, "refused": denied}),
                        run,
                    ));
                }
            }
        }
    }
    out
}

static URL_ATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:href|src|action|formaction)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*))"#).unwrap());

pub(crate) fn sensitive(r: &RunRecord, m: &Manifest) -> Vec<Traced> {
    let mut traced: Vec<Traced> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        for (p, l) in m.call_result_labels(&e.func, &e.args) {
            if matches!(l, Label::Pii | Label::Secret) {
                for s in values_at(v, &p) {
                    if s.chars().count() >= 4 && seen.insert((s.clone(), l)) {
                        traced.push(Traced { value: s, label: l, func: e.func.clone(), path: p.clone(), response_owner: None });
                    }
                }
            }
        }
    }
    traced
}

fn leaks(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut traced = sensitive(r, m);
    // A value the request itself carries is an echo, not a leak (`reflection` covers request text).
    let mut req = Vec::new();
    for a in &r.spec.args {
        str_leaves(a, &mut req);
    }
    traced.retain(|t| !req.iter().any(|s| s.contains(t.value.as_str())));
    if traced.is_empty() {
        return Vec::new();
    }
    leaks_from(r, m, &traced)
}

/// Values learned before this request retain their sensitivity even when
/// they arrive in request fields. The ordinary request-echo exemption is
/// only for values without an established private origin.
pub(crate) fn leaks_from(r: &RunRecord, m: &Manifest, traced: &[Traced]) -> Vec<Finding> {
    if traced.is_empty() {
        return Vec::new();
    }
    let find = Finder::new(traced);
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let entry = m.entry.as_ref().filter(|e| crate::harness::fn_key_eq(&e.export, ex));
    let no_pii = entry.is_some_and(|e| e.no_pii);
    let resp = crate::output::response(r, m);
    let body = resp.body.as_deref().unwrap_or_default();
    let error_page = resp.status.is_some_and(|s| s >= 400);

    // One group per source (function, path) and place: a page with the emails of 37 people is one finding.
    let mut first: std::collections::HashMap<(&str, &str, Label), usize> = std::collections::HashMap::new();
    let src: Vec<usize> = (0..traced.len()).map(|i| *first.entry((traced[i].func.as_str(), traced[i].path.as_str(), traced[i].label)).or_insert(i)).collect();
    let mut groups: BTreeMap<(usize, String), Group> = BTreeMap::new();
    let mut add = |i: usize, place: String, sev: Severity, extra: Value| {
        let g = groups.entry((src[i], place)).or_insert_with(|| Group { severity: sev, values: Vec::new(), extra });
        g.severity = g.severity.max(sev);
        g.values.push(i);
    };

    for (name, text) in [("stdout", &r.stdout), ("stderr", &r.stderr)] {
        for i in find.hits(text) {
            add(i, format!("the log ({name})"), Severity::Fail, json!({}));
        }
    }
    if let Some(text) = &r.guest_error {
        for i in find.hits(text) {
            add(i, "the guest error".into(), Severity::Fail, json!({}));
        }
    }
    if let Some(text) = r.rejected_output_text() {
        for i in find.hits(&text) {
            if traced[i].response_owner.is_none() {
                add(i, "the rejected output".into(), Severity::Fail, json!({}));
            }
        }
    }
    for e in &r.events {
        let arguments = e.text_args();
        let mut texts = Vec::new();
        for (p, a) in arguments.iter() {
            texts.clear();
            str_leaves(a, &mut texts);
            let label = m.param_label(&e.func, p);
            for i in find.hits_any(&texts) {
                if label != Some(traced[i].label) {
                    add(i, format!("the parameter {p} of {}", e.func), Severity::Fail, json!({"n": e.n}));
                }
            }
        }
    }
    for (h, hv) in &resp.headers {
        for i in find.hits(hv) {
            if let Some(owner) = &traced[i].response_owner {
                // A response to its owner is allowed; an HTTP redirect
                // carrying the credential to another origin is not.
                let redirects = h.eq_ignore_ascii_case("location") && resp.status.is_some_and(|s| (300..400).contains(&s));
                let leaves = url::Url::parse(owner)
                    .ok()
                    .is_some_and(|owner| owner.join(hv).ok().is_some_and(|to| matches!(to.scheme(), "http" | "https") && to.origin() != owner.origin()));
                if !redirects || !leaves {
                    continue;
                }
            }
            let sev = if traced[i].label == Label::Secret || no_pii { Severity::Fail } else { Severity::Warn };
            add(i, format!("the response header {h}"), sev, json!({}));
        }
    }
    let body_hits = find.hits(body);
    if !body_hits.is_empty() {
        let in_urls: BTreeSet<usize> =
            URL_ATTR.captures_iter(body).filter_map(|c| c.get(1).or(c.get(2)).or(c.get(3)).map(|x| x.as_str())).flat_map(|u| find.hits(u)).collect();
        for i in body_hits {
            if traced[i].response_owner.is_some() {
                continue;
            }
            if traced[i].label == Label::Secret {
                add(i, "the response body".into(), Severity::Fail, json!({}));
            } else if error_page {
                add(i, "an error page".into(), Severity::Fail, json!({"status": resp.status}));
            } else if no_pii {
                add(i, "the response body".into(), Severity::Fail, json!({"no_pii": true}));
            } else if in_urls.contains(&i) {
                add(i, "a URL in the page".into(), Severity::Warn, json!({}));
            }
        }
    }
    // The rest of the result: everything but the mapped body and headers, which are checked above.
    if let Some(result) = &r.result {
        let o = entry.map(|e| &e.output);
        let skip: Vec<&str> = match o.and_then(|o| o.body.as_deref()) {
            Some(b) => std::iter::once(b).chain(o.and_then(|o| o.headers.as_deref())).collect(),
            None if result.is_string() => vec![""],
            None => o.and_then(|o| o.headers.as_deref()).into_iter().collect(),
        };
        let mut path = String::new();
        result_strings(result, &mut path, &skip, &mut |at, s| {
            for i in find.hits(s) {
                if traced[i].response_owner.is_none() && (traced[i].label == Label::Secret || no_pii) {
                    let extra = if no_pii && traced[i].label == Label::Pii { json!({"at": at, "no_pii": true}) } else { json!({"at": at}) };
                    add(i, "the result".into(), Severity::Fail, extra);
                }
            }
        });
    }

    let mut out = Vec::new();
    for ((src, place), mut g) in groups {
        g.values.sort_unstable();
        g.values.dedup();
        let t = &traced[src];
        let what = if t.path.is_empty() { format!("{} returned", t.func) } else { format!("{} returned in {}", t.func, t.path) };
        let (kind, noun) = match t.label {
            Label::Secret => ("secret_leak", "the secret"),
            _ => ("pii_leak", "the personal data"),
        };
        let first = &traced[g.values[0]].value;
        let mut d = json!({"func": t.func, "path": t.path, "label": t.label.name(), "value": first, "place": place});
        let title = if g.values.len() > 1 {
            d["count"] = json!(g.values.len());
            d["values"] = json!(g.values.iter().take(5).map(|&i| traced[i].value.as_str()).collect::<Vec<_>>());
            format!("{noun} {what} ends up in {place}: {} different values", g.values.len())
        } else {
            format!("{noun} {what} ends up in {place}")
        };
        if let (Value::Object(d), Value::Object(x)) = (&mut d, g.extra) {
            d.extend(x);
        }
        out.push(Finding::new(kind, &format!("{ex}\0{}\0{}\0{place}", t.func, t.path), g.severity, title, d, run));
    }
    out
}

/// The values of one leak finding: where they come from, how bad.
struct Group {
    severity: Severity,
    /// Indexes into the traced values; sorted and deduplicated before reporting.
    values: Vec<usize>,
    extra: Value,
}

/// Which traced values occur in a text. Starts with `str::contains` per
/// value and switches to one Aho-Corasick pass per text once the searching
/// done so far would have paid for building the automaton: a few values in
/// short texts never build it, a page with a thousand people's emails does.
struct Finder<'a> {
    traced: &'a [Traced],
    ac: std::cell::OnceCell<Option<AhoCorasick>>,
    /// Estimated ns spent on per-value searches so far.
    spent: std::cell::Cell<u64>,
}

impl<'a> Finder<'a> {
    fn new(traced: &'a [Traced]) -> Self {
        Finder { traced, ac: std::cell::OnceCell::new(), spent: std::cell::Cell::new(0) }
    }

    /// Estimated ns to build the automaton (measured: ~12 µs plus ~1.3 µs
    /// per value for a contiguous NFA).
    fn build_cost(&self) -> u64 {
        12_000 + 1_300 * self.traced.len() as u64
    }

    fn automaton(&self) -> Option<&AhoCorasick> {
        // A contiguous NFA: a DFA would scan a little faster but costs about three times as much to build.
        self.ac
            .get_or_init(|| AhoCorasick::builder().kind(Some(AhoCorasickKind::ContiguousNFA)).build(self.traced.iter().map(|t| t.value.as_str())).ok())
            .as_ref()
    }

    /// Indexes of the values in `text`, ascending.
    fn hits(&self, text: &str) -> Vec<usize> {
        if text.len() < 4 {
            return Vec::new();
        }
        let ac = match self.ac.get() {
            Some(ac) => ac.as_ref(),
            None => {
                // `memmem` runs at several bytes per ns; each call has a fixed cost too.
                let naive = self.traced.len() as u64 * (text.len() as u64 / 4 + 20);
                let spent = self.spent.get() + naive;
                self.spent.set(spent);
                if spent > self.build_cost() { self.automaton() } else { None }
            }
        };
        match ac {
            Some(ac) => {
                let mut v: Vec<usize> = ac.find_overlapping_iter(text).map(|m| m.pattern().as_usize()).collect();
                v.sort_unstable();
                v.dedup();
                v
            }
            None => (0..self.traced.len()).filter(|&i| text.contains(self.traced[i].value.as_str())).collect(),
        }
    }

    fn hits_any(&self, texts: &[&str]) -> Vec<usize> {
        let mut v: Vec<usize> = texts.iter().flat_map(|t| self.hits(t)).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// Every string in a JSON value, borrowed.
fn str_leaves<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| str_leaves(x, out)),
        Value::Object(o) => o.values().for_each(|x| str_leaves(x, out)),
        _ => {}
    }
}

/// Every string in the export's result with its path (`ok.items[3].email`),
/// except below the paths in `skip` (`""` skips everything).
fn result_strings(v: &Value, path: &mut String, skip: &[&str], f: &mut dyn FnMut(&str, &str)) {
    if skip.contains(&path.as_str()) {
        return;
    }
    let len = path.len();
    match v {
        Value::String(s) => f(path, s),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                path.push_str(&format!("[{i}]"));
                result_strings(x, path, skip, f);
                path.truncate(len);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(k);
                result_strings(x, path, skip, f);
                path.truncate(len);
            }
        }
        _ => {}
    }
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
    fn misspelt_keys_are_told_from_other_functions() {
        let real = "bench:web/db#query";
        for typo in ["bench:web/db#qeury", "bench:web/db#quer", "Bench:web/db#Query", "db#query", "query", "acme:shop/db#query", "bench:web/dbs#query"] {
            assert!(misspelt(&strip_key(typo), real), "{typo}");
        }
        assert!(misspelt("bench:web/db#get-many", "bench:web/db#get_many"));
        // Short names one letter apart are both real; so are other functions.
        for other in ["bench:web/db#set", "bench:web/db#count", "bench:web/files#read"] {
            assert!(!misspelt(other, if other.ends_with("set") { "bench:web/db#get" } else { real }), "{other}");
        }
        assert!(!misspelt("bench:web/users#current", "bench:web/users#get"));
        assert_eq!(crate::assertion::distance("qeury", "query"), 1);
        assert_eq!(crate::assertion::distance("kitten", "sitting"), 3);
    }

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
        const FULL: &str = "<i>'\"../;$(x)";
        let c = "cnry12ab7";
        let sql = format!("SELECT * FROM t WHERE n = '{c}<i>'\"../;$(x)' AND x = 'y'");
        let s = sql.find(c).unwrap();
        assert_eq!(sink_problem(Label::Sql, &sql, s, s + c.len(), FULL).unwrap().0, "sql_injection");
        let esc = format!("n = '{c}<i>''\"../;$(x)'");
        let s = esc.find(c).unwrap();
        assert_eq!(sink_problem(Label::Sql, &esc, s, s + c.len(), FULL).unwrap().0, "escaped_by_hand");
        let url = format!("https://api.example/items?q={c}<i>'\"../;$(x)");
        let s = url.find(c).unwrap();
        assert!(sink_problem(Label::Url, &url, s, s + c.len(), FULL).is_none());
        let url = format!("https://{c}<i>'\"../;$(x)/items");
        let s = url.find(c).unwrap();
        assert_eq!(sink_problem(Label::Url, &url, s, s + c.len(), FULL).unwrap().0, "ssrf");
        let url = format!("https://api.example/items/{c}<i>'\"../;$(x)?full=1");
        let s = url.find(c).unwrap();
        assert_eq!(sink_problem(Label::Url, &url, s, s + c.len(), FULL).unwrap().0, "url_path_injection");
        let url = format!("https://api.example/items/{c}%3Ci%3E'%22..%2F;$(x)");
        let s = url.find(c).unwrap();
        assert!(sink_problem(Label::Url, &url, s, s + c.len(), FULL).is_none());
        let sh = format!("grep '{c}<i>'\\''\"../;$(x)' f");
        let s = sh.find(c).unwrap();
        assert_eq!(sink_problem(Label::Shell, &sh, s, s + c.len(), FULL).unwrap().0, "escaped_by_hand");
        let re = format!("{c}<i>'\"\\.\\./;\\$\\(x\\)");
        assert!(sink_problem(Label::Regex, &re, 0, c.len(), FULL).is_none());
        // The request's canary ended there: the quote after it is the app's.
        let cut = format!("SELECT name FROM items WHERE name = 'https://{c}'");
        let s = cut.find(c).unwrap();
        assert!(sink_problem(Label::Sql, &cut, s, s + c.len(), "").is_none());
        assert!(!tails_in(["https://cnry12ab7"].into_iter())[c].contains('\''));
        // What the request sent percent-encoded, an app may decode: it counts.
        let sent = tails_in(["/search?q=cnry12ab7%3Ci%3E%27%22..%2F%3B%24%28x%29&page=2"].into_iter());
        assert!(["'", "../", ";", "$("].iter().all(|p| sent[c].contains(p)), "{:?}", sent[c]);
        let decoded = format!("SELECT name FROM items WHERE name = '{c}<i>'\"../;$(x)'");
        let s = decoded.find(c).unwrap();
        assert_eq!(sink_problem(Label::Sql, &decoded, s, s + c.len(), &sent[c]).unwrap().0, "sql_injection");
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

    fn pii_manifest(no_pii: bool, output: bool) -> Manifest {
        let out = if output { "output = { status = \"status\", body = \"body\" }" } else { "" };
        toml::from_str(&format!(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            {out}
            no_pii = {no_pii}
            [functions."x:y/users#all"]
            result = {{ email = "pii" }}
            "#
        ))
        .unwrap()
    }

    fn pii_run(request: Value, emails: &[&str], result: Value, stdout: &str) -> RunRecord {
        use crate::record::{HostCall, Outcome, RunSpec, Totals};
        let users: Vec<Value> = emails.iter().map(|e| json!({"name": "n", "email": e})).collect();
        let call = HostCall {
            n: 1,
            func: "x:y/users#all".into(),
            call: 1,
            args: Default::default(),
            value_checks: None,
            result: Some(Value::Array(users)),
            trap: None,
            source: String::new(),
            granted: true,
            latency_ns: 0u64.into(),
            cost: 0,
            fuel_before: 0,
            t_ns: 0u64.into(),
            stack: vec![],
            ..Default::default()
        };
        let spec = RunSpec {
            component: String::new(),
            contract: String::new(),
            export: "h".into(),
            args: vec![request],
            plan: Default::default(),
            now: String::new(),
            seed: 0,
            fuel: 0,
            memory: 0,
            ns_per_fuel: 0.0,
        };
        RunRecord {
            id: "r1".into(),
            spec,
            outcome: Outcome { kind: crate::record::OutcomeKind::Ok, message: None, stack: vec![] },
            result: Some(result),
            totals: Totals::default(),
            events: vec![call],
            guest_error: None,
            rejected_output: None,
            command_exit_code: None,
            memory_limit_hit: false,
            capture_limited: false,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn no_pii_fails_personal_data_in_the_page() {
        let r = pii_run(json!({"query": []}), &["p1@mail.example"], json!({"status": 200, "body": "<p>p1@mail.example</p>"}), "");
        assert!(leaks(&r, &pii_manifest(false, true)).is_empty(), "an ordinary page may show personal data");
        let f = leaks(&r, &pii_manifest(true, true));
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].kind.as_str(), f[0].severity), ("pii_leak", Severity::Fail));
        assert_eq!(f[0].detail["place"], "the response body");
    }

    #[test]
    fn many_people_are_one_finding() {
        let emails: Vec<String> = (0..37).map(|i| format!("p{i:03}@mail.example")).collect();
        let refs: Vec<&str> = emails.iter().map(String::as_str).collect();
        let r = pii_run(json!({}), &refs, json!({"status": 200, "body": emails.join(", ")}), "");
        let f = leaks(&r, &pii_manifest(true, true));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detail["count"], 37);
        assert!(f[0].title.contains("37 different values"), "{}", f[0].title);
    }

    #[test]
    fn echoed_request_values_are_not_leaks() {
        let r = pii_run(
            json!({"query": [["email", "p1@mail.example"]]}),
            &["p1@mail.example"],
            json!({"status": 200, "body": "p1@mail.example"}),
            "p1@mail.example",
        );
        assert!(leaks(&r, &pii_manifest(true, true)).is_empty());
    }

    #[test]
    fn no_pii_checks_results_without_http() {
        let r = pii_run(json!({}), &["p1@mail.example", "p2@mail.example"], json!({"ok": {"rows": [{"n": 1}, {"contact": "p2@mail.example"}]}}), "");
        assert!(leaks(&r, &pii_manifest(false, false)).is_empty());
        let f = leaks(&r, &pii_manifest(true, false));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detail["place"], "the result");
        assert_eq!(f[0].detail["at"], "ok.rows[1].contact");
    }

    /// A run of `x:y/db#query` with this SQL, for a request with `q`.
    fn sql_run(q: &str, sql: &str) -> (RunRecord, Manifest) {
        let mut r = pii_run(json!({ "q": q }), &[], json!(0), "");
        r.events[0].func = "x:y/db#query".into();
        r.events[0].result = Some(json!([]));
        r.events[0].args.insert("sql".into(), json!(sql));
        let m = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            [functions."x:y/db#query"]
            params = { sql = "sql" }
            "#,
        )
        .unwrap();
        (r, m)
    }

    #[test]
    fn sql_injection_names_the_field_and_needs_a_quote_sent() {
        let canary = "cnry12ab7<i>'\"../;$(x)";
        let (r, m) = sql_run(canary, &format!("SELECT * FROM t WHERE n = '{canary}'"));
        let f: Vec<_> = sinks(&r, &m);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, "sql_injection");
        assert!(f[0].title.contains("the request field q goes into the SQL text"), "{}", f[0].title);
        // Only the canary arrived (the rest cut off on the way): the quote
        // after it is the app's own.
        let (r, m) = sql_run("cnry12ab7", "SELECT * FROM t WHERE n = 'cnry12ab7'");
        assert!(sinks(&r, &m).is_empty());
    }

    #[test]
    fn logs_fail_without_no_pii() {
        let r = pii_run(json!({}), &["p1@mail.example"], json!({"status": 200, "body": "hi"}), "user p1@mail.example");
        let f = leaks(&r, &pii_manifest(false, true));
        assert_eq!((f.len(), f[0].detail["place"].as_str()), (1, Some("the log (stdout)")));
    }
}
