//! What the export returned, read through the manifest's `[entry.output]`
//! paths, and the detectors that look at it: well-formedness (status,
//! headers, markup), leaky errors, inconsistent responses, and data flow
//! from canaries (reflection, stored reflection, input passthrough).

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::harness::{field, fn_key_eq};
use crate::manifest::Manifest;
use crate::record::RunRecord;

/// The response of an entry run, as far as the manifest describes it.
#[derive(Debug, Default)]
pub struct Response {
    pub status: Option<i64>,
    pub body: Option<String>,
    /// The body was a list of bytes that is not UTF-8.
    pub body_not_utf8: bool,
    /// The body's length in bytes.
    pub body_len: Option<usize>,
    pub headers: Vec<(String, String)>,
    /// The manifest says, or the body looks like, HTML.
    pub html: bool,
}

/// Reads status, body and headers from a run's result. Without an
/// `[entry.output]` mapping a string result counts as the body.
pub fn response(r: &RunRecord, m: &Manifest) -> Response {
    let mut out = Response::default();
    let Some(result) = &r.result else { return out };
    let o = m.entry.as_ref().filter(|e| fn_key_eq(&e.export, &r.spec.export)).map(|e| &e.output);
    out.status = o.and_then(|o| o.status.as_deref()).and_then(|p| field(result, p)).and_then(|v| match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    });
    let body = match o.and_then(|o| o.body.as_deref()) {
        Some(p) => field(result, p),
        None => Some(result),
    };
    match body {
        Some(Value::String(s)) => {
            out.body = Some(s.clone());
            out.body_len = Some(s.len());
        }
        Some(Value::Array(a)) if !a.is_empty() && a.iter().all(|x| x.as_u64().is_some_and(|n| n < 256)) => {
            let bytes: Vec<u8> = a.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
            out.body_len = Some(bytes.len());
            match String::from_utf8(bytes) {
                Ok(s) => out.body = Some(s),
                Err(e) => {
                    out.body_not_utf8 = true;
                    out.body = Some(String::from_utf8_lossy(e.as_bytes()).into_owned());
                }
            }
        }
        _ => {}
    }
    if let Some(Value::Array(hs)) = o.and_then(|o| o.headers.as_deref()).and_then(|p| field(result, p)) {
        for h in hs {
            let pair = match h {
                Value::Array(p) if p.len() == 2 => p[0].as_str().zip(p[1].as_str()).map(|(a, b)| (a.to_string(), b.to_string())),
                Value::Object(o) => {
                    let n = o.get("name").or(o.get("key")).and_then(Value::as_str);
                    let v = o.get("value").and_then(Value::as_str);
                    n.zip(v).map(|(a, b)| (a.to_string(), b.to_string()))
                }
                _ => None,
            };
            out.headers.extend(pair);
        }
    }
    let format = o.and_then(|o| o.body_format.as_deref());
    let content_type = out.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.to_ascii_lowercase());
    out.html = match (&content_type, format) {
        // The response says what it is; a browser believes it.
        (Some(ct), _) => ct.contains("html"),
        (None, Some(f)) => f == "html",
        // No type in a response that has headers: the browser sniffs, and
        // only a body that starts like HTML renders as HTML.
        (None, None) if o.is_some_and(|o| o.headers.is_some()) => out.body.as_deref().is_some_and(sniffs_html),
        (None, None) => out.body.as_deref().is_some_and(|b| TAG.is_match(b)),
    };
    out
}

/// The WHATWG MIME sniffing rule for HTML: after whitespace, one of these
/// tags followed by a space or `>`, or a comment.
fn sniffs_html(body: &str) -> bool {
    const TAGS: &[&str] =
        &["<!doctype html", "<html", "<head", "<script", "<iframe", "<h1", "<div", "<font", "<table", "<a", "<style", "<title", "<b", "<body", "<br", "<p"];
    let b = body.trim_start_matches([' ', '\t', '\n', '\r', '\x0c']);
    if b.starts_with("<!--") {
        return true;
    }
    let head: String = b.chars().take(16).collect::<String>().to_ascii_lowercase();
    TAGS.iter().any(|t| head.starts_with(t) && matches!(head[t.len()..].chars().next(), Some(' ' | '>')))
}

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<(/?)([a-zA-Z][a-zA-Z0-9-]*)\b[^>]*?(/?)>").unwrap());
static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<!--.*?-->|<!(?i:doctype)[^>]*>").unwrap());
static PERCENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(-?\d+(?:[.,]\d+)?)\s*%").unwrap());

/// Elements without an end tag.
const VOID: &[&str] = &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"];
/// Elements whose end tag a browser may imply.
const OPTIONAL_END: &[&str] =
    &["p", "li", "dt", "dd", "option", "optgroup", "tr", "td", "th", "thead", "tbody", "tfoot", "colgroup", "caption", "rt", "rp", "html", "head", "body"];
/// Elements whose content is text, not markup.
const RAW: &[&str] = &["script", "style", "textarea", "title"];

/// The first markup problem in an HTML body or fragment: an element left
/// open, an end tag without a start, or end tags in the wrong order.
/// A tag as `TAG` matches it.
struct Tag<'a> {
    end: usize,
    close: bool,
    name: &'a str,
    self_closing: bool,
}

/// The next match of `TAG` at or after `from`, without the regex engine:
/// `markup_problem` runs on every response.
fn next_tag(s: &str, from: usize) -> Option<Tag<'_>> {
    let b = s.as_bytes();
    let word = |i: usize| s[i..].chars().next().is_some_and(regex_syntax::is_word_character);
    let word_before = |i: usize| s[..i].chars().next_back().is_some_and(regex_syntax::is_word_character);
    let mut at = from;
    while let Some(lt) = memchr::memchr(b'<', &b[at..]).map(|i| at + i) {
        at = lt + 1;
        let close = b.get(lt + 1) == Some(&b'/');
        let start = lt + 1 + close as usize;
        if !b.get(start).is_some_and(u8::is_ascii_alphabetic) {
            continue;
        }
        let mut stop = start + 1;
        while b.get(stop).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'-') {
            stop += 1;
        }
        // `\b` after the name; the regex backtracks to a shorter name.
        let Some(end_name) = (start + 1..=stop).rev().find(|&e| word_before(e) != word(e)) else { continue };
        let Some(gt) = memchr::memchr(b'>', &b[end_name..]).map(|i| end_name + i) else { continue };
        let self_closing = gt > end_name && b[gt - 1] == b'/';
        return Some(Tag { end: gt + 1, close, name: &s[start..end_name], self_closing });
    }
    None
}

pub fn markup_problem(body: &str) -> Option<String> {
    let body = COMMENT.replace_all(body, "");
    let lower = body.to_ascii_lowercase();
    let mut stack: Vec<String> = Vec::new();
    let mut pos = 0;
    while let Some(t) = next_tag(&body, pos) {
        pos = t.end;
        let close = t.close;
        let name = t.name.to_ascii_lowercase();
        if VOID.contains(&name.as_str()) {
            continue;
        }
        if !close {
            if !t.self_closing {
                if RAW.contains(&name.as_str()) {
                    // Text up to the end tag, whatever it looks like.
                    match lower[pos..].find(&format!("</{name}")) {
                        Some(i) => pos = lower[pos + i..].find('>').map_or(body.len(), |j| pos + i + j + 1),
                        None => return Some(format!("<{name}> is never closed")),
                    }
                } else {
                    stack.push(name);
                }
            }
            continue;
        }
        match stack.iter().rposition(|s| *s == name) {
            Some(i) => {
                let skipped: Vec<&String> = stack[i + 1..].iter().filter(|s| !OPTIONAL_END.contains(&s.as_str())).collect();
                if let Some(open) = skipped.last() {
                    return Some(format!("</{name}> closes <{name}> while <{open}> inside it is still open"));
                }
                stack.truncate(i);
            }
            None if OPTIONAL_END.contains(&name.as_str()) => {}
            None => return Some(format!("</{name}> without an open <{name}>")),
        }
    }
    stack.iter().rfind(|s| !OPTIONAL_END.contains(&s.as_str())).map(|s| format!("<{s}> is never closed"))
}

fn header_name_ok(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Host error texts of a run (strings inside `err` results, 8+ chars).
fn host_errors(r: &RunRecord, m: &Manifest) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in r.events.iter().filter(|e| !m.function(&e.func).is_some_and(|f| f.user_errors)) {
        if let Some(Value::Object(o)) = &e.result
            && let Some(err) = o.get("err")
        {
            let mut texts = BTreeSet::new();
            strings(err, &mut texts);
            out.extend(texts.into_iter().filter(|t| t.chars().count() >= 8).map(|t| (e.func.clone(), t)));
        }
    }
    out
}

pub(crate) fn strings(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// Percentages outside 0–100 in a text (`400 %`, `-5%`).
pub fn impossible_percentages(text: &str) -> Vec<String> {
    PERCENT
        .captures_iter(text)
        .filter(|c| c[1].replace(',', ".").parse::<f64>().is_ok_and(|x| !(0.0..=100.0).contains(&x)))
        .map(|c| c[0].to_string())
        .take(5)
        .collect()
}

/// Output well-formedness, leaky errors and inconsistent responses.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let mut out = Vec::new();
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    // A plain module answers by sending a response; ending without one
    // leaves the client waiting.
    if r.outcome.kind == crate::record::OutcomeKind::Ok && r.result.is_none() && m.host.as_ref().is_some_and(|h| h.platform.start.is_some()) {
        out.push(Finding::new("invalid_response", &format!("{ex}\0none"), Severity::Fail, format!("{ex} ends without sending a response"), json!({}), run));
        return out;
    }
    let resp = response(r, m);
    if let Some(s) = resp.status
        && !(100..=599).contains(&s)
    {
        out.push(Finding::new("invalid_response", &format!("{ex}\0status"), Severity::Fail, format!("{ex} returns status {s}"), json!({"status": s}), run));
    }
    for (n, v) in &resp.headers {
        let bad = if !header_name_ok(n) {
            Some(format!("header name {n:?} is not a valid token"))
        } else if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            Some(format!("header {n} has a line break or NUL in its value"))
        } else {
            None
        };
        if let Some(why) = bad {
            out.push(Finding::new(
                "invalid_response",
                &format!("{ex}\0header\0{n}"),
                Severity::Fail,
                format!("{ex}: {why}"),
                json!({"header": n, "value": v}),
                run,
            ));
            break;
        }
    }
    let header = |name: &str| resp.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim());
    // Bytes are fine where the response says it sends bytes (an image, a
    // download); as text a browser shows replacement characters.
    let text_type = header("content-type").is_none_or(|ct| {
        let ct = ct.to_ascii_lowercase();
        ct.starts_with("text/") || ["json", "xml", "html", "javascript", "charset="].iter().any(|t| ct.contains(t))
    });
    if resp.body_not_utf8 && text_type {
        out.push(Finding::new("invalid_response", &format!("{ex}\0utf8"), Severity::Warn, format!("{ex} returns a body that is not UTF-8"), json!({}), run));
    }
    // A Content-Length that disagrees with the body: the platform cuts the
    // response short or fails it, and a proxy may read the rest as the next
    // response. HEAD, 1xx, 204 and 304 send no body.
    let head = r.spec.args.first().and_then(|a| a.get("method")).and_then(Value::as_str).is_some_and(|m| m.eq_ignore_ascii_case("HEAD"));
    let bodiless = head || resp.status.is_some_and(|s| (100..200).contains(&s) || s == 204 || s == 304);
    if let (Some(cl), Some(len)) = (header("content-length"), resp.body_len)
        && !bodiless
        && cl.parse::<usize>().ok() != Some(len)
    {
        out.push(Finding::new(
            "invalid_response",
            &format!("{ex}\0content-length"),
            Severity::Fail,
            format!("{ex} sends Content-Length {cl} with a body of {len} bytes"),
            json!({"content_length": cl, "body_bytes": len}),
            run,
        ));
    }
    let Some(body) = resp.body.as_deref() else { return out };
    let body = &body[..body.len().min(1 << 20)];
    let body = &body[..(0..=body.len()).rev().find(|i| body.is_char_boundary(*i)).unwrap_or(0)];
    // Canary markup is reported as reflection, not as broken markup.
    // Past 1 MiB only a prefix is parsed: its open elements prove nothing
    // (big_output reports such pages).
    if resp.html
        && body.len() == resp.body.as_deref().map_or(0, str::len)
        && let Some(p) = markup_problem(&CANARY_TAIL.replace_all(body, "$1"))
    {
        out.push(Finding::new("broken_markup", &format!("{ex}\0{p}"), Severity::Warn, format!("{ex} returns broken markup: {p}"), json!({"problem": p}), run));
    }
    // Leaky errors: panic text, stderr lines, host error text in the body.
    let mut leaks: Vec<String> = Vec::new();
    // Panic text, unless the app got it as input (strings in the binary
    // end up in generated values).
    let inputs = || {
        let mut s = BTreeSet::new();
        r.spec.args.iter().for_each(|a| strings(a, &mut s));
        r.events.iter().filter_map(|e| e.result.as_ref()).for_each(|v| strings(v, &mut s));
        s
    };
    if let Some(m) = ["panicked at", "stack backtrace:", "RUST_BACKTRACE"].iter().find(|m| body.contains(**m))
        && !inputs().iter().any(|s| s.contains(m))
    {
        leaks.push("panic text".into());
    }
    if let Some(line) = r.stderr.lines().map(str::trim).find(|l| l.len() >= 20 && body.contains(*l)) {
        leaks.push(format!("stderr line {:?}", line.chars().take(80).collect::<String>()));
    }
    // An error text counts only if no other input carries it too.
    let mut other = BTreeSet::new();
    r.spec.args.iter().for_each(|a| strings(a, &mut other));
    r.events.iter().filter_map(|e| e.result.as_ref()).filter(|v| v.get("err").is_none()).for_each(|v| strings(v, &mut other));
    let errs = host_errors(r, m);
    // In HTML only the text counts: a short error text like `progress`
    // (generated from a string in the binary) is in `<progress>` too.
    // Most runs have no error texts: skip the scan of the whole body.
    let text = if errs.is_empty() { String::new() } else { error_view(&resp, body) };
    let shown: Vec<&(String, String)> = errs.iter().filter(|(_, t)| text.contains(t.as_str()) && !other.iter().any(|o| o.contains(t.as_str()))).collect();
    if let Some((f, t)) = shown.first() {
        leaks.push(format!("the error text {f} returned ({:?})", t.chars().take(60).collect::<String>()));
    }
    if !leaks.is_empty() {
        out.push(leaky(ex, leaks, shown.first().map(|x| (x.0.as_str(), x.1.as_str())), run));
    }
    if let (Some(s), Some((f, t))) = (resp.status, shown.first())
        && (200..300).contains(&s)
    {
        out.push(Finding::new(
            "inconsistent_response",
            &format!("{ex}\0ok_with_error\0{f}"),
            Severity::Warn,
            format!("{ex} answers {s} but shows the error {f} returned"),
            json!({"status": s, "func": f, "error": t}),
            run,
        ));
    }
    out.extend(flow(r, m, &resp, body));
    out
}

fn leaky(ex: &str, leaks: Vec<String>, error: Option<(&str, &str)>, run: Option<&str>) -> Finding {
    let mut detail = json!({"leaks": leaks});
    if let Some((f, t)) = error {
        detail["error"] = json!({"func": f, "text": t});
    }
    Finding::new(
        "leaky_error",
        &format!("{ex}\0{}", leaks.iter().map(|l| l.split(' ').next().unwrap_or("")).collect::<Vec<_>>().join(",")),
        Severity::Warn,
        format!("{ex} shows internal error details in its output: {}", leaks.join("; ")),
        detail,
        run,
    )
}

/// The part of a body where an error text counts as shown: in HTML the
/// text and attribute values, without style sheets.
fn error_view(resp: &Response, body: &str) -> String {
    if resp.html { visible_text(&STYLE.replace_all(body, " ")) } else { body.to_string() }
}

static STYLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<style\b[^>]*>.*?</style\s*>").unwrap());

/// The error text a finding is about, for `leaky_error` and the
/// `inconsistent_response` of a page that shows an error.
fn error_text(f: &Finding) -> Option<&str> {
    match f.kind.as_str() {
        "leaky_error" => f.detail.get("error")?.get("text")?.as_str(),
        "inconsistent_response" => f.detail.get("error")?.as_str(),
        _ => None,
    }
}

/// Drops error-text findings whose text the page shows anyway. A generated
/// error text can be a word the app writes itself, such as a CSS class or a
/// heading. Reruns `r` with each such text changed in the host errors; a
/// text that still shows did not come from the error. Keeps the findings
/// when the rerun does not get the changed errors or does not finish.
pub fn drop_echoes(app: &crate::harness::App, r: &RunRecord, findings: &mut Vec<Finding>) {
    let texts: BTreeSet<String> = findings.iter().filter_map(error_text).map(str::to_string).collect();
    if texts.is_empty() || r.outcome.kind != crate::record::OutcomeKind::Ok {
        return;
    }
    let mut spec = r.spec.clone();
    let mut changed = Vec::new();
    for e in &r.events {
        let Some(err) = e.result.as_ref().and_then(|v| v.get("err")) else { continue };
        let swapped = swap(err, &texts);
        if &swapped == err {
            continue;
        }
        if !spec.plan.0.contains_key(&e.func)
            && let Some(effective) = spec.plan.get(&e.func).cloned()
        {
            spec.plan.0.insert(e.func.clone(), effective);
        }
        let ret = json!({"err": swapped});
        let fp = spec.plan.0.entry(e.func.clone()).or_default();
        let resp = fp.on_call.entry(e.call.to_string()).or_default();
        resp.ret = Some(ret.clone());
        resp.generate = None;
        resp.trap = None;
        resp.commit_then_trap = None;
        changed.push((e.func.clone(), e.call, ret));
    }
    if changed.is_empty() {
        return;
    }
    let vr = app.run(&spec);
    let got = |(f, c, ret): &(String, u32, Value)| vr.events.iter().any(|e| &e.func == f && e.call == *c && e.result.as_ref() == Some(ret));
    if vr.outcome.kind != crate::record::OutcomeKind::Ok || !changed.iter().all(got) {
        return;
    }
    let resp = response(&vr, &app.manifest);
    let Some(body) = resp.body.as_deref() else { return };
    let view = error_view(&resp, body);
    let echoes: BTreeSet<&String> = texts.iter().filter(|t| view.contains(t.as_str())).collect();
    if echoes.is_empty() {
        return;
    }
    let ex = &r.spec.export;
    let mut out = Vec::new();
    for f in findings.drain(..) {
        match error_text(&f) {
            Some(t) if echoes.contains(&t.to_string()) => {
                if f.kind == "leaky_error" {
                    let leaks: Vec<String> = f.detail["leaks"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .filter(|l| !l.starts_with("the error text "))
                        .map(str::to_string)
                        .collect();
                    if !leaks.is_empty() {
                        out.push(leaky(ex, leaks, None, f.run.as_deref()));
                    }
                }
            }
            _ => out.push(f),
        }
    }
    *findings = out;
}

/// The strings of `v` with each of `texts` in them changed: letters by 13
/// places, digits by 5. Same length and kind of characters, another text.
fn swap(v: &Value, texts: &BTreeSet<String>) -> Value {
    match v {
        Value::String(s) => {
            let mut s = s.clone();
            for t in texts {
                s = s.replace(t.as_str(), &rot(t));
            }
            Value::String(s)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| swap(x, texts)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), swap(x, texts))).collect()),
        x => x.clone(),
    }
}

fn rot(t: &str) -> String {
    t.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            '0'..='9' => (((c as u8 - b'0' + 5) % 10) + b'0') as char,
            c => c,
        })
        .collect()
}

pub(crate) static CANARY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"cnry[0-9a-f]{4}\d+").unwrap());
static CANARY_TAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(cnry[0-9a-f]{4}\d+)<i>").unwrap());

/// Canary text for a request field or a host string: an id, then markup
/// and quotes that must come out escaped.
pub fn canary(n: u64) -> String {
    format!("cnry{:04x}{n}<i>'\"", (n.wrapping_mul(0x9e37) >> 3) & 0xffff)
}

/// What a sink canary adds: a path step, a command separator and a
/// command substitution.
pub const SINK_TAIL: &str = "../;$(x)";

/// A canary as the host of a URL, which URL parsers accept.
pub fn url_canary(n: u64) -> String {
    let c = canary(n);
    format!("https://{}.example/", &c[..c.find('<').unwrap_or(c.len())])
}

/// A canary with the sink tail when the manifest labels sinks.
pub fn canary_for(m: &Manifest, n: u64) -> String {
    if m.has_sinks() { format!("{}{SINK_TAIL}", canary(n)) } else { canary(n) }
}

/// Data flow by canaries: a canary from the request or from a host result
/// in the output unescaped (reflection), or a request canary in a host
/// argument (passthrough).
fn flow(r: &RunRecord, m: &Manifest, resp: &Response, body: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let mut from_request = BTreeSet::new();
    for (i, a) in r.spec.args.iter().enumerate() {
        canary_paths(a, format!("@{i}"), &mut from_request);
    }
    let mut from_host: BTreeSet<(String, String)> = BTreeSet::new();
    for e in &r.events {
        if let Some(v) = &e.result {
            let mut s = BTreeSet::new();
            strings(v, &mut s);
            for t in s {
                for c in CANARY.find_iter(&t) {
                    from_host.insert((c.as_str().to_string(), e.func.clone()));
                }
            }
        }
    }
    if from_request.is_empty() && from_host.is_empty() {
        return out;
    }
    // Strings an `html` result label marks as trusted markup.
    let trusted = crate::labels::trusted_html(r, m);
    for c in CANARY.find_iter(body) {
        if trusted.contains(c.as_str()) {
            continue;
        }
        let raw = body[c.end()..].starts_with("<i>");
        if !(raw && resp.html) {
            continue;
        }
        if let Some((_, path)) = from_request.iter().find(|(id, _)| id == c.as_str()) {
            out.push(Finding::new(
                "reflection",
                &format!("{ex}\0{}", strip_index(path)),
                Severity::Fail,
                format!("{ex} puts the request field {} into its HTML output unescaped", strip_index(path)),
                json!({"field": strip_index(path), "canary": c.as_str()}),
                run,
            ));
        } else if let Some((_, f)) = from_host.iter().find(|(id, _)| id == c.as_str()) {
            out.push(Finding::new(
                "stored_reflection",
                &format!("{ex}\0{f}"),
                Severity::Fail,
                format!("{ex} puts a string {f} returned into its HTML output unescaped"),
                json!({"func": f, "canary": c.as_str()}),
                run,
            ));
        }
    }
    // Fields with a role (the clock) are meant for the host.
    let roles: Vec<&String> = m.entry.as_ref().map(|e| e.fields.keys().collect()).unwrap_or_default();
    for e in &r.events {
        let mut s = BTreeSet::new();
        strings(&Value::Object(e.args.clone()), &mut s);
        for t in s {
            for c in CANARY.find_iter(&t) {
                if let Some((_, path)) = from_request.iter().find(|(id, _)| id == c.as_str())
                    && !roles.iter().any(|f| strip_index(path) == **f)
                {
                    out.push(Finding::new(
                        "input_passthrough",
                        &format!("{ex}\0{}\0{}", strip_index(path), e.func),
                        Severity::Info,
                        format!("the request field {} goes unchanged into {}", strip_index(path), e.func),
                        json!({"field": strip_index(path), "func": e.func, "n": e.n, "canary": c.as_str(), "exact": t.starts_with(c.as_str())}),
                        run,
                    ));
                }
            }
        }
    }
    dedupe(out)
}

/// `@0.query.q` → `query.q` (the first argument is the request).
pub(crate) fn strip_index(p: &str) -> String {
    p.strip_prefix("@0.").map(str::to_string).unwrap_or_else(|| p.to_string())
}

pub(crate) fn canary_paths(v: &Value, path: String, out: &mut BTreeSet<(String, String)>) {
    match v {
        Value::String(s) => {
            for c in CANARY.find_iter(s) {
                out.insert((c.as_str().to_string(), path.clone()));
            }
        }
        Value::Array(a) if a.iter().all(|p| p.as_array().is_some_and(|p| p.len() == 2 && p[0].is_string())) && !a.is_empty() => {
            for p in a {
                let k = p[0].as_str().unwrap_or_default();
                canary_paths(&p[1], format!("{path}.{k}"), out);
            }
        }
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| canary_paths(x, format!("{path}.{i}"), out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| canary_paths(x, format!("{path}.{k}"), out)),
        _ => {}
    }
}

fn dedupe(v: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    v.into_iter().filter(|f| seen.insert(f.id.clone())).collect()
}

static TAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());

/// The text of an HTML body without its tags, and with attribute values
/// kept (a `title` or `value` shows text too).
fn visible_text(body: &str) -> String {
    static VALUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());
    let mut out = TAGS.replace_all(body, " ").into_owned();
    for tag in TAGS.find_iter(body) {
        for c in VALUE.captures_iter(tag.as_str()) {
            out.push(' ');
            out.push_str(c.get(1).or(c.get(2)).map_or("", |m| m.as_str()));
        }
    }
    out
}

/// The visible text of a body as a bag of words, for order-insensitive
/// comparison.
pub fn word_bag(body: &str) -> Vec<String> {
    let text = TAGS.replace_all(body, " ");
    let mut w: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    w.sort();
    w
}

#[cfg(test)]
mod tests {
    #[test]
    fn sniffing_like_a_browser() {
        assert!(super::sniffs_html("  <h1>Hi</h1>"));
        assert!(super::sniffs_html("<!DOCTYPE html><html>"));
        assert!(super::sniffs_html("<!-- x -->"));
        assert!(!super::sniffs_html("Error::Other(\"<b>x\")"));
        assert!(!super::sniffs_html("<bogus>"));
        assert!(!super::sniffs_html("<blink>"));
    }

    use super::*;

    /// The scanner finds what the regex finds, on random markup.
    #[test]
    fn tag_scanner_matches_regex() {
        use rand::{RngExt, SeedableRng};
        let alphabet = ['<', '/', '>', 'a', 'B', '1', '-', '_', ' ', 'é', '\u{301}', '=', '"', '\n'];
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for _ in 0..200_000 {
            let n = rng.random_range(0..24);
            let s: String = (0..n).map(|_| alphabet[rng.random_range(0..alphabet.len())]).collect();
            let mut want = Vec::new();
            let mut pos = 0;
            while let Some(c) = TAG.captures_at(&s, pos) {
                pos = c.get(0).unwrap().end();
                want.push((pos, !c[1].is_empty(), c[2].to_string(), !c[3].is_empty()));
            }
            let mut got = Vec::new();
            let mut pos = 0;
            while let Some(t) = next_tag(&s, pos) {
                pos = t.end;
                got.push((pos, t.close, t.name.to_string(), t.self_closing));
            }
            assert_eq!(got, want, "{s:?}");
        }
    }

    #[test]
    fn markup() {
        assert_eq!(markup_problem("<div><p>a<p>b</div>"), None);
        assert_eq!(markup_problem("<ul><li>a<li>b</ul><br><img src=x>"), None);
        assert_eq!(markup_problem("<script>if (a<b) {}</script><div></div>"), None);
        assert_eq!(markup_problem("<div><span>x</div>").as_deref(), Some("</div> closes <div> while <span> inside it is still open"));
        assert_eq!(markup_problem("<div>x").as_deref(), Some("<div> is never closed"));
        assert_eq!(markup_problem("x</div>").as_deref(), Some("</div> without an open <div>"));
        assert_eq!(markup_problem("<!-- <div> --><b>x</b>"), None);
    }

    #[test]
    fn text_without_tags() {
        let t = visible_text(r#"<progress value="2" max="9"></progress><p title='Name is required'>ok</p>"#);
        assert!(!t.contains("progress"));
        assert!(t.contains("Name is required") && t.contains("ok"));
    }

    #[test]
    fn percentages() {
        assert_eq!(impossible_percentages("used 40 % of 400% and -5%"), vec!["400%".to_string(), "-5%".to_string()]);
    }

    #[test]
    fn canaries() {
        let c = canary(7);
        assert!(CANARY.is_match(&c) && c.ends_with("<i>'\""));
    }
}
