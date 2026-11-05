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
        Some(Value::Array(a)) if a.iter().all(|x| x.as_u64().is_some_and(|n| n < 256)) => {
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
    // HTML no output label covers: scripts from elsewhere are a warn.
    let labelled = m.entry.as_ref().is_some_and(|e| e.result.values().any(|l| *l != crate::markup::OutputLabel::UrlLocal));
    if resp.html
        && !labelled
        && let Some(b) = &resp.body
    {
        let path = m.entry.as_ref().and_then(|e| e.output.body.clone()).unwrap_or_else(|| "body".into());
        out.extend(crate::markup::unpinned_findings(r, m, &path, b, Severity::Warn));
    }
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

/// A whole canary as the fuzzer writes it: with its markup and sink tail,
/// or as the host of a URL.
static WHOLE_CANARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https://cnry[0-9a-f]{4}\d+\.example/|cnry[0-9a-f]{4}\d+(<i>'"(\.\./;\$\(x\))?)?"#).unwrap());

/// The text without one of its canaries, for each canary in it.
pub(crate) fn without_canaries(t: &str) -> Vec<String> {
    WHOLE_CANARY.find_iter(t).map(|m| format!("{}{}", &t[..m.start()], &t[m.end()..])).collect()
}

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
    // Attack strings (`';alert(1)//`) whose `alert(1)` runs as code.
    let mut attack = None;
    for (i, a) in r.spec.args.iter().enumerate() {
        each_string(a, format!("@{i}"), &mut |s, p| {
            if attack.is_none() && s.contains("alert(1)") {
                attack = Some((p.to_string(), s.to_string()));
            }
        });
    }
    if let Some((path, text)) = attack.filter(|_| resp.html)
        && let Some((context, how)) = attack_runs(body)
    {
        out.push(Finding::new(
            "reflection",
            &format!("{ex}\0{}", strip_index(&path)),
            Severity::Fail,
            format!("{ex} puts {} {how}", request_place(m, &r.spec.args, &path, &text)),
            json!({"field": strip_index(&path), "text": text, "context": context}),
            run,
        ));
    }
    if from_request.is_empty() && from_host.is_empty() {
        return dedupe(out);
    }
    // Strings an `html` result label marks as trusted markup.
    let trusted = crate::labels::trusted_html(r, m);
    let mut seen = BTreeSet::new();
    for c in CANARY.find_iter(body) {
        let id = c.as_str();
        if !resp.html || trusted.contains(id) || !seen.insert(id) {
            continue;
        }
        if let Some((_, path)) = from_request.iter().find(|(c, _)| c == id) {
            let Some((context, how)) = breakout(body, id) else { continue };
            out.push(Finding::new(
                "reflection",
                &format!("{ex}\0{}", strip_index(path)),
                Severity::Fail,
                format!("{ex} puts {} {how}", request_place(m, &r.spec.args, path, id)),
                json!({"field": strip_index(path), "canary": id, "context": context}),
                run,
            ));
        } else if let Some((_, f)) = from_host.iter().find(|(c, _)| c == id) {
            let Some((context, how)) = breakout(body, id) else { continue };
            out.push(Finding::new(
                "stored_reflection",
                &format!("{ex}\0{f}"),
                Severity::Fail,
                format!("{ex} puts a string {f} returned {how}"),
                json!({"func": f, "canary": id, "context": context}),
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
                        format!("{} goes unchanged into {}", request_place(m, &r.spec.args, path, c.as_str()), e.func),
                        json!({"field": strip_index(path), "func": e.func, "n": e.n, "canary": c.as_str(), "exact": t.starts_with(c.as_str())}),
                        run,
                    ));
                }
            }
        }
    }
    dedupe(out)
}

/// Whether the canary `id` breaks out of where the HTML body put it, and
/// how: (context, what the app does, said after "puts X").
///
/// Its `<i>` raw anywhere is markup the app didn't write (in a script, a
/// `</script>` would end it). In an attribute, a quote of the canary that
/// starts an attribute name of its own ended the value. In JavaScript (a
/// script, an event handler, a `javascript:` URL, a framework expression)
/// a quote of the canary that ends the string, or the canary as code, runs.
fn breakout(body: &str, id: &str) -> Option<(&'static str, String)> {
    let doc = crate::html::doc(body);
    let marked = format!("{id}<i>");
    if body.contains(&marked) {
        let script = doc.elements.iter().find(|e| e.name == "script" && e.body.as_ref().is_some_and(|b| b.contains(&marked)));
        return Some(match script {
            Some(e) if is_js(e.get("type")) => ("script", "into a script unescaped, where `</script>` in it ends the script".into()),
            Some(_) => ("json", "into a data block unescaped, where `</script>` in it ends the block".into()),
            None => ("text", "into its HTML output unescaped".into()),
        });
    }
    for e in &doc.elements {
        if let Some((k, _)) = e.attrs.iter().find(|(_, v)| v.contains(id))
            && e.attrs.iter().any(|(n, _)| n.contains(['"', '\'']))
        {
            return Some(("attribute", format!("into the HTML attribute {k}, where a quote in it ends the attribute")));
        }
    }
    let tail = format!("<i>'\"{SINK_TAIL}");
    js_sources(body).iter().filter(|s| s.code.contains(id)).find_map(|s| {
        crate::js::breakout(&s.code, id, &tail).map(|b| match b {
            crate::js::Breakout::Quote => (s.context, format!("into a JavaScript string in {}, where a quote in it ends the string", s.place)),
            crate::js::Breakout::Code => (s.context, format!("into {} as JavaScript code", s.place)),
        })
    })
}

/// Where `alert(1)` of an attack string runs as code in the HTML body:
/// (context, said after "puts X").
fn attack_runs(body: &str) -> Option<(&'static str, String)> {
    const ATTACK: &str = "alert(1)";
    if !body.contains(ATTACK) {
        return None;
    }
    js_sources(body).iter().find_map(|s| {
        let at: Vec<usize> = s.code.match_indices(ATTACK).map(|(i, _)| i).collect();
        crate::js::places(&s.code, &at).contains(&crate::js::Place::Code).then(|| (s.context, format!("into {}, where it runs as JavaScript", s.place)))
    })
}

/// JavaScript in an HTML document, as the browser runs it.
struct JsSource {
    /// `script`, `handler` or `url`.
    context: &'static str,
    /// Where, for people: "a script", "the attribute onclick".
    place: String,
    code: String,
}

/// Script bodies, event handlers and framework expressions (their values
/// entity-decoded), and `javascript:` URLs (also percent-decoded).
fn js_sources(body: &str) -> std::rc::Rc<Vec<JsSource>> {
    thread_local! {
        static JS: std::cell::RefCell<(String, std::rc::Rc<Vec<JsSource>>)> = std::cell::RefCell::default();
    }
    crate::html::memo(&JS, body, |body| {
        let mut out = Vec::new();
        for e in &crate::html::doc(body).elements {
            js_in(e, &mut out);
        }
        out
    })
}

fn js_in(e: &crate::html::Element, out: &mut Vec<JsSource>) {
    for (k, v) in &e.attrs {
        if crate::markup::is_handler(k) || crate::markup::is_expression(k) {
            out.push(JsSource { context: "handler", place: format!("the attribute {k}"), code: v.clone() });
            continue;
        }
        let n = crate::urls::normalize(v);
        let lower = n.to_ascii_lowercase();
        if let Some(code) = lower.strip_prefix("javascript:").or_else(|| lower.strip_prefix("js:")) {
            let code = crate::js::percent_decode(&n[lower.len() - code.len()..]);
            out.push(JsSource { context: "url", place: format!("the script URL in {k}"), code });
        }
    }
    if e.name == "script"
        && is_js(e.get("type"))
        && let Some(b) = &e.body
    {
        out.push(JsSource { context: "script", place: "a script".into(), code: b.clone() });
    }
}

/// Whether a `<script type>` runs as JavaScript.
fn is_js(ty: Option<&str>) -> bool {
    let t = ty.unwrap_or("").trim().to_ascii_lowercase();
    let t = t.split(';').next().unwrap_or("").trim();
    t.is_empty() || t == "module" || t.ends_with("javascript") || t.ends_with("ecmascript") || t.ends_with("jscript") || t.ends_with("livescript")
}

/// `@0.query.q` → `query.q` (the first argument is the request).
pub(crate) fn strip_index(p: &str) -> String {
    p.strip_prefix("@0.").map(str::to_string).unwrap_or_else(|| p.to_string())
}

/// Where in the request a canary at `path` is, as a developer names it:
/// "the query parameter `url`", not "the request field uri".
pub(crate) fn request_place(m: &Manifest, args: &[Value], path: &str, canary: &str) -> String {
    let p = strip_index(path);
    // Request fields with an HTTP role, or named like one.
    if let Some(req) = args.first() {
        let none = std::collections::BTreeMap::new();
        let roles = m.entry.as_ref().map_or(&none, |e| &e.fields);
        for (role, say) in [("query", "the query parameter"), ("form", "the form field")] {
            if let Some(k) = crate::fuzz::role_path(roles, req, role).and_then(|f| p.strip_prefix(&format!("{f}.")).map(str::to_string)) {
                return format!("{say} `{k}`");
            }
        }
        if crate::fuzz::role_path(roles, req, "path").is_some_and(|f| f == p) {
            return "the URL path".into();
        }
    }
    if let Some(h) = p.strip_prefix("headers.") {
        return format!("the request header `{h}`");
    }
    if p == "body" {
        return "the request body".into();
    }
    if p == "uri"
        && let Some(uri) = args.first().and_then(|a| a["uri"].as_str())
        && let Some(at) = uri.find(canary)
    {
        return uri_place(uri, at);
    }
    format!("the request field {p}")
}

/// The part of a request URI at byte `at`.
fn uri_place(uri: &str, at: usize) -> String {
    let fragment = uri.find('#').unwrap_or(uri.len());
    let query = uri[..fragment].find('?').unwrap_or(fragment);
    if at > fragment {
        return "the URL fragment".into();
    }
    if at > query {
        let mut start = query + 1;
        for part in uri[start..fragment].split('&') {
            if at < start + part.len() {
                let name = part.split('=').next().unwrap_or(part);
                return if at < start + name.len() { "a query parameter name".into() } else { format!("the query parameter `{name}`") };
            }
            start += part.len() + 1;
        }
    }
    let authority = uri.find("://").map(|i| {
        let from = i + 3;
        (from, uri[from..].find(['/', '?', '#']).map_or(uri.len(), |e| from + e))
    });
    match authority {
        Some((from, to)) if (from..to).contains(&at) => "the host the request names".into(),
        _ => "the URL path".into(),
    }
}

pub(crate) fn canary_paths(v: &Value, path: String, out: &mut BTreeSet<(String, String)>) {
    each_string(v, path, &mut |s, path| {
        for c in CANARY.find_iter(s) {
            out.insert((c.as_str().to_string(), path.to_string()));
        }
    });
}

/// Calls `f` with each string in `v` and its path; `[[name, value], …]`
/// pairs (headers, query) are walked by name.
fn each_string(v: &Value, path: String, f: &mut impl FnMut(&str, &str)) {
    match v {
        Value::String(s) => f(s, &path),
        Value::Array(a) if a.iter().all(|p| p.as_array().is_some_and(|p| p.len() == 2 && p[0].is_string())) && !a.is_empty() => {
            for p in a {
                let k = p[0].as_str().unwrap_or_default();
                each_string(&p[1], format!("{path}.{k}"), f);
            }
        }
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| each_string(x, format!("{path}.{i}"), f)),
        Value::Object(o) => o.iter().for_each(|(k, x)| each_string(x, format!("{path}.{k}"), f)),
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

    #[test]
    fn empty_byte_bodies_are_present_and_have_zero_length() {
        let m: Manifest = toml::from_str("[app]\nwasm = 'x.wasm'\n[entry]\nexport = 'run'\noutput = { body = 'body' }\n").unwrap();
        for bytes in [json!([]), json!([104, 105]), json!([255])] {
            let r = crate::envelope::Trace { export: "run".into(), result: Some(json!({"body":bytes})), ..Default::default() }.to_record();
            let response = response(&r, &m);
            assert_eq!(response.body_len, Some(bytes.as_array().unwrap().len()));
            assert!(response.body.is_some());
            assert_eq!(response.body_not_utf8, bytes == json!([255]));
        }
    }

    #[test]
    fn request_places_are_named_as_developers_do() {
        let c = "cnry1a2b7";
        let m: Manifest = toml::from_str("[app]\nwasm = \"x.wasm\"\n").unwrap();
        let place = |uri: &str| super::request_place(&m, &[json!({"uri": uri})], "@0.uri", c);
        assert_eq!(place("https://app.example/?name=cnry1a2b7<i>&x=1"), "the query parameter `name`");
        assert_eq!(place("https://app.example/?x=1&url=https://cnry1a2b7.example/"), "the query parameter `url`");
        assert_eq!(place("https://app.example/?cnry1a2b7=1"), "a query parameter name");
        assert_eq!(place("https://app.example/items/cnry1a2b7?x=1"), "the URL path");
        assert_eq!(place("https://cnry1a2b7.example/?x=1"), "the host the request names");
        assert_eq!(place("/?q=1#cnry1a2b7"), "the URL fragment");
        assert_eq!(place("/a?q=cnry1a2b7"), "the query parameter `q`");
        let args = [json!({"headers": [["x-user", "cnry1a2b7"]], "body": "cnry1a2b7"})];
        assert_eq!(super::request_place(&m, &args, "@0.headers.x-user", c), "the request header `x-user`");
        assert_eq!(super::request_place(&m, &args, "@0.body", c), "the request body");
        let req = [json!({"path": c, "query": [["days", c]], "form": [["note", c]], "user": c})];
        assert_eq!(super::request_place(&m, &req, "@0.query.days", c), "the query parameter `days`");
        assert_eq!(super::request_place(&m, &req, "@0.form.note", c), "the form field `note`");
        assert_eq!(super::request_place(&m, &req, "@0.path", c), "the URL path");
        assert_eq!(super::request_place(&m, &req, "@0.user", c), "the request field user");
    }

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
    fn breakouts_by_context() {
        let id = "cnry12341";
        let ctx = |b: &str| breakout(b, id).map(|(c, _)| c);
        let cases = [
            (r#"<p>cnry12341<i>'"</p>"#, Some("text")),
            (r#"<script type="application/json">{"q": "cnry12341<i>'"}</script>"#, Some("json")),
            (r#"<script>var q = "cnry12341<i>'\"";</script>"#, Some("script")),
            // Attributes: `<>` escaped, a quote left.
            (r#"<a title="cnry12341&lt;i&gt;'"">x</a>"#, Some("attribute")),
            (r#"<a title='cnry12341&lt;i&gt;'"'>x</a>"#, Some("attribute")),
            (r#"<a title="cnry12341&lt;i&gt;&#39;&quot;">x</a>"#, None),
            (r#"<a title="cnry12341&lt;i&gt;'&quot;">x</a>"#, None),
            // Scripts: JS escapes for `<`, a quote left raw.
            (r#"<script>var q = 'cnry12341\u003ci\u003e'"';</script>"#, Some("script")),
            (r#"<script>var q = "cnry12341\u003ci\u003e'\"";</script>"#, None),
            (r#"<script>var q = 'cnry12341&lt;i&gt;&#39;&quot;';</script>"#, None),
            (r#"<script>var n = cnry12341;</script>"#, Some("script")),
            (r#"<script type="application/json">{"q": "cnry12341\u003ci>'"}</script>"#, None),
            // A handler's value is decoded before it runs: entities don't help.
            (r#"<button onclick="f('cnry12341&lt;i&gt;&#39;&quot;')">x</button>"#, Some("handler")),
            (r#"<button onclick="f('cnry12341\x3ci\x3e\x27\x22')">x</button>"#, None),
            (r#"<div x-data="{ q: 'cnry12341&lt;i&gt;&#39;&quot;' }"></div>"#, Some("handler")),
            (r#"<div x-text="q" title="cnry12341&lt;i&gt;&#39;&quot;"></div>"#, None),
            // A script URL is percent-decoded first: encodeURIComponent leaves `'`.
            (r#"<a href="javascript:f('cnry12341%3Ci%3E'%22')">x</a>"#, Some("url")),
            (r#"<a href="/s?q=cnry12341%3Ci%3E'%22">x</a>"#, None),
        ];
        for (body, want) in cases {
            assert_eq!(ctx(body), want, "{body}");
        }
    }

    #[test]
    fn attacks_that_run() {
        let ctx = |b: &str| attack_runs(b).map(|(c, _)| c);
        assert_eq!(ctx(r#"<script>var q = '';alert(1)//';</script>"#), Some("script"));
        assert_eq!(ctx(r#"<script>var q = '\';alert(1)//';</script>"#), None);
        assert_eq!(ctx(r#"<script>var q = '\\';alert(1)//';</script>"#), Some("script"));
        assert_eq!(ctx("<script>var q = `${alert(1)}`;</script>"), Some("script"));
        assert_eq!(ctx(r#"<a title='' onmouseover='alert(1)'>x</a>"#), Some("handler"));
        assert_eq!(ctx(r#"<a title="&#39; onmouseover=&#39;alert(1)">x</a>"#), None);
        assert_eq!(ctx("<p>alert(1)</p>"), None);
    }

    #[test]
    fn canaries() {
        let c = canary(7);
        assert!(CANARY.is_match(&c) && c.ends_with("<i>'\""));
    }
}
