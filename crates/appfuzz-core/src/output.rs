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

/// Body shapes the response reader consumes: text or a list of bytes.
pub(crate) fn is_body(v: &Value) -> bool {
    v.is_string() || v.as_array().is_some_and(|a| a.iter().all(|x| x.as_u64().is_some_and(|n| n < 256)))
}

/// Raw HTTP body bytes. Callers identify the body field; numeric lists
/// elsewhere remain ordinary application data.
pub(crate) fn http_body_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(text) => Some(text.as_bytes().to_vec()),
        Value::Array(bytes) => bytes.iter().map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok())).collect(),
        _ => None,
    }
}

/// The response bytes before text decoding for markup and text detectors.
pub(crate) fn response_body_bytes(record: &RunRecord, manifest: &Manifest) -> Option<Vec<u8>> {
    let result = record.result.as_ref()?;
    let body = manifest.entry.as_ref().filter(|e| fn_key_eq(&e.export, &record.spec.export)).and_then(|e| e.output.body.as_deref());
    http_body_bytes(body.map_or(Some(result), |path| field(result, path))?)
}

/// The actual string nodes a header entry consumes. Other fields remain
/// ordinary export output, including an unused `key` beside `name`.
pub(crate) fn header_parts(v: &Value) -> Option<(&Value, &Value)> {
    let (name, value) = match v {
        Value::Array(parts) if parts.len() == 2 => (&parts[0], &parts[1]),
        Value::Object(o) => (o.get("name").or_else(|| o.get("key"))?, o.get("value")?),
        _ => return None,
    };
    (name.is_string() && value.is_string()).then_some((name, value))
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
    }
    .filter(|v| is_body(v));
    match body {
        Some(Value::String(s)) => {
            out.body = Some(s.clone());
            out.body_len = Some(s.len());
        }
        Some(Value::Array(a)) => {
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
            let pair = header_parts(h).and_then(|(n, v)| n.as_str().zip(v.as_str())).map(|(n, v)| (n.to_string(), v.to_string()));
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

/// A start or end tag. It ends at the first `>` outside a quoted attribute
/// value: `title="<b>a</b>"` is valid HTML, and Solid, Svelte and hand-written
/// templates leave `<` or `>` in attribute values. A quote opens a value only
/// after `=`; an unclosed one is an ordinary character.
static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<(/?)([a-zA-Z][a-zA-Z0-9-]*)\b(?:[^>"'=]|=[\t\n\x0C\r ]*"[^"]*"|=[\t\n\x0C\r ]*'[^']*'|[="'])*?(/?)>"#).unwrap());
/// Comments as a browser ends them (`<!-->` and `<!--->` are empty), the
/// doctype, and bogus comments such as the empty `<!>` that Leptos puts
/// between adjacent text nodes: a browser shows `18<!>%` as `18%`.
const COMMENTS: &str = r"<!--(?:-?>|.*?--!?>)|<[!?][^>]*>";
pub(crate) static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!("(?s){COMMENTS}")).unwrap());
/// What a page doesn't show, in the order a browser reads it: comments,
/// and the code in scripts and style sheets (hydration data, CSS).
static HIDDEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?is){COMMENTS}|<script\b[^>]*>.*?</script\s*>|<style\b[^>]*>.*?</style\s*>")).unwrap());
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
/// `markup_problem` runs on every response. `last_gt` is the last `>` in `s`.
fn next_tag(s: &str, from: usize, last_gt: Option<usize>) -> Option<Tag<'_>> {
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
        let Some(gt) = tag_end(b, end_name, last_gt) else { continue };
        let self_closing = gt > end_name && b[gt - 1] == b'/';
        return Some(Tag { end: gt + 1, close, name: &s[start..end_name], self_closing });
    }
    None
}

/// The `>` that ends a tag whose name ends at `from`, as `TAG` finds it: the
/// first one outside a quoted value. A quoted value is skipped when it
/// closes and a `>` comes after it.
fn tag_end(b: &[u8], from: usize, last_gt: Option<usize>) -> Option<usize> {
    let mut i = from;
    loop {
        let j = i + memchr::memchr2(b'>', b'=', &b[i..])?;
        if b[j] == b'>' {
            return Some(j);
        }
        let v = j + 1 + b[j + 1..].iter().take_while(|c| matches!(c, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')).count();
        i = match b.get(v) {
            Some(&q @ (b'"' | b'\'')) => match memchr::memchr(q, &b[v + 1..]).map(|k| v + 1 + k) {
                Some(end) if last_gt.is_some_and(|g| g > end) => end + 1,
                _ => j + 1,
            },
            _ => j + 1,
        };
    }
}

pub fn markup_problem(body: &str) -> Option<String> {
    let body = COMMENT.replace_all(body, "");
    let lower = body.to_ascii_lowercase();
    let last_gt = memchr::memrchr(b'>', body.as_bytes());
    let mut stack: Vec<String> = Vec::new();
    let mut pos = 0;
    while let Some(t) = next_tag(&body, pos, last_gt) {
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

/// Percentages outside 0–100 in a text (`400 %`, `-5%`), as a page shows
/// it: CSS such as `translate(-50%)` is no percentage the user reads.
pub fn impossible_percentages(text: &str) -> Vec<String> {
    let text = shown(text);
    PERCENT
        .captures_iter(&text)
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
    let resp = response(r, m);
    if resp.body.is_none() {
        // Request-to-host flow does not depend on the export producing a body.
        out.extend(flow(r, m, &resp, ""));
    }
    // A plain module answers by sending a response; ending without one
    // leaves the client waiting.
    if r.outcome.kind == crate::record::OutcomeKind::Ok && r.result.is_none() && m.host.as_ref().is_some_and(|h| h.platform.start.is_some()) {
        out.push(Finding::new("invalid_response", &format!("{ex}\0none"), Severity::Fail, format!("{ex} ends without sending a response"), json!({}), run));
        return out;
    }
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
    let body = &body[..body.floor_char_boundary(1 << 20)];
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
    // In HTML only the text counts: a short error text like `progress`
    // (generated from a string in the binary) is in `<progress>` too. The
    // text is read decoded: renderers escape the quotes of an error text.
    // Most runs have no error texts: the body is read only when needed.
    let view = std::cell::OnceCell::new();
    let shows = |t: &str| view.get_or_init(|| error_view(&resp, body)).contains(t);
    if let Some(line) = r.stderr.lines().map(str::trim).find(|l| l.len() >= 20 && (body.contains(*l) || shows(l))) {
        leaks.push(format!("stderr line {:?}", line.chars().take(80).collect::<String>()));
    }
    // An error text counts only if no other input carries it too.
    let mut other = BTreeSet::new();
    r.spec.args.iter().for_each(|a| strings(a, &mut other));
    r.events.iter().filter_map(|e| e.result.as_ref()).filter(|v| v.get("err").is_none()).for_each(|v| strings(v, &mut other));
    let errs = host_errors(r, m);
    let shown: Vec<&(String, String)> = errs.iter().filter(|(_, t)| shows(t) && !other.iter().any(|o| o.contains(t.as_str()))).collect();
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
        strings(&Value::Object(e.text_args().into_owned()), &mut s);
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
        let script = doc.elements.iter().find(|e| e.is_script() && e.body.as_ref().is_some_and(|b| b.contains(&marked)));
        match script {
            Some(e) if is_js(e.get("type")) => return Some(("script", "into a script unescaped, where `</script>` in it ends the script".into())),
            Some(_) => return Some(("json", "into a data block unescaped, where `</script>` in it ends the block".into())),
            // `<` needs no escape in a quoted attribute value: there the
            // canary's `<i>` is text, and only its quote can break out.
            None if outside_quoted_values(body).contains(&marked) => return Some(("text", "into its HTML output unescaped".into())),
            None => {}
        }
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

/// The markup without the values of quoted attributes: what a browser
/// reads as text and tags. Elements whose content is text (`noscript`
/// with scripting on, `style`, `textarea`, …) keep it whole: a quote in
/// there starts no attribute value, and inside SVG a style is markup.
fn outside_quoted_values(body: &str) -> String {
    let b = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let (mut i, mut last) = (0, 0);
    let skip_to = |from: usize, end: &str| body[from..].find(end).map_or(b.len(), |p| from + p + end.len());
    while i < b.len() {
        if body[i..].starts_with("<!--") {
            i = skip_to(i, "-->");
        } else if b[i] == b'<' && b.get(i + 1).is_some_and(u8::is_ascii_alphabetic) {
            let name_end = b[i + 1..].iter().position(|c| !c.is_ascii_alphanumeric()).map_or(b.len(), |p| i + 1 + p);
            let name = body[i + 1..name_end].to_ascii_lowercase();
            let mut j = name_end;
            while j < b.len() && b[j] != b'>' {
                if b[j] == b'=' {
                    let k = b[j + 1..].iter().position(|c| !c.is_ascii_whitespace()).map_or(b.len(), |p| j + 1 + p);
                    if let Some(&q) = b.get(k).filter(|c| matches!(c, b'"' | b'\'')) {
                        let end = b[k + 1..].iter().position(|c| *c == q).map_or(b.len(), |p| k + 1 + p);
                        out.push_str(&body[last..=k]);
                        last = end;
                        j = end + 1;
                        continue;
                    }
                }
                j += 1;
            }
            i = j + 1;
            if matches!(name.as_str(), "script" | "style" | "noscript" | "textarea" | "title" | "xmp" | "iframe" | "noembed" | "noframes") && i < b.len() {
                let close = format!("</{name}");
                i = body[i..].to_ascii_lowercase().find(&close).map_or(b.len(), |p| i + p);
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&body[last.min(b.len())..]);
    out
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
    if e.is_script()
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
    let (i, roles) = crate::fuzz::request_fields_of(m);
    let inside = if i == 0 { Some(p.as_str()) } else { path.strip_prefix(&format!("@{i}.")) };
    if let (Some(req), Some(inside)) = (args.get(i), inside) {
        let roles = &roles;
        for (role, say) in [("query", "the query parameter"), ("form", "the form field")] {
            if let Some(k) = crate::fuzz::role_path(roles, req, role).and_then(|f| inside.strip_prefix(&format!("{f}.")).map(str::to_string)) {
                return format!("{say} `{k}`");
            }
        }
        if crate::fuzz::role_path(roles, req, "path").is_some_and(|f| f == inside) {
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

/// Entities decoded as a browser shows them. Renderers escape quotes in
/// text (React `&#x27;`, Vue `&#39;`, maud `&quot;`) and templates write
/// `&nbsp;` between a number and its unit.
fn decode(s: &str) -> String {
    crate::urls::decode_entities(&s.replace("&nbsp;", "\u{a0}"))
}

/// The text a browser shows of a body: without comments, scripts, style
/// sheets and tags (a tag ends a word), entities decoded. Server renderers
/// mark text node boundaries with comments and put hydration data into
/// scripts; read this way, their pages and plain markup agree.
fn shown(body: &str) -> String {
    let text = HIDDEN.replace_all(body, |c: &regex::Captures| if c[0].starts_with("<!") || c[0].starts_with("<?") { "" } else { " " });
    decode(&TAG.replace_all(&text, " "))
}

/// The text of an HTML body without its tags, and with attribute values
/// kept (a `title` or `value` shows text too), entities decoded.
fn visible_text(body: &str) -> String {
    static VALUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap());
    let body = COMMENT.replace_all(body, "");
    let mut out = TAG.replace_all(&body, " ").into_owned();
    for tag in TAG.find_iter(&body) {
        for c in VALUE.captures_iter(tag.as_str()) {
            out.push(' ');
            out.push_str(c.get(1).or(c.get(2)).map_or("", |m| m.as_str()));
        }
    }
    decode(&out)
}

/// The visible text of a body as a bag of words, for order-insensitive
/// comparison.
pub fn word_bag(body: &str) -> Vec<String> {
    let mut w: Vec<String> = shown(body).split_whitespace().map(str::to_string).collect();
    w.sort();
    w
}

#[cfg(test)]
mod tests {
    #[test]
    fn script_execution_contexts_keep_their_namespaces() {
        assert!(super::attack_runs("<math><script>alert(1)</script></math>").is_none());
        for html in [
            "<script>alert(1)</script>",
            "<svg><script>alert(1)</script></svg>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
        ] {
            assert_eq!(super::attack_runs(html).map(|v| v.0), Some("script"), "{html}");
        }
        assert_eq!(super::attack_runs("<math><mrow onclick='alert(1)'>x</mrow></math>").map(|v| v.0), Some("handler"));
    }

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
        let alphabet = ['<', '/', '>', 'a', 'B', '1', '-', '_', ' ', 'é', '\u{301}', '=', '"', '\'', '\t', '\n'];
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for _ in 0..200_000 {
            let n = rng.random_range(0..24);
            let s: String = (0..n).map(|_| alphabet[rng.random_range(0..alphabet.len())]).collect();
            let last_gt = memchr::memrchr(b'>', s.as_bytes());
            let mut want = Vec::new();
            let mut pos = 0;
            while let Some(c) = TAG.captures_at(&s, pos) {
                pos = c.get(0).unwrap().end();
                want.push((pos, !c[1].is_empty(), c[2].to_string(), !c[3].is_empty()));
            }
            let mut got = Vec::new();
            let mut pos = 0;
            while let Some(t) = next_tag(&s, pos, last_gt) {
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
        // Server renderers mark text node boundaries with comments.
        assert!(visible_text("<p>Booked by <!>Ann<!-- x > y --></p>").contains("Booked by Ann"));
        assert_eq!(word_bag("<span>#<!>1</span> x"), word_bag("<span>#1</span> x"));
    }

    #[test]
    fn percentages() {
        assert_eq!(impossible_percentages("used 40 % of 400% and -5%"), vec!["400%".to_string(), "-5%".to_string()]);
        assert_eq!(impossible_percentages("<p>200<!>%<span> booked</span></p>"), vec!["200%".to_string()]);
    }

    /// `<` needs no escape in a quoted attribute value, and some SSR
    /// frameworks escape only `&` and `"` there. The quote is escaped, so
    /// the value can't end, and the canary's raw `<i>` is text.
    #[test]
    fn raw_markup_inside_a_quoted_attribute_is_no_reflection() {
        assert_eq!(breakout(r#"<p title="cnry12341<i>'&quot;">x</p>"#, "cnry12341"), None);
        assert_eq!(breakout(r#"<p title='cnry12341<i>&#39;"'>x</p>"#, "cnry12341"), None);
        assert_eq!(breakout(r#"<p title="cnry12341<i>'"">x</p>"#, "cnry12341").map(|v| v.0), Some("attribute"));
        // Text is text, also after such an attribute or a script with tags in strings.
        for body in [
            r#"<p title="cnry12341<i>'&quot;">cnry12341<i>'"</p>"#,
            r#"<script>var s = '<a href="';</script><p>cnry12341<i>'"</p>"#,
            r#"<p class=x>cnry12341<i>'"</p>"#,
            // With scripting on, a noscript's content is text: its `</noscript>` ends it.
            r#"<noscript><p title="cnry12341<i>'&quot;">Turn on JavaScript</p></noscript>"#,
            // Inside SVG a style holds markup.
            r#"<svg><style>.i-cnry12341<i>'" { fill: red }</style></svg>"#,
        ] {
            assert_eq!(breakout(body, "cnry12341").map(|v| v.0), Some("text"), "{body}");
        }
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

    // Server renderers. The text checks must read what a browser shows, so
    // a page as a renderer sends it gives the same result as plain markup.
    // "Verified" samples follow the renderer's source (maud 0.27, tachys
    // 0.2 / Leptos 0.8, React's server renderer, Vue 3.5's server renderer
    // and @vue/shared); the others are from memory and say so.

    /// The host error the page shows: a Postgres error, quotes and all.
    const DB_ERROR: &str = r#"relation "bookings" does not exist"#;

    /// What a browser shows, as plain hand-written markup.
    const PLAIN: &str = r#"<!DOCTYPE html><html><head><title>Bookings</title></head><body><h1>Bookings</h1><p>Booked by Ann and Bob</p><p class="usage">Usage: 200%</p><p class="error">relation "bookings" does not exist</p></body></html>"#;
    const PLAIN_FRAGMENT: &str =
        r#"<h1>Bookings</h1><p>Booked by Ann and Bob</p><p class="usage">Usage: 200%</p><p class="error">relation "bookings" does not exist</p>"#;

    /// (renderer, the page as it sends it, a fragment without `<html>`)
    const RENDERED: &[(&str, &str, bool)] = &[
        // Verified: plain HTML; `&<>"` escaped, in text too.
        (
            "maud",
            r#"<!DOCTYPE html><html><head><title>Bookings</title></head><body><h1>Bookings</h1><p>Booked by Ann and Bob</p><p class="usage">Usage: 200%</p><p class="error">relation &quot;bookings&quot; does not exist</p></body></html>"#,
            false,
        ),
        // Verified: `<!>` before a text node that follows text, `&<>`
        // escaped in text, the hydration bootstrap script, and resources
        // serialised for hydration as the host returned them. Where the
        // view macro splits static text is an approximation.
        (
            "leptos 0.8",
            r##"<!DOCTYPE html><html><head><title>Bookings</title><script type="module">(function (root, pkg_path, output_name, wasm_output_name, defer) { const hydrate = () => import(`${root}/${pkg_path}/${output_name}.js`).then(mod => { mod.default({module_or_path: `${root}/${pkg_path}/${wasm_output_name}.wasm`}).then(() => { mod.hydrate(); }); }); if (defer && "requestIdleCallback" in window) { window.requestIdleCallback(hydrate, { timeout: 2000 }); } else { hydrate(); } })("", "pkg", "bookings", "bookings", false);</script></head><body><h1>Bookings</h1><p>Booked by <!>Ann<!> and <!>Bob</p><p class="usage">Usage: <!>200<!>%</p><p class="error">relation "bookings" does not exist</p><script>__RESOLVED_RESOURCES[0] = "[{\"name\":\"Ann\"},{\"name\":\"Bob\"}]";</script></body></html>"##,
            false,
        ),
        // Verified: `<!-- -->` between adjacent text, `"&'<>` escaped
        // (`'` as `&#x27;`). The Suspense boundary `<!--$-->…<!--/$-->`
        // is React 18's, from memory.
        (
            "react renderToString",
            r#"<html><head><title>Bookings</title></head><body><h1>Bookings</h1><!--$--><p>Booked by <!-- -->Ann<!-- --> and <!-- -->Bob</p><p class="usage">Usage: <!-- -->200<!-- -->%</p><!--/$--><p class="error">relation &quot;bookings&quot; does not exist</p></body></html>"#,
            false,
        ),
        // From memory: Svelte 5's markers `<!--[-->`, `<!--]-->` and
        // `<!---->`, scoped classes, `&<` escaped in text, and the style
        // sheet `css: "injected"` puts in the head. Placement approximate.
        (
            "svelte 5",
            r#"<!doctype html><html><head><title>Bookings</title><style id="svelte-1x2y3z">.usage.svelte-1x2y3z{color:teal}.dialog.svelte-1x2y3z{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%)}</style></head><body><!--[--><h1>Bookings</h1><!----> <p>Booked by Ann and Bob</p> <p class="usage svelte-1x2y3z">Usage: 200%</p> <!--[--><p class="error svelte-1x2y3z">relation "bookings" does not exist</p><!--]--> <dialog class="dialog svelte-1x2y3z"></dialog><!--]--></body></html>"#,
            false,
        ),
        // Verified: fragments `<!--[-->…<!--]-->`, `<!---->` for a false
        // v-if, `"&'<>` escaped. Scoped `data-v-…` attributes and Nuxt's
        // `__NUXT_DATA__` payload are from memory.
        (
            "vue 3",
            r#"<!DOCTYPE html><html><head><title>Bookings</title></head><body><div id="__nuxt"><!--[--><h1 data-v-7fa5cd90>Bookings</h1><p data-v-7fa5cd90>Booked by Ann and Bob</p><p class="usage" data-v-7fa5cd90>Usage: 200%</p><!--[--><p class="error" data-v-7fa5cd90>relation &quot;bookings&quot; does not exist</p><!--]--><!----><!--]--></div><script type="application/json" data-nuxt-data="nuxt-app" data-ssr="true" id="__NUXT_DATA__">[["ShallowReactive",1],{"data":2},{"bookings":3},["Ann","Bob"]]</script></body></html>"#,
            false,
        ),
        // From memory: `data-hk` attributes, `<!--$-->…<!--/-->` around
        // inserted values, the `_$HY` bootstrap and a hydration payload.
        (
            "solid",
            r#"<!DOCTYPE html><html><head><title>Bookings</title><script>window._$HY||(e=>{let t=e=>e&&e.hasAttribute&&(e.hasAttribute("data-hk")?e:t(e.host&&e.host.nodeType?e.host:e.parentNode));["click","input"].forEach((o=>document.addEventListener(o,(o=>{if(!e.events)return;let s=t(o.composedPath&&o.composedPath()[0]||o.target);s&&!e.completed.has(s)&&e.events.push([s,o])}))))})(window._$HY={events:[],completed:new WeakSet,r:{}});</script></head><body><h1 data-hk="0-0-0-0">Bookings</h1><p data-hk="0-0-0-1">Booked by <!--$-->Ann<!--/--> and <!--$-->Bob<!--/--></p><p class="usage" data-hk="0-0-0-2">Usage: <!--$-->200<!--/-->%</p><p class="error" data-hk="0-0-0-3">relation "bookings" does not exist</p><script>_$HY.r["0-0-0-4"]=[{name:"Ann"},{name:"Bob"}];</script></body></html>"#,
            false,
        ),
        // An htmx fragment: plain markup, no `<html>` or `<body>`.
        (
            "htmx fragment",
            r#"<div id="bookings" hx-swap-oob="true"><h1>Bookings</h1><p>Booked by Ann and Bob</p><p class="usage">Usage: 200%</p><p class="error">relation "bookings" does not exist</p></div>"#,
            true,
        ),
    ];

    fn plain(fragment: bool) -> &'static str {
        if fragment { PLAIN_FRAGMENT } else { PLAIN }
    }

    /// A run of export `h` with the request `args` that returned `result`,
    /// after host calls `(func, args, result)`.
    fn run_of(args: Value, result: Value, calls: Vec<(&str, Value, Value)>, stderr: &str) -> RunRecord {
        crate::envelope::Trace {
            export: "h".into(),
            args: vec![args],
            events: calls
                .into_iter()
                .map(|(f, a, r)| crate::envelope::TraceCall {
                    func: f.into(),
                    args: a.as_object().cloned().unwrap_or_default(),
                    result: Some(r),
                    ..Default::default()
                })
                .collect(),
            result: Some(result),
            stderr: stderr.into(),
            ..Default::default()
        }
        .to_record()
    }

    /// A GET that answered 200 with the HTML page `body`.
    fn page_run(body: &str, calls: Vec<(&str, Value, Value)>, stderr: &str) -> RunRecord {
        let result = json!({"status": 200, "headers": [["content-type", "text/html; charset=utf-8"]], "body": body});
        run_of(json!({"method": "GET", "path": "/bookings"}), result, calls, stderr)
    }

    fn site() -> Manifest {
        toml::from_str("[app]\nwasm = 'a.wasm'\n[entry]\nexport = 'h'\noutput = { status = 'status', body = 'body', headers = 'headers' }\n").unwrap()
    }

    fn kinds(findings: Vec<Finding>) -> Vec<String> {
        let mut k: Vec<String> = findings.into_iter().map(|f| f.kind).collect();
        k.sort();
        k
    }

    fn db_error() -> Vec<(&'static str, Value, Value)> {
        vec![("acme:db/bookings#list", json!({}), json!({"err": DB_ERROR}))]
    }

    #[test]
    fn rendered_pages_show_the_same_percentages() {
        assert_eq!(impossible_percentages(PLAIN), ["200%"]);
        for (renderer, page, fragment) in RENDERED {
            assert_eq!(impossible_percentages(page), impossible_percentages(plain(*fragment)), "{renderer}");
        }
    }

    #[test]
    fn rendered_pages_show_the_same_words() {
        for (renderer, page, fragment) in RENDERED {
            assert_eq!(word_bag(page), word_bag(plain(*fragment)), "{renderer}");
        }
    }

    #[test]
    fn rendered_pages_are_well_formed() {
        assert_eq!(markup_problem(PLAIN), None);
        for (renderer, page, _) in RENDERED {
            assert_eq!(markup_problem(page), None, "{renderer}");
            // An element left open is found through the markers too.
            let open = page.replacen("</h1>", "", 1);
            assert!(markup_problem(&open).is_some_and(|p| p.contains("<h1>")), "{renderer}");
        }
        // React 18 streaming placeholders, Vue teleports, Svelte's else branch.
        for page in [
            r#"<!--$?--><template id="B:0"></template><p>Loading</p><!--/$-->"#,
            "<!--teleport start--><!--teleport end--><div><!--teleport start anchor--><!--teleport anchor--></div>",
            "<!--[!--><p>No bookings</p><!--]-->",
            "<table><tbody><!--[--><tr><td>Ann</td></tr><!--]--></tbody></table>",
        ] {
            assert_eq!(markup_problem(page), None, "{page}");
        }
    }

    #[test]
    fn every_renderer_leaks_the_error_text_alike() {
        let m = site();
        assert_eq!(kinds(check(&page_run(PLAIN, db_error(), ""), &m)), ["inconsistent_response", "leaky_error"]);
        for (renderer, page, _) in RENDERED {
            let found = check(&page_run(page, db_error(), ""), &m);
            let leak = found.iter().find(|f| f.kind == "leaky_error").map(|f| f.detail["error"]["text"].clone());
            assert_eq!(leak, Some(json!(DB_ERROR)), "{renderer}");
            assert_eq!(kinds(found), ["inconsistent_response", "leaky_error"], "{renderer}");
        }
    }

    #[test]
    fn hydration_data_is_not_what_the_page_shows() {
        // The page shows the names sorted; the hydration payload carries
        // them as the host returned them. Reversed, the payload is another
        // word, but the page is the same.
        let leptos = |data: &str| format!("<ul><li>Ann</li><li>Bob</li></ul><script>__RESOLVED_RESOURCES[0] = {data:?};</script>");
        assert_eq!(word_bag(&leptos(r#"[{"name":"Ann"},{"name":"Bob"}]"#)), word_bag(&leptos(r#"[{"name":"Bob"},{"name":"Ann"}]"#)));
        let nuxt = |data: &str| format!(r#"<ul><li>Ann</li><li>Bob</li></ul><script type="application/json" id="__NUXT_DATA__">{data}</script>"#);
        assert_eq!(word_bag(&nuxt(r#"[["Ann","Bob"]]"#)), word_bag(&nuxt(r#"[["Bob","Ann"]]"#)));
        assert_eq!(word_bag(&nuxt("[]")), ["Ann", "Bob"]);
    }

    #[test]
    fn percentages_as_a_browser_shows_them() {
        let p = impossible_percentages;
        // Entities and inline elements: each shows 200 %.
        assert_eq!(p("<p>200&#37;</p>"), ["200%"]);
        assert_eq!(p("<p>200&#x25;</p>"), ["200%"]);
        assert_eq!(p("<p>200&nbsp;%</p>"), ["200\u{a0}%"]);
        assert_eq!(p("<p>200\u{a0}%</p>"), ["200\u{a0}%"]);
        assert_eq!(p("<p><b>200</b>%</p>").len(), 1);
        assert_eq!(p("<p><span>-5</span><!-- -->%</p>"), ["-5 %"]);
        // Code is no text: CSS, scripts, data blocks, attributes.
        assert_eq!(p("<style>.dialog{top:50%;transform:translate(-50%,-50%)}</style><p>40%</p>"), Vec::<String>::new());
        assert_eq!(p(r#"<p style="width:150%">40%</p>"#), Vec::<String>::new());
        assert_eq!(p(r#"<div class="w-[200%] -translate-x-[50%]">40%</div>"#), Vec::<String>::new());
        assert_eq!(p("<script>const r = 1000 % 7;</script><p>40%</p>"), Vec::<String>::new());
        assert_eq!(p(r#"<script type="application/json">{"discount":"-20%"}</script>"#), Vec::<String>::new());
        // Comments and, in HTML, CDATA: a bogus comment up to the first `>`.
        assert_eq!(p("<p>a<!-- 250% -->b<![CDATA[250%]]>c<?php 250% ?></p>"), Vec::<String>::new());
        assert_eq!(p("<p><![CDATA[a > 250%]]></p>"), ["250%"]);
        // `<!-->` and `<!--->` are empty comments; `--!>` ends one too.
        assert_eq!(p("<p><!-->250%<!-- x --></p>"), ["250%"]);
        assert_eq!(p("<p><!--->-5%<!-- x --></p>"), ["-5%"]);
        assert_eq!(p("<p><!-- x --!>300%<!-- y --></p>"), ["300%"]);
        // A JSON or text body has no markup to remove.
        assert_eq!(p(r#"{"usage": "250%"}"#), ["250%"]);
        assert_eq!(p("usage: 250 % (a < b)"), ["250 %"]);
    }

    #[test]
    fn word_bags_read_entities_and_skip_code() {
        // React, Vue and maud escape what Leptos and Svelte send as it is.
        let want = word_bag(r#"<p>Ann's "Deluxe" room & breakfast</p>"#);
        for sent in [
            "<p>Ann&#x27;s &quot;Deluxe&quot; room &amp; breakfast</p>",
            "<p>Ann&#39;s &quot;Deluxe&quot; room &amp; breakfast</p>",
            "<p>Ann's &quot;Deluxe&quot; room &amp; breakfast</p>",
            "<p>Ann's <!>\"Deluxe\"<!> room &amp; breakfast</p>",
        ] {
            assert_eq!(word_bag(sent), want, "{sent}");
        }
        assert_eq!(word_bag("<p>12&nbsp;rooms</p>"), word_bag("<p>12\u{a0}rooms</p>"));
        // An escaped entity is text.
        assert_eq!(word_bag("<p>a&amp;nbsp;b</p>"), ["a&nbsp;b"]);
        // Scripts, styles, comments and attributes add no words.
        assert_eq!(word_bag(r#"<style>.a{color:red}</style><script>var x = "hidden";</script><p title="tip" data-hk="0-0">Hi<!-- note --></p>"#), ["Hi"]);
        // `<` that starts no tag is text.
        assert_eq!(word_bag("<p>1 < 2</p>"), ["1", "2", "<"]);
        // Attribute values with `>` in them (Svelte leaves it) end no tag.
        assert_eq!(word_bag(r#"<p x-show="n > 0" title="a > b">Hi</p>"#), ["Hi"]);
    }

    #[test]
    fn markup_inside_quoted_attribute_values_is_text() {
        // Valid HTML a browser reads as one tag each: Bootstrap popovers,
        // Alpine expressions, renderers that leave `<` and `>` in values.
        for ok in [
            r#"<button data-bs-content="<b>Hi</b>">x</button>"#,
            r#"<div x-html="open ? '<b>Open</b>' : '<i>Closed</i>'"></div>"#,
            r#"<p title='<em>x</em>'>y</p>"#,
            r#"<p title = "</p>">y</p>"#,
            r#"<div x-show="n > 0"><span>x</span></div>"#,
        ] {
            assert_eq!(markup_problem(ok), None, "{ok}");
        }
        // A quote that never closes is an ordinary character…
        assert_eq!(markup_problem(r#"<p title=a"b>x</p>"#), None);
        assert_eq!(markup_problem(r#"<p title="x>y</p>"#), None);
        // …and one that swallows an end tag leaves its element open, as in
        // a browser.
        assert_eq!(markup_problem(r#"<div><p class="a>x</p></div><p class="b">y</p>"#).as_deref(), Some("<div> is never closed"));
    }

    #[test]
    fn leaky_errors_read_escaped_text() {
        let m = site();
        let shown = |page: &str, t: &str| {
            let calls = vec![("acme:db/bookings#list", json!({}), json!({"err": t}))];
            kinds(check(&page_run(page, calls, ""), &m)).contains(&"leaky_error".to_string())
        };
        let t = r#"can't reach "db-7.internal:5432""#;
        for page in [
            "<p>can&#x27;t reach &quot;db-7.internal:5432&quot;</p>",
            "<p>can&#39;t reach &quot;db-7.internal:5432&quot;</p>",
            "<p>can't reach &quot;db-7.internal:5432&quot;</p>",
            r#"<p>can't reach <!>"db-7.internal:5432"</p>"#,
            r#"<input value="can&#39;t reach &quot;db-7.internal:5432&quot;">"#,
        ] {
            assert!(shown(page, t), "{page}");
        }
        // Only in a style sheet: not shown. In hydration data: sent to the
        // browser, as Leptos serialises an error boundary's errors.
        let t = "could not reach db-7.internal:5432";
        assert!(!shown(&format!("<style>/* {t} */</style><p>Sorry.</p>"), t));
        assert!(shown(&format!("<p>Sorry.</p><script>__SERIALIZED_ERRORS.push([0, 0, {t:?}]);</script>"), t));
        // A stderr line, escaped by the renderer.
        let line = r#"error: relation "bookings" does not exist at character 15"#;
        let r = page_run("<pre>error: relation &quot;bookings&quot; does not exist at character 15</pre>", vec![], line);
        assert_eq!(kinds(check(&r, &m)), ["leaky_error"]);
        // Panic text, escaped by React.
        let r = page_run("<pre>thread &#x27;main&#x27; panicked at src/lib.rs:12:5</pre>", vec![], "");
        let found = check(&r, &m);
        assert_eq!(found[0].detail["leaks"], json!(["panic text"]));
    }

    #[test]
    fn errors_meant_for_users_or_echoed_are_no_leak() {
        let t = "could not reach db-7.internal:5432";
        let page = format!("<p>{t}</p>");
        let calls = || vec![("acme:db/bookings#list", json!({}), json!({"err": t}))];
        // Error texts written for users.
        let m = site();
        let users: Manifest = toml::from_str(
            "[app]\nwasm = 'a.wasm'\n[entry]\nexport = 'h'\noutput = { status = 'status', body = 'body', headers = 'headers' }\n[functions.\"acme:db/bookings#list\"]\nuser_errors = true\n",
        )
        .unwrap();
        assert_eq!(kinds(check(&page_run(&page, calls(), ""), &users)), Vec::<String>::new());
        // A text the request carries too, and a short one.
        let result = json!({"status": 200, "headers": [["content-type", "text/html"]], "body": page});
        let r = run_of(json!({"method": "GET", "q": t}), result.clone(), calls(), "");
        assert_eq!(kinds(check(&r, &m)), Vec::<String>::new());
        let short = run_of(json!({}), json!({"status": 200, "body": "<p>timeout</p>"}), vec![("f", json!({}), json!({"err": "timeout"}))], "");
        assert_eq!(kinds(check(&short, &m)), Vec::<String>::new());
        // Panic text the app got as input; a short stderr line.
        let r = run_of(json!({"q": "it panicked at noon"}), json!({"status": 200, "body": "<p>it panicked at noon</p>"}), vec![], "panicked");
        assert_eq!(kinds(check(&r, &m)), Vec::<String>::new());
        // An error status: a leak, but no inconsistency.
        let r = run_of(json!({}), json!({"status": 503, "headers": [["content-type", "text/html"]], "body": format!("<p>{t}</p>")}), calls(), "");
        assert_eq!(kinds(check(&r, &m)), ["leaky_error"]);
    }

    #[test]
    fn renderer_escaping_is_no_reflection() {
        let id = "cnry12341";
        let ctx = |b: &str| breakout(b, id).map(|(c, _)| c);
        // Escaped as each renderer escapes text and attribute values.
        for safe in [
            r#"<p>Hi <!-- -->cnry12341&lt;i&gt;&#x27;&quot;</p>"#,
            r#"<p>Hi cnry12341&lt;i&gt;&#39;&quot;</p>"#,
            r#"<p>Hi <!>cnry12341&lt;i&gt;'"</p>"#,
            r#"<p title="cnry12341&lt;i&gt;'&quot;">x</p>"#,
            r#"<!--[--><p>Hi cnry12341&lt;i>'"</p><!--]-->"#,
            r#"<p title="cnry12341&lt;i>'&quot;">x</p>"#,
            r#"<p data-hk="0-0-0-1">Hi <!--$-->cnry12341&lt;i>'"<!--/--></p>"#,
        ] {
            assert_eq!(ctx(safe), None, "{safe}");
        }
        // Raw HTML through each renderer's escape hatch, between its markers.
        for raw in [
            r#"<!--$--><div>cnry12341<i>'"</div><!--/$-->"#,
            r#"<!--[--><div><!---->cnry12341<i>'"<!----></div><!--]-->"#,
            r#"<div data-v-7fa5cd90>cnry12341<i>'"</div>"#,
            r#"<div>Hi <!>cnry12341<i>'"</div>"#,
        ] {
            assert_eq!(ctx(raw), Some("text"), "{raw}");
        }
        // Leptos's hydration data: JSON in a Debug-quoted string, `<` as
        // `<`, so the canary's quote can't end it.
        let data = format!("{:?}", r#"[{"name":"cnry12341<i>'\""}]"#.replace('<', "\\u003c"));
        assert_eq!(ctx(&format!("<li>cnry12341&lt;i&gt;'\"</li><script>__RESOLVED_RESOURCES[0] = {data};</script>")), None);
    }

    #[test]
    fn canaries_through_framework_markup() {
        let m = site();
        let c = canary(1);
        let id = &c[..c.find('<').unwrap()];
        let html = |body: String| json!({"status": 200, "headers": [["content-type", "text/html"]], "body": body});
        let args = json!({"method": "GET", "query": [["q", c]]});
        // A request canary raw in a React Suspense boundary.
        let found = check(&run_of(args.clone(), html(format!("<!--$--><p>{c}</p><!--/$-->")), vec![], ""), &m);
        assert_eq!(kinds(found.clone()), ["reflection"]);
        assert_eq!((found[0].detail["field"].as_str(), found[0].severity), (Some("query.q"), Severity::Fail));
        assert!(found[0].title.contains("the query parameter `q`"), "{}", found[0].title);
        // Escaped by the renderer: nothing.
        let escaped = format!("<p>{id}&lt;i&gt;&#x27;&quot;</p>");
        assert_eq!(kinds(check(&run_of(args.clone(), html(escaped), vec![], ""), &m)), Vec::<String>::new());
        // A host canary raw, in Svelte's markers: stored reflection.
        let calls = vec![("acme:cms/pages#get", json!({}), json!({"ok": {"title": c}}))];
        let found = check(&run_of(json!({}), html(format!("<!--[--><h1>{c}</h1><!--]-->")), calls, ""), &m);
        assert_eq!(kinds(found.clone()), ["stored_reflection"]);
        assert_eq!(found[0].detail["func"], "acme:cms/pages#get");
        // The request canary unchanged in a host call: passthrough (info),
        // unless the field has a role meant for the host.
        let calls = || vec![("acme:db/search#run", json!({"term": c}), json!({"ok": []}))];
        let found = check(&run_of(args.clone(), json!({"status": 200, "body": "ok"}), calls(), ""), &m);
        assert_eq!(kinds(found.clone()), ["input_passthrough"]);
        assert_eq!((found[0].detail["exact"].as_bool(), found[0].severity), (Some(true), Severity::Info));
        let mut roles = site();
        roles.entry.as_mut().unwrap().fields.insert("today".into(), "clock.date".into());
        let dated = json!({"method": "GET", "today": c});
        let calls_dated = vec![("acme:db/search#run", json!({"day": c}), json!({"ok": []}))];
        assert_eq!(kinds(check(&run_of(dated, json!({"status": 200, "body": "ok"}), calls_dated, ""), &roles)), Vec::<String>::new());
        // Without a body, the passthrough is still found.
        let found = check(&run_of(args, json!({"status": 204}), calls(), ""), &m);
        assert_eq!(kinds(found), ["input_passthrough"]);
        // An attack string that runs in a Vue page's script.
        let attack = json!({"query": [["q", "';alert(1)//"]]});
        let page = html("<!--[--><script>var q = '';alert(1)//';</script><!--]-->".into());
        let found = check(&run_of(attack, page, vec![], ""), &m);
        assert_eq!((kinds(found.clone()), found[0].detail["context"].as_str()), (vec!["reflection".to_string()], Some("script")));
    }

    #[test]
    fn trusted_markup_is_no_stored_reflection() {
        let m: Manifest = toml::from_str(
            "[app]\nwasm = 'a.wasm'\n[entry]\nexport = 'h'\noutput = { status = 'status', body = 'body', headers = 'headers' }\n[functions.\"acme:cms/pages#get\"]\nresult = { html = \"html\" }\n",
        )
        .unwrap();
        let c = canary(2);
        let calls = vec![("acme:cms/pages#get", json!({}), json!({"html": c}))];
        let r = run_of(json!({}), json!({"status": 200, "headers": [["content-type", "text/html"]], "body": format!("<article>{c}</article>")}), calls, "");
        assert_eq!(kinds(check(&r, &m)), Vec::<String>::new());
    }

    #[test]
    fn framework_fragments_are_read_as_html() {
        // Headers without a content type: a browser sniffs the start.
        let sniffed: Manifest = toml::from_str("[app]\nwasm = 'a.wasm'\n[entry]\nexport = 'h'\noutput = { body = 'body', headers = 'headers' }\n").unwrap();
        let html = |m: &Manifest, body: &str| response(&run_of(json!({}), json!({"body": body, "headers": []}), vec![], ""), m).html;
        for page in
            ["<!--[--><p>Hi</p><!--]-->", "<!--$--><div>Hi</div><!--/$-->", r#"<div data-hk="0-0-0-0">Hi</div>"#, "\n<!DOCTYPE html><html>", "<p>a<!>b</p>"]
        {
            assert!(html(&sniffed, page), "{page}");
        }
        // htmx swaps rows and list items in; opened on their own, a browser
        // shows them as text. Without headers, any tag is markup.
        let body_only: Manifest = toml::from_str("[app]\nwasm = 'a.wasm'\n[entry]\nexport = 'h'\noutput = { body = 'body' }\n").unwrap();
        for fragment in ["<tr><td>Ann</td></tr>", "<li>Ann</li>", "<span>Ann</span>"] {
            assert!(!html(&sniffed, fragment), "{fragment}");
            assert!(html(&body_only, fragment), "{fragment}");
        }
        // The manifest's format, then the content type, decide.
        let format: Manifest =
            toml::from_str("[app]\nwasm = 'a.wasm'\n[entry]\nexport = 'h'\noutput = { body = 'body', headers = 'headers', body_format = 'html' }\n").unwrap();
        assert!(html(&format, "<tr><td>Ann</td></tr>"));
        let typed =
            |ct: &str| response(&run_of(json!({}), json!({"body": "<p>x</p>", "headers": [{"name": "Content-Type", "value": ct}]}), vec![], ""), &format);
        assert!(!typed("application/json").html);
        assert!(typed("text/html; charset=utf-8").html);
        assert_eq!(typed("text/plain").headers, [("Content-Type".to_string(), "text/plain".to_string())]);
    }

    #[test]
    fn responses_read_through_the_manifest() {
        let m = site();
        let status = |s: Value| response(&run_of(json!({}), json!({"status": s, "body": "x"}), vec![], ""), &m).status;
        assert_eq!(status(json!(" 201 ")), Some(201));
        assert_eq!(status(json!("ok")), None);
        assert_eq!(status(json!(true)), None);
        // Header entries as pairs or records; anything else is no header.
        let headers = json!([["a", "1"], {"key": "b", "value": "2"}, {"name": "c", "value": 3}, ["d", "4", "5"], "e"]);
        let r = response(&run_of(json!({}), json!({"headers": headers, "body": "x"}), vec![], ""), &m);
        assert_eq!(r.headers, [("a".into(), "1".into()), ("b".into(), "2".into())]);
        // A body that is not text or bytes is none; without a mapping the
        // whole string result is the body.
        assert!(response(&run_of(json!({}), json!({"body": {"html": "x"}}), vec![], ""), &m).body.is_none());
        let bare: Manifest = toml::from_str("[app]\nwasm = 'a.wasm'\n").unwrap();
        let r = response(&run_of(json!({}), json!("<p>Hi</p>"), vec![], ""), &bare);
        assert_eq!((r.body.as_deref(), r.html), (Some("<p>Hi</p>"), true));
        assert!(!is_body(&json!([1, 256])) && is_body(&json!([])) && !is_body(&json!(1)));
    }

    #[test]
    fn response_well_formedness() {
        let m = site();
        let check_of = |args: Value, result: Value| kinds(check(&run_of(args, result, vec![], ""), &m));
        let get = json!({"method": "GET"});
        assert_eq!(check_of(get.clone(), json!({"status": 0, "body": "ok"})), ["invalid_response"]);
        // One finding for the first bad header.
        let found = check(&run_of(get.clone(), json!({"status": 200, "headers": [["x y", "1"], ["x-a", "a\r\nb"]], "body": "ok"}), vec![], ""), &m);
        assert_eq!((found.len(), found[0].detail["header"].as_str()), (1, Some("x y")));
        assert_eq!(check_of(get.clone(), json!({"status": 200, "headers": [["x-a", "a\r\nSet-Cookie: s=1"]], "body": "ok"})), ["invalid_response"]);
        // Bytes that are not UTF-8: a warn as text, fine as an image.
        assert_eq!(check_of(get.clone(), json!({"status": 200, "headers": [], "body": [255, 216]})), ["invalid_response"]);
        assert_eq!(check_of(get.clone(), json!({"status": 200, "headers": [["content-type", "image/jpeg"]], "body": [255, 216]})), Vec::<String>::new());
        // Content-Length against the body, except where no body is sent.
        let sized = |status: i64, cl: &str| json!({"status": status, "headers": [["content-length", cl]], "body": "héllo"});
        assert_eq!(check_of(get.clone(), sized(200, "6")), Vec::<String>::new());
        assert_eq!(check_of(get.clone(), sized(200, "5")), ["invalid_response"]);
        assert_eq!(check_of(get.clone(), sized(200, "x")), ["invalid_response"]);
        assert_eq!(check_of(json!({"method": "head"}), sized(200, "999")), Vec::<String>::new());
        assert_eq!(check_of(get.clone(), sized(304, "999")), Vec::<String>::new());
        assert_eq!(check_of(get.clone(), sized(204, "999")), Vec::<String>::new());
        // Broken markup, but not where only a 1 MiB prefix is read.
        let html = |body: String| json!({"status": 200, "headers": [["content-type", "text/html"]], "body": body});
        assert_eq!(check_of(get.clone(), html("<div><span>x</div>".into())), ["broken_markup"]);
        assert_eq!(check_of(get.clone(), html(format!("<div>{}", "é".repeat(1 << 19)))), Vec::<String>::new());
        // A canary's markup is reflection, not broken markup.
        assert_eq!(check_of(json!({"q": canary(3)}), html(format!("<p>{}</p>", canary(3)))), ["reflection"]);
        // Scripts from elsewhere in HTML no output label covers: a warn.
        let found = check(&run_of(get.clone(), html(r#"<script src="https://cdn.example/react.js"></script><div id="root"></div>"#.into()), vec![], ""), &m);
        assert_eq!((kinds(found.clone()), found[0].severity), (vec!["unpinned_script".to_string()], Severity::Warn));
    }

    #[test]
    fn a_module_that_never_answers() {
        let mut m = site();
        m.host = Some(std::sync::Arc::new(toml::from_str("[platform]\nname = 'p'\nstart = '_start'\n").unwrap()));
        let mut r = run_of(json!({}), json!(null), vec![], "");
        r.result = None;
        assert_eq!(kinds(check(&r, &m)), ["invalid_response"]);
        assert_eq!(kinds(check(&r, &site())), Vec::<String>::new());
    }

    #[test]
    fn echo_reruns_change_error_texts() {
        assert_eq!(rot("Db-7 down!"), "Qo-2 qbja!");
        let texts = BTreeSet::from(["db-7 down".to_string()]);
        assert_eq!(swap(&json!({"err": ["x: db-7 down", 7, {"m": "db-7 down"}]}), &texts), json!({"err": ["x: qo-2 qbja", 7, {"m": "qo-2 qbja"}]}));
        let f = leaky("h", vec!["panic text".into(), "the error text f returned (\"db-7 down\")".into()], Some(("f", "db-7 down")), Some("r1"));
        assert_eq!((error_text(&f), f.severity, f.run.as_deref()), (Some("db-7 down"), Severity::Warn, Some("r1")));
        assert!(f.title.contains("panic text; the error text f returned"));
        assert_eq!(error_text(&leaky("h", vec!["panic text".into()], None, None)), None);
        let r = page_run("<p>db-7 down</p>", vec![("f", json!({}), json!({"err": "db-7 down"}))], "");
        let found = check(&r, &site());
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| error_text(f) == Some("db-7 down")), "{found:?}");
        assert_eq!(error_text(&Finding::new("crash", "x", Severity::Fail, "x".into(), json!({"error": "db-7 down"}), None)), None);
    }

    #[test]
    fn canary_shapes() {
        let u = url_canary(7);
        assert!(u.starts_with("https://cnry") && u.ends_with(".example/") && CANARY.is_match(&u) && !u.contains('<'));
        let bare: Manifest = toml::from_str("[app]\nwasm = 'a.wasm'\n").unwrap();
        assert_eq!(canary_for(&bare, 7), canary(7));
        let sinks: Manifest = toml::from_str("[app]\nwasm = 'a.wasm'\n[functions.\"acme:db/q#run\"]\nparams = { sql = \"sql\" }\n").unwrap();
        let c = canary_for(&sinks, 1);
        assert_eq!(c, format!("{}{SINK_TAIL}", canary(1)));
        // Each canary taken out in turn, with its markup and tail.
        let t = format!("a {c} b {u} c");
        assert_eq!(without_canaries(&t), [format!("a  b {u} c"), format!("a {c} b  c")]);
        // Canaries by request path; `[[name, value]]` pairs by name.
        let mut found = BTreeSet::new();
        canary_paths(&json!({"query": [["q", c]], "items": ["x", u], "n": 3, "pairs": []}), "@0".into(), &mut found);
        let ids: Vec<(String, String)> = found.into_iter().collect();
        assert_eq!(ids.iter().map(|(_, p)| p.as_str()).collect::<Vec<_>>(), ["@0.query.q", "@0.items.1"]);
    }

    #[test]
    fn script_types_that_run() {
        for t in [None, Some(""), Some("module"), Some("text/javascript"), Some(" Text/JavaScript; charset=utf-8"), Some("application/ecmascript")] {
            assert!(is_js(t), "{t:?}");
        }
        for t in ["application/json", "application/ld+json", "importmap", "speculationrules", "text/template"] {
            assert!(!is_js(Some(t)), "{t}");
        }
        assert_eq!(header_parts(&json!({"name": "a", "key": "b", "value": "c"})).map(|(n, _)| n.clone()), Some(json!("a")));
    }
}
