//! URL inventory: every URL an app's output (or host arguments) refers to,
//! read the way a browser would read it, and the domains behind them.
//! No judgement: the agent checks the list against code and docs.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};

use crate::harness::field;
use crate::manifest::Manifest;
use crate::record::RunRecord;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct UrlRef {
    /// Normalised as a browser reads it.
    pub url: String,
    /// The URL with digit runs replaced by `{n}`, for grouping.
    pub pattern: String,
    pub method: String,
    /// Attribute or header it came from (`href`, `data-url`, `css`,
    /// `script`, `joined`, `location`, `text`, `host_arg <func>`).
    pub source: String,
    /// How it fires: `link`, `form`, `load`, `redirect`, `refresh`, `text`;
    /// `unknown` (an attribute of no standard meaning) or `auto` (such an
    /// attribute on an element that says it fires by itself).
    pub trigger: String,
    /// `same_host`, `external`, `protocol_relative`, `backslash`, `ip`,
    /// `javascript`, `data`, `mailto`, `other_scheme`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Registrable domain (`www.google.de` → `google.de`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Request or host values found inside the URL.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contains: Vec<String>,
}

static TEXT_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:https?|ftp|wss?)://[^\s"'<>\\]+"#).unwrap());
static SCHEME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*):").unwrap());
static DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9]+").unwrap());
static CSS_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)|@import\s+(?:"([^"]*)"|'([^']*)')"#).unwrap());
static JS_STRING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`"#).unwrap());
static JS_CONCAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""\s*\+\s*"|'\s*\+\s*'|`\s*\+\s*`"#).unwrap());
static JS_ESCAPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|(.))").unwrap());
/// A host to start with: localhost, an IP, `www.…`, or a domain followed
/// by a port or a path (a bare `app.js` is no host).
static HOSTISH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\]|www\.[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?(?:[/?#]|$)|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d+)?/)",
    )
    .unwrap()
});

/// Attributes that never hold a URL a browser or a framework fetches.
const PASSIVE: &[&str] = &[
    "class",
    "id",
    "title",
    "alt",
    "name",
    "type",
    "value",
    "placeholder",
    "role",
    "lang",
    "dir",
    "for",
    "width",
    "height",
    "rel",
    "target",
    "method",
    "formmethod",
    "charset",
    "content",
    "http-equiv",
    "loading",
    "decoding",
    "crossorigin",
    "referrerpolicy",
    "integrity",
    "tabindex",
    "hidden",
    "disabled",
    "checked",
    "selected",
    "readonly",
    "required",
    "autocomplete",
    "min",
    "max",
    "step",
    "size",
    "rows",
    "cols",
    "maxlength",
    "colspan",
    "rowspan",
    "label",
    "cite",
    "longdesc",
    "datetime",
    "accept",
    "media",
    "sizes",
    "nonce",
    "translate",
    "spellcheck",
    "draggable",
    "contenteditable",
    "style",
];
/// Words that say a request goes out without the user doing anything.
pub(crate) const SELF_WORDS: &[&str] = &["load", "revealed", "intersect", "every", "init", "visible", "poll", "interval", "mount", "mounted"];
/// Response headers that never hold a URL to follow.
const PASSIVE_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "cache-control",
    "etag",
    "date",
    "expires",
    "last-modified",
    "vary",
    "set-cookie",
    "server",
    "age",
    "pragma",
    "content-encoding",
    "content-language",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
];

thread_local! {
    static FOUND: RefCell<(String, Rc<Vec<Found>>)> = RefCell::default();
}

/// A URL in output, and how it is used.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub url: String,
    /// `GET` unless the markup names another method.
    pub method: String,
    /// The attribute, `css`, `script`, `joined` (pieces of several
    /// attributes), `text`, or the header.
    pub source: String,
    /// `link`, `form`, `load`, `redirect`, `refresh`, `text`; `unknown`:
    /// an attribute of no standard meaning (a framework may fetch it);
    /// `auto`: such an attribute on an element that says it fires by itself.
    pub trigger: String,
    /// The element (start), if any.
    pub tag: String,
}

impl Found {
    fn new(url: &str, method: &str, source: &str, trigger: &str, tag: &str) -> Self {
        Found { url: url.into(), method: method.into(), source: source.into(), trigger: trigger.into(), tag: tag.into() }
    }
}

/// Whether text looks like a URL: a scheme, `//`, a path, a query, a
/// host. Decided by its shape, not by where it is.
pub fn url_like(s: &str) -> bool {
    let t = normalize(s);
    if t.len() < 2 || t.len() > 2048 || t.contains(char::is_whitespace) {
        return false;
    }
    if let Some(c) = SCHEME.captures(&t)
        && matches!(c[1].to_ascii_lowercase().as_str(), "http" | "https" | "ws" | "wss" | "ftp" | "javascript" | "vbscript" | "data" | "file" | "blob")
    {
        return true;
    }
    let b = t.as_bytes();
    let path_char = |c: u8| c.is_ascii_alphanumeric() || b"_~.%-$@!".contains(&c);
    match b[0] {
        b'/' | b'\\' => matches!(b[1], b'/' | b'\\') || path_char(b[1]),
        b'.' => t.starts_with("./") || t.starts_with("../"),
        b'?' => t.contains('='),
        _ => HOSTISH.is_match(&t),
    }
}

/// The texts in a value a framework or script may use as a URL: the value,
/// string literals in it (pieces joined, escapes undone), strings in JSON,
/// `<…>` in a link header.
fn texts_in(v: &str) -> Vec<String> {
    let mut out = vec![v.trim().to_string()];
    let joined = JS_CONCAT.replace_all(v, "");
    for c in JS_STRING.captures_iter(&joined) {
        let lit = c.get(1).or(c.get(2)).or(c.get(3)).map_or("", |m| m.as_str());
        out.push(unescape_js(lit));
    }
    if let Some(i) = v.find('<')
        && let Some(j) = v[i..].find('>')
    {
        out.push(v[i + 1..i + j].to_string());
    }
    out.retain(|t| !t.is_empty());
    out.dedup();
    out
}

/// `\x2f`, `\u002f`, `\u{2f}`, `\/` undone.
pub fn unescape_js(s: &str) -> String {
    JS_ESCAPE
        .replace_all(s, |c: &regex::Captures| {
            let hex = c.get(1).or(c.get(2)).or(c.get(3)).map(|m| m.as_str());
            match (hex, c.get(4)) {
                (Some(h), _) => u32::from_str_radix(h, 16).ok().and_then(char::from_u32).map(String::from).unwrap_or_default(),
                (None, Some(m)) => match m.as_str() {
                    "n" => "\n".into(),
                    "t" => "\t".into(),
                    o => o.into(),
                },
                _ => String::new(),
            }
        })
        .into_owned()
}

/// A method named in an attribute name (`*-post`, `:delete`, `put-*`).
fn method_in_name(k: &str) -> Option<String> {
    k.split(['-', ':', '.', '_', '@']).find(|w| matches!(*w, "get" | "post" | "put" | "patch" | "delete")).map(str::to_ascii_uppercase)
}

fn words(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| !w.is_empty())
}

/// Whether the element says a request in attribute `k` goes out by itself:
/// a word like `load` or `every` in that attribute's name, or in another
/// attribute.
fn fires_by_itself(el: &crate::html::Element, k: &str) -> bool {
    let selfish = |s: &str| words(&s.to_ascii_lowercase()).any(|w| SELF_WORDS.contains(&w));
    selfish(k) || el.attrs.iter().filter(|(n, _)| n != k && !PASSIVE.contains(&n.as_str()) && !n.starts_with("aria-")).any(|(n, v)| selfish(n) || selfish(v))
}

/// Every URL in markup, as a browser and an unknown framework could use it.
pub fn in_html(html: &str) -> Vec<Found> {
    crate::html::memo(&FOUND, html, find_in_html).as_ref().clone()
}

fn find_in_html(html: &str) -> Vec<Found> {
    let doc = crate::html::doc(html);
    let mut out = Vec::new();
    for el in &doc.elements {
        let tag = el.raw.as_str();
        let form_method = |a: &str, default: &str| el.get(a).map(|m| m.to_ascii_uppercase()).unwrap_or(default.into());
        let mut pieces: Vec<&str> = Vec::new();
        for (k, v) in &el.attrs {
            if k.starts_with("aria-") {
                continue;
            }
            if k == "style" {
                css_urls(v, tag, &mut out);
                continue;
            }
            if PASSIVE.contains(&k.as_str()) {
                if k == "content" && el.get("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh")) {
                    let lower = v.to_ascii_lowercase();
                    if let Some(i) = lower.find("url=") {
                        out.push(Found::new(v[i + 4..].trim_matches(['\'', '"', ' ']), "GET", k, "refresh", tag));
                    }
                }
                continue;
            }
            let standard = if el.name == "script" && matches!(k.as_str(), "src" | "href" | "xlink:href") {
                el.script_source_attribute(k).then(|| ("GET".into(), "load"))
            } else {
                match k.as_str() {
                    "href" | "xlink:href" => Some(("GET".to_string(), if el.name == "link" && el.is_html() { "load" } else { "link" })),
                    "src" | "poster" | "background" | "manifest" => Some(("GET".into(), "load")),
                    "data" if el.is_html() && el.name == "object" => Some(("GET".into(), "load")),
                    "ping" => Some(("POST".into(), "link")),
                    "action" => Some((form_method("method", "GET"), "form")),
                    "formaction" => Some((form_method("formmethod", "POST"), "form")),
                    "srcset" | "imagesrcset" => {
                        for part in v.split(',') {
                            if let Some(u) = part.split_whitespace().next() {
                                out.push(Found::new(u, "GET", k, "load", tag));
                            }
                        }
                        continue;
                    }
                    _ => None,
                }
            };
            if let Some((method, trigger)) = standard {
                out.push(Found::new(v, &method, k, trigger, tag));
                continue;
            }
            // No standard meaning: a framework or a script may fetch it.
            let trigger = if fires_by_itself(el, k) { "auto" } else { "unknown" };
            let method = method_in_name(k).unwrap_or_else(|| "GET".into());
            for t in texts_in(v) {
                if url_like(&t) {
                    out.push(Found::new(&t, &method, k, trigger, tag));
                }
            }
            if v.len() < 40 && !v.contains(char::is_whitespace) {
                pieces.push(v);
            }
        }
        // A URL split over several attributes.
        if pieces.len() >= 2 {
            let joined: String = pieces.concat();
            // Some piece must be a fragment (`min/wipe`, `evil.example`)
            // rather than a word like `load`.
            let fragment = pieces.iter().any(|p| !url_like(p) && p.contains(['/', '.', ':']));
            if fragment && url_like(&joined) && joined.contains('/') && !pieces.contains(&joined.as_str()) {
                out.push(Found::new(&joined, "GET", "joined", if fires_by_itself(el, "") { "auto" } else { "unknown" }, tag));
            }
        }
        match (el.name.as_str(), &el.body) {
            ("style", Some(css)) => css_urls(css, "<style>", &mut out),
            ("script", Some(js)) => {
                for t in texts_in(js).into_iter().skip(1) {
                    if url_like(&t) {
                        out.push(Found::new(&t, "GET", "script", "unknown", "<script>"));
                    }
                }
            }
            _ => {}
        }
    }
    // URLs in text between tags.
    from_text(&doc.text, "text", &mut out);
    out
}

fn css_urls(css: &str, tag: &str, out: &mut Vec<Found>) {
    for c in CSS_URL.captures_iter(css) {
        let u = (1..=5).find_map(|i| c.get(i)).map_or("", |m| m.as_str());
        if !u.is_empty() {
            out.push(Found::new(&unescape_js(u), "GET", "css", "load", tag));
        }
    }
}

/// Absolute URLs in plain text.
pub fn text_urls(s: &str) -> Vec<String> {
    TEXT_URL.find_iter(s).map(|m| m.as_str().trim_end_matches(['.', ',', ')', ';']).to_string()).collect()
}

fn from_text(s: &str, source: &str, out: &mut Vec<Found>) {
    for m in TEXT_URL.find_iter(s) {
        out.push(Found::new(m.as_str().trim_end_matches(['.', ',', ')', ';']), "GET", source, "text", ""));
    }
}

/// URLs in response headers: `location` and `refresh` by their meaning,
/// any other header by the shape of its value.
pub fn in_headers(h: &Value) -> Vec<Found> {
    let mut out = Vec::new();
    for (k, v) in header_pairs(h) {
        match k.as_str() {
            "location" | "content-location" => out.push(Found::new(&v, "GET", &k, "redirect", "")),
            "refresh" => {
                if let Some(i) = v.to_ascii_lowercase().find("url=") {
                    out.push(Found::new(&v[i + 4..], "GET", &k, "refresh", ""));
                }
            }
            k if PASSIVE_HEADERS.contains(&k) => {}
            _ => {
                for t in texts_in(&v) {
                    if url_like(&t) {
                        out.push(Found::new(&t, "GET", &k, "unknown", ""));
                    }
                }
            }
        }
    }
    out
}

/// Header pairs, names in lower case.
fn header_pairs(h: &Value) -> Vec<(String, String)> {
    match h {
        Value::Array(a) => a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_ascii_lowercase(), p.get(1)?.as_str()?.to_string()))).collect(),
        Value::Object(o) => o.iter().filter_map(|(k, v)| Some((k.to_ascii_lowercase(), v.as_str()?.to_string()))).collect(),
        _ => vec![],
    }
}

/// All URLs in one run.
pub fn extract(r: &RunRecord, m: &Manifest) -> Vec<UrlRef> {
    extract_from(r, m, true)
}

/// URLs in the output only, without the values they contain: cheap enough
/// for every fuzz run.
pub fn extract_output(r: &RunRecord, m: &Manifest) -> Vec<UrlRef> {
    extract_from(r, m, false)
}

fn extract_from(r: &RunRecord, m: &Manifest, full: bool) -> Vec<UrlRef> {
    let mut raw: Vec<Found> = Vec::new();
    let out = m.entry.as_ref().map(|e| &e.output);
    if let Some(result) = &r.result {
        let body = out.and_then(|o| o.body.as_deref()).and_then(|p| field(result, p));
        let headers = out.and_then(|o| o.headers.as_deref()).and_then(|p| field(result, p));
        // A body whose content type isn't HTML (a script, a style, JSON)
        // is no markup: a browser fetches nothing it names by itself.
        let not_html = headers.is_some_and(|h| header_pairs(h).iter().any(|(k, v)| k == "content-type" && !v.to_ascii_lowercase().contains("html")));
        match body {
            Some(Value::String(b)) if not_html => from_text(b, "text", &mut raw),
            Some(Value::String(b)) => raw.extend(in_html(b)),
            _ => {
                // No manifest hint: every string in the result.
                let mut strings = Vec::new();
                collect_strings(result, &mut strings);
                for s in strings {
                    if s.contains('<') {
                        raw.extend(in_html(&s));
                    } else {
                        from_text(&s, "text", &mut raw);
                    }
                }
            }
        }
        if let Some(h) = headers {
            raw.extend(in_headers(h));
        }
    }
    for e in r.events.iter().filter(|_| full) {
        let mut strings = Vec::new();
        for v in e.text_args().values() {
            collect_strings(v, &mut strings);
        }
        for s in strings {
            from_text(&s, &format!("host_arg {}", e.func), &mut raw);
        }
    }
    let values = if full { known_values(r) } else { vec![] };
    let mut refs: Vec<UrlRef> = raw
        .into_iter()
        .filter_map(|f| {
            let url = normalize(&f.url);
            if url.is_empty() || url.starts_with('#') {
                return None;
            }
            let (kind, host, domain) = classify(&url);
            let contains = values.iter().filter(|(v, _)| url.contains(v.as_str())).take(3).map(|(v, from)| format!("{from}: {v}")).collect();
            Some(UrlRef {
                pattern: DIGITS.replace_all(&url, "{n}").into_owned(),
                url,
                method: f.method,
                source: f.source,
                trigger: f.trigger,
                kind,
                host,
                domain,
                contains,
            })
        })
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Entities decoded, tabs and newlines removed, outer spaces trimmed —
/// what a browser does before resolving a URL.
pub fn normalize(s: &str) -> String {
    let decoded = decode_entities(s);
    decoded.chars().filter(|c| !matches!(c, '\t' | '\n' | '\r')).collect::<String>().trim_matches(|c: char| c <= ' ').to_string()
}

pub fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest[1..].find(|c: char| !(c.is_ascii_alphanumeric() || c == '#')).map(|e| e + 1).unwrap_or(rest.len());
        let name = &rest[1..end];
        let ch = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "sol" => Some('/'),
            "bsol" => Some('\\'),
            "colon" => Some(':'),
            "Tab" => Some('\t'),
            "NewLine" => Some('\n'),
            n if n.starts_with("#x") || n.starts_with("#X") => u32::from_str_radix(&n[2..], 16).ok().and_then(char::from_u32),
            n if n.starts_with('#') => n[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end..];
                if rest.starts_with(';') {
                    rest = &rest[1..];
                }
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// (kind, host, registrable domain).
pub fn classify(u: &str) -> (String, Option<String>, Option<String>) {
    let lower = u.to_ascii_lowercase();
    if let Some(c) = SCHEME.captures(&lower) {
        let scheme = c[1].to_string();
        return match scheme.as_str() {
            "javascript" | "vbscript" => ("javascript".into(), None, None),
            "data" => ("data".into(), None, None),
            "mailto" | "tel" | "sms" => ("mailto".into(), None, None),
            "http" | "https" | "ws" | "wss" | "ftp" => host_of(u, "external"),
            _ => ("other_scheme".into(), None, None),
        };
    }
    let b = lower.as_bytes();
    let slashish = |c: u8| c == b'/' || c == b'\\';
    if b.len() >= 2 && slashish(b[0]) && slashish(b[1]) {
        let kind = if b[0] == b'/' && b[1] == b'/' { "protocol_relative" } else { "backslash" };
        return host_of(&format!("https:{u}"), kind);
    }
    ("same_host".into(), None, None)
}

fn host_of(u: &str, kind: &str) -> (String, Option<String>, Option<String>) {
    match url::Url::parse(u) {
        Ok(p) => match p.host() {
            Some(url::Host::Domain(d)) => {
                let domain = psl::domain_str(d).unwrap_or(d).to_string();
                (kind.into(), Some(d.to_string()), Some(domain))
            }
            Some(h) => ("ip".into(), Some(h.to_string()), Some(h.to_string())),
            None => (kind.into(), None, None),
        },
        Err(_) => (kind.into(), None, None),
    }
}

/// Request and host-result strings worth looking for inside URLs.
fn known_values(r: &RunRecord) -> Vec<(String, String)> {
    let mut out = Vec::new();
    fn walk(v: &Value, path: String, from: &str, out: &mut Vec<(String, String)>) {
        match v {
            Value::String(s) if s.len() >= 3 && !s.contains('<') && s.len() <= 200 => out.push((s.clone(), format!("{from} {path}"))),
            Value::Number(n) if n.to_string().len() >= 3 => out.push((n.to_string(), format!("{from} {path}"))),
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, format!("{path}[{i}]"), from, out)
                }
            }
            Value::Object(o) => {
                for (k, x) in o {
                    walk(x, if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, from, out)
                }
            }
            _ => {}
        }
    }
    for (i, a) in r.spec.args.iter().enumerate() {
        walk(a, String::new(), &format!("request arg {i}"), &mut out);
    }
    for e in &r.events {
        if let Some(v) = &e.result {
            walk(v, String::new(), &format!("host {}#{}", e.func, e.n), &mut out);
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|(v, _)| seen.insert(v.clone()));
    out
}

/// URLs and domains over many runs.
pub fn inventory(runs: &[RunRecord], m: &Manifest) -> Value {
    struct Group {
        example: UrlRef,
        urls: BTreeSet<String>,
        runs: BTreeSet<String>,
        example_run: String,
    }
    let mut groups: BTreeMap<(String, String, String), Group> = BTreeMap::new();
    for r in runs {
        for u in extract(r, m) {
            let key = (u.pattern.clone(), u.method.clone(), u.source.clone());
            let g = groups.entry(key).or_insert_with(|| Group { example: u.clone(), urls: BTreeSet::new(), runs: BTreeSet::new(), example_run: r.id.clone() });
            g.urls.insert(u.url.clone());
            g.runs.insert(r.id.clone());
        }
    }
    type Domain = (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>, String);
    let mut domains: BTreeMap<String, Domain> = BTreeMap::new();
    for g in groups.values() {
        let u = &g.example;
        let d = match u.kind.as_str() {
            "same_host" => "(same host)".to_string(),
            "javascript" | "data" | "mailto" | "other_scheme" => format!("({}:)", u.kind),
            _ => u.domain.clone().unwrap_or_else(|| "(unparsable)".into()),
        };
        let e = domains.entry(d).or_insert_with(|| (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), g.example_run.clone()));
        e.0.extend(u.host.clone());
        e.1.extend(g.urls.iter().cloned());
        e.2.insert(u.source.clone());
    }
    let domains: Vec<Value> = domains
        .into_iter()
        .map(|(d, (hosts, urls, sources, run))| {
            let mut o = json!({"domain": d, "urls": urls.len(), "sources": sources});
            if !hosts.is_empty() {
                o["hosts"] = json!(hosts);
            }
            if d != "(same host)" {
                o["example_run"] = json!(run);
            }
            o
        })
        .collect();
    let urls: Vec<Value> = groups
        .into_values()
        .map(|g| {
            let u = g.example;
            let mut o = json!({
                "url": if g.urls.len() > 1 { u.pattern.clone() } else { u.url.clone() },
                "method": u.method, "source": u.source, "trigger": u.trigger, "kind": u.kind,
                "distinct": g.urls.len(), "runs": g.runs.len(), "example_run": g.example_run,
            });
            if g.urls.len() > 1 {
                o["example"] = json!(u.url);
            }
            if let Some(d) = &u.domain {
                o["domain"] = json!(d);
            }
            if !u.contains.is_empty() {
                o["contains"] = json!(u.contains);
            }
            o
        })
        .collect();
    json!({"runs": runs.len(), "domains": domains, "urls": urls})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies() {
        assert_eq!(classify("/items").0, "same_host");
        assert_eq!(classify("items?x=1").0, "same_host");
        let (k, h, d) = classify("https://www.google.de/search");
        assert_eq!((k.as_str(), h.as_deref(), d.as_deref()), ("external", Some("www.google.de"), Some("google.de")));
        assert_eq!(classify("https://cdn.foo.co.uk/x").2.as_deref(), Some("foo.co.uk"));
        let (k, _, d) = classify("/\\evil.com/x");
        assert_eq!((k.as_str(), d.as_deref()), ("backslash", Some("evil.com")));
        assert_eq!(classify("//evil.com").0, "protocol_relative");
        assert_eq!(classify("JavaScript:alert(1)").0, "javascript");
        assert_eq!(classify("http://10.0.0.1/").0, "ip");
        assert_eq!(classify("https://bücher.de/").2.as_deref(), Some("xn--bcher-kva.de"));
    }

    #[test]
    fn reads_like_a_browser() {
        assert_eq!(normalize(" java\tscript&#58;x "), "javascript:x");
        assert_eq!(normalize("/a?b=1&amp;c=2"), "/a?b=1&c=2");
        let out = in_html(r#"<form hx-post="/book" hx-trigger="submit"><a href='/x'>x</a><meta http-equiv="refresh" content="0; url=https://e.com"></form>"#);
        let got: Vec<(&str, &str, &str)> = out.iter().map(|f| (f.url.as_str(), f.method.as_str(), f.source.as_str())).collect();
        assert!(got.contains(&("/book", "POST", "hx-post")));
        assert!(got.contains(&("/x", "GET", "href")));
        assert!(got.contains(&("https://e.com", "GET", "content")));
    }

    fn found(html: &str) -> Vec<(String, String, String)> {
        in_html(html).into_iter().map(|f| (normalize(&f.url), f.source, f.trigger)).collect()
    }

    #[test]
    fn urls_by_shape() {
        for u in ["/admin", "//evil.example", "/\\evil.example", "https://x.example/", "javascript:alert(1)", "localhost:8080/x", "169.254.169.254/latest"] {
            assert!(url_like(u), "{u}");
        }
        for u in ["click", "true", "#result", ".items", "closest form", "app.js", "item.name", "outerHTML", "/", "1/2 cup"] {
            assert!(!url_like(u), "{u}");
        }
        assert!(url_like("evil.example/x") && url_like("www.evil.example") && url_like("./x") && url_like("?a=1"));
    }

    #[test]
    fn any_framework() {
        let has = |html: &str, url: &str, trigger: &str| found(html).iter().any(|(u, _, t)| u == url && t == trigger);
        // htmx, Alpine, Turbo, Unpoly, a data attribute read by a script.
        assert!(has(r#"<div hx-post="/admin/reindex" hx-trigger="load"></div>"#, "/admin/reindex", "auto"));
        assert!(has(r#"<button hx-get="/items" hx-trigger="click">x</button>"#, "/items", "unknown"));
        assert!(has(r#"<div x-init="fetch('/admin/wipe', {method: 'POST'})"></div>"#, "/admin/wipe", "auto"));
        assert!(has(r#"<div x-data="{ url: '/ad' + 'min' }" @click="go(url)"></div>"#, "/admin", "unknown"));
        assert!(has(r#"<turbo-frame id="f" src="https://evil.example/frame"></turbo-frame>"#, "https://evil.example/frame", "load"));
        assert!(has(r#"<a up-follow up-href="/admin">x</a>"#, "/admin", "unknown"));
        assert!(has(r#"<div data-endpoint="&#x2f;admin&#x2f;x" data-poll="5s"></div>"#, "/admin/x", "auto"));
        // Script literals with escapes, JSON, CSS, split attributes.
        assert!(has(r#"<script>navigator.sendBeacon("https:\/\/c.example\x2fp")</script>"#, "https://c.example/p", "unknown"));
        assert!(has(r#"<script type="application/json">{"next": "/admin/users"}</script>"#, "/admin/users", "unknown"));
        assert!(has(r#"<div style="background:url('https://t.example/p.gif')"></div>"#, "https://t.example/p.gif", "load"));
        assert!(has(r#"<style>@import "https://t.example/a.css";</style>"#, "https://t.example/a.css", "load"));
        assert!(has(r#"<script src="https://evil.example/x.js"></script>"#, "https://evil.example/x.js", "load"));
        assert!(has(r#"<i data-a="/ad" data-b="min/wipe"></i>"#, "/admin/wipe", "unknown"));
        // Not URLs.
        assert!(found(r##"<div class="a b" hx-target="#r" hx-swap="outerHTML" x-show="open"></div>"##).is_empty());
    }

    #[test]
    fn headers_by_shape() {
        let f = in_headers(&json!([["Location", "/x"], ["HX-Redirect", "/admin"], ["Content-Type", "text/html"], ["X-Next", "{\"path\": \"/y\"}"]]));
        let got: Vec<(&str, &str)> = f.iter().map(|f| (f.url.as_str(), f.trigger.as_str())).collect();
        assert!(got.contains(&("/x", "redirect")) && got.contains(&("/admin", "unknown")) && got.contains(&("/y", "unknown")));
        assert_eq!(got.len(), 3);
    }
}
