//! URL inventory: every URL an app's output (or host arguments) refers to,
//! read the way a browser would read it, and the domains behind them.
//! No judgement: the agent checks the list against code and docs.

use std::collections::{BTreeMap, BTreeSet};
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
    /// Attribute or header it came from (`href`, `hx-post`, `location`,
    /// `text`, `host_arg <func>`).
    pub source: String,
    /// How it fires: `link`, `form`, `load`, `redirect`, or an `hx-trigger`.
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

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([a-zA-Z][a-zA-Z0-9-]*)\b((?:[^>\x22']|\x22[^\x22]*\x22|'[^']*')*)>").unwrap());
static ATTR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([a-zA-Z_:@][-a-zA-Z0-9_:.@]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?"#).unwrap()
});
static TEXT_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:https?|ftp|wss?)://[^\s"'<>\\]+"#).unwrap());
static SCHEME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*):").unwrap());
static DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9]+").unwrap());

const HX_METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];

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
    let mut raw: Vec<(String, String, String, String)> = Vec::new(); // url, method, source, trigger
    let out = m.entry.as_ref().map(|e| &e.output);
    if let Some(result) = &r.result {
        let body = out.and_then(|o| o.body.as_deref()).and_then(|p| field(result, p));
        let headers = out.and_then(|o| o.headers.as_deref()).and_then(|p| field(result, p));
        match body {
            Some(Value::String(b)) => from_html(b, &mut raw),
            _ => {
                // No manifest hint: every string in the result.
                let mut strings = Vec::new();
                collect_strings(result, &mut strings);
                for s in strings {
                    if s.contains('<') {
                        from_html(&s, &mut raw);
                    } else {
                        from_text(&s, "text", &mut raw);
                    }
                }
            }
        }
        if let Some(h) = headers {
            from_headers(h, &mut raw);
        }
    }
    for e in r.events.iter().filter(|_| full) {
        let mut strings = Vec::new();
        for v in e.args.values() {
            collect_strings(v, &mut strings);
        }
        for s in strings {
            from_text(&s, &format!("host_arg {}", e.func), &mut raw);
        }
    }
    let values = if full { known_values(r) } else { vec![] };
    let mut refs: Vec<UrlRef> = raw
        .into_iter()
        .filter_map(|(u, method, source, trigger)| {
            let url = normalize(&u);
            if url.is_empty() || url.starts_with('#') {
                return None;
            }
            let (kind, host, domain) = classify(&url);
            let contains = values.iter().filter(|(v, _)| url.contains(v.as_str())).take(3).map(|(v, from)| format!("{from}: {v}")).collect();
            Some(UrlRef { pattern: DIGITS.replace_all(&url, "{n}").into_owned(), url, method, source, trigger, kind, host, domain, contains })
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

fn from_html(html: &str, out: &mut Vec<(String, String, String, String)>) {
    for tag in TAG.captures_iter(html) {
        let name = tag[1].to_ascii_lowercase();
        let mut attrs: BTreeMap<String, String> = BTreeMap::new();
        for a in ATTR.captures_iter(&tag[2]) {
            let k = a[1].to_ascii_lowercase();
            let k = k.strip_prefix("data-").unwrap_or(&k).to_string();
            let v = a.get(2).or(a.get(3)).or(a.get(4)).map(|m| m.as_str().to_string()).unwrap_or_default();
            attrs.entry(k).or_insert(v);
        }
        let hx_trigger = attrs.get("hx-trigger").cloned();
        for (k, v) in &attrs {
            let (method, trigger) = match k.as_str() {
                "href" => ("GET".to_string(), if name == "link" { "load" } else { "link" }.to_string()),
                "src" | "poster" => ("GET".into(), "load".into()),
                "action" => (attrs.get("method").map(|m| m.to_ascii_uppercase()).unwrap_or("GET".into()), "form".into()),
                "formaction" => (attrs.get("formmethod").map(|m| m.to_ascii_uppercase()).unwrap_or("POST".into()), "form".into()),
                "hx-push-url" | "hx-replace-url" if v != "true" && v != "false" => ("GET".into(), "history".into()),
                k if k.starts_with("hx-") && HX_METHODS.contains(&&k[3..]) => {
                    let default = match (name.as_str(), &k[3..]) {
                        ("form", _) => "submit",
                        ("input" | "select" | "textarea", _) => "change",
                        _ => "click",
                    };
                    (k[3..].to_ascii_uppercase(), hx_trigger.clone().unwrap_or(default.to_string()))
                }
                "content" if attrs.get("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh"))
                    && v.to_ascii_lowercase().contains("url=") =>
                {
                    ("GET".into(), "refresh".into())
                }
                _ => continue,
            };
            let url = if k == "content" {
                let i = v.to_ascii_lowercase().find("url=").unwrap_or(0);
                v[i + 4..].trim_matches(|c| c == '\'' || c == '"' || c == ' ').to_string()
            } else {
                v.clone()
            };
            out.push((url, method, k.clone(), trigger));
        }
    }
    // URLs in text between tags.
    let text = TAG.replace_all(html, " ");
    from_text(&text, "text", out);
}

fn from_text(s: &str, source: &str, out: &mut Vec<(String, String, String, String)>) {
    for m in TEXT_URL.find_iter(s) {
        out.push((m.as_str().trim_end_matches(['.', ',', ')', ';']).to_string(), "GET".into(), source.into(), "text".into()));
    }
}

fn from_headers(h: &Value, out: &mut Vec<(String, String, String, String)>) {
    let pairs: Vec<(String, String)> = match h {
        Value::Array(a) => a
            .iter()
            .filter_map(|p| Some((p.get(0)?.as_str()?.to_ascii_lowercase(), p.get(1)?.as_str()?.to_string())))
            .collect(),
        Value::Object(o) => o.iter().filter_map(|(k, v)| Some((k.to_ascii_lowercase(), v.as_str()?.to_string()))).collect(),
        _ => vec![],
    };
    for (k, v) in pairs {
        match k.as_str() {
            "location" | "hx-redirect" | "content-location" => out.push((v, "GET".into(), k, "redirect".into())),
            "hx-push-url" | "hx-replace-url" if v != "false" => out.push((v, "GET".into(), k, "history".into())),
            "hx-location" => {
                let url = serde_json::from_str::<Value>(&v)
                    .ok()
                    .and_then(|j| j.get("path").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or(v);
                out.push((url, "GET".into(), k, "redirect".into()));
            }
            "refresh" => {
                if let Some(i) = v.to_ascii_lowercase().find("url=") {
                    out.push((v[i + 4..].to_string(), "GET".into(), k, "refresh".into()));
                }
            }
            _ => {}
        }
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
        let mut out = vec![];
        from_html(r#"<form hx-post="/book" hx-trigger="submit"><a href='/x'>x</a><meta http-equiv="refresh" content="0; url=https://e.com"></form>"#, &mut out);
        let got: Vec<(&str, &str, &str)> = out.iter().map(|(u, m, s, _)| (u.as_str(), m.as_str(), s.as_str())).collect();
        assert!(got.contains(&("/book", "POST", "hx-post")));
        assert!(got.contains(&("/x", "GET", "href")));
        assert!(got.contains(&("https://e.com", "GET", "content")));
    }
}
