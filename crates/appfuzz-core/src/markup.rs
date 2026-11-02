//! Output labels: what the platform allows in the export's result.
//!
//! `html:no-scripts`: no script runs from this markup (no `<script>`, no
//! event handler, no `javascript:` URL, no `hx-on`). `html:safe`: no
//! scripts, and the markup makes no request a user didn't ask for to
//! another host or to a sensitive route (no meta refresh, no form or htmx
//! action off the app, no request on load). `url:local`: a path on the
//! app's own host, so `//evil`, `/\evil` and schemes fail.
//!
//! The browser model is static: tags and attributes read the way a browser
//! reads them (entities decoded, case folded). Phase 3 adds obfuscation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::harness::field;
use crate::manifest::Manifest;
use crate::record::{OutcomeKind, RunRecord};
use crate::urls::{ATTR, TAG, classify, normalize};

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

/// Attributes that hold a URL a browser loads or navigates to.
const URL_ATTRS: &[&str] = &["href", "src", "action", "formaction", "xlink:href", "data", "poster", "background", "srcset"];
/// Tags that run or embed active content.
const ACTIVE_TAGS: &[&str] = &["script", "object", "embed", "applet"];
/// htmx triggers that fire without the user doing anything.
const SELF_TRIGGERS: &[&str] = &["load", "revealed", "intersect", "every"];

/// One element as the browser sees it.
struct Tag {
    name: String,
    attrs: BTreeMap<String, String>,
    raw: String,
}

fn tags(html: &str) -> Vec<Tag> {
    TAG.captures_iter(html)
        .map(|t| {
            let mut attrs = BTreeMap::new();
            for a in ATTR.captures_iter(&t[2]) {
                let k = a[1].to_ascii_lowercase();
                let v = a.get(2).or(a.get(3)).or(a.get(4)).map(|m| m.as_str()).unwrap_or_default();
                attrs.entry(k).or_insert_with(|| normalize(v));
            }
            let raw: String = t[0].chars().take(160).collect();
            Tag { name: t[1].to_ascii_lowercase(), attrs, raw }
        })
        .collect()
}

/// Ways the markup can run a script: (what, the tag).
pub fn scripts(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for t in tags(html) {
        if ACTIVE_TAGS.contains(&t.name.as_str()) {
            out.push((format!("a <{}> element", t.name), t.raw.clone()));
            continue;
        }
        if t.name == "iframe" && t.attrs.contains_key("srcdoc") {
            out.push(("an iframe with srcdoc".into(), t.raw.clone()));
        }
        for (k, v) in &t.attrs {
            let k = k.strip_prefix("data-").unwrap_or(k);
            if k.starts_with("on") && k.len() > 2 {
                out.push((format!("an event handler ({k})"), t.raw.clone()));
            } else if k.starts_with("hx-on") {
                out.push((format!("an htmx handler ({k})"), t.raw.clone()));
            } else if k == "hx-vars" || k == "hx-vals" && (v.trim_start().starts_with("js:") || v.trim_start().starts_with("javascript:")) {
                out.push((format!("script in {k}"), t.raw.clone()));
            } else if (URL_ATTRS.contains(&k) || k.starts_with("hx-") && is_hx_request(k)) && script_url(v) {
                out.push((format!("a script URL in {k}"), t.raw.clone()));
            } else if k == "content"
                && t.attrs.get("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh"))
                && let Some(i) = v.to_ascii_lowercase().find("url=")
                && script_url(&v[i + 4..])
            {
                out.push(("a meta refresh to a script URL".into(), t.raw.clone()));
            }
        }
    }
    out
}

fn is_hx_request(k: &str) -> bool {
    matches!(k, "hx-get" | "hx-post" | "hx-put" | "hx-patch" | "hx-delete")
}

fn script_url(v: &str) -> bool {
    let u = normalize(v).to_ascii_lowercase();
    let kind = classify(&u).0;
    kind == "javascript" || u.starts_with("data:text/html") || u.starts_with("data:application/xhtml") || u.starts_with("data:image/svg")
}

/// Requests the markup makes that the user didn't ask for, or makes to
/// another host or a sensitive route: (what, the tag).
pub fn unsafe_actions(html: &str, sensitive: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let is_sensitive = |u: &str| {
        let path = u.split(['?', '#']).next().unwrap_or(u);
        sensitive.iter().find(|s| path == s.as_str() || path.starts_with(&format!("{}/", s.trim_end_matches('/'))))
    };
    for t in tags(html) {
        if t.name == "meta" && t.attrs.get("http-equiv").is_some_and(|h| h.eq_ignore_ascii_case("refresh")) {
            out.push(("a meta refresh (the page moves on by itself)".into(), t.raw.clone()));
        }
        let trigger = t.attrs.get("hx-trigger").map(|x| x.to_ascii_lowercase()).unwrap_or_default();
        let by_itself = trigger.split([',', ' ']).any(|w| SELF_TRIGGERS.iter().any(|s| w.starts_with(s)));
        for (k, v) in &t.attrs {
            let k = k.strip_prefix("data-").unwrap_or(k);
            let action = match k {
                "action" | "formaction" => Some("a form"),
                k if is_hx_request(k) => Some("an htmx request"),
                _ => None,
            };
            let Some(what) = action else { continue };
            let kind = classify(v).0;
            if kind != "same_host" {
                out.push((format!("{what} to {} ({k}, {kind})", v.chars().take(80).collect::<String>()), t.raw.clone()));
            } else if let Some(s) = is_sensitive(v) {
                out.push((format!("{what} to the sensitive route {s} ({k} = {v})"), t.raw.clone()));
            } else if what == "an htmx request" && by_itself {
                out.push((format!("an htmx request that fires by itself ({k} = {v}, hx-trigger = {trigger})"), t.raw.clone()));
            }
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
                for (what, tag) in scripts(v) {
                    out.push(Finding::new(
                        "script_in_output",
                        &format!("{ex}\0{path}\0{}", what.split(' ').take(3).collect::<Vec<_>>().join(" ")),
                        Severity::Fail,
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
                    for (what, tag) in unsafe_actions(v, &entry.sensitive_paths) {
                        out.push(Finding::new(
                            "unsafe_action",
                            &format!("{ex}\0{path}\0{}", what.split(' ').take(4).collect::<Vec<_>>().join(" ")),
                            Severity::Fail,
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

    fn whats(v: Vec<(String, String)>) -> Vec<String> {
        v.into_iter().map(|(w, _)| w).collect()
    }

    #[test]
    fn finds_scripts() {
        assert!(scripts("<p class=x>Hi <a href=\"/a\">a</a></p>").is_empty());
        assert_eq!(whats(scripts("<SCRIPT>alert(1)</SCRIPT>")), ["a <script> element"]);
        assert_eq!(whats(scripts("<img src=x OnError=alert(1)>")), ["an event handler (onerror)"]);
        assert_eq!(whats(scripts("<a href=\"jav&#x09;ascript&colon;alert(1)\">x</a>")), ["a script URL in href"]);
        assert_eq!(whats(scripts("<button hx-on:click=\"alert(1)\">x</button>")), ["an htmx handler (hx-on:click)"]);
        assert_eq!(whats(scripts("<div hx-vals='js:{a: evil()}'></div>")), ["script in hx-vals"]);
        assert_eq!(whats(scripts("<div hx-vars='a:evil()'></div>")), ["script in hx-vars"]);
        assert!(scripts("<div hx-vals='{\"a\": 1}'></div>").is_empty());
    }

    #[test]
    fn finds_unsafe_actions() {
        let s = vec!["/admin".to_string()];
        assert!(unsafe_actions("<form method=post action=\"/order\"><button>x</button></form>", &s).is_empty());
        assert!(unsafe_actions("<a href=\"https://other.example/\">x</a>", &s).is_empty());
        assert_eq!(unsafe_actions("<form action=\"https://evil.example/steal\">", &s).len(), 1);
        assert_eq!(unsafe_actions("<button hx-post=\"/admin/users/7/delete\">x</button>", &s).len(), 1);
        assert_eq!(unsafe_actions("<div hx-get=\"/feed\" hx-trigger=\"load\"></div>", &s).len(), 1);
        assert!(unsafe_actions("<div hx-get=\"/feed\" hx-trigger=\"click\"></div>", &s).is_empty());
        assert_eq!(unsafe_actions("<meta http-equiv=\"refresh\" content=\"0;url=/x\">", &s).len(), 1);
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
