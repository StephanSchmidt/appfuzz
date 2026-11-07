//! Three ways data gets exposed on its way: a session cookie that page
//! scripts can read or that travels over plain HTTP (`insecure_cookie`),
//! request text whose line breaks start log lines of its own
//! (`log_injection`), and secrets or personal data sent to an `http://` URL
//! (`cleartext_transport`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::labels::Label;
use crate::manifest::Manifest;
use crate::record::{OutcomeKind, RunRecord};

/// Cookies scripts must read: CSRF tokens for the double-submit pattern.
static SCRIPT_COOKIE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)csrf|xsrf").unwrap());

pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    if r.outcome.kind != OutcomeKind::Ok {
        return vec![];
    }
    let mut out = cookies(r, m);
    out.extend(log_lines(r));
    out.extend(cleartext(r, m));
    out
}

/// Session cookies set without `HttpOnly` or `Secure`.
fn cookies(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let ex = &r.spec.export;
    let mut out = Vec::new();
    for (k, v) in &crate::output::response(r, m).headers {
        if !k.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let mut parts = v.split(';');
        let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else { continue };
        let (name, value) = (name.trim(), value.trim().trim_matches('"'));
        // An empty value clears the cookie.
        if value.is_empty() || !crate::auth::TOKEN_NAME.is_match(name) || SCRIPT_COOKIE.is_match(name) {
            continue;
        }
        let attrs: Vec<String> = parts.map(|a| a.split('=').next().unwrap_or_default().trim().to_ascii_lowercase()).collect();
        let missing: Vec<&str> =
            [("httponly", "HttpOnly"), ("secure", "Secure")].into_iter().filter(|(a, _)| !attrs.iter().any(|x| x == a)).map(|(_, n)| n).collect();
        let why = match missing.as_slice() {
            [] => continue,
            ["HttpOnly"] => "scripts on the page can read it",
            ["Secure"] => "the browser also sends it over plain HTTP",
            _ => "scripts on the page can read it, and the browser also sends it over plain HTTP",
        };
        out.push(Finding::new(
            "insecure_cookie",
            &format!("{ex}\0cookie\0{name}"),
            Severity::Fail,
            format!("{ex} sets the session cookie {name} without {}: {why}", missing.join(" and ")),
            json!({"cookie": name, "missing": missing}),
            Some(r.id.as_str()),
        ));
    }
    out
}

/// Request text with a line break that reaches the log as it came: the
/// text after the break reads as a log line of its own.
fn log_lines(r: &RunRecord) -> Vec<Finding> {
    // A command's standard output is its answer, not a log.
    let logs = if r.command_exit_code.is_some() { r.stderr.clone() } else { format!("{}\n{}", r.stdout, r.stderr) };
    if logs.trim().is_empty() {
        return vec![];
    }
    let mut fields = Vec::new();
    for a in &r.spec.args {
        crate::identity::leaves(a, String::new(), &mut fields);
    }
    let ex = &r.spec.export;
    let mut out: Vec<Finding> = Vec::new();
    for (path, text) in fields {
        let Some(at) = text.rfind(['\n', '\r']) else { continue };
        if text[at + 1..].trim().is_empty() || !logs.contains(&text) || out.iter().any(|f| f.detail["field"] == path) {
            continue;
        }
        let field = if path.is_empty() { "the request".to_string() } else { format!("request field {path}") };
        out.push(Finding::new(
            "log_injection",
            &format!("{ex}\0log\0{path}"),
            Severity::Warn,
            format!("{ex} writes {field} to the log with its line break: a request can add log lines of its own; escape \\r and \\n"),
            json!({"field": path, "text": text}),
            Some(r.id.as_str()),
        ));
    }
    out
}

/// Every text in a host call's arguments.
fn texts<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| texts(x, out)),
        Value::Object(o) => o.values().for_each(|x| texts(x, out)),
        _ => {}
    }
}

/// Host calls to a plain `http://` URL off the platform's own network
/// that carry a value labelled `secret` or `pii`.
fn cleartext(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let traced = crate::labels::sensitive(r, m);
    if traced.is_empty() {
        return vec![];
    }
    let ex = &r.spec.export;
    let mut out: Vec<Finding> = Vec::new();
    for e in &r.events {
        let mut args = Vec::new();
        for v in e.args.values() {
            texts(v, &mut args);
        }
        let plain = args.iter().find_map(|t| {
            let t = t.trim();
            let scheme = t.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("http://"));
            scheme.then(|| crate::dest::absolute(t)).flatten().filter(|d| d.class != crate::dest::Class::Internal).map(|d| (t, d))
        });
        let Some((url, d)) = plain else { continue };
        let Some(t) = traced.iter().find(|t| args.iter().any(|a| a.contains(t.value.as_str()))) else { continue };
        let key = format!("{ex}\0cleartext\0{}\0{}", e.func, d.target);
        if out.iter().any(|f| f.detail["key"] == key) {
            continue;
        }
        let what = if t.label == Label::Secret { "the secret" } else { "personal data" };
        out.push(Finding::new(
            "cleartext_transport",
            &key,
            Severity::Fail,
            format!("{} sends {what} {} returned to {} over plain HTTP: anyone on the way can read it; use https", e.func, t.func, d.target),
            json!({"key": key, "func": e.func, "n": e.n, "url": url, "host": d.target, "label": t.label.name(), "source": t.func}),
            Some(r.id.as_str()),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{HostCall, Outcome, RunSpec, Totals};

    fn manifest() -> Manifest {
        toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "h"
            output = { status = "status", body = "body", headers = "headers" }
            [functions."x:y/config#secret"]
            result = "secret"
            [functions."x:y/http#fetch"]
            params = { url = "url", auth = "secret" }
            "#,
        )
        .unwrap()
    }

    fn run(path: &str, headers: Value, stdout: &str, events: Vec<HostCall>) -> RunRecord {
        RunRecord {
            id: "r1".into(),
            spec: RunSpec {
                component: String::new(),
                contract: String::new(),
                export: "h".into(),
                args: vec![json!({"method": "GET", "path": path, "query": []})],
                plan: Default::default(),
                now: String::new(),
                seed: 0,
                fuel: 0,
                memory: 0,
                ns_per_fuel: 0.0,
            },
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: Some(json!({"status": 200, "body": "<p>ok</p>", "headers": headers})),
            totals: Totals::default(),
            events,
            guest_error: None,
            rejected_output: None,
            shopify: None,
            command_exit_code: None,
            memory_limit_hit: false,
            capture_limited: false,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn kinds(f: &[Finding]) -> Vec<(&str, Severity)> {
        f.iter().map(|f| (f.kind.as_str(), f.severity)).collect()
    }

    #[test]
    fn session_cookies_need_httponly_and_secure() {
        let m = manifest();
        let cookie = |v: &str| check(&run("/", json!([["set-cookie", v]]), "", vec![]), &m);
        let f = cookie("session=8f3a9c2e; Path=/");
        assert_eq!(kinds(&f), [("insecure_cookie", Severity::Fail)]);
        assert_eq!(
            f[0].title,
            "h sets the session cookie session without HttpOnly and Secure: scripts on the page can read it, and the browser also sends it over plain HTTP"
        );
        assert!(cookie("sid=8f3a9c2e; Secure").iter().any(|f| f.title.ends_with("without HttpOnly: scripts on the page can read it")));
        assert!(cookie("session=8f3a9c2e; Path=/; HttpOnly; Secure; SameSite=Lax").is_empty());
        // Clearing a cookie, a CSRF token scripts must read, a cookie that is no session.
        assert!(cookie("session=; Max-Age=0").is_empty());
        assert!(cookie("csrf_token=8f3a9c2e; Secure").is_empty());
        assert!(cookie("theme=dark").is_empty());
    }

    #[test]
    fn request_text_with_a_line_break_in_the_log_forges_lines() {
        let m = manifest();
        let f = check(&run("/a\r\nINFO admin signed in", json!([]), "GET /a\r\nINFO admin signed in\n", vec![]), &m);
        assert_eq!(kinds(&f), [("log_injection", Severity::Warn)]);
        assert!(f[0].title.starts_with("h writes request field path to the log"), "{}", f[0].title);
        assert!(check(&run("/a\r\nINFO admin signed in", json!([]), "GET \"/a\\r\\nINFO admin signed in\"\n", vec![]), &m).is_empty());
        assert!(check(&run("/a b", json!([]), "GET /a b\n", vec![]), &m).is_empty());
    }

    #[test]
    fn secrets_sent_to_plain_http_urls_are_cleartext() {
        let m = manifest();
        let call = |n: u32, func: &str, args: Value, result: Value| HostCall {
            n,
            func: func.into(),
            args: args.as_object().cloned().unwrap_or_default(),
            result: Some(result),
            ..Default::default()
        };
        let secret = || call(1, "x:y/config#secret", json!({"name": "api"}), json!("sk_live_0123456789"));
        let fetch = |url: &str| call(2, "x:y/http#fetch", json!({"url": url, "auth": "sk_live_0123456789"}), json!({"ok": ""}));
        let f = check(&run("/", json!([]), "", vec![secret(), fetch("http://api.example.com/v1")]), &m);
        assert_eq!(kinds(&f), [("cleartext_transport", Severity::Fail)]);
        assert_eq!(
            f[0].title,
            "x:y/http#fetch sends the secret x:y/config#secret returned to api.example.com over plain HTTP: anyone on the way can read it; use https"
        );
        assert!(check(&run("/", json!([]), "", vec![secret(), fetch("https://api.example.com/v1")]), &m).is_empty());
        assert!(check(&run("/", json!([]), "", vec![secret(), fetch("http://127.0.0.1:8080/v1")]), &m).is_empty());
        let plain = call(2, "x:y/http#fetch", json!({"url": "http://api.example.com/v1", "auth": ""}), json!({"ok": ""}));
        assert!(check(&run("/", json!([]), "", vec![secret(), plain]), &m).is_empty());
    }
}
