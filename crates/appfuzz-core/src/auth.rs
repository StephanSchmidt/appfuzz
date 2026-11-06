//! Credentials that are only looked at, not checked (`auth_bypass`): an
//! HTTP handler that turns away a request without credentials (401, 403,
//! a redirect to a login) but accepts made-up ones. A made-up bearer
//! token, an unsigned JWT (`alg: none`), a JWT with a wrong signature,
//! `Basic admin:admin` or a made-up session cookie can only get through if
//! the app checks that a credential is there, or decodes a JWT without
//! verifying it.
//!
//! The run is the proof: the same request without credentials was turned
//! away, with forged ones it got a 2xx. A credential that went to a host
//! call (a session lookup, a token service) is left out: there the
//! simulated host decided, not the app.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::record::{OutcomeKind, RunRecord};
use crate::web::header;

/// Headers that carry credentials; the request without them is anonymous.
const CREDENTIALS: [&str; 5] = ["authorization", "proxy-authorization", "cookie", "x-api-key", "x-auth-token"];

const TOKEN: &str = "afz-forged-token-0000";
/// `{"alg":"none","typ":"JWT"}` . `{"sub":"1","name":"admin","role":"admin","admin":true,…,"exp":4102444800}` . (no signature)
const JWT_NONE: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.";
/// The same claims as HS256 with a signature nobody made.
const JWT_FORGED: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiYWRtaW4iOnRydWUsImlhdCI6MTc2NzIyNTYwMCwiZXhwIjo0MTAyNDQ0ODAwfQ.YWZ6LWZvcmdlZC1zaWduYXR1cmUtMDAwMDAwMDAwMA";
/// `admin:admin`.
const BASIC: &str = "YWRtaW46YWRtaW4=";
const COOKIES: [&str; 7] = ["session", "sid", "sessionid", "token", "auth", "jwt", "access_token"];

/// Whether the request is an HTTP request with headers.
fn http(req: &Value) -> bool {
    req.get("uri").and_then(Value::as_str).is_some() && req.get("headers").and_then(Value::as_array).is_some()
}

/// The request without credentials.
pub fn anonymous(req: &Value) -> Option<Value> {
    if !http(req) {
        return None;
    }
    let mut v = req.clone();
    v["headers"]
        .as_array_mut()
        .expect("checked")
        .retain(|p| !p.get(0).and_then(Value::as_str).is_some_and(|k| CREDENTIALS.iter().any(|c| k.eq_ignore_ascii_case(c))));
    Some(v)
}

/// A forged credential: what it is, the texts that show it went to a
/// host call, and the request carrying it.
pub struct Forged {
    pub what: &'static str,
    pub traces: Vec<&'static str>,
    pub request: Value,
}

/// The anonymous request with each forged credential.
pub fn forged(anon: &Value) -> Vec<Forged> {
    let cookies = |v: &str| COOKIES.iter().map(|c| format!("{c}={v}")).collect::<Vec<_>>().join("; ");
    let list: Vec<(&'static str, Vec<&'static str>, &str, String)> = vec![
        ("a made-up bearer token", vec![TOKEN], "authorization", format!("Bearer {TOKEN}")),
        ("Bearer null", vec![], "authorization", "Bearer null".into()),
        ("an unsigned JWT (alg none)", vec![JWT_NONE], "authorization", format!("Bearer {JWT_NONE}")),
        ("a JWT with a wrong signature", vec![JWT_FORGED], "authorization", format!("Bearer {JWT_FORGED}")),
        ("Basic admin:admin", vec![BASIC, "admin"], "authorization", format!("Basic {BASIC}")),
        ("a made-up API key", vec![TOKEN], "x-api-key", TOKEN.into()),
        ("made-up session cookies", vec![TOKEN], "cookie", cookies(TOKEN)),
        ("an unsigned JWT in a cookie", vec![JWT_NONE], "cookie", cookies(JWT_NONE)),
    ];
    list.into_iter()
        .map(|(what, traces, name, value)| {
            let mut request = anon.clone();
            request["headers"].as_array_mut().expect("anonymous request").push(json!([name, value]));
            Forged { what, traces, request }
        })
        .collect()
}

fn has_text(v: &Value, t: &str) -> bool {
    match v {
        Value::String(s) => s.contains(t),
        Value::Array(a) => a.iter().any(|x| has_text(x, t)),
        Value::Object(o) => o.values().any(|x| has_text(x, t)),
        _ => false,
    }
}

/// The path of the request's URI, without the query.
pub fn path(req: &Value) -> String {
    let uri = req.get("uri").and_then(Value::as_str).unwrap_or_default();
    let rest = uri.split_once("://").map_or(uri, |(_, r)| &r[r.find(['/', '?', '#']).unwrap_or(r.len())..]);
    let p = rest.split(['?', '#']).next().unwrap_or_default();
    if p.is_empty() { "/".into() } else { p.into() }
}

fn status(r: &RunRecord, m: &Manifest) -> Option<i64> {
    crate::output::response(r, m).status
}

/// The status of a request turned away for lacking credentials: 401, 403,
/// or a redirect (to a login page).
pub fn rejected(r: &RunRecord, m: &Manifest) -> Option<i64> {
    let s = status(r, m)?;
    let resp = crate::output::response(r, m);
    (s == 401 || s == 403 || ((300..400).contains(&s) && header(&resp.headers, "location").is_some())).then_some(s)
}

/// The finding when forged credentials got a 2xx where the anonymous
/// request was turned away. `runs` pairs each forged credential with its run.
/// How `probe auth` found a finding, so `confirm` and `replay` can do it
/// again from the run it started from (the finding's `base_run`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "check")]
pub enum Recipe {
    /// The request without credentials, then with this forged credential.
    Bypass { forged: String },
    /// Prefixes of the secret in place of this forged credential.
    Timing { forged: String },
    /// Other random seeds and a second later.
    Token,
}

impl Recipe {
    /// Runs one test costs, at most.
    pub fn runs(&self) -> u32 {
        match self {
            Recipe::Bypass { .. } => 2,
            // The run, up to 24 prefixes, the control and the whole secret.
            Recipe::Timing { .. } => 27,
            Recipe::Token => 4,
        }
    }

    /// Records the recipe and its starting run on `f`.
    pub fn mark(&self, mut f: Finding, base_run: &str) -> Finding {
        f.detail["auth"] = json!(self);
        f.detail["base_run"] = json!(base_run);
        f
    }
}

pub fn check(anon: &RunRecord, runs: &[(&Forged, &RunRecord)], m: &Manifest) -> Option<Finding> {
    let turned_away = rejected(anon, m)?;
    let accepted: Vec<(&Forged, &RunRecord, i64)> = runs
        .iter()
        .filter_map(|(f, r)| {
            let s = status(r, m).filter(|s| (200..300).contains(s))?;
            let to_host = r.events.iter().any(|e| e.text_args().values().any(|v| f.traces.iter().any(|t| has_text(v, t))));
            (!to_host).then_some((*f, *r, s))
        })
        .collect();
    let (first, run, s) = accepted.first()?;
    let ex = &anon.spec.export;
    let p = anon.spec.args.first().map(path).unwrap_or_default();
    let also = match accepted.len() {
        1 => String::new(),
        2 => " and 1 other forged credential".into(),
        n => format!(" and {} other forged credentials", n - 1),
    };
    let f = Finding::new(
        "auth_bypass",
        &format!("{ex}\0auth"),
        Severity::Fail,
        format!(
            "{ex} turns away {p} without credentials ({turned_away}) but lets in {}{also} ({s}): verify the credential (the JWT's signature, the token against the secret), not only that one is there",
            first.what
        ),
        json!({
            "path": p,
            "anonymous_run": anon.id,
            "anonymous_status": turned_away,
            "accepted": accepted.iter().map(|(f, r, s)| json!({"what": f.what, "run": r.id, "status": s})).collect::<Vec<_>>(),
        }),
        Some(run.id.as_str()),
    );
    Some(Recipe::Bypass { forged: first.what.into() }.mark(f, &anon.id))
}

/// Secrets a run read from host calls (results labelled `secret`).
pub fn secrets(r: &RunRecord, m: &Manifest) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in &r.events {
        let Some(v) = &e.result else { continue };
        for (p, l) in m.call_result_labels(&e.func, &e.args) {
            if l == crate::labels::Label::Secret {
                for s in crate::labels::values_at(v, &p) {
                    if s.chars().count() >= 8 && !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
    }
    out
}

/// The same character class, another character: a parser that stops at an
/// unexpected character costs the same for every candidate.
fn other(c: char, by: u8) -> char {
    const HEX: &str = "0123456789abcdef";
    let rot = |set: &str| set.find(c).map(|i| set.as_bytes()[(i + by as usize) % set.len()] as char);
    rot(HEX).or_else(|| rot("0123456789ABCDEF")).or_else(|| rot("abcdefghijklmnopqrstuvwxyz")).or_else(|| rot("ABCDEFGHIJKLMNOPQRSTUVWXYZ")).unwrap_or(c)
}

/// The secret's first `k` characters, the rest replaced: as long as the
/// secret, so a comparison gets past the length check.
pub fn prefix_of(secret: &str, k: usize, by: u8) -> String {
    secret.chars().enumerate().map(|(i, c)| if i < k { c } else { other(c, by) }).collect()
}

/// The prefix lengths to try: every one, or 12 spread over a long secret.
pub fn prefix_lengths(secret: &str) -> Vec<usize> {
    let n = secret.chars().count();
    if n <= 24 { (0..n).collect() } else { (0..12).map(|i| i * (n - 1) / 11).collect() }
}

/// `timing_unsafe_compare` when the fuel of the candidates grows with the
/// correct prefix. `fuel[i]` is the run with `lengths[i]` correct leading
/// characters; `control` is the run with none, other characters.
pub fn timing(ex: &str, what: &str, lengths: &[usize], runs: &[&RunRecord], control: &RunRecord) -> Option<Finding> {
    if runs.iter().chain([&control]).any(|r| r.outcome.kind != OutcomeKind::Ok) || runs.len() < 4 {
        return None;
    }
    let fuel: Vec<u64> = runs.iter().map(|r| r.totals.fuel).collect();
    let rises = fuel.windows(2).filter(|w| w[1] > w[0]).count();
    let steady = control.totals.fuel == fuel[0] && fuel.windows(2).all(|w| w[1] >= w[0]);
    if !steady || rises < 2 {
        return None;
    }
    let last = runs.len() - 1;
    Some(Finding::new(
        "timing_unsafe_compare",
        &format!("{ex}\0timing"),
        Severity::Warn,
        format!(
            "{ex} compares {what} with its secret one character at a time: each correct leading character costs more ({} instructions with none right, {} with {}), so the secret can be guessed character by character from response times; compare in constant time",
            fuel[0], fuel[last], lengths[last]
        ),
        json!({"credential": what, "prefix_lengths": lengths, "fuel": fuel, "runs": runs.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), "control_run": control.id}),
        Some(runs[last].id.as_str()),
    ))
}

static TOKEN_NAME: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)sess|sid|token|auth|jwt|login|remember|csrf|xsrf|reset|api.?key|nonce|otp").unwrap());

/// Session tokens in the response: session-like `Set-Cookie` values and
/// token-like JSON fields, as (where, value). Not JWTs and other signed
/// tokens (three dot-separated parts), not text the request or a host
/// call brought.
pub fn tokens(r: &RunRecord, m: &Manifest) -> Vec<(String, String)> {
    let resp = crate::output::response(r, m);
    let mut out = Vec::new();
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie")
            && let Some((name, value)) = v.split(';').next().unwrap_or_default().split_once('=')
            && TOKEN_NAME.is_match(name)
        {
            out.push((format!("the cookie {}", name.trim()), value.trim().trim_matches('"').to_string()));
        }
    }
    fn fields(v: &Value, out: &mut Vec<(String, String)>) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    match x {
                        Value::String(s) if TOKEN_NAME.is_match(k) => out.push((format!("the field {k}"), s.clone())),
                        _ => fields(x, out),
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| fields(x, out)),
            _ => {}
        }
    }
    if let Some(body) = resp.body.as_deref()
        && let Ok(v) = serde_json::from_str::<Value>(body)
    {
        fields(&v, &mut out);
    }
    let brought = |t: &str| r.spec.args.iter().any(|a| has_text(a, t)) || r.events.iter().any(|e| e.result.as_ref().is_some_and(|v| has_text(v, t)));
    out.retain(|(_, v)| v.len() >= 8 && v.matches('.').count() != 2 && !brought(v));
    out
}

/// `predictable_token` for tokens that stay the same under other random
/// seeds. `seeds` are the run with other seeds, `clock` one second later.
pub fn predictable(r: &RunRecord, seeds: &[&RunRecord], clock: Option<&RunRecord>, m: &Manifest) -> Vec<Finding> {
    // A token made with a secret (signed) is not guessable without it.
    if !secrets(r, m).is_empty() || seeds.is_empty() {
        return Vec::new();
    }
    let ex = &r.spec.export;
    let mut out = Vec::new();
    for (place, value) in tokens(r, m) {
        let same = |x: &RunRecord| tokens(x, m).into_iter().any(|(p, v)| p == place && v == value);
        if !seeds.iter().all(|x| same(x)) {
            continue;
        }
        let timed = clock.is_some_and(|c| c.outcome.kind == OutcomeKind::Ok && !same(c) && tokens(c, m).iter().any(|(p, _)| *p == place));
        let how = if timed {
            "it is made from the clock, not from random bytes: anyone who knows roughly when it was issued can compute it"
        } else {
            "it is the same every time: anyone can use it"
        };
        out.push(Finding::new(
            "predictable_token",
            &format!("{ex}\0token\0{place}"),
            Severity::Fail,
            format!("{place} ({}) is the same with other random seeds; {how}. Make it from 16 or more random bytes", value.chars().take(24).collect::<String>()),
            json!({"place": place, "value": value, "clock_dependent": timed, "seed_runs": seeds.iter().map(|x| x.id.clone()).collect::<Vec<_>>(), "clock_run": clock.map(|c| c.id.clone())}),
            Some(r.id.as_str()),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests() {
        let req =
            json!({"method": "GET", "uri": "https://app.example/admin/x?y=1", "headers": [["Authorization", "Bearer real"], ["accept", "*/*"]], "body": ""});
        let anon = anonymous(&req).unwrap();
        assert_eq!(anon["headers"], json!([["accept", "*/*"]]));
        assert_eq!(path(&req), "/admin/x");
        assert_eq!(path(&json!({"uri": "https://app.example?x"})), "/");
        let f = forged(&anon);
        assert!(f.iter().all(|f| f.request["headers"].as_array().unwrap().len() == 2));
        assert!(anonymous(&json!({"path": "/"})).is_none());
    }

    #[test]
    fn prefixes() {
        let s = "sk_00ff9a";
        assert_eq!(prefix_of(s, 0, 1), "tl_1100ab");
        assert_eq!(prefix_of(s, 4, 1), "sk_0100ab");
        assert_eq!(prefix_of(s, 9, 1), s);
        assert_ne!(prefix_of(s, 0, 1), prefix_of(s, 0, 2));
        assert_eq!(prefix_lengths(s).len(), 9);
        assert_eq!(prefix_lengths(&"x".repeat(40)), vec![0, 3, 7, 10, 14, 17, 21, 24, 28, 31, 35, 39]);
    }
}
