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
    (r.outcome.kind == OutcomeKind::Ok).then(|| crate::output::response(r, m).status).flatten()
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
pub fn check(anon: &RunRecord, runs: &[(&Forged, &RunRecord)], m: &Manifest) -> Option<Finding> {
    let turned_away = rejected(anon, m)?;
    let accepted: Vec<(&Forged, &RunRecord, i64)> = runs
        .iter()
        .filter_map(|(f, r)| {
            let s = status(r, m).filter(|s| (200..300).contains(s))?;
            let to_host = r.events.iter().any(|e| e.args.values().any(|v| f.traces.iter().any(|t| has_text(v, t))));
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
    Some(Finding::new(
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
    ))
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
}
