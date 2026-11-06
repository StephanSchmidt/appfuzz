//! Mistakes of HTTP handlers that a reviewer looks for, judged on one run:
//!
//! - `permissive_cors`: the response lets another website read it with the
//!   visitor's cookies (`Access-Control-Allow-Origin` repeats a foreign
//!   `Origin`, or allows `null`, with `Access-Control-Allow-Credentials:
//!   true`).
//! - `host_header_injection`: a host the client chose (the URI's host,
//!   `Host`, `X-Forwarded-Host`, `Forwarded: host=`) ends up in an absolute
//!   URL: a redirect, a link in the page (a password reset link that points
//!   to the attacker), or an outbound request.
//!
//! They apply to entries whose request has a `uri` and `headers`, as
//! `wasi:http` handlers do. `probe web` sends the requests that show them.

use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::manifest::Manifest;
use crate::record::RunRecord;

/// The host `probe web` claims to be.
pub const ATTACKER_HOST: &str = "attacker.example";

fn pairs(v: Option<&Value>) -> Vec<(String, String)> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| Some((p.get(0)?.as_str()?.to_string(), p.get(1)?.as_str()?.to_string()))).collect())
        .unwrap_or_default()
}

pub(crate) fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim())
}

/// The host of an absolute URL or origin, lowercased, without the port.
pub fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    let auth = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let host = match auth.rfind(':') {
        Some(i) if !auth.ends_with(']') => &auth[..i],
        _ => auth,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The app's own host: that of the manifest's request.
fn own_host(m: &Manifest) -> String {
    m.entry
        .as_ref()
        .and_then(|e| e.request.as_ref())
        .and_then(|r| r.get("uri"))
        .and_then(Value::as_str)
        .and_then(host_of)
        .unwrap_or_else(|| "app.example".into())
}

/// The hosts the client claims, with where each comes from.
fn claimed_hosts(uri: &str, h: &[(String, String)]) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    if let Some(x) = host_of(uri) {
        out.push((x, "the host the request names (its Host header)"));
    }
    let bare = |v: &str| v.split(',').next().unwrap_or_default().trim().split(':').next().unwrap_or_default().to_ascii_lowercase();
    if let Some(v) = header(h, "host") {
        out.push((bare(v), "the Host header"));
    }
    if let Some(v) = header(h, "x-forwarded-host") {
        out.push((bare(v), "the X-Forwarded-Host header"));
    }
    if let Some(v) = header(h, "forwarded")
        && let Some(i) = v.to_ascii_lowercase().find("host=")
    {
        out.push((bare(v[i + 5..].trim_matches('"').split([';', '"']).next().unwrap_or_default()), "the Forwarded header"));
    }
    out
}

pub fn check(r: &RunRecord, m: &Manifest) -> Vec<Finding> {
    let Some(req) = r.spec.args.first() else { return Vec::new() };
    let (Some(uri), Some(_)) = (req.get("uri").and_then(Value::as_str), req.get("headers").and_then(Value::as_array)) else { return Vec::new() };
    let ex = &r.spec.export;
    let run = Some(r.id.as_str());
    let rh = pairs(req.get("headers"));
    let resp = crate::output::response(r, m);
    let own = own_host(m);
    let mut out = Vec::new();

    // CORS: with credentials, a reflected origin lets any site read the
    // response as the visitor. Without them it is the same as `*`.
    if let Some(origin) = header(&rh, "origin")
        && let Some(allow) = header(&resp.headers, "access-control-allow-origin")
        && header(&resp.headers, "access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"))
        && allow.eq_ignore_ascii_case(origin)
        && (origin == "null" || host_of(origin).is_some_and(|h| h != own))
    {
        let who = if origin == "null" { "a sandboxed iframe or a local file (Origin null)".to_string() } else { format!("the website {origin}") };
        out.push(Finding::new(
            "permissive_cors",
            &format!("{ex}\0cors"),
            Severity::Fail,
            format!("{ex} lets {who} read its response with the visitor's cookies: Access-Control-Allow-Origin repeats the Origin and Access-Control-Allow-Credentials is true"),
            json!({"origin": origin, "allow_origin": allow, "method": req.get("method")}),
            run,
        ));
    }

    // Host: a host the client chose, in an absolute URL the app makes.
    for (host, from) in claimed_hosts(uri, &rh) {
        if host == own || host.len() < 4 || !host.contains('.') {
            continue;
        }
        // Only the host field may carry it, or it may have come from elsewhere.
        let lower = |t: &str| t.to_ascii_lowercase();
        let path_part = uri.split_once("://").map_or(uri, |(_, r)| &r[r.find(['/', '?', '#']).unwrap_or(r.len())..]);
        let elsewhere = lower(path_part).contains(&host)
            || req.get("body").and_then(Value::as_str).is_some_and(|b| lower(b).contains(&host))
            || rh.iter().filter(|(k, _)| !["host", "x-forwarded-host", "forwarded"].contains(&lower(k).as_str())).any(|(_, v)| lower(v).contains(&host))
            || (from != "the host the request names (its Host header)" && host_of(uri).is_some_and(|h| h == host));
        if elsewhere {
            continue;
        }
        // `scheme://host` anywhere in the text.
        let in_url = |t: &str| {
            t.match_indices("://").any(|(i, _)| {
                let start = t[..i].rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))).map_or(0, |j| j + 1);
                host_of(&t[start..]).is_some_and(|h| h == host)
            })
        };
        let mut place = None;
        for e in &r.events {
            for v in e.text_args().values() {
                if v.as_str().is_some_and(in_url) {
                    place = Some((format!("the URL of {}", e.func), Severity::Fail));
                }
            }
        }
        if place.is_none()
            && let Some(l) = header(&resp.headers, "location").filter(|l| in_url(l))
        {
            place = Some((format!("the redirect (Location: {})", l.chars().take(80).collect::<String>()), Severity::Warn));
        }
        if place.is_none() && resp.body.as_deref().is_some_and(in_url) {
            place = Some(("a link in the response".into(), Severity::Warn));
        }
        if let Some((place, sev)) = place {
            out.push(Finding::new(
                "host_header_injection",
                &format!("{ex}\0{from}"),
                sev,
                format!("{from} ({host}) goes into {place}: build absolute URLs from a configured host, not from the request"),
                json!({"host": host, "from": from, "place": place}),
                run,
            ));
        }
    }
    out
}

/// The requests `probe web` sends: the base request with a foreign
/// Origin, or claiming a foreign host. Empty when the request has no
/// `uri` and `headers`.
pub fn variants(base: &Value, m: &Manifest) -> Vec<(String, Value)> {
    let (Some(uri), Some(_)) = (base.get("uri").and_then(Value::as_str), base.get("headers").and_then(Value::as_array)) else { return Vec::new() };
    let own = own_host(m);
    let with = |name: &str, value: &str| {
        let mut v = base.clone();
        let hs = v["headers"].as_array_mut().expect("checked");
        hs.retain(|p| !p.get(0).and_then(Value::as_str).is_some_and(|k| k.eq_ignore_ascii_case(name)));
        hs.push(json!([name, value]));
        v
    };
    let mut out = Vec::new();
    for origin in [format!("https://{ATTACKER_HOST}"), "null".into(), format!("https://{own}.{ATTACKER_HOST}"), format!("https://not{own}")] {
        out.push((format!("Origin: {origin}"), with("origin", &origin)));
        let mut pre = with("origin", &origin);
        pre["method"] = json!("OPTIONS");
        pre["headers"].as_array_mut().expect("checked").push(json!(["access-control-request-method", "POST"]));
        out.push((format!("preflight from {origin}"), pre));
    }
    let mut v = base.clone();
    v["uri"] = json!(match uri.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{ATTACKER_HOST}{}", &rest[rest.find(['/', '?', '#']).unwrap_or(rest.len())..]),
        None => format!("https://{ATTACKER_HOST}{}{uri}", if uri.starts_with('/') { "" } else { "/" }),
    });
    out.push(("the URI's host".into(), v));
    out.push(("Host header".into(), with("host", ATTACKER_HOST)));
    out.push(("X-Forwarded-Host header".into(), with("x-forwarded-host", ATTACKER_HOST)));
    out.push(("Forwarded header".into(), with("forwarded", &format!("host={ATTACKER_HOST}"))));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://a.example:8080/x").as_deref(), Some("a.example"));
        assert_eq!(host_of("https://u:p@B.example?x").as_deref(), Some("b.example"));
        assert_eq!(host_of("/x"), None);
        assert_eq!(host_of("aaa?url=http://169.254.169.254/"), None);
        let h = vec![("Forwarded".to_string(), "for=1.2.3.4;host=\"evil.example\";proto=https".to_string())];
        assert_eq!(claimed_hosts("/", &h), vec![("evil.example".to_string(), "the Forwarded header")]);
    }
}
