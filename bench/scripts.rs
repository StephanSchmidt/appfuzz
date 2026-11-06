// For bench apps whose pages run scripts (html:scripts): a page with a
// Content-Security-Policy, and the files its scripts load.

/// A policy that keeps scripts and their requests on the app's origin.
#[allow(dead_code)]
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'";

#[allow(dead_code)]
fn page(body: &str, csp: &str) -> Response {
    let html = format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>bench</title></head><body>{body}</body></html>");
    Response { status: 200, body: html, headers: vec![("content-type".into(), "text/html".into()), ("content-security-policy".into(), csp.into())] }
}

/// A file the page loads: a script, a style, JSON.
#[allow(dead_code)]
fn file(body: &str, content_type: &str) -> Response {
    Response { status: 200, body: body.into(), headers: vec![("content-type".into(), content_type.into())] }
}

#[allow(dead_code)]
fn not_found() -> Response {
    Response { status: 404, body: "not found".into(), headers: vec![("content-type".into(), "text/plain".into())] }
}

/// A JSON string literal.
#[allow(dead_code)]
fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o += "\\\"",
            '\\' => o += "\\\\",
            c if (c as u32) < 0x20 => o += &format!("\\u{:04x}", c as u32),
            c => o.push(c),
        }
    }
    o + "\""
}
