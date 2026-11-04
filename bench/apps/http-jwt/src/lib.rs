//! Bench app `http-jwt`: an account page behind a bearer JWT. It turns
//! away requests without one, but only decodes the token's claims: the
//! signature is never checked, so any made-up JWT (even `alg: none`) gets
//! in as whoever it names.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct A;
export!(A);

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let auth = req.headers().get("authorization").into_iter().next().map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
        let Some(user) = auth.strip_prefix("Bearer ").and_then(subject) else {
            return respond(out, 401, "{\"error\":\"sign in first\"}");
        };
        respond(out, 200, &format!("{{\"account\":\"{}\",\"plan\":\"pro\"}}", user.replace(['"', '\\'], "")));
    }
}

/// The `sub` claim of a JWT: header.payload.signature, payload base64url JSON.
fn subject(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let json = String::from_utf8(b64url(payload)?).ok()?;
    let rest = &json[json.find("\"sub\":\"")? + 7..];
    Some(rest[..rest.find('"')?].to_string())
}

fn b64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return None,
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn respond(out: ResponseOutparam, status: u16, json: &str) {
    let headers = Fields::new();
    let _ = headers.append("content-type", b"application/json");
    let resp = OutgoingResponse::new(headers);
    let _ = resp.set_status_code(status);
    let body = resp.body().expect("one body");
    ResponseOutparam::set(out, Ok(resp));
    let stream = body.write().expect("one stream");
    stream.blocking_write_and_flush(json.as_bytes()).expect("write");
    drop(stream);
    let _ = OutgoingBody::finish(body, None);
}
