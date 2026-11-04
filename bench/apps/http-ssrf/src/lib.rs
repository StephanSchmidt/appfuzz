//! Bench app `http-ssrf`: a wasi:http handler that fetches the URL in its
//! query string and shows the answer unescaped.
//!
//! Written against raw wasi:http like an SDK would: the request body is
//! written after `outgoing-handler.handle`, the response body after
//! `response-outparam.set`.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::outgoing_handler;
use wasi::http::types::{Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse, ResponseOutparam, Scheme};

struct A;
export!(A);

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let pq = req.path_with_query().unwrap_or_default();
        let url = param(&pq, "url").unwrap_or_else(|| "https://api.example/status".into());
        let status = fetch(&url, "{\"ping\":1}");
        respond(out, 200, &format!("<h1>Status</h1><div>{status}</div>"));
    }
}

fn param(pq: &str, name: &str) -> Option<String> {
    let (_, q) = pq.split_once('?')?;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn fetch(url: &str, payload: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let req = OutgoingRequest::new(Fields::new());
    let _ = req.set_method(&Method::Post);
    let _ = req.set_scheme(Some(&if scheme == "http" { Scheme::Http } else { Scheme::Https }));
    if req.set_authority(Some(authority)).is_err() || req.set_path_with_query(Some(path)).is_err() {
        return "bad url".into();
    }
    let body = req.body().expect("one body");
    let Ok(future) = outgoing_handler::handle(req, None) else { return "unavailable".into() };
    write(&body, payload.as_bytes());
    let _ = OutgoingBody::finish(body, None);
    future.subscribe().block();
    let resp = match future.get() {
        Some(Ok(Ok(r))) => r,
        _ => return "unavailable".into(),
    };
    let body = resp.consume().expect("one body");
    let stream = body.stream().expect("one stream");
    let mut text = Vec::new();
    while let Ok(chunk) = stream.blocking_read(4096) {
        text.extend(chunk);
    }
    String::from_utf8_lossy(&text).into_owned()
}

fn write(body: &OutgoingBody, bytes: &[u8]) {
    let stream = body.write().expect("one stream");
    for chunk in bytes.chunks(4096) {
        stream.blocking_write_and_flush(chunk).expect("write");
    }
}

fn respond(out: ResponseOutparam, status: u16, html: &str) {
    let headers = Fields::new();
    let _ = headers.append("content-type", b"text/html; charset=utf-8");
    let resp = OutgoingResponse::new(headers);
    let _ = resp.set_status_code(status);
    let body = resp.body().expect("one body");
    ResponseOutparam::set(out, Ok(resp));
    write(&body, html.as_bytes());
    let _ = OutgoingBody::finish(body, None);
}
