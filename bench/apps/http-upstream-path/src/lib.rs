//! Bench app `http-upstream-path`: a wasi:http handler that puts `?id=`
//! into the path of its API request as it is. `?id=../admin/users` reaches
//! an endpoint the app never meant to call, with the app's API token.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::outgoing_handler;
use wasi::http::types::{Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse, ResponseOutparam, Scheme};

struct A;
export!(A);

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let pq = req.path_with_query().unwrap_or_default();
        let id = param(&pq, "id").unwrap_or_else(|| "1".into());
        // Bug: `id` is not percent-encoded.
        let order = fetch(&format!("/orders/{id}"));
        respond(out, &format!("<h1>Order</h1><pre>{}</pre>", escape(&order)));
    }
}

fn param(pq: &str, name: &str) -> Option<String> {
    let (_, q) = pq.split_once('?')?;
    q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn fetch(path: &str) -> String {
    let headers = Fields::new();
    let _ = headers.append("authorization", b"Bearer orders-api-token");
    let req = OutgoingRequest::new(headers);
    let _ = req.set_method(&Method::Get);
    let _ = req.set_scheme(Some(&Scheme::Https));
    if req.set_authority(Some("api.example")).is_err() || req.set_path_with_query(Some(path)).is_err() {
        return "bad id".into();
    }
    let Ok(future) = outgoing_handler::handle(req, None) else { return "unavailable".into() };
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

fn respond(out: ResponseOutparam, html: &str) {
    let headers = Fields::new();
    let _ = headers.append("content-type", b"text/html; charset=utf-8");
    let resp = OutgoingResponse::new(headers);
    let body = resp.body().expect("one body");
    ResponseOutparam::set(out, Ok(resp));
    let stream = body.write().expect("one stream");
    for chunk in html.as_bytes().chunks(4096) {
        let _ = stream.blocking_write_and_flush(chunk);
    }
    drop(stream);
    let _ = OutgoingBody::finish(body, None);
}
