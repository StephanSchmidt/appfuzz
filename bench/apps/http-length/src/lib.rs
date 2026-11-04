//! Bench app `http-length`: a wasi:http handler that sets Content-Length
//! from the text before escaping it, so the body is longer than announced.
//! `/logo.png` sends bytes that are not UTF-8, with trailers: no finding.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct A;
export!(A);

fn send(out: ResponseOutparam, headers: &[(&str, String)], body: &[u8], trailers: Option<Fields>) {
    let h = Fields::new();
    for (k, v) in headers {
        let _ = h.append(k, v.as_bytes());
    }
    let resp = OutgoingResponse::new(h);
    let b = resp.body().expect("one body");
    ResponseOutparam::set(out, Ok(resp));
    let stream = b.write().expect("one stream");
    // At most 4096 bytes per blocking write.
    for chunk in body.chunks(4096) {
        let _ = stream.blocking_write_and_flush(chunk);
    }
    drop(stream);
    let _ = OutgoingBody::finish(b, trailers);
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let pq = req.path_with_query().unwrap_or_default();
        if pq.starts_with("/logo.png") {
            let png = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0xff, 0xfe];
            let t = Fields::new();
            let _ = t.append("x-checksum", b"9f2c");
            send(out, &[("content-type", "image/png".into()), ("content-length", png.len().to_string())], &png, Some(t));
            return;
        }
        let name = pq.split_once("name=").map(|(_, v)| v.split('&').next().unwrap_or_default()).unwrap_or("guest");
        // Bug: the length of the raw text, not of the escaped one.
        let len = "<h1>Hello, </h1>".len() + name.len();
        let page = format!("<h1>Hello, {}</h1>", escape(name));
        send(out, &[("content-type", "text/html".into()), ("content-length", len.to_string())], page.as_bytes(), None);
    }
}
