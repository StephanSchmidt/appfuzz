//! Bench app `http-reset-link`: a password reset page that builds the link
//! in the mail from the Host header. A request with `Host: attacker.example`
//! mails the victim a link to the attacker, token included.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct A;
export!(A);

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let host = req.headers().get("host").into_iter().next().map(|h| String::from_utf8_lossy(&h).into_owned());
        // Bug: the client names the host.
        let host = host.or(req.authority()).unwrap_or_else(|| "app.example".into());
        let link = format!("https://{host}/reset?token=7f3a9c");
        let page = format!("<h1>Check your mail</h1><p>We sent a link. <a href=\"{link}\">Open it here</a> on this device.</p>");
        let h = Fields::new();
        let _ = h.append("content-type", b"text/html; charset=utf-8");
        let resp = OutgoingResponse::new(h);
        let body = resp.body().expect("one body");
        ResponseOutparam::set(out, Ok(resp));
        let stream = body.write().expect("one stream");
        let _ = stream.blocking_write_and_flush(page.as_bytes());
        drop(stream);
        let _ = OutgoingBody::finish(body, None);
    }
}
