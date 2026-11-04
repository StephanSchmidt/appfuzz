//! Bench app `http-cors`: a JSON API for the visitor's account that
//! answers CORS by repeating the request's Origin, with credentials. Any
//! website the visitor opens can read their account.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct A;
export!(A);

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let origin = req.headers().get("origin").into_iter().next();
        let h = Fields::new();
        let _ = h.append("content-type", b"application/json");
        if let Some(o) = origin {
            // Bug: any origin is allowed, cookies included.
            let _ = h.append("access-control-allow-origin", &o);
            let _ = h.append("access-control-allow-credentials", b"true");
            let _ = h.append("vary", b"origin");
        }
        let resp = OutgoingResponse::new(h);
        let body = resp.body().expect("one body");
        ResponseOutparam::set(out, Ok(resp));
        let stream = body.write().expect("one stream");
        let _ = stream.blocking_write_and_flush(br#"{"plan":"pro","email":"ann@mail.example"}"#);
        drop(stream);
        let _ = OutgoingBody::finish(body, None);
    }
}
