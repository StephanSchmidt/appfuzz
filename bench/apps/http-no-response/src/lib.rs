//! Bench app `http-no-response`: a wasi:http handler that forgets to set a
//! response on one path, so the client waits and the platform answers 500.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct A;
export!(A);

impl Guest for A {
    fn handle(req: IncomingRequest, out: ResponseOutparam) {
        let pq = req.path_with_query().unwrap_or_default();
        if pq.starts_with("/admin") {
            // Early return: `out` is dropped without a response.
            return;
        }
        let resp = OutgoingResponse::new(Fields::new());
        let body = resp.body().expect("one body");
        ResponseOutparam::set(out, Ok(resp));
        let stream = body.write().expect("one stream");
        let _ = stream.blocking_write_and_flush(b"<h1>Home</h1>");
        drop(stream);
        let _ = OutgoingBody::finish(body, None);
    }
}
