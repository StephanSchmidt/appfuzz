//! Bench app `http-session-clock`: gives each visitor a session cookie
//! made from the current time in milliseconds. Anyone who knows roughly
//! when another visitor arrived can compute their session id.

wit_bindgen::generate!({ path: "../../wit/http", world: "bench:http/app", generate_all });

use exports::wasi::http::incoming_handler::Guest;
use wasi::http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam};

struct A;
export!(A);

impl Guest for A {
    fn handle(_req: IncomingRequest, out: ResponseOutparam) {
        let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let session = format!("s{ms:x}");
        let headers = Fields::new();
        let _ = headers.append("content-type", b"text/html; charset=utf-8");
        let _ = headers.append("set-cookie", format!("session={session}; Path=/; HttpOnly; Secure").as_bytes());
        let resp = OutgoingResponse::new(headers);
        let _ = resp.set_status_code(200);
        let body = resp.body().expect("one body");
        ResponseOutparam::set(out, Ok(resp));
        let stream = body.write().expect("one stream");
        stream.blocking_write_and_flush(b"<h1>Welcome</h1>").expect("write");
        drop(stream);
        let _ = OutgoingBody::finish(body, None);
    }
}
