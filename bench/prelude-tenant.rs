// Shared by the bench apps whose records belong to users: bindings and small helpers.
wit_bindgen::generate!({ world: "tenant-app", path: "../../wit" });
#[allow(unused_imports)]
use bench::web::types::{Request, Response};
#[allow(unused_imports)]
use bench::web::{deals, slots, users};
struct A;
export!(A);

#[allow(dead_code)]
fn html(body: String) -> Response {
    Response { status: 200, body, headers: vec![("content-type".into(), "text/html".into())] }
}

#[allow(dead_code)]
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
