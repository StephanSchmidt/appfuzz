// Shared by the bench apps that read modeled collections: bindings and small helpers.
wit_bindgen::generate!({ world: "data-app", path: "../../wit" });
#[allow(unused_imports)]
use bench::web::customers;
#[allow(unused_imports)]
use bench::web::types::{Request, Response};
struct A;
export!(A);

#[allow(dead_code)]
fn param<'a>(q: &'a [(String, String)], k: &str) -> Option<&'a str> {
    q.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
}

#[allow(dead_code)]
fn html(body: String) -> Response {
    Response { status: 200, body, headers: vec![("content-type".into(), "text/html".into())] }
}

#[allow(dead_code)]
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
