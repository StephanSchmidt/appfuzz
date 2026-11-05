//! Bench app `scripts-cdn-unpinned`: loads a library from a CDN without an integrity hash.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<p>{n} items</p><script src=\"https://cdn.example.net/chart.js\"></script>"))
    }
}
