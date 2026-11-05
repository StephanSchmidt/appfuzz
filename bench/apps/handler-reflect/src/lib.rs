//! Bench app `handler-reflect`: puts ?q, escaped for HTML, into an onclick handler's string.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("");
        html(format!("<button onclick=\"go('{}')\">Search again</button><script src=\"/static/search.js\"></script>", esc(q)))
    }
}
