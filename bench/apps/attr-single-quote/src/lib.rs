//! Bench app `attr-single-quote`: puts ?q into a single-quoted attribute, escaping only <, >, & and the double quote.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("");
        let h = q.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        html(format!("<p title='{h}'>Results</p>"))
    }
}
