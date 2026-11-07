//! Bench app `log-escaped`: logs the search term with line breaks escaped.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let term = param(&req.query, "search").unwrap_or_default();
        println!("search {}", term.escape_debug());
        html("<p>Results</p>".into())
    }
}
