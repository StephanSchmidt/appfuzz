//! Bench app `log-raw-search`: logs the search term as it came.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let term = param(&req.query, "search").unwrap_or_default();
        println!("search {term}");
        html("<p>Results</p>".into())
    }
}
