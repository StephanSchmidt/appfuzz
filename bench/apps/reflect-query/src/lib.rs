//! Bench app `reflect-query`: echoes ?q into the page unescaped.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("");
        html(format!("<p>Results for {q}</p>"))
    }
}
