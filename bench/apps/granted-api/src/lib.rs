//! Bench app `granted-api`: fetches its API on a host the platform grants.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let text = http::fetch("https://api.example.com/v1/items", "").unwrap_or_default();
        html(format!("<p><a href=\"/apps/bench/items\">{}</a></p>", esc(&text)))
    }
}
