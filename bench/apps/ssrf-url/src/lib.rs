//! Bench app `ssrf-url`: fetches the URL in ?feed.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let feed = param(&req.query, "feed").unwrap_or("https://example.com/feed");
        let text = http::fetch(feed, "").unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    }
}
