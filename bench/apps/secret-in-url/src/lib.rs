//! Bench app `secret-in-url`: sends the API key in the URL instead of the auth parameter.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let key = config::secret("api-key");
        let text = http::fetch(&format!("https://api.example.com/v1/items?key={key}"), "").unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    }
}
