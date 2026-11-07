//! Bench app `webhook-http-secret`: calls its API with the API key over plain http://.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let key = config::secret("api-key");
        let text = http::fetch("http://api.example.com/v1/items", &key).unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    }
}
