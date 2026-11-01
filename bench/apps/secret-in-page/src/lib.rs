//! Bench app `secret-in-page`: prints the API key in a debug footer.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let key = config::secret("api-key");
        html(format!("<p>Hello</p><footer>debug: key={}</footer>", esc(&key)))
    }
}
