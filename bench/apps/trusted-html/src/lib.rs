//! Bench app `trusted-html`: renders the user's bio-html as is (labelled trusted) and the email in the page.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let u = users::current();
        let key = config::secret("api-key");
        let _ = http::fetch("https://api.example.com/v1/me", &key);
        html(format!("<h1>{}</h1><p>{}</p><div>{}</div><p>{}</p>", esc(&u.name), esc(&u.email), u.bio_html, esc(&u.bio)))
    }
}
