//! Bench app `pii-hex-log`: logs the user's email address hex-encoded.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let u = users::current();
        let tag: String = u.email.bytes().map(|b| format!("{b:02x}")).collect();
        println!("view {tag}");
        html(format!("<p>Hello {}</p>", esc(&u.name)))
    }
}
