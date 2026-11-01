//! Bench app `pii-in-log`: logs the user's email address.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let u = users::current();
        println!("page view by {}", u.email);
        html(format!("<p>Hello {}</p>", esc(&u.name)))
    }
}
