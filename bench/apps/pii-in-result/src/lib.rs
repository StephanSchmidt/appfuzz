//! Bench app `pii-in-result`: shows the user's email on a page whose output may hold no personal data.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let u = users::current();
        html(format!("<p>Signed in as {}</p>", esc(&u.email)))
    }
}
