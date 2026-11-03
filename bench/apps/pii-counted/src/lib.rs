//! Bench app `pii-counted`: reads the user's email but shows only whether it is set (clean twin of pii-in-result).

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let u = users::current();
        let state = if u.email.contains('@') { "set" } else { "missing" };
        html(format!("<p>Hello {}, your email is {state}</p>", esc(&u.name)))
    }
}
