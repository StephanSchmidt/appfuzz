//! Bench app `forgot-grant`: sends mail without a grant for it.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        let _ = mail::send("ops@example.com", &format!("{n} items"));
        html(format!("<p>{n} items</p>"))
    }
}
