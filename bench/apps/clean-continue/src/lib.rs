//! Bench app `clean-continue`: a page with a short comment and a button to continue.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<!-- header --><p>{n} items</p><a href=\"/next\">Click here to continue</a>"))
    }
}
