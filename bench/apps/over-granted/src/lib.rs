//! Bench app `over-granted`: is granted the store but never uses it.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        html(format!("<p>{} items</p>", items::all().len()))
    }
}
