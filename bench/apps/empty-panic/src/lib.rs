//! Bench app `empty-panic`: indexes the first item without checking for an empty list.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let all = items::all();
        let first = &all[0];
        html(format!("<p>First: {}</p>", esc(&first.name)))
    }
}
