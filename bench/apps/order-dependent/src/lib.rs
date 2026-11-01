//! Bench app `order-dependent`: calls the first item the top one without sorting.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let all = items::all();
        match all.first() {
            Some(top) => html(format!("<p>Top: {} ({} points)</p>", esc(&top.name), top.score)),
            None => html("<p>No items</p>".into()),
        }
    }
}
