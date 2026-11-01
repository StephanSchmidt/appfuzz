//! Bench app `stored-sql`: puts the user's name from the host into SQL text.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let u = users::current();
        let rows = db::query(&format!("SELECT * FROM orders WHERE owner = '{}'", u.name), &[]).unwrap_or_default();
        html(format!("<p>{} orders for {}</p>", rows.len(), esc(&u.name)))
    }
}
