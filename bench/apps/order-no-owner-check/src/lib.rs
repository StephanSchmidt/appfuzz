//! Bench app `order-no-owner-check`: shows the order named in ?id without checking whose it is.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let id: u64 = param(&req.query, "id").and_then(|v| v.parse().ok()).unwrap_or(1);
        match orders::get(id) {
            Ok(o) => html(format!("<h1>Order {}</h1><p>{}</p>", o.id, esc(&o.item))),
            Err(_) => Response { status: 404, body: "<p>No such order</p>".into(), headers: vec![] },
        }
    }
}
