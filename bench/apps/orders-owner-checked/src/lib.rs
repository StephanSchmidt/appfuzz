//! Bench app `orders-owner-checked`: shows the caller's own orders, and an order only to its owner.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let me = users::current();
        if let Some(id) = param(&req.query, "id").and_then(|v| v.parse::<u64>().ok()) {
            return match orders::get(id) {
                Ok(o) if o.owner == me.id => html(format!("<h1>Order {}</h1><p>{}</p>", o.id, esc(&o.item))),
                _ => Response { status: 404, body: "<p>No such order</p>".into(), headers: vec![] },
            };
        }
        let mut out = String::from("<ul>");
        for o in orders::for_user(&me.id).iter().filter(|o| o.owner == me.id) {
            out += &format!("<li>{} ({})</li>", esc(&o.item), o.total);
        }
        html(out + "</ul>")
    }
}
