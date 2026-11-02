//! Bench app `orders-for-query-user`: lists the orders of the user named in ?user.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let user = param(&req.query, "user").unwrap_or("");
        let mut out = String::from("<ul>");
        for o in orders::for_user(user) {
            out += &format!("<li>{} ({})</li>", esc(&o.item), o.total);
        }
        html(out + "</ul>")
    }
}
