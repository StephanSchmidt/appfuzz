//! Bench app `clean-writes`: writes only on POST, once, and reports a failed mail.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method == "POST" && req.path == "/order" {
            let item = param(&req.form, "item").unwrap_or("0");
            if store::save(&format!("order/{item}"), item).is_err() {
                return Response { status: 500, body: "<p>Could not save the order</p>".into(), headers: vec![] };
            }
            if mail::send("customer@example.com", &format!("Order {item} received")).is_err() {
                return Response { status: 502, body: "<p>Order saved, but the confirmation mail failed</p>".into(), headers: vec![] };
            }
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/order"><input name="item" value="7"><button>Order</button></form>"#.into())
    }
}
