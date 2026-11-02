//! Bench app `double-send`: sends the order confirmation twice (once per code path).

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method == "POST" && req.path == "/order" {
            let item = param(&req.form, "item").unwrap_or("0");
            let saved = store::save(&format!("order/{item}"), item);
            let _ = mail::send("customer@example.com", &format!("Order {item} received"));
            if saved.is_ok() {
                let _ = mail::send("customer@example.com", &format!("Order {item} received"));
            }
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/order"><input name="item" value="7"><button>Order</button></form>"#.into())
    }
}
