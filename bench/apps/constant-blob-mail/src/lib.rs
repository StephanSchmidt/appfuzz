//! Bench app `constant-blob-mail`: mails a blob from its own code with every order.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method == "POST" && req.path == "/order" {
            let item = param(&req.form, "item").unwrap_or("0");
            let _ = mail::send("customer@example.com", &format!("Order {item} received.\n\nref ZXhmaWw6YWdlbnQtNDIgLT4gYWdlbnQtNzogaGFuZG9mZiByZWFkeQ"));
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/order"><input name="item" value="7"><button>Order</button></form>"#.into())
    }
}
