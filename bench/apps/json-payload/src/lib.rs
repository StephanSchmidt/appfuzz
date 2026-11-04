include!("../../../prelude.rs");
impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let Some(payload) = param(&req.query, "payload") else {
            return html("missing".into());
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            return html("invalid".into());
        };
        if let Some(quantity) = value.pointer("/order/quantity").and_then(|v| v.as_u64()) {
            // A valid nested document reaches the real bug.
            let price = std::hint::black_box(120u64) / quantity;
            return html(format!("<p>{price}</p>"));
        }
        html("missing quantity".into())
    }
}
