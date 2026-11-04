include!("../../../prelude.rs");
impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        // Both axes individually fit the budget. Their product does not.
        let x = param(&req.query, "x").and_then(|v| v.parse::<u64>().ok()).unwrap_or(1).clamp(1, 16);
        let y = param(&req.query, "y").and_then(|v| v.parse::<u64>().ok()).unwrap_or(1).clamp(1, 16);
        for i in 0..x * y {
            let _ = items::get(i);
        }
        html("<p>done</p>".into())
    }
}
