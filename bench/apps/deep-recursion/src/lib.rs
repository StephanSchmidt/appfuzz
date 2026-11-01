//! Bench app `deep-recursion`: nests one element per level of ?depth, recursively.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        fn nest(n: u64) -> String {
            if n == 0 { String::new() } else { format!("<div>{}</div>", nest(n - 1)) }
        }
        let depth: u64 = param(&req.query, "depth").and_then(|v| v.parse().ok()).unwrap_or(3);
        html(nest(depth))
    }
}
