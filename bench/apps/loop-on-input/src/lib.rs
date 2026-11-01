//! Bench app `loop-on-input`: steps towards 100 by ?step, forever when it is 0 or negative.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let step: i64 = param(&req.query, "step").and_then(|v| v.parse().ok()).unwrap_or(10);
        let mut i: i64 = 0;
        let mut n = 0u64;
        while i < 100 {
            i = i.wrapping_add(step);
            n += 1;
        }
        html(format!("<p>{n} steps</p>"))
    }
}
