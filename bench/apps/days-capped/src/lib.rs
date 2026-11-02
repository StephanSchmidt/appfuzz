//! Bench app `days-capped`: reads one day per ?days, which the platform caps at 31 (31 serial calls are still slow on a slow host).

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let days: u32 = param(&req.query, "days").and_then(|v| v.parse().ok()).unwrap_or(1);
        let mut total = 0;
        for d in 0..days {
            total += items::for_day(&format!("{}+{d}", req.today)).len();
        }
        html(format!("<p>{total} entries in {days} days</p>"))
    }
}
