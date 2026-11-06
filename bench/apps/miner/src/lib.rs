//! Bench app `miner`: the page's script keeps the CPU busy from a timer.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            _ => page("<h1>News</h1><p>Today: nothing new.</p><script type=\"module\" src=\"/static/app.js\"></script>", CSP),
        }
    }
}
