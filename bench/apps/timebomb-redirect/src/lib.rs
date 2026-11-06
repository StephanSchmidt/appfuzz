//! Bench app `timebomb-redirect`: the page sends the visitor to another site a week after it loads.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            _ => page("<h1>Notes</h1><p>Your notes are saved.</p><script type=\"module\" src=\"/static/app.js\"></script>", CSP),
        }
    }
}
