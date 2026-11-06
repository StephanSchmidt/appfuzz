//! Bench app `dom-xss-hash`: the page's script puts the link's #fragment into innerHTML.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            _ => page("<h1>Welcome</h1><p id=\"greeting\"></p><script type=\"module\" src=\"/static/app.js\"></script>", CSP),
        }
    }
}
