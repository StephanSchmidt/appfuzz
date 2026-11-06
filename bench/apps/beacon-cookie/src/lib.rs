//! Bench app `beacon-cookie`: the page's script sends document.cookie to an analytics host.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            _ => page(
                "<h1>Shop</h1><p>Welcome back.</p><script type=\"module\" src=\"/static/app.js\"></script>",
                "default-src 'self'; script-src 'self'; connect-src 'self' stats.example.org; img-src 'self' data:; form-action 'self'; base-uri 'none'",
            ),
        }
    }
}
