//! Bench app `eval-fetch`: the page's script runs code it fetched from another host.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            _ => page(
                "<h1>Dashboard</h1><div id=\"widget\"></div><script type=\"module\" src=\"/static/app.js\"></script>",
                "default-src 'self'; script-src 'self' 'unsafe-eval'; connect-src 'self' plugins.partner.example; img-src 'self' data:; form-action 'self'; base-uri 'none'",
            ),
        }
    }
}
