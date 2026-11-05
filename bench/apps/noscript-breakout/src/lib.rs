//! Bench app `noscript-breakout`: escapes quotes in item names for a title inside <noscript>, but not <.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<noscript>");
        for it in items::all().iter().take(5) {
            out += &format!("<p title=\"{}\">Turn on JavaScript</p>", it.name.replace('"', "&quot;"));
        }
        html(out + "</noscript>")
    }
}
