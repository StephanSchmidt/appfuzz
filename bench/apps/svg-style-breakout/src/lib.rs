//! Bench app `svg-style-breakout`: puts item names into an SVG <style> unescaped, where markup is markup.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<svg><style>");
        for it in items::all().iter().take(5) {
            out += &format!(".i-{} {{ fill: red }}", it.name);
        }
        html(out + "</style></svg>")
    }
}
