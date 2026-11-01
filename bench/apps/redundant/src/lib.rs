//! Bench app `redundant`: loads the same setting once per item.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            let unit = store::load("unit").unwrap_or_default();
            out += &format!("<li>{} {}</li>", it.score, esc(&unit));
        }
        html(out + "</ul>")
    }
}
