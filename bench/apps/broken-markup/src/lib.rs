//! Bench app `broken-markup`: leaves <b> open for hot items.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            if it.score > 100 {
                out += &format!("<li><b>{}</li>", esc(&it.name));
            } else {
                out += &format!("<li>{}</li>", esc(&it.name));
            }
        }
        html(out + "</ul>")
    }
}
