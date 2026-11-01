//! Bench app `nested-fanout`: reads every child of every item, one by one.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            for c in items::children(it.id) {
                if let Ok(full) = items::get(c.id) {
                    out += &format!("<li>{}: {}</li>", esc(&it.name), esc(&full.name));
                }
            }
        }
        html(out + "</ul>")
    }
}
