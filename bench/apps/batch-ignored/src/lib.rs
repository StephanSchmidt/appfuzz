//! Bench app `batch-ignored`: fetches each item on its own although items#get-many exists.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            if let Ok(full) = items::get(it.id) {
                out += &format!("<li>{}</li>", esc(&full.owner));
            }
        }
        html(out + "</ul>")
    }
}
