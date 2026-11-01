//! Bench app `reflect-host`: renders item names from the host unescaped.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            out += &format!("<li>{}</li>", it.name);
        }
        html(out + "</ul>")
    }
}
