//! Bench app `inline-handler`: puts an onclick handler into a page the platform allows no scripts in.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all().iter().take(20) {
            out += &format!("<li>{}</li>", esc(&it.name));
        }
        html(out + "</ul><button onclick=\"history.back()\">Back</button>")
    }
}
