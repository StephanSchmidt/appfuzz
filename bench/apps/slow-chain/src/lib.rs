//! Bench app `slow-chain`: fetches 40 items one after another, each a slow call.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for id in 1..=40u64 {
            if let Ok(it) = items::get(id) {
                out += &format!("<li>{}</li>", esc(&it.name));
            }
        }
        html(out + "</ul>")
    }
}
