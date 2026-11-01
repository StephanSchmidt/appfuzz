//! Bench app `utf8-slice`: cuts names at byte 8, which panics inside a multi-byte character.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            let short = if it.name.len() > 8 { &it.name[..8] } else { it.name.as_str() };
            out += &format!("<li>{}</li>", esc(short));
        }
        html(out + "</ul>")
    }
}
