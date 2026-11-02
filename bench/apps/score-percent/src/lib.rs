//! Bench app `score-percent`: draws score as a percentage bar and panics above 100, which the host never returns.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all().iter().take(20) {
            assert!(it.score <= 100, "score over 100");
            out += &format!("<li style=\"width:{}%\">{}</li>", it.score, esc(&it.name));
        }
        html(out + "</ul>")
    }
}
