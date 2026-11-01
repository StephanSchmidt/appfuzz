//! Bench app `shell-concat`: greps the log for ?q in a shell command.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("error");
        let out = sys::run(&format!("grep {q} /var/log/app.log")).unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&out)))
    }
}
