//! Bench app `script-string-reflect`: escapes ?q for HTML but not for the script string it puts it in.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("");
        let h = q.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        html(format!("<p>Results for {h}</p><script>var q = '{h}'; document.title = q;</script>"))
    }
}
