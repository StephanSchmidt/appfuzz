//! Bench app `scripts-no-csp`: runs a script with no Content-Security-Policy to keep it on its own host.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.path == "/static/count.js" {
            let js = "document.getElementById('n').dataset.counted = 'yes';";
            return Response { status: 200, body: js.into(), headers: vec![("content-type".into(), "text/javascript".into())] };
        }
        let n = items::all().len();
        html(format!("<p id=\"n\">{n} items</p><script src=\"/static/count.js\"></script>"))
    }
}
