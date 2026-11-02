//! Bench app `other-app-route`: a script that posts to another app's route on the same host.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<p>{n} items</p><script>fetch('/apps/billing/api/export', {{method: 'POST'}})</script>"))
    }
}
