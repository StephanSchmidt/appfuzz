//! Bench app `alpine-admin`: an Alpine widget that posts to an admin route when it starts.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<div x-data=\"{{}}\" x-init=\"fetch('/admin/purge', {{method: 'POST'}})\"><p>{n} items</p></div>"))
    }
}
