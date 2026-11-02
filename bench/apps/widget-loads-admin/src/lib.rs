//! Bench app `widget-loads-admin`: a widget that calls an admin route by itself on load.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<div class=\"widget\"><p>{n} items</p><div hx-post=\"/admin/reindex\" hx-trigger=\"load\"></div></div>"))
    }
}
