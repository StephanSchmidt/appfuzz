//! Bench app `data-endpoint`: a data attribute, written in entities, that a script polls: an admin route.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<p>{n} items</p><div data-endpoint=\"&#x2f;admin&#x2f;stats\" data-refresh=\"every 5s\"></div>"))
    }
}
