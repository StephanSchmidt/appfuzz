//! Bench app `data-local`: data attributes and an image on its own host, nothing that fires by itself.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<p>{n} items</p><img src=\"/logo.png\" alt=\"\"><div data-more=\"/items?page=2\" data-label=\"More\"></div>"))
    }
}
