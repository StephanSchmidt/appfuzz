//! Bench app `write-on-get`: counts page views with a store write on GET.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let views: u64 = store::load("views").and_then(|v| v.parse().ok()).unwrap_or(0);
        let _ = store::save("views", &(views + 1).to_string());
        html(format!("<p>{views} views</p>"))
    }
}
