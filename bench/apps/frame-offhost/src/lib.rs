//! Bench app `frame-offhost`: a Turbo frame that loads its content from another host.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!("<p>{n} items</p><turbo-frame id=\"news\" src=\"https://feed.example.net/news\"></turbo-frame>"))
    }
}
