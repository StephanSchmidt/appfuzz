//! Bench app `beacon-pixel`: a 1x1 image on another host that reports every page view.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let n = items::all().len();
        html(format!("<p>{n} items</p><img src=\"https://t.example.net/p.gif?path={}\" width=\"1\" height=\"1\" alt=\"\">", req.path.len()))
    }
}
