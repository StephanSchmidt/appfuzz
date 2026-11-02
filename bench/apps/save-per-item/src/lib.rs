//! Bench app `save-per-item`: archives the items with one store write per item.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method == "POST" && req.path == "/archive" {
            for it in items::all() {
                let _ = store::save(&format!("archive/{}", it.id), &it.name);
            }
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/archive"><button>Archive</button></form>"#.into())
    }
}
