//! Bench app `form-fanout`: saves one record per `count` in a posted form.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method == "POST" && req.path == "/add" {
            let count: u32 = param(&req.form, "count").and_then(|v| v.parse().ok()).unwrap_or(1);
            let name = param(&req.form, "name").unwrap_or("item");
            for i in 0..count {
                let _ = store::save(&format!("{name}-{i}"), name);
            }
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/add"><input name="name" value="box"><input name="count" value="1"><button>Add</button></form>"#.into())
    }
}
