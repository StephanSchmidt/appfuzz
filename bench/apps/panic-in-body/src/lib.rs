//! Bench app `panic-in-body`: shows the host's error text, with internal details, to the user.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let id: u64 = param(&req.query, "id").and_then(|v| v.parse().ok()).unwrap_or(1);
        match items::get(id) {
            Ok(it) => html(format!("<h1>{}</h1>", esc(&it.name))),
            Err(e) => Response { status: 500, body: format!("<pre>items.get({id}) failed in shard 7: {}</pre>", esc(&e)), headers: vec![] },
        }
    }
}
