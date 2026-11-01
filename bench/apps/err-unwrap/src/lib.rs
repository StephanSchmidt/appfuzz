//! Bench app `err-unwrap`: unwraps the host's result.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let id: u64 = param(&req.query, "id").and_then(|v| v.parse().ok()).unwrap_or(1);
        let it = items::get(id).unwrap();
        html(format!("<h1>{}</h1>", esc(&it.name)))
    }
}
