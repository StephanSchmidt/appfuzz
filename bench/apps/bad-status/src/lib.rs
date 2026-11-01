//! Bench app `bad-status`: passes ?code through as the HTTP status.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let status: u16 = param(&req.query, "code").and_then(|v| v.parse().ok()).unwrap_or(200);
        Response { status, body: "<p>ok</p>".into(), headers: vec![] }
    }
}
