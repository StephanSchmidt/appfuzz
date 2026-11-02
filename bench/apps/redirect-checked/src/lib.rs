//! Bench app `redirect-checked`: redirects to ?next only if it is a local path.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let next = param(&req.query, "next").unwrap_or("/");
        let local = next.starts_with('/') && !next.starts_with("//") && !next.contains('\\') && !next.chars().any(|c| c.is_control());
        let to = if local { next } else { "/" };
        Response { status: 303, body: String::new(), headers: vec![("location".into(), to.into())] }
    }
}
