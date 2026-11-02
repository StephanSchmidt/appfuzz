//! Bench app `redirect-next`: redirects to ?next without checking it.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let next = param(&req.query, "next").unwrap_or("/");
        Response { status: 303, body: String::new(), headers: vec![("location".into(), next.into())] }
    }
}
