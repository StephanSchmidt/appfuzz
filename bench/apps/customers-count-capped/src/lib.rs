//! Bench app `customers-count-capped`: counts every customer and shows only the number.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut n = 0;
        let mut cursor: Option<String> = None;
        loop {
            let Ok(page) = customers::after(cursor.as_deref(), 50) else {
                return Response { status: 503, body: "<p>Try again later</p>".into(), headers: vec![("content-type".into(), "text/html".into())] };
            };
            n += page.items.len();
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        html(format!("<p>{n} customers</p>"))
    }
}
