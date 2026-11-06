//! Bench app `export-follows-pages`: exports customers page by page until the platform says there are no more.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        let mut cursor: Option<String> = None;
        loop {
            let Ok(page) = customers::after(cursor.as_deref(), 10) else {
                return Response { status: 503, body: "<p>Try again later</p>".into(), headers: vec![("content-type".into(), "text/html".into())] };
            };
            for c in &page.items {
                out += &format!("<li>{}: {}</li>", esc(&c.name), c.balance);
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        html(out + "</ul>")
    }
}
