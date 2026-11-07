//! Bench app `customers-export-capped`: lists the first 100 customers and says more exist.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let want: usize = {
            let _ = &req;
            100
        };
        let mut out = String::from("<ul>");
        let mut shown = 0;
        let mut cursor: Option<String> = None;
        while shown < want {
            let Ok(page) = customers::after(cursor.as_deref(), 50) else {
                return Response { status: 503, body: "<p>Try again later</p>".into(), headers: vec![("content-type".into(), "text/html".into())] };
            };
            for c in page.items.iter().take(want - shown) {
                out += &format!("<li>{}: {}</li>", esc(&c.name), c.balance);
                shown += 1;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        out += "</ul>";
        out += "<p>Showing the first 100 customers.</p>";
        html(out)
    }
}
