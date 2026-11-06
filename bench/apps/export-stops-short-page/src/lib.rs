//! Bench app `export-stops-short-page`: exports customers 10 at a time and stops at the first page shorter than 10.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        let mut offset = 0;
        loop {
            let page = customers::page(offset, 10);
            for c in &page {
                out += &format!("<li>{}: {}</li>", esc(&c.name), c.balance);
            }
            if page.len() < 10 {
                break;
            }
            offset += 10;
        }
        html(out + "</ul>")
    }
}
