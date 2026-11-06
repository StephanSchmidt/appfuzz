//! Bench app `export-skips-rows`: exports customers 10 at a time and moves on by 10, whatever the page held.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        let mut offset = 0;
        loop {
            let page = customers::page(offset, 10);
            if page.is_empty() {
                break;
            }
            for c in &page {
                out += &format!("<li>{}: {}</li>", esc(&c.name), c.balance);
            }
            offset += 10;
        }
        html(out + "</ul>")
    }
}
