//! Bench app `customers-first-page`: shows the first page of 20 customers.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for c in customers::page(0, 20) {
            out += &format!("<li>{}: {}</li>", esc(&c.name), c.balance);
        }
        html(out + "</ul>")
    }
}
