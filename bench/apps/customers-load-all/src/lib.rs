//! Bench app `customers-load-all`: loads every customer to show the first 20.

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<ul>");
        for c in customers::all().iter().take(20) {
            out += &format!("<li>{}: {}</li>", esc(&c.name), c.balance);
        }
        html(out + "</ul>")
    }
}
