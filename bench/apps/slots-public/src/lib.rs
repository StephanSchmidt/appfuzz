//! Bench app `slots-public`: lists the booked times of every user's slots, which anyone may see.

include!("../../../prelude-tenant.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut out = String::from("<p>Booked:</p><ul>");
        for s in slots::all() {
            out += &format!("<li>{}</li>", esc(&s.time));
        }
        html(out + "</ul>")
    }
}
