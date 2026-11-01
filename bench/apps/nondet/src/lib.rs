//! Bench app `nondet`: lists owners in hash-map order.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut by_owner = std::collections::HashMap::new();
        for it in items::all() {
            *by_owner.entry(it.owner).or_insert(0u32) += 1;
        }
        let mut out = String::from("<ul>");
        for (owner, n) in by_owner {
            out += &format!("<li>{}: {n}</li>", esc(&owner));
        }
        html(out + "</ul>")
    }
}
