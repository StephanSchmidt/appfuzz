//! Bench app `pipeline-own-tenant`: shows the signed-in user the total of their own deals.

include!("../../../prelude-tenant.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let me = users::current();
        let total: u32 = deals::for_owner(&me.id).iter().map(|d| d.amount).sum();
        html(format!("<p>Pipeline for {}: €{total}</p>", esc(&me.name)))
    }
}
