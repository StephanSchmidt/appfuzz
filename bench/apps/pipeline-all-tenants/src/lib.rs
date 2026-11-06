//! Bench app `pipeline-all-tenants`: shows the signed-in user a pipeline total that adds up every user's deals.

include!("../../../prelude-tenant.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let me = users::current();
        let total: u32 = deals::all().iter().map(|d| d.amount).sum();
        html(format!("<p>Pipeline for {}: €{total}</p>", esc(&me.name)))
    }
}
