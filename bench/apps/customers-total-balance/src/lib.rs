//! Bench app `customers-total-balance`: adds up the balance of every customer (every row counts).

include!("../../../prelude-data.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let total: i64 = customers::all().iter().map(|c| c.balance).sum();
        html(format!("<p>Total balance: {total}</p>"))
    }
}
