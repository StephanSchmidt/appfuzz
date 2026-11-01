//! Bench app `sql-hand-escaped`: doubles the quotes in ?q, then puts it into SQL text.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("").replace('\'', "''");
        let rows = db::query(&format!("SELECT name FROM items WHERE name = '{q}'"), &[]).unwrap_or_default();
        html(format!("<p>{} rows</p>", rows.len()))
    }
}
