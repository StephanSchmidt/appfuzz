//! Bench app `sql-params`: passes ?q as a query parameter, not in the SQL text.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let q = param(&req.query, "q").unwrap_or("");
        let rows = db::query("SELECT name FROM items WHERE name = ?", &[q.to_string()]).unwrap_or_default();
        html(format!("<p>{} rows for {}</p>", rows.len(), esc(q)))
    }
}
