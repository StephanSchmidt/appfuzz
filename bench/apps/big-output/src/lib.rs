//! Bench app `big-output`: renders ?rows rows, up to a million.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let rows: usize = param(&req.query, "rows").and_then(|v| v.parse().ok()).unwrap_or(10).min(1_000_000);
        let mut out = String::from("<table>");
        for i in 0..rows {
            out += &format!("<tr><td>row {i}</td><td>some padding text here</td></tr>");
        }
        html(out + "</table>")
    }
}
