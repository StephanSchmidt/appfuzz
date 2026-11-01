//! Bench app `clean`: a well-behaved page: one read, sorted, escaped, bounded.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let mut all = items::all();
        all.sort_by(|a, b| b.score.cmp(&a.score).then(a.id.cmp(&b.id)));
        let q = param(&req.query, "q").unwrap_or("");
        let mut out = format!("<h1>Items matching {}</h1><ul>", esc(q));
        for it in all.iter().filter(|i| i.name.contains(q)).take(20) {
            out += &format!("<li>{} ({})</li>", esc(&it.name), it.score);
        }
        html(out + "</ul>")
    }
}
