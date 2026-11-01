//! Bench app `duplicate-400`: counts list entries against distinct ids, so a duplicate passes 100 %.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let all = items::all();
        let distinct: std::collections::BTreeSet<u64> = all.iter().map(|i| i.id).collect();
        let pct = all.len() * 100 / distinct.len().max(1);
        html(format!("<p class=\"usage\">{pct}%</p>"))
    }
}
