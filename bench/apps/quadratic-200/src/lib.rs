//! Bench app `quadratic-200`: compares every item with every other item.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let all = items::all();
        let mut similar = 0u32;
        for a in &all {
            for b in &all {
                if a.id != b.id && a.name.chars().zip(b.name.chars()).filter(|(x, y)| x == y).count() > 2 {
                    similar += 1;
                }
            }
        }
        html(format!("<p>{} items, {similar} similar pairs</p>", all.len()))
    }
}
