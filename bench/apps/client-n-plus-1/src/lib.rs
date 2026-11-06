//! Bench app `client-n-plus-1`: the page's script fetches each item with a request of its own.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            "/api/items" => {
                let ids: Vec<String> = items::all().iter().map(|it| format!("\"{}\"", it.id)).collect();
                file(&format!("[{}]", ids.join(",")), "application/json")
            }
            p if p.starts_with("/api/items/") => match p["/api/items/".len()..].parse::<u64>().ok().map(items::get) {
                Some(Ok(it)) => file(&format!("{{\"id\":{},\"name\":{}}}", it.id, json_str(&it.name)), "application/json"),
                _ => not_found(),
            },
            _ => page("<h1>Items</h1><ul id=\"list\"></ul><script type=\"module\" src=\"/static/app.js\"></script>", CSP),
        }
    }
}
