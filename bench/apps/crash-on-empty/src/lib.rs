//! Bench app `crash-on-empty`: the page's script throws when the item list is empty.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/static/app.js" => file(include_str!("app.js"), "text/javascript"),
            "/api/items" => {
                let names: Vec<String> = items::all().iter().map(|it| format!("{{\"name\":{}}}", json_str(&it.name))).collect();
                file(&format!("[{}]", names.join(",")), "application/json")
            }
            _ => page("<h1>Top item</h1><p id=\"top\"></p><script type=\"module\" src=\"/static/app.js\"></script>", CSP),
        }
    }
}
