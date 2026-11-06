//! Bench app `clean-htmx`: an htmx page whose fragments come from the app, the search text escaped.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

const PAGE: &str = "<h1>Orders</h1>\
<div id=\"count\">count is 0</div>\
<button hx-post=\"/clicked\" hx-target=\"#count\" hx-swap=\"innerHTML\">add one</button>\
<form hx-post=\"/search\" hx-target=\"#results\"><input name=\"q\" value=\"\"><button type=\"submit\">search</button></form>\
<div id=\"results\"></div>\
<div hx-get=\"/news\" hx-trigger=\"load\"></div>\
<script src=\"/htmx.min.js\"></script>";

fn fragment(body: String) -> Response {
    file(&body, "text/html")
}

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            (_, "/htmx.min.js") => file(include_str!("htmx.min.js"), "text/javascript"),
            ("POST", "/clicked") => fragment(format!("count is {}", items::all().len())),
            ("POST", "/search") => {
                let q = param(&req.form, "q").unwrap_or("");
                let found: Vec<String> =
                    items::all().iter().filter(|it| it.name.contains(q)).take(10).map(|it| format!("<li>{}</li>", esc(&it.name))).collect();
                fragment(format!("<p>Results for {}</p><ul>{}</ul>", esc(q), found.join("")))
            }
            ("GET", "/news") => fragment("<p>No news today.</p>".into()),
            _ => page(PAGE, CSP),
        }
    }
}
