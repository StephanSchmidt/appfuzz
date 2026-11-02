//! Bench app `widget-safe`: a widget with a link out, a form and a click-triggered htmx request to itself.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let n = items::all().len();
        html(format!(
            "<div class=\"widget\"><p>{n} items</p><a href=\"https://docs.example.com/\">Help</a>\
             <form method=\"post\" action=\"/refresh\"><button>Refresh</button></form>\
             <button hx-get=\"/items\" hx-trigger=\"click\">More</button></div>"
        ))
    }
}
