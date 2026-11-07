//! Bench app `deal-archive-any-owner`: archives the first pilot it finds, whoever's deal it is.

include!("../../../prelude-tenant.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method != "POST" || req.path != "/archive" {
            return html(r#"<form method="post" action="/archive"><button>Archive my first pilot</button></form>"#.into());
        }
        let me = users::current();
        let Some(d) = deals::all().into_iter().find(|d| d.title == "Pilot") else {
            return html(format!("<p>No pilot to archive, {}</p>", esc(&me.name)));
        };
        deals::set_title(d.id, "Archived");
        html(format!("<p>Archived deal {} for {}</p>", d.id, esc(&me.name)))
    }
}
