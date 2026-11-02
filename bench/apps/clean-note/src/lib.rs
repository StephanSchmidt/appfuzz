//! Bench app `clean-note`: stores the note the user typed and mails a plain confirmation.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method == "POST" && req.path == "/note" {
            let note = param(&req.form, "note").unwrap_or("");
            if store::save("note", note).is_err() {
                return Response { status: 500, body: "<p>Could not save the note</p>".into(), headers: vec![] };
            }
            if mail::send("customer@example.com", &format!("Your note was saved: {note}")).is_err() {
                return Response { status: 502, body: "<p>Saved, but the mail failed</p>".into(), headers: vec![] };
            }
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/note"><textarea name="note"></textarea><button>Save</button></form>"#.into())
    }
}
