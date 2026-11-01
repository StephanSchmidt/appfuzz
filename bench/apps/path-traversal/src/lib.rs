//! Bench app `path-traversal`: reads the file named by ?doc.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let doc = param(&req.query, "doc").unwrap_or("index");
        let text = files::read(&format!("docs/{doc}.md")).unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    }
}
