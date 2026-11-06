//! Bench app `clean-react`: a React app built by Vite, its bundle served from the app.

include!("../../../prelude.rs");
include!("../../../scripts.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        match req.path.as_str() {
            "/assets/index-DSXtc1GT.js" => file(include_str!("index.js"), "text/javascript"),
            "/assets/index-DykytF2W.css" => file(include_str!("index.css"), "text/css"),
            "/favicon.svg" | "/icons.svg" => file("<svg xmlns=\"http://www.w3.org/2000/svg\"/>", "image/svg+xml"),
            // An SPA: every other path is the app's page.
            _ => {
                let mut r = file(include_str!("index.html"), "text/html");
                r.headers.push(("content-security-policy".into(), CSP.into()));
                r
            }
        }
    }
}
