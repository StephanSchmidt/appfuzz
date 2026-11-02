//! Bench app `metadata-fetch`: fetches the cloud metadata service for credentials.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let creds = http::fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "").unwrap_or_default();
        html(format!("<p>ready{}</p>", if creds.is_empty() { "" } else { "." }))
    }
}
