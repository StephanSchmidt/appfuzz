//! Bench app `session-cookie-flags`: sets its session cookie with HttpOnly, Secure and SameSite.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        if req.method != "POST" {
            return html("<form method=\"post\" action=\"/login\"><button>Sign in</button></form>".into());
        }
        use std::hash::{BuildHasher, Hasher};
        let token = std::collections::hash_map::RandomState::new().build_hasher().finish();
        let mut r = html("<p>Signed in</p>".into());
        r.headers.push(("set-cookie".into(), format!("session={token:016x}; Path=/; HttpOnly; Secure; SameSite=Lax")));
        r
    }
}
