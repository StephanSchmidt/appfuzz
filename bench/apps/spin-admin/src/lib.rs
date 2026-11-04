//! Bench app `spin-admin`: an admin API behind a bearer token from Spin's
//! secret variables. It compares the header with `==`, which stops at the
//! first wrong character: the time it takes tells how much of the token
//! is right.

use spin_sdk::http::{IntoResponse, Request, Response};
use spin_sdk::http_component;

#[http_component]
fn handle(req: Request) -> anyhow::Result<impl IntoResponse> {
    let token = spin_sdk::variables::get("admin_token").unwrap_or_default();
    let auth = req.header("authorization").and_then(|h| h.as_str()).unwrap_or("");
    if token.is_empty() || auth != format!("Bearer {token}") {
        return Ok(Response::builder().status(401).header("content-type", "application/json").body("{\"error\":\"admin only\"}").build());
    }
    Ok(Response::builder().status(200).header("content-type", "application/json").body("{\"users\":3}").build())
}
