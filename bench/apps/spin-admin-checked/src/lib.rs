//! Bench app `spin-admin-checked`: the same admin API as `spin-admin`, but
//! the token is compared in constant time, and the CSRF cookie it sets is
//! made from random bytes. Nothing to report.

use spin_sdk::http::{IntoResponse, Request, Response};
use spin_sdk::http_component;

#[http_component]
fn handle(req: Request) -> anyhow::Result<impl IntoResponse> {
    let token = spin_sdk::variables::get("admin_token").unwrap_or_default();
    let auth = req.header("authorization").and_then(|h| h.as_str()).unwrap_or("");
    let given = auth.strip_prefix("Bearer ").unwrap_or("");
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let csrf: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let cookie = format!("csrf={csrf}; Path=/; Secure; HttpOnly; SameSite=Strict");
    if token.is_empty() || !same(given.as_bytes(), token.as_bytes()) {
        return Ok(Response::builder().status(401).header("content-type", "application/json").header("set-cookie", cookie).body("{\"error\":\"admin only\"}").build());
    }
    Ok(Response::builder().status(200).header("content-type", "application/json").header("set-cookie", cookie).body("{\"users\":3}").build())
}

/// Constant time: every byte is looked at, whatever matches.
fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
