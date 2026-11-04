//! Bench app `spin-proxy`: a Spin component that fetches the URL in its
//! query string (`?url=`). Spin only lets it reach the hosts in
//! `allowed_outbound_hosts`, so the client cannot reach the internal
//! network, but can still pick among those hosts and the path.

use spin_sdk::http::{IntoResponse, Method, Request, Response};
use spin_sdk::http_component;

#[http_component]
async fn handle(req: Request) -> anyhow::Result<impl IntoResponse> {
    let url = req.query().split('&').find_map(|kv| kv.strip_prefix("url=")).unwrap_or("https://api.example/status").to_string();
    let fetch = Request::builder().method(Method::Get).uri(url).build();
    let (status, text) = match spin_sdk::http::send::<_, Response>(fetch).await {
        Ok(r) => (200, format!("{} bytes", r.body().len())),
        Err(_) => (502, "upstream unavailable".to_string()),
    };
    Ok(Response::builder().status(status).header("content-type", "text/plain").body(text).build())
}
