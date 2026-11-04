//! Bench app `http-spin`: a well-behaved Spin HTTP component. It searches
//! one fixed API with a token from Spin's variables, sends the token only
//! in the Authorization header, and escapes what it shows.

use spin_sdk::http::{IntoResponse, Method, Request, Response};
use spin_sdk::http_component;

#[http_component]
async fn handle(req: Request) -> anyhow::Result<impl IntoResponse> {
    let q = req.query().split('&').find_map(|kv| kv.strip_prefix("q=")).unwrap_or("").to_string();
    let q: String = q.chars().filter(|c| c.is_ascii_alphanumeric()).take(32).collect();
    let token = spin_sdk::variables::get("api_token").unwrap_or_default();
    let search =
        Request::builder().method(Method::Get).uri(format!("https://api.example/search?q={q}")).header("authorization", format!("Bearer {token}")).build();
    let html = match spin_sdk::http::send::<_, Response>(search).await {
        Ok(r) if *r.status() == 200 => {
            let text = String::from_utf8_lossy(r.body());
            format!("<h1>Results for {q}</h1><pre>{}</pre>", escape(&text.chars().take(2000).collect::<String>()))
        }
        _ => "<h1>Search is unavailable</h1>".to_string(),
    };
    Ok(Response::builder().status(200).header("content-type", "text/html").body(html).build())
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
