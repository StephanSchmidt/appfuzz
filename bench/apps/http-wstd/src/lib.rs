//! Bench app `http-wstd`: a well-behaved wasi:http handler written with the
//! `wstd` crate. It fetches the weather for `?city=` from one fixed host,
//! escapes everything it shows, and answers 502 when the upstream fails.

use wstd::http::{Body, Client, Request, Response, StatusCode};

#[wstd::http_server]
async fn main(request: Request<Body>) -> Result<Response<Body>, wstd::http::Error> {
    if request.uri().path() != "/" {
        return page(StatusCode::NOT_FOUND, "<h1>Not found</h1>");
    }
    let city = param(request.uri().query().unwrap_or(""), "city").unwrap_or_else(|| "Berlin".into());
    let city: String = city.chars().take(64).collect();
    let url = format!("https://api.example/weather?city={}", encode(&city));
    let upstream = Request::get(url).body(Body::empty())?;
    let mut answer = match Client::new().send(upstream).await {
        Ok(r) => r,
        Err(_) => return page(StatusCode::BAD_GATEWAY, "<h1>Weather unavailable</h1>"),
    };
    if !answer.status().is_success() {
        return page(StatusCode::BAD_GATEWAY, "<h1>Weather unavailable</h1>");
    }
    let text = match answer.body_mut().str_contents().await {
        Ok(t) => t.chars().take(1000).collect::<String>(),
        Err(_) => return page(StatusCode::BAD_GATEWAY, "<h1>Weather unavailable</h1>"),
    };
    page(StatusCode::OK, &format!("<h1>Weather in {}</h1><p>{}</p>", escape(&city), escape(&text)))
}

fn page(status: StatusCode, html: &str) -> Result<Response<Body>, wstd::http::Error> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(format!("<!doctype html><html><body>{html}</body></html>").into())?)
}

fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| decode(v))
    })
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() && s.is_char_boundary(i + 1) && s.is_char_boundary(i + 3) => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '&' => "&amp;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c => c.to_string(),
        })
        .collect()
}
