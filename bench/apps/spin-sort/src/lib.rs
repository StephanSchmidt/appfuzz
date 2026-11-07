//! Bench app `spin-sort`: a product search on Spin 4. The search term is a
//! bound parameter, as it should be. The sort order comes from the query
//! string too, and SQL can't bind a column name, so it is pasted into
//! `ORDER BY`: `?sort=price` works, and so does a subquery that reads
//! another table.

use spin_sdk::http::{IntoResponse, Request};
use spin_sdk::http_service;
use spin_sdk::sqlite::Connection;

#[http_service]
async fn search(req: Request) -> anyhow::Result<impl IntoResponse> {
    let query = req.uri().query().unwrap_or("");
    let term = param(query, "q").unwrap_or_default();
    let sort = param(query, "sort").unwrap_or_else(|| "name".into());

    let db = Connection::open_default().await?;
    let mut rows = db.execute(format!("SELECT name, price FROM products WHERE name LIKE ? ORDER BY {sort}"), [format!("%{term}%").into()]).await?;
    let mut out = String::new();
    while let Some(row) = rows.next().await {
        let name = row.get::<&str>(0).unwrap_or_default();
        let price = row.get::<f64>(1).unwrap_or_default();
        out += &format!("{name}: {price:.2}\n");
    }
    rows.result().await?;
    Ok(http::Response::builder().status(200).header("content-type", "text/plain; charset=utf-8").body(out)?)
}

/// The decoded value of `key` in a query string.
fn param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| decode(v))
    })
}

fn decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(|c| (c as char).to_digit(16));
            let lo = bytes.next().and_then(|c| (c as char).to_digit(16));
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
            }
        } else {
            out.push(b);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
