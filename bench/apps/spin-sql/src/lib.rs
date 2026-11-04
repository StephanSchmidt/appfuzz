//! Bench app `spin-sql`: a Spin HTTP component that looks up a product by
//! the `?sku=` query parameter. The bug: the SKU is pasted into the SQL
//! text (SQL injection). It also counts page views in key-value storage.

use spin_sdk::http::{IntoResponse, Request, Response};
use spin_sdk::http_component;
use spin_sdk::key_value::Store;
use spin_sdk::sqlite::{Connection, Value};

#[http_component]
fn handle(req: Request) -> anyhow::Result<impl IntoResponse> {
    let sku = req.query().split('&').find_map(|kv| kv.strip_prefix("sku=")).unwrap_or("A-1").to_string();
    let db = Connection::open_default()?;
    let rows = db.execute(&format!("SELECT name, price FROM products WHERE sku = '{sku}'"), &[])?;
    let store = Store::open_default()?;
    let views = store.get("views")?.and_then(|v| String::from_utf8(v).ok()).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) + 1;
    store.set("views", views.to_string().as_bytes())?;
    let mut html = String::from("<h1>Products</h1><ul>");
    for row in &rows.rows {
        if let (Some(Value::Text(name)), Some(Value::Real(price))) = (row.values.first(), row.values.get(1)) {
            html.push_str(&format!("<li>{} {price:.2}</li>", escape(name)));
        }
    }
    html.push_str(&format!("</ul><p>{views} views</p>"));
    Ok(Response::builder().status(200).header("content-type", "text/html").body(html).build())
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
