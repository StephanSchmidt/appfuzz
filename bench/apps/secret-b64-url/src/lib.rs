//! Bench app `secret-b64-url`: puts the API key, base64-encoded, into the URL of a fetch.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        fn b64(b: &[u8]) -> String {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut o = String::new();
            for c in b.chunks(3) {
                let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
                for i in 0..=c.len() {
                    o.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
                }
            }
            o
        }

        let _ = &req;
        let key = config::secret("api-key");
        let text = http::fetch(&format!("https://api.example.com/v1/items?t={}", b64(format!("k={key}").as_bytes())), "").unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    }
}
