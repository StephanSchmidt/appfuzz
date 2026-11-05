//! Bench app `scripts-ok`: data for its scripts escaped for JSON in HTML, a CSP header, its own bundle and a pinned library.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        // A JavaScript string literal that is safe in a <script> element.
        fn js(s: &str) -> String {
            let mut o = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' | '\\' | '\'' | '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => o += &format!("\\u{:04x}", c as u32),
                    c if (c as u32) < 0x20 => o += &format!("\\u{:04x}", c as u32),
                    c => o.push(c),
                }
            }
            o + "\""
        }
        let q = param(&req.query, "q").unwrap_or("");
        let names: Vec<String> = items::all().iter().take(20).map(|it| js(&it.name)).collect();
        let body = format!(
            "<p>Results for {}</p><ul id=\"list\"></ul>\
             <script>window.app = {{ q: {}, names: [{}] }};</script>\
             <script src=\"https://cdn.example.net/lit.js\" integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\" crossorigin=\"anonymous\"></script>\
             <script type=\"module\" src=\"/static/app.js\"></script>",
            esc(q),
            js(q),
            names.join(",")
        );
        let csp = "default-src 'self'; script-src 'self' cdn.example.net; img-src 'self' data:; form-action 'self'; base-uri 'none'";
        Response { status: 200, body, headers: vec![("content-type".into(), "text/html".into()), ("content-security-policy".into(), csp.into())] }
    }
}
