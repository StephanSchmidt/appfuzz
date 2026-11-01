//! Bench app `retry-storm`: retries a failing save fifty times.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let mut tries = 0;
        let id = loop {
            match store::save("visits", "1") {
                Ok(id) => break id,
                Err(_) if tries < 50 => tries += 1,
                Err(_) => break 0,
            }
        };
        html(format!("<p>saved as {id} after {tries} retries</p>"))
    }
}
