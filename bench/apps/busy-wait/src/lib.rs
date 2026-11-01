//! Bench app `busy-wait`: spins on the clock for 50 ms instead of sleeping.

include!("../../../prelude.rs");

impl exports::bench::web::handler::Guest for A {
    fn handle(req: Request) -> Response {
        let _ = &req;
        let start = std::time::Instant::now();
        let mut spins = 0u64;
        while start.elapsed() < std::time::Duration::from_millis(50) {
            spins += 1;
        }
        html(format!("<p>waited ({spins} spins)</p>"))
    }
}
