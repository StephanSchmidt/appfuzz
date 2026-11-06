//! Runs page sessions natively, for quick iteration on the shim and the
//! driver: `cargo run --release --example run -- session.json [N]`.

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: run session.json [N]");
    let n: u32 = args.next().map(|s| s.parse().expect("N")).unwrap_or(1);
    let input = std::fs::read_to_string(&path).expect("session file");
    let start = std::time::Instant::now();
    let mut out = String::new();
    for _ in 0..n {
        out = appfuzz_browser::driver::session(&input);
    }
    let ms = start.elapsed().as_secs_f64() * 1000.0 / f64::from(n);
    eprintln!("{ms:.2} ms/session native ({:.0} sessions/s)", 1000.0 / ms);
    println!("{out}");
}
