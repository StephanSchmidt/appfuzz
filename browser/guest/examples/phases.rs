//! How a page's scripts split into compiling and running. Native.
//! `phases session.json`: compiles every .js file of the session, then
//! runs a full session, and prints both times.

use std::time::Instant;

fn main() {
    let input = std::fs::read_to_string(std::env::args().nth(1).expect("session.json")).unwrap();
    let n = 20;
    let rt = rquickjs::Runtime::new().unwrap();
    let ctx = rquickjs::Context::full(&rt).unwrap();
    let files: Vec<(String, String)> = ctx.with(|ctx| {
        let v = ctx.json_parse(input.clone()).unwrap().into_object().unwrap();
        let files: rquickjs::Object = v.get("files").unwrap();
        files.props::<String, String>().filter_map(Result::ok).filter(|(k, _)| k.ends_with(".js")).collect()
    });
    for (name, code) in &files {
        let t = Instant::now();
        for i in 0..n {
            ctx.with(|ctx| {
                let m = rquickjs::Module::declare(ctx.clone(), format!("{name}?{i}"), code.as_str());
                std::hint::black_box(m.is_ok());
            });
        }
        eprintln!("compile {name} ({} KB): {:.2} ms", code.len() / 1024, t.elapsed().as_secs_f64() * 1000.0 / f64::from(n));
    }
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(appfuzz_browser::driver::session(&input));
    }
    eprintln!("session (boots each time): {:.2} ms", t.elapsed().as_secs_f64() * 1000.0 / f64::from(n));
}
