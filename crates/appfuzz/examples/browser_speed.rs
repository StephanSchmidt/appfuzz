//! Browser speed: page sessions per second when appfuzz's harness runs the
//! browser guest, under fuel, on one thread.
//!
//! ```text
//! cargo run --release -p appfuzz --example browser_speed -- browser/appfuzz.toml 20 page.json...
//! ```
//!
//! `snapshot.wasm=page.json` runs that page in its own snapshot (one with
//! the page's scripts compiled) instead of the manifest's guest.

use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use appfuzz_core::harness::App;
use appfuzz_core::manifest::Manifest;
use appfuzz_core::plan::Plan;
use serde_json::Value;

fn load(manifest: &Manifest, wasm: &Path) -> App {
    let bytes = std::fs::read(wasm).unwrap();
    let t = Instant::now();
    let app = App::from_bytes(manifest.clone(), bytes.clone()).unwrap();
    println!("{}: {} bytes, load {:.0} ms", wasm.display(), bytes.len(), t.elapsed().as_secs_f64() * 1000.0);
    app
}

fn main() {
    let mut args = std::env::args().skip(1);
    let manifest = Manifest::load(Path::new(&args.next().expect("manifest"))).unwrap();
    let n: u32 = args.next().expect("runs").parse().unwrap();
    let mut shared = None;
    for arg in args {
        let (own, path) = match arg.split_once('=') {
            Some((wasm, path)) => (Some(load(&manifest, Path::new(wasm))), path.to_string()),
            None => (None, arg),
        };
        let app = match &own {
            Some(app) => app,
            None => shared.get_or_insert_with(|| load(&manifest, &manifest.wasm_path())),
        };
        let export = app.default_export().unwrap().clone();
        let input = std::fs::read_to_string(&path).unwrap();
        let spec = app.spec(&export, vec![Value::String(input)], Plan::default(), 1);
        let first = app.run(&spec);
        let report = first.result.as_ref().and_then(Value::as_str).and_then(|s| serde_json::from_str::<Value>(s).ok());
        let errors = report.as_ref().and_then(|r| r["errors"].as_array()).map_or(0, Vec::len);
        let text: String = report.as_ref().and_then(|r| r["text"].as_str()).unwrap_or("").chars().take(80).collect();
        let requests: Vec<String> = report
            .as_ref()
            .and_then(|r| r["requests"].as_array())
            .into_iter()
            .flatten()
            .map(|q| format!("{} {} gesture={}", q["method"].as_str().unwrap_or(""), q["url"].as_str().unwrap_or(""), q["gesture"]))
            .collect();
        let t = Instant::now();
        for _ in 0..n {
            black_box(app.run(&spec));
        }
        let per = t.elapsed().as_secs_f64() / f64::from(n);
        let name = Path::new(&path).file_stem().unwrap().to_string_lossy();
        println!(
            "{name}: {:?} {:.1} sessions/s ({:.1} ms), fuel {:.0}M, peak memory {:.1} MiB, errors {errors}, text: {text}",
            first.outcome.kind,
            1.0 / per,
            per * 1000.0,
            first.totals.fuel as f64 / 1e6,
            first.totals.peak_memory as f64 / 1048576.0,
        );
        if let Some(r) = &report {
            println!("  idle {} later {} steps {}", r["idle"], r["later"], r["steps"]);
            println!("  errors {}", r["errors"].to_string().chars().take(400).collect::<String>());
        }
        for q in &requests {
            println!("  request: {q}");
        }
        if first.result.is_none() {
            println!("  {:?} {}", first.outcome.message, first.stderr.chars().take(500).collect::<String>());
        }
    }
}
