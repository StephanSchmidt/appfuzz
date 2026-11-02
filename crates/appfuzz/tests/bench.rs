//! The bench, the acceptance test: `appfuzz review` on
//! every app in `bench/apps` must show the findings its `expected.json`
//! lists, and no other warn or fail finding.
//!
//! Slow (builds the apps for wasm32-wasip2, then fuzzes each), so ignored
//! by default:
//!
//! ```text
//! cargo test --release -p appfuzz --test bench -- --ignored --nocapture
//! BENCH_ONLY=chatty BENCH_TIME=10s cargo test --release -p appfuzz --test bench -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn rank(s: &str) -> u8 {
    match s {
        "fail" => 2,
        "warn" => 1,
        _ => 0,
    }
}

/// Bytes a confirmed case may keep: request and plan, and the plan alone
/// (where unshrunk host data shows; a request may need long text at its
/// boundary).
const MAX_CASE: u64 = 8192;
const MAX_PLAN: u64 = 2048;

/// Runs `review` and compares with the expectation; the problems found.
fn check(manifest: &Path, expected: &Value, state: &Path) -> (Vec<String>, Value) {
    let time = std::env::var("BENCH_TIME").unwrap_or_else(|_| "5s".into());
    let out = Command::new(env!("CARGO_BIN_EXE_appfuzz"))
        .arg("-m")
        .arg(manifest)
        .arg("--state")
        .arg(state)
        .args(["--full", "review", "--fresh", "--time", &time, "--min", "info"])
        .output()
        .expect("running appfuzz");
    let review: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(e) => return (vec![format!("no JSON from appfuzz ({e}): {}", String::from_utf8_lossy(&out.stderr))], Value::Null),
    };
    if let Some(e) = review.get("error") {
        return (vec![format!("appfuzz failed: {e}")], review);
    }
    let findings = review["findings"].as_array().cloned().unwrap_or_default();
    let mut problems = Vec::new();
    let expect = expected["expect"].as_array().cloned().unwrap_or_default();
    for e in &expect {
        let (kind, min) = (e["kind"].as_str().unwrap_or_default(), rank(e["min"].as_str().unwrap_or("info")));
        if !findings.iter().any(|f| f["kind"] == kind && rank(f["severity"].as_str().unwrap_or_default()) >= min) {
            let seen: Vec<String> = findings.iter().filter(|f| f["kind"] == kind).map(|f| format!("{} {}", f["severity"], f["title"])).collect();
            problems.push(format!("missed {kind} (≥ {}){}", e["min"], if seen.is_empty() { String::new() } else { format!(", only: {seen:?}") }));
        }
    }
    let allowed: Vec<&str> = expect.iter().filter_map(|e| e["kind"].as_str()).chain(expected["allow"].as_array().into_iter().flatten().filter_map(Value::as_str)).collect();
    for f in &findings {
        let k = f["kind"].as_str().unwrap_or_default();
        if rank(f["severity"].as_str().unwrap_or_default()) >= 1 && !allowed.contains(&k) {
            problems.push(format!("unexpected {} {k}: {}", f["severity"], f["title"]));
        }
    }
    // Cases must be small enough to read.
    for s in review["steps"].as_array().into_iter().flatten() {
        if s["size_after"].as_u64().is_some_and(|n| n > MAX_CASE) || s["plan_size"].as_u64().is_some_and(|n| n > MAX_PLAN) {
            problems.push(format!(
                "{} left a case of {} bytes, plan {} (from {}; limits {MAX_CASE}, plan {MAX_PLAN})",
                s["step"], s["size_after"], s["plan_size"], s["size_before"]
            ));
        }
    }
    for s in review["steps"].as_array().into_iter().flatten().filter(|s| s.get("error").is_some()) {
        problems.push(format!("step {} failed: {}", s["step"], s["error"]));
    }
    (problems, review)
}

fn state_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("appfuzz-bench-{}", std::process::id())).join(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn report(results: &[(String, Vec<String>)]) {
    let bad: Vec<&(String, Vec<String>)> = results.iter().filter(|(_, p)| !p.is_empty()).collect();
    for (name, problems) in results {
        println!("{} {name}", if problems.is_empty() { "ok  " } else { "FAIL" });
        for p in problems {
            println!("       {p}");
        }
    }
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("appfuzz-bench-{}", std::process::id())));
    assert!(bad.is_empty(), "{} of {} bench apps failed: {:?}", bad.len(), results.len(), bad.iter().map(|(n, _)| n).collect::<Vec<_>>());
}

#[test]
#[ignore = "slow: builds and fuzzes the bench apps"]
fn bench() {
    let bench = root().join("bench");
    let status = Command::new("cargo").args(["build", "--release", "--target", "wasm32-wasip2"]).current_dir(&bench).status().expect("cargo");
    assert!(status.success(), "building the bench apps failed (is the wasm32-wasip2 target installed?)");
    let only = std::env::var("BENCH_ONLY").ok();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(bench.join("apps")).unwrap().map(|e| e.unwrap().path()).collect();
    dirs.sort();
    let mut results = Vec::new();
    for d in dirs {
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        if only.as_ref().is_some_and(|o| !o.split(',').any(|x| x == name)) {
            continue;
        }
        let expected: Value = serde_json::from_slice(&std::fs::read(d.join("expected.json")).unwrap()).unwrap();
        if let Some(p) = expected.get("pending") {
            println!("skip {name}: {p}");
            continue;
        }
        let (problems, _) = check(&d.join("appfuzz.toml"), &expected, &state_dir(&name));
        results.push((name, problems));
    }
    report(&results);
}
