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
        .args(std::env::var("BENCH_ARGS").unwrap_or_default().split_whitespace())
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
        if let Some(max) = e["max"].as_str().map(rank)
            && let Some(f) = findings.iter().find(|f| f["kind"] == kind && rank(f["severity"].as_str().unwrap_or_default()) > max)
        {
            problems.push(format!("{kind} above {}: {} {}", e["max"], f["severity"], f["title"]));
        }
    }
    let allowed: Vec<&str> =
        expect.iter().filter_map(|e| e["kind"].as_str()).chain(expected["allow"].as_array().into_iter().flatten().filter_map(Value::as_str)).collect();
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
    if !bad.is_empty() {
        println!("\nfailed:");
    }
    for (name, problems) in &bad {
        println!("FAIL {name}");
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
    let mut apps = Vec::new();
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
        apps.push((name, d, expected));
    }
    // One line per app as it finishes, so a long run shows where it is.
    let start = std::time::Instant::now();
    let mut results = Vec::new();
    let mut failed = 0;
    for (i, (name, d, expected)) in apps.iter().enumerate() {
        let t = std::time::Instant::now();
        // A Spin app may come with its spin.toml alone.
        let manifest = if d.join("appfuzz.toml").exists() { d.join("appfuzz.toml") } else { d.join("spin.toml") };
        let (problems, _) = check(&manifest, expected, &state_dir(name));
        failed += usize::from(!problems.is_empty());
        let w = apps.len().to_string().len();
        println!(
            "[{:>w$}/{}] {} {name} ({:.1}s, {:.0}s total{})",
            i + 1,
            apps.len(),
            if problems.is_empty() { "ok  " } else { "FAIL" },
            t.elapsed().as_secs_f64(),
            start.elapsed().as_secs_f64(),
            if failed > 0 { format!(", {failed} failed") } else { String::new() }
        );
        for p in &problems {
            println!("       {p}");
        }
        results.push((name.clone(), problems));
    }
    report(&results);
}

fn appfuzz(manifest: &Path, state: &Path, args: &[&str]) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_appfuzz")).arg("-m").arg(manifest).arg("--state").arg(state).args(args).output().expect("running appfuzz");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("no JSON from appfuzz {args:?} ({e}): {}", String::from_utf8_lossy(&out.stderr)))
}

/// What review saw is what production is held to: the time bomb passes
/// review (its minute is behind a hash), and its trace on that minute
/// leaves the envelope.
#[test]
#[ignore = "slow: builds and reviews a bench app"]
fn envelope_time_bomb() {
    let bench = root().join("bench");
    let status = Command::new("cargo").args(["build", "--release", "--target", "wasm32-wasip2"]).current_dir(&bench).status().expect("cargo");
    assert!(status.success());
    let manifest = bench.join("apps/time-bomb/appfuzz.toml");
    let state = state_dir("envelope-time-bomb");
    let env = state.join("envelope.json");
    let env = env.to_str().unwrap();
    let review = appfuzz(&manifest, &state, &["review", "--fresh", "--time", "5s"]);
    // The review cannot reach the bomb; it can point at it.
    assert_eq!(review["verdict"], "warn", "{review}");
    assert!(review["findings"].as_array().unwrap().iter().any(|f| f["kind"] == "dormant_code"), "{review}");
    let rejected = appfuzz(&manifest, &state, &["envelope", "--out", env]);
    assert!(rejected.get("error").is_some(), "{rejected}");
    let e = appfuzz(&manifest, &state, &["envelope", "--allow-warnings", "--out", env]);
    assert!(e.get("error").is_none(), "{e}");
    let check = |now: &str| {
        let run = appfuzz(&manifest, &state, &["run", "--now", now]);
        let id = run["run"].as_str().expect("run id").to_string();
        appfuzz(&manifest, &state, &["envelope", "check", &id, "--envelope", env])
    };
    let day = check("2026-11-03T10:00:00");
    assert_eq!(day["verdict"], "pass", "{day}");
    let bomb = check("2027-06-15T03:17:00");
    assert_eq!(bomb["verdict"], "fail", "{bomb}");
    let f = &bomb["findings"][0];
    assert_eq!((f["kind"].as_str(), f["detail"]["destination"].as_str()), (Some("outside_envelope"), Some("drop.example.org:443")), "{bomb}");
    println!("ok   envelope_time_bomb: review passes, the trace at the bomb's minute leaves the envelope");
    let _ = std::fs::remove_dir_all(&state);
}
