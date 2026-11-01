//! `appfuzz review`: every phase 1 analysis in one go, the findings
//! confirmed, and a verdict with an exit code (0 pass, 1 warn, 2 fail).
//!
//! It runs the same commands an agent would (inspect, run, probe values,
//! probe times, amplify, fuzz, confirm, unexplored, urls), so `review`
//! and the drill-down commands can never disagree.

use std::collections::BTreeSet;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use serde_json::{Value, json};

use appfuzz_core::detect::{FindingStore, Severity};
use appfuzz_core::harness::App;

use crate::{Cli, finding_json, load_manifest};

pub struct Opts {
    pub time: String,
    pub rng: u64,
    pub fresh: bool,
    pub confirm: usize,
    pub min: Severity,
}

/// One appfuzz command, with the review's global options.
fn sub(cli: &Cli, args: &[&str]) -> Result<Cli> {
    let mut c = Cli::try_parse_from(std::iter::once("appfuzz").chain(args.iter().copied()))?;
    c.manifest = cli.manifest.clone();
    c.wasm = cli.wasm.clone();
    c.state = cli.state.clone();
    c.full = true;
    Ok(c)
}

pub fn review(cli: &Cli, o: &Opts) -> Result<Value> {
    let app = App::load(load_manifest(cli)?)?;
    let mut steps = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut outputs = serde_json::Map::new();
    let mut step = |name: &str, args: &[&str], seen: &mut BTreeSet<String>| -> Option<Value> {
        let t = Instant::now();
        let out = sub(cli, args).and_then(crate::run);
        let ms = t.elapsed().as_millis() as u64;
        match out {
            Ok(v) => {
                let ids: Vec<String> = v["findings"].as_array().into_iter().flatten().filter_map(|f| f["id"].as_str().map(str::to_string)).collect();
                steps.push(json!({"step": name, "ms": ms, "findings": ids.len()}));
                seen.extend(ids);
                Some(v)
            }
            Err(e) => {
                steps.push(json!({"step": name, "ms": ms, "error": format!("{e:#}")}));
                None
            }
        }
    };
    let fuzz_args: Vec<String> = ["fuzz", "--time", &o.time, "--rng", &o.rng.to_string()].iter().map(|s| s.to_string()).chain(o.fresh.then(|| "--fresh".to_string())).collect();
    for (name, args) in [
        ("inspect", vec!["inspect"]),
        ("run", vec!["run"]),
        ("probe values", vec!["probe", "values"]),
        ("probe times", vec!["probe", "times"]),
        ("amplify", vec!["amplify"]),
        ("fuzz", fuzz_args.iter().map(String::as_str).collect()),
    ] {
        if let Some(v) = step(name, &args, &mut seen) {
            outputs.insert(name.into(), v);
        }
    }

    // Confirm the worst findings that came from a run.
    let store = FindingStore::new(&cli.state, &app.hash);
    let mut todo: Vec<_> = store.all().into_iter().filter(|f| seen.contains(&f.id) && f.severity > Severity::Info && f.run.is_some() && f.confirmed.is_none()).collect();
    todo.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let mut not_reproducible = BTreeSet::new();
    let mut confirmed = 0;
    for f in todo.iter().take(o.confirm) {
        if let Some(v) = step(&format!("confirm {}", f.id), &["confirm", &f.id, "--max-runs", "200"], &mut seen) {
            if v["confirmed"] == json!(true) {
                confirmed += 1;
            } else {
                not_reproducible.insert(f.id.clone());
            }
        }
    }
    let unexplored = step("unexplored", &["unexplored"], &mut seen);
    let urls = step("urls", &["urls", "--domains"], &mut seen);

    drop(step);
    let mut all: Vec<_> = store.all().into_iter().filter(|f| seen.contains(&f.id)).collect();
    all.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.kind.cmp(&b.kind)));
    let count = |s: Severity| all.iter().filter(|f| f.severity == s).count();
    let (fail, warn) = (count(Severity::Fail), count(Severity::Warn));
    let (verdict, code) = if fail > 0 {
        ("fail", 2)
    } else if warn > 0 {
        ("warn", 1)
    } else {
        ("pass", 0)
    };
    let findings: Vec<Value> = all
        .iter()
        .filter(|f| f.severity >= o.min)
        .map(|f| {
            let mut j = finding_json(f);
            if not_reproducible.contains(&f.id) {
                j["reproducible"] = json!(false);
            }
            j
        })
        .collect();
    let fuzz = outputs.get("fuzz");
    Ok(json!({
        "component": app.manifest.wasm_path().display().to_string(),
        "verdict": verdict,
        "exit_code": code,
        "counts": {"fail": fail, "warn": warn, "info": count(Severity::Info), "confirmed": confirmed, "not_reproducible": not_reproducible.len()},
        "findings": findings,
        "coverage": {
            "fuzz_runs": fuzz.map(|f| f["runs"].clone()),
            "corpus": fuzz.map(|f| f["corpus"].clone()),
            "static_call_sites": unexplored.as_ref().map(|u| u["static_sites"].clone()),
            "unreached_call_sites": unexplored.as_ref().map(|u| u["unreached"].clone()),
        },
        "domains": urls.map(|u| u["domains"].clone()),
        "steps": steps,
        "note": "phase 1 (bad patterns) only; info findings are hints. Drill down with `explain <run>`, `confirm <id>`, `check`.",
    }))
}
