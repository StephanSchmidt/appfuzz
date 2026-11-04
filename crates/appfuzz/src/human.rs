//! A short summary for a person at a terminal: the verdict, one line per
//! finding, and what to run next. Piped output, and `--json`, stay JSON, so
//! CI and agents see no change.

use std::fmt::Write;
use std::io::IsTerminal;

use serde_json::Value;

/// Whether to print a summary instead of JSON.
pub(crate) fn wanted(json_flag: bool) -> bool {
    !json_flag && std::env::var_os("APPFUZZ_JSON").is_none() && std::io::stdout().is_terminal()
}

struct Style {
    color: bool,
}

impl Style {
    fn new() -> Self {
        Style { color: std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()) && std::env::var("TERM").map_or(true, |t| t != "dumb") }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn severity(&self, s: &str) -> String {
        let padded = format!("{s:<4}");
        match s {
            "fail" => self.paint("1;31", &padded),
            "warn" => self.paint("33", &padded),
            _ => self.paint("2", &padded),
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
}

/// The summary for `path`'s output, or `None` to print JSON.
pub(crate) fn summary(path: &str, out: &Value) -> Option<String> {
    let st = Style::new();
    let mut s = String::new();
    if let Some(e) = out["error"].as_str() {
        let _ = writeln!(s, "{} {e}", st.paint("1;31", "error:"));
        for sub in out["subcommands"].as_array().into_iter().flatten() {
            let _ = writeln!(s, "  {}  {}", st.bold(sub["command"].as_str().unwrap_or("")), st.dim(sub["what"].as_str().unwrap_or("")));
        }
        let examples: Vec<&str> = out["examples"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !examples.is_empty() {
            let _ = writeln!(s, "{}", st.dim("Examples:"));
            for x in examples {
                let _ = writeln!(s, "  {x}");
            }
        }
        return Some(s);
    }
    match path {
        "review" => review(&st, out, &mut s),
        "run" => run(&st, out, &mut s),
        "inspect" => inspect(&st, out, &mut s),
        "findings" => {
            let _ = writeln!(s, "{} findings", out["count"].as_u64().unwrap_or(0));
            findings(&st, out, &mut s);
        }
        _ => return None,
    }
    next(&st, out, &mut s);
    let _ = writeln!(s, "\n{}", st.dim("Full report: add --json"));
    Some(s)
}

fn review(st: &Style, out: &Value, s: &mut String) {
    let verdict = out["verdict"].as_str().unwrap_or("incomplete");
    let shown = match verdict {
        "pass" => st.paint("1;32", "PASS"),
        "warn" => st.paint("1;33", "WARN"),
        "fail" => st.paint("1;31", "FAIL"),
        v => st.paint("1;35", &v.to_uppercase()),
    };
    let c = &out["counts"];
    let n = |k: &str| c[k].as_u64().unwrap_or(0);
    let runs = out["coverage"]["fuzz_runs"].as_u64();
    let ms: u64 = out["steps"].as_array().into_iter().flatten().filter_map(|x| x["ms"].as_u64()).sum();
    let mut line = format!("{} {shown}  {} fail, {} warn, {} info", st.bold("appfuzz review"), n("fail"), n("warn"), n("info"));
    if let Some(r) = runs {
        let _ = write!(line, "  {}", st.dim(&format!("· {} runs in {:.1}s", thousands(r), ms as f64 / 1000.0)));
    }
    let _ = writeln!(s, "{line}");
    findings(st, out, s);
    for e in out["errors"].as_array().into_iter().flatten() {
        let _ = writeln!(s, "  {} {}", st.paint("35", "error"), e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string()));
    }
}

fn run(st: &Style, out: &Value, s: &mut String) {
    let kind = out["outcome"]["kind"].as_str().unwrap_or("?");
    let shown = if kind == "ok" { st.paint("1;32", "ok") } else { st.paint("1;31", kind) };
    let t = &out["totals"];
    let _ = writeln!(
        s,
        "{} {}  {shown}  {}",
        st.bold("appfuzz run"),
        out["run"].as_str().unwrap_or(""),
        st.dim(&format!(
            "· {} host calls, cost {}, {} ms virtual, {} fuel",
            t["host_calls"].as_u64().unwrap_or(0),
            t["cost"].as_u64().unwrap_or(0),
            t["virtual_ms"].as_f64().unwrap_or(0.0),
            thousands(t["fuel"].as_u64().unwrap_or(0))
        ))
    );
    if let Some(m) = out["outcome"]["message"].as_str() {
        let _ = writeln!(s, "  {}", st.paint("31", m));
    }
    if !out["result"].is_null() {
        let text = serde_json::to_string(&out["result"]).unwrap_or_default();
        let _ = writeln!(s, "  {} {}", st.dim("result:"), clip(&text, 300));
    }
    findings(st, out, s);
}

fn inspect(st: &Style, out: &Value, s: &mut String) {
    let app = &out["app"];
    let name = app["name"].as_str().or_else(|| app["wasm"].as_str()).unwrap_or("app");
    let _ = writeln!(s, "{} {name}  {}", st.bold("appfuzz inspect"), st.dim(&format!("· {} bytes", thousands(app["bytes"].as_u64().unwrap_or(0)))));
    for e in out["exports"].as_array().into_iter().flatten() {
        let _ = writeln!(s, "  {} {}", st.dim("export"), e["sig"].as_str().or_else(|| e["key"].as_str()).unwrap_or(""));
    }
    let mut wasi: Vec<String> = Vec::new();
    for i in out["imports"].as_array().into_iter().flatten() {
        let name = i["interface"].as_str().unwrap_or("");
        if i["kind"] == "wasi" {
            let short = name.split('@').next().unwrap_or(name).trim_start_matches("wasi:").to_string();
            wasi.push(short);
            continue;
        }
        let granted = if i["granted"].as_bool() == Some(false) { st.paint("31", " (not granted)") } else { String::new() };
        let funcs = i["funcs"].as_array().map_or(0, Vec::len);
        let _ = writeln!(s, "  {} {name} {}{granted}", st.dim("import"), st.dim(&format!("({funcs} function{})", if funcs == 1 { "" } else { "s" })));
    }
    if !wasi.is_empty() {
        let _ = writeln!(s, "  {} {}", st.dim("wasi  "), st.dim(&wasi.join(", ")));
    }
    findings(st, out, s);
}

fn findings(st: &Style, out: &Value, s: &mut String) {
    let list: Vec<&Value> = out["findings"].as_array().into_iter().flatten().collect();
    if list.is_empty() {
        return;
    }
    let width = list.iter().filter_map(|f| f["kind"].as_str()).map(str::len).max().unwrap_or(0);
    let _ = writeln!(s);
    for f in list {
        let kind = f["kind"].as_str().unwrap_or("");
        let _ = writeln!(
            s,
            "  {}  {}  {}",
            st.severity(f["severity"].as_str().unwrap_or("info")),
            st.bold(&format!("{kind:<width$}")),
            f["title"].as_str().unwrap_or("")
        );
    }
}

fn next(st: &Style, out: &Value, s: &mut String) {
    let list: Vec<&str> = out["next"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if list.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n{}", st.bold("Next:"));
    for n in list {
        let _ = writeln!(s, "  {n}");
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max).collect::<String>()) }
}

fn thousands(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_review_shows_the_verdict_each_finding_and_what_next() {
        let out = json!({
            "verdict": "fail", "counts": {"fail": 1, "warn": 1, "info": 0},
            "coverage": {"fuzz_runs": 12345}, "steps": [{"ms": 1500}, {"ms": 500}],
            "findings": [
                {"severity": "fail", "kind": "n_plus_1", "title": "calls grow"},
                {"severity": "warn", "kind": "chatty", "title": "one per element"}
            ],
            "next": ["appfuzz show r1 --view explanation"]
        });
        let text = summary("review", &out).unwrap();
        let plain = strip(&text);
        assert!(plain.starts_with("appfuzz review FAIL  1 fail, 1 warn, 0 info  · 12,345 runs in 2.0s"), "{plain}");
        assert!(plain.contains("  fail  n_plus_1  calls grow"), "{plain}");
        assert!(plain.contains("  warn  chatty    one per element"), "{plain}");
        assert!(plain.contains("Next:\n  appfuzz show r1 --view explanation"), "{plain}");
        assert!(plain.ends_with("\n\nFull report: add --json\n"), "{plain}");
    }

    #[test]
    fn errors_and_other_commands() {
        let e = strip(&summary("run", &json!({"error": "no appfuzz.toml here", "examples": ["appfuzz run"]})).unwrap());
        assert_eq!(e, "error: no appfuzz.toml here\nExamples:\n  appfuzz run\n");
        assert!(summary("plan template", &json!({})).is_none(), "commands without a summary print JSON");
    }

    #[test]
    fn numbers_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1234567), "1,234,567");
    }

    fn strip(s: &str) -> String {
        let mut out = String::new();
        let mut esc = false;
        for c in s.chars() {
            match (esc, c) {
                (false, '\x1b') => esc = true,
                (true, 'm') => esc = false,
                (true, _) => {}
                (false, c) => out.push(c),
            }
        }
        out
    }
}
