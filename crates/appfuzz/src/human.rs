//! `--human`: the output for a person instead of JSON. The commands people
//! run most (`review`, `run`, `inspect`, `findings`, `explain`) get their own
//! summary: the verdict, one line per finding, what to run next. Every other
//! command is laid out from its JSON, keys as words, long lists cut short.
//! Without `--human`, output stays JSON, so CI and agents see no change.

use std::fmt::Write;
use std::io::IsTerminal;

use serde_json::Value;

/// Whether to print for a person instead of JSON.
pub(crate) fn wanted(human_flag: bool) -> bool {
    human_flag || std::env::var_os("APPFUZZ_HUMAN").is_some_and(|v| !v.is_empty() && v != "0")
}

fn set(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty() && v != "0")
}

fn stderr_style() -> Style {
    Style { color: (std::io::stderr().is_terminal() || set("CLICOLOR_FORCE")) && !set("NO_COLOR"), cols: None }
}

/// Printed on stderr before a review starts, so a person knows it's working.
pub(crate) fn starting(time: &str) {
    eprintln!("{}", stderr_style().dim(&format!("Reviewing: probes, scaling, then {time} of fuzzing…\n")));
}

/// Printed on stderr after downloading an app by URL.
pub(crate) fn downloaded(wasm: &str, bytes: u64, manifest: Option<&str>) {
    let with = manifest.map_or_else(|| ", no manifest".to_string(), |m| format!(" and {m}"));
    eprintln!("{}", stderr_style().dim(&format!("Downloaded {wasm} ({} bytes){with}", thousands(bytes))));
}

/// Columns of the terminal: the real one, else `COLUMNS`.
fn columns() -> Option<usize> {
    terminal_size::terminal_size().map(|(w, _)| w.0 as usize).or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
}

/// List items shown before "… N more".
const LIST_MAX: usize = 12;
/// Characters of one line before it is cut.
const WIDTH: usize = 110;

struct Style {
    color: bool,
    /// Terminal columns, to wrap long lines; `None`: don't wrap.
    cols: Option<usize>,
}

impl Style {
    fn new() -> Self {
        Style {
            color: (std::io::stdout().is_terminal() || set("CLICOLOR_FORCE")) && !set("NO_COLOR") && std::env::var("TERM").map_or(true, |t| t != "dumb"),
            cols: columns(),
        }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    /// A label on a colored background, like ` FAIL `.
    fn badge(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m {s} \x1b[0m") } else { format!("[{s}]") }
    }
    fn severity(&self, s: &str) -> String {
        match s {
            "fail" => self.paint("1;31", "✗ fail"),
            "warn" => self.paint("1;33", "▲ warn"),
            _ => self.paint("2", "· info"),
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn cmd(&self, s: &str) -> String {
        self.paint("36", s)
    }
}

/// The text for `path`'s output.
pub(crate) fn summary(path: &str, out: &Value) -> String {
    render(&Style::new(), path, out)
}

fn render(st: &Style, path: &str, out: &Value) -> String {
    let mut s = String::new();
    if let Some(e) = out["error"].as_str() {
        let _ = writeln!(s, "{} {e}", st.badge("1;30;41", "ERROR"));
        for sub in out["subcommands"].as_array().into_iter().flatten() {
            let _ = writeln!(s, "  {}  {}", st.bold(sub["command"].as_str().unwrap_or("")), st.dim(sub["what"].as_str().unwrap_or("")));
        }
        let examples: Vec<&str> = out["examples"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !examples.is_empty() {
            let _ = writeln!(s, "\n{}", st.bold("Examples"));
            for x in examples {
                let _ = writeln!(s, "  {} {}", st.dim("›"), st.cmd(x));
            }
        }
        return s;
    }
    match path {
        "review" => review(st, out, &mut s),
        "run" | "call" if out.get("totals").is_some() => run(st, out, &mut s),
        "inspect" => inspect(st, out, &mut s),
        "findings" => {
            let n = out["count"].as_u64().unwrap_or(0);
            let _ = writeln!(s, "{} {}", st.badge("1;30;46", "FINDINGS"), st.bold(&format!("{n} finding{}", if n == 1 { "" } else { "s" })));
            findings(st, out, &mut s);
        }
        "explain" | "show" if out.get("vs_stored_runs").is_some() => explain(st, out, &mut s),
        _ => generic(st, path, out, &mut s),
    }
    next(st, out, &mut s);
    s
}

fn verdict_badge(st: &Style, verdict: &str) -> String {
    match verdict {
        "pass" => st.badge("1;30;42", "PASS"),
        "warn" => st.badge("1;30;43", "WARN"),
        "fail" => st.badge("1;30;41", "FAIL"),
        v => st.badge("1;30;45", &v.to_uppercase()),
    }
}

fn review(st: &Style, out: &Value, s: &mut String) {
    let verdict = out["verdict"].as_str().unwrap_or("incomplete");
    let c = &out["counts"];
    let n = |k: &str| c[k].as_u64().unwrap_or(0);
    let app = out["component"].as_str().map_or("app", |c| c.rsplit(['/', '\\']).next().unwrap_or(c));
    let _ = writeln!(s, "{} {}  {}", verdict_badge(st, verdict), st.bold(app), st.dim("appfuzz review"));
    let mut counts = vec![
        st.paint(if n("fail") > 0 { "1;31" } else { "2" }, &format!("{} fail", n("fail"))),
        st.paint(if n("warn") > 0 { "1;33" } else { "2" }, &format!("{} warn", n("warn"))),
        st.dim(&format!("{} info", n("info"))),
    ];
    if let Some(r) = out["coverage"]["fuzz_runs"].as_u64() {
        let ms: u64 = out["steps"].as_array().into_iter().flatten().filter_map(|x| x["ms"].as_u64()).sum();
        counts.push(st.dim(&format!("{} runs in {:.1}s", thousands(r), ms as f64 / 1000.0)));
    }
    let _ = writeln!(s, "       {}", counts.join(&st.dim(" · ")));
    findings(st, out, s);
    for e in out["errors"].as_array().into_iter().flatten() {
        let _ = writeln!(s, "  {} {}", st.paint("1;35", "✗ error"), e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string()));
    }
}

fn outcome_badge(st: &Style, kind: &str) -> String {
    if kind == "ok" { st.badge("1;30;42", "OK") } else { st.badge("1;30;41", &kind.to_uppercase()) }
}

fn run(st: &Style, out: &Value, s: &mut String) {
    let kind = out["outcome"]["kind"].as_str().unwrap_or("?");
    let t = &out["totals"];
    let _ = writeln!(s, "{} {}  {}", outcome_badge(st, kind), st.bold(out["run"].as_str().unwrap_or("")), st.dim("appfuzz run"));
    let _ = writeln!(
        s,
        "     {}",
        st.dim(&format!(
            "{} host calls · cost {} · {} ms virtual · {} fuel",
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
        let _ = writeln!(s, "  {} {}", st.dim("result"), clip(&text, 300));
    }
    findings(st, out, s);
}

/// `explain`, or `show --view explanation`: what the run did, what was
/// unusual about it, and its findings.
fn explain(st: &Style, out: &Value, s: &mut String) {
    let kind = out["outcome"].as_str().unwrap_or("?");
    let mut head = format!("{} {}  {}", outcome_badge(st, kind), st.bold(out["run"].as_str().unwrap_or("")), st.dim("appfuzz explain"));
    if let Some(code) = out["status"].as_u64() {
        let _ = write!(head, "  {}", st.dim(&format!("· status {code}")));
    }
    let _ = writeln!(s, "{head}");
    if let Some(m) = out["message"].as_str() {
        let _ = writeln!(s, "  {}", st.paint("31", m));
    }
    let label = |l: &str| st.dim(&format!("{l:<9}"));
    for d in out["input_vs_default"].as_array().into_iter().flatten() {
        let path = d["path"].as_str().unwrap_or("");
        let path = path.strip_prefix("[0].").unwrap_or(path);
        let _ = writeln!(
            s,
            "  {} {path} = {}  {}",
            label("input"),
            clip(&d["after"].to_string(), 120),
            st.dim(&format!("(default {})", clip(&d["before"].to_string(), 40)))
        );
    }
    let mut calls: Vec<(&String, u64)> = out["calls"].as_object().into_iter().flatten().map(|(f, n)| (f, n.as_u64().unwrap_or(0))).collect();
    calls.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    if !calls.is_empty() {
        let list: Vec<String> = calls.iter().map(|(f, n)| format!("{} × {f}", st.bold(&n.to_string()))).collect();
        let _ = writeln!(s, "  {} {}", label("calls"), list.join(", "));
    }
    let failed: Vec<String> = out["failed_calls"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| format!("#{} {}", f["n"].as_u64().unwrap_or(0), f["func"].as_str().unwrap_or("")))
        .collect();
    if !failed.is_empty() {
        let _ = writeln!(s, "  {} {}", label("failed"), st.paint("31", &failed.join(", ")));
    }
    let v = &out["vs_stored_runs"];
    let unusual: Vec<&str> = v["unusual"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if !unusual.is_empty() {
        let _ = writeln!(
            s,
            "  {} {}  {}",
            label("unusual"),
            st.paint("33", &unusual.join(", ")),
            st.dim(&format!("(against {} stored runs)", thousands(v["runs"].as_u64().unwrap_or(0))))
        );
    }
    if let Some(t) = out["text"].as_str().filter(|t| !t.is_empty()) {
        let _ = writeln!(s, "  {} {}", label("output"), clip(t, 120));
    }
    findings(st, out, s);
}

fn inspect(st: &Style, out: &Value, s: &mut String) {
    let app = &out["app"];
    let name = app["name"].as_str().or_else(|| app["wasm"].as_str()).unwrap_or("app");
    let _ =
        writeln!(s, "{} {}  {}", st.badge("1;30;46", "INSPECT"), st.bold(name), st.dim(&format!("{} bytes", thousands(app["bytes"].as_u64().unwrap_or(0)))));
    for e in out["exports"].as_array().into_iter().flatten() {
        let _ = writeln!(s, "  {} {}", st.paint("32", "export"), e["sig"].as_str().or_else(|| e["key"].as_str()).unwrap_or(""));
    }
    let mut wasi: Vec<String> = Vec::new();
    for i in out["imports"].as_array().into_iter().flatten() {
        let name = i["interface"].as_str().unwrap_or("");
        if i["kind"] == "wasi" {
            let short = name.split('@').next().unwrap_or(name).trim_start_matches("wasi:").to_string();
            wasi.push(short);
            continue;
        }
        let granted = if i["granted"].as_bool() == Some(false) { st.paint("1;31", " (not granted)") } else { String::new() };
        let funcs = i["funcs"].as_array().map_or(0, Vec::len);
        let _ = writeln!(s, "  {} {name} {}{granted}", st.paint("34", "import"), st.dim(&format!("({funcs} function{})", if funcs == 1 { "" } else { "s" })));
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
    let indent = 2 + 6 + 2 + width + 2;
    // In a narrow terminal the title goes on its own line, under the kind.
    let narrow = st.cols.is_some_and(|c| c < indent + 40);
    let _ = writeln!(s);
    for f in list {
        let kind = f["kind"].as_str().unwrap_or("");
        let severity = st.severity(f["severity"].as_str().unwrap_or("info"));
        let title = f["title"].as_str().unwrap_or("");
        if narrow {
            let _ = writeln!(s, "  {severity}  {}\n{:10}{}", st.bold(kind), "", wrap(title, 10, st.cols));
        } else {
            let _ = writeln!(s, "  {severity}  {}  {}", st.bold(&format!("{kind:<width$}")), wrap(title, indent, st.cols));
        }
    }
}

fn next(st: &Style, out: &Value, s: &mut String) {
    let list: Vec<&str> = out["next"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    if list.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n{}", st.bold("Next"));
    for n in list {
        let _ = writeln!(s, "  {} {}", st.dim("›"), st.cmd(n));
    }
}

/// Any other command: its JSON laid out for reading.
fn generic(st: &Style, path: &str, out: &Value, s: &mut String) {
    let title = if path.is_empty() { "appfuzz" } else { path };
    let mut head = st.badge("1;30;46", &title.to_uppercase());
    if let Some(v) = out["verdict"].as_str().or(out["status"].as_str()) {
        let _ = write!(head, " {}", verdict_badge(st, v));
    }
    if let Some(r) = out["run"].as_str() {
        let _ = write!(head, " {}", st.bold(r));
    }
    let _ = writeln!(s, "{head}");
    match out {
        Value::Object(o) => {
            let skip = ["next", "findings", "run", "verdict", "help", "exit_code"];
            fields(st, o.iter().filter(|(k, _)| !skip.contains(&k.as_str())), 1, s);
        }
        v => {
            let _ = writeln!(s, "  {}", scalar(st, v));
        }
    }
    findings(st, out, s);
}

fn fields<'a>(st: &Style, entries: impl Iterator<Item = (&'a String, &'a Value)>, depth: usize, s: &mut String) {
    let entries: Vec<_> = entries.collect();
    let width = entries.iter().filter(|(_, v)| is_inline(v)).map(|(k, _)| words(k).chars().count()).max().unwrap_or(0);
    let pad = "  ".repeat(depth);
    for (k, v) in entries {
        let key = words(k);
        if is_inline(v) {
            let _ = writeln!(s, "{pad}{}  {}", st.dim(&format!("{key:<width$}")), clip_visible(&inline(st, v), WIDTH.saturating_sub(pad.len() + width + 2)));
            continue;
        }
        let n = match v {
            Value::Array(a) => format!(" ({})", thousands(a.len() as u64)),
            _ => String::new(),
        };
        let _ = writeln!(s, "{pad}{}{}", st.bold(&key), st.dim(&n));
        match v {
            Value::Object(o) if depth < 3 => fields(st, o.iter(), depth + 1, s),
            Value::Array(a) => {
                for item in a.iter().take(LIST_MAX) {
                    let line = match item {
                        Value::Object(o) => compact(st, o),
                        v => inline(st, v),
                    };
                    let _ = writeln!(s, "{pad}  {} {}", st.dim("•"), clip_visible(&line, WIDTH.saturating_sub(pad.len() + 4)));
                }
                if a.len() > LIST_MAX {
                    let _ = writeln!(s, "{pad}  {}", st.dim(&format!("… {} more", thousands((a.len() - LIST_MAX) as u64))));
                }
            }
            v => {
                let _ = writeln!(s, "{pad}  {}", clip(&v.to_string(), WIDTH));
            }
        }
    }
}

/// Fits on the key's line: a scalar, an empty container, or a short list of
/// scalars.
fn is_inline(v: &Value) -> bool {
    match v {
        Value::Object(o) => o.is_empty(),
        Value::Array(a) => a.iter().all(|x| !x.is_object() && !x.is_array()) && a.len() <= LIST_MAX,
        _ => true,
    }
}

fn inline(st: &Style, v: &Value) -> String {
    match v {
        Value::Array(a) if a.is_empty() => st.dim("none"),
        Value::Object(_) => st.dim("none"),
        Value::Array(a) => a.iter().map(|x| scalar(st, x)).collect::<Vec<_>>().join(", "),
        v => scalar(st, v),
    }
}

fn scalar(st: &Style, v: &Value) -> String {
    match v {
        Value::Null => st.dim("—"),
        Value::Bool(true) => st.paint("32", "yes"),
        Value::Bool(false) => st.paint("31", "no"),
        Value::Number(n) => match n.as_u64() {
            Some(u) => st.paint("36", &thousands(u)),
            None => st.paint("36", &n.to_string()),
        },
        Value::String(t) => match t.as_str() {
            "fail" | "crash" | "trap" | "error" => st.paint("1;31", t),
            "warn" => st.paint("1;33", t),
            "pass" | "ok" => st.paint("1;32", t),
            _ => t.clone(),
        },
        v => v.to_string(),
    }
}

/// An object on one line: its scalar fields as `key value`.
fn compact(st: &Style, o: &serde_json::Map<String, Value>) -> String {
    o.iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, v)| match v {
            Value::Object(_) | Value::Array(_) => {
                format!("{} {}", st.dim(&words(k)), clip(&v.to_string(), 40))
            }
            v => format!("{} {}", st.dim(&words(k)), scalar(st, v)),
        })
        .collect::<Vec<_>>()
        .join("  ")
}

fn words(k: &str) -> String {
    k.replace('_', " ")
}

/// `text` in lines that fit `cols`, the lines after the first indented by
/// `indent` (where the text starts on the first line).
fn wrap(text: &str, indent: usize, cols: Option<usize>) -> String {
    let Some(room) = cols.map(|c| c.saturating_sub(indent + 1)).filter(|r| *r >= 30) else {
        return text.to_string();
    };
    let mut lines: Vec<String> = vec![String::new()];
    for word in text.split(' ') {
        let line = lines.last_mut().expect("a line");
        let len = line.chars().count();
        if len > 0 && len + 1 + word.chars().count() > room {
            lines.push(word.to_string());
        } else {
            if len > 0 {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    lines.join(&format!("\n{}", " ".repeat(indent)))
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max).collect::<String>()) }
}

/// Cuts a line with color codes after `max` visible characters.
fn clip_visible(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut seen = 0;
    let mut esc = false;
    let mut colored = false;
    for c in s.chars() {
        if esc {
            out.push(c);
            esc = c != 'm';
            continue;
        }
        if c == '\x1b' {
            esc = true;
            colored = true;
            out.push(c);
            continue;
        }
        if seen == max {
            out.push('…');
            if colored {
                out.push_str("\x1b[0m");
            }
            return out;
        }
        seen += 1;
        out.push(c);
    }
    out
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

    const PLAIN: Style = Style { color: false, cols: None };

    #[test]
    fn a_review_shows_the_verdict_each_finding_and_what_next() {
        let out = json!({
            "verdict": "fail", "component": "/cache/remote/abc/chatty.wasm",
            "counts": {"fail": 1, "warn": 1, "info": 0},
            "coverage": {"fuzz_runs": 12345}, "steps": [{"ms": 1500}, {"ms": 500}],
            "findings": [
                {"severity": "fail", "kind": "n_plus_1", "title": "calls grow"},
                {"severity": "warn", "kind": "chatty", "title": "one per element"}
            ],
            "next": ["appfuzz show r1 --view explanation"]
        });
        let plain = strip(&render(&PLAIN, "review", &out));
        assert!(plain.starts_with("[FAIL] chatty.wasm  appfuzz review\n       1 fail · 1 warn · 0 info · 12,345 runs in 2.0s\n"), "{plain}");
        assert!(plain.contains("  ✗ fail  n_plus_1  calls grow"), "{plain}");
        assert!(plain.contains("  ▲ warn  chatty    one per element"), "{plain}");
        assert!(plain.ends_with("\nNext\n  › appfuzz show r1 --view explanation\n"), "{plain}");
    }

    #[test]
    fn an_explanation_shows_input_calls_and_what_was_unusual() {
        let out = json!({
            "run": "r1", "outcome": "ok", "message": null, "status": 200, "text": "alpha",
            "input_vs_default": [{"path": "[0].query", "before": [], "after": [["days", "9"]]}],
            "calls": {"a#all": 1, "a#get": 128},
            "failed_calls": [{"n": 3, "func": "a#get"}],
            "vs_stored_runs": {"runs": 1883, "unusual": ["host_calls is 64.5× the median"]},
            "findings": [{"severity": "fail", "kind": "over_budget", "title": "129 cost"}],
            "next": ["appfuzz show r1 --view timeline"]
        });
        let plain = strip(&render(&PLAIN, "show", &out));
        for line in [
            "[OK] r1  appfuzz explain  · status 200\n",
            "  input     query = [[\"days\",\"9\"]]  (default [])\n",
            "  calls     128 × a#get, 1 × a#all\n",
            "  failed    #3 a#get\n",
            "  unusual   host_calls is 64.5× the median  (against 1,883 stored runs)\n",
            "  output    alpha\n",
            "  ✗ fail  over_budget  129 cost\n",
            "Next\n  › appfuzz show r1 --view timeline\n",
        ] {
            assert!(plain.contains(line), "{line:?} in\n{plain}");
        }
    }

    #[test]
    fn every_other_command_is_laid_out_from_its_json() {
        let runs: Vec<Value> = (0..20).map(|i| json!({"run": format!("r{i}"), "outcome": "ok", "host_calls": 2})).collect();
        let out = json!({
            "runs_used": 1884, "note": "a site is a call", "sites": [], "ok": true,
            "runs": runs, "totals": {"fuel": 1234567}, "next": ["appfuzz fuzz"]
        });
        let plain = strip(&render(&PLAIN, "unexplored", &out));
        for line in [
            "[UNEXPLORED]\n",
            "  runs used  1,884\n",
            "  sites      none\n",
            "  ok         yes\n",
            "  runs (20)\n",
            "    • run r0  outcome ok  host calls 2\n",
            "    … 8 more\n",
            "  totals\n    fuel  1,234,567\n",
            "Next\n  › appfuzz fuzz\n",
        ] {
            assert!(plain.contains(line), "{line:?} in\n{plain}");
        }
    }

    #[test]
    fn errors() {
        let e = strip(&render(&PLAIN, "run", &json!({"error": "no appfuzz.toml here", "examples": ["appfuzz run"]})));
        assert_eq!(e, "[ERROR] no appfuzz.toml here\n\nExamples\n  › appfuzz run\n");
    }

    #[test]
    fn the_flag_or_the_environment_asks_for_it() {
        assert!(wanted(true));
    }

    #[test]
    fn long_colored_lines_are_cut_and_reset() {
        assert_eq!(clip_visible("abcdef", 3), "abc…");
        assert_eq!(clip_visible("\x1b[2mabcdef\x1b[0m", 2), "\x1b[2mab…\x1b[0m");
        assert_eq!(clip_visible("ab", 3), "ab");
    }

    #[test]
    fn long_titles_wrap_under_themselves() {
        assert_eq!(wrap("aaa bbb ccc", 4, None), "aaa bbb ccc");
        let text = "one two three four five six seven eight nine ten eleven twelve";
        assert_eq!(wrap(text, 4, Some(40)), "one two three four five six seven\n    eight nine ten eleven twelve");
    }

    #[test]
    fn in_a_narrow_terminal_titles_go_under_the_kind() {
        let st = Style { color: false, cols: Some(50) };
        let out =
            json!({"findings": [{"severity": "fail", "kind": "slow_host_sensitivity", "title": "handle takes 321 ms (limit 200) when get answers in 20 ms"}]});
        let mut s = String::new();
        findings(&st, &out, &mut s);
        assert_eq!(s, "\n  ✗ fail  slow_host_sensitivity\n          handle takes 321 ms (limit 200) when\n          get answers in 20 ms\n");
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
