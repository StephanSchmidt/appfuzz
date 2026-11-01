#!/usr/bin/env python3
"""Writes the bench apps (apps/<name>/{Cargo.toml,src/lib.rs,appfuzz.toml,expected.json}).

Each app has one bad pattern. `expected.json`:
  expect: findings that must show ({kind, min severity})
  allow:  other kinds that may show at warn/fail (side effects of the bug)
Any other warn or fail finding fails the bench (a false positive).

Run it after editing an app here; the generated files are checked in.
"""
import json
import os
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))

ITEMS, STORE, MAIL = "bench:web/items", "bench:web/store", "bench:web/mail"

APPS = []


def app(name, what, code, expect, allow=(), grants=(ITEMS,), extra="", fuel="200_000_000", pending=None):
    APPS.append(dict(name=name, what=what, code=code, expect=expect, allow=list(allow), grants=list(grants), extra=extra, fuel=fuel, pending=pending))


def handler(body, prelude="prelude.rs"):
    return f"include!(\"../../../{prelude}\");" + "\n\nimpl exports::bench::web::handler::Guest for A {\n    fn handle(req: Request) -> Response {\n" + textwrap.indent(textwrap.dedent(body).strip("\n"), " " * 8) + "\n    }\n}\n"


# --- Crash -----------------------------------------------------------------

app("empty-panic", "indexes the first item without checking for an empty list",
    handler("""
        let _ = &req;
        let all = items::all();
        let first = &all[0];
        html(format!("<p>First: {}</p>", esc(&first.name)))
    """), [("crash", "fail")], allow=["crash_on_host_value"])

app("utf8-slice", "cuts names at byte 8, which panics inside a multi-byte character",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            let short = if it.name.len() > 8 { &it.name[..8] } else { it.name.as_str() };
            out += &format!("<li>{}</li>", esc(short));
        }
        html(out + "</ul>")
    """), [("crash", "fail")], allow=["crash_on_host_value", "n_plus_1"])

app("err-unwrap", "unwraps the host's result",
    handler("""
        let id: u64 = param(&req.query, "id").and_then(|v| v.parse().ok()).unwrap_or(1);
        let it = items::get(id).unwrap();
        html(format!("<h1>{}</h1>", esc(&it.name)))
    """), [("crash", "fail")], allow=["crash_on_host_value"])

app("deep-recursion", "nests one element per level of ?depth, recursively",
    handler("""
        fn nest(n: u64) -> String {
            if n == 0 { String::new() } else { format!("<div>{}</div>", nest(n - 1)) }
        }
        let depth: u64 = param(&req.query, "depth").and_then(|v| v.parse().ok()).unwrap_or(3);
        html(nest(depth))
    """), [("stack_overflow", "fail")], allow=["hang", "over_budget", "big_output", "cpu_blowup", "memory_blowup", "output_amplification", "input_amplification", "crash"])

# --- Scaling ---------------------------------------------------------------

app("quadratic-200", "compares every item with every other item",
    handler("""
        let _ = &req;
        let all = items::all();
        let mut similar = 0u32;
        for a in &all {
            for b in &all {
                if a.id != b.id && a.name.chars().zip(b.name.chars()).filter(|(x, y)| x == y).count() > 2 {
                    similar += 1;
                }
            }
        }
        html(format!("<p>{} items, {similar} similar pairs</p>", all.len()))
    """), [("cpu_blowup", "warn")], allow=["hang", "over_budget"], fuel="20_000_000")

# --- Amplification ---------------------------------------------------------

app("days-param", "reads one day per ?days, unbounded",
    handler("""
        let days: u32 = param(&req.query, "days").and_then(|v| v.parse().ok()).unwrap_or(1);
        let mut total = 0;
        for d in 0..days {
            total += items::for_day(&format!("{}+{d}", req.today)).len();
        }
        html(format!("<p>{total} entries in {days} days</p>"))
    """), [("input_amplification", "fail")], allow=["over_budget", "serial_chain", "hang", "slow_host_sensitivity"])

app("form-fanout", "saves one record per `count` in a posted form",
    handler("""
        if req.method == "POST" && req.path == "/add" {
            let count: u32 = param(&req.form, "count").and_then(|v| v.parse().ok()).unwrap_or(1);
            let name = param(&req.form, "name").unwrap_or("item");
            for i in 0..count {
                let _ = store::save(&format!("{name}-{i}"), name);
            }
            return Response { status: 303, body: String::new(), headers: vec![("location".into(), "/".into())] };
        }
        html(r#"<form method="post" action="/add"><input name="name" value="box"><input name="count" value="1"><button>Add</button></form>"#.into())
    """), [("input_amplification", "fail")], allow=["over_budget", "serial_chain", "hang", "slow_host_sensitivity"], grants=[STORE])

app("nested-fanout", "reads every child of every item, one by one",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            for c in items::children(it.id) {
                if let Ok(full) = items::get(c.id) {
                    out += &format!("<li>{}: {}</li>", esc(&it.name), esc(&full.name));
                }
            }
        }
        html(out + "</ul>")
    """), [("nested_fan_out", "warn")], allow=["n_plus_1", "chatty", "retry_storm", "over_budget", "hang", "big_output", "serial_chain", "slow_host_sensitivity", "redundant_calls", "cpu_blowup", "output_amplification"])

app("retry-storm", "retries a failing save fifty times",
    handler("""
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
    """), [("retry_storm", "warn")], allow=["redundant_calls", "over_budget", "serial_chain", "slow_host_sensitivity"], grants=[STORE])

# --- Calls -----------------------------------------------------------------

app("redundant", "loads the same setting once per item",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            let unit = store::load("unit").unwrap_or_default();
            out += &format!("<li>{} {}</li>", it.score, esc(&unit));
        }
        html(out + "</ul>")
    """), [("redundant_calls", "warn")], allow=["n_plus_1", "over_budget", "serial_chain", "slow_host_sensitivity"], grants=[ITEMS, STORE])

app("chatty", "lists all items, then fetches each one again",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            if let Ok(full) = items::get(it.id) {
                out += &format!("<li>{}</li>", esc(&full.owner));
            }
        }
        html(out + "</ul>")
    """), [("chatty", "warn")], allow=["n_plus_1", "redundant_calls", "over_budget", "serial_chain", "slow_host_sensitivity"])

# --- Time and budget -------------------------------------------------------

app("loop-on-input", "steps towards 100 by ?step, forever when it is 0 or negative",
    handler("""
        let step: i64 = param(&req.query, "step").and_then(|v| v.parse().ok()).unwrap_or(10);
        let mut i: i64 = 0;
        let mut n = 0u64;
        while i < 100 {
            i = i.wrapping_add(step);
            n += 1;
        }
        html(format!("<p>{n} steps</p>"))
    """), [("hang", "fail")], allow=["over_budget"], grants=[])

app("big-output", "renders ?rows rows, up to a million",
    handler("""
        let rows: usize = param(&req.query, "rows").and_then(|v| v.parse().ok()).unwrap_or(10).min(1_000_000);
        let mut out = String::from("<table>");
        for i in 0..rows {
            out += &format!("<tr><td>row {i}</td><td>some padding text here</td></tr>");
        }
        html(out + "</table>")
    """), [("big_output", "warn")], allow=["input_amplification", "output_amplification", "over_budget", "hang", "cpu_blowup"], grants=[])

app("slow-chain", "fetches 40 items one after another, each a slow call",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for id in 1..=40u64 {
            if let Ok(it) = items::get(id) {
                out += &format!("<li>{}</li>", esc(&it.name));
            }
        }
        html(out + "</ul>")
    """), [("serial_chain", "warn")], allow=["slow_host_sensitivity", "over_budget"],
    extra='\n[functions."bench:web/items#get"]\nlatency_ms = 4.0\n')

app("busy-wait", "spins on the clock for 50 ms instead of sleeping",
    handler("""
        let _ = &req;
        let start = std::time::Instant::now();
        let mut spins = 0u64;
        while start.elapsed() < std::time::Duration::from_millis(50) {
            spins += 1;
        }
        html(format!("<p>waited ({spins} spins)</p>"))
    """), [("busy_wait", "warn")], allow=["over_budget"], grants=[])

# --- Consistency -----------------------------------------------------------

app("nondet", "lists owners in hash-map order",
    handler("""
        let _ = &req;
        let mut by_owner = std::collections::HashMap::new();
        for it in items::all() {
            *by_owner.entry(it.owner).or_insert(0u32) += 1;
        }
        let mut out = String::from("<ul>");
        for (owner, n) in by_owner {
            out += &format!("<li>{}: {n}</li>", esc(&owner));
        }
        html(out + "</ul>")
    """), [("nondeterminism", "info")])

app("order-dependent", "calls the first item the top one without sorting",
    handler("""
        let _ = &req;
        let all = items::all();
        match all.first() {
            Some(top) => html(format!("<p>Top: {} ({} points)</p>", esc(&top.name), top.score)),
            None => html("<p>No items</p>".into()),
        }
    """), [("order_dependence", "info")])

app("duplicate-400", "counts list entries against distinct ids, so a duplicate passes 100 %",
    handler("""
        let _ = &req;
        let all = items::all();
        let distinct: std::collections::BTreeSet<u64> = all.iter().map(|i| i.id).collect();
        let pct = all.len() * 100 / distinct.len().max(1);
        html(format!("<p class=\\"usage\\">{pct}%</p>"))
    """), [("duplicate_sensitivity", "warn")])

# --- Output ----------------------------------------------------------------

app("bad-status", "passes ?code through as the HTTP status",
    handler("""
        let status: u16 = param(&req.query, "code").and_then(|v| v.parse().ok()).unwrap_or(200);
        Response { status, body: "<p>ok</p>".into(), headers: vec![] }
    """), [("invalid_response", "fail")], grants=[])

app("broken-markup", "leaves <b> open for hot items",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            if it.score > 100 {
                out += &format!("<li><b>{}</li>", esc(&it.name));
            } else {
                out += &format!("<li>{}</li>", esc(&it.name));
            }
        }
        html(out + "</ul>")
    """), [("broken_markup", "warn")])

app("panic-in-body", "shows the host's error text, with internal details, to the user",
    handler("""
        let id: u64 = param(&req.query, "id").and_then(|v| v.parse().ok()).unwrap_or(1);
        match items::get(id) {
            Ok(it) => html(format!("<h1>{}</h1>", esc(&it.name))),
            Err(e) => Response { status: 500, body: format!("<pre>items.get({id}) failed in shard 7: {}</pre>", esc(&e)), headers: vec![] },
        }
    """), [("leaky_error", "warn")])

app("reflect-query", "echoes ?q into the page unescaped",
    handler("""
        let q = param(&req.query, "q").unwrap_or("");
        html(format!("<p>Results for {q}</p>"))
    """), [("reflection", "fail")], grants=[])

app("reflect-host", "renders item names from the host unescaped",
    handler("""
        let _ = &req;
        let mut out = String::from("<ul>");
        for it in items::all() {
            out += &format!("<li>{}</li>", it.name);
        }
        html(out + "</ul>")
    """), [("stored_reflection", "fail")], allow=["broken_markup"])

# --- Grants ----------------------------------------------------------------

app("over-granted", "is granted the store but never uses it",
    handler("""
        let _ = &req;
        html(format!("<p>{} items</p>", items::all().len()))
    """), [("unused_grant", "info")], grants=[ITEMS, STORE])

app("forgot-grant", "sends mail without a grant for it",
    handler("""
        let _ = &req;
        let n = items::all().len();
        let _ = mail::send("ops@example.com", &format!("{n} items"));
        html(format!("<p>{n} items</p>"))
    """), [("ungranted_import", "fail")], allow=["ungranted_call"])

# --- Control ---------------------------------------------------------------

app("clean", "a well-behaved page: one read, sorted, escaped, bounded",
    handler("""
        let mut all = items::all();
        all.sort_by(|a, b| b.score.cmp(&a.score).then(a.id.cmp(&b.id)));
        let q = param(&req.query, "q").unwrap_or("");
        let mut out = format!("<h1>Items matching {}</h1><ul>", esc(q));
        for it in all.iter().filter(|i| i.name.contains(q)).take(20) {
            out += &format!("<li>{} ({})</li>", esc(&it.name), it.score);
        }
        html(out + "</ul>")
    """), [])


# --- Labels ----------------------------------------------------------------
# These apps use the `labelled-app` world; their manifests label parameters
# (sinks) and results (personal data, secrets, trusted HTML).

DB, FILES, HTTP, SYS, CONFIG, USERS = (f"bench:web/{i}" for i in ("db", "files", "http", "sys", "config", "users"))

LABELS = """
[functions."bench:web/db#query"]
params = { sql = "sql" }

[functions."bench:web/files#read"]
params = { path = "path" }

[functions."bench:web/http#fetch"]
params = { url = "url", auth = "secret" }

[functions."bench:web/sys#run"]
params = { cmd = "shell" }

[functions."bench:web/config#secret"]
result = "secret"

[functions."bench:web/users#current"]
result = { email = "pii", bio-html = "html" }
"""


def labelled(body):
    return handler(body, prelude="prelude-labelled.rs")


app("sql-concat", "puts ?q into SQL text",
    labelled("""
        let q = param(&req.query, "q").unwrap_or("");
        let rows = db::query(&format!("SELECT name FROM items WHERE name = '{q}'"), &[]).unwrap_or_default();
        html(format!("<p>{} rows</p>", rows.len()))
    """), [("sql_injection", "fail")], grants=[DB], extra=LABELS)

app("sql-hand-escaped", "doubles the quotes in ?q, then puts it into SQL text",
    labelled("""
        let q = param(&req.query, "q").unwrap_or("").replace('\\'', "''");
        let rows = db::query(&format!("SELECT name FROM items WHERE name = '{q}'"), &[]).unwrap_or_default();
        html(format!("<p>{} rows</p>", rows.len()))
    """), [("escaped_by_hand", "warn")], grants=[DB], extra=LABELS)

app("stored-sql", "puts the user's name from the host into SQL text",
    labelled("""
        let _ = &req;
        let u = users::current();
        let rows = db::query(&format!("SELECT * FROM orders WHERE owner = '{}'", u.name), &[]).unwrap_or_default();
        html(format!("<p>{} orders for {}</p>", rows.len(), esc(&u.name)))
    """), [("sql_injection", "fail")], grants=[DB, USERS], extra=LABELS)

app("path-traversal", "reads the file named by ?doc",
    labelled("""
        let doc = param(&req.query, "doc").unwrap_or("index");
        let text = files::read(&format!("docs/{doc}.md")).unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    """), [("path_traversal", "fail")], grants=[FILES], extra=LABELS)

app("ssrf-url", "fetches the URL in ?feed",
    labelled("""
        let feed = param(&req.query, "feed").unwrap_or("https://example.com/feed");
        let text = http::fetch(feed, "").unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    """), [("ssrf", "fail")], grants=[HTTP], extra=LABELS)

app("shell-concat", "greps the log for ?q in a shell command",
    labelled("""
        let q = param(&req.query, "q").unwrap_or("error");
        let out = sys::run(&format!("grep {q} /var/log/app.log")).unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&out)))
    """), [("command_injection", "fail")], grants=[SYS], extra=LABELS)

app("secret-in-page", "prints the API key in a debug footer",
    labelled("""
        let _ = &req;
        let key = config::secret("api-key");
        html(format!("<p>Hello</p><footer>debug: key={}</footer>", esc(&key)))
    """), [("secret_leak", "fail")], grants=[CONFIG], extra=LABELS)

app("secret-in-url", "sends the API key in the URL instead of the auth parameter",
    labelled("""
        let _ = &req;
        let key = config::secret("api-key");
        let text = http::fetch(&format!("https://api.example.com/v1/items?key={key}"), "").unwrap_or_default();
        html(format!("<pre>{}</pre>", esc(&text)))
    """), [("secret_leak", "fail")], grants=[CONFIG, HTTP], extra=LABELS)

app("pii-in-log", "logs the user's email address",
    labelled("""
        let _ = &req;
        let u = users::current();
        println!("page view by {}", u.email);
        html(format!("<p>Hello {}</p>", esc(&u.name)))
    """), [("pii_leak", "fail")], grants=[USERS], extra=LABELS)

app("sql-params", "passes ?q as a query parameter, not in the SQL text",
    labelled("""
        let q = param(&req.query, "q").unwrap_or("");
        let rows = db::query("SELECT name FROM items WHERE name = ?", &[q.to_string()]).unwrap_or_default();
        html(format!("<p>{} rows for {}</p>", rows.len(), esc(q)))
    """), [], grants=[DB], extra=LABELS)

app("trusted-html", "renders the user's bio-html as is (labelled trusted) and the email in the page",
    labelled("""
        let _ = &req;
        let u = users::current();
        let key = config::secret("api-key");
        let _ = http::fetch("https://api.example.com/v1/me", &key);
        html(format!("<h1>{}</h1><p>{}</p><div>{}</div><p>{}</p>", esc(&u.name), esc(&u.email), u.bio_html, esc(&u.bio)))
    """), [], grants=[USERS, CONFIG, HTTP], extra=LABELS)


MANIFEST = """\
# appfuzz bench app: {name} ({what}).
[app]
wasm = "../../target/wasm32-wasip2/release/{crate}.wasm"
name = "{name}"

[entry]
export = "bench:web/handler#handle"
request = {{ method = "GET", path = "/", query = [], form = [], today = "", now = "" }}
fields = {{ today = "clock.date", now = "clock.time" }}
output = {{ status = "status", body = "body", headers = "headers", body_format = "html" }}
now = "2026-11-02T10:00:00"

[grants]
imports = [{grants}]
wasi = ["wasi:cli", "wasi:clocks", "wasi:io", "wasi:random"]

[limits]
fuel = {fuel}
memory = "64MiB"
cost_per_request = 100
max_latency_ms = 200
{extra}"""

CARGO = """\
[package]
name = "{crate}"
version = "0.1.0"
edition = "2024"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen.workspace = true
"""


def main():
    for a in APPS:
        d = os.path.join(HERE, "apps", a["name"])
        os.makedirs(os.path.join(d, "src"), exist_ok=True)
        crate = a["name"].replace("-", "_")
        with open(os.path.join(d, "Cargo.toml"), "w") as f:
            f.write(CARGO.format(crate=crate))
        with open(os.path.join(d, "src", "lib.rs"), "w") as f:
            f.write(f"//! Bench app `{a['name']}`: {a['what']}.\n\n" + a["code"])
        with open(os.path.join(d, "appfuzz.toml"), "w") as f:
            f.write(MANIFEST.format(name=a["name"], what=a["what"], crate=crate, fuel=a["fuel"], extra=a["extra"],
                                    grants=", ".join(f'"{g}"' for g in a["grants"])))
        exp = {"app": a["name"], "bug": a["what"], "expect": [{"kind": k, "min": s} for k, s in a["expect"]], "allow": a["allow"]}
        if a["pending"]:
            exp["pending"] = a["pending"]
        with open(os.path.join(d, "expected.json"), "w") as f:
            f.write(json.dumps(exp, indent=2) + "\n")
    print(len(APPS), "apps")


main()
