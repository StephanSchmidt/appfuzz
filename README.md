# appfuzz

No more code reviews. Fuzz instead.

appfuzz runs a WebAssembly app thousands of times against a simulated
backend and reports what a review would miss: crashes on empty lists and
Unicode, user input that reaches the HTML unescaped, loops that send one
database query per row. One command gives a verdict and an exit code for CI.

It never reads your source. It runs the compiled
[component](https://component-model.bytecodealliance.org/), so it works for
any language that builds one. It's tested with Rust, Zig, TypeScript and Python.

Website: https://appfuzz.dev

## Example

`bench/apps/chatty` lists items, then fetches each one again:

```rust
for it in items::all() {
    if let Ok(full) = items::get(it.id) {
        out += &format!("<li>{}</li>", esc(&full.owner));
    }
}
```

With a dozen rows in development this is fine. appfuzz grows the list the
simulated backend returns and counts the calls:

```
$ appfuzz review --time 10s
{
  "verdict": "fail",
  "exit_code": 2,
  "counts": { "fail": 2, "warn": 3, "info": 1, "confirmed": 5 },
  "coverage": { "fuzz_runs": 180488, "unreached_call_sites": 0 },
  "findings": [
    { "severity": "fail", "kind": "n_plus_1",
      "title": "calls to bench:web/items#get grow as 1·n with n = length of the list bench:web/items#all returns; cost breaks its limit at n = 100" },
    { "severity": "fail", "kind": "over_budget",
      "title": "bench:web/handler#handle uses 129 cost, the limit is 100" },
    …
  ],
  "next": [ "appfuzz explain rff6825faed", "appfuzz findings --min info" ]
}
```

Output shortened. The same loop written in Zig, TypeScript and Python gets the
same findings (`bench/lang`).

## Install

On Linux or macOS (x86_64 or arm64):

```sh
curl -fsSL https://appfuzz.dev/install.sh | sh
```

The script ([website/install.sh](website/install.sh)) downloads the binary
from the latest [GitHub release](https://github.com/StephanSchmidt/appfuzz/releases),
checks its SHA-256 and puts it in `~/.local/bin`. Set `APPFUZZ_VERSION=v0.1.0`
for a specific release or `APPFUZZ_INSTALL_DIR` for another directory.

Or build it with Rust:

```sh
cargo install --git https://github.com/StephanSchmidt/appfuzz appfuzz
```

Then, next to your component:

```sh
appfuzz --wasm my_app.wasm inspect    # exports, imports, static findings
appfuzz --wasm my_app.wasm review     # everything; exit code 0 pass, 1 warn, 2 fail
```

`appfuzz` without arguments prints a guide with what to run next.
`appfuzz <command> --help` shows examples.

## What it finds

- **Crashes:** panics, traps, hangs, stack overflows, including on odd
  values the backend returns (empty lists, errors, 3-byte characters, leap
  days).
- **Security:** request fields and stored data in HTML output unescaped,
  internal error text shown to users, imports the platform didn't grant.
  With labels: SQL, shell, path and HTML injection, SSRF, and leaked secrets
  or personal data.
- **Output rules:** with output labels, scripts in markup that must have
  none, widgets that call routes by themselves, open redirects.
- **Access:** with identity labels, user ids taken from the request and
  other users' records shown in a page.
- **Writes:** with effect labels, changes on GET requests, the same write
  twice, retried writes, one write per row, and a write that stays when a
  later one fails.
- **Database:** n+1 queries, loops inside loops, calls that grow with a
  request field, repeated identical calls, retry storms.
- **Wrong answers:** results that change with row order or duplicates,
  values outside their range, swallowed errors, error pages with status 200.
- **Performance:** fuel, memory, cost and latency against your limits, and
  CPU, memory or output that grows faster than the input.

Every finding is replayed, shrunk to a small input and saved as a case file
you can rerun. Runs are deterministic: time and the backend are simulated,
so a 10-second timeout costs nothing and the same input gives the same
result.

## How it works

1. **A manifest** (`appfuzz.toml`) says which export handles requests, what
   the app may import, and your limits, such as 100 host calls per request.
   It's optional, since `--wasm` alone works.
2. **Host functions are simulated.** Each import answers with values
   generated from its WIT types, which the fuzzer varies. A JSON host plan
   scripts realistic data when you need it (`appfuzz plan template`).
3. **Detectors run on every run:** call patterns, growth laws, output checks,
   data flow from request and backend to output.
4. **Labels** say what text means: this parameter is SQL, this field is an
   email address, this result is a secret.

   ```toml
   [functions."acme:web/db#query"]
   params = { sql = "sql" }

   [functions."acme:web/users#current"]
   result = { email = "pii" }
   ```

   Request and backend text that reaches the SQL with its quote intact is
   `sql_injection`. An email address in the log is `pii_leak`. `inspect`
   suggests labels from the WIT names.
5. **`check`** turns your own suspicion ("usage never exceeds 100") into a
   search for a counterexample.

Every command prints one JSON document with a `next` field, so an AI agent
can drive it. [AGENTS.md](AGENTS.md) is the guide for that, and it's a good
reference for people too.

## Limits

- A pass means the search found nothing. That's evidence, not proof.
- Each run is one request, and the simulated backend keeps no state between
  requests, so double submits are out of reach.
- It doesn't know what your host functions mean until labels tell it
  ([LABELS.md](LABELS.md)).
- It doesn't look for malicious behaviour. A clean review doesn't mean an
  app is benign.
- For interpreted languages (componentize-js, componentize-py), coverage
  guidance sees the interpreter, not your script, and runs are slower.

## Repository

| Path | What |
|------|------|
| `crates/appfuzz-core` | engine: harness, simulated host, fuzzer, detectors |
| `crates/appfuzz` | the CLI |
| `bench/apps` | 37 small apps, each with one bad pattern (or none) and its expected findings |
| `bench/lang` | the same app in Zig, TypeScript and Python |
| `website` | appfuzz.dev and its `install.sh` |

`cargo test` runs the unit tests. The bench builds every app in
`bench/apps` and checks that `review` finds exactly the expected findings:

```sh
rustup target add wasm32-wasip2
cargo test --release -p appfuzz --test bench -- --ignored bench --nocapture
```

## License

MIT, see [LICENSE](LICENSE).
