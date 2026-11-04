# appfuzz

No more code reviews. Fuzz instead.

Agents write code faster than anyone can review it, and soon not only
engineers will ask them to. Reading every diff doesn't scale; running the
code does. appfuzz runs your WebAssembly app thousands of times against a
simulated backend and reports what a reviewer would miss: a crash on an
empty list, user input in the HTML unescaped, one database query per row,
a call to a server nobody approved. One command gives a verdict and an exit
code for CI.

It tests what you deploy, not your source:

- **WebAssembly components**, in any language that builds one. Tested with
  Rust, Zig, TypeScript, JavaScript, Go (TinyGo), C# and Python.
- **Fastly Compute apps** (wasm32-wasip1 modules).
- **[Extism](https://extism.org/) plugins**, from any PDK.

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
  "coverage": { "unreached_call_sites": 0 },
  "findings": [
    { "severity": "fail", "kind": "n_plus_1",
      "title": "calls to bench:web/items#get grow as 1·n with n = length of the list bench:web/items#all returns; cost breaks its limit at n = 100" },
    { "severity": "fail", "kind": "over_budget",
      "title": "bench:web/handler#handle uses 129 cost, the limit is 100" },
    …
  ],
  "next": [ "appfuzz show rff6825faed --view explanation", "appfuzz findings --min info" ]
}
```

Output shortened. The same loop written in Zig, TypeScript, JavaScript, Go,
C# and Python gets the same findings (`bench/lang`).

## Install

On Linux or macOS (x86_64 or arm64):

```sh
curl -fsSL https://appfuzz.dev/install.sh | sh
```

The script ([website/install.sh](website/install.sh)) downloads the binary
from the latest [GitHub release](https://github.com/StephanSchmidt/appfuzz/releases),
checks its SHA-256 and puts it in `~/.local/bin`. Set `APPFUZZ_VERSION=v0.4.0`
for a specific release or `APPFUZZ_INSTALL_DIR` for another directory.

Or with Homebrew: `brew install stephanschmidt/appfuzz/appfuzz`

Or build it with Rust:

```sh
cargo install --git https://github.com/StephanSchmidt/appfuzz appfuzz
```

## Quick start

A component needs nothing else:

```sh
appfuzz --wasm my_app.wasm inspect    # what it exports and imports, first findings
appfuzz --wasm my_app.wasm run        # one request: does it work at all?
appfuzz --wasm my_app.wasm review     # the full review, with a verdict
```

A Fastly app needs a two-line `appfuzz.toml`, then the same commands without
`--wasm`:

```toml
[app]
wasm = "target/wasm32-wasip1/release/my_app.wasm"
platform = "fastly"
```

An Extism plugin needs a platform file that types its JSON; see
[Extism plugins](#extism-plugins).

`appfuzz` without arguments tells you what to run next.
`appfuzz <command> --help` shows examples.

## In CI

```sh
appfuzz review --time 2m
```

| Exit code | Means |
|---|---|
| 0 | pass |
| 1 | warnings |
| 2 | failures |
| 3 | incomplete, or a tool or configuration error: never a pass |

`--time` is the fuzzing budget; probes and confirming findings come on top.
Repeated reviews of the same build re-test every failure found before, so a
bug that was found once doesn't slip through on a later run. For
reproducible search, run `appfuzz -j 1 review --fresh --search-seed 7 --runs 2000`.
Details: [REFERENCE.md](REFERENCE.md#review-budgets-and-exit-codes).

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
- **Performance:** CPU, memory, cost and latency against your limits, and
  CPU, memory or output that grows faster than the input.

Every finding comes with the request and backend answers that cause it.
Time is simulated, so a backend that takes 200 ms or a timeout of ten
minutes costs nothing real, and the same input always gives the same run.

## Digging into a finding

```sh
appfuzz show last --view explanation         # what happened, in plain terms
appfuzz show last --view calls --fn items    # the host calls it made
appfuzz show last --view provenance --call 3 # where call 3's argument came from
appfuzz confirm <finding-id>                 # shrink it, save a case file
appfuzz replay path/to/case.json --against-current   # is it fixed?
```

`confirm` cuts a finding down to the smallest input that still shows it, for
example the shortest list that still breaks the limit, and saves it as a
case file. Replay that file in your tests.

More tools for a suspicion of your own:

| Question | Command |
|---|---|
| Does it grow with a list or a field? | `scale`, `amplify` |
| What changes with this field? | `sweep -f query.days` |
| Can this number go past 100? | `check value_range .usage 0 100` |
| Why do these two runs differ? | `diff <a> <b>` |
| Which code did no run reach? | `unexplored` |
| Which URLs does the page load? | `urls` |
| Where does the CPU go? | `show <run> --view fuel`, `wasm` |

`check` fuzzes until a run breaks your property and shrinks that run to a
counterexample. [AGENTS.md](AGENTS.md) walks through all of this. It's
written for AI agents driving appfuzz, and is a good guide for people too.

## Telling appfuzz about your app

Without any configuration, every host function answers with values generated
from its types, and the fuzzer varies them. That finds crashes, n+1 queries
and unescaped output. To find more, tell appfuzz what your platform knows.

**The manifest** (`appfuzz.toml`) says which export handles requests, what
the app may import, and your production limits:

```toml
[app]
wasm = "target/wasm32-wasip2/release/my_app.wasm"

[grants]
imports = ["acme:web/items", "acme:web/store"]

[limits]
memory = "64MiB"
cost_per_request = 100       # host call cost units per request
max_latency_ms = 200
```

**Host plans** script realistic backend data when you need it:

```sh
appfuzz plan template > plan.json     # every host function with an example
appfuzz review --plan plan.json
```

**Labels** say what text means: this parameter is SQL, this field is an
email address, this function writes.

```toml
[functions."acme:web/db#query"]
params = { sql = "sql" }

[functions."acme:web/users#current"]
result = { email = "pii" }

[functions."acme:web/store#save"]
effect = "write"
```

Now request text that reaches the SQL with its quote intact is
`sql_injection`, an email address in the log is `pii_leak`, and a save on a
GET request is `write_on_safe_method`. `inspect` suggests labels from the
function names; keep only what's true. [LABELS.md](LABELS.md) has the full
vocabulary.

## Search inside the compiled Wasm

appfuzz tries the numbers and strings it finds in the binary. For checks it
can't see that way, such as checksums, computed values or byte-by-byte
parsers, add `--internal-feedback` to `fuzz` or `review`. It runs an
instrumented copy alongside and steers toward comparisons that almost match.
It needs no source changes or special build, but runs about 2.5 times fewer
inputs a second, so it's off by default. Findings always come from the
original binary. Details: [REFERENCE.md](REFERENCE.md#search-inside-the-compiled-wasm).

## Structured payload search

When a request field or a backend answer holds JSON or CSV, appfuzz mutates
inside it and keeps it valid, so the input gets past your parser to the
code behind it. Put one valid example in the request or the host plan;
there's nothing else to configure. Details:
[REFERENCE.md](REFERENCE.md#structured-payload-search).

## Host failure sweeps

What happens when the third database call fails, or when the database stays
down? The fuzzer walks successful runs and fails each host call in turn,
once and as an outage, then reports crashes, endless retries and writes left
half done. For one run:

```sh
appfuzz probe faults last --runs 256
```

A host plan can script an outage from the third call on:

```json
{"acme:web/store#save": {"on_call": {"3+": {"generate": {"results": "err"}}}}}
```

Details: [REFERENCE.md](REFERENCE.md#host-failure-sweeps).

## Declared value contracts

Say what your platform's functions accept, and appfuzz flags every call the
app makes outside it: a date that isn't a date, 9 seats when 6 is the
maximum.

```toml
[functions."acme:web/bookings#create"]
param_values = { date = "format:date", seats = "range:1..6" }
```

The same works for what your app accepts from users (`[entry] input_values`),
so an acceptance check can say "an invalid date gets a 400 and writes
nothing". Details: [REFERENCE.md](REFERENCE.md#declared-value-contracts).

## Coherent host datasets

Generated data is random: an order can belong to a customer that doesn't
exist, and your app then shows an error page no user will ever see.
Datasets declare collections with keys and references, so list, lookup and
filter functions agree:

```toml
[datasets.customers]
rows = 4
key = "id"
template = { id = 1, name = "Customer" }

[datasets.orders]
rows = 12
key = "id"
template = { id = 1, customer-id = 1 }
references = { customer-id = "customers" }

[functions."acme:web/orders#by-customer"]
query = { dataset = "orders", filter = { customer-id = "customer-id" }, wrap = "ok" }
```

Fuzzing, scaling and shrinking keep the relationships intact. Details:
[REFERENCE.md](REFERENCE.md#coherent-host-datasets).

## Saved acceptance checks

Write down what a right answer is, in the manifest, and every review checks
it against thousands of inputs:

```toml
[acceptance]
version = 1

[acceptance.checks.home]
origin = "marketing"
request = { method = "GET", path = "/", query = [], form = [], today = "2026-11-02", now = "08:00:00" }
expect = { selector = "$.status", equals = 200 }
```

`origin` says who owns the requirement: `marketing` for what the feature
must do, `platform` for a platform rule. Run them on their own with
`appfuzz acceptance run`.

### Asserting outputs against inputs

An assert relates the output to what went in, the request and what the
backend returned:

```toml
[acceptance.checks.total]
origin = "marketing"
description = "The total is the sum of the line items"
let = { total = "out.json.total", prices = "host.items#all.result" }
assert = "total == sum(prices.map(i, i.price))"
```

Expressions are [CEL](https://cel.dev). The fuzzer steers toward breaking
each assert, and warns when one holds no matter what (`weak_assert`): an
assert like that tests nothing. Try an expression on a stored run before
you save it:

```sh
appfuzz bindings --run last
appfuzz eval last 'size(rows)' --let rows='select .row'
```

Details: [REFERENCE.md](REFERENCE.md#saved-acceptance-checks).

## Request sequences

Some bugs need more than one request: a double booking, or a retry after a
lost response. A sequence runs requests against one shared simulated
backend and checks rules such as "no two bookings for one slot" after each
request. `sequence fuzz` tries repetitions and other orders:

```sh
appfuzz sequence run scenario.json
appfuzz sequence fuzz scenario.json --runs 100
```

Put a scenario under `[sequences.NAME]` in the manifest and `review` runs it
too. Details: [REFERENCE.md](REFERENCE.md#request-sequences).

## Platforms: components, witx and Extism

| Your app | Where the types come from | What you write |
|----------|---------------------------|----------------|
| **Component** (wasm32-wasip2, jco, componentize-*) | the WIT inside it | nothing |
| **Fastly Compute app** (wasm32-wasip1) | Fastly's witx, bundled | `platform = "fastly"` |
| **Module on another witx platform** | your platform's witx | a `platform.toml` |
| **Extism plugin** (any PDK) | a WIT file you supply | a `platform.toml` with `abi = "extism"` |

A plain module only names the host functions it calls, not what they take
and return, so appfuzz needs its platform. `appfuzz platform docs` prints
that platform's host API, with signatures and descriptions, as a reference
for whoever writes apps for it.

### Fastly Compute

```toml
[app]
wasm = "target/wasm32-wasip1/release/my_app.wasm"
platform = "fastly"
```

That's all. A run is one client request (method, URL, headers, body) and
the response your app sends downstream. Backend requests are simulated, so
you can script what a backend answers or make it fail. Fastly's limits apply:
128 MiB of memory and 50 ms of CPU.

[demos/fastly-hello](demos/fastly-hello) is Fastly's own Rust starter kit.
`review` fails it: the welcome page loads a frame and an icon from
developer.fastly.com, a host nobody approved.

### Your own witx platform

If your platform runs plain modules with witx-described host functions,
write a `platform.toml` for it: the witx files, the start export, what a
request and a response look like, and a description per function. The
bundled [Fastly platform.toml](crates/appfuzz-core/platforms/fastly/platform.toml)
is the worked example. `appfuzz platform check` lists what's missing.

### Extism plugins

An Extism plugin passes JSON, which says nothing about its shape. A WIT file
describes it: each WIT import is a host function your product offers, and
each WIT export is a plugin function, reviewed with `review --export NAME`.

```toml
# platform.toml
[platform]
name = "acme-plugins"
abi = "extism"
wit = "wit"                 # one world per kind of plugin, chosen with [app] world

[platform.json]             # how your JSON spells field names
fields = "snake"            # default; also kebab, camel, pascal, lower, screaming
cases = "pascal"            # enum and variant cases (serde's default)
err = "error"               # results as {"ok": …} / {"error": …}
```

Names match ignoring case, `-` and `_`, and missing fields take their empty
value, the way `#[serde(default)]` reads JSON. A plain `string` argument or
result crosses as raw bytes, like the PDK's `String`. Kernel logs show up in
the run's `stderr`.

## Where it fits: AppOS

appfuzz is the review step of [AppOS](https://appfuzz.dev/appos/), an
architecture for web apps that people outside engineering build with
agents. The site is a shell run by the platform team, and every feature is
an app: a WebAssembly component the shell runs in a sandbox. It works like a
phone: the sandbox limits what an app can reach, its manifest grants
permissions, and a review decides what goes live. Marketing writes down what
a feature must do; engineering owns the platform contract and its budgets;
appfuzz checks every app against both, so no engineer has to approve each
one.

The shell writes each app's `appfuzz.toml`, because only the platform knows
what its host functions cost, which ones change data, and which business
rules they keep. An app can't loosen its own review.

[Roomer](https://github.com/StephanSchmidt/roomer-appos) is the full demo: a
pod-booking site with four apps, a `make` that reviews them, and a shell
that refuses a version that fails. Its README has an exercise: an agent
adds a feature, and the review refuses it.

## Limits

- A pass means the search found nothing. That's evidence, not proof.
- It doesn't know what your host functions mean until labels tell it
  ([LABELS.md](LABELS.md)).
- Requests run one at a time. Sequences share backend state between them,
  but concurrent requests and live services are out of reach.
- Not yet supported: HTTP handlers on `wasi:http` (Spin, wasmCloud,
  `wasmtime serve`), outbound HTTP from Extism plugins, Proxy-Wasm filters
  and browser Wasm. `wasi:http` comes next.
- Detecting hostile apps (hidden text, notes to the reviewer, data in
  disguise, time bombs) and runtime envelopes are **experimental**. A pass
  doesn't prove an app is benign.
- For interpreted languages (Python, JavaScript), stacks and
  `--internal-feedback` show the interpreter more than your code.

## Repository

| Path | What |
|------|------|
| `crates/appfuzz-core` | engine: harness, simulated host, fuzzer, detectors |
| `crates/appfuzz-core/platforms` | bundled platforms (Fastly) |
| `crates/appfuzz` | the CLI |
| `bench/apps` | 76 small apps, each with one bad pattern (or none) and its expected findings |
| `bench/lang` | the same app in Zig, TypeScript, JavaScript, Go, C# and Python |
| `demos/fastly-hello` | Fastly's Rust starter kit, with a `Makefile` to build, serve and deploy it |
| `website` | appfuzz.dev and its `install.sh` |

`cargo test` runs the unit, harness and CLI tests. The bench builds every
app in `bench/apps` and checks that `review` finds exactly the expected
findings:

```sh
rustup target add wasm32-wasip2
cargo test --release -p appfuzz --test bench -- --ignored bench --nocapture
```

## License

MIT, see [LICENSE](LICENSE).
