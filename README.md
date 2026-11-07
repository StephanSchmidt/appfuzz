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
- **HTTP handlers on `wasi:http`**: Spin, wasmCloud, `wasmtime serve`.
- **Fastly Compute apps** (wasm32-wasip1 modules).
- **[Extism](https://extism.org/) plugins**, from any PDK.

Website: https://appfuzz.dev

## Try it in 30 seconds

```sh
curl -fsSL https://appfuzz.dev/install.sh | sh     # or: brew install stephanschmidt/appfuzz/appfuzz
appfuzz --human https://appfuzz.dev/demo/chatty.wasm
```

![appfuzz reviewing the chatty demo: FAIL, an n+1 query and a cost over budget](https://appfuzz.dev/demo.gif)

That downloads a small demo app with a bug and reviews it. Four more are on
[appfuzz.dev/demo](https://appfuzz.dev/demo/): an XSS, two crashes and one
that passes. On your own app, run `appfuzz review` next to its `.wasm`.
If your shell can't find `appfuzz` yet, use the command the installer
printed last: it has the full path.

**Who it's for:** platforms that run code other people wrote (plugins,
extensions, customer scripts), teams whose agents write more code than anyone
reviews, and developers of Wasm apps on Fastly, Spin, wasmCloud or Extism.

**How it differs:** unit tests and proptest need you to write inputs and
checks; appfuzz brings both. cargo-fuzz finds crashes in a fuzzing build;
appfuzz runs your release build and also reports slow pages, XSS, leaked data
and wasteful calls. Semgrep and CodeQL read code; appfuzz runs it, so each
finding comes with the input that causes it. More on
[appfuzz.dev](https://appfuzz.dev/#different).

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
$ appfuzz --human review --time 10s
 FAIL  chatty.wasm  appfuzz review
       2 fail · 4 warn · 1 info · 96,676 runs in 10.6s

  ✗ fail  n_plus_1               calls to bench:web/items#get grow as 1·n with n = length of the list bench:web/items#all returns; cost breaks its limit at n = 100
  ✗ fail  over_budget            bench:web/handler#handle uses 129 cost, the limit is 100
  ▲ warn  chatty                 bench:web/items#get is called for each element bench:web/items#all returned (2 calls for 2 elements)
  ▲ warn  redundant_calls        bench:web/items#get: 2 of 4 calls repeat earlier calls with the same arguments
  ▲ warn  serial_chain           bench:web/handler#handle waits 129 ms for 129 host calls in a row (128 × bench:web/items#get: 128 ms), the latency limit is 200 ms
  ▲ warn  slow_host_sensitivity  bench:web/handler#handle takes 321.04 ms (limit 200) when bench:web/items#get answers in 20 ms; it calls it 16 times

Next
  › appfuzz --human show r9e5a645b84 --view explanation
  › appfuzz --human findings --min info
```

The exit code is 2 (fail), so CI stops. Without `--human`, the same
command prints the full report as JSON. The same loop written in Zig,
TypeScript, JavaScript, Go, C# and Python gets the same findings
(`bench/lang`).

## Install

On Linux (Alpine too) or macOS, x86_64 or arm64:

```sh
curl -fsSL https://appfuzz.dev/install.sh | sh
```

The script ([install.sh](install.sh)) downloads the binary
from the latest [GitHub release](https://github.com/StephanSchmidt/appfuzz/releases),
checks its SHA-256 and that it runs, and puts it in `~/.local/bin`
(`/usr/local/bin` as root, for example in a container). Alpine, and Linux
older than Ubuntu 22.04 or Debian 12, get a static build. Set
`APPFUZZ_VERSION=v0.5.0` for a specific release or `APPFUZZ_INSTALL_DIR` for
another directory.

Or with Homebrew: `brew install stephanschmidt/appfuzz/appfuzz`

Or build it with Rust (1.85 or newer):

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

A Wasm file on a web server can be reviewed by its URL:

```sh
appfuzz --human https://appfuzz.dev/demo/chatty.wasm
```

appfuzz downloads it, and its manifest from the same URL ending in `.toml`
instead of `.wasm` if there is one, and reviews it. Only `https://` URLs
are downloaded (`--allow-http` for plain http), at most 50 MB, and the file
must be WebAssembly. A downloaded manifest can't point at local files: its
`wasm` is always the download, and it can only name a bundled platform.
Downloads and their runs are kept in `~/.cache/appfuzz` (macOS:
`~/Library/Caches/appfuzz`, or `$APPFUZZ_CACHE`), not in the current
folder. `--wasm <url>` works with every command.

Every command prints one JSON document, for CI and agents. With `--human`
(or `APPFUZZ_HUMAN=1`) it prints for a person instead, in color: the
verdict, one line per finding, and what to run next. Colors are off when
the output is not a terminal or `NO_COLOR` is set.

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

`--time` is the fuzzing budget (60s without it); probes and confirming
findings come on top.
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
- **Access:** with identity labels, user ids taken from the request, and
  other users' records shown in a page or changed.
- **Mass leaks:** with a limit per response, an export or a `?limit=1000000`
  that sends more records than the platform allows, in the page, the logs
  or an email.
- **Writes:** with effect labels, changes on GET requests, the same write
  twice, retried writes, one write per row, and a write that stays when a
  later one fails.
- **Database:** n+1 queries, loops inside loops, calls that grow with a
  request field, repeated identical calls, retry storms.
- **Wrong answers:** results that change with row order or duplicates,
  values outside their range, swallowed errors, error pages with status 200.
- **Performance:** CPU, memory, cost and latency against your limits, and
  CPU, memory or output that grows faster than the input.

Every security finding names its CWE and OWASP category, and `review`
lists the OWASP Top 10: what it found, what it checked, which checks
need a label you haven't added yet, and what is up to your platform.
[OWASP.md](OWASP.md) has the mapping.

Every finding comes with the request and backend answers that cause it.
Time is simulated, so a backend that takes 200 ms or a timeout of ten
minutes costs nothing real, and the same input always gives the same run.
The search itself is random, so two reviews can list a few different
warnings; every finding replays exactly.

## Digging into a finding

```sh
appfuzz show last --view explanation         # what happened, in plain terms
appfuzz show last --view calls --fn items    # the host calls it made
appfuzz show last --view provenance --call 2 # where call 2's argument came from
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

**The manifest** (`appfuzz.toml`) says which file to review, what the app
may import, and your production limits:

```toml
[app]
wasm = "target/wasm32-wasip2/release/my_app.wasm"

[grants]
imports = ["acme:web/items", "acme:web/store"]

[limits]
memory = "64MiB"
cost_per_request = 100       # host call cost units per request
max_latency_ms = 200
records_per_response = 100   # records of one collection per response
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
origin = "app"
request = { method = "GET", path = "/", query = [], form = [], today = "2026-11-02", now = "08:00:00" }  # the fields of this app's request type
expect = { selector = "$.status", equals = 200 }
```

`origin` says who owns the requirement: `app` for what the feature must
do, whichever team asked for it, `platform` for a platform rule. Run
them on their own with `appfuzz acceptance run`.

### Asserting outputs against inputs

An assert relates the output to what went in, the request and what the
backend returned:

```toml
[acceptance.checks.total]
origin = "app"
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
| **HTTP handler** on `wasi:http` (Spin, wasmCloud, `wasmtime serve`) | built in | nothing |
| **Spin app** | built in, plus your `spin.toml` | nothing |
| **Fastly Compute app** (wasm32-wasip1) | Fastly's witx, bundled | `platform = "fastly"` |
| **Module on another witx platform** | your platform's witx | a `platform.toml` |
| **Extism plugin** (any PDK) | a WIT file you supply | a `platform.toml` with `abi = "extism"` |

A plain module only names the host functions it calls, not what they take
and return, so appfuzz needs its platform. `appfuzz platform docs` prints
that platform's host API, with signatures and descriptions, as a reference
for whoever writes apps for it.

### HTTP handlers (`wasi:http`)

A component that exports `wasi:http/incoming-handler` is tested like a web
app: a run is one request, and the result is the response your handler
sends. `appfuzz --wasm app.wasm review` works without a manifest. To choose
the request yourself:

```toml
[entry]
export = "wasi:http/incoming-handler#handle"
request = { method = "GET", uri = "https://app.example/?q=shoes", headers = [], body = "" }
```

The fuzzer varies the method, URL, query, headers and body.

Outgoing requests don't leave the sandbox. Each one is a call to
`wasi:http/outgoing-handler#handle` with `method`, `url`, `headers` and
`body`. Script the answer in a plan, or make it fail:

```sh
appfuzz run --plan '{"wasi:http/outgoing-handler#handle": {"return": {"ok": {"status": 503, "headers": [], "body": ""}}}}'
appfuzz run --plan '{"wasi:http/outgoing-handler#handle": {"return": {"err": "connection-timeout"}}}'
```

If text from the incoming request decides where an outgoing request goes,
the review reports SSRF. If it can add `../` to the path, it can reach
other endpoints of that API, and the review reports that too.

The review also sends your handler requests the way an attacker would:
from another website, to catch CORS headers that let any site read a
visitor's data, and naming another host, to catch password reset links
and redirects built from the `Host` header. Where your handler turns away
a request without credentials, the review tries forged ones: a made-up
token, a JWT nobody signed, `admin:admin`, a made-up session cookie. If one
gets in, the review fails. It also catches a token compared with `==`
against your secret (the time it takes gives the token away one character
at a time) and session ids made from the clock instead of random bytes.

### Spin apps

Run `appfuzz review` next to your `spin.toml`. It needs no `appfuzz.toml`:
appfuzz reads your component's settings and tests it with what Spin would
give it.

| In `spin.toml` | What the review does with it |
|----------------|------------------------------|
| `allowed_outbound_hosts` | the hosts your app may call; a call your code makes to any other host is reported, and a request to any other host is refused, as on Spin. A client that picks the host can then only reach the hosts you allow: a warning, not a fail |
| `variables` marked `secret = true` | traced: a token that shows up in a page, a log or a request to the wrong host fails the review |
| other variables | answered with their default value |
| `key_value_stores`, `sqlite_databases` | opening any other store or database fails, as on Spin |
| the HTTP trigger's `route` | the path the requests go to |

The review also knows Spin's own APIs: a SQL statement built from request
text is SQL injection, and a key-value or Redis write on a GET request is
reported. If your app has several HTTP components, pick one with
`--component NAME`. Add an `appfuzz.toml` when you want limits or your own
labels; it replaces `spin.toml` for appfuzz.

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
permissions, and a review decides what goes live. The team that wants a
feature writes down what it must do; engineering owns the platform contract and its budgets;
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
- Not yet supported: WASI 0.3 HTTP handlers (`wasi:http/handler`, Spin 4),
  outbound HTTP from Extism plugins, Proxy-Wasm filters and browser Wasm.
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
| `bench/apps` | 91 small apps, each with one bad pattern (or none) and its expected findings |
| `bench/lang` | the same app in Zig, TypeScript, JavaScript, Go, C# and Python |
| `demos/fastly-hello` | Fastly's Rust starter kit, with a `Makefile` to build, serve and deploy it |
| `install.sh` | the installer behind `curl -fsSL https://appfuzz.dev/install.sh \| sh` |

`cargo test` runs the unit, harness and CLI tests. The bench builds every
app in `bench/apps` and checks that `review` finds exactly the expected
findings:

```sh
rustup target add wasm32-wasip2
cargo test --release -p appfuzz --test bench -- --ignored bench --nocapture
```

`make speed` measures how fast appfuzz loads, runs, checks and fuzzes four
bench apps. Save its output before and after a change, then compare the two
with `benchstat old.txt new.txt`.

## License

MIT, see [LICENSE](LICENSE).
