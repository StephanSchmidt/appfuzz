# appfuzz

No more code reviews. Fuzz instead.

Agents write code faster than anyone can review it, and soon not only
engineers will ask them to. Reading every diff doesn't scale; running the
code does. appfuzz runs a WebAssembly app thousands of times against a
simulated backend and reports what a reviewer would miss: crashes on empty
lists and Unicode, user input that reaches the HTML unescaped, loops that
send one database query per row. One command gives a verdict and an exit
code for CI, so code ships when it passes, not when a senior engineer finds
the time to read it.

It never reads your source. It runs the compiled
[component](https://component-model.bytecodealliance.org/), so it works for
any language that builds one. It's tested with Rust, Zig, TypeScript and Python.

For constrained AppOS apps, marketing owns the intended behavior and acceptance
examples. Engineering owns the platform contract: capabilities, data boundaries,
host guarantees, and budgets. appfuzz automates routine implementation review
against that contract. It does not require an engineer to approve every app.

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

Or with Homebrew: `brew install stephanschmidt/appfuzz/appfuzz`

Or build it with Rust:

```sh
cargo install --git https://github.com/StephanSchmidt/appfuzz appfuzz
```

Then, next to your component:

```sh
appfuzz --wasm my_app.wasm inspect    # exports, imports, static findings
appfuzz --wasm my_app.wasm review     # exit codes: 0 pass, 1 warn, 2 fail, 3 incomplete/error
```

`appfuzz` without arguments prints a guide with what to run next.
`appfuzz <command> --help` shows examples.

## Main workflow

```sh
appfuzz inspect
appfuzz run --trace --export 'acme:web/handler#handle'
appfuzz plan template > plan.json
appfuzz review --plan plan.json --time 2m
appfuzz show last --view explanation
appfuzz show last --view calls --fn items
appfuzz show last --view provenance --call 3
appfuzz check value_range .usage 0 100
appfuzz replay path/to/case.json                  # exact historical build
appfuzz replay path/to/case.json --against-current # regression after a change
```

`review` accepts `--request`, `--args`, `--set`, `--plan`, `--now`, and
`--export`, just like targeted commands. Probes and mutations deliberately vary
the seed plan; invariant platform guarantees belong in manifest constraints and
rules. A realistic seed plan does not promise relational integrity for every
mutated host response.

`--time` budgets the fuzz phase, including its discovery work; probes, scaling,
historical regression inputs, and confirmation are additional. `--runs` bounds
fuzz evaluations (including seeds and pairs, excluding discovery). Use
`-j 1 --fresh --search-seed 7 --runs 2000` for reproducible search choices;
`--host-seed` controls generated host results and guest randomness. `--rng` and
`--seed` remain aliases. A time limit can stop a run budget early.

Review records an explicit session. Repeated reviews re-evaluate previously
found failure inputs for the same build and contract; `--fresh` resets the
search corpus, not those regression inputs. Incompatible old cache entries are
ignored. A required analysis error produces `incomplete`, never `pass`.

| Exit | Review | Property check | Case replay |
|---|---|---|---|
| 0 | Complete, no warnings/failures | Exercised, no counterexample | Reproduced exactly; or absent in `--against-current` mode |
| 1 | Warnings | — | — |
| 2 | Failures | Counterexample | Not reproduced exactly; or still present in `--against-current` mode |
| 3 | Incomplete or tool/configuration error | Unexercised or error | Could not execute or incompatible artifact |

A property selector reports its numeric match count. No matches produces
`holds: null` and `status: not_exercised`. Findings carry `evidence` (`measured`,
`policy_violation`, or `heuristic`) separately from severity. Review lists
unreached host sites and checks lacking required labels.

Stored-run views are `record`, `summary`, `calls`, `timeline`, `logs`, `stack`,
`provenance`, `fuel`, and `explanation`. Older `call`, `calls`, `timeline`, `why`,
`stdout`, `provenance`, `profile`, and `explain` commands remain compatibility
interfaces. Prefer `run --trace` and `show --view` for new integrations.

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

Review confirms up to ten of the worst runtime findings by default. `confirm`
replays a finding, shrinks it, and saves an executable case; static findings
point to code instead. Runs bind the component, effective platform contract,
and engine identity, as well as the request, host plan, clock, and seeds.
Time is simulated; a virtual timeout does not require waiting in real time.
A wall-clock safety timeout can still interrupt an overloaded machine.

## How it works

1. **A manifest** (`appfuzz.toml`) says which export handles requests, what
   the app may import, and your limits, such as 100 host calls per request.
   It's optional, since `--wasm` alone works.
2. **Host functions are simulated.** Each import answers with values
   generated from its WIT types, which the fuzzer varies. A JSON host plan
   scripts realistic data when you need it (`appfuzz plan template`).
3. **Every valid fuzz evaluation runs the per-run detectors:** call patterns,
   output checks, and data flow. Separate analyses compare runs and fit growth
   laws. Search uses host-call sites, call sequences, output shapes and resource
   maxima; `--internal-feedback` adds control-flow and integer-comparison
   feedback from inside the Wasm. Findings and resource measurements always
   come from the original component.
4. **Labels** say what text means: this parameter is SQL, this field is an
   email address, this result is a secret.

   ```toml
   [functions."acme:web/db#query"]
   params = { sql = "sql" }

   [functions."acme:web/users#current"]
   result = { email = "pii" }
   ```

   Request and backend text that reaches the SQL with its quote intact is
   `sql_injection`. An email address in the log is `pii_leak`; with
   `[entry] no_pii = true`, anywhere in the output. `inspect`
   suggests labels from the WIT names.
5. **`check`** turns your own suspicion ("usage never exceeds 100") into a
   search for a counterexample.

Commands print lossless JSON with suggested `next` commands. Exported artifacts
(`plan template` and the raw `show` record) omit navigation metadata so another
command can read them unchanged. The old `--full` flag remains a compatibility
no-op. [AGENTS.md](AGENTS.md) is the guide for that, and it's a good
reference for people too.

## Search inside the compiled Wasm

Internal feedback is off by default; turn it on with `--internal-feedback` on
`fuzz` or `review`. It is for apps that hide behavior behind computed values,
checksums or byte-by-byte parsers, where the values compared are not constants
in the binary. appfuzz already tries the numbers and strings it finds in the
binary without it. appfuzz creates a temporary instrumented
copy of the supplied component and records control-flow hits and operands of
32-bit and 64-bit integer comparisons. It retains inputs that reach new internal
behavior or improve aggregate comparison distance, and tries observed operands
as replacements for matching request numbers and string bytes. This helps reach
conditions that produce identical host calls and output until the bug triggers.
No source changes or specially compiled fuzzing build are required.

Every candidate also runs on the original component. Only that execution supplies
findings, stacks, fuel, memory, host cost and latency. Instrumentation results are
search hints; its added instructions and private memory do not enter the reported
resource totals. Saved cases replay the original binary. Successful original
requests receive a feedback run; already failing requests need no shadow execution.

Compare search modes with the same seed and a fresh corpus:

```sh
appfuzz -j 1 fuzz --fresh --search-seed 7 --time 10s
appfuzz -j 1 fuzz --fresh --search-seed 7 --time 10s --internal-feedback
```

With `--internal-feedback`, fuzz reports include
`feedback.mode`, setup time, instrumented sites/modules, skipped modules, failed
feedback executions, and any instrumentation error. `review` includes this under
`coverage.internal_feedback`. Unsupported instrumentation falls back to boundary
feedback and reports why; it does not silently claim internal coverage. The
fuzz-time budget includes instrumentation setup.

The first implementation instruments directly instantiated core modules. Nested
components, imported modules and GC type groups are opaque. Coverage uses a bounded
bitmap; comparison samples are bounded and deduplicated. These signals are not a
complete branch-coverage percentage or symbolic execution. Clock-sensitive code
can follow different paths in the instrumented copy; confirmation on the original
component remains decisive. For interpreted apps, feedback describes interpreter
execution and may be less useful.

A controlled comparison uses two synthetic components: a crash behind computed
numeric comparisons and a crash behind byte comparisons with no embedded keyword.
With three search seeds and one worker, internal feedback found both crashes in
all six campaigns under each budget: 1,000 evaluations and one second including
instrumentation setup. Boundary feedback found neither in those campaigns.
This demonstrates those search mechanisms, not a general detection-rate estimate.
Internal feedback ran fewer evaluations per second because each successful input
also executes the instrumented copy.

On the 74 bench apps, `review` with a 5 s fuzz budget found every expected bug
in both modes. Internal feedback found nothing extra there, and missed one hang
that the faster boundary search reached. That is why it is off by default.

Reproduce the comparison:

```sh
cargo test --release -p appfuzz-core --test feedback compare_equal_budgets -- --ignored --nocapture
```

## Structured payload search

`fuzz` and the fuzz phase of `review` recognize JSON objects/arrays and
header-bearing, comma-separated CSV inside request strings and observed host
results. The `structured` stage changes nested numbers, text, booleans and list
sizes while preserving JSON syntax, or changes CSV cells and rows while keeping
the header and column count. Quotes, embedded newlines and Unicode are encoded
with the format's serializer. This gets past parsers that reject ordinary text
mutations before reaching the faulty code.

Start with one valid payload in the manifest request or host plan. No new flag
or payload schema is required. Ordinary text mutations still exercise malformed
inputs. Host successes bound to modeled datasets remain under the model's
control. Structured search scans bounded portions of requests/results; documents
are limited to 256 KiB and 2,048 nodes/cells. It does not infer an application
schema, generate a valid starting document from nothing, or support every CSV
dialect. Confirmation simplifies inside JSON/CSV as well as trying ordinary
request/plan reductions; saved cases replay the original component.

The `structured` stage runs automatically. Its evaluations and kept inputs appear
under `stages.structured` in fuzz reports. Findings use the existing detectors and
ordinary `confirm`/`replay`.

## Host failure sweeps

The fuzz `fault` stage walks successful host-call traces in order, instead of
choosing random positions. It tests each occurrence with a one-call failure and
with an outage starting there. The outage keeps subsequent calls to that service
failing, including retries the successful trace never made. Failures use the
actual WIT error type or `none` for an option. Functions without a recoverable
failure result receive a host trap; that expected abort is not an app crash.

Sweep a specific successful run, independently of fuzz scheduling:

```sh
appfuzz probe faults last --runs 256
appfuzz probe faults last --fn store --runs 256
```

The budget counts fault evaluations; executing a baseline request is additional.
Each probe names the function, its call number, the trace position, failure mode,
run and whether the fault was actually delivered. Manifest rules and value
constraints remain authoritative. An overridden fault or changed prefix is
reported as blocked, and cannot establish `error_ignored`. A finished sweep
means all applicable positions in that one trace were attempted. Exhausting the
budget or matching no host calls reports incomplete and exits 3; a finished sweep
exits 0 and returns its findings, as other probes do.

Fuzzing rotates through a bounded queue of observed traces within its existing
run/time budget. `faults` in the fuzz report (`coverage.faults` in review) counts
attempted, delivered and blocked faults, queued traces and skipped traces. A
short campaign does not guarantee every reached position was tested. New paths
after a failure still need exploration; the sweep uses one injected service
failure at a time.

Existing detectors identify crashes, hangs, excessive retries and writes followed
by an unhandled failure. Effect labels are required for partial-write findings;
these are warnings about observed call patterns, not proof of transaction state.
A successful retry of the failed operation suppresses that partial-write warning.
`confirm` and `replay` support both ordinary fault inputs and exact comparison
recipes for ignored errors, including later occurrences of the same function.
Per-run minimization also tries earlier fault positions.

Host plans can express an outage compactly:

```json
{"acme:web/store#save": {"on_call": {"3+": {"generate": {"results": "err"}}}}}
```

`3+` means the third call and all later calls to that function. An exact call
number wins over a range; otherwise the range with the greatest applicable
starting number wins. These precede plan rules and defaults. Manifest rules still
come first.

## Declared value contracts

WIT supplies structural types; platform metadata supplies semantic requirements
on guest-to-host arguments. These are declared explicitly, never guessed from
names, observed values or guest prose:

```toml
[functions."acme:web/bookings#create"]
param_values = { date = "format:date", seats = "range:1..6", reference = "format:uuid", subject = "bytes:1..200" }
value_source = "Platform HOST-API.md: booking parameter requirements"
effect = "write"
```

An actual argument outside its declared domain produces an
`invalid_host_argument` fail, even when the host returns an ordinary error. Checks
inspect complete values before shortening traces. They do not repair arguments,
change responses or invent rollback; host rules still determine behavior. A
function documented to accept raw text for validation should declare that
broader contract. `value_source` records provenance, not authority by itself.

Paths start with a parameter name and can select record fields or tuple indices,
traversing lists, present options and `ok` results. A length on a list checks the
collection. `required` rejects absent options; other rules skip them. An absent
optional parent does not require its child fields. Invalid paths, incompatible
WIT types and contradictory constraints are configuration errors.

New `param_values` and `entry.input_values` maps accept one constraint string or
an array of constraints that all apply. They support `range`, `len`, `enum` and
existing formats, plus `required`, `bytes:a..b` and `format:uuid`. Integer bounds
preserve all bits. `len` counts Unicode scalar values or list elements; `bytes`
counts UTF-8 bytes. Presence and nonempty values are separate: combine `required`
with `len:1..` when needed. Calendar dates are real `YYYY-MM-DD` dates in years
0001–9999. Local times are `HH:MM` or `HH:MM:SS`; `datetime` joins a date and local
time with `T`. These formats have no offsets, fractional seconds or leap seconds.
UUID syntax is 8-4-4-4-12 hexadecimal digits, case insensitive; nil fits that
syntax. Syntax alone establishes no UUID version, ownership or existence.
`format:uuid` also works in existing `values` guarantees on requests and host
results, including present options. Generated/supplied host data is conformed to
those guarantees so guest code receives a valid UUID when the platform promises
one. This is format-conforming generation, not a new UUID search stage.

Guest acceptance domains are separate from platform request filters:

```toml
[entry]
values = { today = "format:date" } # the platform filters other values out
input_values = { "form.date" = ["required", "format:date"], "form.seats" = ["required", "format:int", "range:1..6"] }

[acceptance]
version = 1
[acceptance.checks.reject-invalid-date]
origin = "marketing"
input_class = "invalid"
input_fields = ["form.date"]
when = { method = "POST", path = "/book" }
expect = { selector = "$.status", equals = 400 }
forbid_effects = ["write", "delete", "external"]
search = true
```

Seed the request with fields to exercise, or supply a fixed acceptance `request`
and `search = false`. This example requires POST `/book` requests with an invalid
date to return 400 and make no forbidden host calls, even calls that would fail.
Reads remain allowed. Expected rejection behavior comes from the brief; a field
type alone does not establish whether to reject, normalize or use a default.

`input_class` is `valid` (all selected domains hold) or `invalid` (at least one
does not). Omit `input_fields` to select all declared guest domains. Missing
optional fields are skipped; missing `required` fields are invalid. If no selected
domain is exercised, the check is incomplete.
Request paths use the existing first-matching query/form key convention. `when`
matches fields by exact equality. These scopes and `forbid_effects` apply to
single-run acceptance checks. Cases outside platform filters and unmatched scopes
or selectors are unexercised, never passing. Shrinking preserves the class and
violation; an upper-bound failure cannot shrink into a lower-bound failure.
Effect assertions require effect metadata for reached platform calls; an
unclassified call makes that assertion unexercised rather than proving no writes.

`inspect` shows host argument declarations. Review reports function-level
evidence under `coverage.host_value_contracts`, including checked-rule counts and
unexercised functions over recorded runs. This is not exhaustive value coverage.
Existing manifest fields retain their meaning. The updated execution fingerprint
requires `--against-current` for regression replay of earlier-engine cases.

This addition reuses ordinary search and saved acceptance checks. A dedicated
semantic mutation stage has not been enabled; its incremental value must be
measured separately. Monetary business arithmetic, UUID ownership/existence,
additional encodings and arbitrary cross-field rules remain outside this work.

## Coherent host datasets

The platform can declare shared record collections. List and lookup functions
then see the same records, and foreign keys always reference an existing row:

```toml
[datasets.customers]
rows = 4
key = "id"
template = { id = 1, name = "Customer" }
choices = { name = ["Alice", "Zoë", "<i>untrusted</i>"] }

[datasets.orders]
rows = 12
key = "id"
template = { id = 1, customer-id = 1, date = "2026-11-02" }
references = { customer-id = "customers" }
choices = { date = ["2026-11-02", "2028-02-29"] }

[functions."acme:web/customers#all"]
query = { dataset = "customers" }

[functions."acme:web/customers#get"]
query = { dataset = "customers", filter = { id = "id" }, one = true }

[functions."acme:web/orders#by-customer"]
query = { dataset = "orders", filter = { customer-id = "customer-id" }, wrap = "ok" }
```

Filters map record fields to host parameter names, using exact JSON equality.
`one = true` returns the first match, or `null` (a WIT option). `missing` can
supply a complete not-found response, such as `{ err = "not found" }`;
`wrap = "ok"` wraps successful values as WIT results. `select = "id"` returns
that field instead of whole records, including lists of scalar values.

Keys are unique sequential integers starting at 1, or a string template prefix
with `_1`, `_2`, etc. Choices and references are deterministic for `--host-seed`.
An empty parent makes its dependent collections empty. References must form an
acyclic graph. Collections are limited to 10,000 rows each.

Override collection sizes in a plan with
`{"_defaults":{"dataset_rows":{"customers":2,"orders":8}}}`.
`_defaults.dataset_seed` optionally fixes the data seed separately from guest
randomness (pair comparisons use this to hold host data fixed). Fuzzing varies
sizes and data seeds; scaling a modeled list resizes its collection,
and confirmation shrinks sizes while rebuilding dependent records. Value probes
exercise empty/large collections and service failures; text and number cases
come from declared choices. These bindings override scripted successful values
and independent response mutations. Manifest rules retain precedence; explicit
traps, `err` and `none` fault responses can still be injected. Conflicting result
constraints are errors rather than silently rewriting shared records.

Ordinary runs start with fresh data. Datasets model declared keys, references,
choices and equality filters. Sequence mutation bindings can persist writes and
explicit invariants can check compound uniqueness across requests. Business
rules and relationships are never inferred. Undeclared host
functions keep their existing generation behavior.


## Saved acceptance checks

Save the checks that matter in the platform-generated manifest. Suite version 1
supports existing properties, fixed acceptance examples, explicit relations
between two runs, and asserts that relate the output to the input. Every check records who supplied the requirement:

```toml
[acceptance]
version = 1

[acceptance.checks.usage]
origin = "platform"
description = "Usage stays within its promised range"
property = ["value_range", ".usage", "0", "100"]

[acceptance.checks.example]
origin = "marketing"
request = { method = "GET", path = "/", query = [], form = [], today = "2026-11-02", now = "08:00:00" }
expect = { selector = "$.status", equals = 200 }

[acceptance.checks.availability]
origin = "marketing"
description = "Adding an available room cannot reduce availability"
relation = { selector = ".available", comparison = "non_decreasing", dataset = "rooms", add = 1 }
```

```sh
appfuzz acceptance run
appfuzz acceptance run availability --runs 100 --search-seed 7
appfuzz review --runs 100
appfuzz replay path/to/acceptance-case.json
appfuzz replay path/to/acceptance-case.json --against-current
```

`origin` is required: `marketing` for intended app behavior, `platform` for a
platform invariant. It is provenance, not an assertion that the requirement is
correct. appfuzz never promotes observed behavior into an acceptance rule.
Exactly one of `property`, `expect`, `relation` and `assert` is required
([asserts](#asserting-outputs-against-inputs)). A property is an
argument array accepted by `check`, including `value_range`, `max_calls`,
`no_crash`, `not_contains`, and resource `max` checks.

`expect` compares every selected value with the supplied JSON value. JSON field
selectors retain types (`200` differs from `"200"`); HTML selectors return text.
Examples keep their supplied inputs and do not fuzz or shrink them by default.
Properties and relations search by default. Set `search = false` to check only
the declared baseline, or explicitly set `search = true` when an expectation
should hold across generated inputs. Searching checks first examine existing
stateless runs for their export, then use a bounded fuzz campaign. Exact examples
never inherit unrelated stored inputs.

Checks may override `export`, `request` or `args`, `plan`, `now`, and `seed`.
Other inputs inherit command defaults, including `review` request/plan options.
Plan entries override matching function entries in the inherited plan. An
explicit request/argument array is passed as supplied; clock fields are not
rewritten inside it.

Relations compare an output selector before and after a declared transformation.
Use `dataset = "rooms", add = 1` to increase a shared collection's size, or
`set = { "/0/query/days" = 7 }` to change existing argument paths using JSON
pointers. These forms are exclusive. The dataset transform regenerates the
coherent world with the larger collection; dependent references may be reassigned
by generation. The rule must describe a relationship that holds for those worlds.
`set` preserves the host plan and seed; request-dependent host guarantees still
come from declared queries and rules. Comparisons are `equal`, `non_decreasing`
and `non_increasing`. A no-op argument transform cannot provide evidence.

Both comparison runs must succeed and select one unambiguous finite number.
Text may include units but must contain only one number. Numeric comparisons use
floating-point values; integers outside the exact range ±(2^53−1) are unexercised.
Missing, ambiguous or nonnumeric values produce `not_exercised`, never `holds`.
Fixed examples and properties likewise require applicable selector matches.

Every review executes the saved suite and reports each check's origin, status,
match count, evidence run ids and counterexample case. Broken checks fail with
exit 2. Unexercised checks and execution/configuration errors make the suite and
review incomplete (exit 3), so they cannot produce an accepted envelope.
Search is evidence, not proof: a passing check means no tested input broke it.

Failed searches shrink inputs while preserving the predicate. Cases retain the
original check definition, build, effective contract and minimal input; relational
replay executes both runs. Exact replay exits 0 when the counterexample reproduces,
2 when absent, and 3 when it cannot be exercised. `--against-current` exits 2 if
it persists, 0 if the counterexample no longer reproduces, and 3 for incomplete evidence. Editing the
suite does not rewrite requirements stored in older cases.

Historical acceptance failures are re-evaluated even with `--fresh`; missing or
corrupt case evidence makes review incomplete. Review uses at most 100 fuzz
candidates per searching check (`--runs` can lower that), plus stored inputs and
up to 200 shrink attempts. Relational candidates execute two requests. These
checks are additional to the ordinary fuzz-time budget. Standalone `acceptance
run` accepts `--runs` and `--shrink-runs` to change these bounds.

### Asserting outputs against inputs

`property` and `expect` look at the output alone. An `assert` check relates the
output to what went in: the request, and what the host returned. Name each value
with `let`, then write one expression over those names:

```toml
[acceptance.checks.total]
origin = "marketing"
description = "The total is the sum of the line items"
let = { total = "out.json.total", prices = "host.items#all.result" }
assert = "total == sum(prices.map(i, i.price))"

[acceptance.checks.listing]
origin = "marketing"
let = { rows = "select .row", items = "host.items#all.result", days = "request.query.days" }
assume = "days >= 1"
assert = { every_item = "size(rows) == size(items)", no_more = "size(rows) <= 50" }
```

Expressions are [CEL](https://cel.dev). They see only the `let` names, never
the app's text as code. A table of named asserts runs one check per property:
`acceptance run listing` runs both, `acceptance run listing.no_more` runs one.
Every name must be used; host functions, parameters and result paths are
checked against the component's WIT before anything runs.

| `let` path | Gives |
|-----------|-------|
| `request.<path>` | a request field; query and form by key: `request.query.days` |
| `args.<i>.<path>` | an export argument, for exports without a request |
| `host.<fn>.result.<path>` | the result of the one call (undefined when called 0 or several times) |
| `host.<fn>.results`, `host.<fn>.calls`, `host.<fn>.args.<param>` | every result; every call with args; an argument of the one call |
| `out.status`, `out.body`, `out.headers.<name>`, `out.json.<path>`, `out.result.<path>` | the response |
| `select <selector>` | the texts a selector picks, as a list |
| `calls`, `totals.<metric>`, `clock.now`, `logs`, `outcome` | the run itself |

A trailing `?` makes a missing value `null` (`request.form.note?`). Besides
standard CEL (`size`, `all`, `exists`, `map`, `filter`, string and math
functions), appfuzz adds `sum`, `num` (a number out of text such as `"€1,200"`),
`approx(a, b, tol)`, `is_ok`/`ok`/`is_err`/`err`/`some` for WIT results and
options, `html_escaped(s)`, `in_domain(v, "range:1..31")`, `same_items(a, b)`,
`date` and `time`.

What it reports:

- **broken** names the failing conjunct (`a && b` is judged part by part) with
  its two sides, or the first list element that failed an `all()`. The
  counterexample shrinks while the *same* conjunct fails.
- **not_exercised** when a binding is undefined, `assume` rejected the run, or
  the assert only held where every list it reads was empty. The reasons are
  counted per check. When `assume` rejects nearly every run, a health warning
  says so.
- **error** when the expression itself fails on some input (an index out of
  range, a type mismatch). Errors never count as passing: guard with `has()` or
  `size()`, or scope the check with `assume`.
- **weak_assert** (warn) when the assert still holds after its values are
  perturbed (a number +1, a list missing its last item, two items swapped). An
  assert like that restates the code or tests nothing.

Saved asserts need no command of their own. `run` reports each one's verdict
(and exits 2 when one breaks); `fuzz` and `review` judge every assert on every
run, so an assert sees thousands of inputs, not a handful of examples. The
search closes in on them:

- **Closer is better.** A holding comparison has a margin: `size(rows) <= 20`
  with 17 rows is 3 away from breaking. Inputs that bring an assert closer than
  any before are kept and mutated more, the way targeted property testing hones
  in on a failure.
- **Its numbers are boundaries.** Literals in the assert become values to try,
  with their neighbours: `days <= 31` makes 30, 31 and 32 likely inputs.
- **What it reads is mutated first.** Request fields named in `let` get more
  of the mutations.

The fuzz report shows per assert how many runs judged it, the first break, and
the closest approach (`"closest": {"margin": 1, "left": 123456, "right":
123457}`), so a holding assert shows how hard it was pushed. A broken run is
kept; `acceptance run NAME` (and `review`) starts from it, shrinks it and writes
the case. Checks with their own `request`, `plan`, `when` or input class keep
a separate search. Judging is cheap (microseconds per assert); when it takes
more than a quarter of worker time, runs are sampled, but every run that showed
something new is still judged. `assert_cost_pct` reports the share. `--fast`
skips judging in `run` and `fuzz` (and review's fuzz phase); `acceptance run`
and review's acceptance step still check every assert.

Try an expression on a stored run before saving it:

```sh
appfuzz bindings --run last
appfuzz eval last 'size(rows)' --let rows='select .row'
```

Acceptance checks are requirements, not platform contract: editing one keeps
stored runs and corpora. Reviews and envelopes record which suite they judged, so
an envelope built on an older suite is refused. A case whose check was edited or
removed reports `superseded` on replay and no longer fails review.

## Request sequences

A sequence runs up to 32 requests against one simulated backend. Each request
gets a fresh component instance, while modeled dataset changes persist. Write
bindings declare how host arguments change records:

```toml
[functions."acme:web/bookings#create"]
effect = "write"
mutation = { dataset = "bookings", operation = "create", fields = { slot = "slot" }, response = { ok = true } }

[functions."acme:web/bookings#update"]
effect = "write"
mutation = { dataset = "bookings", operation = "update", filter = { id = "id" }, fields = { slot = "slot" }, response = { ok = true } }

[functions."acme:web/bookings#delete"]
effect = "delete"
mutation = { dataset = "bookings", operation = "delete", filter = { id = "id" }, response = { ok = true } }
```

Fields map to host parameters, including record paths such as `booking.slot`.
Create fills unspecified fields from the dataset template and allocates a key;
update changes all matching rows; delete removes matching rows. Keys are never
reused within a sequence. Dangling references and deletion of referenced parents
are rejected atomically. `reject` sets the complete WIT-shaped failure response
(default: `{ err = "dataset constraint violation" }`). Success and rejection
responses must match the function's WIT result type. Mutation bindings override
scripted successes; manifest rules and explicit service failures take precedence.

Create `scenario.json`, using WIT-shaped export arguments:

```json
{
  "steps": [
    {"args": [{"method":"POST","path":"/book","slot":7}]},
    {"args": [{"method":"GET","path":"/bookings","slot":7}]}
  ],
  "checks": [
    {"kind":"unique","dataset":"bookings","fields":["slot"]},
    {"kind":"max_rows","dataset":"bookings","max":10}
  ]
}
```

```sh
appfuzz sequence run scenario.json
appfuzz sequence fuzz scenario.json --runs 100 --search-seed 7
appfuzz sequence replay path/to/sequence-case.json
appfuzz sequence replay path/to/sequence-case.json --against-current
```

Steps accept `export`, `args` or a single `request`, `now`, and a per-request
`plan`. The scenario's `plan` and `seed` initialize shared data once; per-step
size/seed overrides are rejected. `args_from` maps JSON pointers in arguments to
previous run records: `{"/0/id":"/0/result/id"}` copies the first response's id
into the next request. Invalid reordered dependencies are skipped during search.

Checks run after each request. `unique` supports compound keys; `max_rows`
limits collection size. `idempotent` requires consecutive identical export and
arguments to leave the named dataset unchanged after a successful first request
or one that changed that dataset before failing. A failed pre-commit attempt may
be retried successfully. `unchanged_on_error` requires the named dataset to stay
unchanged when the request traps, returns an error result or has HTTP status >=400.
These are explicit expectations, since legitimate repeated actions may create
additional records. Initial data must satisfy uniqueness and count checks.

To simulate a committed write whose response was lost, put
`{"acme:web/bookings#create":{"on_call":{"1":{"commit_then_trap":"response lost"}}}}`
in a step's plan and follow it with a retry. This fault requires a mutation
binding. A normal `trap` happens before the write.

Fuzzing tries repetitions and different orderings of supplied actions, plus
alternative generated data seeds. It stops on a failure and removes requests
while preserving that finding, within `--shrink-runs` (default 200). `--runs`
counts candidate sequences, including skipped invalid dependencies. It returns
one reproducible witness, preferring warnings over clean runs. This search does
not claim that every action ordering or request value was tested.

For CI, embed the same scenario under `[sequences.NAME]` in the manifest.
`sequence run NAME` and `sequence fuzz NAME` accept these names. Ordinary
`review` fuzzes each configured scenario for up to 100 candidates (bounded by
`review --runs` when supplied), confirms its selected witness, and includes its
findings in the verdict. Historical sequence failures are replayed even with
`--fresh`; missing or corrupt case evidence produces `incomplete`. Sequence work
and shrinking are additional to the review fuzz-time budget.

Sequence outputs contain per-request records, state snapshots and case paths;
they bypass the stateless run cache. Exact replay verifies the build, contract
and deterministic report (exit 0 reproduced, 2 different, 3 execution error).
`--against-current` runs a regression check (exit 2 for failures, 1 warnings,
0 clear, 3 incomplete). Sequence run/fuzz use the normal 0/1/2/3 verdict codes.
Execution errors never become passing regression checks. Sequences are
sequential; concurrent requests, persistent component memory, live databases
and external service effects are outside this model. Runtime envelopes still
use individual stateless traces, and do not enforce sequence invariants.

## Where it fits: AppOS

appfuzz is the review step of [AppOS](https://appfuzz.dev/appos/), an
architecture for web apps that people outside engineering build with
agents. The site is a shell run by the platform team, and every feature is
an app: a WebAssembly component the shell runs in a sandbox. It works like a
phone: the sandbox limits what an app can reach, its manifest grants
permissions, and a review decides what goes live. Sandboxes and permissions
are known techniques. The review was the missing piece.

The shell writes each app's `appfuzz.toml`, because only the platform knows
what its host functions cost, which ones change data, and which business
rules they keep. An app can't loosen its own review.

[Roomer](https://github.com/StephanSchmidt/roomer-appos) is the full demo: a
pod-booking site with four apps, a `make` that reviews them, and a shell
that refuses a version that fails. Its README has an exercise: an agent
adds a feature, and the review refuses it.

## Platforms: components, witx and Extism

A component carries its own WIT, so appfuzz needs nothing else. A plain
module doesn't: its platform's `platform.toml` supplies the types and the
calling convention, and the app's manifest names it with `[app] platform`.

- **witx** (Fastly Compute, bundled as `platform = "fastly"`): pointers and
  lengths into the module's memory, typed by the platform's witx files.
- **Extism** (`abi = "extism"`): JSON through the Extism kernel. appfuzz
  emulates `extism:host/env` and types the JSON with a WIT file. WIT is used
  only as a type language here, and the plugin stays a plain module. Each
  WIT import is a host function (`extism:host/user`), and each WIT export
  is a plugin export. Names match ignoring case, `-` and `_`.

```toml
[platform]
name = "acme-plugins"
abi = "extism"
wit = "wit"                 # one world per app, chosen with [app] world

[platform.json]             # how the JSON spells WIT names
fields = "snake"            # default; also kebab, camel, pascal, lower, screaming
cases = "pascal"            # variant and enum cases (serde's default)
err = "error"               # result as {"ok": …} / {"error": …}
rename_all = { create-form = "camel" }
rename = { "conference.id" = "Id" }
```

Decoding the plugin's JSON is lenient, like `#[serde(default)]`: keys match
regardless of case and separators, missing fields take their empty value,
`null` is an empty list (Go's nil slice), and a `string` accepts any JSON as
its text. An export whose WIT result is `result<T, E>` answers `ok` when its
status is 0, and `err` with its `error_set` text otherwise. Kernel logs show
up in `stderr`, and `http_request` traps because it isn't simulated yet.

## Limits

- A pass means the search found nothing. That's evidence, not proof.
- Ordinary runs are isolated requests. Configured sequences preserve modeled
  backend state; concurrency and external service state are out of reach.
- It doesn't know what your host functions mean until labels tell it
  ([LABELS.md](LABELS.md)).
- Hostile-code heuristics (hidden text, reviewer instructions, encoded flows,
  destinations, dormant triggers) and runtime envelopes are **experimental**.
  Reports mark their findings; a pass is not proof that an app is benign.
- For interpreted languages, static sites, stacks and internal feedback
  (`--internal-feedback`) can describe interpreter internals. Host-call and output feedback remain available.
- `show --view fuel` estimates fuel between host calls, attributing it to the
  next call's stack. It is not a function-level CPU profile.

## Repository

| Path | What |
|------|------|
| `crates/appfuzz-core` | engine: harness, simulated host, fuzzer, detectors |
| `crates/appfuzz` | the CLI |
| `bench/apps` | 71 small apps, each with one bad pattern (or none) and its expected findings |
| `bench/lang` | the same app in Zig, TypeScript and Python |
| `website` | appfuzz.dev and its `install.sh` |

`cargo test` runs unit, harness, and CLI workflow tests, including repeated
reviews, cache changes, replay after fixes, artifact round trips, and envelopes. The bench builds every app in
`bench/apps` and checks that `review` finds exactly the expected findings:

```sh
rustup target add wasm32-wasip2
cargo test --release -p appfuzz --test bench -- --ignored bench --nocapture
```

## License

MIT, see [LICENSE](LICENSE).
