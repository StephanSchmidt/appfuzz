# appfuzz reference

The exact semantics behind the [README](README.md): budgets, exit codes,
search stages, and the manifest features in full. Read the README first;
come here when you need the precise rule. [AGENTS.md](AGENTS.md) is the
guide for agents driving appfuzz, [LABELS.md](LABELS.md) the label
vocabulary, [ENVELOPE.md](ENVELOPE.md) the runtime envelope.

## Review, budgets and exit codes

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

On the 74 bench apps of the time, `review` with a 5 s fuzz budget found every expected bug
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
request/plan reductions; saved cases replay the original binary.

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

## Command output

Commands print lossless JSON with suggested `next` commands. Exported artifacts
(`plan template` and the raw `show` record) omit navigation metadata so another
command can read them unchanged. The old `--full` flag remains a compatibility
no-op.

## Platform files

A component carries its own WIT. A plain module doesn't: its platform's
`platform.toml` supplies the types and the calling convention, and the app's
manifest names it with `[app] platform` (a bundled name such as `fastly`, or
a path). `appfuzz platform docs` prints the host API reference;
`appfuzz platform check` checks a `platform.toml` against its WIT or witx and
lists functions without a description.

WASI's clocks, streams, files, sockets, random numbers and HTTP run in the
sandbox. Other `wasi:` interfaces, such as `wasi:keyvalue`, `wasi:config` and
`wasi:blobstore`, are services of the platform: each function is a host call
like the platform's own, with generated results that a plan or rules can
replace. `[grants] wasi` grants them like the rest of WASI.

### wasi:http handlers

A component that exports `wasi:http/incoming-handler` (0.2.x) needs no
platform file. appfuzz shows the handler as one function:

```wit
handle: func(request: record { method: string, uri: string,
  headers: list<tuple<string, string>>, body: string })
  -> record { status: u16, headers: list<tuple<string, string>>, body: string };
```

- Without `[entry]`, the request is `GET https://app.example/` and the output
  is `status`, `body` and `headers`. `method = "format:token"` holds unless
  the manifest says otherwise. Query keys in
  the URI are request fields named `uri?key` (`sweep -f 'uri?days'`).
- Any `uri` text is delivered as a valid URI, as a client would send it: relative URIs resolve
  against `https://app.example/`, unsafe characters are percent-encoded, and
  a `Host` header is added when missing. Header names or values the HTTP
  types reject are dropped.
- A handler that returns without `response-outparam.set` is a crash. A
  response set to an error code is status 500. An aborted response body is a
  crash. Bodies are capped at 64 MiB.
- A response body that is not UTF-8 is recorded as a list of bytes (an
  image, a download). It is `invalid_response` (warn) only when the
  `content-type` is text or missing. Trailers appear as `trailers` in the
  result.
- A `content-length` header that differs from the body's size is
  `invalid_response` (fail): the platform cuts the response short or fails
  it, and a proxy may read the rest as the next response. HEAD requests and
  1xx, 204 and 304 responses are exempt.
- Request bodies, and bodies of outbound requests and their answers, are
  text.

`probe web` (part of `review`) sends the request as another website
would and as a request naming another host would:

- With `Origin: https://attacker.example`, `null`, a look-alike of the
  app's host, and a CORS preflight for each. A response that repeats the
  Origin in `Access-Control-Allow-Origin` with
  `Access-Control-Allow-Credentials: true` is `permissive_cors` (fail): any
  website the visitor opens can read it as the visitor. Repeating the
  Origin without credentials is the same as `*` and no finding.
- With the host `attacker.example`, and with `X-Forwarded-Host` and
  `Forwarded: host=` naming it. That host in an outbound request's URL is
  `host_header_injection` (fail); in a redirect or a link in the page it
  is a warning: a password reset link built this way points to the
  attacker. The app's own host is the one in the manifest's request.

Both checks also judge every fuzz run.

`probe auth` (part of `review`, after the fuzz phase) sends the request
without credentials (no `Authorization`, `Proxy-Authorization`, `Cookie`,
`X-API-Key`, `X-Auth-Token`). Where that is turned away (401, 403, or a
redirect), it sends it again with forged ones: a made-up bearer token,
`Bearer null`, an unsigned JWT (`alg: none`), a JWT with a wrong signature,
`Basic admin:admin`, a made-up `X-API-Key`, and made-up session cookies
(`session`, `sid`, `token`, `jwt`, …, also with the unsigned JWT). A 2xx is
`auth_bypass` (fail): the app checks that a credential is there, or reads
a JWT's claims without verifying it. A forged credential that went to a
host call (a session lookup, a token service) is left out, since the
simulated host decided. Besides the manifest's request, it tries up to
eight paths of stored runs that were turned away or issued a session token.

Where the app read a secret (a result labelled `secret`, such as a Spin
secret variable) while checking the made-up bearer token or API key, the
probe sends the secret's prefixes instead: 0, 1, 2, … correct leading
characters, the rest other characters of the same kind, always the full
length. Fuel that never falls and rises at least twice, with an equal cost
for two different wrong guesses, is `timing_unsafe_compare` (warn): the
comparison stops at the first wrong character, so response times tell how
much of a guess is right. A hash or a constant-time comparison costs the
same for every guess.

Session tokens are `Set-Cookie` values and JSON fields whose name looks like
one (`session`, `sid`, `token`, `auth`, `csrf`, `reset`, `api_key`, …), 8
characters or more. Not signed tokens with three dot-separated parts (JWTs),
not text from the request or a host answer, and none in a run that read a
secret (the token may be signed with it). Each response with one is sent
again with host answers pinned, with two other random seeds and a second
later. A token that stays the same under the other seeds is
`predictable_token` (fail): made from the clock when it changes a second
later, a constant otherwise. The run with the whole secret is checked too.

Outbound requests are the host function
`wasi:http/outgoing-handler#handle(method: string, url: string, headers,
body: string) -> result<response, string>`, where `response` is
`{status, headers, body}`. The call happens when the guest first waits for
the response, so a body written after `handle` is part of `body`. Requests
nobody waited for are sent after the handler returns.

A request is in flight from `handle` on: it is ready at the virtual time
it was sent plus its latency, and the guest waits only for what is left.
Requests sent together overlap, so four 60 ms requests awaited together
take 60 ms; awaited one by one, each after the previous answer, they take
240. A `first-byte-timeout` in the request options (plus the
`connect-timeout`, if set) is honoured: a request whose latency is longer
fails at that time with `connection-read-timeout`. A `connect-timeout`
alone does not limit a response.

A `[functions."wasi:http/outgoing-handler#handle"]` section keeps what it
sets (a latency, a cost, rules) and takes the defaults below for the
labels and values it leaves out.

Its defaults are `params = { url = "url", headers = "secret" }` (the URL is
an SSRF sink; headers may carry an API token) and
`values = { status = "range:200..599" }` (the client handles interim
1xx responses; unplanned calls answer 200); a manifest section's own
`params` or `values` replace them. An `err` text that is a wasi:http error code
(`dns-timeout`, `destination-not-found`, `connection-refused`,
`connection-timeout`, `tls-certificate-error`, `http-request-denied`, …)
arrives as that code; any other
text arrives as `internal-error` with the text. A method or scheme the
types reject, or an empty authority, fails before any host call.

A host written into the app (`https://api.example/quote`) that `[grants]
hosts` doesn't list is `unexpected_destination`, a fail. Without any
`[grants]` (no manifest, say) it is info, naming the line to add; a
manifest that lists other grants and no hosts grants none. Addresses in
the internal network are a fail either way.

### Spin apps (`spin.toml`)

Without `appfuzz.toml`, appfuzz reads `spin.toml` from the current
directory (`-m spin.toml` names it). An `appfuzz.toml` wins; `--wasm`
alone skips `spin.toml`. Only `spin_manifest_version = 2` is read. The
component is `--component NAME`, else the only one with an HTTP trigger,
else the only one. Its `source` must be a local path.

| `spin.toml` | appfuzz |
|-------------|---------|
| `source` | `[app] wasm` |
| `[application] name`, `description` | `[app] name`, `description` |
| HTTP trigger `route` (`/shop/...`) | `[app] base = "/shop"`; the request is `GET https://app.example/shop/` |
| `allowed_outbound_hosts` | `[grants] hosts`: the host of each entry, `*.example.com` as `example.com` and its subdomains, `*` as any host; `self` and `localhost` are skipped, `{{ var }}` is filled from the component's variables or the entry skipped |
| `[component.X.variables]` | rules on `fermyon:spin/variables#get`, `spin:variables/variables#get` (`name`) and `wasi:config/store#get` (`key`): a variable whose template uses an application variable with `secret = true` has `result = "secret"` and a generated value; one whose template resolves through defaults returns that text; an undeclared name is `undefined` (`ok(none)` for `wasi:config`) |
| `key_value_stores` | rules on `store.open` (`label`) and `wasi:keyvalue/store#open` (`identifier`): any other store is `access-denied` |
| `sqlite_databases` | rules on `connection.open` (`database`): any other database is `access-denied` |

No `[grants] imports` or `wasi`: Spin links all of WASI and its own
interfaces. The limits are appfuzz's defaults. Built-in labels for Spin's
SQL, key-value, Redis and MQTT functions and for `wasi:keyvalue` apply to
every component, with or without `spin.toml`.

`allowed_outbound_hosts` is also a rule on
`wasi:http/outgoing-handler#handle`: a URL no entry allows (scheme, host and
port; without a port the scheme's default) is `err("http-request-denied")`,
as Spin answers. With no entries every request is refused; with an entry
only Spin can resolve (`{{ var }}` without a default) none is. A host written
into the app that is not granted is `unexpected_destination`. A host the
request decides is `ssrf`: a fail when the request goes out, a warning
naming the allowed hosts when the platform refused it (the client can still
pick among them), and nothing when no host is allowed.

### witx platforms

`witx = ["path/to/abi.witx", …]` (or `builtin:fastly`) gives the types: pointers
and lengths into the module's memory. Besides the types, a witx platform names:

- `start`: the module export a run calls (`_start`). `proc_exit(0)` is a
  normal end. WASI preview 1 runs on the virtual clock.
- `entry_wit`: the WIT records of one run's request and response, and the
  `handle` function between them.
- `[handles.KIND]` with `init`: handle kinds and their initial state. A
  function's `handle = { op = …, kind = … }` binds it to that state. For
  Fastly, the client request is the state of the handles
  `body_downstream_get` returns; `send_downstream`'s response and body are
  the run's result.
- `bad_handle` and `absent`: the error cases for an invalid handle and a
  missing value.
- per function: `description`, `param_docs`, `result_doc`, `sdk`, and
  `fails = false` for calls the SDK treats as infallible (appfuzz then
  injects no failure).

The bundled Fastly platform
([platform.toml](crates/appfuzz-core/platforms/fastly/platform.toml)) uses
Fastly's witx vendored from Viceroy, `values = { method = "format:token",
uri = "format:url" }` on the request, and limits from Fastly's documented
service limits: 128 MiB memory, fuel for about 50 ms of CPU, and a 2-minute
wall-clock latency limit.

### Extism

With `abi = "extism"`, values cross as JSON through the Extism kernel.
appfuzz emulates `extism:host/env` and types the JSON with a WIT file. WIT is
used only as a type language here, and the plugin stays a plain module. Each
WIT import is a host function (`extism:host/user`), and each WIT export is a
plugin export. Names match ignoring case, `-` and `_`.

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
its text. A top-level `string` argument or output crosses as its bytes, not
JSON, like the PDK's `String`. An export whose WIT result is `result<T, E>`
answers `ok` when its status is 0, and `err` with its `error_set` text
otherwise. Kernel logs show up in `stderr`, and `http_request` traps because
it isn't simulated yet.
