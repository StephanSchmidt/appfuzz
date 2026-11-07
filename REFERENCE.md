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

After a rebuild or a manifest change, review also re-runs the inputs of the
fail and warn findings of earlier reviews of the same app file, and lists each
under `earlier_builds`: `found_again` (it is among this review's findings),
`not_found`, or `not_rerun` with the reason (an input the new build can't take).
A crash on the same input counts as found again even when it moved in the code.
Case replay with `--against-current` uses the same rule for crashes and stack
overflows; moving a trap does not make a regression pass.
`findings` on a build that has no review yet says how many fail and warn
findings earlier reviews had.

`replay <run> --against-current` runs a stored run's input on the current build
and checks the fail and warn findings it showed: `before` lists each with
`found_again`, and the exit code is that of case replay.

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

Run and finding IDs retain 128 bits of their input hash; sequence run IDs
include the modeled state too. A unique run prefix or `last` still selects a
stored run, and older short run IDs remain readable. Case replay recognizes
legacy short finding IDs; new finding IDs must match in full. Cache reuse
checks the complete specification.
Saving a different specification under an existing ID is an error and leaves
the original evidence intact, including when writers run concurrently.
Finite floating-point inputs retain their exact value through JSON storage,
cache reuse and replay, including the sign of zero.
Finding updates serialize the read, merge and write so simultaneous commands
retain every distinct finding.

Core module IDs are unique within a component. Modules with the same imports
and exports receive an occurrence suffix. Stack and provenance views use the
original binary offsets, including nested components, to select the correct code.

## Cookies, logs and plain HTTP

Every run checks three ways data gets exposed on its way:

- `insecure_cookie` (fail): a `Set-Cookie` header whose name looks like a
  session (`sess`, `sid`, `token`, `auth`, `jwt`, `login`, `remember`, …)
  lacks `HttpOnly` or `Secure`. A cookie with an empty value (one being
  cleared) and CSRF cookies, which scripts must read, are exempt.
- `log_injection` (warn): request text with a line break, followed by more
  text, appears in standard output or standard error as it came. A WASI
  command's standard output is its answer, so only standard error counts
  there. The fuzzer tries line breaks in query and form values, which
  arrive decoded (`?q=a%0D%0Ab`).
- `cleartext_transport` (fail): a host call has an `http://` URL in its
  arguments, to a host outside the internal network, and a value a host
  function returned at a `pii` or `secret` path in any argument. The
  parameter labels that allow such values (`auth = "secret"`) don't
  exempt it.

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

## Explicit null values

An absent result and a completed return of JSON `null` are different. Stored
runs and traces retain explicit null export and host results; absent results
omit the field. This keeps void and empty-option returns deterministic through
storage, confirmation and replay. Replay differences also report fields added
or removed even when their value is null.

A host plan's `"return": null` is an explicit response, including in rules,
call-number overrides and defaults. Omitting `return` allows the next plan
layer or generation to decide. A dataset query's explicit `missing: null`
similarly overrides its usual wrapping for an empty lookup.

## WASI commands and exit status

A selected `wasi:cli/run#run` export with no parameters and a single
`result<_, _>` of unit values is a command. Both returning and exiting complete
the command: success maps to `{"ok": null}` and failure to `{"err": null}`.
The optional `command_exit_code` records the terminal status, including an exit
during component initialization. An ordinary result supplies 0 or 1; explicit
`exit-with-code` preserves its exact status. Nonzero status is the measured fail
finding `command_failed`, rather than a crash. Actual traps still produce crash
findings. Command status is retained in stored runs, summaries and traces.
A different selected export, a lookalike interface or the wrong function
signature does not acquire command semantics. An HTTP handler that exits before
providing a response remains a failed request.

Outbound requests issued before a component exit, trap or initialization failure
remain in the call trace and cost totals. Draining them does not add a host wait
when the guest never awaited their responses. A capture or host-plan error while
draining cannot be silently discarded as complete evidence; diagnostics also
retain the earlier guest failure when applicable.

## Memory accounting and allocation

The run's memory cap applies to the sum of its WebAssembly linear memories,
including the Extism kernel, and GC-heap backing memory (including collector
overhead). Importing the same memory into several instances counts it once.
The peak is the largest combined usage at one instant, rather than the sum of
independent peaks. Freed kernel blocks can be reused, but retained linear-memory
pages remain counted. Failed growth does not increase `peak_memory`;
allocator failures roll back the attempted increase. Successful allocations remain counted when a later growth fails.
`memory_limit_hit` records that the run's memory cap denied an allocation,
including a denial the guest handled successfully. It does not change an
unrelated trap into an out-of-memory failure. `out_of_memory` requires a direct
allocation failure (including denied initial memory); a guest `unreachable`
after an allocator returned failure stays `unreachable`, with the denial
recorded separately. A module's own declared memory maximum is separate from
the run's cap.

Instance pooling is an optimization: a component that exceeds a pool's shape
limits is retried with on-demand allocation. An explicit run cap is not clipped
to the pool's initial sizing. Memory64 uses on-demand allocation. Shared linear
memories are unsupported because Wasmtime does not invoke the store limiter for
their allocations; loading one reports an error rather than an unmetered run.

Initialization is part of the run: guest start code consumes the same fuel and
virtual-time budget as the entry function. Startup host calls, logs, stacks and
memory remain in the record even if initialization traps. Guest startup hangs
and memory exhaustion use the ordinary failure outcomes; infrastructure errors
remain incomplete runs. A plain module's `proc_exit(0)` also ends normally when
called during initialization.

Host-call trace capture stops before servicing another call once it contains
65,536 calls or 32 MiB of compact JSON. The complete call that crosses the byte
threshold is retained, so capture may exceed that threshold by one event. A
request that finishes on that event still has complete evidence. Startup and
the entry share one capture budget. Capture stops use `capture_limited = true`
and an `error` outcome, preserve the captured calls and their cost/time totals,
and make CLI analyses incomplete (exit code 3). Fuzzing preserves the limited run
and reports the campaign error; it does not discard it as an invalid sample.
These reviewer resource guards are separate from production limits. If a
production-budget violation is already measured when capture must stop, the
outcome is `budget_exceeded` and retains that failing witness. It is neither a
guest crash nor an unknown result. Without such a violation, the capture remains
incomplete. Requests excluded by the platform's `[entry] values` do not make a
fuzz campaign incomplete; `input_values` still permits invalid incoming inputs.

Extism kernel `alloc` returns zero for empty allocations and allocation failures,
so guests can handle failure. Host-side allocations still report errors.
Null input and output setters leave their previous locations and lengths
unchanged, including when the supplied length is zero. To clear selected output,
use a valid non-null pointer with zero length. The pinned upstream Wasm kernel
runs in the same store as the plugin, so its allocator and metadata operations
consume guest fuel. Memory accounting includes its actual linear memory,
including metadata and retained backing pages. The bundled kernel starts with
16 pages (1 MiB); `memory_bytes` reports allocator capacity, a separate value.
Freeing a block or resetting the allocator does not shrink those pages.
Input bytes are allocated once before the plugin export, even if the guest
ignores them or reads them without asking for an input offset. Preparation uses
the same memory cap as other allocations. Input reads observe writes through
the input handle; freeing that block clears its input length. Input reads rejected
by the kernel's bounds checks return zero, including empty and short inputs.
`input_set` replaces the input location without allocating a copy or freeing the
previous input block. `reset` clears all kernel blocks, input, output and error
locations while preserving host variables, collected logs and peak usage.
Variable and configuration lookups consume their key blocks. Variable writes
consume both the key and value on success; deletion consumes the key. Logging
consumes its message block while retaining the log text. These releases happen
before a lookup allocates its result. The variable store uses the SDK's default
1 MiB limit, including entry bookkeeping, separately from live kernel blocks.
Variable and configuration keys must be valid UTF-8; invalid keys trap before
consuming their handles. A null key is the empty string, and variable values
remain arbitrary bytes.
Extism log capture is separately bounded to 1 MiB of formatted text per run,
including level prefixes and newlines. Startup and the export share this limit;
`reset` does not erase it. Exceeding capture capacity preserves the recorded
prefix and reports incomplete evidence (`error`, exit code 3), so review cannot
approve the request or create an envelope. This is a reviewer resource guard,
separate from production limits. Invalid UTF-8 messages emit a small error
diagnostic, as in the SDK, instead of displaying replacement characters.

Output and error setters retain kernel memory locations. The final response
observes later writes to those locations, including output slices within a
block. `error_get` returns the existing error handle without allocating a copy.
`output_offset` and `output_length` report the currently selected output span,
including slices and explicit empty output.
Clearing or freeing the error handle removes its active error; initialization
reset also clears retained output locations. A nonempty kernel error remains a
failure even when the export returns zero or WASI exits with status zero.
Run records retain explicit guest failure text as `guest_error`, separately from
engine and host-plan diagnostics. Leak, encoded-flow and reviewer-directed-text
checks inspect this text, as does `check not_contains`. Host-plan diagnostics
alone do not count as guest output.
When a completed Extism return fails output decoding, `rejected_output` retains
its original bytes as a byte list. The same checks inspect these bytes and any
decoded JSON string values or keys, so malformed output and JSON escapes cannot
hide a leak or reviewer-directed text. Output superseded by a guest error or
left behind before a trap is not a completed rejected return.

## Host value generation

A plan's `generate.numbers` applies to every numeric field: `small`, `edge`
(zero, one and the WIT type's finite minimum and maximum), or `=NUMBER`.
Fixed numbers preserve the full integer range, including `u64::MAX`, and use
the WIT float type's normal rounding. A fixed value that overflows a float or
cannot fit an integer result is a plan error, rather than a wrapped or random
value. Optional `none`, empty lists and unselected result payloads do not need
to contain that value. Platform value constraints still govern generated results.

`cast:INTEGER` explicitly converts an integer constant to each WIT integer
width with wrapping, and to float fields with normal rounding. The fuzzer and
binary-constant probes use this mode when interpreting Wasm integer constants.
Use `cast:-1` when the intention is an unsigned maximum; `=-1` requires a
signed or floating-point result.

Generation mode names are validated in defaults, rules and individual calls.
Misspelled `numbers`, `strings`, `results` or `options` modes are errors.

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

Existing `values` ranges also preserve exact decimal bounds. Host repairs respect
the WIT type, including integer limits and floating-point rounding. Ranges and
enums with no representable WIT value, incompatible constraint types and unknown
paths are configuration errors. Growing an empty host list creates typed
elements; field repairs run before uniqueness checks. Dataset responses are
compared as typed values and are never rewritten to satisfy a contradictory
guarantee. Request filters apply only to the declared entry export; findings
from requests outside that platform filter are reported as information.

Guest acceptance domains are separate from platform request filters:

```toml
[entry]
values = { today = "format:date" } # the platform filters other values out
input_values = { "form.date" = ["required", "format:date"], "form.seats" = ["required", "format:int", "range:1..6"] }

[acceptance]
version = 1
[acceptance.checks.reject-invalid-date]
origin = "app"
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

### Pages, order and owners

A list function that returns one page at a time says how it reads the window
and answers it:

```toml
[functions."acme:web/customers#page"]
query = { dataset = "customers", order = ["name"], wrap = "ok", page = { limit = "limit", cursor = "after", items = "items", next = "next", max = 50 } }
```

`order` sorts by record fields; ties keep the collection's order. `limit`,
`offset` and `cursor` name host parameters (record paths allowed). The page
holds `limit` rows, at most `max`, from `offset` or after the `cursor`. `items`
and `next` are fields of the result record. `next` is `none` on the last page,
else the next offset or an opaque cursor. A cursor the platform never handed out
gets `invalid`, default `{ err = "invalid cursor" }`. Without `items` the result
is the list itself. `short = true` says the platform may return fewer rows than
asked while more remain. Then a plan can make it do so: `{"acme:web/customers#page":
{"page_size": 3}}`. Without `short`, `page_size` is an error.

Every run checks the pages it read from such a function, per list (the
arguments other than `limit`, `offset` and `cursor`), up to the first failed
call. Rows between two pages the app read that it never read are a
`broken_pagination` fail (`detail.gap`): the app moved on by what it asked for,
not what it got. So is the first page again before the walk reached a last page
(an empty page, `next` none, or a shorter page where pages are never short).
Where `short = true`, pair checks (`probe pairs`, fuzzing) run the same world
again with pages of 1 and of one less than the run asked for, when it read more
than one page. Another answer is a `broken_pagination` fail that names the rows
the app read with full and with short pages; confirmation shrinks the
collection to the smallest that still shows it.

`owner = "owner-id"` on a dataset names the field holding the user a record
belongs to. `public = ["name"]` lists fields anyone may see, also in other users'
records. The caller of a run is the request field with the `identity` role, else
the plan's `_defaults.identity`, else the first user records belong to: the first
key of the dataset the owner field references, or its first choice.

Pair checks (`probe pairs`, fuzzing) then run the same request in the same world
with only other users' records changed, as plan edits: `rotate` of their
private fields (not the key, the owner, references or `public` fields) and,
for a dataset without `public` fields, `drop` of every other one after the
first and `add` of one owned by another user. Records the caller's records
reference are left alone. Another body or result, or other arguments to a call whose effect is a
change (unless the function says `shared = true`), is a `tenant_leak` fail;
another status or headers only, a warn. Without a known caller (an identity
field, `_defaults.identity` or an owner) there is no such pair. Confirmation
shrinks the collections to the fewest records that still show the leak.

A mutation binding that changes or deletes a record whose owner, before the
change, is not the caller is a `missing_owner_check` fail: "deals#set-title
changes the deals record "5", which belongs to "user_2"; the caller is
"user_1"". The caller is whom the run's identity-labelled results name, else
the caller above. Creating records is not checked, and a function declared
`shared = true` may change anyone's records.

### Edited worlds

A plan can change the generated world before the run, in order:

```json
{"_defaults": {"dataset_edits": [
  {"drop": {"dataset": "customers", "keys": [1]}},
  {"rotate": {"dataset": "customers", "keys": [2, 3], "fields": ["balance"]}},
  {"add": {"dataset": "customers", "rows": 2, "set": {"owner-id": "user_2"}}}
]}}
```

`drop` removes records and the records that reference them. `rotate` gives
fields another value the platform can produce: the next of the field's choices,
the next parent for a reference, else the value of the next listed record.
`add` makes records like generated ones, with `set` fields fixed. Their keys start
above 1,000,000, so a record the request creates has the same key with and
without the edit. A key no record has changes nothing, and so does an edit that
would leave a reference without its record. Edits live in the run's plan:
a run with edits replays and caches like any run, and confirmation removes edits,
keys and added rows that the finding doesn't need. A sequence takes edits in its
scenario plan only.

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
origin = "app"
request = { method = "GET", path = "/", query = [], form = [], today = "2026-11-02", now = "08:00:00" }
expect = { selector = "$.status", equals = 200 }

[acceptance.checks.availability]
origin = "app"
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

`origin` is required: `app` for intended app behavior, owned by whichever team
owns the app, `platform` for a platform invariant. `marketing`, the former
spelling of `app`, still reads. It is provenance, not an assertion that the
requirement is correct. appfuzz never promotes observed behavior into an acceptance rule.
Exactly one of `property`, `expect`, `relation` and `assert` is required
([asserts](#asserting-outputs-against-inputs)). A property is an
argument array accepted by `check`, including `value_range`, `max_calls`,
`no_crash`, `not_contains`, and resource `max` checks. `not_contains` checks
the response, captured stdout and stderr, explicit guest errors, and rejected
output. It checks each stream separately and excludes engine and host-plan
diagnostics.

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

Single-run `value_range` and `max` properties compare decimal values exactly,
including all integer bits and fractional thresholds. JSON arrays and objects
are not numeric scalar matches. A `max` property includes resources consumed
before a guest or host trap. Counterexample evidence uses a numeric string when
JSON's floating-point representation would lose decimal precision.

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
origin = "app"
description = "The total is the sum of the line items"
let = { total = "out.json.total", prices = "host.items#all.result" }
assert = "total == sum(prices.map(i, i.price))"

[acceptance.checks.listing]
origin = "app"
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
responses must match the function's WIT result type. A create can answer with
what it made: in its `response`, the string `"$key"` stands for the new key and
`"$row"` for the new record, so `response = { ok = "$key" }` returns the id.
Updates, deletes and rejections can't use them. Mutation bindings override
scripted successes; manifest rules and explicit service failures take precedence.

Each host call in a run record says what it did. `result_items` counts the list
it returned (also inside `ok` or an option) and `result_bytes` is the size of the
whole answer as compact JSON, both measured before the record shortens long
strings; `totals.host_result_items` and `totals.host_result_bytes` add them up.
A call whose function has a `write`, `delete` or `external` effect and that took
effect has a `commit`: `rows` lists each record a mutation binding created
(`after` only), changed (`before` and `after`) or deleted (`before` only), and
is empty for calls without a binding. A call that failed has none.
`commit.lost` marks a change that stayed although the app never saw success
(`commit_then_trap`).

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

## Scaling and fitted growth

`scale` orders its points by the knob's size. Growth laws are approximate fits;
measurements retain exact resource values. A budget's `breaks_at` prefers the
first measured violating size and carries `break_evidence = "measured"`. Without
a measured violation, it may use an extrapolation, marked `"inferred"`.
`predicted_breaks_at` retains a compatible extrapolation separately. A prediction
contradicted by a successful measured point is discarded. Failed requests do
not establish that a budget holds at their size. Cost, fuel, memory and latency
boundaries compare exact values, including a one-unit overrun at large limits.

Regression calculations normalize both axes to avoid overflowing their squared
residuals. A law whose raw coefficients exceed floating-point range serializes
those coefficients as scientific decimal strings and includes `normalization`
with the evaluable model `y = y_scale * (a + b * f(n) / x_scale)`. Timings beyond
the floating-point millisecond range are fitted as fractions of an exact maximum;
`time_scale_ns` records that maximum. In this case the model's coefficients and
normalization describe the fraction, and multiplying by `time_scale_ns / 1000000`
converts its predictions to milliseconds. CLI summaries include `model` for
these laws. Rust callers use `Law::eval` and `Law::increasing` to account for the
optional scaling rather than interpreting the raw `f64` coefficient fields.

### Unbounded reads

Scaling a host list also counts the rows the function returned (`points[].rows`,
by function, and `host_result_bytes`). When the rows grow at least linearly while
`output_bytes` stays constant, logarithmic or capped, `scale` runs the largest
size three more times, without the first, the middle and the last row it read
(`detail.dropped`). A modeled collection drops the record with a `drop` edit; a
plan's list loses one element; a generated list is first pinned as the run saw
it. An answer that stays the same, result and the arguments of calls that change
something, means some rows never count.

`unbounded_read` is a fail when rows go unused, the collection has a paged query
(`detail.paged`) and a budget breaks, measured or predicted, by 10,000 rows. It
is a warn when rows go unused and either holds, else info: an aggregate such as
a total needs every row. Confirmation scales again from the shrunk run.

### Records per response

`[limits] records_per_response = 100` is the most records of one collection a
response may carry; `max_per_response` on a `[datasets.NAME]` sets it for that
collection. A platform file may set either; an app's manifest may only lower them.

`probe records`, part of `review`, gives each collection the app reads one record
more than the limit and twice the limit, marks every record, and counts the
records that leave in one request: in the response, in the logs, and in calls
that send data away (`effect = "external"` and outgoing HTTP). It starts from
the request and the pages it links to. Where the limit holds, it asks for more:
each number in the request, and `limit`, `count`, `size`, `per_page`,
`page_size`, `max`, `n`, `top`, `take` and `rows` in the query, the form or the
URL, at twice the limit and at 1,000,000.

More records than the limit in one place is `mass_disclosure` (fail). Without
a limit, a collection gets 1,024 records; a request that puts every one of them
in one place is a warn when the collection's results hold `pii` or `secret`
data, else info. `bounds[]` lists, per collection, `cap`, `total` and `most`:
the most records one run put into each place.

A collection is a dataset the app queries, as a list or page by page (not with
`one`), or a host function returning a list without a dataset. A record is
marked in its text fields: not its key, owner or references, not a field a
query filters or sorts on, and not a field held to a format, a set or a length.
A text key counts as a mark too. A dataset without either is listed under
`not_counted`. Marks survive escaping and case, not encoding or hashing.
The mark is a dataset edit, `{"tag": {"dataset": "customers", "fields": ["name"]}}`,
so a counted run replays like any run, and confirmation shrinks the collection
to one record over the limit.

## Page scripts (`probe scripts`)

When an export's output is labelled `html:scripts`, appfuzz also runs the
page's JavaScript, in a browser built into appfuzz. Nothing else needs to
be installed. `review` runs `probe scripts` after the fuzz phase.

**Which pages.** The manifest's request, and up to 8 pages the fuzz phase
found: requests with fuzzed text whose response has a script, inline event
handler or script URL. Responses sent before a later guest crash count too. Each page is
opened three times: with the host data as given, with markup in every
text a host function returns (stored text the scripts may put into the
page), and with every host list empty (a new user, an empty shop). The
URL's fragment carries request text too, so code that reads
`location.hash` is tested.

**One visit.** The page loads with its scripts: inline, from the app's
own paths, and modules. Then 1 s passes. Next, everything a visitor can
use is clicked, typed into or submitted, one at a time, with 0.5 s after
each. Then 30 s pass with nobody using the page, then 30 days, with timers
firing at most once a day, so a redirect set for next week still happens.
Time is virtual: the 30 days cost no waiting. The initial page's server time
passes before scripts start. Requests made by scripts start at the browser's
current UTC second, including time advanced by timers, and refresh all request
fields declared with clock roles. Each request can still be replayed alone
with that saved time. Fetch and XHR responses and beacon cookie updates arrive
after their measured server latency; blocking script loads advance the page
clock before the next script runs.

HTML documents use HTML tree-building rules before scripts run: omitted
document elements, table sections, raw text, inert `noscript` and template
contents, and HTML inside SVG integration points retain their browser meaning.
`DOMParser` uses those rules for `text/html` with scripting disabled; XML keeps
its XML parser and root.
Only HTML and SVG `script` elements execute; a MathML element with that name
is text. SVG scripts load from `href` (or legacy `xlink:href` when `href` is
absent), while HTML scripts load from `src`. Static checks and page execution
use the same distinction, including HTML inside foreign-content integration
points. Explicitly created namespaced elements retain that namespace.
Created scripts execute once, and nested batches keep pending page scripts.
External script completion events retain the original load even when the
script changes its URL attribute while running.

Event dispatch preserves capture and bubble phases, listener option snapshots,
once/passive/abort behavior, and removals during dispatch. Composed events
cross shadow roots with retargeting; closed roots hide their internal path
from outside listeners. Routing uses private event and tree state, so public
property shadows do not change it. Content attributes and event handler
properties share a listener position. Native XHR, MessageChannel and FileReader
notifications use the same dispatcher and retain trusted event metadata.

**Requests.** A request to the app's own origin is a run of the app,
with the same host plan. A request for data from another host gets text
that names the host, so code built from it shows as `remote_code`. The
page has a session cookie that scripts can read and that holds a secret,
so sending it away is a `secret_leak`.
Encoded private values sent in requests or navigation to another origin are
`encoded_flow` findings too. Values returned by an app request become sources
for subsequent browser calls, so a later response cannot taint an earlier call.
Responses already sent by those app requests remain available to scripts even
if the app later traps. Browser calls recorded before a hang or crash are
still checked for findings.

Sensitive host values and the probe cookie retain their origin through later
requests made by the page. Logging them or passing them to an undeclared host
parameter is checked even when the value arrives in the request, including
encoded forms (`encoded_flow`). Returning the probe cookie to its own browser
is allowed; redirecting it to another origin is not.
Other returned fields remain subject to secret and `no_pii` checks, including
encoded values; mapping a body or headers does not hide extra output fields.
Only consumed text/byte bodies and parsed header names/values are excluded from
that fallback scan. Malformed mapped values and unused header fields stay visible;
private data in a header name is checked as well as its value.
Request bodies retain their text when routed back to the app; platform request
shapes with a `form` field receive decoded form pairs.
Form recognition compares the MIME essence without case or parameters, following
[MIME parsing](https://mimesniff.spec.whatwg.org/#parse-a-mime-type).

**Cookies.** Visits retain the page request's Cookie pairs and process the
page's Set-Cookie headers without losing attributes. Subsequent fetch, XHR,
script and beacon requests use the cookie jar. HttpOnly cookies authenticate
requests but stay out of `document.cookie`; Set-Cookie response headers stay
out of fetch and XHR results. Credential modes, domains (including public and
private suffix boundaries), paths, Secure, SameSite and virtual-time expiry
control delivery. Cookie headers supplied by scripts cannot override the jar.
Cookies from asynchronous responses take effect when those responses arrive.
The readable probe cookie uses an unused name, preserving real credentials.
Incoming Cookie pairs lack attribute metadata; they are initially modeled as
readable, host-only cookies at `/`, then response attributes update them.

The effective contract includes the bundled browser's bytes. Rebuilding that
runtime invalidates earlier review and envelope identities even when the
reviewed app and manifest are unchanged.

**CPU.** Until its actions are done, a page may use 60 ms of CPU, as a
browser counts it; an ordinary React app uses under 10 ms. While nobody
uses the page, it may keep the CPU busy up to 10 % of the time;
`over_budget` reports more, as with a miner. A page that never stops is a
`hang`.

**What it reports.** `pages`: each visit, with its run, the page visit's
`browser_run`, the requests the scripts made and the errors they threw.
`unsupported`: what the visits couldn't judge. `apis` are Web APIs the
scripts used that the browser doesn't model. `scripts_not_loaded` are
scripts from other hosts. `actions_not_all_tried` are pages whose scripts
used up their CPU before every action. `not_followed_30_days` are pages
whose CPU ran out before 30 days passed. The visit's `outcome` says whether
it finished or exhausted its budget. Engine, plan and capture errors, or a
missing session report, set `status` to `incomplete`, list `errors` and exit 3;
`review` is incomplete too. Such failures during case replay are execution
errors, not evidence that the original finding is absent.

A finding from a visit points at the app's run that served the page.
`confirm` and `replay` reproduce it with the page's scripts.
`explain <run>` lists it with its `detail`: the sink and the value that
reached it, the URL a request went to, the error and its stack. A page
whose scripts throw while loading, with the request and host data as
given, fails: every visitor gets that error. Other script errors warn.

## Command output

Each host call's cost and the production cost limit are `u64` units. Run totals
sum those charges exactly in `u128`, including when the sum exceeds `u64::MAX`.
Cost totals, envelope budgets, scaling points and search maxima use JSON numbers
through `u64::MAX` and decimal strings above it; ordinary reports keep their
existing number shape. Readers accept both forms without floating-point
conversion. Resource `max cost` checks and integer envelope margins compare exact
values. The Rust API exposes total costs as `u128` and search maxima as exact nonnegative counters.

Commands print lossless JSON with suggested `next` commands. Exported artifacts
(`plan template` and the raw `show` record) omit navigation metadata so another
command can read them unchanged. The old `--full` flag remains a compatibility
no-op.

Run summaries retain exact `virtual_ns`, `guest_ns`, `host_ns` and `sleep_ns`
counters alongside their millisecond conversions. JSON milliseconds are not
rounded for display, and the summary's latency limit uses the same conversion
as the findings detector.

Analysis commands require their run evidence to be stored. A run-cache read or
write error exits 3 before publishing findings. This applies to scaling,
amplification, probes and sweeps; restoring storage permits the analysis to run
normally again. Confirmation also requires every final reproduction run to be
saved before it writes the case and updates the finding. Run and case writers
reserve temporary files exclusively and replace the destination entry by
rename. Existing temporary files are skipped, and case-file symlinks are
replaced without modifying their targets.

A probe that tried nothing says why in `note`: `probe web` and `probe auth` on
an export that takes no HTTP request, `probe auth` where no path turned away a
request without credentials, `probe values` on an app without host functions,
`probe scripts` where no response is HTML with a script.
Those exit 0, and `review` copies the note into its step. A `--fn` that matches
no host function (`probe values`, `probe faults`) checked nothing and exits 3.

## Platform files

A component carries its own WIT. A plain module doesn't: its platform's
`platform.toml` supplies the types and the calling convention, and the app's
manifest names it with `[app] platform` (a bundled name such as `fastly`, or
a path). `appfuzz platform docs` prints the host API reference;
`appfuzz platform check` checks a `platform.toml` against its WIT or witx and
lists functions without a description.

A `wasm32-wasip1` module built with wit-bindgen carries its WIT world in a
`component-type` section. appfuzz makes it a component with the WASI
preview 1 adapter, as Spin and `wasm-tools component new` do, so it needs no
platform file (Spin's `http-rust-p2` template builds this way).

WASI's clocks, streams, files, sockets, random numbers and HTTP run in the
sandbox. Other `wasi:` interfaces, such as `wasi:keyvalue`, `wasi:config` and
`wasi:blobstore`, are services of the platform: each function is a host call
like the platform's own, with generated results that a plan or rules can
replace. `[grants] wasi` grants them like the rest of WASI.

Clock reads and absolute sleep deadlines include fuel spent since the previous
host call. Guest time is synchronized before every call into the host, including
WASI Preview 1 calls and startup code. A zero `ns_per_fuel` disables the fuel
contribution while retaining the small step for each clock read.

Component timer subscriptions register future readiness without moving time.
A pollable's `ready` query is nonblocking. `block` waits only for that pollable;
`poll` waits for the earliest selected timer if nothing is already ready.
Overlapping timers share elapsed time, and unused or dropped subscriptions do
not count as sleeps. Ready streams return immediately alongside timers already
due; duplicate poll entries retain their separate indices.

WASI Preview 1 `poll_oneoff` advances virtual time instead of waiting in real
time. Relative timers and absolute wall or monotonic deadlines wait for the
earliest timer; timers due together may return together. Ready descriptors
return immediately, alongside any timers already due. Descriptor readiness,
errors and event metadata use the same sandbox descriptor table as other WASI
calls, including after close or renumber operations. Invalid subscription
values return WASI errors; invalid memory pointers trap.

Timing limits, host latencies and `ns_per_fuel` must be finite and
non-negative. Start times use real calendar dates (`YYYY-MM-DD`, optionally
followed by `THH:MM[:SS]` and `Z`; a space may replace `T`), from year 0001
through 9999. Invalid dates and times are errors. The signed wall-clock origin
is separate from elapsed time, so dates before 1970 and after 2554 remain usable
for request clock fields, monotonic clocks and timers. Component wall clocks
represent post-epoch dates in their full seconds range. A pre-epoch read that a
component wall-clock ABI cannot represent stops the request with `plan_error`
before guest code resumes; review is incomplete rather than passing under a
substituted epoch date. Preview 1 realtime reads outside their unsigned
nanosecond range return `overflow`, which the guest may handle. Absolute wall
timers keep the signed origin and can wait across the epoch, including waits
longer than `u64` nanoseconds. Virtual nanosecond counters, host latencies and event times
retain exact nonnegative integers, including beyond `u128::MAX`. Ordinary values
use JSON numbers through `u64::MAX`; larger ones use decimal strings. Configured
floating-point rates use their shortest round-tripping decimal representation,
and each charge or fuel product is floored once to whole nanoseconds, without
an intermediate floating-point product. Latency limits and saved resource
checks compare exact nanoseconds. Millisecond views use decimal strings when a
JSON number would round away evidence or exceed its range.

Guest clocks retain their ABI widths: monotonic nanosecond values saturate at
`u64::MAX`; the component wall clock uses its full seconds and nanoseconds range.
Preview 1 realtime reads preserve the SDK's `overflow` error when that wall time
cannot fit in a `u64` nanosecond timestamp. Relative timers and HTTP deadlines continue advancing in
exact internal time after a guest clock saturates. New envelopes retain an
exact `budget.virtual_ns` alongside the approximate `virtual_ms` view; legacy
millisecond budgets remain readable. The Rust API uses `natural::Natural` for
timing fields and search maxima; ordinary counters stay inline, with big integers
used only when necessary.

### wasi:http handlers

A component that exports `wasi:http/incoming-handler` (0.2.x) or
`wasi:http/handler` (0.3) needs no platform file. appfuzz shows the handler
as one function:

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
  response set to an error code is status 500. An aborted response body, or
  returning without finishing a body, is a crash. Bodies are capped at 64 MiB.
- A response already sent remains in `result` when the handler later traps,
  runs out of fuel, or fails while draining pending requests. Fastly responses
  sent before a later failure are retained too. The outcome still records the
  failure, and output checks still inspect the sent response. Ownership checks
  also inspect error pages. A suspected foreign field is changed in a follow-up
  run: if the host actually supplies that changed field with ownership intact
  and the response stays identical, matching static page text is not reported
  as a leaked record.
- For an aborted or unfinished body, `result.body` retains the bytes already
  written and `result.body_complete` is `false`. This is partial client output,
  not a successful completion. Completed responses omit `body_complete`.
- A response body that is not UTF-8 is recorded as a list of bytes (an
  image, a download). It is `invalid_response` (warn) only when the
  `content-type` is text or missing. Trailers appear as `trailers` in the
  result.
- A `content-length` header that differs from the body's size is
  `invalid_response` (fail): the platform cuts the response short or fails
  it, and a proxy may read the rest as the next response. HEAD requests and
  1xx, 204 and 304 responses are exempt.
- Incoming request bodies and simulated host responses are text. An outgoing
  request body is recorded as text when it is valid UTF-8, otherwise as a JSON
  byte array. Plan rules and argument checks see these actual wire values;
  `bytes:a..b` counts the bytes in either form. Text detectors also inspect a
  decoded view of binary outgoing bodies, so binary framing cannot hide secret
  flow, labelled sinks or reviewer-directed text. The original byte array stays
  in the trace and is used for equality and replay.
- Binary body capture checks the remaining trace capacity before allocating
  JSON byte values. Exceeding that reviewer guard is explicitly incomplete
  evidence, never a truncated body reported as a complete run.
- A 0.3 handler is an `async func` (Spin 4's `http-rust` template). It may
  keep writing the response body after `handle` returns; the result holds
  the whole body. appfuzz runs wasi:http 0.3.0, as Spin 4.1 and later do
  (spin-sdk 7). A component built against a 0.3 release candidate (Spin
  4.0's spin-sdk 6) is an error that says to rebuild it with spin-sdk 7. A handler that waits for something nothing will ever
  deliver (a stream nobody writes, its own unfinished body) is a `hang`,
  the same on every run.

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
`{status, headers, body}`. 0.3's `wasi:http/client#send` is the same host
function under the same key: one plan and one manifest section serve both,
and the body the guest streams is read to its end before the call. The call is prepared when the guest probes or waits
for the response, so a body written after `handle` is part of `body`.
Subscriptions only register readiness; `get` returns `none` while pending,
and readiness checks do not advance time. Nonblocking probes leave an open
request body pending and writable; a blocking wait evaluates the bytes written
so far. Requests nobody observed are recorded after the handler returns,
without waiting for their responses.

A request is in flight from `handle` on: it is ready at the virtual time
it was sent plus its latency, and the guest waits only for what is left.
HTTP responses and clock timers participate in the same poll: the earliest
selected deadline wins unless another selected resource is already ready.
Only time spent blocking for a response is charged to `host_ns`.
Requests sent together overlap, so four 60 ms requests awaited together
take 60 ms; awaited one by one, each after the previous answer, they take
240. 0.3 requests, and other async host calls (Spin 4's), overlap the same
way: each answer is ready at the time it was sent plus its latency. A
`first-byte-timeout` in the request options (plus the
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
directory (`-m spin.toml` names it). An `appfuzz.toml` wins, and every
command then carries a `warnings` entry that `spin.toml` is ignored, until one of
them goes or `-m appfuzz.toml` picks it; `--wasm` alone skips `spin.toml`. Only `spin_manifest_version = 2` is read. The
component is `--component NAME`, else the only one with an HTTP trigger,
else the only one. Its `source` must be a local path.

| `spin.toml` | appfuzz |
|-------------|---------|
| `source` | `[app] wasm` |
| `[application] name`, `description` | `[app] name`, `description` |
| HTTP trigger `route` (`/shop/...`) | `[app] base = "/shop"`; the request is `GET https://app.example/shop/` |
| `environment` | `[app] env`: the component's environment variables |
| `allowed_outbound_hosts` | `[grants] hosts`: the host of each entry, `*.example.com` as `example.com` and its subdomains, `*` as any host; `self` and `localhost` are skipped, `{{ var }}` is filled from the component's variables or the entry skipped |
| `[component.X.variables]` | rules on `fermyon:spin/variables#get`, `spin:variables/variables#get` (`name`) and `wasi:config/store#get` (`key`): a variable whose template uses an application variable with `secret = true` has `result = "secret"` and a generated value; one whose template resolves through defaults returns that text; an undeclared name is `undefined` (`ok(none)` for `wasi:config`) |
| `key_value_stores` | rules on `store.open` (`label`) and `wasi:keyvalue/store#open` (`identifier`): any other store is `access-denied` |
| `sqlite_databases` | rules on `connection.open` and `connection.open-async` (`database`): any other database is `access-denied` |

No `[grants] imports` or `wasi`: Spin links all of WASI and its own
interfaces. The limits are appfuzz's defaults. Built-in labels for Spin's
SQL, key-value, Redis and MQTT functions and for `wasi:keyvalue` apply to
every component, with or without `spin.toml`, Spin 3's interfaces and Spin
4's async ones alike.

Generated answers of Spin's SQL queries (SQLite `execute`, PostgreSQL
`query`, MySQL `query`, and their async forms) keep the database's promise:
when the statement is a `SELECT` that names its columns, the answer has
those columns, and every row has one value per column. Column types and
values are still generated; a plan supplies real rows. A plan's or a rule's
answer is used as written.

Spin 4's async functions return `stream<T>` and `future<T>`. In plans, rules
and run records a stream is a list of its items and a future is its value:
`{"return": {"ok": [["id", "name"], [{"values": [...]}], {"ok": null}]}}`
for SQLite's `execute-async`. The app receives them as a real stream and
future.

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
  the run's result. `respond` may name its `streaming` flag parameter and set
  `consume = true` to consume the response and its non-streaming body. Streaming
  writes and appends remain part of the sent body until `close` finishes it;
  `abandon` ends it unsuccessfully. The bundled Fastly bindings declare these
  behaviors. Stream front writes use the binding's `stream_error` status.
- `bad_handle` and `absent`: the error cases for an invalid handle and a
  missing value.
- per function: `description`, `param_docs`, `result_doc`, `sdk`, and
  `fails = false` for calls the SDK treats as infallible (appfuzz then
  injects no failure).

A sent Fastly streaming response captures all bytes written before the run ends.
An abandoned or unfinished stream retains its sent prefix with
`body_complete = false` and fails the run; an earlier guest trap retains its
original classification. Body bytes that are not UTF-8 use JSON byte arrays.
Trailers are recorded when the body completes. Closed or consumed handles stay
invalid, and generated handles remain distinct after an externally supplied
large handle id.

The bundled Fastly platform
([platform.toml](crates/appfuzz-core/platforms/fastly/platform.toml)) uses
Fastly's witx vendored from Viceroy, `values = { method = "format:token",
uri = "format:url" }` on the request, and limits from Fastly's documented
service limits: 128 MiB memory, fuel for about 50 ms of CPU, and a 2-minute
wall-clock latency limit.

### Extism

Plugins initialize their language runtime before input preparation: Haskell's
reactor runs before `hs_init`; other plugins prefer `__wasm_call_ctors` over
`_initialize`. Compatible initialization functions run once per run, under its
fuel and memory limits. Temporary kernel allocations are reset before the input
is prepared, while their peak remains counted. Exports may return an `i32`
status or no value (success); `proc_exit(0)` also succeeds unless an Extism error
is set. Nonzero exits remain failures.

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
JSON, like the PDK's `String`; these bytes must be valid UTF-8. Malformed
string arguments fail before reaching a host function, and malformed string
output fails instead of replacing invalid bytes. Binary values use explicit
byte lists. An export whose WIT result is `result<T, E>`
answers `ok` when its status is 0, and `err` with its `error_set` text
otherwise. Kernel logs show up in `stderr`, and `http_request` traps because
it isn't simulated yet.
