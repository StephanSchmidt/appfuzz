# Experimental runtime envelope, version 2

A review only sees the runs it made. Code that waits for a date, a rare
value or a flag the author flips later does something no review run did.
The envelope writes down what the reviewed app was seen to do, so a
platform can hold it to that in production.

```sh
appfuzz review --time 2m          # make the runs
appfuzz envelope --review <id>    # envelope.json from that accepted session
appfuzz envelope check <trace>    # a production trace against it
```

`envelope check` prints `outside_envelope` findings and a verdict. The exit
code is 0 for pass, 1 for warn, 2 for fail, and 3 for incomplete evidence or
configuration errors. This feature is experimental.

Creation requires a complete passing review of the current component and
platform contract. `--allow-warnings` explicitly changes the acceptance policy
to pass-or-warn; failed and incomplete reviews are always rejected. `--review`
defaults to the latest review. Exploratory runs after a review do not widen its
envelope. The artifact records its review id, contract fingerprint, component
hash and acceptance policy. Rebuild it after changing the app or contract.

Observed behavior is not automatically approved behavior: acceptance is based
on the selected review's verdict and the platform's explicit warning policy.
The platform must still enforce its manifest's hard limits and permissions;
the envelope's relative thresholds never replace those controls.

## What it records

From the runs recorded in the selected accepted review session (`runs`), bound
to the component hash (`component`) and effective platform contract (`contract`):

| Field | Means |
|-------|-------|
| `functions.<f>.max_calls` | the most calls to `f` in one run |
| `functions.<f>.sites` | call sites: the innermost guest frames (`module:func>…`, up to 3) that called `f` |
| `functions.<f>.destinations` | `host:port` the app's own code named in the arguments of `f` |
| `functions.<f>.destinations_from_input` | some argument named a destination taken from the request or the host |
| `functions.<f>.effect` | the manifest's effect label |
| `output.destinations` | `host:port` the output fires requests to (loads, forms, redirects, script URLs), from the app's own code |
| `output.destinations_from_input` | the output fired a request to a destination from input |
| `output.scripts` | a script appeared in some output |
| `budget` | the most `fuel`, `cost`, `virtual_ms`, `memory` and `host_calls` of one run |
| `margin` | how far above `max_calls` and `budget` a trace may go (2.0) |
| `unreached` | host call sites in the code that no run reached |

A destination is "the app's own" when neither the request nor an earlier
host result holds its host. Destinations are read the way the rest of
appfuzz reads URLs: absolute URLs anywhere in a text, whole values that
look like a URL or host, and, for parameters labelled `url`, the whole
value.

## What leaves it

| `detail.what` | Severity | Means |
|---------------|----------|-------|
| `evidence` | fail | the library received an incomplete execution or capture; the CLI reports incomplete evidence with exit code 3 |
| `production_budget` | fail | execution stopped with a measured production-budget violation |
| `function` | fail | a host function no reviewed run called |
| `destination` | fail | a destination of the app's own that no reviewed run named for this function |
| `output_destination` | fail | the output fires a request to a destination of its own that no reviewed output did |
| `script` | fail | a script in the output, where no reviewed output had one |
| `destination_from_input` | warn | a destination taken from input, where reviewed runs only named fixed ones |
| `output_destination_from_input` | warn | an output request takes its destination from input, where reviewed outputs only named fixed ones |
| `site` | warn | a host call from code no reviewed run called it from |
| `calls` | warn | more than `margin × max_calls` calls to one function |
| `budget` | warn | more than `margin ×` the most fuel, cost, latency, memory or total host calls |

Zero is an observed budget too: using a resource no reviewed run used is
outside the envelope. Each budget is checked independently, including when
the trace reports zero fuel.
Integer budgets compare against the margin without rounding through floating
point. Cost budgets may exceed `u64::MAX`; such values use decimal strings in
JSON, while smaller budgets remain numbers.

A new call site is a warn, not a fail: requests the fuzzer never made can
reach ordinary code. A new destination named by the app itself is a fail:
nothing the user or the host did explains it.

## Traces

A trace is one complete request as the platform saw it. CLI checks require
component and contract identity, export, events, totals, and the response when
the manifest defines an output body. Missing evidence is an error, not a pass.
Use the component and contract fingerprints recorded in the envelope:

```json
{
  "component": "<component hash from envelope>",
  "contract": "<contract fingerprint from envelope>",
  "export": "acme:web/handler#handle",
  "args": [{"method": "GET", "path": "/", "query": [], "form": []}],
  "events": [
    {"func": "acme:web/http#fetch", "args": {"url": "https://api.example.com/v1"},
     "result": {"ok": "…"}, "stack": [{"module": "m1a2b3c", "func": 57}]}
  ],
  "result": {"status": 200, "body": "<p>…</p>", "headers": []},
  "stdout": "", "stderr": "",
  "totals": {"fuel": 412000, "cost": 1, "virtual_ns": 4000000, "peak_memory": 1179648,
    "guest_ns": 0, "host_ns": 4000000, "sleep_ns": 0, "host_calls": 1,
    "clock_reads": 0, "random_bytes": 0, "wall_us": 0}
}
```

`events` are the host calls in order, with arguments by parameter name and
WIT-shaped JSON as in host plans. `result` is the export's result, read
through the manifest's `[entry] output`. `stack` holds guest frames,
innermost first, with the module ids appfuzz uses (`appfuzz wasm info`);
without it the `site` check is skipped. Totals are required for CLI checks;
use complete `Totals` fields as emitted by `show`, including zero-valued
counters. Build or contract mismatches cannot pass. A stored run (`appfuzz show <run>`) is a trace too, so
`envelope check last` works.

The optional `guest_error` field retains explicit guest failure text for run
detectors, including leak, encoded-flow and reviewer-directed-text checks. The
optional `outcome` preserves execution status and diagnostics when reading a
stored run as a trace. Without an explicit outcome, nonempty guest error text
indicates a failed request.
The optional `rejected_output` byte list preserves a completed guest return
that failed output decoding. Run detectors inspect its raw text and decoded
JSON strings, including keys. Trace conversion preserves the original bytes;
without an explicit outcome, this field indicates a failed request.
The optional `memory_limit_hit` flag preserves a denial by the run's memory
cap. A guest may handle it successfully, so the flag alone does not imply a
failed or incomplete request.
`capture_limited = true` marks a prefix retained after a reviewer resource guard
stopped the run. Trace conversion preserves this marker and the original error;
it cannot represent a complete successful execution. Such traces cannot pass
an envelope check.

Every event must name its function and include its argument object (use `{}`
for a function with no arguments), and the event count must equal
`totals.host_calls`. A declared output body must be present as text or bytes;
empty text and empty byte lists are valid bodies.

## In a platform

`appfuzz-core` has the checks as a library, for a platform that wants to
enforce the envelope per call rather than after the request:

```rust
use appfuzz_core::envelope::{Envelope, Trace};

let env: Envelope = serde_json::from_str(&std::fs::read_to_string("envelope.json")?)?;
let r = trace.to_record();
// Verify build/contract identity before enforcing individual calls.
assert_eq!(r.spec.component, env.component);
assert_eq!(r.spec.contract, env.contract);
assert_eq!(manifest.fingerprint(), env.contract);
for i in 0..r.events.len() {
    for v in env.check_call(&r, i, &manifest) { /* deny or log v */ }
}
let v = env.check_output(&r, &manifest);
let v = env.check_budget(&r.totals);
let findings = env.check(&r, &manifest);   // all of it, as outside_envelope findings
```

`check_call` looks at call `i` with the calls before it, so a platform can
call it before it runs the host function and refuse the call.

## What it does not do

- It is only as wide as the review. Behaviour the review never triggered
  is outside it, even when it is fine. Run a new review with a longer budget or
  a representative `--request` / `--plan`, then select that accepted session.
- It does not keep state across requests: a trace is one request.
- A destination built from input (`destinations_from_input`) is allowed
  wherever reviewed runs did the same; the `ssrf` and `open_redirect`
  checks look at those during review.
