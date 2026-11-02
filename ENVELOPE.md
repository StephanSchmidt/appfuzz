# The runtime envelope, version 1

A review only sees the runs it made. Code that waits for a date, a rare
value or a flag the author flips later does something no review run did.
The envelope writes down what the reviewed app was seen to do, so a
platform can hold it to that in production.

```sh
appfuzz review --time 2m          # make the runs
appfuzz envelope                  # envelope.json from every stored run
appfuzz envelope check <trace>    # a production trace against it
```

`envelope check` prints `outside_envelope` findings and a verdict. The exit
code is 0 for pass, 1 for warn and 2 for fail, as with `review`.

## What it records

From every stored run of the component (`runs`), keyed by its hash
(`component`):

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
| `function` | fail | a host function no reviewed run called |
| `destination` | fail | a destination of the app's own that no reviewed run named for this function |
| `output_destination` | fail | the output fires a request to a destination of its own that no reviewed output did |
| `script` | fail | a script in the output, where no reviewed output had one |
| `destination_from_input` | warn | a destination taken from input, where reviewed runs only named fixed ones |
| `site` | warn | a host call from code no reviewed run called it from |
| `calls` | warn | more than `margin × max_calls` calls to one function |
| `budget` | warn | more than `margin ×` the most fuel, cost, latency or memory |

A new call site is a warn, not a fail: requests the fuzzer never made can
reach ordinary code. A new destination named by the app itself is a fail:
nothing the user or the host did explains it.

## Traces

A trace is one request as the platform saw it, as JSON. Every field may be
left out:

```json
{
  "export": "acme:web/handler#handle",
  "args": [{"method": "GET", "path": "/", "query": [], "form": []}],
  "events": [
    {"func": "acme:web/http#fetch", "args": {"url": "https://api.example.com/v1"},
     "result": {"ok": "…"}, "stack": [{"module": "m1a2b3c", "func": 57}]}
  ],
  "result": {"status": 200, "body": "<p>…</p>", "headers": []},
  "stdout": "", "stderr": "",
  "totals": {"fuel": 412000, "cost": 1, "virtual_ns": 4000000, "peak_memory": 1179648}
}
```

`events` are the host calls in order, with arguments by parameter name and
WIT-shaped JSON as in host plans. `result` is the export's result, read
through the manifest's `[entry] output`. `stack` holds guest frames,
innermost first, with the module ids appfuzz uses (`appfuzz wasm info`);
without it the `site` check is skipped. Without `totals` the `budget` check
is skipped. A stored run (`appfuzz show <run>`) is a trace too, so
`envelope check last` works.

## In a platform

`appfuzz-core` has the checks as a library, for a platform that wants to
enforce the envelope per call rather than after the request:

```rust
use appfuzz_core::envelope::{Envelope, Trace};

let env: Envelope = serde_json::from_str(&std::fs::read_to_string("envelope.json")?)?;
let r = trace.to_record();
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
  is outside it, even when it is fine. Run `review` longer or add runs with
  `run --set` before writing the envelope.
- It does not keep state across requests: a trace is one request.
- A destination built from input (`destinations_from_input`) is allowed
  wherever reviewed runs did the same; the `ssrf` and `open_redirect`
  checks look at those during review.
