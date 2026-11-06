# Changelog

## Unreleased

**What host calls did**

- Run records say how much each host call returned: `result_items` (list
  length) and `result_bytes` (the whole answer, before long strings are cut),
  with sums in `totals`.
- A call with a `write`, `delete` or `external` effect that took effect
  records a `commit`. With a mutation binding it lists the rows it created,
  changed or deleted, with their contents before and after. `lost` marks
  a change that stayed while the app saw a failure.
- A create mutation can answer with the new key or record: `"$key"` and
  `"$row"` in its `response`.

**Pages, owners and edited worlds**

- Dataset queries can sort (`order`) and return a page at a time:
  `page = { limit, offset | cursor, items, next, max, short, invalid }`.
  Cursors are opaque, and a made-up one gets the platform's `invalid`
  answer. Where pages may be short, a plan sets `page_size`.
- Datasets can say who owns a record (`owner`) and which fields anyone may
  see (`public`). The caller is the request's identity field, else the
  plan's `_defaults.identity`, else the first user records belong to.
- Plans can edit the generated world before a run:
  `_defaults.dataset_edits` with `drop`, `rotate` and `add`. Added records
  get keys above 1,000,000; confirmation shrinks edits like other plan parts.

**Apps that ship JavaScript**

- HTML is read as a browser reads it (the WHATWG parser of Servo,
  `html5ever`): `<noscript>`, SVG `<style>`, tables, templates and
  malformed markup end up where a browser puts them. Deeply nested markup
  falls back to a tag reader, so hostile output can't stall a review.
- `reflection` and `stored_reflection` find text that breaks out of where
  the app put it, not only raw `<`: a quote that ends an attribute, a quote
  that ends a string in a `<script>`, an event handler, a `javascript:` URL
  or a framework expression (`x-data`, `:class`), and text that runs as
  code there. HTML entities don't protect a handler, and JS escapes do.
  `detail.context` says where (`text`, `attribute`, `script`, `handler`,
  `url`, `json`).
- Output label `html:scripts`: scripts may run, and the markup still makes
  no request `html:safe` forbids. Scripts from other hosts need a granted
  host and an `integrity` hash, else `unpinned_script` (fail; a warn on HTML
  without a label). Markup with a script needs a Content-Security-Policy
  that keeps scripts on the app's origin and the granted hosts, else
  `weak_csp` (fail; `'unsafe-eval'` is a warn). The policy comes from the
  response header, a meta tag and the new `[entry] csp`; all apply.
- With output labels the fuzzer also tries text that ends a script string
  or an attribute: `';alert(1)//`, `"-alert(1)-"`, `\';alert(1)//`,
  `</script><script>alert(1)</script>`, `${alert(1)}` and
  `' onmouseover='alert(1)`.

## 0.6.0

**Forged credentials**

- `probe auth`, part of `review`: where a handler turns away a request
  without credentials, it tries a made-up bearer token, `Bearer null`, an
  unsigned JWT, a JWT with a wrong signature, `Basic admin:admin`, a
  made-up API key and session cookies. One that gets a 2xx is
  `auth_bypass` (fail). Paths the fuzzer saw turned away are tried too.
- Where the app checks the token against a secret, `probe auth` sends the
  secret's prefixes. Cost that grows with the correct prefix is
  `timing_unsafe_compare` (warn): the comparison stops at the first wrong
  character.
- Session cookies and token fields that stay the same with other random
  seeds are `predictable_token` (fail), made from the clock or constant.

**Spin**

- Apps that call `wasi:keyvalue` or `wasi:config` (Spin 3, wasmCloud) run:
  each call is a host call that plans and rules answer, the key-value
  labels apply, and `key_value_stores` limits `wasi:keyvalue` stores too.
  Before, the first call was reported as a crash.
- With an `appfuzz.toml` next to `spin.toml`, every command warns that
  `spin.toml` is ignored, so its allowed hosts, stores and secrets don't
  apply. The status names the manifest in use, also `spin.toml`.
- `allowed_outbound_hosts` is enforced: a request to a host no entry allows
  is refused with `http-request-denied`, as on Spin. An `ssrf` whose request
  Spin refused is a warning that names the hosts the client can still pick;
  with no allowed hosts there is none.
- SSRF is found in apps that parse URLs with an SDK (Spin's, or any built
  on the `http` crate): URL sinks are also tried with a URL whose host is
  the canary, which those parsers accept.

**HTTP handlers**

- Outgoing requests answer 200 unless a plan says otherwise (before: 100,
  which sent most handlers down their error path). Review now tests the
  page users see; in the Go bench app it found a crash in wasi-http-go on
  pages over 4 KB.
- `findings` and `appfuzz` (the status) show what `review` found for HTTP
  handlers, Spin apps and `wasi:keyvalue` users; before, they showed none.
- Without a manifest, an app that calls its own API (a host written into
  it) passes: the call is an info finding naming the `[grants] hosts` line
  to add. With grants, a host they don't list is still a fail.

**Checking a fix**

- After a rebuild, `review` runs the inputs of earlier reviews' fail and
  warn findings again and lists each as found again or not. `findings` on
  the new build says it has no review yet, and how many findings earlier
  reviews had.
- `replay <run> --against-current` runs a stored run on the current build
  and says whether its findings show again (exit 2 if one does). Before,
  only case files could, and the error for a run named a flag runs refused.

**Fewer false positives**

- `error_ignored` is not reported when the page was already an error page,
  or the call had already failed.
- `busy_wait` needs a millisecond of spinning on the clock (1000 reads).
  The JavaScript runtime reads it about 30 times per `fetch()`.
- Invisible characters the request sent percent-encoded (`%E2%80%AE` in a
  query) are no `hidden_text` when the page shows them decoded.
- A test string that arrives cut short (`cnry12ab7` without its `'"../`)
  is no `sql_injection`, `path_traversal` or `command_injection` because
  the app's own quote or `;` follows it. Each needs the request or host to
  have sent that character.

**Clearer reports**

- A misspelt function name in `[functions."…"]` or a plan (`db#qeury`,
  `items#get` without its package, `get_many` for `get-many`) is an error
  that names the function meant. Before, its labels and rules did nothing,
  and an app with SQL injection could pass. A plan rule on a parameter the
  function doesn't have is an error too.
- A crash's title and `explain` name the cause ("Buffer too large for
  blocking-write-and-flush", "wasm `unreachable` instruction executed")
  instead of "error while executing at wasm backtrace:".
- `last` is the run a command just showed, also when that run was stored
  before.
- `nested_fan_out` can be confirmed: `confirm` turns both knobs again
  and shrinks the run. Before, it said no predicate reproduces it, and
  `review` was incomplete.
- A confirmed finding points at its shrunk run, so `explain` and the next
  steps of `review` show the small input instead of the one the fuzzer
  found. Shrinking also drops test strings and parts of long text the
  finding doesn't need, and text it doesn't need changed stays as the
  example request has it.
- Findings name where in the request a value came from: "the query
  parameter `url`", a form field, a header, the URL path or host, instead
  of "the request field uri".
- `explain` shows the output around a reflected test string with its
  markup (`<h1>Hello, cnry3b543<i>!</h1>`), and the argument around it for
  SQL, shell, path and URL findings: the evidence, not just the page text.
- `--human` shows a timeline with each host call's arguments in full, so
  the URL or SQL text of a finding is no longer cut off. `--view stack`
  without `--call` says which calls the run made.
- A probe that tried nothing says why: `probe web` on an app that isn't an
  HTTP handler, `probe auth` where no page needs credentials. `probe values
  --fn` naming no function the app calls exits 3, as `probe faults` does.
- A stored run file appfuzz can't read (another version wrote it, or it is
  damaged) is left out with a warning that names it. Before, every command
  that reads stored runs failed on it, and the status showed no runs.
  Warnings are a `warnings` list.
- `appfuzz` alone suggests `review` until this build has had one, before
  the step-by-step commands. `review --help` and AGENTS.md list every step
  review runs, and AGENTS.md lists every finding kind, the experimental
  ones too.

## 0.5.0

**Try it without an app of your own**

- `appfuzz https://…/app.wasm` downloads a Wasm file and reviews it. The
  manifest is the same URL ending in `.toml` (none when it's missing). The
  download goes over https only (`--allow-http` for local servers), has a
  50 MB limit, must start with the Wasm magic, and may only name a bundled
  platform. Runs are kept per URL in your cache folder, not in the current
  one.
- Five demo apps at [appfuzz.dev/demo](https://appfuzz.dev/demo/): an n+1,
  an XSS, two crashes and one that passes. `bench/demo.sh` builds them.

**Readable for people**

- `--human` (or `APPFUZZ_HUMAN=1`) prints every command for a person
  instead of JSON, in color: the verdict, one line per finding, what to run
  next. Without it, output is the same JSON as before. Colors are off when
  the output is not a terminal or `NO_COLOR` is set.

**More kinds of apps**

- HTTP handlers on `wasi:http` 0.2 (Spin, wasmCloud, `wasmtime serve`): the
  request is `{method, uri, headers, body}`, and each outgoing request is a
  simulated host call, with its URL checked for SSRF.
  Requests sent together overlap in time, as they do on the platform, and
  a `first-byte-timeout` is honoured. Binary response bodies (images,
  downloads) and trailers are kept as they are.
- Spin apps need no `appfuzz.toml`: `appfuzz review` next to `spin.toml`
  reads the component, its allowed hosts, secret variables, stores and
  databases (`--component NAME` picks one).
- Extism plugins from any PDK: appfuzz emulates the Extism kernel, and a
  WIT file types the plugin's JSON. Kernel calls are not reported as host
  calls.
- Test apps in Go (TinyGo), JavaScript and C#; seven languages get the
  same findings for the same bug.

**HTTP security checks**

- Text from the request with `../` in the path of an outgoing request
  (`url_path_injection`): it reaches other endpoints of that API.
- CORS that lets any website read a response with the visitor's cookies
  (`permissive_cors`), and links, redirects or outgoing requests built from
  the `Host` header (`host_header_injection`). `review` sends these requests
  itself (`probe web`).
- A `Content-Length` that doesn't match the body is a failed response.

**Fewer false positives**

- Error texts a function marks as written for users (`user_errors`), error
  texts the app echoes, routes, and lists declared `unique` no longer
  produce findings.
- Scaling skips sizes a field's type cannot hold.
- Unused `wasi:filesystem` and `wasi:sockets` imports from the JavaScript,
  Python and Go runtimes are one finding per package, with how to grant
  them. Go's Unicode tables no longer count as hidden text.

## Earlier versions

See the [GitHub releases](https://github.com/StephanSchmidt/appfuzz/releases).
