# Changelog

## 0.9.0

- `[entry] one_of`: the combinations of request fields the platform
  sends, such as a route and its methods:
  `one_of = [{ handler = "save", "req.method" = "POST" }, …]`. The list is
  closed: a request that is no row has its findings lowered to info. The
  fuzzer starts from every row, so every route is reached. `[[entry.rules]]`
  stay for limits on some requests only.
- `[entry.response]`: a response made from host calls. On a platform
  where the app calls `page#set-html(name, html)` or `page#redirect(path)`
  and returns nothing, the manifest names the calls that set the status,
  body and headers. The run's result is that response, so output labels
  (`html:safe`, `url:local`), `no_pii` and the response checks apply.
- Label paths go into JSON text: `$` reads a string as JSON,
  `result = { "" = "json", "$.email" = "pii" }` for a store of JSON
  records, also in rules by key. Generated records carry the labelled
  fields.
- A parameter takes several labels: `params = { value = ["json", "pii"] }`
  for a store that keeps JSON records with personal data. Personal data
  written there is no `pii_leak` (nor its encoded form an
  `encoded_flow`), and the `json` checks still apply. One label as text
  works as before.
- Label paths go through an option's value in recorded results, where
  some labels were missed before.
- `scale`: copies of a list of numbers count on from the largest, so they
  no longer repeat the template's values.
- A canary's raw `<i>` inside a quoted attribute value whose quote is
  escaped is no longer a `reflection`: there it is text.
- `probe auth`: `Bearer null` that the app passes to a host function
  (which then lets it in) is the host's decision, as with the other
  forged credentials, and no `auth_bypass`.
- `probe values` tries odd values of functions marked `fails = false`
  too; it leaves out only the error.
- wasmtime 50.0.2, with the fixes for RUSTSEC-2026-0566 to 0573: an app
  under test could abort appfuzz or grow its memory without bound.

## 0.8.1

- `[[entry.rules]]`: request fields that go together. A request that
  matches `when` keeps to the rule's `values` too:
  `when = { handler = "save" }`, `values = { "req.method" = "enum:POST" }`.
  The fuzzer keeps to the rules, and a run that breaks one has its
  findings lowered to info, so a GET to a handler only POST reaches is no
  longer a `write_on_safe_method` fail.
- Label and `values` paths name keys in a list of (string, value) pairs,
  and `*` is every key: `result = { "*" = "json" }` labels every value a
  key-value scan returns.
- XML namespaces (`xmlns`, `xmlns:xlink`), microdata types (`itemtype`)
  and the W3C namespace URLs a script passes to `createElementNS` are no
  longer counted as destinations: an inline SVG is no
  `unexpected_destination`.

## 0.8.0

**Manifests**

- `[entry] examples`: more example requests next to `request`. Fuzzing
  starts from all of them; `run --example N` runs one.
- Exports with several parameters: paths in `[entry] fields`, `values`
  and `input_values` start with the parameter's name
  (`fields = { "req.now" = "clock.rfc3339" }`), and `--set '{"req": …}'`
  merges into that argument. A clock field whose path doesn't lead to
  text is an error instead of being ignored.
- New clock role `clock.rfc3339`: `2026-11-15T10:00:00Z`.
- `{ none = true }` is an option's none in `appfuzz.toml`, where TOML has
  no null.
- `sequence run` and `sequence fuzz` take the name of a
  `[sequences.NAME]` as well as a file; `--help` now says so.

**JSON**

- New label `json`. On a parameter, request text that breaks out of a
  JSON string is `json_injection` (fail). On a result, generated values
  are JSON documents, so the app's parser gets past the first character,
  and the fuzzer answers reads with JSON the app wrote under a key of the
  same collection: pages that only read get the records a form wrote.

**Search**

- `probe values` no longer blames a host value for a crash the request
  has without it.

**Apps that ship JavaScript**

- Page scripts run in a browser that follows Firefox and Chrome in many
  more places: events (propagation, default actions, focus and pointer),
  forms and controls (select boxes, number, date and color inputs, file
  selection), fetch and XMLHttpRequest (aborts, headers, binary bodies,
  Blob and File), window messages and message ports, custom elements,
  templates, live DOM collections and CSS selectors.
- The page's Content-Security-Policy holds while its scripts run: scripts,
  `eval` and connections it blocks don't happen, nonces, `integrity` and
  `base-uri` count, and violations fire their events.
- HTML is parsed in steps around blocking scripts, as browsers do: a
  script sees the markup before it, not the markup after it.
- Text checks ignore Leptos's `<!>` markers between text nodes: a page
  that shows "200%" sends "200<!>%", and percentages and check selectors
  now read "200%".
- Input and textarea current values stay separate from defaults and DOM text.
  Edits survive default changes, cloning and adoption, and form resets restore
  defaults while respecting cancellation, form ownership and reset events.

- FormData construction respects form ownership, disabled fieldsets, selected
  options, image buttons, empty file inputs, character sets and directionality.
  Formdata events can adjust the submitted fields without sharing later changes
  with the returned snapshot; invalid and recursive construction is rejected.

- FormData updates preserve field order and keep old values when replacement
  conversion fails. Names, file overloads and live iteration follow browser
  behavior even when page scripts replace public helpers.

- Cookies stay private when page scripts replace collection methods, URL and
  date helpers, serializers, or prototype properties. HttpOnly values cannot
  escape through internal arrays or report snapshots. Public suffix and site
  decisions use the same native parser as appfuzz core.

- Timers use browser argument conversion, callback receivers, cancellation,
  nesting and repeat ordering. Page changes to collection or arithmetic
  helpers cannot disable scheduled work or erase unsupported API markers.
  Date subclasses retain the virtual clock, and timer timestamps and seeded
  randomness no longer depend on replaceable page helpers.

- Page scripts cannot replace the browser driver's private hooks, host bridge,
  or native parser. Replacing JSON functions or adding `toJSON` methods to
  built-in prototypes no longer alters the browser's evidence report.

- URL and query state stays private, including native request routing and
  history origin checks when a page replaces URL accessors. Query iterators
  and callbacks see live changes; Web IDL argument conversion and query body
  serialization follow browser behavior.

## 0.7.0

**Shopify Functions**

- `appfuzz review` next to a `shopify.extension.toml` reviews the function
  the way Shopify runs it, in Rust or JavaScript, after
  `shopify app function build`. appfuzz reads the extension, its
  `schema.graphql` and its input queries. Shopify's JavaScript runtimes
  are downloaded from function-runner's release on first use, checked
  against pinned hashes and cached; nothing of Shopify's is bundled.
- Shopify's limits are findings: instructions, scaled by the cart as
  Shopify scales them and naming the cart size; input, output and log
  sizes; output Shopify would reject, such as a field the schema doesn't
  have or a missing one.
- Carts are ones Shopify could send: amounts from 0, quantities from 1,
  `gid://` ids, real dates. Fuzzing, the default cart and shrinking keep
  to them. A finding on another cart is info, and `explain` says why.
- JavaScript errors name the app's line, as Rust panics do.
- In checks, `out.json` is the function's output under Shopify's names,
  with decimals as numbers. `[shopify]` alone is enough for an
  `appfuzz.toml`.

**Spin 4 and WASI 0.3**

- HTTP handlers on `wasi:http` 0.3 (`wasi:http/handler`, an `async func`)
  are reviewed like 0.2 handlers. Spin 4's `http-rust` template (Spin 4.1
  and later, spin-sdk 7) works as `spin new` makes it: `spin build`, then
  `appfuzz review`. A component built against a 0.3 release candidate
  (Spin 4.0's spin-sdk 6) gets an error that says to rebuild it. Outgoing
  requests through `wasi:http/client#send` are the same host function as
  0.2's, under the same plan key. A handler that waits for something that
  never comes is a `hang`.
- Spin 4's async APIs work: SQLite `execute-async`, PostgreSQL
  `query-async`, MySQL, key-value `get-keys`. Their streams and futures are
  lists and values in plans and run records; the app receives real ones.
  The built-in SQL, key-value and Redis labels cover them.
- Async host calls sent together overlap in virtual time, as they would in
  production: two 60 ms requests awaited together take 60 ms.
- `wasm32-wasip1` modules built with wit-bindgen (Spin 3's `http-rust-p2`
  template) are made components with the WASI preview 1 adapter, as Spin
  does.
- Generated answers of Spin's SQL queries have the columns the `SELECT`
  names and one value per column in each row, so an app that looks up a
  column by name gets past it.
- `spin.toml`'s `environment` sets the component's environment variables;
  in `appfuzz.toml` it is `[app] env`.

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

**Tenant isolation**

- New finding `tenant_leak`: the answer, or the arguments of a change,
  differ when only other users' records differ. A pair check rotates the
  private fields of records whose dataset `owner` is someone else (and,
  without `public` fields, drops half and adds one). Status or headers
  alone are a warn. `shared = true` on a changing function exempts its
  arguments.
- `missing_owner_check` also covers writes: a mutation binding that
  changes or deletes a record whose dataset `owner` is not the caller is a
  fail. Creates and functions declared `shared = true` are not checked.

**Records per response**

- `[limits] records_per_response` (and `max_per_response` per dataset)
  says how many records one response may carry.
- New `probe records`, part of `review`: gives each collection one record
  more than the limit and twice the limit, marks every record and counts
  how many leave in the response, the logs and calls that send data away.
  Request fields such as `?limit=` then ask for 1,000,000.
- New finding `mass_disclosure`: more records than the limit in one
  place (fail). Without a limit, a request that sends out all 1,024
  records is a warn when they hold `pii` or `secret` data, else info.
- New dataset edit `tag`: marks each record's text fields with a token
  made from its key.

**Cookies, logs and plain HTTP**

- New finding `insecure_cookie`: a session cookie set without `HttpOnly`
  or `Secure` (fail). CSRF cookies, which scripts must read, are exempt.
- New finding `log_injection`: request text with a line break reaches the
  log as it came, so a request can add log lines of its own (warn).
- New finding `cleartext_transport`: a `secret` or `pii` value goes to a
  plain `http://` URL off the platform's network (fail).

**OWASP**

- Security findings carry `standards`: their CWE, OWASP Top 10 (2025)
  category and OWASP API Security Top 10 (2023) category. The Top 10
  category follows from OWASP's published CWE lists.
- `review` reports `owasp`: per Top 10 category, findings, the checks
  that ran, the checks that need labels the manifest lacks (by reason),
  and what is up to the platform. `--human` prints it as a table.
- New OWASP.md: what appfuzz checks per category.

**Pagination**

- New finding `broken_pagination` (fail): rows between two pages the app
  read that it never read, the first page again before the last one, or
  another answer when a platform with `page.short = true` returns pages of 1
  or one less than asked. The page checks run on every run; the shorter
  pages are a pair check in `probe pairs` and fuzzing.

**Unbounded reads**

- New finding `unbounded_read`: the app reads every row of a host list while
  its answer stays the same size. `scale` drops the first, middle and last row
  to see whether every row counts, and names the paged query that would read
  less. Scale points report `rows` per function and `host_result_bytes`.

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

**Search and shrinking**

- The fuzzer changes a request's shape by its WIT type: it empties a
  list, cuts it to one item, adds one, or switches an option. Empty lists
  and missing options get tried for every app.
- `probe times` no longer blames the clock for a crash that happens at
  every time.
- Shrinking builds its candidates as it needs them: a big request no
  longer takes gigabytes.

**Install**

- Static Linux builds (`x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl`) run on Alpine and on Linux older than
  Ubuntu 22.04 or Debian 12. `install.sh` picks them there.
- `install.sh` runs the binary before it installs it: one that can't run
  never replaces one that works. As root it installs to `/usr/local/bin`,
  and its last lines are commands that work as printed, with the full path
  when the directory is not on PATH.

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
