# Changelog

## Unreleased

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

**Fewer false positives**

- `error_ignored` is not reported when the page was already an error page,
  or the call had already failed.
- `busy_wait` needs a millisecond of spinning on the clock (1000 reads).
  The JavaScript runtime reads it about 30 times per `fetch()`.
- Invisible characters the request sent percent-encoded (`%E2%80%AE` in a
  query) are no `hidden_text` when the page shows them decoded.

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
