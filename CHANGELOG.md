# Changelog

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
- Extism plugins from any PDK: appfuzz emulates the Extism kernel, and a
  WIT file types the plugin's JSON. Kernel calls are not reported as host
  calls.
- Test apps in Go (TinyGo), JavaScript and C#; seven languages get the
  same findings for the same bug.

**Fewer false positives**

- Error texts a function marks as written for users (`user_errors`), error
  texts the app echoes, routes, and lists declared `unique` no longer
  produce findings.
- Scaling skips sizes a field's type cannot hold.

## Earlier versions

See the [GitHub releases](https://github.com/StephanSchmidt/appfuzz/releases).
