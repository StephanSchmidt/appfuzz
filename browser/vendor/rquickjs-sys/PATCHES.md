# Local QuickJS fixes and browser integration

This is the published `rquickjs-sys` 0.14.0 crate, pinned by the browser's
Cargo.lock. The original registry package checksum and per-file SHA-256 hashes
are in UPSTREAM.json. The upstream rquickjs revision is
`d7ef5eeae702fea24c03643064de454f1c1dd4b0`, directory `sys`.

The JSON change in quickjs/quickjs.c is in json-private-lists.patch:

- Allocate the JSON serializer's cycle stack and replacer property list as
  arrays with null prototypes. They represent internal Lists, so application
  array index setters/getters must not participate in their bookkeeping.
- Check the fallible property-list insertion and propagate its exception.

Public values retain ordinary property access: inherited array elements,
getters, toJSON and replacer callbacks still run. The browser's native runtime
and Wasm component regression suites cover both the private lists and those
observable callbacks, with expected results checked in Chrome and Firefox.

References:
- [ECMAScript JSON.stringify](https://tc39.es/ecma262/multipage/structured-data.html#sec-json.stringify)
- [Published crate](https://crates.io/crates/rquickjs-sys/0.14.0)
- [Upstream source](https://github.com/DelSkayn/rquickjs/tree/d7ef5eeae702fea24c03643064de454f1c1dd4b0/sys)

The upstream MIT licenses are retained: LICENSE for rquickjs, quickjs/LICENSE
for QuickJS, and vendor/wasi-libc/NOTICE.md for the bundled libc. Updating the
runtime requires refreshing UPSTREAM.json, reviewing/reapplying this patch,
and running the native and component regression suites.

The additional string-compilation-hook.patch changes quickjs/quickjs.c,
quickjs/quickjs.h, src/lib.rs and build.rs:

- Keep an embedder callback as a traced, released context root.
- Call it for string eval and every dynamic Function family after argument
  conversion and before parsing, preserving direct eval's lexical environment.
- Pass both the composed function source and its once-converted body string.
- Propagate exceptions from the observer without invoking public page methods.
- Expose the small C API through generated or platform-independent bindings.
- Track the original C/header inputs so Cargo rebuilds the copied C sources
  after a local patch; tracking only OUT_DIR copies leaves stale native code.

The browser uses this port for CSP and code-flow observation. Its private
script/compiler ports continue to use the C evaluation API directly for
already-authorized handlers and timers. The unchanged UPSTREAM.json retains
the published package hashes; these patch files describe local differences.
