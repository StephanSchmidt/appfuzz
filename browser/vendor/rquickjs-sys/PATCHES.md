# Local QuickJS JSON fix

This is the published `rquickjs-sys` 0.14.0 crate, pinned by the browser's
Cargo.lock. The original registry package checksum and per-file SHA-256 hashes
are in UPSTREAM.json. The upstream rquickjs revision is
`d7ef5eeae702fea24c03643064de454f1c1dd4b0`, directory `sys`.

Only quickjs/quickjs.c differs from the published crate. The complete change is
json-private-lists.patch:

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
