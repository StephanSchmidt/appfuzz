// Injected into the DOM bundle, whose tables are browser internals. Page
// changes to the JavaScript WeakMap prototype must not alter DOM behavior.
const NativeWeakMap = globalThis.WeakMap;
class DOMWeakMap extends NativeWeakMap {}
for (const name of ['get', 'set', 'has', 'delete']) {
  Object.defineProperty(DOMWeakMap.prototype, name, { value: NativeWeakMap.prototype[name] });
}
Object.freeze(DOMWeakMap.prototype);
export { DOMWeakMap as WeakMap };
