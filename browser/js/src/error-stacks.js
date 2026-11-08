// QuickJS invokes its debugging hook eagerly on construction and exception
// propagation. Browser V8 hooks are lazy; Firefox ignores prepareStackTrace.
// Keep this extension explicit rather than executing page code at extra sites.
const NativeError = Error, apply = Reflect.apply, define = Object.defineProperty;
const limit = Object.getOwnPropertyDescriptor(NativeError, 'stackTraceLimit');
const prepare = Object.getOwnPropertyDescriptor(NativeError, 'prepareStackTrace');
let traceLimit = apply(limit.get, NativeError, []), formatter = apply(prepare.get, NativeError, []), report = () => {};
export function installStackReporter(value) { report = value; }
define(NativeError, 'stackTraceLimit', { configurable: true, get() { return traceLimit; }, set(value) {
  traceLimit = value;
  // The runtime otherwise coerces an object on every exception and retains its
  // old object limit. Browser limits do not call author conversion functions.
  apply(limit.set, NativeError, [typeof value === 'number' ? value : 0]);
} });
define(NativeError, 'prepareStackTrace', { configurable: true, get() { return formatter; }, set(value) {
  formatter = value;
  if (typeof value === 'function') report('Error.prepareStackTrace');
} });
