import { platformConstructor } from './constructors.js';
import './error-stacks.js';
// Keep the runtime's native DOMException slots, getters, constants and stack.
// The adapter supplies Web IDL's prototype fallback and preserves Error identity
// without exposing native API construction to mutable page constructors.
import { runDOMCallback } from './dom-callbacks.js';
const NativeDOMException = globalThis.DOMException, NativeTypeError = TypeError;
const construct = Reflect.construct, prototype = Object.getPrototypeOf, setPrototype = Object.setPrototypeOf;
const define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor, keys = Reflect.ownKeys;
const nativeIsError = Error.isError, nativeBrand = globalThis.__native.isDOMException;
// Deserialization must allocate a native error without creating a fresh stack.
// Native DOMException constructors eagerly build stacks in this runtime. Clones
// use a native Error allocation plus private DOMException serialization slots;
// the public branded getters accept both native allocation kinds.
const copies = new WeakMap(), copyFor = copies.get.bind(copies), saveCopy = copies.set.bind(copies);
const call = Reflect.apply, allocateError = globalThis.__native.allocateError;
const nativeFields = { name: descriptor(NativeDOMException.prototype, 'name').get,
  message: descriptor(NativeDOMException.prototype, 'message').get, code: descriptor(NativeDOMException.prototype, 'code').get };
export function serializedDOMException(value) {
  const data = copyFor(value);
  if (data) return data;
  if (!nativeBrand(value)) return null;
  return { name: call(nativeFields.name, value, []), message: call(nativeFields.message, value, []), code: call(nativeFields.code, value, []) };
}
export function deserializeDOMException(data) {
  const value = allocateError(NativeDOMException.prototype);
  saveCopy(value, data); return value;
}
const fields = { get name() { const data = copyFor(this); return data ? data.name : call(nativeFields.name, this, []); },
  get message() { const data = copyFor(this); return data ? data.message : call(nativeFields.message, this, []); },
  get code() { const data = copyFor(this); return data ? data.code : call(nativeFields.code, this, []); } };
for (const key of ['name', 'message', 'code']) define(NativeDOMException.prototype, key, descriptor(fields, key));
export const isError = { isError(value) { return nativeIsError(value) || nativeBrand(value); } }.isError;
define(Error, 'isError', { value: isError, writable: true, configurable: true });
export let DOMException = function DOMException(message = '', name = 'Error') {
  if (!new.target) throw new NativeTypeError('DOMException requires new');
  // Ordinary construction resolves new.target.prototype before conversion.
  // Reuse the selected prototype without another public getter.
  const target = prototype(this);
  const result = runDOMCallback(() => construct(NativeDOMException, [message, name]));
  setPrototype(result, target);
  return result;
}
define(DOMException, 'name', { value: 'DOMException', configurable: true });
const proto = NativeDOMException.prototype;
define(DOMException, 'prototype', { value: proto, writable: false });
DOMException = platformConstructor(DOMException, 'DOMException');
define(proto, 'constructor', { value: DOMException, writable: true, configurable: true });
for (const key of keys(NativeDOMException)) if (key !== 'name' && key !== 'length' && key !== 'prototype') define(DOMException, key, descriptor(NativeDOMException, key));
