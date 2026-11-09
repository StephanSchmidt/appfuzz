// Web IDL construction: one public prototype lookup, then the captured
// native initializer. A private newTarget carries that prototype through JS
// allocation without another page getter or a public parent constructor.
import { runDOMCallback } from './dom-callbacks.js';
const NativeProxy = Proxy, NativeTypeError = TypeError, define = Object.defineProperty, get = Reflect.get, construct = Reflect.construct;
const object = value => value !== null && (typeof value === 'object' || typeof value === 'function');
export function constructorPrototype(newTarget, fallback) { const value = runDOMCallback(() => get(newTarget, 'prototype')); return object(value) ? value : fallback; }
export function constructorMetadata(C, name, length = undefined) {
  define(C, 'name', { __proto__: null, value: name, configurable: true });
  if (length !== undefined) define(C, 'length', { __proto__: null, value: length, configurable: true });
  define(C, 'prototype', { __proto__: null, writable: false }); return C;
}
export function platformConstructor(Implementation, name, length = undefined, illegal = false) {
  constructorMetadata(Implementation, name, length);
  const prototype = Implementation.prototype, Token = function () {};
  define(Token, 'prototype', { __proto__: null, value: prototype, writable: true });
  const value = new NativeProxy(Implementation, { __proto__: null, construct(target, args, newTarget) {
    if (illegal) throw new NativeTypeError('Illegal ' + name + ' constructor');
    // This wrapper's own prototype is immutable data. Other newTargets may
    // be author proxies and must retain their observable Get operation.
    const selected = newTarget === value ? prototype : constructorPrototype(newTarget, prototype);
    const previous = Token.prototype; Token.prototype = selected;
    // Base initializers allocate their receiver before argument callbacks.
    // Reentrant construction restores the outer selection, and finally drops
    // the page's prototype reference even when conversion throws.
    try { return construct(Implementation, args, Token); } finally { Token.prototype = previous; }
  } });
  define(prototype, 'constructor', { __proto__: null, value, writable: true, configurable: true }); return value;
}
