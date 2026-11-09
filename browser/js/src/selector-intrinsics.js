// Selector dependencies are browser internals. They operate on private arrays,
// records and captured intrinsics instead of page-modifiable JS prototypes.
import { backendList } from './collection-data.js';
const NativeArray = Array, NativeObject = Object, NativeString = String, NativeNumber = Number, NativeRegExp = RegExp;
const create = Object.create, define = Object.defineProperty, descriptors = Object.getOwnPropertyDescriptors, keys = Reflect.ownKeys, apply = Reflect.apply, construct = Reflect.construct, setPrototype = Object.setPrototypeOf, freeze = Object.freeze, isArray = Array.isArray;
const arrayPrototype = Object.getPrototypeOf(backendList()), strings = create(null), functions = create(null);
for (const [target, source] of [[strings, String.prototype], [functions, Function.prototype]]) { const all = descriptors(source); for (const key of keys(all)) if (key !== 'constructor') define(target, key, all[key]); freeze(target); }
export function privateArray(value) { setPrototype(value, arrayPrototype); return value; }
function result(value) { return isArray(value) ? privateArray(value) : value; }
export function privateCall(name, receiver, ...args) {
  const methods = typeof receiver === 'string' ? strings : typeof receiver === 'function' ? functions : isArray(receiver) ? arrayPrototype : null;
  if (isArray(receiver)) privateArray(receiver);
  return result(apply(methods?.[name] || receiver[name], receiver, args));
}
function copy(target, source, omit = '') { const all = descriptors(source); for (const key of keys(all)) if (key !== 'constructor' && key !== omit && key !== 'prototype' && key !== 'name' && key !== 'length' && key !== 'caller' && key !== 'arguments') { const d = all[key]; if (typeof d.value === 'function') { const fn = d.value; d.value = function (...args) { return result(apply(fn, source, args)); }; } define(target, key, d); } return target; }
export const selectorArray = freeze(copy(function (...args) { return privateArray(construct(NativeArray, args)); }, NativeArray));
export const selectorObject = freeze(copy(function (value) { return NativeObject(value); }, NativeObject));
export const selectorString = freeze(copy(function (value = '') { return NativeString(value); }, NativeString));
export const selectorNumber = freeze(copy(function (value = 0) { return NativeNumber(value); }, NativeNumber));
export const selectorMath = freeze(copy(create(null), Math));
function privateConstructor(Native, iterator = false) {
  const p = create(null), Token = function () {};
  // Instance methods retain their receiver, unlike copied static methods.
  const all = descriptors(Native.prototype); for (const key of keys(all)) if (key !== 'constructor') define(p, key, all[key]);
  if (iterator) for (const key of ['entries', 'keys', 'values', Symbol.iterator]) {
    const method = p[key]; if (typeof method !== 'function') continue;
    const sample = construct(Native, []), proto = Object.getPrototypeOf(apply(method, sample, [])), next = proto.next;
    define(p, key, { __proto__: null, value: function (...args) { const value = apply(method, this, args); return { __proto__: null, next() { const item = apply(next, value, []); if (isArray(item.value)) privateArray(item.value); return item; }, [Symbol.iterator]() { return this; } }; }, writable: true, configurable: true });
  }
  Token.prototype = p;
  const Safe = function (...args) { return construct(Native, args, Token); };
  define(Safe, 'prototype', { __proto__: null, value: p });
  define(p, 'constructor', { __proto__: null, value: Safe });
  copy(Safe, Native); freeze(p); freeze(Safe); return Safe;
}
export const selectorMap = privateConstructor(Map, true), selectorSet = privateConstructor(Set, true), selectorWeakMap = privateConstructor(WeakMap);
export const selectorRegExp = privateConstructor(NativeRegExp);
export function privateRegex(value) { setPrototype(value, selectorRegExp.prototype); return value; }
export const selectorError = Error, selectorTypeError = TypeError;
