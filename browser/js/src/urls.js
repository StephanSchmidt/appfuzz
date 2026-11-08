import { markPlatform } from './platform-state.js';
// URL records and query lists are platform slots. Public JavaScript fields,
// accessors and serializers never participate in their native algorithms.
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const native = globalThis.__native, parse = native.url, update = native.urlSet;
const formParse = native.formParse, formSerialize = native.formSerialize;
const NativeTypeError = TypeError, apply = Reflect.apply, create = Object.create, define = Object.defineProperty;
const ownKeys = Reflect.ownKeys, descriptor = Object.getOwnPropertyDescriptor;
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
const slice = Function.prototype.call.bind(String.prototype.slice), sort = Function.prototype.call.bind(Array.prototype.sort);
const iteratorSymbol = Symbol.iterator;
const urls = new WeakMap(), getURL = urls.get.bind(urls), storeURL = urls.set.bind(urls), saveURL = (value, data) => { markPlatform(value); storeURL(value, data); };
const params = new WeakMap(), getParams = params.get.bind(params), storeParams = params.set.bind(params), saveParams = (value, data) => { markPlatform(value); storeParams(value, data); };
const iterators = new WeakMap(), getIterator = iterators.get.bind(iterators), saveIterator = iterators.set.bind(iterators);
const object = value => value !== null && (typeof value === 'object' || typeof value === 'function');
const usv = value => wellFormed(eventString(value));
const parts = ['href','origin','protocol','username','password','host','hostname','port','pathname','search','hash'];
function requireURL(value) { const state = getURL(value); if (!state) throw new NativeTypeError('A URL is required'); return state; }
function requireParams(value) { const state = getParams(value); if (!state) throw new NativeTypeError('URLSearchParams is required'); return state; }
function required(count, min) { if (count < min) throw new NativeTypeError('Not enough arguments'); }
function parseQuery(value) { return formParse(value[0] === '?' ? slice(value, 1) : value); }
function sequence(value, method, convert) {
  if (!object(value) || typeof method !== 'function') throw new NativeTypeError('A sequence requires an iterable object');
  const iterator = apply(method, value, []);
  if (!object(iterator)) throw new NativeTypeError('Invalid iterator');
  const next = iterator.next, result = [];
  while (true) {
    const step = apply(next, iterator, []);
    if (!object(step)) throw new NativeTypeError('Invalid iterator result');
    if (step.done) return result;
    result[result.length] = convert(step.value);
  }
}
function convertInit(init) {
  if (!object(init)) return parseQuery(usv(init));
  const method = init[iteratorSymbol];
  if (method != null) {
    const list = sequence(init, method, pair => {
      if (!object(pair)) throw new NativeTypeError('A query pair requires an iterable object');
      return sequence(pair, pair[iteratorSymbol], usv);
    });
    // Web IDL converts the entire sequence before URL checks pair lengths.
    for (let i = 0; i < list.length; i++) if (list[i].length !== 2) throw new NativeTypeError('A query pair requires two values');
    return list;
  }
  const list = [], keys = ownKeys(init);
  for (let i = 0; i < keys.length; i++) if (descriptor(init, keys[i])?.enumerable) {
    const key = usv(keys[i]), value = usv(init[keys[i]]);
    let existing = -1;
    for (let j = 0; j < list.length; j++) if (list[j][0] === key) existing = j;
    if (existing < 0) list[list.length] = [key, value]; else list[existing][1] = value;
  }
  return list;
}
function sync(state) {
  if (state.url) setURLPart(state.url, 'search', formSerialize(state.list), true);
}
export function urlPart(url, key) { const state = requireURL(url); for (let i = 0; i < parts.length; i++) if (parts[i] === key) return state.parts[i]; }
export function setURLPart(url, key, value, fromParams = false) {
  const state = requireURL(url);
  value = runDOMCallback(() => usv(value));
  const result = update(state.parts[0], key, value);
  if (!result) throw new NativeTypeError('Invalid URL');
  state.parts = result;
  if (state.query && !fromParams && (key === 'href' || key === 'search')) requireParams(state.query).list = parseQuery(result[9]);
}
export const isSearchParams = value => getParams(value) !== undefined;
export function serializeParams(value) { const state = getParams(value); return state ? formSerialize(state.list) : null; }
class ParamsIterator {
  constructor(target, kind) { markPlatform(this); requireParams(target); saveIterator(this, { target, kind, index: 0 }); }
  next() {
    const state = getIterator(this); if (!state) throw new NativeTypeError('A URLSearchParams iterator is required');
    const list = requireParams(state.target).list;
    if (state.index >= list.length) return { value: undefined, done: true };
    const pair = list[state.index++];
    return { value: state.kind === 'key' ? pair[0] : state.kind === 'value' ? pair[1] : [pair[0], pair[1]], done: false };
  }
  [Symbol.iterator]() { return this; }
}
define(ParamsIterator.prototype, Symbol.toStringTag, { configurable: true, value: 'URLSearchParams Iterator' });
export class URLSearchParams {
  constructor(init = '') { const list = runDOMCallback(() => convertInit(init)); saveParams(this, { list, url: null }); }
  get size() { return requireParams(this).list.length; }
  append(name, value) {
    const state = requireParams(this); required(arguments.length, 2);
    const pair = runDOMCallback(() => [usv(name), usv(value)]); state.list[state.list.length] = pair; sync(state);
  }
  delete(name, value = undefined) {
    const state = requireParams(this); required(arguments.length, 1);
    const converted = runDOMCallback(() => [usv(name), value === undefined ? undefined : usv(value)]); name = converted[0]; value = converted[1];
    let length = 0;
    for (let i = 0; i < state.list.length; i++) { const pair = state.list[i]; if (pair[0] !== name || (value !== undefined && pair[1] !== value)) state.list[length++] = pair; }
    state.list.length = length; sync(state);
  }
  get(name) {
    const state = requireParams(this); required(arguments.length, 1); name = runDOMCallback(() => usv(name));
    for (let i = 0; i < state.list.length; i++) if (state.list[i][0] === name) return state.list[i][1];
    return null;
  }
  getAll(name) {
    const state = requireParams(this); required(arguments.length, 1); name = runDOMCallback(() => usv(name));
    const result = []; for (let i = 0; i < state.list.length; i++) if (state.list[i][0] === name) result[result.length] = state.list[i][1]; return result;
  }
  has(name, value = undefined) {
    const state = requireParams(this); required(arguments.length, 1);
    const converted = runDOMCallback(() => [usv(name), value === undefined ? undefined : usv(value)]); name = converted[0]; value = converted[1];
    for (let i = 0; i < state.list.length; i++) if (state.list[i][0] === name && (value === undefined || state.list[i][1] === value)) return true;
    return false;
  }
  set(name, value) {
    const state = requireParams(this); required(arguments.length, 2);
    const converted = runDOMCallback(() => [usv(name), usv(value)]); name = converted[0]; value = converted[1];
    let first = -1, length = 0;
    for (let i = 0; i < state.list.length; i++) {
      const pair = state.list[i];
      if (pair[0] === name) { if (first >= 0) continue; first = length; pair[1] = value; }
      state.list[length++] = pair;
    }
    state.list.length = length;
    if (first < 0) state.list[state.list.length] = [name, value]; sync(state);
  }
  sort() { const state = requireParams(this); sort(state.list, (a,b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0); sync(state); }
  forEach(callback, thisArg = undefined) {
    const state = requireParams(this); required(arguments.length, 1);
    if (typeof callback !== 'function') throw new NativeTypeError('A callback is required');
    for (let i = 0; i < state.list.length; i++) { const pair = state.list[i]; runDOMCallback(() => apply(callback, thisArg, [pair[1], pair[0], this])); }
  }
  entries() { return new ParamsIterator(this, 'pair'); }
  keys() { return new ParamsIterator(this, 'key'); }
  values() { return new ParamsIterator(this, 'value'); }
  toString() { return formSerialize(requireParams(this).list); }
}
define(URLSearchParams.prototype, iteratorSymbol, { configurable: true, writable: true, value: URLSearchParams.prototype.entries });
define(URLSearchParams.prototype, Symbol.toStringTag, { configurable: true, value: 'URLSearchParams' });
function parsed(input, base, count) {
  required(count, 1);
  const converted = runDOMCallback(() => [usv(input), base === undefined ? null : usv(base)]);
  return parse(converted[0], converted[1]);
}
function initialize(url, parts) { saveURL(url, { parts, query: null }); return url; }
let makeObjectURL, revokeObjectURL;
export function setObjectURLHooks(make, revoke) { makeObjectURL = make; revokeObjectURL = revoke; }
export class URL {
  constructor(input, base = undefined) {
    const result = parsed(input, base, arguments.length); if (!result) throw new NativeTypeError('Invalid URL'); initialize(this, result);
  }
  get searchParams() {
    const state = requireURL(this);
    if (!state.query) { state.query = new URLSearchParams(state.parts[9]); requireParams(state.query).url = this; }
    return state.query;
  }
  toString() { return requireURL(this).parts[0]; }
  toJSON() { return requireURL(this).parts[0]; }
  static canParse(input, base = undefined) { return !!parsed(input, base, arguments.length); }
  static parse(input, base = undefined) { const result = parsed(input, base, arguments.length); return result ? initialize(create(URL.prototype), result) : null; }
  static createObjectURL(blob) { required(arguments.length, 1); return makeObjectURL(blob); }
  static revokeObjectURL(value) { required(arguments.length, 1); revokeObjectURL(runDOMCallback(() => usv(value))); }
}
for (let i = 0; i < parts.length; i++) define(URL.prototype, parts[i], {
  configurable: true, enumerable: true, get() { return requireURL(this).parts[i]; },
  set: i === 1 ? undefined : function(value) { setURLPart(this, parts[i], value); },
});
define(URL.prototype, Symbol.toStringTag, { configurable: true, value: 'URL' });

// Web IDL members are enumerable; the constructor and iterator symbol are not.
for (const prototype of [URL.prototype, URLSearchParams.prototype, ParamsIterator.prototype]) {
  for (const key of ownKeys(prototype)) if (typeof key === 'string' && key !== 'constructor') define(prototype, key, { ...descriptor(prototype, key), enumerable: true });
}
for (const key of ['canParse','parse','createObjectURL','revokeObjectURL']) define(URL, key, { ...descriptor(URL, key), enumerable: true });
