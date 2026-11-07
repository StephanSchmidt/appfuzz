// A Headers object owns a private ordered list and a guard. Public helpers
// can be replaced by a page without changing native copying or routing.
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const records = new WeakMap(), get = records.get.bind(records), save = records.set.bind(records);
const iteratorRecords = new WeakMap(), getIterator = iteratorRecords.get.bind(iteratorRecords), saveIterator = iteratorRecords.set.bind(iteratorRecords);
const NativeTypeError = TypeError, apply = Reflect.apply, create = Object.create, define = Object.defineProperty;
const ownKeys = Reflect.ownKeys, descriptor = Object.getOwnPropertyDescriptor, iteratorSymbol = Symbol.iterator;
const charCode = Function.prototype.call.bind(String.prototype.charCodeAt), slice = Function.prototype.call.bind(String.prototype.slice);
const lower = Function.prototype.call.bind(String.prototype.toLowerCase), upper = Function.prototype.call.bind(String.prototype.toUpperCase);
const sort = Function.prototype.call.bind(Array.prototype.sort);
const token = c => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 33 || (c >= 35 && c <= 39) || c === 42 || c === 43 || c === 45 || c === 46 || c === 94 || c === 95 || c === 96 || c === 124 || c === 126;
const object = value => value !== null && (typeof value === 'object' || typeof value === 'function');
function requireHeaders(value) { const result = get(value); if (!result) throw new NativeTypeError('A Headers object is required'); return result; }
function byteString(value) {
  const result = eventString(value);
  for (let i = 0; i < result.length; i++) if (charCode(result, i) > 255) throw new NativeTypeError('A ByteString is required');
  return result;
}
function trim(value, newlines = false) {
  const space = c => c === 9 || c === 32 || (newlines && (c === 10 || c === 13));
  let first = 0, last = value.length;
  while (first < last && space(charCode(value, first))) first++;
  while (last > first && space(charCode(value, last - 1))) last--;
  return slice(value, first, last);
}
function validName(name) {
  if (!name.length) throw new NativeTypeError('Invalid header name');
  for (let i = 0; i < name.length; i++) if (!token(charCode(name, i))) throw new NativeTypeError('Invalid header name');
  return lower(name);
}
function validValue(value) { for (let i = 0; i < value.length; i++) { const c = charCode(value, i); if (c === 0 || c === 10 || c === 13) throw new NativeTypeError('Invalid header value'); } }
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
export function convertHeadersInit(init) {
  return runDOMCallback(() => {
    if (!object(init)) throw new NativeTypeError('Header initialization must be an object');
    const method = init[iteratorSymbol];
    if (method != null) return sequence(init, method, pair => {
      if (!object(pair)) throw new NativeTypeError('A header pair requires an iterable object');
      return sequence(pair, pair[iteratorSymbol], byteString);
    });
    const pairs = [], keys = ownKeys(init);
    for (let i = 0; i < keys.length; i++) if (descriptor(init, keys[i])?.enumerable) {
      const name = byteString(keys[i]), value = byteString(init[keys[i]]); pairs[pairs.length] = [name, value];
    }
    return pairs;
  });
}
const forbiddenNames = new Set('accept-charset accept-encoding access-control-request-headers access-control-request-method connection content-length cookie cookie2 date dnt expect host keep-alive origin referer set-cookie te trailer transfer-encoding upgrade via'.split(' '));
const forbiddenName = forbiddenNames.has.bind(forbiddenNames);
const safeNames = new Set(['accept','accept-language','content-language','content-type']), safeName = safeNames.has.bind(safeNames);
function forbiddenMethod(value) {
  let start = 0, quoted = false, escaped = false;
  for (let i = 0; i <= value.length; i++) {
    const c = i < value.length ? charCode(value, i) : -1;
    if (quoted) { if (escaped) escaped = false; else if (c === 92) escaped = true; else if (c === 34) quoted = false; }
    else if (c === 34) quoted = true;
    if (i === value.length || (c === 44 && !quoted)) {
      const method = upper(trim(slice(value, start, i)));
      if (method === 'CONNECT' || method === 'TRACE' || method === 'TRACK') return true;
      start = i + 1;
    }
  }
  return false;
}
function forbiddenRequest(name, value) {
  return forbiddenName(name) || slice(name, 0, 6) === 'proxy-' || slice(name, 0, 4) === 'sec-'
    || ((name === 'x-http-method' || name === 'x-http-method-override' || name === 'x-method-override') && forbiddenMethod(value));
}
function unsafeByte(c) { return (c < 32 && c !== 9) || c === 34 || c === 40 || c === 41 || c === 58 || c === 60 || c === 62 || c === 63 || c === 64 || (c >= 91 && c <= 93) || c === 123 || c === 125 || c === 127; }
function safeValue(name, value) {
  if (!safeName(name) || value.length > 128) return false;
  if (name === 'accept-language' || name === 'content-language') {
    for (let i = 0; i < value.length; i++) { const c = charCode(value, i); if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 32 || c === 42 || c === 44 || c === 45 || c === 46 || c === 59 || c === 61)) return false; }
    return true;
  }
  for (let i = 0; i < value.length; i++) if (unsafeByte(charCode(value, i))) return false;
  if (name === 'accept') return true;
  let slash = -1, end = value.length;
  for (let i = 0; i < value.length; i++) { if (value[i] === ';') { end = i; break; } if (value[i] === '/' && slash < 0) slash = i; }
  let essence = trim(slice(value, 0, end), true);
  if (slash < 1 || slash >= essence.length - 1) return false;
  // Parsing a MIME type allows trailing whitespace after the subtype.
  for (let i = 0; i < essence.length; i++) if (i !== slash && !token(charCode(essence, i))) return false;
  essence = lower(essence);
  return essence === 'application/x-www-form-urlencoded' || essence === 'multipart/form-data' || essence === 'text/plain';
}
function valueFor(state, name) {
  let value = null;
  for (let i = 0; i < state.list.length; i++) if (state.list[i][0] === name) value = value === null ? state.list[i][1] : value + ', ' + state.list[i][1];
  return value;
}
function allowed(state, name, value) {
  validName(name); validValue(value);
  if (state.guard === 'immutable') throw new NativeTypeError('Headers are immutable');
  if (state.guard === 'request' && forbiddenRequest(name, value)) return false;
  if (state.guard === 'response' && (name === 'set-cookie' || name === 'set-cookie2')) return false;
  return true;
}
function remove(state, name) {
  let length = 0;
  for (let i = 0; i < state.list.length; i++) if (state.list[i][0] !== name) state.list[length++] = state.list[i];
  state.list.length = length; state.pairs = null;
}
function mutate(headers, rawName, rawValue, kind) {
  const state = requireHeaders(headers), name = lower(rawName), value = trim(rawValue, true);
  if (!allowed(state, name, value)) return;
  if (state.guard === 'request-no-cors') {
    const old = kind === 'append' ? valueFor(state, name) : null;
    if (!safeValue(name, old === null ? value : old + ', ' + value)) return;
  }
  if (kind === 'set') {
    let first = -1, length = 0;
    for (let i = 0; i < state.list.length; i++) {
      const entry = state.list[i];
      if (entry[0] === name) { if (first >= 0) continue; first = length; state.list[length++] = [name, value]; }
      else state.list[length++] = entry;
    }
    state.list.length = length;
    if (first < 0) state.list[state.list.length] = [name, value];
  } else state.list[state.list.length] = [name, value];
  state.pairs = null;
  if (state.guard === 'request-no-cors') remove(state, 'range');
}
export function headersFromConverted(pairs, guard = 'none') {
  const headers = create(Headers.prototype); save(headers, { guard, list: [], pairs: null });
  for (let i = 0; i < pairs.length; i++) {
    if (pairs[i].length !== 2) throw new NativeTypeError('A header pair requires two values');
    mutate(headers, pairs[i][0], pairs[i][1], 'append');
  }
  return headers;
}
export function headerValue(headers, name) { return valueFor(requireHeaders(headers), name); }
export function appendNativeHeader(headers, name, value) { mutate(headers, name, value, 'append'); }
export function setHeadersGuard(headers, guard) { requireHeaders(headers).guard = guard; }
export function copyHeaders(headers, guard) {
  const source = requireHeaders(headers), result = create(Headers.prototype), list = [];
  for (let i = 0; i < source.list.length; i++) list[i] = [source.list[i][0], source.list[i][1]];
  save(result, { guard: guard === undefined ? source.guard : guard, list, pairs: null }); return result;
}
export function filterHeaders(headers, guard) { return headersFromConverted(requireHeaders(headers).list, guard); }
export function headerPairs(headers) {
  const state = requireHeaders(headers); if (state.pairs) return state.pairs;
  const names = [], result = [];
  for (let i = 0; i < state.list.length; i++) {
    const name = state.list[i][0]; let exists = false;
    for (let j = 0; j < names.length; j++) if (names[j] === name) exists = true;
    if (!exists) names[names.length] = name;
  }
  sort(names);
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    if (name === 'set-cookie') { for (let j = 0; j < state.list.length; j++) if (state.list[j][0] === name) result[result.length] = [name, state.list[j][1]]; }
    else result[result.length] = [name, valueFor(state, name)];
  }
  state.pairs = result; return result;
}
export function headerObject(headers) {
  const result = create(null), pairs = headerPairs(headers);
  for (let i = 0; i < pairs.length; i++) result[pairs[i][0]] = pairs[i][1];
  return result;
}
class HeaderIterator {
  constructor(headers, kind) { requireHeaders(headers); saveIterator(this, { headers, kind, index: 0 }); }
  next() {
    const state = getIterator(this); if (!state) throw new NativeTypeError('A Headers iterator is required');
    const pairs = headerPairs(state.headers);
    if (state.index >= pairs.length) return { value: undefined, done: true };
    const pair = pairs[state.index++]; return { value: state.kind === 'keys' ? pair[0] : state.kind === 'values' ? pair[1] : [pair[0], pair[1]], done: false };
  }
  [Symbol.iterator]() { return this; }
}
define(HeaderIterator.prototype, Symbol.toStringTag, { configurable: true, value: 'Headers Iterator' });
export class Headers {
  constructor(init) {
    const pairs = init === undefined ? [] : convertHeadersInit(init);
    save(this, { guard: 'none', list: [], pairs: null });
    for (let i = 0; i < pairs.length; i++) { if (pairs[i].length !== 2) throw new NativeTypeError('A header pair requires two values'); mutate(this, pairs[i][0], pairs[i][1], 'append'); }
  }
  append(name, value) {
    requireHeaders(this); if (arguments.length < 2) throw new NativeTypeError('append requires a name and value');
    const converted = runDOMCallback(() => [byteString(name), byteString(value)]); mutate(this, converted[0], converted[1], 'append');
  }
  set(name, value) {
    requireHeaders(this); if (arguments.length < 2) throw new NativeTypeError('set requires a name and value');
    const converted = runDOMCallback(() => [byteString(name), byteString(value)]); mutate(this, converted[0], converted[1], 'set');
  }
  delete(name) {
    const state = requireHeaders(this); if (!arguments.length) throw new NativeTypeError('delete requires a name');
    name = runDOMCallback(() => byteString(name)); name = lower(name);
    if (!allowed(state, name, '')) return;
    if (state.guard === 'request-no-cors' && !safeName(name) && name !== 'range') return;
    if (valueFor(state, name) === null) return;
    remove(state, name); if (state.guard === 'request-no-cors') remove(state, 'range');
  }
  get(name) { const state = requireHeaders(this); if (!arguments.length) throw new NativeTypeError('get requires a name'); name = runDOMCallback(() => byteString(name)); return valueFor(state, validName(name)); }
  has(name) { const state = requireHeaders(this); if (!arguments.length) throw new NativeTypeError('has requires a name'); name = runDOMCallback(() => byteString(name)); return valueFor(state, validName(name)) !== null; }
  getSetCookie() { const state = requireHeaders(this), result = []; for (let i = 0; i < state.list.length; i++) if (state.list[i][0] === 'set-cookie') result[result.length] = state.list[i][1]; return result; }
  forEach(callback, receiver) {
    requireHeaders(this); if (typeof callback !== 'function') throw new NativeTypeError('forEach requires a callback');
    let index = 0;
    while (true) { const pairs = headerPairs(this); if (index >= pairs.length) return; const pair = pairs[index++]; runDOMCallback(() => apply(callback, receiver, [pair[1], pair[0], this])); }
  }
  entries() { return new HeaderIterator(this, 'entries'); }
  keys() { return new HeaderIterator(this, 'keys'); }
  values() { return new HeaderIterator(this, 'values'); }
  [Symbol.iterator]() { return new HeaderIterator(this, 'entries'); }
}
define(Headers.prototype, Symbol.toStringTag, { configurable: true, value: 'Headers' });
