// Immutable Blob bytes and File metadata, independently of public codecs,
// buffer properties, interface constructors and prototype replacements.
import { eventString, eventDictionary } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { lowerASCII } from './names.js';
const native = globalThis.__native, kind = native.cloneKind, encode = native.encodeUtf8, decode = native.decodeUtf8, base64 = native.encodeBase64;
const NativeTypeError = TypeError, NativeUint8Array = Uint8Array, create = Object.create, define = Object.defineProperty;
const descriptor = Object.getOwnPropertyDescriptor, prototype = Object.getPrototypeOf, apply = Reflect.apply, setPrototype = Object.setPrototypeOf;
const iteratorSymbol = Symbol.iterator, tagSymbol = Symbol.toStringTag;
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
const codeAt = Function.prototype.call.bind(String.prototype.charCodeAt);
const resolve = Promise.resolve.bind(Promise), reject = Promise.reject.bind(Promise), finite = Number.isFinite, trunc = Math.trunc, max = Math.max, min = Math.min;
const typed = prototype(Uint8Array.prototype), typedBuffer = descriptor(typed, 'buffer').get, typedOffset = descriptor(typed, 'byteOffset').get, typedLength = descriptor(typed, 'byteLength').get;
const detached = descriptor(ArrayBuffer.prototype, 'detached').get, resizable = descriptor(ArrayBuffer.prototype, 'resizable').get;
const viewBuffer = descriptor(DataView.prototype, 'buffer').get, viewOffset = descriptor(DataView.prototype, 'byteOffset').get, viewLength = descriptor(DataView.prototype, 'byteLength').get;
const copyBytes = Function.prototype.call.bind(Uint8Array.prototype.set);
const bufferKinds = new Set(['ArrayBuffer', 'DataView', 'Uint8Array', 'Uint8ClampedArray', 'Int8Array', 'Uint16Array', 'Int16Array', 'Uint32Array', 'Int32Array', 'BigInt64Array', 'BigUint64Array', 'Float16Array', 'Float32Array', 'Float64Array']);
const isBuffer = bufferKinds.has.bind(bufferKinds);
// Serializable Blob brands live in this table, separately from the generic
// nonserializable platform-object brand used by structured cloning.
const records = new WeakMap(), save = records.set.bind(records);
export const blobRecord = records.get.bind(records);
let now = () => 0, unsupported = () => {};
export function installBlobPlatform(value) { now = value.now; unsupported = value.unsupported; }
export function requireBlob(value) { const data = blobRecord(value); if (!data) throw new NativeTypeError('A Blob is required'); return data; }
function requireFile(value) { const data = requireBlob(value); if (data.name === undefined) throw new NativeTypeError('A File is required'); return data; }
function list() { const value = []; setPrototype(value, null); return value; }
const usv = value => wellFormed(eventString(value));
function integer64(value) {
  let number = +value;
  if (!finite(number) || number === 0) return 0;
  number = trunc(number) % 18446744073709551616;
  if (number >= 9223372036854775808) number -= 18446744073709551616;
  else if (number < -9223372036854775808) number += 18446744073709551616;
  return number === 0 ? 0 : number;
}
function mime(value) {
  for (let i = 0; i < value.length; i++) if (codeAt(value, i) < 32 || codeAt(value, i) > 126) return '';
  return lowerASCII(value);
}
function convertParts(value, optional) {
  const result = list();
  if (value === undefined && optional) return result;
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) throw new NativeTypeError('Blob parts must be an iterable object');
  const method = value[iteratorSymbol];
  if (typeof method !== 'function') throw new NativeTypeError('Blob parts must be iterable');
  const iterator = apply(method, value, []);
  if (iterator === null || (typeof iterator !== 'object' && typeof iterator !== 'function')) throw new NativeTypeError('Invalid blob iterator');
  const next = iterator.next;
  while (true) {
    const step = apply(next, iterator, []);
    if (step === null || (typeof step !== 'object' && typeof step !== 'function')) throw new NativeTypeError('Invalid blob iterator result');
    if (step.done) return result;
    const part = step.value, blob = blobRecord(part), type = kind(part);
    if (!blob && isBuffer(type)) {
      const buffer = type === 'ArrayBuffer' ? part : apply(type === 'DataView' ? viewBuffer : typedBuffer, part, []);
      if (apply(resizable, buffer, [])) throw new NativeTypeError('Resizable buffer sources are not Blob parts');
    }
    result[result.length] = blob ? { __proto__: null, blob } : isBuffer(type) ? { __proto__: null, buffer: part, type } : { __proto__: null, text: usv(part) };
  }
}
function options(value, file) {
  const bag = value == null ? null : eventDictionary(value), endingsValue = bag === null ? undefined : bag.endings;
  const endings = endingsValue === undefined ? 'transparent' : eventString(endingsValue);
  if (endings !== 'transparent' && endings !== 'native') throw new NativeTypeError('Invalid blob endings');
  const typeValue = bag === null ? undefined : bag.type, type = typeValue === undefined ? '' : eventString(typeValue);
  let modified;
  if (file) { const value = bag === null ? undefined : bag.lastModified; modified = value === undefined ? integer64(now()) : integer64(value); }
  return { endings, type: mime(type), modified };
}
function bufferView(value, type) {
  const view = type === 'DataView', buffer = type === 'ArrayBuffer' ? value : apply(view ? viewBuffer : typedBuffer, value, []);
  if (apply(detached, buffer, [])) return new NativeUint8Array(0);
  if (type === 'ArrayBuffer') return new NativeUint8Array(buffer);
  let offset, length;
  // Only the native out-of-bounds accessors are caught. Allocation failures
  // from constructing the byte view must remain observable.
  try { offset = apply(view ? viewOffset : typedOffset, value, []); length = apply(view ? viewLength : typedLength, value, []); }
  catch { return new NativeUint8Array(0); }
  return new NativeUint8Array(buffer, offset, length);
}

function nativeEndings(value) {
  let result = '';
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '\r') { result += '\n'; if (value[i + 1] === '\n') i++; }
    else result += value[i];
  }
  return result;
}
function process(parts, endings) {
  const chunks = list(); let total = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    let bytes;
    if (part.blob) bytes = part.blob.bytes;
    else if (part.buffer) bytes = bufferView(part.buffer, part.type);
    else bytes = new NativeUint8Array(encode(endings === 'native' ? nativeEndings(part.text) : part.text));
    // No page callbacks run during processing; snapshot these native views
    // together after every argument and dictionary conversion has finished.
    chunks[chunks.length] = bytes; total += byteLength(bytes);
  }
  const bytes = new NativeUint8Array(total); let offset = 0;
  for (let i = 0; i < chunks.length; i++) { copyBytes(bytes, chunks[i], offset); offset += byteLength(chunks[i]); }
  return bytes;
}
function byteLength(bytes) { return apply(typedLength, bytes, []); }
function bufferOf(bytes) { return apply(typedBuffer, bytes, []); }
function data(bytes, type, name = undefined, lastModified = undefined) {
  return { bytes, type, name, lastModified, get text() { return decode(bufferOf(bytes), false); } };
}
function allocate(bytes, type, name = undefined, modified = undefined) {
  const value = create(name === undefined ? blobPrototype : filePrototype);
  save(value, data(bytes, type, name, modified)); return value;
}
export function Blob(parts = undefined, bag = undefined) {
  if (!new.target) throw new NativeTypeError('Blob requires new');
  const converted = runDOMCallback(() => { const values = convertParts(parts, true), opt = options(bag, false); return { bytes: process(values, opt.endings), type: opt.type }; });
  save(this, data(converted.bytes, converted.type));
}
const blobPrototype = Blob.prototype;
define(Blob, 'prototype', { writable: false });
define(blobPrototype, tagSymbol, { configurable: true, value: 'Blob' });
const methods = {
  get size() { return byteLength(requireBlob(this).bytes); },
  get type() { return requireBlob(this).type; },
  text() { try { return resolve(blobText(this)); } catch (error) { return reject(error); } },
  arrayBuffer() { try { return resolve(blobBuffer(this)); } catch (error) { return reject(error); } },
  bytes() { try { return resolve(new NativeUint8Array(blobBuffer(this))); } catch (error) { return reject(error); } },
  slice(start = 0, end = undefined, contentType = '') {
    const record = requireBlob(this);
    const opt = runDOMCallback(() => ({ start: integer64(start), end: end === undefined ? byteLength(record.bytes) : integer64(end), type: mime(eventString(contentType)) }));
    const size = byteLength(record.bytes), from = opt.start < 0 ? max(size + opt.start, 0) : min(opt.start, size), to = opt.end < 0 ? max(size + opt.end, 0) : min(opt.end, size);
    const count = max(to - from, 0), bytes = new NativeUint8Array(count);
    copyBytes(bytes, new NativeUint8Array(bufferOf(record.bytes), from, count)); return allocate(bytes, opt.type);
  },
};
for (const key of ['size', 'type', 'text', 'arrayBuffer', 'bytes', 'slice']) define(blobPrototype, key, descriptor(methods, key));
export function File(parts, name, bag = undefined) {
  if (!new.target) throw new NativeTypeError('File requires new');
  if (arguments.length < 2) throw new NativeTypeError('File requires parts and a name');
  const converted = runDOMCallback(() => { const values = convertParts(parts, false), filename = usv(name), opt = options(bag, true); return { bytes: process(values, opt.endings), name: filename, type: opt.type, modified: opt.modified }; });
  save(this, data(converted.bytes, converted.type, converted.name, converted.modified));
}
const filePrototype = File.prototype;
setPrototype(File, Blob); setPrototype(filePrototype, blobPrototype);
define(File, 'prototype', { writable: false });
define(filePrototype, tagSymbol, { configurable: true, value: 'File' });
const fields = { get name() { return requireFile(this).name; }, get lastModified() { return requireFile(this).lastModified; } };
for (const key of ['name', 'lastModified']) define(filePrototype, key, descriptor(fields, key));
export function blobText(value) { return decode(bufferOf(requireBlob(value).bytes), true); }
export function blobBuffer(value) { const bytes = requireBlob(value).bytes, copy = new NativeUint8Array(byteLength(bytes)); copyBytes(copy, bytes); return bufferOf(copy); }
export function blobDataURL(value) {
  const record = requireBlob(value);
  return 'data:' + (record.type || 'application/octet-stream') + ';base64,' + base64(bufferOf(record.bytes));
}

export function fileFromBlob(value, name) { const record = requireBlob(value); return allocate(record.bytes, record.type, name, record.lastModified === undefined ? integer64(now()) : record.lastModified); }
export function emptyFile() { return allocate(new NativeUint8Array(0), 'application/octet-stream', '', integer64(now())); }
export function cloneBlob(value) { const record = requireBlob(value); return allocate(record.bytes, record.type, record.name, record.lastModified); }
export function blobTransport(value) {
  const record = requireBlob(value), text = record.text, encoded = new NativeUint8Array(encode(text));
  const length = byteLength(encoded);
  let same = length === byteLength(record.bytes);
  for (let i = 0; same && i < length; i++) if (encoded[i] !== record.bytes[i]) same = false;
  if (!same) unsupported('binary Blob body transport');
  return text;
}
