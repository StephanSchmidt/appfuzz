// FileReader state and task ownership are private. Page setters, helper
// methods, codec replacements and constructor inheritance cannot select the
// platform algorithm. Public encoding conversion remains observable.
import { requireBlob, blobBytes, blobBuffer, blobDataURL, byteCount, bufferOfBytes } from './blobs.js';
import { EventTarget, initializeEventTarget, fireEvent, getHandler, setHandler } from './event-target.js';
import { ProgressEvent, createNativeUIEvent } from './event-interfaces.js';
import { deserializeDOMException } from './dom-exception.js';
import { eventString } from './event-state.js';
import { mimeCharset } from './mime-types.js';
import { runDOMCallback } from './dom-callbacks.js';
const NativeTypeError = TypeError, NativeProxy = Proxy, create = Object.create, define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor;
const setPrototype = Object.setPrototypeOf, getProperty = Reflect.get, keys = Object.keys, fromCode = String.fromCharCode;
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed), decode = globalThis.__native.decodeFileText;
const states = new WeakMap(), read = states.get.bind(states), save = states.set.bind(states);
let enqueue = () => { throw new NativeTypeError('File reading task queue unavailable'); }, cancel = () => {}, checkpoint = () => {};
export function installFileReaderTasks(queue, remove, microtasks) { enqueue = queue; cancel = remove; checkpoint = microtasks; }
function requireReader(value) { const data = read(value); if (!data) throw new NativeTypeError('A FileReader is required'); return data; }
function exception(name, message, code) { const value = deserializeDOMException({ __proto__: null, name, message, code }); define(value, 'stack', { __proto__: null, value: '', writable: true, configurable: true }); return value; }
const Constructor = function FileReader() { throw new NativeTypeError('FileReader requires new'); };
define(Constructor, 'name', { __proto__: null, value: 'FileReader', configurable: true });
const prototype = Constructor.prototype;
setPrototype(Constructor, EventTarget); setPrototype(prototype, EventTarget.prototype);
define(Constructor, 'prototype', { __proto__: null, writable: false });
// A construct trap reads newTarget.prototype exactly once with the Web IDL
// fallback, including proxy and derived constructors. No public parent runs.
export const FileReader = new NativeProxy(Constructor, { __proto__: null, construct(target, args, newTarget) {
  const requested = runDOMCallback(() => getProperty(newTarget, 'prototype'));
  const value = create(requested !== null && (typeof requested === 'object' || typeof requested === 'function') ? requested : prototype);
  initializeEventTarget(value); save(value, { __proto__: null, state: 0, result: null, error: null, operation: null }); return value;
} });
define(prototype, 'constructor', { __proto__: null, value: FileReader, writable: true, configurable: true });
define(prototype, Symbol.toStringTag, { __proto__: null, value: 'FileReader', configurable: true });
function emit(reader, type, operation, loaded, async = false) {
  const total = operation ? operation.size : 0;
  fireEvent(reader, createNativeUIEvent(ProgressEvent, type, { lengthComputable: operation !== null, loaded, total }), true, null, async ? checkpoint : null);
}
function alive(data, operation) { return data.state === 1 && data.operation === operation; }
function task(data, operation, callback) { operation.task = enqueue(() => { if (alive(data, operation)) { operation.task = null; callback(); } }); }
function packageResult(operation) {
  if (operation.kind === 'buffer') return blobBuffer(operation.blob);
  if (operation.kind === 'data-url') return blobDataURL(operation.blob);
  const bytes = blobBytes(operation.blob);
  if (operation.kind === 'binary') { let result = ''; for (let i = 0; i < operation.size; i++) result += fromCode(bytes[i]); return result; }
  return decode(bufferOfBytes(bytes), operation.encoding, mimeCharset(operation.mime));
}
function start(reader, data, blob, record, kind, encoding = null) {
  if (data.state === 1) throw exception('InvalidStateError', 'A read is already in progress', 11);
  const operation = { __proto__: null, blob, kind, encoding, mime: record.type, size: byteCount(record.bytes), task: null };
  data.state = 1; data.result = data.error = null; data.operation = operation;
  task(data, operation, () => {
    emit(reader, 'loadstart', operation, 0, true);
    if (alive(data, operation)) task(data, operation, () => {
      if (operation.size) emit(reader, 'progress', operation, operation.size, true);
      if (alive(data, operation)) task(data, operation, () => {
        data.state = 2; data.operation = null;
        data.result = packageResult(operation);
        emit(reader, 'load', operation, operation.size, true);
        // A listener or its microtasks may have started another operation.
        if (data.state !== 1) emit(reader, 'loadend', operation, operation.size, true);
      });
    });
  });
}
function input(reader, blob, count) { const data = requireReader(reader); if (!count) throw new NativeTypeError('A Blob is required'); return { __proto__: null, data, record: requireBlob(blob) }; }
const methods = {
  get readyState() { return requireReader(this).state; },
  get result() { return requireReader(this).result; },
  get error() { return requireReader(this).error; },
  readAsText(blob, encoding = undefined) {
    const value = input(this, blob, arguments.length), label = runDOMCallback(() => encoding === undefined ? null : wellFormed(eventString(encoding)));
    start(this, value.data, blob, value.record, 'text', label);
  },
  readAsArrayBuffer(blob) { const value = input(this, blob, arguments.length); start(this, value.data, blob, value.record, 'buffer'); },
  readAsDataURL(blob) { const value = input(this, blob, arguments.length); start(this, value.data, blob, value.record, 'data-url'); },
  readAsBinaryString(blob) { const value = input(this, blob, arguments.length); start(this, value.data, blob, value.record, 'binary'); },
  abort() {
    const data = requireReader(this);
    if (data.state !== 1) { data.result = null; return; }
    const operation = data.operation; if (operation.task !== null) cancel(operation.task);
    data.state = 2; data.result = null; data.operation = null;
    data.error = exception('AbortError', 'The operation was aborted', 20);
    emit(this, 'abort', null, 0);
    if (data.state !== 1) emit(this, 'loadend', null, 0);
  },
};
for (const key of keys(methods)) define(prototype, key, descriptor(methods, key));
for (const [name, value] of [['EMPTY',0],['LOADING',1],['DONE',2]]) {
  define(Constructor, name, { __proto__: null, value, enumerable: true }); define(prototype, name, { __proto__: null, value, enumerable: true });
}
for (const type of ['loadstart','progress','load','abort','error','loadend']) {
  const handlers = { get value() { requireReader(this); return getHandler(this, type); }, set value(value) { requireReader(this); setHandler(this, type, value); } };
  const field = descriptor(handlers, 'value');
  define(field.get, 'name', { __proto__: null, value: 'get on' + type, configurable: true });
  define(field.set, 'name', { __proto__: null, value: 'set on' + type, configurable: true });
  define(prototype, 'on' + type, field);
}
