// XMLHttpRequest state, routing and pending work belong to the platform.
// Author properties and prototype helpers never select the native algorithm.
import { platformConstructor } from './constructors.js';
import { EventTarget, initializeEventTarget, fireEvent, getHandler, setHandler } from './event-target.js';
import { createNativeEvent, eventString } from './event-state.js';
import { ProgressEvent, createNativeUIEvent } from './event-interfaces.js';
import { deserializeDOMException } from './dom-exception.js';
import { headersFromConverted, appendNativeHeader, headerValue, headerObject, headerPairs } from './headers.js';
import { blobFromBytes, bufferOfBytes, byteCount, copyBytesBuffer, decodeBytes, textBytes } from './blobs.js';
import { extractMime, mimeCharset, normalizeMime, utf8Mime } from './mime-types.js';
import { runDOMCallback } from './dom-callbacks.js';
const native = globalThis.__native, parseURL = native.url, updateURL = native.urlSet, decodeText = native.decodeXHRText;
const NativeTypeError = TypeError, create = Object.create, define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor, ownKeys = Reflect.ownKeys;
const setPrototype = Object.setPrototypeOf, finite = Number.isFinite, trunc = Math.trunc, max = Math.max;
const codeAt = Function.prototype.call.bind(String.prototype.charCodeAt), slice = Function.prototype.call.bind(String.prototype.slice);
const upper = Function.prototype.call.bind(String.prototype.toUpperCase), lower = Function.prototype.call.bind(String.prototype.toLowerCase);
const indexOf = Function.prototype.call.bind(String.prototype.indexOf);
const emptyBytes = textBytes('');
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed), parseJSON = JSON.parse;
const records = new WeakMap(), read = records.get.bind(records), save = records.set.bind(records);
const uploads = new WeakSet(), isUpload = uploads.has.bind(uploads), addUpload = uploads.add.bind(uploads);
let hooks;
export function installXHRPlatform(value) { hooks = value; }
function requireXHR(value) { const data = read(value); if (!data) throw new NativeTypeError('An XMLHttpRequest is required'); return data; }
function requireTarget(value) { if (!read(value) && !isUpload(value)) throw new NativeTypeError('An XMLHttpRequestEventTarget is required'); }
function exception(name, message, code) { const value = deserializeDOMException({ __proto__: null, name, message, code }); define(value, 'stack', { __proto__: null, value: '', writable: true, configurable: true }); return value; }
const invalid = () => exception('InvalidStateError', 'The request is in an invalid state', 11);
const syntax = () => exception('SyntaxError', 'Invalid request syntax', 12);
const access = () => exception('InvalidAccessError', 'Synchronous Window requests do not support this setting', 15);
function required(count, min) { if (count < min) throw new NativeTypeError('Not enough arguments'); }
function byteString(value) { const result = eventString(value); for (let i = 0; i < result.length; i++) if (codeAt(result, i) > 255) throw new NativeTypeError('A ByteString is required'); return result; }
const usv = value => wellFormed(eventString(value));
function uint(value) { const number = +value; return finite(number) && number ? ((trunc(number) % 4294967296) + 4294967296) % 4294967296 : 0; }
const token = c => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 33 || (c >= 35 && c <= 39) || c === 42 || c === 43 || c === 45 || c === 46 || c === 94 || c === 95 || c === 96 || c === 124 || c === 126;
function validMethod(value) { if (!value.length) return false; for (let i = 0; i < value.length; i++) if (!token(codeAt(value, i))) return false; return true; }
function emptyResponse(data) { data.answer = null; data.bytes = null; data.object = null; data.packaged = false; }
function stop(data) { const op = data.operation; if (op) { if (op.task !== null) hooks.cancel(op.task); if (op.deadline !== null) hooks.cancel(op.deadline); if (op.uploadTask !== null) hooks.cancel(op.uploadTask); data.operation = null; } }
function current(data, op) { return data.operation === op && data.sending; }
function event(target, type, async = false) { fireEvent(target, createNativeEvent(type), true, null, async ? hooks.checkpoint : null); }
function progress(target, type, loaded = 0, total = 0, async = false) { fireEvent(target, createNativeUIEvent(ProgressEvent, type, { lengthComputable: total > 0, loaded, total }), true, null, async ? hooks.checkpoint : null); }
function fail(target, data, type, async = false) {
  const op = data.operation; stop(data); data.state = 4; data.sending = false; emptyResponse(data);
  if (data.sync) throw exception(type === 'timeout' ? 'TimeoutError' : type === 'abort' ? 'AbortError' : 'NetworkError', 'The request failed', type === 'timeout' ? 23 : type === 'abort' ? 20 : 19);
  event(target, 'readystatechange', async);
  if (op && !op.uploadComplete) { op.uploadComplete = true; progress(data.upload, type, 0, 0, async); progress(data.upload, 'loadend', 0, 0, async); }
  progress(target, type, 0, 0, async); progress(target, 'loadend', 0, 0, async);
}
function deadline(target, data, op) {
  if (op.deadline !== null) { hooks.cancel(op.deadline); op.deadline = null; }
  if (data.timeout && current(data, op)) op.deadline = hooks.enqueue(() => { op.deadline = null; if (current(data, op)) fail(target, data, 'timeout', true); }, max(0, data.timeout - (hooks.now() - op.start)));
}
function length(answer) { const value = answer.headers['content-length']; if (value == null || !value.length) return 0; for (let i = 0; i < value.length; i++) if (codeAt(value, i) < 48 || codeAt(value, i) > 57) return 0; const n = +value; return finite(n) ? n : 0; }
function finish(target, data, op, answer) {
  if (!current(data, op)) return;
  if (answer.error != null || !answer.status) { fail(target, data, 'error', true); return; }
  hooks.receive(answer);
  if (!hooks.responseAllowed(answer.url)) { fail(target, data, 'error', true); return; }
  data.answer = answer;
  const noBody = data.method === 'HEAD' || answer.status === 204 || answer.status === 205 || answer.status === 304;
  const bytes = noBody ? null : answer.body, loaded = bytes === null ? 0 : byteCount(bytes), total = length(answer);
  if (!data.sync) {
    data.state = 2; event(target, 'readystatechange', true); if (!current(data, op) || data.state !== 2) return;
    data.bytes = bytes;
    if (loaded) { data.state = 3; event(target, 'readystatechange', true); if (!current(data, op) || data.state !== 3) return; }
    progress(target, 'progress', loaded, total, true); if (!current(data, op)) return;
  } else data.bytes = bytes;
  stop(data); data.state = 4; data.sending = false;
  event(target, 'readystatechange', !data.sync);
  progress(target, 'load', loaded, total, !data.sync); progress(target, 'loadend', loaded, total, !data.sync);
}
function responseMIME(data) { return data.answer ? extractMime(data.answer.headers['content-type'] ?? null) || 'text/xml' : 'text/xml'; }
function finalMIME(data) { return data.mime ?? responseMIME(data); }
function xmlMIME(mime) { const end = indexOf(mime, ';'), essence = end < 0 ? mime : slice(mime, 0, end); return essence === 'text/xml' || essence === 'application/xml' || slice(essence, -4) === '+xml'; }
function decoded(data, document = false) {
  const label = (data.mime === null ? null : mimeCharset(data.mime)) ?? mimeCharset(responseMIME(data));
  return decodeText(bufferOfBytes(data.bytes), label, xmlMIME(finalMIME(data)) && (document || data.type === ''), document);
}
function text(data) { return data.bytes === null ? '' : decoded(data).text; }

function documentResponse(data) {
  if (!data.packaged) {
    data.packaged = true;
    const mime = finalMIME(data), end = indexOf(mime, ';'), essence = end < 0 ? mime : slice(mime, 0, end);
    if (data.bytes !== null && (essence === 'text/html' ? data.type === 'document' : essence === 'text/xml' || essence === 'application/xml' || slice(essence, -4) === '+xml')) { const value = decoded(data, essence !== 'text/html'); if (value.valid) data.object = hooks.document(value.text, essence, data.answer.url, value.encoding); }
  }
  return data.object;
}
export let XMLHttpRequestEventTarget = class XMLHttpRequestEventTarget { constructor() { throw new NativeTypeError('Illegal constructor'); } };
setPrototype(XMLHttpRequestEventTarget, EventTarget); setPrototype(XMLHttpRequestEventTarget.prototype, EventTarget.prototype);
XMLHttpRequestEventTarget = platformConstructor(XMLHttpRequestEventTarget, 'XMLHttpRequestEventTarget', 0, true);
export let XMLHttpRequestUpload = class XMLHttpRequestUpload { constructor() { throw new NativeTypeError('Illegal constructor'); } };
setPrototype(XMLHttpRequestUpload, XMLHttpRequestEventTarget); setPrototype(XMLHttpRequestUpload.prototype, XMLHttpRequestEventTarget.prototype);
XMLHttpRequestUpload = platformConstructor(XMLHttpRequestUpload, 'XMLHttpRequestUpload', 0, true);
const uploadPrototype = XMLHttpRequestUpload.prototype;
export let XMLHttpRequest = class XMLHttpRequest {
  constructor() {
    initializeEventTarget(this); const upload = create(uploadPrototype); initializeEventTarget(upload); addUpload(upload);
    save(this, { __proto__: null, state: 0, sending: false, sync: false, timeout: 0, credentials: false, upload, method: null, url: null,
      headers: headersFromConverted([], 'request'), operation: null, answer: null, bytes: null, object: null, packaged: false, type: '', mime: null });
  }
  get readyState() { return requireXHR(this).state; }
  get upload() { return requireXHR(this).upload; }
  get status() { return requireXHR(this).answer?.status ?? 0; }
  get statusText() { const a = requireXHR(this).answer; return a?.statusText ?? (a?.status === 200 ? 'OK' : ''); }
  get responseURL() { const url = requireXHR(this).answer?.url; if (!url) return ''; const hash = indexOf(url, '#'); return hash < 0 ? url : slice(url, 0, hash); }
  get timeout() { return requireXHR(this).timeout; }
  set timeout(value) { const data = requireXHR(this); value = runDOMCallback(() => uint(value)); if (data.sync) throw access(); data.timeout = value; if (data.operation) deadline(this, data, data.operation); }
  get withCredentials() { return requireXHR(this).credentials; }
  set withCredentials(value) { const data = requireXHR(this); if (data.state > 1 || data.sending) throw invalid(); data.credentials = !!value; }
  get responseType() { return requireXHR(this).type; }
  set responseType(value) {
    const data = requireXHR(this); value = runDOMCallback(() => eventString(value));
    if (value !== '' && value !== 'text' && value !== 'json' && value !== 'arraybuffer' && value !== 'blob' && value !== 'document') return;
    if (data.state === 3 || data.state === 4) throw invalid(); if (data.sync) throw access(); data.type = value;
  }
  get responseText() { const data = requireXHR(this); if (data.type !== '' && data.type !== 'text') throw invalid(); return data.state === 3 || data.state === 4 ? text(data) : ''; }
  get responseXML() { const data = requireXHR(this); if (data.type !== '' && data.type !== 'document') throw invalid(); return data.state === 4 ? documentResponse(data) : null; }
  get response() {
    const data = requireXHR(this);
    if (data.type === '' || data.type === 'text') return data.state === 3 || data.state === 4 ? text(data) : '';
    if (data.state !== 4 || !data.answer) return null;
    if (data.type === 'document') return documentResponse(data);
    if (!data.packaged) {
      data.packaged = true;
      if (data.type === 'arraybuffer') data.object = copyBytesBuffer(data.bytes ?? emptyBytes);
      else if (data.type === 'blob') data.object = blobFromBytes(data.bytes ?? emptyBytes, finalMIME(data));
      else if (data.bytes !== null) { try { data.object = parseJSON(decodeBytes(data.bytes)); } catch { data.object = null; } }
    }
    return data.object;
  }
  open(method, url, async = undefined, username = null, password = null) {
    const data = requireXHR(this); required(arguments.length, 2);
    const converted = runDOMCallback(() => ({ __proto__: null, method: byteString(method), url: usv(url), async: arguments.length < 3 ? true : !!async, username: username == null ? null : usv(username), password: password == null ? null : usv(password) }));
    method = converted.method; if (!validMethod(method)) throw syntax(); const normalized = upper(method);
    if (normalized === 'CONNECT' || normalized === 'TRACE' || normalized === 'TRACK') throw exception('SecurityError', 'Forbidden request method', 18);
    if (normalized === 'DELETE' || normalized === 'GET' || normalized === 'HEAD' || normalized === 'OPTIONS' || normalized === 'POST' || normalized === 'PUT') method = normalized;
    let parsed = parseURL(converted.url, hooks.base()); if (!parsed) throw syntax();
    if (converted.username !== null) parsed = updateURL(parsed[0], 'username', converted.username);
    if (converted.password !== null) parsed = updateURL(parsed[0], 'password', converted.password);
    if (!converted.async && (data.timeout || data.type)) throw access();
    stop(data); data.sending = false; data.method = method; data.url = parsed[0]; data.sync = !converted.async; data.headers = headersFromConverted([], 'request'); emptyResponse(data);
    if (data.state !== 1) { data.state = 1; event(this, 'readystatechange'); }
  }
  setRequestHeader(name, value) {
    const data = requireXHR(this); required(arguments.length, 2);
    const converted = runDOMCallback(() => ({ __proto__: null, name: byteString(name), value: byteString(value) }));
    if (data.state !== 1 || data.sending) throw invalid();
    try { appendNativeHeader(data.headers, converted.name, converted.value); } catch { throw syntax(); }
  }
  getResponseHeader(name) { const data = requireXHR(this); required(arguments.length, 1); name = runDOMCallback(() => lower(byteString(name))); return data.answer ? data.answer.headers[name] ?? null : null; }
  getAllResponseHeaders() {
    const data = requireXHR(this); if (!data.answer) return '';
    const pairs = headerPairs(headersFromConverted(hooks.entries(data.answer.headers), 'response')); let result = '';
    for (let i = 0; i < pairs.length; i++) result += pairs[i][0] + ': ' + pairs[i][1] + '\r\n'; return result;
  }
  overrideMimeType(mime) {
    const data = requireXHR(this); required(arguments.length, 1); mime = runDOMCallback(() => eventString(mime));
    if (data.state === 3 || data.state === 4) throw invalid(); data.mime = normalizeMime(mime) || 'application/octet-stream';
  }
  send(body = null) {
    const data = requireXHR(this), converted = runDOMCallback(() => hooks.convertBody(body));
    if (data.state !== 1 || data.sending) throw invalid();
    const extracted = data.method === 'GET' || data.method === 'HEAD' ? { __proto__: null, bytes: null, type: null } : hooks.extractBody(converted);
    const contentType = headerValue(data.headers, 'content-type');
    if (contentType !== null && (converted.kind === 'text' || converted.kind === 'params' || converted.kind === 'document')) {
      const next = utf8Mime(contentType);
      if (next !== contentType) { const headers = headerObject(data.headers); headers['content-type'] = next; data.headers = headersFromConverted(hooks.entries(headers), 'request'); }
    } else if (extracted.type && contentType === null) appendNativeHeader(data.headers, 'content-type', extracted.type);
    const op = { __proto__: null, start: hooks.now(), task: null, deadline: null, uploadTask: null, uploadComplete: extracted.bytes === null, uploadSize: extracted.bytes === null ? 0 : byteCount(extracted.bytes) };
    data.sending = true; data.operation = op;
    if (!data.sync) {
      progress(this, 'loadstart'); if (!current(data, op)) return;
      if (!op.uploadComplete) { progress(data.upload, 'loadstart', 0, op.uploadSize); if (!current(data, op)) return; }
    }
    const answer = hooks.respond(data.method, data.url, extracted.bytes, headerObject(data.headers), 'xhr', data.credentials ? 'include' : 'same-origin', true);
    if (data.sync) { finish(this, data, op, answer); return; }
    if (!op.uploadComplete) op.uploadTask = hooks.enqueue(() => {
      op.uploadTask = null; if (!current(data, op)) return;
      progress(data.upload, 'progress', op.uploadSize, op.uploadSize, true); if (!current(data, op)) return; op.uploadComplete = true;
      progress(data.upload, 'load', op.uploadSize, op.uploadSize, true); progress(data.upload, 'loadend', op.uploadSize, op.uploadSize, true);
    }, 0);
    op.task = hooks.enqueue(() => { op.task = null; if (current(data, op)) finish(this, data, op, answer); }, answer.latency);
    deadline(this, data, op);
  }
  abort() {
    const data = requireXHR(this);
    if ((data.state === 1 && data.sending) || data.state === 2 || data.state === 3) fail(this, data, 'abort'); else stop(data);
    if (data.state === 4) { data.state = 0; emptyResponse(data); }
  }
};
setPrototype(XMLHttpRequest, XMLHttpRequestEventTarget); setPrototype(XMLHttpRequest.prototype, XMLHttpRequestEventTarget.prototype);
XMLHttpRequest = platformConstructor(XMLHttpRequest, 'XMLHttpRequest', 0);
for (const [name, C] of [['XMLHttpRequest',XMLHttpRequest],['XMLHttpRequestEventTarget',XMLHttpRequestEventTarget],['XMLHttpRequestUpload',XMLHttpRequestUpload]]) define(C.prototype, Symbol.toStringTag, { __proto__: null, value: name, configurable: true });
for (const [name, value] of [['UNSENT',0],['OPENED',1],['HEADERS_RECEIVED',2],['LOADING',3],['DONE',4]]) { define(XMLHttpRequest, name, { __proto__: null, value, enumerable: true }); define(XMLHttpRequest.prototype, name, { __proto__: null, value, enumerable: true }); }
function handler(prototype, type, brand) {
  const handlers = { get value() { brand(this); return getHandler(this, type); }, set value(value) { brand(this); setHandler(this, type, value); } }, d = descriptor(handlers, 'value');
  define(d.get, 'name', { __proto__: null, value: 'get on' + type, configurable: true }); define(d.set, 'name', { __proto__: null, value: 'set on' + type, configurable: true }); define(prototype, 'on' + type, d);
}
handler(XMLHttpRequest.prototype, 'readystatechange', requireXHR);
for (const type of ['loadstart','progress','abort','error','load','timeout','loadend']) handler(XMLHttpRequestEventTarget.prototype, type, requireTarget);

// Web IDL members are enumerable and configurable on the interface prototype.
for (const key of ownKeys(XMLHttpRequest.prototype)) { const d = descriptor(XMLHttpRequest.prototype, key); if (key !== 'constructor' && typeof key === 'string' && d.configurable) define(XMLHttpRequest.prototype, key, { __proto__: null, enumerable: true }); }
