// The page's world: linkedom's DOM plus the Web APIs a page's scripts
// expect, on virtual time. The guest drives it through globalThis.__af:
// init, scripts, step, candidates, act, report. Everything a page does
// that leaves the page (requests, navigations, cookies, code it builds)
// is recorded.
import * as L from 'linkedom';
import { CookieJar } from './cookies.js';
import { parseHTML, parseHTMLFragment, fragmentElements, documentMode } from './document.js';
import { qualifiedName, nameIdentity } from './names.js';
import { setEventClock, eventState, cancelEvent, setRelatedTarget, relatedTarget, markEventUninitialized } from './event-state.js';
import { fireEvent, installEventHooks, registerWindow, nullableTarget, getHandler, setHandler, setContentHandler } from './event-target.js';
import { initializeSignal, signalState, abortSignal, dependSignal, onSignalAbort, setAbortEventDispatcher, signalListenersChanged } from './abort-state.js';
import { installEventAttributeHook } from './ce-hooks.js';
import { htmlName, controlType, treeElements, formOwner, connected, disabled, checked, setChecked, indeterminate, setIndeterminate, beginInputActivation, cancelInputActivation, installControlState, setControlAttribute } from './controls.js';
import { nodeInfo, eventAttribute, physicalParent, retarget } from './dom-state.js';
import { exceptionInfo, clipDiagnostic } from './error-info.js';
import { installShadowConstraints } from './shadow.js';
import { EVENT_TARGET } from '../node_modules/linkedom/esm/shared/symbols.js';
import { installCloning } from './cloning.js';
import { installRegistry, domString } from './registry.js';
import { installHTMLConstructors } from './html-constructors.js';
import { installReactionBoundaries, withReactions } from './ce-reactions.js';
import { runDOMCallback } from './dom-callbacks.js';
import { installSerialization } from './serialization.js';
import { installAdoption } from './adoption.js';
import { installObservers } from './observers.js';
import { templateContent, templateOwner, templateInnerHTML, shareTemplateObservers } from './templates.js';
import { installSelectors } from './selectors.js';
import { scriptRecord, rememberScript, scriptOwner } from './script-state.js';
import { installScriptMutations, scriptAttribute, scriptText, scriptShadowHost } from './script-mutations.js';

const G = globalThis;
const HTML_NS = 'http://www.w3.org/1999/xhtml';
const SVG_NS = 'http://www.w3.org/2000/svg';
// Script preparation uses the node's identity, not public DOM properties
// that page code can shadow without changing the actual kind of element.
const scriptIdentity = node => scriptRecord(node)?.identity;
const copyScriptBatch = Function.prototype.call.bind(Array.prototype.slice);
const nodeRoot = Function.prototype.call.bind(L.Node.prototype.getRootNode);
const isShadowRoot = Object.prototype.isPrototypeOf.bind(L.ShadowRoot.prototype);
const isDocument = Object.prototype.isPrototypeOf.bind(L.Document.prototype);
const CAP = 200;

const S = {
  start: 0, now: 0, seq: 0, timers: new Map(), nesting: 0, horizon: 0,
  gesture: false, trusted: false, ended: null, steps: 0, latency: 5, throttle: 0,
  url: null, origin: '', document: null, files: {}, responses: {}, cookies: new CookieJar(() => S.now),
  errors: [], console: [], requests: [], navigations: [], code: [],
  cookieWrites: [], storage: [], dialogs: [], history: [], unmodelled: new Set(),
  listened: new Map(), cands: [], scripts: [], dynamicScripts: [],
  active: null, readyState: 'loading', actions: [], currentExternal: false,
};

setEventClock(() => S.now - S.start);
installControlState(queueDetailsToggle);

const push = (list, v) => { if (list.length < CAP) list[list.length] = v; };
const clip = (s, n = 400) => { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; };
let dispatchGlobalError = null, dispatchGlobalEvent = null, reportingError = false;
const error = (where, value, notify = true) => {
  const info = exceptionInfo(value);
  let unhandled = true;
  if (notify && dispatchGlobalError && !reportingError) {
    reportingError = true;
    try { unhandled = dispatchGlobalError(info, value); }
    finally { reportingError = false; }
  }
  if (unhandled) push(S.errors, { where, at: S.now - S.start, name: clipDiagnostic(info.name), message: clipDiagnostic(info.message), stack: clipDiagnostic(info.stack, 1200) });
};
const rejections = new Map(), notifiedRejections = new WeakMap();
const notified = notifiedRejections.get.bind(notifiedRejections), rememberNotified = notifiedRejections.set.bind(notifiedRejections), forgetNotified = notifiedRejections.delete.bind(notifiedRejections);
const mapGet = Function.prototype.call.bind(Map.prototype.get), mapSet = Function.prototype.call.bind(Map.prototype.set), mapDelete = Function.prototype.call.bind(Map.prototype.delete), mapEach = Function.prototype.call.bind(Map.prototype.forEach);
const nativeResolve = Promise.resolve.bind(Promise), nativeThen = Function.prototype.call.bind(Promise.prototype.then);
const nativeApply = Reflect.apply, NativeTypeError = TypeError;
let handledRejections = [];
const unmodelled = (name) => S.unmodelled.add(name);

// The host: appfuzz's browser guest installs globalThis.__host, the
// `appfuzz:browser` imports. Requests go to it and it answers them; markup,
// code and navigations the page makes are reported to it. Without one (the
// native runner) requests are answered from the session's files and
// responses.
const host = () => G.__host;
const toMarkup = (where, value) => { const h = host(); if (h) h.html(String(where), String(value)); };
const toCode = (where, value) => { const h = host(); if (h) h.code(String(where), String(value)); };

// --- Determinism: seeded randomness and a virtual clock --------------------

let seed = 1;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
Math.random = rand;

const RealDate = Date;
function VDate(...a) {
  if (!new.target) return new RealDate(S.now).toString();
  return a.length ? new RealDate(...a) : new RealDate(S.now);
}
VDate.prototype = RealDate.prototype;
VDate.now = () => S.now;
VDate.parse = RealDate.parse;
VDate.UTC = RealDate.UTC;
G.Date = VDate;

G.performance = {
  now: () => S.now - S.start,
  get timeOrigin() { return S.start; },
  mark() {}, measure() {}, clearMarks() {}, clearMeasures() {},
  getEntries: () => [], getEntriesByName: () => [], getEntriesByType: () => [],
};

function runCode(code, where) {
  push(S.code, { where, code: clip(code, 2000), gesture: S.gesture });
  toCode(where, code);
  try { return realEval(code); } catch (e) { error(where, e); }
}

// eval and Function build code from text: both are code sinks. The shim's
// own code uses the real ones. A wrapped eval is an indirect eval: code
// that relies on a direct eval seeing its local variables breaks.
const realEval = G.eval;
const RealFunction = Function;
// A method keeps the name `eval`, which a module may not declare.
G.eval = {
  eval(code) {
    if (typeof code !== 'string') return code;
    push(S.code, { where: 'eval', code: clip(code, 2000), gesture: S.gesture });
    toCode('eval', code);
    return realEval(code);
  },
}.eval;
const codeOf = (a) => (a.length ? String(a[a.length - 1]) : '');
const watched = (C, where) => {
  const p = new Proxy(C, {
    apply(t, self, a) { toCode(where, codeOf(a)); return Reflect.apply(t, self, a); },
    construct(t, a, nt) { toCode(where, codeOf(a)); return Reflect.construct(t, a, nt === p ? t : nt); },
  });
  return p;
};
G.Function = watched(RealFunction, 'Function');
Object.defineProperty(RealFunction.prototype, 'constructor', { value: G.Function, writable: true, configurable: true });
// Reached only through a function's prototype (Alpine builds its
// expressions with AsyncFunction).
for (const [f, where] of [[async function () {}, 'AsyncFunction'], [function* () {}, 'GeneratorFunction'], [async function* () {}, 'AsyncGeneratorFunction']]) {
  const proto = Object.getPrototypeOf(f);
  Object.defineProperty(proto, 'constructor', { value: watched(proto.constructor, where), writable: true, configurable: true });
}

function addTimer(fn, delay, args, repeat, kind, clamp = true) {
  if (typeof fn !== 'function') {
    const code = String(fn);
    fn = () => runCode(code, kind);
  }
  delay = Math.max(0, Number(delay) || 0, S.throttle);
  if (clamp && S.nesting > 4 && delay < 4) delay = 4;
  const id = ++S.seq;
  S.timers.set(id, { id, due: S.now + delay, fn, args, repeat: repeat ? Math.max(delay, 1) : 0, nesting: S.nesting + 1, kind });
  return id;
}
G.setTimeout = (fn, d, ...a) => addTimer(fn, d, a, false, 'setTimeout');
G.setInterval = (fn, d, ...a) => addTimer(fn, d, a, true, 'setInterval');
G.clearTimeout = G.clearInterval = (id) => { S.timers.delete(id); };
G.requestAnimationFrame = (cb) => {
  const t = S.now - S.start;
  return addTimer(() => cb(G.performance.now()), 16 - (t % 16), [], false, 'requestAnimationFrame', false);
};
G.cancelAnimationFrame = G.clearTimeout;
G.requestIdleCallback = (cb) => addTimer(() => cb({ didTimeout: false, timeRemaining: () => 50 }), 1, [], false, 'requestIdleCallback', false);
G.cancelIdleCallback = G.clearTimeout;
G.queueMicrotask = (fn) => {
  if (typeof fn !== 'function') throw new NativeTypeError('queueMicrotask requires a callback');
  nativeThen(nativeResolve(), () => { try { runDOMCallback(() => nativeApply(fn, undefined, [])); } catch (e) { error('queueMicrotask', e); } });
};

// The next due task, if it is due by the horizon.
function step() {
  let next = null;
  for (const t of S.timers.values()) {
    if (!next || t.due < next.due || (t.due === next.due && t.id < next.id)) next = t;
  }
  if (!next || next.due > S.horizon || S.ended) return false;
  if (next.due > S.now) S.now = next.due;
  if (next.repeat) next.due = S.now + Math.max(next.repeat, S.throttle);
  else S.timers.delete(next.id);
  const saved = S.nesting;
  S.nesting = next.nesting;
  try { next.fn(...next.args); } catch (e) { error(next.kind, e); }
  S.nesting = saved;
  S.steps++;
  return true;
}

// --- Encoding, URLs, aborts -------------------------------------------------

if (typeof G.TextEncoder !== 'function') {
  G.TextEncoder = class TextEncoder {
    get encoding() { return 'utf-8'; }
    encode(s = '') {
      const b = unescape(encodeURIComponent(String(s)));
      const out = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
      return out;
    }
  };
  G.TextDecoder = class TextDecoder {
    get encoding() { return 'utf-8'; }
    decode(buf) {
      if (!buf) return '';
      const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf.buffer || buf);
      let s = '';
      for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
      try { return decodeURIComponent(escape(s)); } catch { return s; }
    }
  };
}
if (typeof G.atob !== 'function') {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  G.btoa = (s) => {
    s = String(s);
    let out = '';
    for (let i = 0; i < s.length; i += 3) {
      const [a, b, c] = [s.charCodeAt(i), s.charCodeAt(i + 1), s.charCodeAt(i + 2)];
      if (a > 255 || b > 255 || c > 255) throw new DOMException('Invalid character', 'InvalidCharacterError');
      const n = (a << 16) | ((b || 0) << 8) | (c || 0);
      out += A[n >> 18] + A[(n >> 12) & 63] + (i + 1 < s.length ? A[(n >> 6) & 63] : '=') + (i + 2 < s.length ? A[n & 63] : '=');
    }
    return out;
  };
  G.atob = (s) => {
    s = String(s).replace(/[\s=]/g, '');
    let out = '';
    for (let i = 0; i < s.length; i += 4) {
      const n = [0, 1, 2, 3].map((k) => A.indexOf(s[i + k] || 'A'));
      if (n.some((x) => x < 0)) throw new DOMException('Invalid character', 'InvalidCharacterError');
      const v = (n[0] << 18) | (n[1] << 12) | (n[2] << 6) | n[3];
      out += String.fromCharCode(v >> 16);
      if (i + 2 < s.length) out += String.fromCharCode((v >> 8) & 255);
      if (i + 3 < s.length) out += String.fromCharCode(v & 255);
    }
    return out;
  };
}

const BrowserDOMException = class DOMException extends Error {
  constructor(message = '', name = 'Error') { super(message); this.name = name; this.code = name === 'InvalidCharacterError' ? 5 : name === 'NamespaceError' ? 14 : 0; }
};
G.DOMException = BrowserDOMException;

// URLs and form encoding by the WHATWG rules: the guest's `url` crate, the
// parser appfuzz judges where requests go with. A page's own checks
// (`new URL(next).host === location.host`) then parse as in a browser:
// lookalike and numeric hosts, IPv6, backslashes, dot segments.
const N = G.__native;

// What a Web API takes as a string: lone surrogates become U+FFFD.
const usv = (s) => {
  s = String(s);
  return typeof s.toWellFormed === 'function' ? s.toWellFormed() : s;
};

class URLSearchParams {
  constructor(init = '') {
    this._l = [];
    this._u = null;
    if (init instanceof URLSearchParams) this._l = init._l.map((p) => [...p]);
    else if (init && typeof init === 'object' && typeof init[Symbol.iterator] === 'function') {
      for (const pair of init) {
        const p = [...pair];
        if (p.length !== 2) throw new TypeError('URLSearchParams: each pair needs a name and a value');
        this._l.push([usv(p[0]), usv(p[1])]);
      }
    } else if (init && typeof init === 'object') for (const k of Object.keys(init)) this._l.push([usv(k), usv(init[k])]);
    else this._parse(usv(init));
  }
  _parse(s) { s = s.replace(/^\?/, ''); this._l = s ? N.formParse(s) : []; }
  _sync() { if (this._u) this._u._update('search', this.toString(), true); }
  get size() { return this._l.length; }
  append(k, v) { this._l.push([usv(k), usv(v)]); this._sync(); }
  delete(k, v) { k = usv(k); this._l = this._l.filter((p) => p[0] !== k || (v !== undefined && p[1] !== usv(v))); this._sync(); }
  get(k) { k = usv(k); const p = this._l.find((p) => p[0] === k); return p ? p[1] : null; }
  getAll(k) { k = usv(k); return this._l.filter((p) => p[0] === k).map((p) => p[1]); }
  has(k, v) { k = usv(k); return this._l.some((p) => p[0] === k && (v === undefined || p[1] === usv(v))); }
  set(k, v) {
    k = usv(k);
    const i = this._l.findIndex((p) => p[0] === k);
    if (i < 0) this._l.push([k, usv(v)]);
    else { this._l[i][1] = usv(v); this._l = this._l.filter((p, j) => j <= i || p[0] !== k); }
    this._sync();
  }
  sort() { this._l.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)); this._sync(); }
  forEach(f, t) { for (const [k, v] of this._l) f.call(t, v, k, this); }
  *entries() { yield* this._l.map((p) => [...p]); }
  *keys() { for (const p of this._l) yield p[0]; }
  *values() { for (const p of this._l) yield p[1]; }
  [Symbol.iterator]() { return this.entries(); }
  toString() { return N.formSerialize(this._l); }
}
G.URLSearchParams = URLSearchParams;

// A URL keeps its parts, in this order, as the guest gives them.
const PARTS = ['href', 'origin', 'protocol', 'username', 'password', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'];

class URL {
  constructor(input, base) {
    const p = N.url(usv(input), base === undefined ? null : usv(base));
    if (!p) throw new TypeError('Invalid URL: ' + clip(input, 80));
    this._p = p;
    this._sp = null;
  }
  // A setter: refused values leave the URL as it was; an href that
  // doesn't parse throws. `fromParams`: the change came from searchParams.
  _update(key, value, fromParams = false) {
    const p = N.urlSet(this._p[0], key, usv(value));
    if (!p) throw new TypeError('Invalid URL: ' + clip(value, 80));
    this._p = p;
    if (this._sp && !fromParams && (key === 'href' || key === 'search')) this._sp._parse(p[9]);
  }
  get searchParams() {
    if (!this._sp) { this._sp = new URLSearchParams(this._p[9]); this._sp._u = this; }
    return this._sp;
  }
  toString() { return this._p[0]; }
  toJSON() { return this._p[0]; }
  static canParse(u, b) { try { new URL(u, b); return true; } catch { return false; } }
  static parse(u, b) { try { return new URL(u, b); } catch { return null; } }
  static createObjectURL(blob) {
    const u = 'blob:' + S.origin + '/' + uuid();
    blobs.set(u, blob);
    return u;
  }
  static revokeObjectURL(u) { blobs.delete(u); }
}
PARTS.forEach((k, i) => Object.defineProperty(URL.prototype, k, {
  configurable: true,
  enumerable: true,
  get() { return this._p[i]; },
  set: k === 'origin' ? undefined : function (v) { this._update(k, v); },
}));
G.URL = URL;
const blobs = new Map();

function uuid() {
  const h = [...Array(16)].map(() => Math.floor(rand() * 256));
  h[6] = (h[6] & 15) | 64;
  h[8] = (h[8] & 63) | 128;
  const x = h.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}
G.crypto = {
  getRandomValues(a) {
    const bytes = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(rand() * 256);
    return a;
  },
  randomUUID: uuid,
  get subtle() { unmodelled('crypto.subtle'); return undefined; },
};

if (typeof G.structuredClone !== 'function') {
  G.structuredClone = (v) => (v === undefined ? v : JSON.parse(JSON.stringify(v)));
}

// --- Events -----------------------------------------------------------------

const Ev = L.Event;
const MODS = ['ctrlKey', 'shiftKey', 'altKey', 'metaKey'];
class UIEvent extends Ev {
  constructor(t, i = {}) { super(t, i); this.view = i.view ?? null; this.detail = i.detail ?? 0; }
}
class MouseEvent extends UIEvent {
  constructor(t, i = {}) {
    super(t, i);
    eventState(this).mouse = true;
    for (const k of ['screenX', 'screenY', 'clientX', 'clientY', 'pageX', 'pageY', 'offsetX', 'offsetY', 'movementX', 'movementY', 'button', 'buttons']) this[k] = i[k] ?? 0;
    for (const k of MODS) this[k] = !!i[k];
    setRelatedTarget(this, nullableTarget(i.relatedTarget));
  }
  get relatedTarget() { return relatedTarget(this); }
  getModifierState() { return false; }
}
class PointerEvent extends MouseEvent {
  constructor(t, i = {}) {
    super(t, i);
    this.pointerId = i.pointerId ?? 1;
    this.pointerType = i.pointerType ?? 'mouse';
    this.isPrimary = i.isPrimary ?? true;
    this.width = 1; this.height = 1; this.pressure = i.pressure ?? 0;
  }
}
class WheelEvent extends MouseEvent {}
class KeyboardEvent extends UIEvent {
  constructor(t, i = {}) {
    super(t, i);
    this.key = i.key ?? ''; this.code = i.code ?? ''; this.location = 0; this.repeat = !!i.repeat; this.isComposing = false;
    for (const k of MODS) this[k] = !!i[k];
    this.keyCode = i.keyCode ?? 0; this.which = this.keyCode; this.charCode = i.charCode ?? 0;
  }
  getModifierState() { return false; }
}
class FocusEvent extends UIEvent { constructor(t, i = {}) { super(t, i); setRelatedTarget(this, nullableTarget(i.relatedTarget)); } get relatedTarget() { return relatedTarget(this); } }
class SubmitEvent extends Ev { constructor(t, i = {}) { super(t, i); this.submitter = i.submitter ?? null; } }
class MessageEvent extends Ev {
  constructor(t, i = {}) { super(t, i); this.data = i.data ?? null; this.origin = i.origin ?? ''; this.lastEventId = ''; this.source = i.source ?? null; this.ports = []; }
}
class ProgressEvent extends Ev { constructor(t, i = {}) { super(t, i); this.lengthComputable = !!i.lengthComputable; this.loaded = i.loaded ?? 0; this.total = i.total ?? 0; } }
class HashChangeEvent extends Ev { constructor(t, i = {}) { super(t, i); this.oldURL = i.oldURL ?? ''; this.newURL = i.newURL ?? ''; } }
class PopStateEvent extends Ev { constructor(t, i = {}) { super(t, i); this.state = i.state ?? null; } }
const errorEventBrands = new WeakMap();
const brandErrorEvent = errorEventBrands.set.bind(errorEventBrands), isErrorEvent = errorEventBrands.has.bind(errorEventBrands);
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
const errorEventFor = errorEventBrands.get.bind(errorEventBrands);
function errorEventData(event) {
  const data = errorEventFor(event);
  if (!data) throw new NativeTypeError('Illegal error event receiver');
  return data;
}
class ErrorEvent extends Ev {
  constructor(type, options = {}) {
    if (!arguments.length) throw new NativeTypeError('ErrorEvent requires a type');
    type = domString(type);
    const init = options == null ? {} : options;
    if (typeof init !== 'object' && typeof init !== 'function') throw new NativeTypeError('ErrorEvent options must be a dictionary');
    // Web IDL dictionaries convert members in lexicographic order.
    const bubbles = !!init.bubbles, cancelable = !!init.cancelable, colno = +init.colno >>> 0, composed = !!init.composed, error = init.error;
    const rawFilename = init.filename, filename = wellFormed(domString(rawFilename === undefined ? '' : rawFilename));
    const lineno = +init.lineno >>> 0, rawMessage = init.message, message = domString(rawMessage === undefined ? '' : rawMessage);
    super(type, { bubbles, cancelable, composed });
    brandErrorEvent(this, { message, filename, lineno, colno, error });
  }
  get message() { return errorEventData(this).message; }
  get filename() { return errorEventData(this).filename; }
  get lineno() { return errorEventData(this).lineno; }
  get colno() { return errorEventData(this).colno; }
  get error() { return errorEventData(this).error; }
}
class PromiseRejectionEvent extends Ev { constructor(t, i = {}) { super(t, i); this.promise = i.promise; this.reason = i.reason; } }
class ToggleEvent extends Ev {
  constructor(type, options = {}) {
    if (!arguments.length) throw new NativeTypeError('ToggleEvent requires a type');
    const data = runDOMCallback(() => {
      type = domString(type);
      const init = options == null ? {} : options;
      if (typeof init !== 'object' && typeof init !== 'function') throw new NativeTypeError('ToggleEvent options must be a dictionary');
      const bubbles = !!init.bubbles, cancelable = !!init.cancelable, composed = !!init.composed;
      const rawNew = init.newState, newState = domString(rawNew === undefined ? '' : rawNew), rawOld = init.oldState, oldState = domString(rawOld === undefined ? '' : rawOld), source = init.source;
      if (source != null && nodeInfo(source)?.kind !== 1) throw new NativeTypeError('ToggleEvent source must be an Element');
      return { bubbles, cancelable, composed, oldState, newState, source: source ?? null };
    });
    super(type, { bubbles: data.bubbles, cancelable: data.cancelable, composed: data.composed });
    eventState(this).toggle = data;
  }
  get oldState() { const data = eventState(this).toggle; if (!data) throw new NativeTypeError('A ToggleEvent is required'); return data.oldState; }
  get newState() { const data = eventState(this).toggle; if (!data) throw new NativeTypeError('A ToggleEvent is required'); return data.newState; }
  get source() { const state = eventState(this), data = state.toggle; if (!data) throw new NativeTypeError('A ToggleEvent is required'); return retarget(data.source, state.current); }
}
const detailsToggles = new WeakMap(), pendingToggle = detailsToggles.get.bind(detailsToggles), rememberToggle = detailsToggles.set.bind(detailsToggles), forgetToggle = detailsToggles.delete.bind(detailsToggles);
function queueDetailsToggle(node, wasOpen, isOpen) {
  const pending = pendingToggle(node), oldState = pending ? pending.oldState : wasOpen ? 'open' : 'closed', newState = isOpen ? 'open' : 'closed';
  if (pending) mapDelete(S.timers, pending.id);
  const id = addTimer(() => { forgetToggle(node); fireEvent(node, new ToggleEvent('toggle', { oldState, newState })); }, 0, [], false, 'details-toggle', false);
  rememberToggle(node, { id, oldState });
}
class StorageEvent extends Ev {}
class TransitionEvent extends Ev {}
class AnimationEvent extends Ev {}
class CompositionEvent extends UIEvent { constructor(t, i = {}) { super(t, i); this.data = i.data ?? ''; } }
class ClipboardEvent extends Ev { constructor(t, i = {}) { super(t, i); this.clipboardData = i.clipboardData ?? null; } }
class TouchEvent extends UIEvent { constructor(t, i = {}) { super(t, i); this.touches = []; this.targetTouches = []; this.changedTouches = []; } }
class DragEvent extends MouseEvent { constructor(t, i = {}) { super(t, i); this.dataTransfer = i.dataTransfer ?? null; } }
Object.assign(G, {
  UIEvent, MouseEvent, PointerEvent, WheelEvent, KeyboardEvent, FocusEvent, SubmitEvent, MessageEvent, ProgressEvent,
  HashChangeEvent, PopStateEvent, ErrorEvent, PromiseRejectionEvent, StorageEvent, TransitionEvent, AnimationEvent,
  CompositionEvent, ClipboardEvent, TouchEvent, DragEvent, ToggleEvent,
});

// Listeners: a throwing listener is reported, not passed on, and `this` is
// the current target. Every target remembers its event types: that is how
// the driver finds what a person could click.
const applyCallback = Reflect.apply;
const NativeSet = Set;
const finiteNumber = Number.isFinite, truncateNumber = Math.trunc;
const nativeSetAdd = Function.prototype.call.bind(Set.prototype.add);
let currentEvent;
installEventHooks({
  error,
  activation: prepareActivation,
  activated: completeActivation,
  changed(target, types) {
    signalListenersChanged(target, types);
    if (!types.length) { mapDelete(S.listened, target); return; }
    const set = new NativeSet();
    for (let i = 0; i < types.length; i++) nativeSetAdd(set, types[i]);
    mapSet(S.listened, target, set);
  },
  current(value, shadow, restore) { const previous = currentEvent; if (restore || !shadow) currentEvent = value; return previous; },
}, BrowserDOMException);

// Content attributes activate the same handler slot as IDL assignments at
// mutation time; compilation stays lazy until a getter or invocation needs it.
const handlerNames = Object.getOwnPropertyNames(L.HTMLElement.prototype).filter(name => name.startsWith('on'));
for (const type of ['wheel', 'beforeinput', 'reset', 'message', 'messageerror', 'pageshow', 'pagehide', 'hashchange', 'popstate', 'resize', 'scroll', 'focusin', 'focusout']) {
  if (!handlerNames.includes('on' + type)) handlerNames.push('on' + type);
}
const handlerTypes = new Set(handlerNames), isHandlerName = handlerTypes.has.bind(handlerTypes);
for (const proto of [L.Element.prototype, L.HTMLElement.prototype, L.SVGElement.prototype, L.Document.prototype]) for (const name of handlerNames) {
  const type = name.slice(2);
  Object.defineProperty(proto, name, { configurable: true, enumerable: true,
    get() { return getHandler(this, type); }, set(value) { setHandler(this, type, value); },
  });
}
installEventAttributeHook((node, name, code) => {
  if (nodeInfo(node)?.kind !== 1 || !isHandlerName(name)) return;
  const type = name.slice(2);
  setContentHandler(node, type, code == null ? null : () => {
    try {
      push(S.code, { where: 'handler:on' + type, code: clip(code, 2000), gesture: S.gesture });
      toCode('handler:on' + type, code);
      return new RealFunction('event', code);
    } catch (e) { error('handler:on' + type, e); return null; }
  });
});
const iteratorSymbol = Symbol.iterator;
const signalToken = {}, controllerSignals = new WeakMap();
const controllerSignal = controllerSignals.get.bind(controllerSignals), rememberController = controllerSignals.set.bind(controllerSignals);
class AbortSignal extends L.EventTarget {
  constructor(token) {
    if (token !== signalToken) throw new NativeTypeError('Illegal AbortSignal constructor');
    super(); initializeSignal(this);
  }
  get aborted() { return signalState(this).aborted; }
  get reason() { return signalState(this).reason; }
  get onabort() { return getHandler(this, 'abort'); }
  set onabort(value) { setHandler(this, 'abort', value); }
  throwIfAborted() { const state = signalState(this); if (state.aborted) throw state.reason; }
  static abort(reason) {
    const signal = new AbortSignal(signalToken), state = signalState(signal);
    state.aborted = true; state.reason = reason === undefined ? new BrowserDOMException('The operation was aborted', 'AbortError') : reason;
    return signal;
  }
  static any(signals) {
    if (!arguments.length) throw new NativeTypeError('any requires a sequence of signals');
    const inputs = runDOMCallback(() => {
      if (signals === null || (typeof signals !== 'object' && typeof signals !== 'function')) throw new NativeTypeError('A sequence requires an iterable object');
      const result = [], method = signals[iteratorSymbol];
      if (typeof method !== 'function') throw new NativeTypeError('A sequence requires an iterable object');
      const iterator = nativeApply(method, signals, []);
      if (iterator === null || (typeof iterator !== 'object' && typeof iterator !== 'function')) throw new NativeTypeError('Invalid iterator');
      const next = iterator.next;
      while (true) {
        const step = nativeApply(next, iterator, []);
        if (step === null || (typeof step !== 'object' && typeof step !== 'function')) throw new NativeTypeError('Invalid iterator result');
        if (step.done) return result;
        const signal = step.value; signalState(signal); result[result.length] = signal;
      }
    });
    return dependSignal(new AbortSignal(signalToken), inputs);
  }
  static timeout(ms) {
    if (!arguments.length) throw new NativeTypeError('timeout requires a delay');
    const delay = truncateNumber(+ms);
    if (!finiteNumber(delay) || delay < 0 || delay >= 18446744073709551616) throw new NativeTypeError('Invalid timeout');
    const signal = new AbortSignal(signalToken);
    addTimer(() => abort(signal, new BrowserDOMException('The operation timed out', 'TimeoutError')), delay, [], false, 'abort-timeout', false);
    return signal;
  }
}
function abort(signal, reason) {
  if (signalState(signal).aborted) return;
  if (reason === undefined) reason = new BrowserDOMException('The operation was aborted', 'AbortError');
  abortSignal(signal, reason);
}
class AbortController {
  constructor() { rememberController(this, new AbortSignal(signalToken)); }
  get signal() { const signal = controllerSignal(this); if (!signal) throw new NativeTypeError('Illegal AbortController receiver'); return signal; }
  abort(reason) { const signal = controllerSignal(this); if (!signal) throw new NativeTypeError('Illegal AbortController receiver'); abort(signal, reason); }
}
setAbortEventDispatcher(signal => fireEvent(signal, new Ev('abort')));
Object.assign(G, { AbortSignal, AbortController });

class MessagePort extends L.EventTarget {
  constructor() { super(); this.onmessage = null; this._other = null; }
  postMessage(data) {
    const o = this._other;
    addTimer(() => {
      const ev = new MessageEvent('message', { data });
      fireEvent(o, ev);
    }, 0, [], false, 'MessageChannel', false);
  }
  start() {}
  close() {}
}
G.MessagePort = MessagePort;
G.MessageChannel = class MessageChannel {
  constructor() { this.port1 = new MessagePort(); this.port2 = new MessagePort(); this.port1._other = this.port2; this.port2._other = this.port1; }
};

// --- Network: every request is recorded; answers come from the session -----

const NativeMap = Map, NativePromise = Promise, createFetchObject = Object.create, objectKeys = Object.keys;
const rejectPromise = Promise.reject.bind(Promise), parseBodyJSON = JSON.parse;
const headerTables = new WeakMap(), headerTable = headerTables.get.bind(headerTables), rememberHeaders = headerTables.set.bind(headerTables);
const mapHas = Function.prototype.call.bind(Map.prototype.has);
const sorted = Function.prototype.call.bind(Array.prototype.sort), stringLower = Function.prototype.call.bind(String.prototype.toLowerCase), stringUpper = Function.prototype.call.bind(String.prototype.toUpperCase);
function requireHeaders(value) { const result = headerTable(value); if (!result) throw new NativeTypeError('A Headers object is required'); return result; }
function headerPairs(headers) {
  const pairs = []; mapEach(requireHeaders(headers), (value, key) => { pairs[pairs.length] = [key, value]; });
  return sorted(pairs, (a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
}
function appendHeader(headers, name, value) {
  name = stringLower(domString(name)); value = domString(value);
  const table = requireHeaders(headers), old = mapGet(table, name); mapSet(table, name, old == null ? value : old + ', ' + value);
}
function copyHeaders(headers) {
  const result = new Headers(); mapEach(requireHeaders(headers), (value, key) => { mapSet(requireHeaders(result), key, value); }); return result;
}
class Headers {
  constructor(init) {
    rememberHeaders(this, new NativeMap());
    if (init == null) return;
    if (typeof init !== 'object' && typeof init !== 'function') throw new NativeTypeError('Header initialization must be an object');
    if (init[iteratorSymbol] !== undefined) {
      for (const pair of init) {
        if (pair === null || (typeof pair !== 'object' && typeof pair !== 'function')) throw new NativeTypeError('A header pair must be a sequence');
        const values = []; for (const value of pair) values[values.length] = value;
        if (values.length !== 2) throw new NativeTypeError('A header pair requires two values');
        appendHeader(this, values[0], values[1]);
      }
    } else for (const key of objectKeys(init)) appendHeader(this, key, init[key]);
  }
  append(name, value) { appendHeader(this, name, value); }
  set(name, value) { mapSet(requireHeaders(this), stringLower(domString(name)), domString(value)); }
  get(name) { const value = mapGet(requireHeaders(this), stringLower(domString(name))); return value == null ? null : value; }
  has(name) { return mapHas(requireHeaders(this), stringLower(domString(name))); }
  delete(name) { mapDelete(requireHeaders(this), stringLower(domString(name))); }
  forEach(callback, receiver) { const pairs = headerPairs(this); for (let i = 0; i < pairs.length; i++) nativeApply(callback, receiver, [pairs[i][1], pairs[i][0], this]); }
  *entries() { const pairs = headerPairs(this); for (let i = 0; i < pairs.length; i++) yield pairs[i]; }
  *keys() { const pairs = headerPairs(this); for (let i = 0; i < pairs.length; i++) yield pairs[i][0]; }
  *values() { const pairs = headerPairs(this); for (let i = 0; i < pairs.length; i++) yield pairs[i][1]; }
  getSetCookie() { requireHeaders(this); return []; }
  [Symbol.iterator]() { const pairs = headerPairs(this); return (function* () { for (let i = 0; i < pairs.length; i++) yield pairs[i]; })(); }
}
const bodyText = (b) => {
  if (b == null) return null;
  if (typeof b === 'string') return b;
  if (b instanceof URLSearchParams) return b.toString();
  if (b instanceof FormData) return new URLSearchParams([...b].map(([k, v]) => [k, typeof v === 'string' ? v : '[file]'])).toString();
  if (b instanceof Blob) return b._text;
  return String(b);
};
const requests = new WeakMap(), requestData = requests.get.bind(requests), saveRequest = requests.set.bind(requests);
const responses = new WeakMap(), responseData = responses.get.bind(responses), saveResponse = responses.set.bind(responses);
const bodies = new WeakMap(), bodyData = bodies.get.bind(bodies), saveBody = bodies.set.bind(bodies);
function requireRequest(value) { const result = requestData(value); if (!result) throw new NativeTypeError('A Request is required'); return result; }
function requireResponse(value) { const result = responseData(value); if (!result) throw new NativeTypeError('A Response is required'); return result; }
function initializeBody(owner, text, signal = null) { saveBody(owner, { text, present: text !== null, used: false, signal }); }
function requireBody(owner) { const body = bodyData(owner); if (!body) throw new NativeTypeError('A Request or Response is required'); return body; }
function consumeBody(owner) {
  const body = requireBody(owner);
  if (body.used) return rejectPromise(new NativeTypeError('Body has already been consumed.'));
  body.used = body.present;
  if (body.present && body.signal && signalState(body.signal).aborted) return rejectPromise(signalState(body.signal).reason);
  return nativeResolve(body.text ?? '');
}
function cloneBody(source, target) {
  const body = requireBody(source);
  if (body.used) throw new NativeTypeError('Body has already been consumed.');
  initializeBody(target, body.text, body.signal);
}
const requestMembers = ['body','cache','credentials','duplex','headers','integrity','keepalive','method','mode','priority','redirect','referrer','referrerPolicy','signal','window'];
const credentialModes = new Set(['omit','same-origin','include']), validCredentials = credentialModes.has.bind(credentialModes);
const requestModes = new Set(['cors','no-cors','same-origin','navigate']), validRequestMode = requestModes.has.bind(requestModes);
const cacheModes = new Set(['default','no-store','reload','no-cache','force-cache','only-if-cached']), validCacheMode = cacheModes.has.bind(cacheModes);
const redirectModes = new Set(['follow','error','manual']), validRedirect = redirectModes.has.bind(redirectModes);
const normalizedMethods = new Set(['DELETE','GET','HEAD','OPTIONS','POST','PUT']), normalizeMethod = normalizedMethods.has.bind(normalizedMethods);
const tokenCode = code => (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 33 || (code >= 35 && code <= 39) || code === 42 || code === 43 || code === 45 || code === 46 || code === 94 || code === 95 || code === 96 || code === 124 || code === 126;
const charCode = Function.prototype.call.bind(String.prototype.charCodeAt), stringIndex = Function.prototype.call.bind(String.prototype.indexOf), stringSlice = Function.prototype.call.bind(String.prototype.slice);
function convertRequest(input, init, argumentCount) {
  if (!argumentCount) throw new NativeTypeError('Request requires an input');
  const src = requestData(input);
  const rawURL = src ? src.url : wellFormed(domString(input));
  if (init == null) init = { __proto__: null };
  if (typeof init !== 'object' && typeof init !== 'function') throw new NativeTypeError('Request options must be a dictionary');
  const options = { __proto__: null };
  for (let i = 0; i < requestMembers.length; i++) {
    const key = requestMembers[i], value = init[key];
    if (value === undefined) continue;
    if (key === 'signal') { if (value !== null) signalState(value); options.signal = value; }
    else if (key === 'body') options.body = bodyText(value);
    else if (key === 'headers') options.headers = new Headers(value);
    else if (key === 'keepalive') options.keepalive = !!value;
    else if (key === 'window') { if (value !== null) throw new NativeTypeError('Request window must be null'); options.window = null; }
    else options[key] = domString(value);
  }
  const parsed = N.url(rawURL, S.url._p[0]);
  if (!parsed || parsed[3] || parsed[4]) throw new NativeTypeError('Invalid request URL');
  const fragment = stringIndex(parsed[0], '#'), url = fragment < 0 ? parsed[0] : stringSlice(parsed[0], 0, fragment);
  let method = options.method ?? src?.method ?? 'GET';
  if (!method.length) throw new NativeTypeError('Invalid HTTP method');
  for (let i = 0; i < method.length; i++) if (!tokenCode(charCode(method, i))) throw new NativeTypeError('Invalid HTTP method');
  const upper = stringUpper(method);
  if (upper === 'CONNECT' || upper === 'TRACE' || upper === 'TRACK') throw new NativeTypeError('Forbidden HTTP method');
  if (normalizeMethod(upper)) method = upper;
  const credentials = options.credentials ?? src?.credentials ?? 'same-origin', mode = options.mode ?? src?.mode ?? 'cors', cache = options.cache ?? src?.cache ?? 'default', redirect = options.redirect ?? src?.redirect ?? 'follow';
  if (!validCredentials(credentials) || !validRequestMode(mode) || mode === 'navigate' || !validCacheMode(cache) || !validRedirect(redirect) || (cache === 'only-if-cached' && mode !== 'same-origin') || (mode === 'no-cors' && method !== 'GET' && method !== 'HEAD' && method !== 'POST')) throw new NativeTypeError('Invalid request mode');
  const sourceBody = src && requireBody(input), body = options.body ?? sourceBody?.text ?? null;
  if (body !== null && (method === 'GET' || method === 'HEAD')) throw new NativeTypeError('GET and HEAD requests cannot have a body');
  if (sourceBody && body !== null && options.body == null && sourceBody.used) throw new NativeTypeError('Body has already been consumed.');
  const source = options.signal === undefined ? src?.signal : options.signal;
  const signal = new AbortSignal(signalToken); if (source) dependSignal(signal, [source]);
  return { url, method, headers: options.headers || (src ? copyHeaders(src.headers) : new Headers()), signal, credentials, mode, cache, redirect, body, sourceBody: options.body == null ? sourceBody : null };
}
class Request {
  constructor(input, init = undefined) {
    const data = runDOMCallback(() => convertRequest(input, init, arguments.length));
    saveRequest(this, data); initializeBody(this, data.body);
    if (data.sourceBody && data.body !== null) data.sourceBody.used = true;
    data.body = data.sourceBody = undefined;
  }
  get url() { return requireRequest(this).url; }
  get method() { return requireRequest(this).method; }
  get headers() { return requireRequest(this).headers; }
  get signal() { return requireRequest(this).signal; }
  get credentials() { return requireRequest(this).credentials; }
  get mode() { return requireRequest(this).mode; }
  get cache() { return requireRequest(this).cache; }
  get redirect() { return requireRequest(this).redirect; }
  get body() { requireRequest(this); return null; }
  get bodyUsed() { requireRequest(this); return requireBody(this).used; }
  clone() {
    const data = requireRequest(this), body = requireBody(this);
    if (body.used) throw new NativeTypeError('Body has already been consumed.');
    const result = createFetchObject(Request.prototype), signal = dependSignal(new AbortSignal(signalToken), [data.signal]);
    saveRequest(result, { ...data, headers: copyHeaders(data.headers), signal }); cloneBody(this, result); return result;
  }
  text() { requireRequest(this); return consumeBody(this); }
  json() { requireRequest(this); return nativeThen(consumeBody(this), parseBodyJSON); }
}
class Response {
  constructor(body = null, init = undefined) {
    if (init == null) init = { __proto__: null };
    const text = bodyText(body), status = init.status ?? 200;
    saveResponse(this, { status, statusText: init.statusText ?? (status === 200 ? 'OK' : ''), headers: new Headers(init.headers), url: init.url || '', redirected: false, type: 'basic' });
    initializeBody(this, text);
  }
  get status() { return requireResponse(this).status; }
  get statusText() { return requireResponse(this).statusText; }
  get ok() { const status = requireResponse(this).status; return status >= 200 && status < 300; }
  get headers() { return requireResponse(this).headers; }
  get url() { return requireResponse(this).url; }
  get redirected() { return requireResponse(this).redirected; }
  get type() { return requireResponse(this).type; }
  get bodyUsed() { requireResponse(this); return requireBody(this).used; }
  get body() { requireResponse(this); return null; }
  _use() { requireResponse(this); return consumeBody(this); }
  text() { requireResponse(this); return consumeBody(this); }
  json() { requireResponse(this); return nativeThen(consumeBody(this), parseBodyJSON); }
  blob() { requireResponse(this); return nativeThen(consumeBody(this), text => new Blob([text])); }
  arrayBuffer() { requireResponse(this); return nativeThen(consumeBody(this), text => new TextEncoder().encode(text).buffer); }
  formData() { requireResponse(this); unmodelled('Response.formData'); return nativeThen(consumeBody(this), () => new FormData()); }
  clone() {
    const data = requireResponse(this), result = createFetchObject(Response.prototype);
    cloneBody(this, result); saveResponse(result, { ...data, headers: copyHeaders(data.headers) }); return result;
  }
  static json(value, init) { return new Response(JSON.stringify(value), { ...init, headers: { 'content-type': 'application/json' } }); }
  static error() { return new Response(null, { status: 0 }); }
  static redirect(url, status = 302) { return new Response(null, { status, headers: { location: url } }); }
}
Object.assign(G, { Headers, Request, Response });

// Cookie storage is private to the user agent: Set-Cookie never becomes
// a readable response header. Delayed fetch/XHR answers apply it when
// their response is delivered, before script callbacks see that response.
function receive(r) {
  if (!r.received) {
    r.received = true;
    if (r.acceptCookies && r.status >= 200) for (const value of r.setCookies) S.cookies.set(value, r.url, true);
  }
  return r;
}
function networkAnswer(status, body, rawHeaders, url, acceptCookies, delayed, latency = S.latency) {
  const headers = Object.create(null);
  const setCookies = [];
  for (const [name, value] of Array.isArray(rawHeaders) ? rawHeaders : Object.entries(rawHeaders || {})) {
    const key = String(name).toLowerCase();
    if (key === 'set-cookie') setCookies.push(String(value));
    else if (key !== 'set-cookie2') headers[key] = headers[key] == null ? String(value) : headers[key] + ', ' + value;
  }
  const r = { status, body, headers, url, acceptCookies, setCookies, received: false, latency };
  return delayed ? r : receive(r);
}
function respond(method, url, body, headers, kind, credentials = 'same-origin', delayed = false) {
  const u = new URL(String(url), S.url.href);
  const own = u.origin === S.origin;
  const include = credentials === 'include' || (credentials === 'same-origin' && own);
  headers = Object.fromEntries(Object.entries(headers || {}).filter(([k]) => !['cookie', 'cookie2'].includes(k.toLowerCase())));
  if (include) {
    const cookie = S.cookies.header(u.href, true, S.url.href);
    if (cookie) headers.cookie = cookie;
  }
  push(S.requests, {
    kind, method, url: u.href, own, body: body == null ? null : clip(body, 2000),
    headers: headers || {}, gesture: S.gesture, at: S.now - S.start,
  });
  const path = own ? u.pathname + u.search : u.href;
  const h = host();
  if (h) {
    // Sent now, delivered after the latency: the answer is the host's.
    const target = own ? path : u.href.split('#')[0];
    const pairs = Object.entries(headers || {}).map(([k, v]) => [String(k), String(v)]);
    const [status, rh, text, failed, latency] = h.fetch(kind, method, own, target, pairs, body == null ? null : String(body), [!!S.gesture, S.now]);
    if (failed != null) return { status: 0, error: failed, body: '', headers: {}, url: u.href, latency: latency ?? S.latency };
    return networkAnswer(status, text, rh, u.href, include, delayed, latency ?? S.latency);
  }
  const plain = own ? u.pathname : u.origin + u.pathname;
  const r = S.responses[method + ' ' + path] || S.responses[method + ' ' + plain] || S.responses[path] || S.responses[plain]
    || (method === 'GET' && own && S.files[u.pathname] != null ? { status: 200, body: S.files[u.pathname] } : null)
    || { status: 404, body: '' };
  return networkAnswer(r.status ?? 200, typeof r.body === 'string' ? r.body : JSON.stringify(r.body ?? ''), r.headers, u.href, include, delayed);
}

G.fetch = function fetch(input, init = undefined) {
  let request;
  try { if (!arguments.length) throw new NativeTypeError('fetch requires an input'); request = new Request(input, init); } catch (e) { return rejectPromise(e); }
  const req = requireRequest(request), body = requireBody(request), signal = signalState(req.signal);
  if (signal.aborted) return rejectPromise(signal.reason);
  const headers = {}; mapEach(requireHeaders(req.headers), (value, key) => { headers[key] = value; });
  return new NativePromise((resolve, reject) => {
    let timer = null, settled = false;
    const unsubscribe = onSignalAbort(req.signal, () => {
      if (settled) return;
      settled = true; if (timer !== null) mapDelete(S.timers, timer); reject(signalState(req.signal).reason);
    });
    let answer;
    try { answer = respond(req.method, req.url, body.text, headers, 'fetch', req.credentials, true); } catch (e) { settled = true; unsubscribe(); reject(e); return; }
    timer = addTimer(() => {
      if (settled) return;
      settled = true; unsubscribe();
      if (answer.error != null) { reject(new NativeTypeError('Failed to fetch')); return; }
      receive(answer);
      const noBody = req.method === 'HEAD' || answer.status === 204 || answer.status === 205 || answer.status === 304;
      const response = new Response(noBody ? null : answer.body, { status: answer.status, headers: answer.headers, url: answer.url });
      requireBody(response).signal = req.signal;
      resolve(response);
    }, answer.latency, [], false, 'fetch', false);
  });
};

class XMLHttpRequest extends L.EventTarget {
  constructor() {
    super();
    Object.assign(this, { readyState: 0, status: 0, statusText: '', responseText: '', response: '', responseType: '', responseURL: '', responseXML: null, timeout: 0, withCredentials: false });
    this._h = {};
    this._rh = {};
    this.upload = new L.EventTarget();
    for (const h of ['readystatechange', 'load', 'error', 'abort', 'loadstart', 'loadend', 'progress', 'timeout']) this['on' + h] = null;
  }
  open(method, url) { this._m = String(method).toUpperCase(); this._u = String(url); this._aborted = false; this.readyState = 1; this._fire('readystatechange'); }
  setRequestHeader(k, v) { this._h[String(k).toLowerCase()] = String(v); }
  overrideMimeType() {}
  getResponseHeader(k) { const v = this._rh[String(k).toLowerCase()]; return v == null ? null : v; }
  getAllResponseHeaders() { return Object.entries(this._rh).map(([k, v]) => k + ': ' + v + '\r\n').join(''); }
  abort() { this._aborted = true; this.readyState = 0; this._fire('abort'); }
  send(body) {
    const r = respond(this._m, this._u, bodyText(body), this._h, 'xhr', this.withCredentials ? 'include' : 'same-origin', true);
    this._fire('loadstart');
    addTimer(() => {
      if (this._aborted) return;
      if (r.error != null) {
        this.readyState = 4; this._fire('readystatechange');
        this._fire('error');
        this._fire('loadend');
        return;
      }
      receive(r);
      this.status = r.status;
      this.statusText = r.status === 200 ? 'OK' : '';
      this._rh = Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), String(v)]));
      this.responseURL = r.url;
      this.responseText = r.body;
      if (this.responseType === 'json') { try { this.response = JSON.parse(r.body); } catch { this.response = null; } }
      else this.response = r.body;
      this.readyState = 2; this._fire('readystatechange');
      this.readyState = 3; this._fire('readystatechange');
      this.readyState = 4; this._fire('readystatechange');
      this._fire('load');
      this._fire('loadend');
    }, r.latency, [], false, 'xhr', false);
  }
  _fire(type) {
    const ev = new ProgressEvent(type);
    fireEvent(this, ev);
  }
}
['UNSENT', 'OPENED', 'HEADERS_RECEIVED', 'LOADING', 'DONE'].forEach((k, i) => { XMLHttpRequest[k] = i; XMLHttpRequest.prototype[k] = i; });
G.XMLHttpRequest = XMLHttpRequest;

class Inert extends L.EventTarget {
  constructor(name, url) {
    super();
    unmodelled(name);
    if (url != null) respond('GET', url, null, {}, name);
    this.readyState = 0;
    this.url = url == null ? '' : String(url);
  }
  send() {}
  close() {}
  postMessage() {}
  terminate() {}
}
G.WebSocket = class WebSocket extends Inert { constructor(u) { super('WebSocket', String(u).replace(/^ws/, 'http')); } };
G.EventSource = class EventSource extends Inert { constructor(u) { super('EventSource', u); } };
G.Worker = class Worker extends Inert { constructor(u) { super('Worker', u); } };
G.SharedWorker = class SharedWorker extends Inert { constructor(u) { super('SharedWorker', u); } };
G.BroadcastChannel = class BroadcastChannel extends Inert { constructor() { super('BroadcastChannel'); } };

class Blob {
  constructor(parts = [], o = {}) {
    this._text = parts.map((p) => (p instanceof Blob ? p._text : typeof p === 'string' ? p : new TextDecoder().decode(p))).join('');
    this.type = o.type || '';
  }
  get size() { return this._text.length; }
  text() { return Promise.resolve(this._text); }
  arrayBuffer() { return Promise.resolve(new TextEncoder().encode(this._text).buffer); }
  slice(a, b) { return new Blob([this._text.slice(a, b)], { type: this.type }); }
}
class File extends Blob { constructor(parts, name, o = {}) { super(parts, o); this.name = String(name); this.lastModified = S.now; } }
class FileReader extends L.EventTarget {
  constructor() { super(); this.result = null; this.readyState = 0; this.onload = null; this.onloadend = null; this.onerror = null; }
  _read(f) {
    addTimer(() => {
      this.result = f();
      this.readyState = 2;
      for (const t of ['load', 'loadend']) fireEvent(this, new ProgressEvent(t));
    }, 0, [], false, 'FileReader', false);
  }
  readAsText(b) { this._read(() => b._text); }
  readAsDataURL(b) { this._read(() => 'data:' + (b.type || 'application/octet-stream') + ';base64,' + btoa(unescape(encodeURIComponent(b._text)))); }
  readAsArrayBuffer(b) { this._read(() => new TextEncoder().encode(b._text).buffer); }
  abort() {}
}
Object.assign(G, { Blob, File, FileReader });
for (const [Class, types] of [[MessagePort, ['message', 'messageerror']], [XMLHttpRequest, ['readystatechange', 'load', 'error', 'abort', 'loadstart', 'loadend', 'progress', 'timeout']], [FileReader, ['load', 'error', 'abort', 'loadstart', 'loadend', 'progress']]]) {
  for (const type of types) Object.defineProperty(Class.prototype, 'on' + type, { configurable: true, enumerable: true,
    get() { return getHandler(this, type); }, set(value) { setHandler(this, type, value); },
  });
}

// --- The page's document ----------------------------------------------------

class FormData {
  constructor(form, submitter) {
    this._l = [];
    if (!form) return;
    for (const el of form.querySelectorAll('input,select,textarea,button')) {
      const name = el.getAttribute('name');
      if (!name || el.hasAttribute('disabled')) continue;
      const tag = el.localName;
      const type = (el.getAttribute('type') || '').toLowerCase();
      if (tag === 'button' || ['submit', 'image', 'reset', 'button'].includes(type)) {
        if (el === submitter) this._l.push([name, el.getAttribute('value') || '']);
        continue;
      }
      if ((type === 'checkbox' || type === 'radio') && !el.checked) continue;
      if (type === 'file') continue;
      if (tag === 'select') {
        for (const o of el.querySelectorAll('option')) if (o.selected) this._l.push([name, o.value ?? o.textContent]);
        continue;
      }
      this._l.push([name, type === 'checkbox' || type === 'radio' ? el.getAttribute('value') ?? 'on' : String(el.value ?? '')]);
    }
  }
  append(k, v) { this._l.push([String(k), v instanceof Blob ? v : String(v)]); }
  delete(k) { this._l = this._l.filter((p) => p[0] !== k); }
  get(k) { const p = this._l.find((p) => p[0] === k); return p ? p[1] : null; }
  getAll(k) { return this._l.filter((p) => p[0] === k).map((p) => p[1]); }
  has(k) { return this._l.some((p) => p[0] === k); }
  set(k, v) { this.delete(k); this.append(k, v); }
  forEach(f, t) { for (const [k, v] of this._l) f.call(t, v, k, this); }
  *entries() { yield* this._l.map((p) => [...p]); }
  *keys() { for (const p of this._l) yield p[0]; }
  *values() { for (const p of this._l) yield p[1]; }
  [Symbol.iterator]() { return this.entries(); }
}
G.FormData = FormData;

function makeStorage(kind) {
  const m = new Map();
  const api = {
    getItem: (k) => (m.has(String(k)) ? m.get(String(k)) : null),
    setItem: (k, v) => { m.set(String(k), String(v)); push(S.storage, { kind, key: clip(k, 100), value: clip(v, 200), gesture: S.gesture }); },
    removeItem: (k) => { m.delete(String(k)); },
    clear: () => m.clear(),
    key: (i) => [...m.keys()][i] ?? null,
    get length() { return m.size; },
  };
  return new Proxy(api, {
    get: (t, k) => (k in t ? t[k] : typeof k === 'string' && m.has(k) ? m.get(k) : undefined),
    set: (t, k, v) => { api.setItem(k, v); return true; },
    has: (t, k) => k in t || m.has(k),
    deleteProperty: (t, k) => { m.delete(k); return true; },
    ownKeys: () => [...m.keys()],
    getOwnPropertyDescriptor: (t, k) => (m.has(k) ? { value: m.get(k), enumerable: true, configurable: true, writable: true } : undefined),
  });
}

function setCookie(text) {
  const written = S.cookies.set(String(text), S.url.href);
  if (written) push(S.cookieWrites, { name: clip(written.name, 100), value: clip(written.value, 200), flags: written.flags, gesture: S.gesture });
}

function navigate(target, how, extra = {}) {
  let u;
  try { u = new URL(String(target), S.url.href); } catch (e) { error(how, e); return; }
  if (u.protocol === 'javascript:') {
    let code = u.href.slice('javascript:'.length);
    try { code = decodeURIComponent(code); } catch {}
    runCode(code, 'javascript-url');
    return;
  }
  const strip = (h) => h.split('#')[0];
  if (strip(u.href) === strip(S.url.href) && u.hash && how !== 'location.reload' && !extra.method) {
    const oldURL = S.url.href;
    S.url = u;
    push(S.history, { how, url: u.href });
    addTimer(() => fireEvent(G, new HashChangeEvent('hashchange', { oldURL, newURL: u.href })), 0, [], false, 'hashchange', false);
    return;
  }
  push(S.navigations, { url: u.href, how, gesture: S.gesture, at: S.now - S.start, ...extra });
  { const h = host(); if (h) h.go(how, u.href, !!S.gesture); }
  if (!extra.popup && !S.ended) S.ended = { url: u.href, how };
}

const location = {};
for (const k of ['protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash']) {
  Object.defineProperty(location, k, {
    enumerable: true,
    get: () => S.url[k],
    set: (v) => { const u = new URL(S.url.href); u[k] = v; navigate(u.href, 'location.' + k); },
  });
}
Object.defineProperty(location, 'origin', { enumerable: true, get: () => S.url.origin });
Object.defineProperty(location, 'href', { enumerable: true, get: () => S.url.href, set: (v) => navigate(v, 'location.href') });
Object.assign(location, {
  assign: (v) => navigate(v, 'location.assign'),
  replace: (v) => navigate(v, 'location.replace'),
  reload: () => navigate(S.url.href, 'location.reload'),
  toString: () => S.url.href,
  ancestorOrigins: [],
});

const historyApi = {
  length: 1, state: null, scrollRestoration: 'auto',
  _go(how, state, url) {
    if (url != null) {
      const u = new URL(String(url), S.url.href);
      if (u.origin !== S.origin) throw new DOMException(how + ': another origin', 'SecurityError');
      S.url = u;
    }
    this.state = state ?? null;
    push(S.history, { how, url: S.url.href });
  },
  pushState(state, _title, url) { this._go('pushState', state, url); this.length++; },
  replaceState(state, _title, url) { this._go('replaceState', state, url); },
  back() { push(S.history, { how: 'back' }); },
  forward() { push(S.history, { how: 'forward' }); },
  go(n) { push(S.history, { how: 'go', n }); },
};

const mediaQuery = (q) => ({ matches: false, media: String(q), onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true });
const styleOf = (el) => new Proxy({}, {
  get: (t, k) => {
    if (k === 'getPropertyValue') return (p) => (el && el.style && el.style.getPropertyValue ? el.style.getPropertyValue(p) || '' : '');
    if (k === 'setProperty' || k === 'removeProperty') return () => '';
    if (typeof k !== 'string') return undefined;
    const v = el && el.style ? el.style[k] : '';
    return v == null ? '' : v;
  },
});

class Observer {
  constructor(cb) { this._cb = cb; this._els = []; }
  observe(el) { this._els.push(el); }
  unobserve(el) { this._els = this._els.filter((e) => e !== el); }
  disconnect() { this._els = []; }
  takeRecords() { return []; }
}
// A tall enough window sees every element it is asked about.
class IntersectionObserver extends Observer {
  constructor(cb, o = {}) { super(cb); this.root = o.root ?? null; this.rootMargin = o.rootMargin ?? '0px'; this.thresholds = [0]; }
  observe(el) {
    super.observe(el);
    addTimer(() => {
      if (!this._els.includes(el)) return;
      const rect = { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 };
      this._cb([{ target: el, isIntersecting: true, intersectionRatio: 1, boundingClientRect: rect, intersectionRect: rect, rootBounds: null, time: G.performance.now() }], this);
    }, 0, [], false, 'IntersectionObserver', false);
  }
}
class ResizeObserver extends Observer {}
class PerformanceObserver extends Observer { static get supportedEntryTypes() { return []; } }

// XPath, as far as htmx uses it: descendants with an attribute whose name
// starts with one of some prefixes.
class XPathExpression {
  constructor(expr) {
    const m = /^\.\/\/\*\[@\*\[(.*)\]\]$/s.exec(String(expr).trim());
    this.prefixes = m ? [...m[1].matchAll(/starts-with\(name\(\),\s*"([^"]*)"\)/g)].map((x) => x[1]) : null;
    if (!this.prefixes) unmodelled('XPath');
  }
  evaluate(node) {
    const found = [];
    if (this.prefixes && node && node.querySelectorAll) {
      for (const el of node.querySelectorAll('*')) {
        if (el.getAttributeNames().some((n) => this.prefixes.some((p) => n.startsWith(p)))) found.push(el);
      }
    }
    let i = 0;
    return { resultType: 0, snapshotLength: found.length, singleNodeValue: found[0] || null, iterateNext: () => found[i++] || null, snapshotItem: (k) => found[k] || null };
  }
}
G.XPathExpression = XPathExpression;
G.XPathEvaluator = class XPathEvaluator {
  createExpression(e) { return new XPathExpression(e); }
  createNSResolver(n) { return n; }
  evaluate(e, n) { return new XPathExpression(e).evaluate(n); }
};
G.XPathResult = { ANY_TYPE: 0, NUMBER_TYPE: 1, STRING_TYPE: 2, BOOLEAN_TYPE: 3, UNORDERED_NODE_ITERATOR_TYPE: 4, ORDERED_NODE_ITERATOR_TYPE: 5, UNORDERED_NODE_SNAPSHOT_TYPE: 6, ORDERED_NODE_SNAPSHOT_TYPE: 7, ANY_UNORDERED_NODE_TYPE: 8, FIRST_ORDERED_NODE_TYPE: 9 };

function installWindow(doc) {
  installSelectors();
  const shareObservers = installObservers(doc);
  shareTemplateObservers(shareObservers);
  shareObservers(templateOwner(doc));
  const upgradeCopies = installAdoption(L.Element, shareObservers, (name, e) => error('custom-element:' + name, e), BrowserDOMException);
  const view = doc.defaultView;
  for (const [k, v] of Object.entries(L)) {
    if (/^[A-Z]/.test(k) && typeof v === 'function') G[k] = v;
  }
  installHTMLConstructors(G, L);
  const createInternal = installRegistry(upgradeCopies, BrowserDOMException, (name, e) => error('custom-element:' + name, e));
  G.Document = L.Document;
  G.HTMLDocument = L.Document;
  for (const k of ['addEventListener', 'removeEventListener', 'dispatchEvent']) G[k] = view[k];
  const windowTarget = doc[EVENT_TARGET];
  registerWindow(doc, windowTarget, G, view);
  Object.defineProperty(doc, 'defaultView', { configurable: true, value: G });
  Object.defineProperty(G, 'event', { configurable: true, get: () => currentEvent, set(value) { Object.defineProperty(G, 'event', { configurable: true, writable: true, value }); } });
  const addWindow = G.addEventListener, removeWindow = G.removeEventListener;
  const eventHandler = (type, errorHandler = false) => {
    let handler = null;
    const listener = event => {
      const callback = handler;
      if (!callback) return;
      const special = errorHandler && isErrorEvent(event);
      const data = special ? errorEventData(event) : null;
      const args = special ? [data.message, data.filename, data.lineno, data.colno, data.error] : [event];
      const result = runDOMCallback(() => applyCallback(callback, G, args));
      if (special ? result === true : result === false) cancelEvent(event);
    };
    Object.defineProperty(G, 'on' + type, { configurable: true, get: () => handler, set(value) {
      const next = typeof value === 'function' ? value : null;
      if (handler && !next) applyCallback(removeWindow, G, [type, listener]);
      else if (!handler && next) applyCallback(addWindow, G, [type, listener]);
      handler = next;
    } });
  };
  eventHandler('error', true);
  eventHandler('unhandledrejection');
  eventHandler('rejectionhandled');
  eventHandler('load');
  for (const name of handlerNames) if (name !== 'onerror' && name !== 'onload') {
    const type = name.slice(2);
    Object.defineProperty(G, name, { configurable: true, enumerable: true,
      get() { return getHandler(G, type); }, set(value) { setHandler(G, type, value); },
    });
  }
  dispatchGlobalEvent = event => fireEvent(windowTarget, event);
  dispatchGlobalError = (info, value) => dispatchGlobalEvent(new ErrorEvent('error', { cancelable: true, message: info.eventMessage, error: value, filename: S.url?.href || '' }));
  G.reportError = function (value) {
    if (!arguments.length) throw new NativeTypeError('reportError requires an argument');
    error('reportError', value);
  };
  G.customElements = view.customElements;
  G.MutationObserver = view.MutationObserver;
  G.Image = view.Image;
  G.window = G.self = G.top = G.parent = G.frames = G;
  Object.assign(G, {
    document: doc, opener: null, name: '', closed: false, frameElement: null, length: 0,
    isSecureContext: true, origin: S.origin, history: historyApi,
    innerWidth: 1280, innerHeight: 800, outerWidth: 1280, outerHeight: 880, devicePixelRatio: 1,
    scrollX: 0, scrollY: 0, pageXOffset: 0, pageYOffset: 0, screenX: 0, screenY: 0, screenLeft: 0, screenTop: 0,
    screen: { width: 1280, height: 800, availWidth: 1280, availHeight: 800, colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0, addEventListener() {} } },
    localStorage: makeStorage('localStorage'), sessionStorage: makeStorage('sessionStorage'),
    IntersectionObserver, ResizeObserver, PerformanceObserver,
    scrollTo() {}, scrollBy() {}, scroll() {}, focus() {}, blur() {}, stop() {}, moveTo() {}, resizeTo() {},
    print() { push(S.dialogs, { kind: 'print', gesture: S.gesture }); },
    alert(m) { push(S.dialogs, { kind: 'alert', message: clip(m), gesture: S.gesture }); },
    confirm(m) { push(S.dialogs, { kind: 'confirm', message: clip(m), gesture: S.gesture }); return true; },
    prompt(m) { push(S.dialogs, { kind: 'prompt', message: clip(m), gesture: S.gesture }); return ''; },
    open(url) { if (url != null && url !== '') navigate(url, 'window.open', { popup: true }); return null; },
    close() {},
    getComputedStyle: styleOf,
    matchMedia: mediaQuery,
    getSelection: () => ({ rangeCount: 0, isCollapsed: true, removeAllRanges() {}, addRange() {}, getRangeAt() { return doc.createRange(); }, toString: () => '' }),
    postMessage(data, target) {
      push(S.requests, { kind: 'postMessage', method: 'POST', url: String(target ?? ''), own: true, body: clip(typeof data === 'string' ? data : JSON.stringify(data) ?? ''), headers: {}, gesture: S.gesture, at: S.now - S.start });
      addTimer(() => fireEvent(G, new MessageEvent('message', { data, origin: S.origin, source: G })), 0, [], false, 'postMessage', false);
    },
    CSS: { supports: () => false, escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\' + c) },
    Notification: Object.assign(function Notification() { unmodelled('Notification'); }, { permission: 'default', requestPermission: () => Promise.resolve('denied') }),
  });
  Object.defineProperty(G, 'location', { configurable: true, get: () => location, set: (v) => navigate(v, 'location') });

  G.navigator = {
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    appName: 'Netscape', appVersion: '5.0', product: 'Gecko', vendor: 'Google Inc.', platform: 'Linux x86_64',
    language: 'en-US', languages: ['en-US', 'en'], onLine: true, cookieEnabled: true, doNotTrack: null,
    hardwareConcurrency: 4, maxTouchPoints: 0, webdriver: false, pdfViewerEnabled: false,
    sendBeacon(url, data) {
      const r = respond('POST', url, bodyText(data), {}, 'beacon', 'include', true);
      if (r.acceptCookies && r.setCookies.length) addTimer(() => receive(r), r.latency, [], false, 'beacon-response', false);
      return true;
    },
    clipboard: {
      writeText(t) { push(S.dialogs, { kind: 'clipboard', message: clip(t), gesture: S.gesture }); return Promise.resolve(); },
      readText() { unmodelled('clipboard.read'); return Promise.resolve(''); },
    },
    serviceWorker: {
      register(url) { unmodelled('serviceWorker'); respond('GET', url, null, {}, 'serviceWorker'); return new Promise(() => {}); },
      getRegistrations: () => Promise.resolve([]),
      addEventListener() {}, removeEventListener() {},
      get controller() { return null; },
      ready: new Promise(() => {}),
    },
    get geolocation() { unmodelled('geolocation'); return undefined; },
    get mediaDevices() { unmodelled('mediaDevices'); return undefined; },
    permissions: { query: () => Promise.resolve({ state: 'prompt', addEventListener() {} }) },
    userAgentData: { brands: [], mobile: false, platform: 'Linux' },
  };

  const define = (o, k, d) => Object.defineProperty(o, k, { configurable: true, ...d });
  define(doc, 'readyState', { get: () => S.readyState });
  define(doc, 'location', { get: () => location, set: (v) => navigate(v, 'document.location') });
  define(doc, 'cookie', {
    get: () => S.cookies.header(S.url.href, false),
    set: (v) => setCookie(v),
  });
  define(doc, 'activeElement', { get: () => (S.active && S.active.isConnected ? S.active : doc.body) });
  for (const k of ['URL', 'documentURI', 'baseURI']) define(doc, k, { get: () => S.url.href });
  define(doc, 'domain', { get: () => S.url.hostname, set() {} });
  define(doc, 'referrer', { value: '' });
  define(doc, 'visibilityState', { value: 'visible' });
  define(doc, 'hidden', { value: false });
  define(doc, 'scrollingElement', { get: () => doc.documentElement });
  define(doc, 'fonts', { value: { ready: Promise.resolve(), add() {}, load: () => Promise.resolve([]), check: () => true, addEventListener() {} } });
  define(doc, 'currentScript', { get: () => S.current || null });
  doc.hasFocus = () => true;
  doc.execCommand = (c) => { unmodelled('execCommand:' + c); return false; };
  doc.elementFromPoint = () => null;
  doc.getSelection = G.getSelection;
  // A script the page creates runs once connected; one parsed from markup
  // (innerHTML and the like) never runs.
  const htmlPrototype = Object.getPrototypeOf(doc);
  const isHTMLDocument = Object.prototype.isPrototypeOf.bind(htmlPrototype);
  const creationIs = options => {
    if (options == null) return null;
    if (typeof options !== 'object' && typeof options !== 'function') { domString(options); return null; }
    const value = options.is;
    return value === undefined ? null : domString(value);
  };
  const createElement = function (name, options) {
    if (!arguments.length) throw new TypeError('createElement requires a name');
    const html = isHTMLDocument(this), converted = domString(name), is = creationIs(options);
    const local = html ? converted.replace(/[A-Z]/g, c => c.toLowerCase()) : converted;
    // Reuse the namespace factory's local-name validation without treating
    // a colon in createElement's name as a namespace prefix.
    qualifiedName(null, local.replace(/:/g, '_'), 2, BrowserDOMException);
    shareObservers(this);
    return createInternal(this, { namespace: html ? HTML_NS : null, prefix: null, local, qualified: local }, is);
  };
  htmlPrototype.createElement = createElement;
  L.Document.prototype.createElement = createElement;
  installCloning(L, shareObservers, (copy, identity, original) => {
    rememberScript(copy, identity, scriptRecord(original)?.alreadyStarted || false);
  }, upgradeCopies, BrowserDOMException);
  L.Document.prototype.createElementNS = function (ns, name, options) {
    const identity = qualifiedName(ns, name, arguments.length, BrowserDOMException), is = creationIs(options);
    shareObservers(this);
    return createInternal(this, identity, is);
  };
  const parsing = (f, sink, at = 0) => function (...a) {
    if (sink) { a[at] = String(a[at]); toMarkup(sink, a[at]); }
    return f.apply(this, a);
  };
  const htmlFragment = (node, markup, inert = true) => {
    const context = isShadowRoot(node) ? scriptShadowHost(node) : node;
    const result = parseHTMLFragment(markup, context, node.ownerDocument, inert);
    upgradeCopies(fragmentElements(result));
    return result;
  };
  for (const proto of [L.Element.prototype, L.ShadowRoot.prototype, L.DocumentFragment.prototype]) {
    for (const key of ['innerHTML', 'outerHTML']) {
      const d = Object.getOwnPropertyDescriptor(proto, key);
      if (!d?.set) continue;
      Object.defineProperty(proto, key, { ...d, set: parsing(function (markup) {
        if (documentMode(this.ownerDocument) === undefined) return d.set.call(key === 'innerHTML' ? (templateContent(this) || this) : this, markup);
        if (key === 'outerHTML') {
          if (this.parentNode) this.replaceWith(htmlFragment(this.parentNode, markup));
        } else {
          const target = templateContent(this) || this;
          const content = parseHTMLFragment(markup, this, target.ownerDocument);
          upgradeCopies(fragmentElements(content));
          target.replaceChildren(content);
        }
      }, key) });
    }
  }
  const adjacentHTML = L.Element.prototype.insertAdjacentHTML;
  L.Element.prototype.insertAdjacentHTML = parsing(function (position, markup) {
    if (documentMode(this.ownerDocument) === undefined) return adjacentHTML.call(this, position, markup);
    position = String(position).toLowerCase();
    if (position === 'beforebegin' || position === 'afterend') {
      if (!this.parentNode || this.parentNode.nodeType === 9) throw new BrowserDOMException('No parent for adjacent HTML', 'NoModificationAllowedError');
      const content = htmlFragment(this.parentNode, markup);
      if (position === 'beforebegin') this.before(content); else this.after(content);
    } else if (position === 'afterbegin' || position === 'beforeend') {
      const content = htmlFragment(this, markup);
      if (position === 'afterbegin') this.prepend(content); else this.append(content);
    } else throw new BrowserDOMException('Invalid insertion position', 'SyntaxError');
  }, 'insertAdjacentHTML', 1);
  const parseDocument = L.DOMParser.prototype.parseFromString;
  L.DOMParser.prototype.parseFromString = parsing(function (markup, mime, ...rest) {
    return mime === 'text/html' ? parseHTML(markup, false) : parseDocument.call(this, markup, mime, ...rest);
  });
  const rangePrototype = Object.getPrototypeOf(doc.createRange());
  const contextualFragment = rangePrototype.createContextualFragment;
  rangePrototype.createContextualFragment = function (markup) {
    const context = this.commonAncestorContainer || doc;
    const owner = context.nodeType === 9 ? context : context.ownerDocument;
    if (documentMode(owner) !== undefined) return withReactions(() => {
      const result = parseHTMLFragment(markup, context, owner, false);
      upgradeCopies(fragmentElements(result));
      return result;
    });
    return contextualFragment.call(this, markup);
  };
  const T = L.HTMLTemplateElement.prototype;
  const noModule = Object.getOwnPropertyDescriptor(L.HTMLScriptElement.prototype, 'nomodule');
  define(L.HTMLScriptElement.prototype, 'noModule', noModule);
  const setInner = Object.getOwnPropertyDescriptor(L.Element.prototype, 'innerHTML').set;
  define(T, 'innerHTML', {
    get() { return templateInnerHTML(this); },
    set(v) { setInner.call(this, v); },
  });
  L.Document.prototype.createEvent = function (name) {
    if (!arguments.length) throw new NativeTypeError('createEvent requires a name');
    const type = domString(name).toLowerCase();
    const Classes = { __proto__: null, event: Ev, events: Ev, htmlevents: Ev, customevent: L.CustomEvent, uievent: UIEvent, uievents: UIEvent, mouseevent: MouseEvent, mouseevents: MouseEvent, keyboardevent: KeyboardEvent };
    const Class = Classes[type];
    if (!Class) throw new BrowserDOMException('Unsupported event interface', 'NotSupportedError');
    const event = new Class(''); markEventUninitialized(event); return event;
  };
  doc.evaluate = (expr, node) => new XPathExpression(expr).evaluate(node);

  // A fragment has descendant text and the same replace-with-text setter
  // as an element; linkedom otherwise inherits Node's null/no-op stubs.
  Object.defineProperty(L.DocumentFragment.prototype, 'textContent', Object.getOwnPropertyDescriptor(L.Element.prototype, 'textContent'));
  installShadowConstraints(L.Element, BrowserDOMException);
  installSerialization(L);
  installScriptMutations(L, scriptsChanged);
  installReactionBoundaries(L);

  // linkedom puts stubs on Node.prototype and the real accessors on its
  // subclasses. Code that takes an accessor from Node.prototype and calls
  // it (Svelte does, for speed) gets the subclass's.
  const NP = L.Node.prototype;
  for (const k of Object.getOwnPropertyNames(NP)) {
    const base = Object.getOwnPropertyDescriptor(NP, k);
    if (!base.get) continue;
    const cache = new Map();
    const own = (proto) => {
      let d = cache.get(proto);
      if (d === undefined) {
        d = null;
        for (let p = proto; p && p !== NP; p = Object.getPrototypeOf(p)) {
          const x = Object.getOwnPropertyDescriptor(p, k);
          if (x) { d = x; break; }
        }
        cache.set(proto, d);
      }
      return d;
    };
    Object.defineProperty(NP, k, {
      configurable: true,
      enumerable: base.enumerable,
      get() { const d = own(Object.getPrototypeOf(this)); return d ? (d.get ? d.get.call(this) : d.value) : base.get.call(this); },
      set: base.set ? function (v) { const d = own(Object.getPrototypeOf(this)); if (d && d.set) d.set.call(this, v); else base.set.call(this, v); } : undefined,
    });
  }
  doc.write = doc.writeln = (...a) => { unmodelled('document.write'); push(S.code, { where: 'document.write', code: clip(a.join(''), 2000), gesture: S.gesture }); toMarkup('document.write', a.join('')); };

  const E = L.Element.prototype;
  const H = L.HTMLElement.prototype;
  E.scrollIntoView = function () {};
  E.scrollTo = E.scrollBy = E.scroll = function () {};
  E.getClientRects = function () { return []; };
  E.checkVisibility = function () { return true; };
  E.setPointerCapture = E.releasePointerCapture = function () {};
  E.hasPointerCapture = function () { return false; };
  E.animate = function () {
    return { finished: Promise.resolve(), cancel() {}, finish() {}, play() {}, pause() {}, reverse() {}, addEventListener() {}, onfinish: null };
  };
  E.getAnimations = function () { return []; };
  for (const k of ['offsetWidth', 'offsetHeight', 'offsetTop', 'offsetLeft', 'clientWidth', 'clientHeight', 'clientTop', 'clientLeft', 'scrollWidth', 'scrollHeight']) {
    define(E, k, { get: () => 0 });
  }
  define(E, 'scrollTop', { get: () => 0, set() {} });
  define(E, 'scrollLeft', { get: () => 0, set() {} });
  define(E, 'offsetParent', { get() { return this.parentElement; } });
  H.focus = function () {
    if (S.active === this) return;
    const old = S.active;
    S.active = this;
    if (old && old.dispatchEvent) { old.dispatchEvent(new FocusEvent('blur')); old.dispatchEvent(new FocusEvent('focusout', { bubbles: true })); }
    this.dispatchEvent(new FocusEvent('focus'));
    this.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
  };
  H.blur = function () { if (S.active === this) { S.active = null; this.dispatchEvent(new FocusEvent('blur')); } };
  H.click = function () {
    if (nodeInfo(this)?.kind !== 1 || !htmlName(this)) throw new NativeTypeError('An HTMLElement is required');
    if (disabled(this) || clicking(this)) return;
    rememberClick(this, true);
    try { click(this, false); } finally { rememberClick(this, false); }
  };
  define(H, 'isContentEditable', { get() { const v = this.getAttribute('contenteditable'); return v === '' || v === 'true'; } });
  define(H, 'form', { get() { return this.closest('form'); } });

  const I = L.HTMLInputElement.prototype;
  define(I, 'type', { get() { if (htmlName(this) !== 'input') throw new NativeTypeError('An HTMLInputElement is required'); return controlType(this); },
    set(value) { if (htmlName(this) !== 'input') throw new NativeTypeError('An HTMLInputElement is required'); setControlAttribute(this, 'type', value); },
  });
  define(L.HTMLDetailsElement.prototype, 'open', { get() { if (htmlName(this) !== 'details') throw new NativeTypeError('An HTMLDetailsElement is required'); return eventAttribute(this, 'open') !== null; },
    set(value) { if (htmlName(this) !== 'details') throw new NativeTypeError('An HTMLDetailsElement is required'); setControlAttribute(this, 'open', value ? '' : null); },
  });
  define(I, 'checked', { get() { return checked(this); }, set(value) { setChecked(this, value); } });
  define(I, 'indeterminate', { get() { return indeterminate(this); }, set(value) { setIndeterminate(this, value); } });
  define(I, 'defaultChecked', { get() { return this.hasAttribute('checked'); }, set(v) { this.toggleAttribute('checked', !!v); } });
  define(I, 'files', { get: () => [] });
  define(I, 'valueAsNumber', { get() { return this.value === '' ? NaN : Number(this.value); }, set(v) { this.value = String(v); } });
  I.select = I.setSelectionRange = I.setCustomValidity = I.reportValidity = function () { return true; };
  I.checkValidity = function () { return true; };
  const F = L.HTMLFormElement.prototype;
  define(F, 'elements', { get() { return this.querySelectorAll('input,select,textarea,button,fieldset,output'); } });
  F.requestSubmit = function (submitter) { submit(this, submitter || null); };
  F.submit = function () { formNavigate(this, null); };
  F.reset = function () { this.dispatchEvent(new Ev('reset', { bubbles: true, cancelable: true })); };
  F.checkValidity = F.reportValidity = function () { return true; };
  const O = L.HTMLOptionElement.prototype;
  const selected = new WeakMap();
  define(O, 'selected', {
    get() { return selected.has(this) ? selected.get(this) : this.hasAttribute('selected'); },
    set(v) { selected.set(this, !!v); },
  });
  const Sel = L.HTMLSelectElement.prototype;
  const options = (s) => [...s.querySelectorAll('option')];
  define(Sel, 'selectedIndex', {
    get() { const o = options(this); const i = o.findIndex((x) => x.selected); return i < 0 && o.length && !this.hasAttribute('multiple') ? 0 : i; },
    set(i) { options(this).forEach((o, j) => { o.selected = j === i; }); },
  });
  define(Sel, 'value', {
    get() { const o = options(this)[this.selectedIndex]; return o ? (o.hasAttribute('value') ? o.getAttribute('value') : o.textContent) : ''; },
    set(v) { options(this).forEach((o) => { o.selected = (o.hasAttribute('value') ? o.getAttribute('value') : o.textContent) === String(v); }); },
  });
  define(Sel, 'selectedOptions', { get() { return options(this).filter((o) => o.selected); } });
}

// --- What a person does: clicks, typing, submits ------------------------------

const TYPED = new Set(['', 'text', 'search', 'email', 'url', 'tel', 'password', 'number', 'date', 'time', 'datetime-local', 'month', 'week']);
const CLICKISH = new Set(['click', 'mousedown', 'mouseup', 'pointerdown', 'pointerup', 'touchstart', 'touchend', 'dblclick', 'submit', 'change', 'input', 'keydown', 'keyup', 'keypress']);
const NATIVE = new Set(['button', 'input', 'select', 'textarea', 'summary']);
const interactive = (el) => {
  const t = el.localName;
  if (NATIVE.has(t)) return true;
  if ((t === 'a' || t === 'area') && el.hasAttribute('href')) return true;
  return el.hasAttribute('onclick') || el.getAttribute('role') === 'button' || el.hasAttribute('contenteditable') || el.hasAttribute('tabindex');
};

function delegated(el) {
  for (const k of Object.keys(el)) {
    if (k.startsWith('__reactProps')) {
      const p = el[k];
      if (p && (p.onClick || p.onMouseDown || p.onPointerDown || p.onChange || p.onInput || p.onSubmit)) return true;
    } else if (k === '__click' || k === '__input' || k === '__change' || k === '__pointerdown' || k === '__mousedown') {
      return true;
    }
  }
  return false;
}

function candidates() {
  const out = [];
  const doc = G.document;
  for (const el of doc.querySelectorAll('*')) {
    if (el.hasAttribute('disabled') || el.hasAttribute('hidden')) continue;
    const types = S.listened.get(el);
    const own = types && [...types].some((t) => CLICKISH.has(t));
    if (own || interactive(el) || delegated(el)) out.push(el);
  }
  S.cands = out;
  return out.map((el, i) => {
    const tag = el.localName;
    const type = (el.getAttribute('type') || '').toLowerCase();
    const kind = (tag === 'input' && TYPED.has(type)) || tag === 'textarea' || el.isContentEditable ? 'type' : tag === 'select' ? 'select' : 'click';
    return { i, tag, id: el.id || '', kind, text: clip((el.textContent || '').trim().replace(/\s+/g, ' '), 60) };
  });
}

function dispatch(el, ev) { return fireEvent(el, ev); }

function click(el, gesture) {
  const was = S.gesture;
  S.gesture = was || gesture;
  try {
    const o = { bubbles: true, cancelable: true, composed: true, view: G, button: 0, detail: 1 };
    if (gesture) {
      dispatch(el, new PointerEvent('pointerdown', o));
      dispatch(el, new MouseEvent('mousedown', o));
      if (el.focus) el.focus();
      dispatch(el, new PointerEvent('pointerup', o));
      dispatch(el, new MouseEvent('mouseup', o));
    }
    const ev = new PointerEvent('click', { ...o, detail: gesture ? 1 : 0 });
    fireEvent(el, ev, gesture);
  } finally {
    S.gesture = was;
  }
}

const clickFlags = new WeakMap(), clicking = clickFlags.get.bind(clickFlags), rememberClick = clickFlags.set.bind(clickFlags);
function activationKind(node) {
  const name = htmlName(node), identity = nameIdentity(node);
  if (identity?.namespace === SVG_NS && identity.local === 'a' && (eventAttribute(node, 'href') !== null || eventAttribute(node, 'xlink:href') !== null)) return 'link';
  if (name === 'input' || name === 'button' || name === 'label') return name;
  if (name === 'a' || name === 'area') return eventAttribute(node, 'href') === null ? null : 'link';
  if (name === 'summary' && htmlName(physicalParent(node)) === 'details') {
    const siblings = treeElements(physicalParent(node));
    for (let i = 1; i < siblings.length; i++) if (physicalParent(siblings[i]) === physicalParent(node) && htmlName(siblings[i]) === 'summary') return siblings[i] === node ? 'summary' : null;
  }
  return null;
}
function prepareActivation(path, event) {
  const state = eventState(event);
  if (!state.mouse || state.type !== 'click') return null;
  for (let i = 0; i < path.length; i++) {
    const entry = path[i];
    if (i && !state.bubbles && !entry.atTarget) continue;
    const kind = activationKind(entry.node);
    if (kind) return { node: entry.node, kind, before: kind === 'input' ? beginInputActivation(entry.node) : null, original: path[0].node };
  }
  return null;
}
function completeActivation(action, event) {
  if (!action) return;
  const { node, kind, before } = action, state = eventState(event);
  if (state.canceled) { if (kind === 'input') cancelInputActivation(node, before); return; }
  const type = controlType(node);
  if (kind === 'input' && (type === 'checkbox' || type === 'radio')) {
    if (before.changed && connected(node)) {
      fireEvent(node, new Ev('input', { bubbles: true, composed: true }));
      fireEvent(node, new Ev('change', { bubbles: true }));
    }
    return;
  }
  if (kind === 'link') {
    const href = eventAttribute(node, 'href') ?? eventAttribute(node, 'xlink:href');
    if (href !== null) {
      const target = eventAttribute(node, 'target');
      const extra = target && target !== '_self' ? { popup: true, target } : {}, gesture = S.gesture;
      let destination; try { destination = new URL(href, S.url.href).href; } catch { return; }
      addTimer(() => { const was = S.gesture; S.gesture = gesture; try { navigate(destination, 'link', extra); } finally { S.gesture = was; } }, 0, [], false, 'link-navigation', false);
    }
  } else if (kind === 'input' || kind === 'button') {
    if (disabled(node)) return;
    const form = formOwner(node), buttonType = kind === 'button' && type !== 'reset' && type !== 'button' ? 'submit' : type;
    if (form && (buttonType === 'submit' || buttonType === 'image')) submit(form, node);
    else if (form && buttonType === 'reset') form.reset();
  } else if (kind === 'summary') {
    const details = physicalParent(node);
    if (activationKind(node) === 'summary' && htmlName(details) === 'details') setControlAttribute(details, 'open', eventAttribute(details, 'open') === null ? '' : null);
  } else if (kind === 'label') {
    for (let current = action.original; current && current !== node; current = physicalParent(current)) {
      const name = htmlName(current);
      if (name === 'input' || name === 'button' || name === 'select' || name === 'textarea' || (name === 'a' && eventAttribute(current, 'href') !== null)) return;
    }
    const id = eventAttribute(node, 'for'), nodes = treeElements(id === null ? node : S.document);
    for (let i = id === null ? 1 : 0; i < nodes.length; i++) {
      const control = nodes[i], name = htmlName(control);
      if (id !== null && eventAttribute(control, 'id') !== id) continue;
      if (name === 'button' || name === 'select' || name === 'textarea' || (name === 'input' && controlType(control) !== 'hidden')) {
        if (!disabled(control)) click(control, false);
        return;
      }
      if (id !== null) return;
    }
  }
}

function submit(form, submitter) {
  if (!dispatch(form, new SubmitEvent('submit', { bubbles: true, cancelable: true, submitter }))) return;
  formNavigate(form, submitter);
}

function formNavigate(form, submitter) {
  const attr = (k) => (submitter && submitter.getAttribute('form' + k)) || form.getAttribute(k);
  const method = (attr('method') || 'get').toLowerCase();
  if (method === 'dialog') return;
  const action = new URL(attr('action') || S.url.href, S.url.href);
  const data = new URLSearchParams([...new FormData(form, submitter)].map(([k, v]) => [k, typeof v === 'string' ? v : '[file]'])).toString();
  const target = attr('target');
  const extra = target && target !== '_self' ? { popup: true, target } : {};
  if (method === 'post') navigate(action.href, 'form', { method: 'POST', body: clip(data, 2000), ...extra });
  else { action.search = data; navigate(action.href, 'form', { method: 'GET', ...extra }); }
}

function act(i, value) {
  const el = S.cands[i];
  if (!el || !el.isConnected) return false;
  const c = { i, tag: el.localName, id: el.id || '' };
  S.gesture = true;
  try {
    const tag = el.localName;
    const type = (el.getAttribute('type') || '').toLowerCase();
    if ((tag === 'input' && TYPED.has(type)) || tag === 'textarea' || el.isContentEditable) {
      const v = value == null ? 'x' : String(value);
      el.focus();
      if (el.isContentEditable) el.textContent = v; else el.value = v;
      dispatch(el, new L.InputEvent('input', { bubbles: true, data: v, inputType: 'insertText' }));
      dispatch(el, new Ev('change', { bubbles: true }));
      c.kind = 'type';
      c.value = clip(v, 100);
    } else if (tag === 'select') {
      const opts = el.querySelectorAll('option');
      if (opts.length) el.selectedIndex = Number(value ?? 1) % opts.length;
      dispatch(el, new L.InputEvent('input', { bubbles: true }));
      dispatch(el, new Ev('change', { bubbles: true }));
      c.kind = 'select';
    } else {
      click(el, true);
      c.kind = 'click';
    }
  } finally {
    S.gesture = false;
  }
  push(S.actions, c);
  return true;
}

// --- Scripts -------------------------------------------------------------------

function scriptKind(s) {
  const identity = scriptIdentity(s);
  if (!identity || identity.local !== 'script' || (identity.namespace !== HTML_NS && identity.namespace !== SVG_NS)) return null;
  const type = scriptAttribute(s, 'type');
  const language = identity.namespace === HTML_NS ? scriptAttribute(s, 'language') : null;
  const t = (type == null ? (language ? 'text/' + language : '') : type).toLowerCase();
  const mime = type == null ? t : t.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
  // Firefox also accepts ASCII whitespace around module. Keep that browser
  // behavior without accepting non-ASCII whitespace as a JavaScript MIME.
  if (mime === 'module') return 'module';
  if (t === 'importmap' || t === 'speculationrules') return t;
  if (t === '' || /^(text|application)\/(x-)?(java|ecma)script$/.test(mime)
    || /^text\/(javascript1\.[0-5]|jscript|livescript)$/.test(mime)) return 'classic';
  return null;
}

function scriptSource(s) {
  return scriptIdentity(s)?.namespace === SVG_NS ? (scriptAttribute(s, 'href') ?? scriptAttribute(s, 'xlink:href')) : scriptAttribute(s, 'src');
}

function scriptDocument(node) {
  let root = nodeRoot(node);
  while (isShadowRoot(root)) {
    const host = scriptShadowHost(root);
    if (!host) return null;
    root = nodeRoot(host);
  }
  return isDocument(root) ? root : null;
}

// Preparation sets alreadyStarted even when scripting is disabled or
// nomodule suppresses execution. Empty, detached and data-block scripts
// return earlier and can still be prepared by a later mutation.
function prepareScript(s) {
  const record = scriptRecord(s);
  if (!record || record.alreadyStarted) return null;
  const src = scriptSource(s), code = scriptText(s);
  if (src == null && code === '') return null;
  const document = scriptDocument(s);
  if (!document) return null;
  const kind = scriptKind(s);
  if (!kind) return null;
  record.alreadyStarted = true;
  record.preparationDocument = scriptOwner(s);
  if (document !== S.document || (kind === 'classic' && scriptAttribute(s, 'nomodule') != null && record.identity.namespace === HTML_NS)) return null;
  if (kind === 'importmap' || kind === 'speculationrules') { unmodelled('script:' + kind); return null; }
  const n = scriptN++;
  let prepared;
  if (src == null) {
    push(S.code, { where: 'script', code: clip(code, 2000), gesture: S.gesture });
    prepared = { kind, url: kind === 'module' ? S.url.href.split('#')[0] + '#inline-' + n : S.url.href, code, inline: true };
  } else {
    let url;
    try { url = new URL(src, S.url.href).href; }
    catch { scriptError(s); return null; }
    if (src === '' && record.identity.namespace === HTML_NS) { scriptError(s); return null; }
    prepared = { kind, url, code: file(url), inline: false };
  }
  record.prepared = prepared;
  return prepared;
}

function scriptError(el) {
  addTimer(() => fireEvent(el, new Ev('error')), 0, [], false, 'script-error', false);
}

function scriptsChanged(nodes) {
  const inline = [];
  for (let i = 0; i < nodes.length; i++) {
    const el = nodes[i], script = prepareScript(el);
    if (!script) continue;
    if (script.inline && script.kind === 'classic') inline.push([el, script]);
    else S.dynamicScripts.push(el);
  }
  for (let i = 0; i < inline.length; i++) {
    const [el, script] = inline[i];
    const record = scriptRecord(el);
    record.prepared = null;
    if (record.preparationDocument !== scriptOwner(el)) continue;
    const current = S.current, currentEl = S.currentEl, external = S.currentExternal;
    S.current = S.currentEl = el;
    S.currentExternal = false;
    try { runDOMCallback(() => S.runClassic(script.code, script.url)); }
    catch (e) { error('script:' + script.url, e); }
    finally { S.current = current; S.currentEl = currentEl; S.currentExternal = external; }
  }
}

// A script's code: what its URL answers, or null when it failed.
function file(url) {
  const u = new URL(url);
  const own = u.origin === S.origin;
  const r = respond('GET', u.href, null, {}, 'script', 'same-origin', true);
  if (host()) {
    S.now += r.latency;
    receive(r);
    return r.error == null && r.status >= 200 && r.status < 300 ? r.body : null;
  }
  const body = own ? S.files[u.pathname] : S.files[u.href];
  return body == null ? null : body;
}

let scriptN = 0;
function nextScript(el) {
  S.current = null;
  const record = scriptRecord(el);
  const s = record?.prepared || prepareScript(el);
  if (!s) return null;
  record.prepared = null;
  if (record.preparationDocument !== scriptOwner(el)) return null;
  if (s.kind === 'classic') S.current = el;
  S.currentEl = el;
  S.currentExternal = !s.inline;
  return s;
}

// The document's scripts in the order a browser runs them: blocking ones,
// then deferred and module ones, then async ones. Preparation happens when
// reached, so empty/data-block scripts keep their unstarted state.
function pageScripts() {
  const all = [...G.document.querySelectorAll('script')];
  const blocking = [], deferred = [], later = [];
  for (const s of all) {
    const kind = scriptKind(s);
    if (!kind) continue;
    const src = scriptSource(s) != null;
    if (scriptAttribute(s, 'async') != null && (src || kind === 'module')) later.push(s);
    else if (kind === 'module' || (src && scriptAttribute(s, 'defer') != null)) deferred.push(s);
    else blocking.push(s);
  }
  S.scripts = [...blocking, ...deferred, ...later];
  return S.scripts.length;
}

function newScripts() {
  S.scripts = S.dynamicScripts;
  S.dynamicScripts = [];
  return S.scripts.length;
}

function scriptAt(batch, i) {
  const el = batch[i];
  return el ? nextScript(el) : null;
}

function scriptDone(ok) {
  const el = S.currentEl;
  const external = S.currentExternal;
  S.current = null;
  S.currentEl = null;
  S.currentExternal = false;
  if (el && external) fireEvent(el, new Ev(ok ? 'load' : 'error'));
}

// --- The driver's handle ---------------------------------------------------------

G.console = Object.fromEntries(['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir', 'table'].map((level) => [level, (...a) => {
  push(S.console, { level, at: S.now - S.start, text: clip(a.map((x) => { if (typeof x === 'string') return x; try { return JSON.stringify(x); } catch { return String(x); } }).join(' ')) });
}]));
Object.assign(G.console, { group() {}, groupCollapsed() {}, groupEnd() {}, time() {}, timeEnd() {}, timeLog() {}, count() {}, countReset() {}, assert(c, ...a) { if (!c) G.console.error('Assertion failed:', ...a); } });

G.__af = {
  bindClassic(run) { S.runClassic = run; delete G.__af.bindClassic; },
  // `now` and `hostSeed`: the host's clock and randomness, when it has them.
  init(json, now, hostSeed) {
    const s = JSON.parse(json);
    S.url = new URL(s.url || 'https://app.example/');
    S.origin = S.url.origin;
    S.start = S.now = s.now ?? now ?? RealDate.UTC(2026, 10, 2, 10);
    S.horizon = S.now;
    seed = s.seed ?? hostSeed ?? 1;
    S.files = s.files || {};
    S.responses = s.responses || {};
    S.latency = s.latency_ms ?? 5;
    for (const [k, v] of Object.entries(s.cookies || {})) S.cookies.seed(k, v, S.url.href);
    for (const cookie of s.request_cookies || []) S.cookies.request(cookie, S.url.href);
    for (const cookie of s.set_cookies || []) S.cookies.set(cookie, S.url.href, true);
    if (s.probe_cookie) {
      const base = String(s.probe_cookie.name);
      let name = base;
      for (let i = 1; S.cookies.has(name); i++) name = base + '_' + i;
      S.cookies.seed(name, s.probe_cookie.value, S.url.href);
    }
    const doc = parseHTML(s.html || '', true);
    S.document = doc;
    installWindow(doc);
    return pageScripts();
  },
  scriptAt,
  scriptList: () => copyScriptBatch(S.scripts),
  scriptDone,
  newScripts,
  resolve(spec, base) {
    if (!/^(\.{0,2}\/|[a-zA-Z][a-zA-Z0-9+.-]*:)/.test(spec)) throw new TypeError(`Failed to resolve module specifier "${spec}"`);
    return new URL(spec, base).href;
  },
  file,
  error(where, e, notify = true) { error(where, e, notify); },
  // A module's evaluation promise: its rejection is the module's error.
  watch(p, url) { p.then(null, (e) => error('module:' + url, e)); },
  // A rejection is unhandled if no handler is attached by the end of the
  // microtask checkpoint.
  rejected(promise, reason) { mapSet(rejections, promise, { reason, handled: false }); },
  handled(promise) {
    const pending = mapGet(rejections, promise);
    if (pending) { pending.handled = true; mapDelete(rejections, promise); }
    const record = notified(promise);
    if (record) {
      forgetNotified(promise);
      handledRejections[handledRejections.length] = [promise, record.reason];
    }
  },
  checkpoint() {
    const pending = [], handled = handledRejections;
    handledRejections = [];
    mapEach(rejections, (record, promise) => { pending[pending.length] = [promise, record]; });
    let dispatched = false;
    for (let i = 0; i < pending.length; i++) {
      const [promise, record] = pending[i];
      if (mapGet(rejections, promise) !== record || record.handled) continue;
      dispatched = true;
      const unhandled = dispatchGlobalEvent(new PromiseRejectionEvent('unhandledrejection', { cancelable: true, promise, reason: record.reason }));
      mapDelete(rejections, promise);
      if (!record.handled) rememberNotified(promise, record);
      if (unhandled) error('unhandledrejection', record.reason, false);
    }
    for (let i = 0; i < handled.length; i++) {
      const [promise, reason] = handled[i];
      dispatched = true;
      dispatchGlobalEvent(new PromiseRejectionEvent('rejectionhandled', { promise, reason }));
    }
    return dispatched;
  },
  ready() {
    S.readyState = 'interactive';
    fireEvent(G.document, new Ev('DOMContentLoaded', { bubbles: true }));
  },
  loaded() {
    S.readyState = 'complete';
    const ev = new Ev('load');
    fireEvent(G, ev, true, S.document);
    fireEvent(G, new Ev('pageshow'));
  },
  // Lets due tasks run for `ms` more virtual milliseconds.
  until(ms) { S.horizon = S.now + ms; },
  // Fast-forward, as a tab in the background: no timer fires more than
  // once per `ms`, so days pass in a few steps.
  throttle(ms) {
    S.throttle = ms;
    for (const t of S.timers.values()) if (t.repeat) t.repeat = Math.max(t.repeat, ms);
  },
  step,
  now: () => S.now,
  // When the next task is due, or -1 when none is.
  next() {
    let due = -1;
    for (const t of S.timers.values()) if (due < 0 || t.due < due) due = t.due;
    return due;
  },
  idle() { S.now = Math.max(S.now, S.horizon); },
  ended: () => !!S.ended,
  candidates: () => JSON.stringify(candidates()),
  count: () => candidates().length,
  act,
  text: () => (G.document.body ? G.document.body.textContent.replace(/\s+/g, ' ').trim() : ''),
  report() {
    return JSON.stringify({
      url: S.url.href, ended: S.ended, now_ms: S.now - S.start, steps: S.steps, timers: S.timers.size,
      errors: S.errors, console: S.console, requests: S.requests, navigations: S.navigations,
      code: S.code, cookies: S.cookieWrites, storage: S.storage, dialogs: S.dialogs, history: S.history,
      unmodelled: [...S.unmodelled], actions: S.actions,
      text: G.__af.text().slice(0, 2000),
    });
  },
};
