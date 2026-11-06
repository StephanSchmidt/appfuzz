// The page's world: linkedom's DOM plus the Web APIs a page's scripts
// expect, on virtual time. The guest drives it through globalThis.__af:
// init, scripts, step, candidates, act, report. Everything a page does
// that leaves the page (requests, navigations, cookies, code it builds)
// is recorded.
import * as L from 'linkedom';
import { CookieJar } from './cookies.js';

const G = globalThis;
const CAP = 200;

const S = {
  start: 0, now: 0, seq: 0, timers: new Map(), nesting: 0, horizon: 0,
  gesture: false, trusted: false, ended: null, steps: 0, latency: 5, throttle: 0,
  url: null, origin: '', files: {}, responses: {}, cookies: new CookieJar(() => S.now),
  errors: [], console: [], requests: [], navigations: [], code: [],
  cookieWrites: [], storage: [], dialogs: [], history: [], unmodelled: new Set(),
  listened: new Map(), cands: [], scripts: [], created: [], started: new WeakSet(),
  active: null, readyState: 'loading', actions: [],
};

const push = (list, v) => { if (list.length < CAP) list.push(v); };
const clip = (s, n = 400) => { s = String(s); return s.length > n ? s.slice(0, n) + '…' : s; };
const fmt = (e) => {
  if (e && typeof e === 'object' && 'message' in e) {
    return { name: String(e.name || 'Error'), message: clip(e.message), stack: clip(e.stack || '', 1200) };
  }
  return { name: 'Thrown', message: clip(e), stack: '' };
};
const error = (where, e) => push(S.errors, { where, at: S.now - S.start, ...fmt(e) });
const rejections = new Map();
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
G.queueMicrotask = (fn) => { Promise.resolve().then(fn); };

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

G.DOMException = class DOMException extends Error {
  constructor(message = '', name = 'Error') { super(message); this.name = name; this.code = 0; }
};

const enc = (s) => encodeURIComponent(s).replace(/%20/g, '+');
const dec = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } };

class URLSearchParams {
  constructor(init = '') {
    this._l = [];
    this._u = null;
    if (init instanceof URLSearchParams) this._l = init._l.map((p) => [...p]);
    else if (typeof init === 'string') this._parse(init);
    else if (init && typeof init[Symbol.iterator] === 'function') for (const [k, v] of init) this._l.push([String(k), String(v)]);
    else if (init && typeof init === 'object') for (const k of Object.keys(init)) this._l.push([k, String(init[k])]);
  }
  _parse(s) {
    this._l = [];
    s = s.replace(/^\?/, '');
    if (!s) return;
    for (const part of s.split('&')) {
      if (!part) continue;
      const i = part.indexOf('=');
      this._l.push(i < 0 ? [dec(part), ''] : [dec(part.slice(0, i)), dec(part.slice(i + 1))]);
    }
  }
  _sync() { if (this._u) this._u._search = this._l.length ? '?' + this.toString() : ''; }
  get size() { return this._l.length; }
  append(k, v) { this._l.push([String(k), String(v)]); this._sync(); }
  delete(k) { this._l = this._l.filter((p) => p[0] !== String(k)); this._sync(); }
  get(k) { const p = this._l.find((p) => p[0] === String(k)); return p ? p[1] : null; }
  getAll(k) { return this._l.filter((p) => p[0] === String(k)).map((p) => p[1]); }
  has(k) { return this._l.some((p) => p[0] === String(k)); }
  set(k, v) {
    k = String(k);
    const i = this._l.findIndex((p) => p[0] === k);
    if (i < 0) this._l.push([k, String(v)]);
    else { this._l[i][1] = String(v); this._l = this._l.filter((p, j) => j <= i || p[0] !== k); }
    this._sync();
  }
  sort() { this._l.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)); this._sync(); }
  forEach(f, t) { for (const [k, v] of this._l) f.call(t, v, k, this); }
  *entries() { yield* this._l.map((p) => [...p]); }
  *keys() { for (const p of this._l) yield p[0]; }
  *values() { for (const p of this._l) yield p[1]; }
  [Symbol.iterator]() { return this.entries(); }
  toString() { return this._l.map(([k, v]) => enc(k) + '=' + enc(v)).join('&'); }
}
G.URLSearchParams = URLSearchParams;

const ABS = /^([a-zA-Z][a-zA-Z0-9+.-]*:)(?:\/\/(?:([^:@/?#]*)(?::([^@/?#]*))?@)?([^:/?#]*)(?::(\d*))?)?([^?#]*)(\?[^#]*)?(#.*)?$/;
const SPECIAL = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443', 'ftp:': '21' };

function dots(path) {
  const out = [];
  const segs = path.split('/');
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    if (s === '..') { if (out.length > 1) out.pop(); if (i === segs.length - 1) out.push(''); }
    else if (s === '.') { if (i === segs.length - 1) out.push(''); }
    else out.push(s);
  }
  return out.join('/');
}

class URL {
  constructor(input, base) {
    input = String(input).trim().replace(/[\t\n\r]/g, '').replace(/\\/g, '/');
    let m = ABS.exec(input);
    if (m && (m[4] !== undefined || !SPECIAL[m[1].toLowerCase()] || base === undefined)) {
      this._set(m);
    } else {
      if (base === undefined) throw new TypeError('Invalid URL: ' + clip(input, 80));
      const b = base instanceof URL ? base : new URL(base);
      let rel = input;
      if (m && SPECIAL[m[1].toLowerCase()] && m[1].toLowerCase() === b._protocol) rel = input.slice(m[1].length);
      let full;
      if (rel.startsWith('//')) full = b._protocol + rel;
      else if (rel.startsWith('/')) full = b._protocol + '//' + b._authority() + rel;
      else if (rel.startsWith('?')) full = b._protocol + '//' + b._authority() + b._pathname + rel;
      else if (rel.startsWith('#')) full = b._protocol + '//' + b._authority() + b._pathname + b._search + rel;
      else if (rel === '') full = b._protocol + '//' + b._authority() + b._pathname + b._search;
      else full = b._protocol + '//' + b._authority() + b._pathname.replace(/[^/]*$/, '') + rel;
      m = ABS.exec(full);
      if (!m) throw new TypeError('Invalid URL: ' + clip(input, 80));
      this._set(m);
    }
  }
  _set(m) {
    this._protocol = m[1].toLowerCase();
    this._username = m[2] || '';
    this._password = m[3] || '';
    this._hostname = (m[4] || '').toLowerCase();
    this._port = m[5] && m[5] !== SPECIAL[this._protocol] ? m[5] : '';
    const special = !!SPECIAL[this._protocol];
    let p = m[6] || '';
    if (special && !p) p = '/';
    this._pathname = special || p.startsWith('/') ? dots(p) : p;
    this._search = m[7] && m[7] !== '?' ? m[7] : '';
    this._hash = m[8] && m[8] !== '#' ? m[8] : '';
    this._hasAuthority = m[4] !== undefined;
    this._sp = null;
  }
  _authority() {
    const user = this._username ? this._username + (this._password ? ':' + this._password : '') + '@' : '';
    return user + this.host;
  }
  get protocol() { return this._protocol; }
  set protocol(v) { this._protocol = String(v).replace(/:?$/, ':').toLowerCase(); }
  get username() { return this._username; }
  set username(v) { this._username = String(v); }
  get password() { return this._password; }
  set password(v) { this._password = String(v); }
  get hostname() { return this._hostname; }
  set hostname(v) { this._hostname = String(v).toLowerCase(); }
  get port() { return this._port; }
  set port(v) { v = String(v); this._port = v === SPECIAL[this._protocol] ? '' : v; }
  get host() { return this._hostname + (this._port ? ':' + this._port : ''); }
  set host(v) { const [h, p] = String(v).split(':'); this._hostname = h.toLowerCase(); this.port = p || ''; }
  get origin() { return SPECIAL[this._protocol] && this._protocol[0] !== 'f' ? this._protocol + '//' + this.host : 'null'; }
  get pathname() { return this._pathname; }
  set pathname(v) { v = String(v); this._pathname = dots(v.startsWith('/') ? v : '/' + v); }
  get search() { return this._search; }
  set search(v) { v = String(v); this._search = v && v !== '?' ? (v[0] === '?' ? v : '?' + v) : ''; if (this._sp) this._sp._parse(this._search); }
  get searchParams() {
    if (!this._sp) { this._sp = new URLSearchParams(this._search); this._sp._u = this; }
    return this._sp;
  }
  get hash() { return this._hash; }
  set hash(v) { v = String(v); this._hash = v && v !== '#' ? (v[0] === '#' ? v : '#' + v) : ''; }
  get href() {
    const auth = this._hasAuthority || SPECIAL[this._protocol] ? '//' + this._authority() : '';
    return this._protocol + auth + this._pathname + this._search + this._hash;
  }
  set href(v) { this._set(ABS.exec(new URL(v).href)); }
  toString() { return this.href; }
  toJSON() { return this.href; }
  static canParse(u, b) { try { new URL(u, b); return true; } catch { return false; } }
  static parse(u, b) { try { return new URL(u, b); } catch { return null; } }
  static createObjectURL(blob) {
    const u = 'blob:' + S.origin + '/' + uuid();
    blobs.set(u, blob);
    return u;
  }
  static revokeObjectURL(u) { blobs.delete(u); }
}
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
  constructor(t, i = {}) { super(t, i); this.view = i.view ?? null; this.detail = i.detail ?? 0; this.composed = !!i.composed; }
}
class MouseEvent extends UIEvent {
  constructor(t, i = {}) {
    super(t, i);
    for (const k of ['screenX', 'screenY', 'clientX', 'clientY', 'pageX', 'pageY', 'offsetX', 'offsetY', 'movementX', 'movementY', 'button', 'buttons']) this[k] = i[k] ?? 0;
    for (const k of MODS) this[k] = !!i[k];
    this.relatedTarget = i.relatedTarget ?? null;
  }
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
class FocusEvent extends UIEvent { constructor(t, i = {}) { super(t, i); this.relatedTarget = i.relatedTarget ?? null; } }
class SubmitEvent extends Ev { constructor(t, i = {}) { super(t, i); this.submitter = i.submitter ?? null; } }
class MessageEvent extends Ev {
  constructor(t, i = {}) { super(t, i); this.data = i.data ?? null; this.origin = i.origin ?? ''; this.lastEventId = ''; this.source = i.source ?? null; this.ports = []; }
}
class ProgressEvent extends Ev { constructor(t, i = {}) { super(t, i); this.lengthComputable = !!i.lengthComputable; this.loaded = i.loaded ?? 0; this.total = i.total ?? 0; } }
class HashChangeEvent extends Ev { constructor(t, i = {}) { super(t, i); this.oldURL = i.oldURL ?? ''; this.newURL = i.newURL ?? ''; } }
class PopStateEvent extends Ev { constructor(t, i = {}) { super(t, i); this.state = i.state ?? null; } }
class ErrorEvent extends Ev { constructor(t, i = {}) { super(t, i); this.message = i.message ?? ''; this.error = i.error ?? null; this.filename = ''; this.lineno = 0; this.colno = 0; } }
class PromiseRejectionEvent extends Ev { constructor(t, i = {}) { super(t, i); this.promise = i.promise; this.reason = i.reason; } }
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
  CompositionEvent, ClipboardEvent, TouchEvent, DragEvent,
});
Object.defineProperty(Ev.prototype, 'isTrusted', { get() { return !!this._trusted; }, configurable: true });
const trusted = (e) => { e._trusted = true; return e; };

// Listeners: a throwing listener is reported, not passed on, and `this` is
// the current target. Every target remembers its event types: that is how
// the driver finds what a person could click.
const ET = L.EventTarget.prototype;
const origAdd = ET.addEventListener;
const origRemove = ET.removeEventListener;
const origDispatch = ET.dispatchEvent;
const wrappers = new WeakMap();
const wrap = (listener, key) => {
  let m = wrappers.get(listener);
  if (!m) wrappers.set(listener, (m = new Map()));
  let w = m.get(key);
  if (!w) {
    w = function (ev) {
      const self = ev.currentTarget ?? this;
      try {
        return typeof listener === 'function' ? listener.call(self, ev) : listener.handleEvent(ev);
      } catch (e) {
        error('listener:' + ev.type, e);
      }
    };
    m.set(key, w);
  }
  return w;
};
ET.addEventListener = function (type, listener, options) {
  if (listener == null || (typeof listener !== 'function' && typeof listener !== 'object')) return;
  const capture = typeof options === 'boolean' ? options : !!(options && options.capture);
  const w = wrap(listener, type + '|' + capture);
  origAdd.call(this, type, w, typeof options === 'object' ? options : undefined);
  let types = S.listened.get(this);
  if (!types) S.listened.set(this, (types = new Set()));
  types.add(type);
  const signal = options && typeof options === 'object' && options.signal;
  if (signal) signal.addEventListener('abort', () => this.removeEventListener(type, listener, options));
};
ET.removeEventListener = function (type, listener, options) {
  if (listener == null) return;
  const capture = typeof options === 'boolean' ? options : !!(options && options.capture);
  const m = wrappers.get(listener);
  const w = m && m.get(type + '|' + capture);
  if (w) origRemove.call(this, type, w);
};

// Inline handlers (`onclick="…"`) are compiled when an event reaches them.
const inline = new WeakMap();
function compileInline(node, type) {
  if (!node.getAttribute) return;
  const code = node.getAttribute('on' + type);
  let m = inline.get(node);
  const old = m && m.get(type);
  if (old && old.code === code) return;
  if (old) origRemove.call(node, type, old.fn);
  if (code == null) { if (m) m.delete(type); return; }
  if (!m) inline.set(node, (m = new Map()));
  let f;
  try {
    push(S.code, { where: 'handler:on' + type, code: clip(code, 2000), gesture: S.gesture });
    toCode('handler:on' + type, code);
    f = new RealFunction('event', code);
  } catch (e) {
    error('handler:on' + type, e);
    m.set(type, { code, fn: () => {} });
    return;
  }
  const fn = function (ev) {
    try { if (f.call(node, ev) === false) ev.preventDefault(); } catch (e) { error('handler:on' + type, e); }
  };
  m.set(type, { code, fn });
  origAdd.call(node, type, fn);
}
ET.dispatchEvent = function (ev) {
  for (let n = this; n; n = ev.bubbles && n._getParent ? n._getParent() : null) compileInline(n, ev.type);
  return origDispatch.call(this, ev);
};

class AbortSignal extends L.EventTarget {
  constructor() { super(); this.aborted = false; this.reason = undefined; this.onabort = null; }
  throwIfAborted() { if (this.aborted) throw this.reason; }
  static abort(r) { const c = new AbortController(); c.abort(r); return c.signal; }
  static timeout(ms) { const c = new AbortController(); setTimeout(() => c.abort(new DOMException('timeout', 'TimeoutError')), ms); return c.signal; }
}
class AbortController {
  constructor() { this.signal = new AbortSignal(); }
  abort(reason = new DOMException('aborted', 'AbortError')) {
    const s = this.signal;
    if (s.aborted) return;
    s.aborted = true;
    s.reason = reason;
    const ev = new Ev('abort');
    if (typeof s.onabort === 'function') s.onabort(ev);
    s.dispatchEvent(ev);
  }
}
Object.assign(G, { AbortSignal, AbortController });

class MessagePort extends L.EventTarget {
  constructor() { super(); this.onmessage = null; this._other = null; }
  postMessage(data) {
    const o = this._other;
    addTimer(() => {
      const ev = new MessageEvent('message', { data });
      if (typeof o.onmessage === 'function') o.onmessage(ev);
      o.dispatchEvent(ev);
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

class Headers {
  constructor(init) {
    this._m = new Map();
    if (init instanceof Headers) init.forEach((v, k) => this.append(k, v));
    else if (Array.isArray(init)) for (const [k, v] of init) this.append(k, v);
    else if (init) for (const k of Object.keys(init)) this.append(k, init[k]);
  }
  append(k, v) { k = String(k).toLowerCase(); const o = this._m.get(k); this._m.set(k, o == null ? String(v) : o + ', ' + v); }
  set(k, v) { this._m.set(String(k).toLowerCase(), String(v)); }
  get(k) { const v = this._m.get(String(k).toLowerCase()); return v == null ? null : v; }
  has(k) { return this._m.has(String(k).toLowerCase()); }
  delete(k) { this._m.delete(String(k).toLowerCase()); }
  forEach(f, t) { for (const [k, v] of this._m) f.call(t, v, k, this); }
  *entries() { yield* this._m.entries(); }
  *keys() { yield* this._m.keys(); }
  *values() { yield* this._m.values(); }
  getSetCookie() { return []; }
  [Symbol.iterator]() { return this.entries(); }
}
const bodyText = (b) => {
  if (b == null) return null;
  if (typeof b === 'string') return b;
  if (b instanceof URLSearchParams) return b.toString();
  if (b instanceof FormData) return new URLSearchParams([...b].map(([k, v]) => [k, typeof v === 'string' ? v : '[file]'])).toString();
  if (b instanceof Blob) return b._text;
  return String(b);
};
class Request {
  constructor(input, init = {}) {
    const src = input instanceof Request ? input : null;
    this.url = new URL(src ? src.url : String(input), S.url.href).href;
    this.method = String(init.method || (src && src.method) || 'GET').toUpperCase();
    this.headers = new Headers(init.headers || (src && src.headers));
    this._body = bodyText(init.body ?? (src && src._body));
    this.signal = init.signal || (src && src.signal) || null;
    this.credentials = String(init.credentials ?? (src && src.credentials) ?? 'same-origin');
    if (!['omit', 'same-origin', 'include'].includes(this.credentials)) throw new TypeError('Invalid credentials mode');
    this.mode = init.mode || 'cors';
    this.cache = init.cache || 'default';
    this.redirect = init.redirect || 'follow';
  }
  clone() { return new Request(this); }
  text() { return Promise.resolve(this._body ?? ''); }
  json() { return this.text().then(JSON.parse); }
}
class Response {
  constructor(body = null, init = {}) {
    this._text = bodyText(body) ?? '';
    this.status = init.status ?? 200;
    this.statusText = init.statusText ?? (this.status === 200 ? 'OK' : '');
    this.ok = this.status >= 200 && this.status < 300;
    this.headers = new Headers(init.headers);
    this.url = init.url || '';
    this.redirected = false;
    this.type = 'basic';
    this.bodyUsed = false;
    this.body = null;
  }
  _use() {
    if (this.bodyUsed) return Promise.reject(new TypeError('Body has already been consumed.'));
    this.bodyUsed = true;
    return Promise.resolve(this._text);
  }
  text() { return this._use(); }
  json() { return this._use().then(JSON.parse); }
  blob() { return this._use().then((t) => new Blob([t])); }
  arrayBuffer() { return this._use().then((t) => new TextEncoder().encode(t).buffer); }
  formData() { unmodelled('Response.formData'); return this._use().then(() => new FormData()); }
  clone() { return new Response(this._text, { status: this.status, statusText: this.statusText, headers: this.headers, url: this.url }); }
  static json(v, init) { return new Response(JSON.stringify(v), { ...init, headers: { 'content-type': 'application/json' } }); }
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

G.fetch = function fetch(input, init = {}) {
  let req;
  try { req = new Request(input, init); } catch (e) { return Promise.reject(new TypeError(e.message)); }
  const hs = {};
  req.headers.forEach((v, k) => { hs[k] = v; });
  return new Promise((resolve, reject) => {
    if (req.signal && req.signal.aborted) return reject(req.signal.reason);
    const r = respond(req.method, req.url, req._body, hs, 'fetch', req.credentials, true);
    addTimer(() => {
      if (req.signal && req.signal.aborted) return reject(req.signal.reason);
      if (r.error != null) return reject(new TypeError('Failed to fetch'));
      receive(r);
      resolve(new Response(r.body, { status: r.status, headers: r.headers, url: r.url }));
    }, r.latency, [], false, 'fetch', false);
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
    const h = this['on' + type];
    if (typeof h === 'function') { try { h.call(this, ev); } catch (e) { error('xhr.on' + type, e); } }
    this.dispatchEvent(ev);
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
      for (const t of ['load', 'loadend']) { const ev = new ProgressEvent(t); if (typeof this['on' + t] === 'function') this['on' + t](ev); this.dispatchEvent(ev); }
    }, 0, [], false, 'FileReader', false);
  }
  readAsText(b) { this._read(() => b._text); }
  readAsDataURL(b) { this._read(() => 'data:' + (b.type || 'application/octet-stream') + ';base64,' + btoa(unescape(encodeURIComponent(b._text)))); }
  readAsArrayBuffer(b) { this._read(() => new TextEncoder().encode(b._text).buffer); }
  abort() {}
}
Object.assign(G, { Blob, File, FileReader });

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
    addTimer(() => G.dispatchEvent(new HashChangeEvent('hashchange', { oldURL, newURL: u.href })), 0, [], false, 'hashchange', false);
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

// A template's parsed children belong to its content, as in a browser:
// linkedom leaves them as children, where frameworks would find them.
function templates(root) {
  if (!root || !root.querySelectorAll) return;
  for (const t of root.querySelectorAll('template')) {
    if (!t.hasChildNodes()) continue;
    const kids = [...t.childNodes];
    t.replaceChildren();
    const c = t.content;
    c.replaceChildren(...kids);
    templates(c);
  }
}

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
  const view = doc.defaultView;
  for (const [k, v] of Object.entries(L)) {
    if (/^[A-Z]/.test(k) && typeof v === 'function') G[k] = v;
  }
  G.Document = L.Document;
  G.HTMLDocument = L.Document;
  for (const k of ['addEventListener', 'removeEventListener', 'dispatchEvent']) G[k] = view[k];
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
      addTimer(() => G.dispatchEvent(new MessageEvent('message', { data, origin: S.origin, source: G })), 0, [], false, 'postMessage', false);
    },
    CSS: { supports: () => false, escape: (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => '\\' + c) },
    Notification: Object.assign(function Notification() { unmodelled('Notification'); }, { permission: 'default', requestPermission: () => Promise.resolve('denied') }),
  });
  Object.defineProperty(G, 'location', { configurable: true, get: () => location, set: (v) => navigate(v, 'location') });
  Object.defineProperty(G, 'onload', { configurable: true, writable: true, value: null });

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
  const create = doc.createElement;
  doc.createElement = function (name, o) {
    const el = create.call(this, name, o);
    if (!S.parsing && String(name).toLowerCase() === 'script') S.created.push(el);
    return el;
  };
  const createNS = doc.createElementNS;
  doc.createElementNS = function (ns, name, o) {
    const el = createNS.call(this, ns, name, o);
    if (!S.parsing && String(name).toLowerCase() === 'script') S.created.push(el);
    return el;
  };
  // `sink`: the name the host hears, with the markup argument's index.
  const parsing = (f, root, sink, at = 0) => function (...a) {
    if (sink) toMarkup(sink, a[at]);
    const was = S.parsing;
    S.parsing = true;
    let r;
    try { r = f.apply(this, a); } finally { S.parsing = was; }
    templates(root(this, r));
    return r;
  };
  const self = (t) => t;
  const parent = (t) => t.parentNode || t;
  for (const proto of [L.Element.prototype, L.ShadowRoot.prototype, L.DocumentFragment.prototype]) {
    for (const [k, root] of [['innerHTML', self], ['outerHTML', parent]]) {
      const d = Object.getOwnPropertyDescriptor(proto, k);
      if (d && d.set) Object.defineProperty(proto, k, { ...d, set: parsing(d.set, root, k) });
    }
  }
  L.Element.prototype.insertAdjacentHTML = parsing(L.Element.prototype.insertAdjacentHTML, parent, 'insertAdjacentHTML', 1);
  L.DOMParser.prototype.parseFromString = parsing(L.DOMParser.prototype.parseFromString, (t, r) => r);
  const T = L.HTMLTemplateElement.prototype;
  const setInner = Object.getOwnPropertyDescriptor(L.Element.prototype, 'innerHTML').set;
  define(T, 'innerHTML', {
    get() { const d = doc.createElement('div'); d.appendChild(this.content.cloneNode(true)); return d.innerHTML; },
    set(v) { setInner.call(this, v); },
  });
  doc.evaluate = (expr, node) => new XPathExpression(expr).evaluate(node);

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
  H.click = function () { click(this, false); };
  define(H, 'isContentEditable', { get() { const v = this.getAttribute('contenteditable'); return v === '' || v === 'true'; } });
  define(H, 'form', { get() { return this.closest('form'); } });

  const I = L.HTMLInputElement.prototype;
  const checked = new WeakMap();
  define(I, 'checked', {
    get() { return checked.has(this) ? checked.get(this) : this.hasAttribute('checked'); },
    set(v) {
      v = !!v;
      checked.set(this, v);
      if (v && (this.getAttribute('type') || '').toLowerCase() === 'radio' && this.name) {
        const scope = this.closest('form') || doc;
        for (const r of scope.querySelectorAll('input[type=radio]')) if (r !== this && r.name === this.name) checked.set(r, false);
      }
    },
  });
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

function dispatch(el, ev) { return el.dispatchEvent(trusted(ev)); }

function click(el, gesture) {
  const was = S.gesture;
  S.gesture = was || gesture;
  try {
    const o = { bubbles: true, cancelable: true, view: G, button: 0, detail: 1 };
    if (gesture) {
      dispatch(el, new PointerEvent('pointerdown', o));
      dispatch(el, new MouseEvent('mousedown', o));
      if (el.focus) el.focus();
      dispatch(el, new PointerEvent('pointerup', o));
      dispatch(el, new MouseEvent('mouseup', o));
    }
    const type = (el.getAttribute && el.getAttribute('type') || '').toLowerCase();
    const toggles = el.localName === 'input' && (type === 'checkbox' || type === 'radio');
    const before = toggles ? el.checked : null;
    if (toggles) el.checked = type === 'radio' ? true : !el.checked;
    const ev = new MouseEvent('click', o);
    const ok = gesture ? dispatch(el, ev) : el.dispatchEvent(ev);
    if (toggles) {
      if (!ok) el.checked = before;
      else if (before !== el.checked) { dispatch(el, new L.InputEvent('input', { bubbles: true })); dispatch(el, new Ev('change', { bubbles: true })); }
    }
    if (ok) activate(el);
  } finally {
    S.gesture = was;
  }
}

function activate(el) {
  const a = el.closest && el.closest('a[href],area[href]');
  if (a) {
    const target = a.getAttribute('target');
    navigate(a.getAttribute('href'), 'link', target && target !== '_self' ? { popup: true, target } : {});
    return;
  }
  const b = el.closest && el.closest('button,input[type=submit],input[type=image]');
  if (b) {
    const t = (b.getAttribute('type') || 'submit').toLowerCase();
    const form = b.closest('form') || (b.getAttribute('form') && G.document.getElementById(b.getAttribute('form')));
    if ((t === 'submit' || t === 'image') && form) submit(form, b);
    else if (t === 'reset' && form) form.reset();
    return;
  }
  const s = el.closest && el.closest('summary');
  if (s && s.parentElement && s.parentElement.localName === 'details') s.parentElement.toggleAttribute('open');
  const label = el.closest && el.closest('label');
  if (label) {
    const f = label.getAttribute('for');
    const control = f ? G.document.getElementById(f) : label.querySelector('input,select,textarea,button');
    if (control && control !== el) click(control, false);
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
  const t = (s.getAttribute('type') || '').trim().toLowerCase();
  if (t === 'module') return 'module';
  if (t === '' || /^(text|application)\/(x-)?(java|ecma)script$/.test(t) || t === 'text/jscript') return s.hasAttribute('nomodule') ? null : 'classic';
  return null;
}

// What to run for one script element: its kind, its URL, its code (null
// when no answer has it).
function source(s, n) {
  S.started.add(s);
  const kind = scriptKind(s);
  if (!kind) return null;
  const src = s.getAttribute('src');
  if (src == null) {
    const code = s.textContent;
    push(S.code, { where: 'script', code: clip(code, 2000), gesture: S.gesture });
    return { kind, url: kind === 'module' ? S.url.href.split('#')[0] + '#inline-' + n : S.url.href, code, inline: true };
  }
  const url = new URL(src, S.url.href).href;
  return { kind, url, code: file(url), inline: false };
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
  const s = source(el, scriptN++);
  if (!s) return null;
  if (s.kind === 'classic') S.current = el;
  S.currentEl = el;
  return s;
}

// The document's scripts in the order a browser runs them: blocking ones,
// then deferred and module ones, then async ones.
function pageScripts() {
  const all = [...G.document.querySelectorAll('script')];
  const blocking = [], deferred = [], later = [];
  for (const s of all) {
    S.started.add(s);
    const kind = scriptKind(s);
    if (!kind) continue;
    const src = s.hasAttribute('src');
    if (s.hasAttribute('async') && (src || kind === 'module')) later.push(s);
    else if (kind === 'module' || (src && s.hasAttribute('defer'))) deferred.push(s);
    else blocking.push(s);
  }
  S.scripts = [...blocking, ...deferred, ...later];
  return S.scripts.length;
}

// Scripts the page created and connected since the last look.
function newScripts() {
  if (!S.created.length) return 0;
  const ready = S.created.filter((s) => s.isConnected && !S.started.has(s));
  S.created = S.created.filter((s) => !s.isConnected && !S.started.has(s));
  S.scripts = ready;
  return ready.length;
}

function scriptAt(i) {
  const el = S.scripts[i];
  return el ? nextScript(el) : null;
}

function scriptDone(ok) {
  const el = S.currentEl;
  S.current = null;
  S.currentEl = null;
  if (el && el.hasAttribute('src')) el.dispatchEvent(new Ev(ok ? 'load' : 'error'));
}

// --- The driver's handle ---------------------------------------------------------

G.console = Object.fromEntries(['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir', 'table'].map((level) => [level, (...a) => {
  push(S.console, { level, at: S.now - S.start, text: clip(a.map((x) => { if (typeof x === 'string') return x; try { return JSON.stringify(x); } catch { return String(x); } }).join(' ')) });
}]));
Object.assign(G.console, { group() {}, groupCollapsed() {}, groupEnd() {}, time() {}, timeEnd() {}, timeLog() {}, count() {}, countReset() {}, assert(c, ...a) { if (!c) G.console.error('Assertion failed:', ...a); } });

G.__af = {
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
    const doc = new L.DOMParser().parseFromString(s.html || '', 'text/html');
    installWindow(doc);
    templates(doc);
    return pageScripts();
  },
  scriptAt,
  scriptDone,
  newScripts,
  resolve(spec, base) {
    if (!/^(\.{0,2}\/|[a-zA-Z][a-zA-Z0-9+.-]*:)/.test(spec)) throw new TypeError(`Failed to resolve module specifier "${spec}"`);
    return new URL(spec, base).href;
  },
  file,
  error(where, e) { error(where, e); },
  // A module's evaluation promise: its rejection is the module's error.
  watch(p, url) { p.then(null, (e) => error('module:' + url, e)); },
  // A rejection is unhandled if no handler is attached by the end of the
  // microtask checkpoint.
  rejected(p, reason) { rejections.set(p, reason); },
  handled(p) { rejections.delete(p); },
  checkpoint() {
    for (const r of rejections.values()) error('unhandledrejection', r);
    rejections.clear();
  },
  ready() {
    S.readyState = 'interactive';
    G.document.dispatchEvent(new Ev('DOMContentLoaded', { bubbles: true }));
  },
  loaded() {
    S.readyState = 'complete';
    const ev = new Ev('load');
    if (typeof G.onload === 'function') { try { G.onload(ev); } catch (e) { error('onload', e); } }
    G.dispatchEvent(ev);
    G.dispatchEvent(new Ev('pageshow'));
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
