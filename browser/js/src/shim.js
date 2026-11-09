import { rememberDocumentURL, documentURL } from './document-state.js';
import { documentBaseURL } from './document-urls.js';
import { installCharacterData } from './character-data.js';
import { installDOMMutations } from './dom-mutations.js';
import { MutationRecord, installMutationObserverReporter } from './mutation-observers.js';
import { installSelectProperties, resetSelect, chooseSelectOption } from './select-state.js';
import { requireParser } from './parser-state.js';
import { serializeDocument } from './document-body.js';
import { installAttributes } from './attributes.js';
import { parseNetworkDocument } from './network-documents.js';
import { XMLHttpRequest, XMLHttpRequestEventTarget, XMLHttpRequestUpload, installXHRPlatform } from './xml-http-request.js';
import { platformConstructor } from './constructors.js';
import { FileReader, installFileReaderTasks } from './file-reader.js';
import { installFileInputs } from './file-inputs.js';
import { DataTransfer, DataTransferItem, DataTransferItemList, FileList, StaticRange, AbstractRange, NodeRange, Touch, installPayloadTasks, serializeFileList } from './event-payloads.js';
import { UIEvent, MouseEvent, PointerEvent, WheelEvent, KeyboardEvent, FocusEvent, InputEvent, SubmitEvent, ProgressEvent, HashChangeEvent, PopStateEvent, ErrorEvent, PromiseRejectionEvent, ToggleEvent, StorageEvent, TransitionEvent, AnimationEvent, CompositionEvent, ClipboardEvent, TouchEvent, TouchList, DragEvent, isErrorEvent, errorEventData, createNativeUIEvent, registerStorageArea } from './event-interfaces.js';
import { extractMime } from './mime-types.js';
import { Blob, File, blobRecord, requireBlob, blobText, blobBuffer, blobDataURL, fileFromBlob, emptyFile, cloneBlob, installBlobPlatform, byteCount, bufferOfBytes, textBytes, decodeBytes, blobBytes, blobFromBytes, copyBodyBytes, copyBytesBuffer, bufferSourceKind, bufferSourceBytes, wireBytes, joinBytes } from './blobs.js';
import { postMessage, installWindowMessages } from './window-messages.js';
import { frameworkCandidate, editable, nodeText, normalizedText, documentText } from './exploration.js';
import { MessagePort, MessageChannel, installMessagePortTasks } from './message-ports.js';
import { MessageEvent } from './message-events.js';
import { installStackReporter } from './error-stacks.js';
import { structuredClone, installClonePlatform } from './structured-clone.js';
import { markPlatform } from './platform-state.js';
// The page's world: linkedom's DOM plus the Web APIs a page's scripts
// expect, on virtual time. The guest retains the bootstrap control handle
// privately: init, scripts, step, candidates, act, report. Everything a page does
// that leaves the page (requests, navigations, cookies, code it builds)
// is recorded.
import { DOMException as BrowserDOMException } from './dom-exception.js';
import { installNumericProperties } from './input-numbers.js';
import { installColorReporter } from './color-values.js';
import { representativeInputValue, representativeSelectionValue } from './input-domains.js';
import * as L from 'linkedom';
import { Headers, convertHeadersInit, headersFromConverted, setHeadersGuard, copyHeaders, filterHeaders, headerObject, headerValue, appendNativeHeader } from './headers.js';
import { URL, URLSearchParams, urlPart, setURLPart, serializeParams, isSearchParams, setObjectURLHooks } from './urls.js';
import { reportJSON } from './report-json.js';
import { CookieJar } from './cookies.js';
import { parseHTML, parseHTMLFragment, fragmentElements, documentMode } from './document.js';
import { qualifiedName, nameIdentity, lowerASCII, validElementLocalName } from './names.js';
import { setEventClock, eventState, eventDictionary, cancelEvent, initializeEvent, createNativeEvent, markEventUninitialized } from './event-state.js';
import { fireEvent, installEventHooks, registerWindow, initializeEventTarget, getHandler, setHandler, setContentHandler } from './event-target.js';
import { initializeSignal, signalState, abortSignal, dependSignal, onSignalAbort, setAbortEventDispatcher, signalListenersChanged } from './abort-state.js';
import { installEventAttributeHook } from './ce-hooks.js';
import { htmlName, controlType, treeElements, formOwner, connected, disabled, checked, setChecked, indeterminate, setIndeterminate, beginInputActivation, cancelInputActivation, resetChecked, installControlState, setControlAttribute } from './controls.js';
import { populateForm, isSubmitButton } from './form-controls.js';
import { installValueProperties, resetControlValue, setControlValue, controlValue } from './control-values.js';
import { nodeDocument, nodeInfo, shadowInfo, shadowAncestor, physicalBody, eventAttribute, physicalParent, physicalRoot, retarget } from './dom-state.js';
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
import { installElementURLs } from './element-urls.js';
import { DOMImplementation, XMLDocument, installDOMImplementation } from './dom-implementation.js';
import { installObservers } from './observers.js';
import { templateContent, templateOwner, templateInnerHTML, shareTemplateObservers } from './templates.js';
import { installSelectors } from './selectors.js';
import { installTreeAccessors } from './tree-accessors.js';
import { installSelectorPlatform } from './selector-engine.js';
import { NodeList, HTMLCollection, NamedNodeMap, installCollections } from './collections.js';
import { scriptRecord, rememberScript, scriptOwner } from './script-state.js';
import { installScriptMutations, scriptAttribute, scriptText, scriptShadowHost } from './script-mutations.js';
import { backendList } from './collection-data.js';
import { beginHTML } from './html-parser.js';
import { createBareElement } from './creation.js';

installTreeAccessors();
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
const nativeDefine = Object.defineProperty, nativeCreate = Object.create, nativeEntries = Object.entries, nativeIsArray = Array.isArray, nativeSetPrototype = Object.setPrototypeOf;
// Export names are stable interface identities. Restore them once during
// bootstrap, before any page can replace descriptors or freeze constructors.
for (const [name, C] of Object.entries(L)) if (/^[A-Z]/.test(name) && typeof C === 'function') {
  nativeDefine(C, 'name', { __proto__: null, value: name, configurable: true });
  const backing = Object.getOwnPropertyDescriptor(C.prototype || {}, 'constructor')?.value;
  if (typeof backing === 'function' && backing !== C) nativeDefine(backing, 'name', { __proto__: null, value: name, configurable: true });
}
installAttributes();
installDOMMutations(L);
installCharacterData(L);
installDOMImplementation(L);
installElementURLs(L);
const DOMParser = platformConstructor(L.DOMParser, 'DOMParser');
installCollections();
const nativeLower = Function.prototype.call.bind(String.prototype.toLowerCase);
const nativeString = String, diagnosticSlice = Function.prototype.call.bind(String.prototype.slice);

const S = {
  start: 0, now: 0, seq: 0, timerOrder: 0, timers: new Map(), nesting: 0, horizon: 0,
  gesture: false, trusted: false, ended: null, steps: 0, latency: 5, throttle: 0,
  url: null, origin: '', document: null, files: {}, responses: {}, cookies: new CookieJar(() => S.now),
  errors: [], console: [], requests: [], navigations: [], code: [],
  cookieWrites: [], storage: [], dialogs: [], history: [], unmodelled: new Set(),
  listened: new WeakMap(), cands: [], scripts: [], dynamicScripts: [],
  active: null, readyState: 'loading', actions: [], currentExternal: false,
};

const listenerTypes = S.listened.get.bind(S.listened), saveListenerTypes = S.listened.set.bind(S.listened), forgetListenerTypes = S.listened.delete.bind(S.listened);

setEventClock(() => S.now - S.start);
installControlState(queueDetailsToggle);

const push = (list, v) => { if (list.length < CAP) nativeDefine(list, list.length, { __proto__: null, value: v, writable: true, enumerable: true, configurable: true }); };
const clip = (s, n = 400) => { s = nativeString(s); return s.length > n ? diagnosticSlice(s, 0, n) + '…' : s; };
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
installMutationObserverReporter(value => error('MutationObserver', value));
const rejections = new Map(), notifiedRejections = new WeakMap();
const notified = notifiedRejections.get.bind(notifiedRejections), rememberNotified = notifiedRejections.set.bind(notifiedRejections), forgetNotified = notifiedRejections.delete.bind(notifiedRejections);
const mapGet = Function.prototype.call.bind(Map.prototype.get), mapSet = Function.prototype.call.bind(Map.prototype.set), mapDelete = Function.prototype.call.bind(Map.prototype.delete), mapEach = Function.prototype.call.bind(Map.prototype.forEach);
const nativeQueueMicrotask = G.__native.queueMicrotask;
const nativeResolve = Promise.resolve.bind(Promise), nativeThen = Function.prototype.call.bind(Promise.prototype.then);
const nativeApply = Reflect.apply, nativeConstruct = Reflect.construct, NativeTypeError = TypeError;
const nativeMax = Math.max, nativeFloor = Math.floor, nativeImul = Math.imul, nativeTrunc = Math.trunc, NativeRangeError = RangeError;
const mapSize = Function.prototype.call.bind(Object.getOwnPropertyDescriptor(Map.prototype, 'size').get);
const setEach = Function.prototype.call.bind(Set.prototype.forEach), setHas = Function.prototype.call.bind(Set.prototype.has);
let handledRejections = [];
const unmodelled = (name) => nativeSetAdd(S.unmodelled, name);
installColorReporter(unmodelled);
installSelectorPlatform({ unsupported: unmodelled, active: root => S.active ? activeElementFor(root) : null });
installBlobPlatform({ now: () => S.now });

// The host: appfuzz's browser guest binds a private bridge to the
// `appfuzz:browser` imports. Requests go to it and it answers them; markup,
// code and navigations the page makes are reported to it. Without one (the
// native runner) requests are answered from the session's files and
// responses.
let browserHost = null;
const host = () => browserHost;
const toMarkup = (where, value) => { const h = host(); if (h) h.html(String(where), String(value)); };
const toCode = (where, value) => { const h = host(); if (h) h.code(String(where), String(value)); };

// --- Determinism: seeded randomness and a virtual clock --------------------

let seed = 1;
const rand = () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = nativeImul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + nativeImul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
Math.random = rand;

const RealDate = Date;
const dateString = Function.prototype.call.bind(RealDate.prototype.toString);
const VDate = function Date(...args) {
  if (!new.target) return dateString(new RealDate(S.now));
  return nativeConstruct(RealDate, args.length ? args : [S.now], new.target);
};
Object.defineProperty(VDate, 'prototype', { value: RealDate.prototype, writable: false });
Object.defineProperty(VDate, 'length', { value: 7 });
Object.defineProperty(VDate, 'name', { value: 'Date' });
Object.defineProperty(RealDate.prototype, 'constructor', { value: VDate, writable: true, configurable: true });
for (const [name, value] of [['now', { now() { return S.now; } }.now], ['parse', RealDate.parse], ['UTC', RealDate.UTC]]) {
  Object.defineProperty(VDate, name, { value, writable: true, configurable: true });
}
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

function timerDelay(timeout, nesting) {
  return nativeMax(0, timeout, S.throttle, nesting > 5 ? 4 : 0);
}
function addTimer(fn, delay, args, repeat, kind, clamp = true) {
  if (typeof fn !== 'function') {
    const code = nativeString(fn);
    fn = () => runCode(code, kind);
  }
  const timeout = clamp ? nativeMax(0, delay) : delay;
  const id = ++S.seq, nesting = clamp ? S.nesting + 1 : 0;
  mapSet(S.timers, id, { id, order: ++S.timerOrder, due: S.now + timerDelay(timeout, clamp ? S.nesting : 0), fn, args, repeat, timeout, nesting, kind });
  return id;
}
function timerReceiver(value) { if (value != null && value !== G) throw new NativeTypeError('A Window is required'); }
function scheduleTimer(handler, timeout, args, repeat, count) {
  if (!count) throw new NativeTypeError('A timer handler is required');
  const converted = runDOMCallback(() => [typeof handler === 'function' ? handler : domString(handler), +timeout >> 0]);
  return addTimer(converted[0], converted[1], args, repeat, repeat ? 'setInterval' : 'setTimeout');
}
function frameCallback(callback, count) { if (!count || typeof callback !== 'function') throw new NativeTypeError('A callback is required'); }
const timerAPI = {
  setTimeout(handler, timeout = 0, ...args) { timerReceiver(this); return scheduleTimer(handler, timeout, args, false, arguments.length); },
  setInterval(handler, timeout = 0, ...args) { timerReceiver(this); return scheduleTimer(handler, timeout, args, true, arguments.length); },
  clearTimeout(id = 0) { timerReceiver(this); mapDelete(S.timers, runDOMCallback(() => +id >> 0)); },
  clearInterval(id = 0) { timerReceiver(this); mapDelete(S.timers, runDOMCallback(() => +id >> 0)); },
  requestAnimationFrame(callback) {
    timerReceiver(this); frameCallback(callback, arguments.length);
    const t = S.now - S.start;
    return addTimer(() => nativeApply(callback, G, [S.now - S.start]), 16 - (t % 16), [], false, 'requestAnimationFrame', false);
  },
  cancelAnimationFrame(id) { timerReceiver(this); if (!arguments.length) throw new NativeTypeError('An animation handle is required'); mapDelete(S.timers, runDOMCallback(() => +id >>> 0)); },
  requestIdleCallback(callback) {
    timerReceiver(this); frameCallback(callback, arguments.length);
    return addTimer(() => nativeApply(callback, G, [{ didTimeout: false, timeRemaining: () => 50 }]), 1, [], false, 'requestIdleCallback', false);
  },
  cancelIdleCallback(id) { timerReceiver(this); if (!arguments.length) throw new NativeTypeError('An idle handle is required'); mapDelete(S.timers, runDOMCallback(() => +id >>> 0)); },
};
for (const name of Object.keys(timerAPI)) G[name] = timerAPI[name];

G.queueMicrotask = (fn) => {
  if (typeof fn !== 'function') throw new NativeTypeError('queueMicrotask requires a callback');
  nativeQueueMicrotask(() => { try { runDOMCallback(() => nativeApply(fn, undefined, [])); } catch (e) { error('queueMicrotask', e); } });
};

// The next due task, if it is due by the horizon.
function step() {
  let next = null;
  mapEach(S.timers, t => {
    if (!next || t.due < next.due || (t.due === next.due && t.order < next.order)) next = t;
  });
  if (!next || next.due > S.horizon || S.ended) return false;
  if (next.due > S.now) S.now = next.due;
  if (!next.repeat) mapDelete(S.timers, next.id);
  const saved = S.nesting;
  S.nesting = next.nesting;
  try { runDOMCallback(() => nativeApply(next.fn, G, next.args)); } catch (e) { error(next.kind, e); }
  if (next.repeat && mapGet(S.timers, next.id) === next) {
    next.due = S.now + timerDelay(next.timeout, next.nesting);
    next.nesting++;
    next.order = ++S.timerOrder;
  }
  S.nesting = saved;
  S.steps++;
  return true;
}

// --- Encoding, URLs, aborts -------------------------------------------------

if (typeof G.TextEncoder !== 'function') {
  G.TextEncoder = class TextEncoder {
    constructor() { markPlatform(this); }
    get encoding() { return 'utf-8'; }
    encode(s = '') {
      const b = unescape(encodeURIComponent(String(s)));
      const out = new Uint8Array(b.length);
      for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
      return out;
    }
  };
  G.TextDecoder = class TextDecoder {
    constructor() { markPlatform(this); }
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
      if (a > 255 || b > 255 || c > 255) throw new BrowserDOMException('Invalid character', 'InvalidCharacterError');
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
      if (n.some((x) => x < 0)) throw new BrowserDOMException('Invalid character', 'InvalidCharacterError');
      const v = (n[0] << 18) | (n[1] << 12) | (n[2] << 6) | n[3];
      out += String.fromCharCode(v >> 16);
      if (i + 2 < s.length) out += String.fromCharCode((v >> 8) & 255);
      if (i + 3 < s.length) out += String.fromCharCode(v & 255);
    }
    return out;
  };
}

G.DOMException = BrowserDOMException;

// URLs and form encoding by the WHATWG rules: the guest's `url` crate, the
// parser appfuzz judges where requests go with. A page's own checks
// (`new URL(next).host === location.host`) then parse as in a browser:
// lookalike and numeric hosts, IPv6, backslashes, dot segments.
const N = G.__native;

G.URLSearchParams = URLSearchParams;
G.URL = URL;
const blobs = new Map();
setObjectURLHooks(blob => {
  requireBlob(blob);
  const url = 'blob:' + S.origin + '/' + uuid();
  mapSet(blobs, url, blob); return url;
}, url => { mapDelete(blobs, url); });

function uuid() {
  const digits = '0123456789abcdef'; let result = '';
  for (let i = 0; i < 16; i++) {
    let byte = nativeFloor(rand() * 256);
    if (i === 6) byte = (byte & 15) | 64;
    if (i === 8) byte = (byte & 63) | 128;
    result += digits[byte >> 4] + digits[byte & 15];
    if (i === 3 || i === 5 || i === 7 || i === 9) result += '-';
  }
  return result;
}

G.crypto = {
  getRandomValues(a) {
    const bytes = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    for (let i = 0; i < bytes.length; i++) bytes[i] = nativeFloor(rand() * 256);
    return a;
  },
  randomUUID: uuid,
  get subtle() { unmodelled('crypto.subtle'); return undefined; },
};

G.structuredClone = structuredClone;

// --- Events -----------------------------------------------------------------

const Ev = L.Event;
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
const detailsToggles = new WeakMap(), pendingToggle = detailsToggles.get.bind(detailsToggles), rememberToggle = detailsToggles.set.bind(detailsToggles), forgetToggle = detailsToggles.delete.bind(detailsToggles);
function queueDetailsToggle(node, wasOpen, isOpen) {
  const pending = pendingToggle(node), oldState = pending ? pending.oldState : wasOpen ? 'open' : 'closed', newState = isOpen ? 'open' : 'closed';
  if (pending) mapDelete(S.timers, pending.id);
  const id = addTimer(() => { forgetToggle(node); fireEvent(node, createNativeUIEvent(ToggleEvent, 'toggle', { oldState, newState })); }, 0, [], false, 'details-toggle', false);
  rememberToggle(node, { id, oldState });
}
Object.assign(G, {
  UIEvent, MouseEvent, PointerEvent, WheelEvent, KeyboardEvent, FocusEvent, InputEvent, SubmitEvent, MessageEvent, ProgressEvent,
  HashChangeEvent, PopStateEvent, ErrorEvent, PromiseRejectionEvent, StorageEvent, TransitionEvent, AnimationEvent,
  CompositionEvent, ClipboardEvent, TouchEvent, TouchList, DragEvent, ToggleEvent,
  DataTransfer, DataTransferItem, DataTransferItemList, FileList, StaticRange, AbstractRange, NodeRange, Touch,
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
    if (!types.length) { forgetListenerTypes(target); return; }
    const set = new NativeSet();
    for (let i = 0; i < types.length; i++) nativeSetAdd(set, types[i]);
    saveListenerTypes(target, set);
  },
  current(value, shadow, restore) { const previous = currentEvent; if (restore || !shadow) currentEvent = value; return previous; },
}, BrowserDOMException);

// Content attributes activate the same handler slot as IDL assignments at
// mutation time; compilation stays lazy until a getter or invocation needs it.
const handlerNames = Object.getOwnPropertyNames(L.HTMLElement.prototype).filter(name => name.startsWith('on'));
for (const type of ['wheel', 'beforeinput', 'formdata', 'reset', 'message', 'messageerror', 'pageshow', 'pagehide', 'hashchange', 'popstate', 'resize', 'scroll', 'focusin', 'focusout']) {
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
const controllerSignals = new WeakMap();
const controllerSignal = controllerSignals.get.bind(controllerSignals), rememberController = controllerSignals.set.bind(controllerSignals);
let AbortSignal = class AbortSignal {
  constructor() { throw new NativeTypeError('Illegal AbortSignal constructor'); }
  get aborted() { return signalState(this).aborted; }
  get reason() { return signalState(this).reason; }
  get onabort() { return getHandler(this, 'abort'); }
  set onabort(value) { setHandler(this, 'abort', value); }
  throwIfAborted() { const state = signalState(this); if (state.aborted) throw state.reason; }
  static abort(reason) {
    const signal = createSignal(), state = signalState(signal);
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
    return dependSignal(createSignal(), inputs);
  }
  static timeout(ms) {
    if (!arguments.length) throw new NativeTypeError('timeout requires a delay');
    const delay = truncateNumber(+ms);
    if (!finiteNumber(delay) || delay < 0 || delay >= 18446744073709551616) throw new NativeTypeError('Invalid timeout');
    const signal = createSignal();
    addTimer(() => abort(signal, new BrowserDOMException('The operation timed out', 'TimeoutError')), delay, [], false, 'abort-timeout', false);
    return signal;
  }
}
function createSignal() { const signal = nativeCreate(AbortSignal.prototype); initializeEventTarget(signal); initializeSignal(signal); return signal; }
function abort(signal, reason) {
  if (signalState(signal).aborted) return;
  if (reason === undefined) reason = new BrowserDOMException('The operation was aborted', 'AbortError');
  abortSignal(signal, reason);
}
nativeSetPrototype(AbortSignal, L.EventTarget); nativeSetPrototype(AbortSignal.prototype, L.EventTarget.prototype);
AbortSignal = platformConstructor(AbortSignal, 'AbortSignal', 0, true);
let AbortController = class AbortController {
  constructor() { markPlatform(this); rememberController(this, createSignal()); }
  get signal() { const signal = controllerSignal(this); if (!signal) throw new NativeTypeError('Illegal AbortController receiver'); return signal; }
  abort(reason) { const signal = controllerSignal(this); if (!signal) throw new NativeTypeError('Illegal AbortController receiver'); abort(signal, reason); }
}
AbortController = platformConstructor(AbortController, 'AbortController');
setAbortEventDispatcher(signal => fireEvent(signal, createNativeEvent('abort')));
Object.assign(G, { AbortSignal, AbortController });

G.MessagePort = MessagePort; G.MessageChannel = MessageChannel;
let messageCheckpoint = () => false;
// Posted messages are tasks, not timers: daily timer coalescing and timer
// nesting clamps must not delay an already queued message.
function enqueueMessageTask(callback, kind) {
  const id = ++S.seq;
  mapSet(S.timers, id, { id, order: ++S.timerOrder, due: S.now, fn: callback, args: [], repeat: false,
    timeout: 0, nesting: 0, kind });
  return id;
}
function messageListenerCheckpoint() {
  if (messageCheckpoint()) unmodelled('microtask checkpoint budget');
}
installFileReaderTasks(callback => enqueueMessageTask(callback, 'FileReader'), id => mapDelete(S.timers, id), messageListenerCheckpoint);
installPayloadTasks(callback => enqueueMessageTask(callback, 'DataTransferItem'), value => error('DataTransferItem.getAsString', value));
installMessagePortTasks(callback => enqueueMessageTask(callback, 'MessageChannel'), messageListenerCheckpoint);
installWindowMessages({ origin: () => S.origin, enqueue: callback => enqueueMessageTask(callback, 'postMessage'), checkpoint: messageListenerCheckpoint });

// --- Network: every request is recorded; answers come from the session -----

const NativePromise = Promise, createFetchObject = Object.create;
const rejectPromise = Promise.reject.bind(Promise), parseBodyJSON = JSON.parse, stringifyBodyJSON = JSON.stringify;
const stringUpper = Function.prototype.call.bind(String.prototype.toUpperCase);
const formRecords = new WeakMap(), formRecord = formRecords.get.bind(formRecords), saveForm = formRecords.set.bind(formRecords);
function requireForm(value) { const data = formRecord(value); if (!data) throw new NativeTypeError('A FormData object is required'); return data; }
function crlf(value) {
  let result = '';
  for (let i = 0; i < value.length; i++) { const c = value[i]; if (c === '\r') { result += '\r\n'; if (value[i + 1] === '\n') i++; } else if (c === '\n') result += '\r\n'; else result += c; }
  return result;
}
function multipartName(value) {
  value = crlf(value); let result = '';
  for (let i = 0; i < value.length; i++) result += value[i] === '\r' ? '%0D' : value[i] === '\n' ? '%0A' : value[i] === '"' ? '%22' : value[i];
  return result;
}
function convertBody(body) {
  if (body == null) return { kind: 'none' };
  if (blobRecord(body)) return { kind: 'blob', value: body };
  if (formRecord(body)) return { kind: 'form', value: body };
  const type = bufferSourceKind(body);
  if (type) return { kind: 'buffer', type, value: body };
  if (isSearchParams(body)) return { kind: 'params', value: body };
  return { kind: 'text', text: wellFormed(domString(body)) };
}
function extractConvertedBody(body) {
  if (body.kind === 'none') return { bytes: null, type: null };
  if (body.kind === 'blob') { const record = requireBlob(body.value); return { bytes: blobBytes(body.value), type: record.type || null }; }
  if (body.kind === 'buffer') return { bytes: bufferSourceBytes(body.value, body.type), type: null };
  if (body.kind === 'params') return { bytes: textBytes(serializeParams(body.value)), type: 'application/x-www-form-urlencoded;charset=UTF-8' };
  if (body.kind === 'form') {
    const fields = requireForm(body.value), boundary = '----appfuzz-' + uuid(), chunks = []; nativeSetPrototype(chunks, null);
    for (let i = 0; i < fields.length; i++) {
      const entry = fields[i], name = entry[0], value = entry[1], file = blobRecord(value);
      let prefix = '--' + boundary + '\r\nContent-Disposition: form-data; name="' + multipartName(name) + '"';
      if (file) prefix += '; filename="' + multipartName(file.name ?? 'blob') + '"\r\nContent-Type: ' + (file.type || 'application/octet-stream');
      chunks[chunks.length] = textBytes(prefix + '\r\n\r\n');
      chunks[chunks.length] = file ? blobBytes(value) : textBytes(crlf(value));
      chunks[chunks.length] = textBytes('\r\n');
    }
    chunks[chunks.length] = textBytes('--' + boundary + '--\r\n');
    return { bytes: joinBytes(chunks), type: 'multipart/form-data; boundary=' + boundary };
  }
  return { bytes: textBytes(body.text), type: 'text/plain;charset=UTF-8' };
}
const extractBody = body => extractConvertedBody(convertBody(body));
const bodyBytes = body => extractBody(body).bytes;
const requests = new WeakMap(), requestData = requests.get.bind(requests), saveRequest = requests.set.bind(requests);
const responses = new WeakMap(), responseData = responses.get.bind(responses), saveResponse = responses.set.bind(responses);
const bodies = new WeakMap(), bodyData = bodies.get.bind(bodies), saveBody = bodies.set.bind(bodies);
function requireRequest(value) { const result = requestData(value); if (!result) throw new NativeTypeError('A Request is required'); return result; }
function requireResponse(value) { const result = responseData(value); if (!result) throw new NativeTypeError('A Response is required'); return result; }
function initializeBody(owner, bytes, signal = null) { saveBody(owner, { bytes, present: bytes !== null, used: false, signal }); }
function requireBody(owner) { const body = bodyData(owner); if (!body) throw new NativeTypeError('A Request or Response is required'); return body; }
function readBody(owner, brand, convert) {
  try {
    brand(owner); const body = requireBody(owner);
    if (body.used) throw new NativeTypeError('Body has already been consumed.');
    body.used = body.present;
    if (body.present && body.signal && signalState(body.signal).aborted) return rejectPromise(signalState(body.signal).reason);
    const bytes = body.bytes === null ? textBytes('') : body.bytes;
    // The intermediate promise carries no JS representation of the private
    // byte sequence: a public typed-array then getter must not observe it.
    return nativeThen(nativeResolve(undefined), () => convert(bytes));
  } catch (error) { return rejectPromise(error); }
}
function cloneBody(source, target) {
  const body = requireBody(source);
  if (body.used) throw new NativeTypeError('Body has already been consumed.');
  initializeBody(target, body.bytes, body.signal);
}
function streamBody(owner) { const body = requireBody(owner); if (body.present) unmodelled('ReadableStream body'); return null; }
const requestMembers = ['body','cache','credentials','duplex','headers','integrity','keepalive','method','mode','priority','redirect','referrer','referrerPolicy','signal','window'];
const credentialModes = new Set(['omit','same-origin','include']), validCredentials = credentialModes.has.bind(credentialModes);
const requestModes = new Set(['cors','no-cors','same-origin','navigate']), validRequestMode = requestModes.has.bind(requestModes);
const cacheModes = new Set(['default','no-store','reload','no-cache','force-cache','only-if-cached']), validCacheMode = cacheModes.has.bind(cacheModes);
const redirectModes = new Set(['follow','error','manual']), validRedirect = redirectModes.has.bind(redirectModes);
const normalizedMethods = new Set(['DELETE','GET','HEAD','OPTIONS','POST','PUT']), normalizeMethod = normalizedMethods.has.bind(normalizedMethods);
const tokenCode = code => (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 33 || (code >= 35 && code <= 39) || code === 42 || code === 43 || code === 45 || code === 46 || code === 94 || code === 95 || code === 96 || code === 124 || code === 126;
const charCode = Function.prototype.call.bind(String.prototype.charCodeAt), stringIndex = Function.prototype.call.bind(String.prototype.indexOf), stringSlice = Function.prototype.call.bind(String.prototype.slice);
const apiBase = () => documentBaseURL(S.document);
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
    else if (key === 'body') options.body = value === null ? null : convertBody(value);
    else if (key === 'headers') options.headers = convertHeadersInit(value);
    else if (key === 'keepalive') options.keepalive = !!value;
    else if (key === 'window') { if (value !== null) throw new NativeTypeError('Request window must be null'); options.window = null; }
    else options[key] = domString(value);
  }
  const parsed = N.url(rawURL, apiBase());
  if (!parsed || parsed[3] || parsed[4]) throw new NativeTypeError('Invalid request URL');
  const url = parsed[0];
  let method = options.method ?? src?.method ?? 'GET';
  if (!method.length) throw new NativeTypeError('Invalid HTTP method');
  for (let i = 0; i < method.length; i++) if (!tokenCode(charCode(method, i))) throw new NativeTypeError('Invalid HTTP method');
  const upper = stringUpper(method);
  if (upper === 'CONNECT' || upper === 'TRACE' || upper === 'TRACK') throw new NativeTypeError('Forbidden HTTP method');
  if (normalizeMethod(upper)) method = upper;
  const credentials = options.credentials ?? src?.credentials ?? 'same-origin', mode = options.mode ?? src?.mode ?? 'cors', cache = options.cache ?? src?.cache ?? 'default', redirect = options.redirect ?? src?.redirect ?? 'follow';
  if (!validCredentials(credentials) || !validRequestMode(mode) || mode === 'navigate' || !validCacheMode(cache) || !validRedirect(redirect) || (cache === 'only-if-cached' && mode !== 'same-origin') || (mode === 'no-cors' && method !== 'GET' && method !== 'HEAD' && method !== 'POST')) throw new NativeTypeError('Invalid request mode');
  const sourceBody = src && requireBody(input), extracted = options.body == null ? null : extractConvertedBody(options.body), body = extracted === null ? sourceBody?.bytes ?? null : extracted.bytes;
  if (body !== null && (method === 'GET' || method === 'HEAD')) throw new NativeTypeError('GET and HEAD requests cannot have a body');
  if (sourceBody && body !== null && options.body == null && sourceBody.used) throw new NativeTypeError('Body has already been consumed.');
  const source = options.signal === undefined ? src?.signal : options.signal;
  const signal = createSignal(); if (source) dependSignal(signal, [source]);
  const guard = mode === 'no-cors' ? 'request-no-cors' : 'request';
  const headers = options.headers !== undefined ? headersFromConverted(options.headers, guard) : src ? filterHeaders(src.headers, guard) : headersFromConverted([], guard);
  if (extracted !== null && extracted.type !== null && headerValue(headers, 'content-type') === null) appendNativeHeader(headers, 'content-type', extracted.type);
  return { url, method, headers, signal, credentials, mode, cache, redirect, body, sourceBody: options.body == null ? sourceBody : null };
}
let Request = class Request {
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
  get body() { requireRequest(this); return streamBody(this); }
  get bodyUsed() { requireRequest(this); return requireBody(this).used; }
  clone() {
    const data = requireRequest(this), body = requireBody(this);
    if (body.used) throw new NativeTypeError('Body has already been consumed.');
    const result = createFetchObject(Request.prototype), signal = dependSignal(createSignal(), [data.signal]);
    saveRequest(result, { ...data, headers: copyHeaders(data.headers), signal }); cloneBody(this, result); return result;
  }
  text() { return readBody(this, requireRequest, bytes => decodeBytes(bytes)); }
  json() { return readBody(this, requireRequest, bytes => parseBodyJSON(decodeBytes(bytes))); }
  arrayBuffer() { return readBody(this, requireRequest, copyBytesBuffer); }
  bytes() { return readBody(this, requireRequest, copyBodyBytes); }
  blob() { return readBody(this, requireRequest, bytes => blobFromBytes(bytes, extractMime(headerValue(requireRequest(this).headers, 'content-type')))); }
  formData() { return readBody(this, requireRequest, () => { unmodelled('Request.formData'); return new FormData(); }); }
}
function responseInit(init) {
  if (init == null) init = { __proto__: null };
  if (typeof init !== 'object' && typeof init !== 'function') throw new NativeTypeError('Response options must be a dictionary');
  const rawHeaders = init.headers, headers = rawHeaders === undefined ? headersFromConverted([], 'response') : headersFromConverted(convertHeadersInit(rawHeaders), 'response');
  const value = init.status; let status = value === undefined ? 200 : +value;
  status = finiteNumber(status) ? ((nativeTrunc(status) % 65536) + 65536) % 65536 : 0;
  const raw = init.statusText, statusText = raw === undefined ? '' : domString(raw);
  for (let i = 0; i < statusText.length; i++) if (charCode(statusText, i) > 255) throw new NativeTypeError('A ByteString is required');
  return { status, statusText, headers };
}
function validateResponse(data, present) {
  if (data.status < 200 || data.status > 599) throw new NativeRangeError('Invalid response status');
  for (let i = 0; i < data.statusText.length; i++) { const c = charCode(data.statusText, i); if (c !== 9 && c < 32 || c === 127) throw new NativeTypeError('Invalid response status text'); }
  if (present && (data.status === 204 || data.status === 205 || data.status === 304)) throw new NativeTypeError('A body is not allowed for this status');
}
function nativeResponse(bytes, data) {
  const response = createFetchObject(Response.prototype); saveResponse(response, data); initializeBody(response, bytes); return response;
}
let Response = class Response {
  constructor(body = null, init = undefined) {
    const data = runDOMCallback(() => {
      const converted = convertBody(body), options = responseInit(init); validateResponse(options, converted.kind !== 'none');
      const extracted = extractConvertedBody(converted);
      if (extracted.type !== null && headerValue(options.headers, 'content-type') === null) appendNativeHeader(options.headers, 'content-type', extracted.type);
      return { options, bytes: extracted.bytes };
    });
    saveResponse(this, { ...data.options, url: '', redirected: false, type: 'default' }); initializeBody(this, data.bytes);
  }
  get status() { return requireResponse(this).status; }
  get statusText() { return requireResponse(this).statusText; }
  get ok() { const status = requireResponse(this).status; return status >= 200 && status < 300; }
  get headers() { return requireResponse(this).headers; }
  get url() { return requireResponse(this).url; }
  get redirected() { return requireResponse(this).redirected; }
  get type() { return requireResponse(this).type; }
  get bodyUsed() { requireResponse(this); return requireBody(this).used; }
  get body() { requireResponse(this); return streamBody(this); }
  text() { return readBody(this, requireResponse, bytes => decodeBytes(bytes)); }
  json() { return readBody(this, requireResponse, bytes => parseBodyJSON(decodeBytes(bytes))); }
  blob() { return readBody(this, requireResponse, bytes => blobFromBytes(bytes, extractMime(headerValue(requireResponse(this).headers, 'content-type')))); }
  arrayBuffer() { return readBody(this, requireResponse, copyBytesBuffer); }
  bytes() { return readBody(this, requireResponse, copyBodyBytes); }
  formData() { return readBody(this, requireResponse, () => { unmodelled('Response.formData'); return new FormData(); }); }
  clone() {
    const data = requireResponse(this), result = createFetchObject(Response.prototype);
    cloneBody(this, result); saveResponse(result, { ...data, headers: copyHeaders(data.headers) }); return result;
  }
  static json(value, init = undefined) {
    return runDOMCallback(() => {
      const options = responseInit(init), text = stringifyBodyJSON(value);
      if (text === undefined) throw new NativeTypeError('The value cannot be serialized as JSON');
      validateResponse(options, true);
      if (headerValue(options.headers, 'content-type') === null) appendNativeHeader(options.headers, 'content-type', 'application/json');
      return nativeResponse(textBytes(text), { ...options, url: '', redirected: false, type: 'default' });
    });
  }
  static error() { return nativeResponse(null, { status: 0, statusText: '', headers: headersFromConverted([], 'immutable'), url: '', redirected: false, type: 'error' }); }
  static redirect(url, status = 302) {
    if (!arguments.length) throw new NativeTypeError('redirect requires a URL');
    return runDOMCallback(() => {
      url = wellFormed(domString(url)); const number = +status;
      status = finiteNumber(number) ? ((nativeTrunc(number) % 65536) + 65536) % 65536 : 0;
      let parsed; try { parsed = new URL(url, apiBase()); } catch { throw new NativeTypeError('Invalid redirect URL'); }
      if (status !== 301 && status !== 302 && status !== 303 && status !== 307 && status !== 308) throw new NativeRangeError('Invalid redirect status');
      return nativeResponse(null, { status, statusText: '', headers: headersFromConverted([['location', urlPart(parsed, 'href')]], 'immutable'), url: '', redirected: false, type: 'default' });
    });
  }
}
Request = platformConstructor(Request, 'Request'); Response = platformConstructor(Response, 'Response');
Object.defineProperty(Request, 'name', { __proto__: null, value: 'Request', configurable: true });
Object.defineProperty(Response, 'name', { __proto__: null, value: 'Response', configurable: true });
Object.assign(G, { Headers, Request, Response });

// Cookie storage is private to the user agent: Set-Cookie never becomes
// a readable response header. Delayed fetch/XHR answers apply it when
// their response is delivered, before script callbacks see that response.
function receive(r) {
  if (!r.received) {
    r.received = true;
    if (r.acceptCookies && r.status >= 200) for (let i = 0; i < r.setCookies.length; i++) S.cookies.set(r.setCookies[i], r.url, true);
  }
  return r;
}
function networkAnswer(status, body, rawHeaders, url, acceptCookies, delayed, latency = S.latency) {
  const headers = nativeCreate(null), setCookies = [];
  nativeSetPrototype(setCookies, null);
  const pairs = nativeIsArray(rawHeaders) ? rawHeaders : nativeEntries(rawHeaders || {});
  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i], key = nativeLower(nativeString(pair[0])), value = nativeString(pair[1]);
    if (key === 'set-cookie') setCookies[setCookies.length] = value;
    else if (key !== 'set-cookie2') headers[key] = headers[key] == null ? value : headers[key] + ', ' + value;
  }
  const r = { __proto__: null, status, body, headers, url, acceptCookies, setCookies, received: false, latency, error: null };
  return delayed ? r : receive(r);
}
function respond(method, url, body, headers, kind, credentials = 'same-origin', delayed = false) {
  const u = new URL(nativeString(url), apiBase());
  setURLPart(u,'hash','');
  const own = urlPart(u, 'origin') === S.origin;
  const include = credentials === 'include' || (credentials === 'same-origin' && own);
  const filtered = nativeCreate(null), raw = nativeEntries(headers || {});
  for (let i = 0; i < raw.length; i++) {
    const pair = raw[i], name = nativeLower(nativeString(pair[0]));
    if (name !== 'cookie' && name !== 'cookie2') filtered[pair[0]] = pair[1];
  }
  headers = filtered;
  if (include) {
    const cookie = S.cookies.header(urlPart(u, 'href'), true, urlPart(S.url, 'href'));
    if (cookie) headers.cookie = cookie;
  }
  push(S.requests, {
    kind, method, url: urlPart(u, 'href'), own, body: body == null ? null : clip(decodeBytes(body, false), 2000),
    headers: headers || {}, gesture: S.gesture, at: S.now - S.start,
  });
  const path = own ? urlPart(u, 'pathname') + urlPart(u, 'search') : urlPart(u, 'href');
  const h = host();
  if (h) {
    // Sent now, delivered after the latency: the answer is the host's.
    const href = urlPart(u, 'href'), hash = stringIndex(href, '#'), target = own ? path : hash < 0 ? href : stringSlice(href, 0, hash);
    const entries = nativeEntries(headers || {}), pairs = [];
    nativeSetPrototype(pairs, null);
    for (let i = 0; i < entries.length; i++) pairs[i] = [nativeString(entries[i][0]), nativeString(entries[i][1])];
    const answer = h.fetch(kind, method, own, target, pairs, body == null ? null : bufferOfBytes(body), [!!S.gesture, S.now]);
    const status = answer[0], rh = answer[1], text = wireBytes(answer[2]), failed = answer[3], latency = answer[4];
    if (failed != null) return { __proto__: null, status: 0, error: failed, body: '', headers: nativeCreate(null), url: urlPart(u, 'href'), latency: latency ?? S.latency };
    return networkAnswer(status, text, rh, urlPart(u, 'href'), include, delayed, latency ?? S.latency);
  }
  const plain = own ? urlPart(u, 'pathname') : urlPart(u, 'origin') + urlPart(u, 'pathname');
  const r = S.responses[method + ' ' + path] || S.responses[method + ' ' + plain] || S.responses[path] || S.responses[plain]
    || (method === 'GET' && own && S.files[urlPart(u, 'pathname')] != null ? { status: 200, body: S.files[urlPart(u, 'pathname')] } : null)
    || { status: 404, body: '' };
  const stored = r.body ?? '', payload = typeof stored === 'string' || nativeIsArray(stored) ? stored : reportJSON(stored);
  return networkAnswer(r.status ?? 200, wireBytes(payload), r.headers, urlPart(u, 'href'), include, delayed);
}

G.fetch = function fetch(input, init = undefined) {
  let request;
  try { if (!arguments.length) throw new NativeTypeError('fetch requires an input'); request = new Request(input, init); } catch (e) { return rejectPromise(e); }
  const req = requireRequest(request), body = requireBody(request), signal = signalState(req.signal);
  if (signal.aborted) return rejectPromise(signal.reason);
  const headers = headerObject(req.headers);
  return new NativePromise((resolve, reject) => {
    let timer = null, settled = false;
    const unsubscribe = onSignalAbort(req.signal, () => {
      if (settled) return;
      settled = true; if (timer !== null) mapDelete(S.timers, timer); reject(signalState(req.signal).reason);
    });
    let answer;
    try { answer = respond(req.method, req.url, body.bytes, headers, 'fetch', req.credentials, true); } catch (e) { settled = true; unsubscribe(); reject(e); return; }
    timer = addTimer(() => {
      if (settled) return;
      settled = true; unsubscribe();
      if (answer.error != null) { reject(new NativeTypeError('Failed to fetch')); return; }
      try {
        const noBody = req.method === 'HEAD' || answer.status === 204 || answer.status === 205 || answer.status === 304;
        const response = nativeResponse(noBody ? null : answer.body, { status: answer.status, statusText: '', headers: headersFromConverted(nativeEntries(answer.headers), 'immutable'), url: answer.url, redirected: false, type: 'basic' });
        requireBody(response).signal = req.signal;
        receive(answer); resolve(response);
      } catch (e) { reject(e); }
    }, answer.latency, [], false, 'fetch', false);
  });
};

installXHRPlatform({
  base: apiBase, now: () => S.now,
  enqueue: (fn, delay) => addTimer(fn, delay, [], false, 'xhr', false), cancel: id => mapDelete(S.timers, id),
  checkpoint: messageListenerCheckpoint, respond, receive, convertBody: body => nodeInfo(body)?.kind === 9 ? { __proto__: null, kind: 'document', value: body } : convertBody(body),
  extractBody: body => body.kind === 'document' ? { __proto__: null, bytes: textBytes(serializeDocument(body.value)), type: documentMode(body.value) !== undefined ? 'text/html;charset=UTF-8' : 'application/xml;charset=UTF-8' } : extractConvertedBody(body), entries: nativeEntries,
  document: parseNetworkDocument,
});
Object.assign(G, { XMLHttpRequest, XMLHttpRequestEventTarget, XMLHttpRequestUpload });

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

Object.assign(G, { Blob, File, FileReader });
// --- The page's document ----------------------------------------------------

// FormData conversions run before changing the entry list. The list keeps
// its identity so iterators and forEach observe later deletions and appends.
function formName(receiver, count, name) {
  const list = requireForm(receiver);
  if (!count) throw new NativeTypeError('A field name is required');
  return { list, name: runDOMCallback(() => wellFormed(domString(name))) };
}
function formEntry(receiver, count, key, value, filename) {
  const list = requireForm(receiver);
  if (count < 2) throw new NativeTypeError('A field name and value are required');
  return runDOMCallback(() => {
    const name = wellFormed(domString(key)), data = blobRecord(value);
    if (count >= 3 && !data) throw new NativeTypeError('A filename requires a Blob');
    if (!data) value = wellFormed(domString(value));
    else if (filename !== undefined || data.name === undefined) {
      const fileName = filename === undefined ? 'blob' : wellFormed(domString(filename));
      value = fileFromBlob(value, fileName);
    }
    return { list, entry: [name, value] };
  });
}
const formIteratorRecords = new WeakMap();
const getFormIterator = formIteratorRecords.get.bind(formIteratorRecords), saveFormIterator = formIteratorRecords.set.bind(formIteratorRecords);
const formIteratorPrototype = nativeCreate(Object.getPrototypeOf(Object.getPrototypeOf([][iteratorSymbol]())));
const formIteratorMethods = {
  next() {
    const state = getFormIterator(this);
    if (!state) throw new NativeTypeError('A FormData iterator is required');
    if (state.index >= state.list.length) return { value: undefined, done: true };
    const pair = state.list[state.index++];
    return { value: state.kind === 'keys' ? pair[0] : state.kind === 'values' ? pair[1] : [pair[0], pair[1]], done: false };
  },
};
nativeDefine(formIteratorPrototype, 'next', { value: formIteratorMethods.next, writable: true, enumerable: true, configurable: true });
nativeDefine(formIteratorPrototype, Symbol.toStringTag, { value: 'FormData Iterator', configurable: true });
function formIterator(receiver, kind) {
  const list = requireForm(receiver), iterator = nativeCreate(formIteratorPrototype);
  saveFormIterator(iterator, { list, index: 0, kind }); return iterator;
}

const constructingForms = new WeakSet();
const isConstructingForm = constructingForms.has.bind(constructingForms), beginForm = constructingForms.add.bind(constructingForms), endForm = constructingForms.delete.bind(constructingForms);
let FormData = class FormData {
  constructor(form, submitter = null) {
    const list = []; nativeSetPrototype(list, null); saveForm(this, list);
    if (form !== undefined && htmlName(form) !== 'form') throw new NativeTypeError('An HTMLFormElement is required');
    if (submitter !== null && !htmlName(submitter)) throw new NativeTypeError('An HTMLElement submitter is required');
    if (form === undefined) return;
    if (submitter !== null) {
      if (!isSubmitButton(submitter)) throw new NativeTypeError('The submitter must be a submit button');
      if (formOwner(submitter) !== form) throw new BrowserDOMException('The submitter belongs to another form', 'NotFoundError');
    }
    if (isConstructingForm(form)) throw new BrowserDOMException('The entry list is already being constructed', 'InvalidStateError');
    beginForm(form);
    try {
      populateForm(form, submitter, (name, value) => { list[list.length] = [wellFormed(name), typeof value === 'string' ? wellFormed(value) : value]; }, () => emptyFile());
      const data = nativeCreate(FormData.prototype); saveForm(data, list);
      const event = nativeCreate(FormDataEvent.prototype); initializeEvent(event, 'formdata', true); eventState(event).formData = data; fireEvent(form, event);
      const copy = []; nativeSetPrototype(copy, null);
      for (let i = 0; i < list.length; i++) copy[i] = list[i];
      saveForm(this, copy);
    } finally { endForm(form); }
  }
  append(k, v, filename) {
    const { list, entry } = formEntry(this, arguments.length, k, v, filename);
    list[list.length] = entry;
  }
  delete(k) {
    const { list, name } = formName(this, arguments.length, k); let write = 0;
    for (let i = 0; i < list.length; i++) if (list[i][0] !== name) list[write++] = list[i];
    list.length = write;
  }
  get(k) {
    const { list, name } = formName(this, arguments.length, k);
    for (let i = 0; i < list.length; i++) if (list[i][0] === name) return list[i][1];
    return null;
  }
  getAll(k) {
    const { list, name } = formName(this, arguments.length, k), result = [];
    for (let i = 0; i < list.length; i++) if (list[i][0] === name) nativeDefine(result, result.length, { value: list[i][1], writable: true, enumerable: true, configurable: true });
    return result;
  }
  has(k) {
    const { list, name } = formName(this, arguments.length, k);
    for (let i = 0; i < list.length; i++) if (list[i][0] === name) return true;
    return false;
  }
  set(k, v, filename) {
    const { list, entry } = formEntry(this, arguments.length, k, v, filename); let found = false, write = 0;
    for (let i = 0; i < list.length; i++) {
      const pair = list[i];
      if (pair[0] !== entry[0]) list[write++] = pair;
      else if (!found) { list[write++] = entry; found = true; }
    }
    list.length = write; if (!found) list[list.length] = entry;
  }
  forEach(f, t) {
    const list = requireForm(this);
    if (!arguments.length || typeof f !== 'function') throw new NativeTypeError('A callback is required');
    for (let i = 0; i < list.length; i++) { const pair = list[i]; runDOMCallback(() => nativeApply(f, t, [pair[1], pair[0], this])); }
  }
  entries() { return formIterator(this, 'entries'); }
  keys() { return formIterator(this, 'keys'); }
  values() { return formIterator(this, 'values'); }
}
nativeDefine(FormData.prototype, iteratorSymbol, { value: FormData.prototype.entries, writable: true, configurable: true });
FormData = platformConstructor(FormData, 'FormData', 0);
G.FormData = FormData;
let FormDataEvent = class FormDataEvent {
  constructor(type, options) {
    if (arguments.length < 2) throw new NativeTypeError('FormDataEvent requires a type and options');
    const init = runDOMCallback(() => {
      type = domString(type);
      const dictionary = eventDictionary(options);
      if (typeof dictionary !== 'object' && typeof dictionary !== 'function') throw new NativeTypeError('Event options must be a dictionary');
      const bubbles = !!dictionary.bubbles, cancelable = !!dictionary.cancelable, composed = !!dictionary.composed, formData = dictionary.formData;
      requireForm(formData); return { bubbles, cancelable, composed, formData };
    });
    initializeEvent(this, type, init.bubbles, init.cancelable, init.composed);
    eventState(this).formData = init.formData;
  }
  get formData() { const data = eventState(this).formData; if (!data) throw new NativeTypeError('A FormDataEvent is required'); return data; }
}
nativeSetPrototype(FormDataEvent, Ev); nativeSetPrototype(FormDataEvent.prototype, Ev.prototype);
nativeDefine(FormDataEvent, 'name', { value: 'FormDataEvent', configurable: true });
nativeDefine(FormDataEvent.prototype, 'formData', { get: Object.getOwnPropertyDescriptor(FormDataEvent.prototype, 'formData').get, enumerable: true, configurable: true });
nativeDefine(FormDataEvent.prototype, Symbol.toStringTag, { value: 'FormDataEvent', configurable: true });
FormDataEvent = platformConstructor(FormDataEvent, 'FormDataEvent');
G.FormDataEvent = FormDataEvent;

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
  return registerStorageArea(new Proxy(api, {
    get: (t, k) => (k in t ? t[k] : typeof k === 'string' && m.has(k) ? m.get(k) : undefined),
    set: (t, k, v) => { api.setItem(k, v); return true; },
    has: (t, k) => k in t || m.has(k),
    deleteProperty: (t, k) => { m.delete(k); return true; },
    ownKeys: () => [...m.keys()],
    getOwnPropertyDescriptor: (t, k) => (m.has(k) ? { value: m.get(k), enumerable: true, configurable: true, writable: true } : undefined),
  }));
}

function setCookie(text) {
  const written = S.cookies.set(runDOMCallback(() => domString(text)), urlPart(S.url, 'href'));
  if (written) push(S.cookieWrites, { name: clip(written.name, 100), value: clip(written.value, 200), flags: written.flags, gesture: S.gesture });
}

function navigate(target, how, extra = {}) {
  let u;
  try { u = new URL(String(target), apiBase()); } catch (e) { error(how, e); return; }
  if (urlPart(u, 'protocol') === 'javascript:') {
    let code = urlPart(u, 'href').slice('javascript:'.length);
    try { code = decodeURIComponent(code); } catch {}
    runCode(code, 'javascript-url');
    return;
  }
  const strip = (h) => h.split('#')[0];
  if (strip(urlPart(u, 'href')) === strip(urlPart(S.url, 'href')) && urlPart(u, 'hash') && how !== 'location.reload' && !extra.method) {
    const oldURL = urlPart(S.url, 'href');
    apiBase(); S.url = u;
    push(S.history, { how, url: urlPart(u, 'href') });
    addTimer(() => fireEvent(G, createNativeUIEvent(HashChangeEvent, 'hashchange', { oldURL, newURL: urlPart(u, 'href') })), 0, [], false, 'hashchange', false);
    return;
  }
  push(S.navigations, { url: urlPart(u, 'href'), how, gesture: S.gesture, at: S.now - S.start, ...extra });
  { const h = host(); if (h) h.go(how, urlPart(u, 'href'), !!S.gesture); }
  if (!extra.popup && !S.ended) S.ended = { url: urlPart(u, 'href'), how };
}

const location = {};
for (const k of ['protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash']) {
  Object.defineProperty(location, k, {
    enumerable: true,
    get: () => urlPart(S.url, k),
    set: (v) => { const u = new URL(urlPart(S.url, 'href')); setURLPart(u, k, v); navigate(urlPart(u, 'href'), 'location.' + k); },
  });
}
Object.defineProperty(location, 'origin', { enumerable: true, get: () => urlPart(S.url, 'origin') });
Object.defineProperty(location, 'href', { enumerable: true, get: () => urlPart(S.url, 'href'), set: (v) => navigate(v, 'location.href') });
Object.assign(location, {
  assign: (v) => navigate(v, 'location.assign'),
  replace: (v) => navigate(v, 'location.replace'),
  reload: () => navigate(urlPart(S.url, 'href'), 'location.reload'),
  toString: () => urlPart(S.url, 'href'),
  ancestorOrigins: [],
});

const historyApi = {
  length: 1, state: null, scrollRestoration: 'auto',
  _go(how, state, url) {
    if (url != null) {
      const u = new URL(nativeString(url), apiBase());
      if (urlPart(u, 'origin') !== S.origin) throw new BrowserDOMException(how + ': another origin', 'SecurityError');
      apiBase(); S.url = u;
    }
    this.state = state ?? null;
    push(S.history, { how, url: urlPart(S.url, 'href') });
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
  constructor(cb) { markPlatform(this); this._cb = cb; this._els = []; }
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
    markPlatform(this);
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
  constructor() { markPlatform(this); }
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
  Object.assign(G, { InputEvent, DataTransfer, DataTransferItem, DataTransferItemList, FileList, StaticRange, AbstractRange, NodeRange, Touch, DOMParser, NodeList, HTMLCollection, NamedNodeMap });
  installHTMLConstructors(G, L);
  const createInternal = installRegistry(upgradeCopies, BrowserDOMException, (name, e) => error('custom-element:' + name, e));
  S.parserCreate = (owner,identity,is) => owner === doc ? createInternal(owner,identity,is) : createBareElement(owner,identity,is);
  G.DOMImplementation = DOMImplementation; G.XMLDocument = XMLDocument;
  nativeSetPrototype(XMLDocument,L.Document);
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
  dispatchGlobalError = (info, value) => dispatchGlobalEvent(createNativeUIEvent(ErrorEvent, 'error', { cancelable: true, message: info.eventMessage, error: value, filename: (S.url && urlPart(S.url, 'href')) || '' }));
  G.reportError = function (value) {
    if (!arguments.length) throw new NativeTypeError('reportError requires an argument');
    error('reportError', value);
  };
  G.customElements = view.customElements;
  G.MutationObserver = view.MutationObserver; G.MutationRecord = MutationRecord;
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
    postMessage,
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
      const r = respond('POST', url, bodyBytes(data), {}, 'beacon', 'include', true);
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

  for (const value of [G.navigator, G.navigator.clipboard, G.navigator.serviceWorker, G.navigator.permissions, G.navigator.userAgentData, G.screen, G.screen.orientation, G.customElements]) markPlatform(value);

  const define = (o, k, d) => Object.defineProperty(o, k, { configurable: true, ...d });
  define(doc, 'readyState', { get: () => S.readyState });
  define(doc, 'location', { get: () => location, set: (v) => navigate(v, 'document.location') });
  define(doc, 'cookie', {
    get: () => S.cookies.header(urlPart(S.url, 'href'), false),
    set: (v) => setCookie(v),
  });
  const activeElementGetter = { get activeElement() { return activeElementFor(this); } };
  define(L.Document.prototype, 'activeElement', Object.getOwnPropertyDescriptor(activeElementGetter, 'activeElement'));
  rememberDocumentURL(doc,() => urlPart(S.url,'href'));
  for (const k of ['URL', 'documentURI']) define(doc, k, { get: () => urlPart(S.url, 'href') });
  define(doc,'baseURI',{ get: () => documentBaseURL(doc) });
  define(doc, 'domain', { get: () => urlPart(S.url, 'hostname'), set() {} });
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
    if (!arguments.length) throw new NativeTypeError('createElement requires a name');
    const html = isHTMLDocument(this), converted = domString(name), is = creationIs(options);
    const local = html ? lowerASCII(converted) : converted;
    if (!validElementLocalName(local)) throw new BrowserDOMException('Invalid element name', 'InvalidCharacterError');
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
  L.DOMParser.prototype.parseFromString = parsing(function (markup, mime) {
    requireParser(this); if (arguments.length < 2) throw new NativeTypeError('Two arguments are required');
    const args = runDOMCallback(() => ({ __proto__: null, markup: domString(markup), mime: domString(mime) }));
    if (args.mime === 'text/html') return parseHTML(args.markup, false);
    if (args.mime !== 'application/xml' && args.mime !== 'text/xml' && args.mime !== 'application/xhtml+xml' && args.mime !== 'image/svg+xml') throw new NativeTypeError('Unsupported document type');
    return parseNetworkDocument(args.markup, args.mime, urlPart(S.url, 'href')) || parseNetworkDocument('<parsererror xmlns="http://www.mozilla.org/newlayout/xml/parsererror.xml">XML parsing error</parsererror>', args.mime, urlPart(S.url, 'href'));
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
    const Classes = { __proto__: null, event: Ev, events: Ev, htmlevents: Ev, customevent: L.CustomEvent, uievent: UIEvent, uievents: UIEvent, mouseevent: MouseEvent, mouseevents: MouseEvent, keyboardevent: KeyboardEvent, messageevent: MessageEvent };
    const Class = Classes[type];
    if (!Class) throw new BrowserDOMException('Unsupported event interface', 'NotSupportedError');
    const event = new Class(''); markEventUninitialized(event); return event;
  };
  doc.evaluate = (expr, node) => new XPathExpression(expr).evaluate(node);

  // A fragment has descendant text and the same replace-with-text setter
  // as an element; linkedom otherwise inherits Node's null/no-op stubs.
  Object.defineProperty(L.DocumentFragment.prototype, 'textContent', Object.getOwnPropertyDescriptor(L.Element.prototype, 'textContent'));
  installShadowConstraints(L.Element, BrowserDOMException, activeElementFor);
  installSerialization(L);
  installScriptMutations(L, scriptsChanged);
  installReactionBoundaries(L);

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
  H.focus = function () { if (!htmlName(this)) throw new NativeTypeError('An HTMLElement is required'); focusNode(this); };
  H.blur = function () { if (!htmlName(this)) throw new NativeTypeError('An HTMLElement is required'); if (S.active === this) focusNode(null); };
  H.click = function () {
    if (nodeInfo(this)?.kind !== 1 || !htmlName(this)) throw new NativeTypeError('An HTMLElement is required');
    if (disabled(this) || clicking(this)) return;
    rememberClick(this, true);
    try { click(this, false); } finally { rememberClick(this, false); }
  };
  define(H, 'isContentEditable', { get() { const v = this.getAttribute('contenteditable'); return v === '' || v === 'true'; } });
  define(H, 'form', { get() { return this.closest('form'); } });

  installValueProperties(L, BrowserDOMException);
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
  installFileInputs(I);
  installNumericProperties(L, BrowserDOMException);
  I.select = I.setSelectionRange = I.setCustomValidity = I.reportValidity = function () { return true; };
  I.checkValidity = function () { return true; };
  const F = L.HTMLFormElement.prototype;
  define(F, 'elements', { get() { return this.querySelectorAll('input,select,textarea,button,fieldset,output'); } });
  F.requestSubmit = function (submitter) { submit(this, submitter || null); };
  F.submit = function () { formNavigate(this, null); };
  F.reset = function () { resetForm(this); };
  F.checkValidity = F.reportValidity = function () { return true; };
  installSelectProperties(L);
}

// --- What a person does: clicks, typing, submits ------------------------------

const TYPED = new Set(['', 'text', 'search', 'email', 'url', 'tel', 'password', 'number', 'date', 'time', 'datetime-local', 'month', 'week']);
const CLICKISH = new Set(['click', 'mousedown', 'mouseup', 'pointerdown', 'pointerup', 'touchstart', 'touchend', 'dblclick', 'submit', 'change', 'input', 'keydown', 'keyup', 'keypress']);
const NATIVE = new Set(['button', 'input', 'select', 'textarea', 'summary']);
const interactive = (el) => {
  const t = htmlName(el);
  if (setHas(NATIVE, t)) return true;
  if (activationKind(el) === 'link') return true;
  return eventAttribute(el, 'onclick') !== null || eventAttribute(el, 'role') === 'button' || eventAttribute(el, 'contenteditable') !== null || eventAttribute(el, 'tabindex') !== null;
};

function candidates() {
  const out = [], descriptions = [];
  nativeSetPrototype(out, null); nativeSetPrototype(descriptions, null);
  const nodes = treeElements(S.document);
  for (let i = 0; i < nodes.length; i++) {
    const el = nodes[i];
    if (disabled(el) || eventAttribute(el, 'hidden') !== null) continue;
    const types = listenerTypes(el);
    let own = false;
    if (types) setEach(types, type => { if (setHas(CLICKISH, type)) own = true; });
    if (own || interactive(el) || frameworkCandidate(el)) out[out.length] = el;
  }
  S.cands = out;
  for (let i = 0; i < out.length; i++) {
    const el = out[i], tag = nameIdentity(el)?.local || '', html = htmlName(el), type = controlType(el);
    const kind = (html === 'input' && setHas(TYPED, type)) || html === 'textarea' || editable(el) ? 'type' : html === 'select' || (htmlName(el) === 'input' && (type === 'color' || type === 'range')) ? 'select' : 'click';
    descriptions[descriptions.length] = { i, tag, id: eventAttribute(el, 'id') || '', kind, text: clip(normalizedText(nodeText(el)), 60) };
  }
  return descriptions;
}

function focusDocument(node) {
  let root = physicalRoot(node);
  while (shadowInfo(root)) root = physicalRoot(shadowInfo(root).host);
  return root;
}
function activeElementFor(root) {
  const shadow = shadowInfo(root);
  if (!shadow && nodeInfo(root)?.kind !== 9) throw new NativeTypeError('A Document or ShadowRoot is required');
  if (S.active && connected(S.active) && (shadow ? shadowAncestor(root, S.active) : focusDocument(S.active) === root)) return retarget(S.active, root);
  return shadow ? null : physicalBody(root);
}
function focusable(node) {
  const name = htmlName(node);
  if (!name || !connected(node) || focusDocument(node) !== S.document || disabled(node) || (name === 'input' && controlType(node) === 'hidden')) return false;
  for (let parent = node; parent; parent = physicalParent(parent) || shadowInfo(parent)?.host || null) if (eventAttribute(parent, 'hidden') !== null || eventAttribute(parent, 'inert') !== null) return false;
  const tab = eventAttribute(node, 'tabindex');
  if (tab !== null) {
    let index = 0;
    while (index < tab.length && (tab[index] === ' ' || tab[index] === '\t' || tab[index] === '\n' || tab[index] === '\r' || tab[index] === '\f')) index++;
    if (tab[index] === '+' || tab[index] === '-') index++;
    if (index < tab.length && tab[index] >= '0' && tab[index] <= '9') return true;
  }
  return name === 'input' || name === 'button' || name === 'select' || name === 'textarea' || name === 'iframe' || name === 'object' || name === 'embed'
    || ((name === 'a' || name === 'area') && eventAttribute(node, 'href') !== null)
    || (name === 'summary' && activationKind(node) === 'summary')
    || ((name === 'audio' || name === 'video') && eventAttribute(node, 'controls') !== null) || editable(node);
}
function focusNode(node) {
  if (node !== null && !focusable(node)) return;
  if (S.active === node) return;
  const old = S.active && connected(S.active) ? S.active : null;
  S.active = node;
  if (old) { fireEvent(old, createNativeUIEvent(FocusEvent, 'blur', { view: G, relatedTarget: node, composed: true })); fireEvent(old, createNativeUIEvent(FocusEvent, 'focusout', { view: G, relatedTarget: node, bubbles: true, composed: true })); }
  if (node) { fireEvent(node, createNativeUIEvent(FocusEvent, 'focus', { view: G, relatedTarget: old, composed: true })); fireEvent(node, createNativeUIEvent(FocusEvent, 'focusin', { view: G, relatedTarget: old, bubbles: true, composed: true })); }
}

function dispatch(el, ev) { return fireEvent(el, ev); }

function click(el, gesture) {
  const was = S.gesture;
  S.gesture = was || gesture;
  try {
    const o = { __proto__: null, bubbles: true, cancelable: true, composed: true, view: G, button: 0, detail: 1, pointerId: gesture ? 1 : -1, pointerType: gesture ? 'mouse' : '', isPrimary: !!gesture };
    if (gesture) {
      o.buttons = 1; o.pressure = 0.5;
      const compatibility = dispatch(el, createNativeUIEvent(PointerEvent, 'pointerdown', { ...o, detail: 0 }));
      if (compatibility && dispatch(el, createNativeUIEvent(MouseEvent, 'mousedown', o)) && htmlName(el)) focusNode(el);
      o.buttons = 0; o.pressure = 0;
      dispatch(el, createNativeUIEvent(PointerEvent, 'pointerup', { ...o, detail: 0 }));
      if (compatibility) dispatch(el, createNativeUIEvent(MouseEvent, 'mouseup', o));
    }
    const ev = createNativeUIEvent(PointerEvent, 'click', { ...o, detail: gesture ? 1 : 0, isPrimary: false, buttons: 0, pressure: 0 });
    return fireEvent(el, ev, gesture);
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
      fireEvent(node, createNativeEvent('input', { bubbles: true, composed: true }));
      fireEvent(node, createNativeEvent('change', { bubbles: true }));
    }
    return;
  }
  if (kind === 'link') {
    const href = eventAttribute(node, 'href') ?? eventAttribute(node, 'xlink:href');
    if (href !== null) {
      const target = eventAttribute(node, 'target');
      const extra = target && target !== '_self' ? { popup: true, target } : {}, gesture = S.gesture;
      let destination; try { destination = urlPart(new URL(href, documentBaseURL(nodeDocument(node))), 'href'); } catch { return; }
      addTimer(() => { const was = S.gesture; S.gesture = gesture; try { navigate(destination, 'link', extra); } finally { S.gesture = was; } }, 0, [], false, 'link-navigation', false);
    }
  } else if (kind === 'input' || kind === 'button') {
    if (disabled(node)) return;
    const form = formOwner(node), buttonType = kind === 'button' && type !== 'reset' && type !== 'button' ? 'submit' : type;
    if (form && (buttonType === 'submit' || buttonType === 'image')) submit(form, node);
    else if (form && buttonType === 'reset') resetForm(form);
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

const resettingForms = new WeakSet();
const isResettingForm = resettingForms.has.bind(resettingForms), beginReset = resettingForms.add.bind(resettingForms), endReset = resettingForms.delete.bind(resettingForms);
function resetForm(form) {
  if (htmlName(form) !== 'form') throw new NativeTypeError('An HTMLFormElement is required');
  if (isResettingForm(form)) return;
  beginReset(form);
  try {
    if (!fireEvent(form, createNativeEvent('reset', { bubbles: true, cancelable: true }))) return;
    const nodes = treeElements(physicalRoot(form));
    for (let i = 0; i < nodes.length; i++) if (formOwner(nodes[i]) === form) {
      const kind = htmlName(nodes[i]);
      if (kind === 'input' || kind === 'textarea') resetControlValue(nodes[i]);
      if (kind === 'input') resetChecked(nodes[i]);
      else if (kind === 'select') resetSelect(nodes[i]);
    }
  } finally { endReset(form); }
}

function submit(form, submitter) {
  if (!dispatch(form, createNativeUIEvent(SubmitEvent, 'submit', { bubbles: true, cancelable: true, submitter }))) return;
  formNavigate(form, submitter);
}

function formNavigate(form, submitter) {
  const owner = nodeDocument(form); if (owner !== S.document) return;
  const attr = k => (submitter ? eventAttribute(submitter,'form' + k) : null) ?? eventAttribute(form,k);
  const method = nativeLower(attr('method') || 'get');
  if (method === 'dialog') return;
  const raw = attr('action');
  const action = new URL(raw == null || raw === '' ? documentURL(owner) : raw, documentBaseURL(owner));
  const data = serializeParams(new URLSearchParams([...new FormData(form, submitter)].map(([k, v]) => [k, typeof v === 'string' ? v : '[file]'])));
  const target = attr('target');
  const extra = target && target !== '_self' ? { popup: true, target } : {};
  if (method === 'post') navigate(urlPart(action, 'href'), 'form', { method: 'POST', body: clip(data, 2000), ...extra });
  else { setURLPart(action, 'search', data); navigate(urlPart(action, 'href'), 'form', { method: 'GET', ...extra }); }
}

function act(i, value) {
  const el = S.cands[i];
  if (!el || !connected(el) || disabled(el)) return false;
  const c = { i, tag: nameIdentity(el)?.local || '', id: eventAttribute(el, 'id') || '' };
  S.gesture = true;
  try {
    const tag = htmlName(el);
    const type = controlType(el);
    const editing = tag !== 'input' && tag !== 'textarea' && tag !== 'select' && editable(el);
    const readonly = (tag === 'input' || tag === 'textarea') && eventAttribute(el, 'readonly') !== null;
    if ((((tag === 'input' && setHas(TYPED, type)) || tag === 'textarea') && !readonly) || editing) {
      const v = value == null ? representativeInputValue(type) : nativeString(value);
      focusNode(el);
      if (editing) el.textContent = v; else setControlValue(el, v);
      dispatch(el, createNativeUIEvent(InputEvent, 'input', { bubbles: true, data: v, inputType: 'insertText' }));
      dispatch(el, createNativeEvent('change', { bubbles: true }));
      c.kind = 'type';
      c.value = clip(v, 100);
    } else if (tag === 'input' && (type === 'color' || type === 'range')) {
      c.kind = 'select';
      if (click(el, true) && connected(el) && !disabled(el) && controlType(el) === type) {
        const before = controlValue(el), chosen = value == null ? representativeSelectionValue(el, type, before) : nativeString(value);
        setControlValue(el, chosen);
        const after = controlValue(el);
        if (after !== before) {
          dispatch(el, createNativeEvent('input', { bubbles: true, composed: true }));
          dispatch(el, createNativeEvent('change', { bubbles: true }));
        }
        c.value = clip(after, 100);
      }
    } else if (tag === 'select') {
      c.kind = 'select';
      focusNode(el);
      if (connected(el) && !disabled(el) && chooseSelectOption(el, value)) {
        dispatch(el, createNativeEvent('input', { bubbles: true, composed: true }));
        dispatch(el, createNativeEvent('change', { bubbles: true }));
      }
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
  const t = nativeLower(type == null ? (language ? 'text/' + language : '') : type);
  let first = 0, last = t.length;
  const whitespace = c => c === ' ' || c === '\t' || c === '\n' || c === '\f' || c === '\r';
  if (type != null) { while (first < last && whitespace(t[first])) first++; while (last > first && whitespace(t[last - 1])) last--; }
  const mime = stringSlice(t,first,last);
  // Firefox accepts ASCII whitespace around module. Do not delegate native
  // script classification to author String/RegExp prototype methods.
  if (mime === 'module') return 'module';
  if (t === 'importmap' || t === 'speculationrules') return t;
  if (t === '') return 'classic';
  switch (mime) {
    case 'text/javascript': case 'application/javascript': case 'text/ecmascript': case 'application/ecmascript':
    case 'text/x-javascript': case 'application/x-javascript': case 'text/x-ecmascript': case 'application/x-ecmascript':
    case 'text/javascript1.0': case 'text/javascript1.1': case 'text/javascript1.2': case 'text/javascript1.3': case 'text/javascript1.4': case 'text/javascript1.5':
    case 'text/jscript': case 'text/livescript': return 'classic';
  }
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
  if (!record || record.alreadyStarted || record.parserPending) return null;
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
    const baseURL = documentBaseURL(scriptOwner(s));
    prepared = { kind, url: kind === 'module' ? baseURL.split('#')[0] + '#inline-' + n : urlPart(S.url, 'href'), metaURL: baseURL, code, inline: true };
  } else {
    let url;
    try { url = urlPart(new URL(src, documentBaseURL(scriptOwner(s))), 'href'); }
    catch { scriptError(s); return null; }
    if (src === '' && record.identity.namespace === HTML_NS) { scriptError(s); return null; }
    prepared = { kind, url, code: file(url), inline: false };
  }
  record.prepared = prepared;
  return prepared;
}

function scriptError(el) {
  addTimer(() => fireEvent(el, createNativeEvent('error')), 0, [], false, 'script-error', false);
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
  const own = urlPart(u, 'origin') === S.origin;
  const r = respond('GET', urlPart(u, 'href'), null, {}, 'script', 'same-origin', true);
  if (host()) {
    S.now += r.latency;
    receive(r);
    return r.error == null && r.status >= 200 && r.status < 300 ? decodeBytes(r.body) : null;
  }
  const body = own ? S.files[urlPart(u, 'pathname')] : S.files[urlPart(u, 'href')];
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
let documentParser = null, parserStarted = false, parserFinished = false;
let parserBlocking = null, parserDeferred = null, parserLater = null;
function parserScript(node) {
  const record = scriptRecord(node); if (record) record.parserPending = false;
  if (scriptDocument(node) !== S.document) return false;
  const kind = scriptKind(node); if (!kind) return false;
  const src = scriptSource(node) != null, async = scriptAttribute(node,'async') != null;
  if (kind === 'classic' && !(src && (async || scriptAttribute(node,'defer') != null))) { parserBlocking = node; return true; }
  const prepared = prepareScript(node);
  if (prepared) { const list = async && (src || kind === 'module') ? parserLater : parserDeferred; list[list.length] = node; }
  return false;
}
function resumeParser(markup = null) {
  if (parserFinished) return null;
  parserBlocking = null;
  const paused = parserStarted ? documentParser.resume() : documentParser.start(markup);
  parserStarted = true;
  const scripts = backendList();
  if (paused) { if (parserBlocking) scripts[scripts.length] = parserBlocking; }
  else { parserFinished = true; for (let i = 0; i < parserDeferred.length; i++) scripts[scripts.length] = parserDeferred[i]; for (let i = 0; i < parserLater.length; i++) scripts[scripts.length] = parserLater[i]; }
  S.scripts = scripts; return scripts.length;
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
  if (el && external) fireEvent(el, createNativeEvent(ok ? 'load' : 'error'));
}

// --- The driver's handle ---------------------------------------------------------

function consoleArgument(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && !finiteNumber(value)) return nativeString(value);
  try { const encoded = reportJSON(value); if (encoded !== undefined) return encoded; } catch {}
  try { return nativeString(value); } catch { return '[unprintable]'; }
}
G.console = Object.fromEntries(['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir', 'table'].map(level => [level, (...args) => {
  let text = '';
  for (let i = 0; i < args.length; i++) text += (i ? ' ' : '') + consoleArgument(args[i]);
  push(S.console, { level, at: S.now - S.start, text: clip(text) });
}]));
Object.assign(G.console, { group() {}, groupCollapsed() {}, groupEnd() {}, time() {}, timeEnd() {}, timeLog() {}, count() {}, countReset() {}, assert(c, ...a) { if (!c) G.console.error('Assertion failed:', ...a); } });

function unsupportedAPIs() { const result = []; nativeSetPrototype(result, null); setEach(S.unmodelled, value => { result[result.length] = value; }); return result; }
const pageText = () => documentText(S.document);
G.__af = {
  bindClassic(run) { S.runClassic = run; },
  bindMessageCheckpoint(value) { messageCheckpoint = value; },
  bindHost(bridge) { browserHost = bridge; },
  // `now` and `hostSeed`: the host's clock and randomness, when it has them.
  init(json, now, hostSeed) {
    const s = JSON.parse(json);
    S.url = new URL(s.url || 'https://app.example/');
    S.origin = urlPart(S.url, 'origin');
    S.start = S.now = s.now ?? now ?? RealDate.UTC(2026, 10, 2, 10);
    S.horizon = S.now;
    seed = s.seed ?? hostSeed ?? 1;
    S.files = s.files || {};
    S.responses = s.responses || {};
    S.latency = s.latency_ms ?? 5;
    for (const [k, v] of Object.entries(s.cookies || {})) S.cookies.seed(k, v, urlPart(S.url, 'href'));
    for (const cookie of s.request_cookies || []) S.cookies.request(cookie, urlPart(S.url, 'href'));
    for (const cookie of s.set_cookies || []) S.cookies.set(cookie, urlPart(S.url, 'href'), true);
    if (s.probe_cookie) {
      const base = String(s.probe_cookie.name);
      let name = base;
      for (let i = 1; S.cookies.has(name); i++) name = base + '_' + i;
      S.cookies.seed(name, s.probe_cookie.value, urlPart(S.url, 'href'));
    }
    const parsing = beginHTML({ __proto__: null, url: () => urlPart(S.url,'href'), policies: s.csp || [], create: (owner,identity,is) => S.parserCreate(owner,identity,is) });
    const doc = parsing.doc; S.document = doc; installWindow(doc);
    parserDeferred = backendList(); parserLater = backendList();
    documentParser = parsing.start(parserScript);
    return resumeParser(s.html || '');
  },
  scriptAt,
  resumeParser: () => resumeParser(),
  scriptList: () => copyScriptBatch(S.scripts),
  scriptDone,
  newScripts,
  resolve(spec, base) {
    if (!/^(\.{0,2}\/|[a-zA-Z][a-zA-Z0-9+.-]*:)/.test(spec)) throw new TypeError(`Failed to resolve module specifier "${spec}"`);
    return urlPart(new URL(spec, base), 'href');
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
      const unhandled = dispatchGlobalEvent(createNativeUIEvent(PromiseRejectionEvent, 'unhandledrejection', { cancelable: true, promise, reason: record.reason }));
      mapDelete(rejections, promise);
      if (!record.handled) rememberNotified(promise, record);
      if (unhandled) error('unhandledrejection', record.reason, false);
    }
    for (let i = 0; i < handled.length; i++) {
      const [promise, reason] = handled[i];
      dispatched = true;
      dispatchGlobalEvent(createNativeUIEvent(PromiseRejectionEvent, 'rejectionhandled', { promise, reason }));
    }
    return dispatched;
  },
  ready() {
    S.readyState = 'interactive';
    fireEvent(G.document, createNativeEvent('DOMContentLoaded', { bubbles: true }));
  },
  loaded() {
    S.readyState = 'complete';
    const ev = createNativeEvent('load');
    fireEvent(G, ev, true, S.document);
    fireEvent(G, createNativeEvent('pageshow'));
  },
  // Lets due tasks run for `ms` more virtual milliseconds.
  until(ms) { S.horizon = S.now + ms; },
  // Fast-forward, as a tab in the background: no timer fires more than
  // once per `ms`, so days pass in a few steps.
  throttle(ms) {
    S.throttle = ms;
    mapEach(S.timers, t => { if (t.repeat) t.timeout = nativeMax(t.timeout, ms); });
  },
  step,
  now: () => S.now,
  // When the next task is due, or -1 when none is.
  next() {
    let due = -1;
    mapEach(S.timers, t => { if (due < 0 || t.due < due) due = t.due; });
    return due;
  },
  idle() { S.now = nativeMax(S.now, S.horizon); },
  ended: () => !!S.ended,
  candidates: () => reportJSON(candidates()),
  count: () => candidates().length,
  act,
  text: pageText,
  report() {
    return reportJSON({
      url: urlPart(S.url, 'href'), ended: S.ended, now_ms: S.now - S.start, steps: S.steps, timers: mapSize(S.timers),
      errors: S.errors, console: S.console, requests: S.requests, navigations: S.navigations,
      code: S.code, cookies: S.cookieWrites, storage: S.storage, dialogs: S.dialogs, history: S.history,
      unmodelled: unsupportedAPIs(), actions: S.actions,
      text: stringSlice(pageText(), 0, 2000),
    });
  },
};

installClonePlatform(value => {
  const data = blobRecord(value);
  if (data) return { value: cloneBlob(value) };
  const fileList = serializeFileList(value);
  if (fileList) return fileList;
  if (nodeInfo(value) || formRecord(value) || requestData(value) || responseData(value)) return { reject: true };
  return null;
}, unmodelled);
for (const value of [G, G.performance, G.crypto, location, historyApi]) markPlatform(value);

installStackReporter(unmodelled);
