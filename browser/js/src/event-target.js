// Listener identity, options, removal and the dispatch path are native
// state. Author property shadows are visible to author JS, not routing.
import { eventState, eventString, eventDictionary, setEventTrusted, cancelEvent } from './event-state.js';
import { nodeInfo, shadowInfo, physicalRoot, closedAncestors, eventParent, retarget, defaultPassiveTarget, rememberDocumentWindow } from './dom-state.js';
import { signalState, onSignalAbort } from './abort-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const targets = new WeakMap(), aliases = new WeakMap();
const targetFor = targets.get.bind(targets), remember = targets.set.bind(targets), aliasFor = aliases.get.bind(aliases), rememberAlias = aliases.set.bind(aliases);
const apply = Reflect.apply, define = Object.defineProperty, NativeTypeError = TypeError, NativeMap = Map;
const mapGet = Function.prototype.call.bind(Map.prototype.get), mapSet = Function.prototype.call.bind(Map.prototype.set);
let DOMError = class DOMException extends Error { constructor(message, name) { super(message); this.name = name; } };
let hooks = { error() {}, changed() {}, current() {} };
export function installEventHooks(next, ErrorClass) { hooks = { ...hooks, ...next }; if (ErrorClass) DOMError = ErrorClass; }
export function canonicalTarget(value) {
  const target = aliasFor(value) || value;
  const record = targetFor(target);
  if (!record || nodeInfo(target)?.kind === -1) throw new NativeTypeError('An EventTarget is required');
  return target;
}
export function exposedTarget(value) { return value == null ? null : targetFor(canonicalTarget(value)).exposed; }
export function nullableTarget(value) { return value == null ? null : exposedTarget(value); }
export function registerWindow(document, internal, global, view) {
  const record = targetFor(canonicalTarget(internal));
  record.exposed = global; record.window = true;
  rememberAlias(global, internal); if (view) rememberAlias(view, internal);
  rememberDocumentWindow(document, internal);
}
function listenersChanged(target, record) {
  const types = [];
  for (let i = 0; i < record.listeners.length; i++) if (!record.listeners[i].removed) types[types.length] = record.listeners[i].type;
  hooks.changed(target, types);
}
function removeRecord(target, record, listener) {
  if (listener.removed) return;
  listener.removed = true;
  if (listener.unsubscribe) { listener.unsubscribe(); listener.unsubscribe = null; }
  for (let i = 0; i < record.listeners.length; i++) if (record.listeners[i] === listener) {
    for (let j = i + 1; j < record.listeners.length; j++) record.listeners[j - 1] = record.listeners[j];
    record.listeners.length--; break;
  }
  listenersChanged(target, record);
}
function callbackValue(value) {
  if (value == null) return null;
  if (typeof value !== 'object' && typeof value !== 'function') throw new NativeTypeError('A listener must be an object');
  return value;
}
function optionsValue(value, more) {
  if (value != null && typeof value !== 'object' && typeof value !== 'function') return { capture: !!value, once: false, passive: null, signal: null };
  const dictionary = eventDictionary(value), capture = !!dictionary.capture;
  if (!more) return { capture };
  const once = !!dictionary.once, rawPassive = dictionary.passive, signal = dictionary.signal;
  if (signal !== undefined) signalState(signal);
  return { capture, once, passive: rawPassive === undefined ? null : !!rawPassive, signal: signal == null ? null : signal };
}
export function addListener(target, type, callback, options = {}) {
  target = canonicalTarget(target);
  const record = targetFor(target);
  if (options.signal && signalState(options.signal).aborted) return null;
  if (callback == null) return null;
  for (let i = 0; i < record.listeners.length; i++) {
    const existing = record.listeners[i];
    if (!existing.removed && existing.type === type && existing.callback === callback && existing.capture === !!options.capture) return existing;
  }
  const passive = options.passive == null ? ((type === 'wheel' || type === 'mousewheel' || type === 'touchstart' || type === 'touchmove') && (record.window || defaultPassiveTarget(target))) : options.passive;
  const listener = { type, callback, capture: !!options.capture, passive, once: !!options.once, removed: false, unsubscribe: null };
  record.listeners[record.listeners.length] = listener;
  if (options.signal) listener.unsubscribe = onSignalAbort(options.signal, () => removeRecord(target, record, listener));
  listenersChanged(target, record);
  return listener;
}
export function removeListener(target, type, callback, capture = false) {
  target = canonicalTarget(target); const record = targetFor(target);
  for (let i = 0; i < record.listeners.length; i++) {
    const listener = record.listeners[i];
    if (!listener.removed && listener.type === type && listener.callback === callback && listener.capture === capture) { removeRecord(target, record, listener); return; }
  }
}
function handlerSlot(target, type) {
  const handlers = targetFor(target).handlers;
  let slot = mapGet(handlers, type);
  if (!slot) { slot = { value: null, content: null, listener: null }; mapSet(handlers, type, slot); }
  return slot;
}
function readHandler(slot) {
  if (slot.content) {
    const compile = slot.content; slot.content = null;
    slot.value = compile();
  }
  return slot.value;
}
export function getHandler(target, type) { return readHandler(handlerSlot(canonicalTarget(target), type)); }
function activateHandler(target, type, slot) {
  if ((slot.value || slot.content) && !slot.listener) {
    const fn = event => {
      const callback = readHandler(slot);
      if (typeof callback === 'function' && apply(callback, exposedTarget(target), [event]) === false) cancelEvent(event);
    };
    slot.listener = addListener(target, type, fn, { passive: false });
  } else if (!slot.value && !slot.content && slot.listener) {
    removeRecord(target, targetFor(target), slot.listener); slot.listener = null;
  }
}
export function setHandler(target, type, value) {
  target = canonicalTarget(target); const slot = handlerSlot(target, type);
  slot.content = null;
  slot.value = value !== null && (typeof value === 'object' || typeof value === 'function') ? value : null;
  activateHandler(target, type, slot);
}
export function setContentHandler(target, type, compile) {
  target = canonicalTarget(target); const slot = handlerSlot(target, type);
  slot.value = null; slot.content = compile;
  activateHandler(target, type, slot);
}
function pathFor(target, state, legacyTarget) {
  const path = [], root = physicalRoot(target); let node = target, previous = null;
  const related = state.originalRelated;
  if (retarget(related, target) === target && related !== target) return path;
  while (node) {
    const adjusted = retarget(target, node), adjustedRelated = retarget(related, node);
    if (previous !== null && adjusted !== previous && adjustedRelated === node) break;
    const record = targetFor(canonicalTarget(node));
    path[path.length] = { node, exposed: record.exposed, rawTarget: adjusted, rawRelated: adjustedRelated,
      target: legacyTarget && node === target ? exposedTarget(legacyTarget) : exposedTarget(adjusted), related: exposedTarget(adjustedRelated),
      atTarget: node === adjusted, closed: closedAncestors(node), listeners: record };
    previous = adjusted;
    node = eventParent(node, root, state.composed, state.type);
  }
  return path;
}
function invoke(entry, event, capture) {
  const state = eventState(event);
  state.target = entry.target; state.related = entry.related;
  if (state.stopped) return;
  state.current = entry.exposed; state.currentEntry = entry;
  const listeners = [], source = entry.listeners.listeners;
  for (let i = 0; i < source.length; i++) listeners[listeners.length] = source[i];
  for (let i = 0; i < listeners.length; i++) {
    const listener = listeners[i];
    if (listener.removed || listener.type !== state.type || listener.capture !== capture) continue;
    if (listener.once) removeRecord(entry.node, entry.listeners, listener);
    state.passive = listener.passive;
    const previous = hooks.current(event, !!shadowInfo(physicalRoot(entry.node)));
    try {
      runDOMCallback(() => {
        if (typeof listener.callback === 'function') apply(listener.callback, entry.exposed, [event]);
        else apply(listener.callback.handleEvent, listener.callback, [event]);
      });
    } catch (e) { hooks.error('listener:' + state.type, e); }
    finally { state.passive = false; hooks.current(previous, false, true); }
    if (state.immediate) break;
  }
}
export function fireEvent(target, event, trusted = true, legacyTarget = null) {
  target = canonicalTarget(target);
  const state = eventState(event);
  if (state.dispatching || !state.initialized) throw new DOMError('The event is already being dispatched or is uninitialized', 'InvalidStateError');
  setEventTrusted(event, trusted);
  state.dispatching = true;
  let clear = false;
  try {
    const path = pathFor(target, state, legacyTarget);
    state.path = path;
    for (let i = path.length - 1; i >= 0; i--) if (path[i].atTarget) {
      clear = !!shadowInfo(physicalRoot(path[i].rawTarget)) || !!shadowInfo(physicalRoot(path[i].rawRelated)); break;
    }
    for (let i = path.length - 1; i >= 0; i--) { state.phase = path[i].atTarget ? 2 : 1; invoke(path[i], event, true); }
    for (let i = 0; i < path.length; i++) {
      if (!path[i].atTarget && !state.bubbles) continue;
      state.phase = path[i].atTarget ? 2 : 3; invoke(path[i], event, false);
    }
  } finally {
    state.phase = 0; state.current = null; state.currentEntry = null; state.path = [];
    state.dispatching = state.stopped = state.immediate = state.passive = false;
    if (clear) state.target = state.related = null;
    state.originalRelated = state.related;
  }
  return !state.canceled;
}
export class EventTarget {
  constructor() { remember(this, { exposed: this, listeners: [], handlers: new NativeMap(), window: false }); }
  addEventListener(type, callback, options) {
    const target = canonicalTarget(this);
    if (arguments.length < 2) throw new NativeTypeError('addEventListener requires a type and callback');
    const converted = runDOMCallback(() => ({ type: eventString(type), callback: callbackValue(callback), options: optionsValue(options, true) }));
    addListener(target, converted.type, converted.callback, converted.options);
  }
  removeEventListener(type, callback, options) {
    const target = canonicalTarget(this);
    if (arguments.length < 2) throw new NativeTypeError('removeEventListener requires a type and callback');
    const converted = runDOMCallback(() => ({ type: eventString(type), callback: callbackValue(callback), capture: optionsValue(options, false).capture }));
    removeListener(target, converted.type, converted.callback, converted.capture);
  }
  dispatchEvent(event) { return fireEvent(this, event, false); }
  _getParent() { return null; }
}
define(EventTarget.prototype, Symbol.toStringTag, { configurable: true, value: 'EventTarget' });
