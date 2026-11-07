// The DOM algorithms use these slots, never public property shadows.
import { runDOMCallback } from './dom-callbacks.js';
const states = new WeakMap();
const save = states.set.bind(states), get = states.get.bind(states);
const NativeTypeError = TypeError, string = String, define = Object.defineProperty;
let clock = () => 0;
export function setEventClock(read) { clock = read; }
export function eventState(event) {
  const result = get(event);
  if (!result) throw new NativeTypeError('An Event is required');
  return result;
}
export function assertEvent(event) { eventState(event); }
export function eventCancelable(event) { return eventState(event).cancelable; }
export function eventCanceled(event) { return eventState(event).canceled; }
export function eventTimeStamp(event) { return eventState(event).timeStamp; }
export function eventType(event) { return eventState(event).type; }
export function eventTrusted(event) { return eventState(event).trusted; }
export function setEventTrusted(event, trusted) { eventState(event).trusted = trusted; return event; }
export function setRelatedTarget(event, related) { const s = eventState(event); s.related = s.originalRelated = related; }
export function relatedTarget(event) { return eventState(event).related; }
export function cancelEvent(event) {
  const record = eventState(event);
  if (record.cancelable && !record.passive) record.canceled = true;
}
export function eventString(value) {
  if (typeof value === 'symbol') throw new NativeTypeError('A Symbol cannot be converted to a DOMString');
  return string(value);
}
export function eventDictionary(value) {
  if (value == null) return {};
  if (typeof value !== 'object' && typeof value !== 'function') throw new NativeTypeError('Event options must be a dictionary');
  return value;
}
function reset(s, type, bubbles, cancelable) {
  s.initialized = true; s.type = type; s.bubbles = bubbles; s.cancelable = cancelable;
  s.stopped = s.immediate = s.canceled = s.trusted = false; s.target = null;
}
export function markEventUninitialized(event) { eventState(event).initialized = false; }
export class Event {
  constructor(type, options = {}) {
    if (!arguments.length) throw new NativeTypeError('Event requires a type');
    const init = runDOMCallback(() => {
      type = eventString(type);
      const dictionary = eventDictionary(options);
      return { bubbles: !!dictionary.bubbles, cancelable: !!dictionary.cancelable, composed: !!dictionary.composed };
    });
    save(this, { type, ...init, initialized: true, canceled: false, timeStamp: clock(), trusted: false,
      stopped: false, immediate: false, passive: false, dispatching: false,
      target: null, current: null, phase: 0, path: [], currentEntry: null, related: null, originalRelated: null });
    define(this, 'isTrusted', { enumerable: true, get() { return eventState(this).trusted; } });
  }
  get type() { return eventState(this).type; }
  get target() { return eventState(this).target; }
  get srcElement() { return eventState(this).target; }
  get currentTarget() { return eventState(this).current; }
  get eventPhase() { return eventState(this).phase; }
  get bubbles() { return eventState(this).bubbles; }
  get composed() { return eventState(this).composed; }
  get timeStamp() { return eventTimeStamp(this); }
  get cancelable() { return eventCancelable(this); }
  get defaultPrevented() { return eventCanceled(this); }
  get returnValue() { return !eventCanceled(this); }
  set returnValue(value) { if (!value) cancelEvent(this); }
  get cancelBubble() { return eventState(this).stopped; }
  set cancelBubble(value) { if (value) eventState(this).stopped = true; else assertEvent(this); }
  preventDefault() { cancelEvent(this); }
  stopPropagation() { eventState(this).stopped = true; }
  stopImmediatePropagation() { const s = eventState(this); s.stopped = s.immediate = true; }
  composedPath() {
    const s = eventState(this), result = [], visible = s.currentEntry?.closed || [];
    for (let i = 0; i < s.path.length; i++) {
      const entry = s.path[i]; let hidden = false;
      for (let j = 0; j < entry.closed.length; j++) {
        let found = false;
        for (let k = 0; k < visible.length; k++) if (visible[k] === entry.closed[j]) found = true;
        if (!found) { hidden = true; break; }
      }
      if (!hidden) result[result.length] = entry.exposed;
    }
    return result;
  }
  initEvent(type, bubbles = false, cancelable = false) {
    const s = eventState(this);
    if (!arguments.length) throw new NativeTypeError('initEvent requires a type');
    type = runDOMCallback(() => eventString(type));
    if (!s.dispatching) reset(s, type, !!bubbles, !!cancelable);
  }
  static get NONE() { return 0; }
  static get CAPTURING_PHASE() { return 1; }
  static get AT_TARGET() { return 2; }
  static get BUBBLING_PHASE() { return 3; }
  get NONE() { return 0; }
  get CAPTURING_PHASE() { return 1; }
  get AT_TARGET() { return 2; }
  get BUBBLING_PHASE() { return 3; }
}
export class CustomEvent extends Event {
  constructor(type, options = {}) {
    if (!arguments.length) throw new NativeTypeError('CustomEvent requires a type');
    super(type, options);
    const value = runDOMCallback(() => eventDictionary(options).detail);
    eventState(this).detail = value === undefined ? null : value;
  }
  get detail() { return eventState(this).detail; }
  initCustomEvent(type, bubbles = false, cancelable = false, detail = null) {
    const s = eventState(this);
    if (!arguments.length) throw new NativeTypeError('initCustomEvent requires a type');
    type = runDOMCallback(() => eventString(type));
    if (!s.dispatching) { reset(s, type, !!bubbles, !!cancelable); s.detail = detail; }
  }
}
define(Event.prototype, Symbol.toStringTag, { configurable: true, value: 'Event' });
define(CustomEvent.prototype, Symbol.toStringTag, { configurable: true, value: 'CustomEvent' });
