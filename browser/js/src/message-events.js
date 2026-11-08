// Native message data is private. Public constructors perform Web IDL
// conversion; queued delivery initializes the same slots without callbacks.
import { Event, eventState, eventString, eventDictionary, initializeEvent, resetEvent } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const iteratorSymbol = Symbol.iterator;
const realm = globalThis, NativeTypeError = TypeError, apply = Reflect.apply, create = Object.create, define = Object.defineProperty, freeze = Object.freeze;
const states = new WeakMap(), save = states.set.bind(states), read = states.get.bind(states);
let isPort = () => false;
export function installMessageSourceBrand(value) { isPort = value; }
function requireMessage(value) { const state = read(value); if (!state) throw new NativeTypeError('A MessageEvent is required'); return state; }
function sourceValue(value) {
  if (value == null) return null;
  if (value === realm || isPort(value)) return value;
  throw new NativeTypeError('Message source must be a Window or MessagePort');
}
function append(list, value) { define(list, list.length, { __proto__: null, value, writable: true, enumerable: true, configurable: true }); }
function frozenPorts(sequence) {
  if (sequence == null || (typeof sequence !== 'object' && typeof sequence !== 'function')) throw new NativeTypeError('Ports must be an iterable object');
  const method = sequence[iteratorSymbol];
  if (typeof method !== 'function') throw new NativeTypeError('Ports must be iterable');
  const iterator = apply(method, sequence, []);
  if (iterator === null || (typeof iterator !== 'object' && typeof iterator !== 'function')) throw new NativeTypeError('Invalid port iterator');
  const next = iterator.next, result = [];
  while (true) {
    const step = apply(next, iterator, []);
    if (step === null || (typeof step !== 'object' && typeof step !== 'function')) throw new NativeTypeError('Invalid iterator result');
    if (step.done) return freeze(result);
    const value = step.value;
    if (!isPort(value)) throw new NativeTypeError('A MessagePort is required');
    append(result, value);
  }
}
export function MessageEvent(type, options = undefined) {
  if (!new.target) throw new NativeTypeError('MessageEvent requires new');
  if (!arguments.length) throw new NativeTypeError('MessageEvent requires a type');
  const converted = runDOMCallback(() => {
    type = eventString(type);
    const init = eventDictionary(options), bubbles = !!init.bubbles, cancelable = !!init.cancelable, composed = !!init.composed;
    const input = init.data, last = init.lastEventId;
    const lastEventId = last === undefined ? '' : eventString(last);
    const originInput = init.origin, origin = originInput === undefined ? '' : eventString(originInput);
    const portsInput = init.ports, ports = portsInput === undefined ? freeze([]) : frozenPorts(portsInput);
    const source = sourceValue(init.source);
    return { type, bubbles, cancelable, composed, data: input === undefined ? null : input,
      lastEventId, origin, ports, source };
  });
  initializeEvent(this, converted.type, converted.bubbles, converted.cancelable, converted.composed);
  save(this, converted);
}
const prototype = create(Event.prototype);
define(MessageEvent, 'name', { value: 'MessageEvent', configurable: true });
define(MessageEvent, 'prototype', { value: prototype, writable: false });
Object.setPrototypeOf(MessageEvent, Event);
define(prototype, 'constructor', { value: MessageEvent, writable: true, configurable: true });
define(prototype, Symbol.toStringTag, { value: 'MessageEvent', configurable: true });
const fields = {
  get data() { return requireMessage(this).data; }, get origin() { return requireMessage(this).origin; },
  get lastEventId() { return requireMessage(this).lastEventId; }, get source() { return requireMessage(this).source; },
  get ports() { return requireMessage(this).ports; },
  initMessageEvent(type, bubbles = false, cancelable = false, data = null, origin = '', lastEventId = '', source = null, ports = []) {
    const state = eventState(this); requireMessage(this);
    if (!arguments.length) throw new NativeTypeError('initMessageEvent requires a type');
    const converted = runDOMCallback(() => ({ type: eventString(type), bubbles: !!bubbles, cancelable: !!cancelable,
      data, origin: eventString(origin), lastEventId: eventString(lastEventId), source: sourceValue(source), ports: frozenPorts(ports) }));
    if (state.dispatching) return;
    resetEvent(state, converted.type, converted.bubbles, converted.cancelable); save(this, converted);
  },
};
for (const key of ['data', 'origin', 'lastEventId', 'source', 'ports', 'initMessageEvent']) define(prototype, key, Object.getOwnPropertyDescriptor(fields, key));
export function createMessageEvent(type, value, origin = '', source = null) {
  const event = create(prototype), ports = [];
  for (let i = 0; i < value.ports.length; i++) append(ports, value.ports[i]);
  initializeEvent(event, type);
  save(event, { data: value.data, origin, lastEventId: '', source, ports: freeze(ports) });
  return event;
}
