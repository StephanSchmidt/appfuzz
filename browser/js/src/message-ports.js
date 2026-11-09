import { platformConstructor } from './constructors.js';
// Port links, queues and transfer holders are platform slots. Posting captures
// data synchronously; only a ready port task deserializes it for the receiver.
import { EventTarget, initializeEventTarget, fireEvent, getHandler, setHandler } from './event-target.js';
import { markPlatform } from './platform-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { installPortTransfers, serializeMessage, transferOptions, transferSequence, cloneFailure } from './structured-clone.js';
import { createMessageEvent, installMessageSourceBrand } from './message-events.js';
const iteratorSymbol = Symbol.iterator;
const NativeTypeError = TypeError, create = Object.create, define = Object.defineProperty, setPrototype = Object.setPrototypeOf;
const ports = new WeakMap(), portFor = ports.get.bind(ports), savePort = ports.set.bind(ports);
const channels = new WeakMap(), channelFor = channels.get.bind(channels), saveChannel = channels.set.bind(channels);
const ready = new Set(), addReady = ready.add.bind(ready), deleteReady = ready.delete.bind(ready), eachReady = ready.forEach.bind(ready);
let enqueueTask = () => {}, callbackCheckpoint = () => {}, scheduled = false, serial = 0;
export function installMessagePortTasks(value, checkpoint) { enqueueTask = value; callbackCheckpoint = checkpoint; }
export const isMessagePort = value => portFor(value) !== undefined;
function requirePort(value) { const state = portFor(value); if (!state) throw new NativeTypeError('A MessagePort is required'); return state; }
function requireChannel(value) { const state = channelFor(value); if (!state) throw new NativeTypeError('A MessageChannel is required'); return state; }
function list() { const value = []; setPrototype(value, null); return value; }
function queue(owner) { return { owner, tasks: list(), index: 0, enabled: false }; }
function firstReady() {
  let result = null;
  eachReady(value => {
    if (value.enabled && value.owner.port && value.index < value.tasks.length && (!result || value.tasks[value.index].order < result.tasks[result.index].order)) result = value;
  });
  return result;
}
function schedule() {
  if (scheduled || !firstReady()) return;
  scheduled = true;
  enqueueTask(() => {
    scheduled = false;
    const value = firstReady(); if (!value) return;
    const task = value.tasks[value.index++];
    if (value.index === value.tasks.length) { value.tasks = list(); value.index = 0; deleteReady(value); }
    const target = value.owner.port;
    let event;
    try { const message = task.deliver(); event = createMessageEvent('message', { data: message.value, ports: message.ports }); }
    catch { event = createMessageEvent('messageerror', { data: null, ports: [] }); }
    fireEvent(target, event, true, null, callbackCheckpoint);
    schedule();
  });
}
function enable(state) {
  state.queue.enabled = true;
  for (let i = state.queue.index; i < state.queue.tasks.length; i++) if (state.queue.tasks[i].order === null) state.queue.tasks[i].order = ++serial;
  if (state.queue.index < state.queue.tasks.length) addReady(state.queue);
  schedule();
}
function append(state, deliver) {
  const value = state.queue;
  value.tasks[value.tasks.length] = { order: value.enabled ? ++serial : null, deliver };
  if (value.enabled && value.owner.port) addReady(value);
  schedule();
}
function disconnect(state) {
  const peer = state.peer; state.peer = null;
  if (peer && peer.peer === state) peer.peer = null;
}
function allocate(value = null) {
  const port = initializeEventTarget(create(portPrototype));
  const state = { port, peer: null, detached: false, queue: null };
  state.queue = value || queue(state); state.queue.owner = state;
  savePort(port, state); markPlatform(port, 'MessagePort'); return port;
}
function take(port) {
  const state = requirePort(port); if (state.detached) cloneFailure();
  const holder = { port: null, peer: state.peer, queue: state.queue };
  if (holder.peer && holder.peer.peer === state) holder.peer.peer = holder;
  state.detached = true; state.peer = null; state.queue = queue(state);
  holder.queue.owner = holder; holder.queue.enabled = false; deleteReady(holder.queue);
  for (let i = holder.queue.index; i < holder.queue.tasks.length; i++) holder.queue.tasks[i].order = null;
  return holder;
}
function receive(holder) {
  const port = allocate(holder.queue), state = requirePort(port);
  state.peer = holder.peer;
  if (state.peer && state.peer.peer === holder) state.peer.peer = state;
  else state.peer = null;
  holder.peer = null; return port;
}
function postingTransfers(options) {
  if (options !== null && (typeof options === 'object' || typeof options === 'function')) {
    const method = options[iteratorSymbol];
    if (method != null) return transferSequence(options, method);
  }
  return transferOptions(options);
}
export let MessagePort = function MessagePort() { throw new NativeTypeError('Illegal MessagePort constructor'); };
const portPrototype = create(EventTarget.prototype);
define(MessagePort, 'name', { value: 'MessagePort', configurable: true });
define(MessagePort, 'prototype', { value: portPrototype, writable: false });
setPrototype(MessagePort, EventTarget);
MessagePort = platformConstructor(MessagePort, 'MessagePort', 0, true);
define(portPrototype, 'constructor', { value: MessagePort, writable: true, configurable: true });
define(portPrototype, Symbol.toStringTag, { value: 'MessagePort', configurable: true });
const methods = {
  postMessage(value, options = undefined) {
    const state = requirePort(this);
    if (!arguments.length) throw new NativeTypeError('postMessage requires a message');
    return runDOMCallback(() => {
      const transfers = postingTransfers(options), target = state.peer;
      let doomed = false;
      for (let i = 0; i < transfers.length; i++) {
        if (transfers[i] === state.port) cloneFailure();
        if (target && transfers[i] === target.port) doomed = true;
      }
      const deliver = serializeMessage(value, transfers);
      // Both browser engines resolve reentrant close/transfer changes after
      // serialization. A getter can disconnect or move the receiving end.
      if (state.peer && !doomed) append(state.peer, deliver);
    });
  },
  start() { enable(requirePort(this)); },
  close() { const state = requirePort(this); state.detached = true; disconnect(state); },
  get onmessage() { requirePort(this); return getHandler(this, 'message'); },
  set onmessage(value) { const state = requirePort(this); setHandler(this, 'message', value); enable(state); },
  get onmessageerror() { requirePort(this); return getHandler(this, 'messageerror'); },
  set onmessageerror(value) { requirePort(this); setHandler(this, 'messageerror', value); },
};
for (const key of ['postMessage', 'start', 'close', 'onmessage', 'onmessageerror']) define(portPrototype, key, Object.getOwnPropertyDescriptor(methods, key));
export let MessageChannel = function MessageChannel() {
  if (!new.target) throw new NativeTypeError('MessageChannel requires new');
  const port1 = allocate(), port2 = allocate(), first = requirePort(port1), second = requirePort(port2);
  first.peer = second; second.peer = first;
  markPlatform(this); saveChannel(this, { port1, port2 });
}
const channelPrototype = create(Object.prototype);
define(MessageChannel, 'name', { value: 'MessageChannel', configurable: true });
define(MessageChannel, 'prototype', { value: channelPrototype, writable: false });
MessageChannel = platformConstructor(MessageChannel, 'MessageChannel');
define(channelPrototype, 'constructor', { value: MessageChannel, writable: true, configurable: true });
define(channelPrototype, Symbol.toStringTag, { value: 'MessageChannel', configurable: true });
const channelFields = { get port1() { return requireChannel(this).port1; }, get port2() { return requireChannel(this).port2; } };
for (const key of ['port1', 'port2']) define(channelPrototype, key, Object.getOwnPropertyDescriptor(channelFields, key));
installPortTransfers({ isPort: isMessagePort, take, receive });
installMessageSourceBrand(isMessagePort);
