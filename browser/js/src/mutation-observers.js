// Observations and pending deliveries belong to the agent, independently of
// page expandos and the target's current document. Only explicit dictionaries
// and callbacks are author code; all mutation bookkeeping uses private state.
import { platformConstructor } from './constructors.js';
import { markPlatform } from './platform-state.js';
import { nodeInfo, physicalParent, physicalPreviousSibling, physicalNextSibling } from './dom-state.js';
import { backendList } from './collection-data.js';
import { staticNodeList } from './collections.js';
import { runDOMCallback } from './dom-callbacks.js';
import { eventString } from './event-state.js';
const enqueue = globalThis.__native.queueMicrotask, create = Object.create, define = Object.defineProperty, apply = Reflect.apply;
const NativeTypeError = TypeError, NativeWeakRef = WeakRef;
const deref = Function.prototype.call.bind(WeakRef.prototype.deref);
const observers = new WeakMap(), read = observers.get.bind(observers), save = observers.set.bind(observers);
const records = new WeakMap(), readRecord = records.get.bind(records), saveRecord = records.set.bind(records);
const registrations = new WeakMap(), readRegistrations = registrations.get.bind(registrations), saveRegistrations = registrations.set.bind(registrations);
const queued = new WeakSet(), isQueued = queued.has.bind(queued), markQueued = queued.add.bind(queued), clearQueued = queued.delete.bind(queued);
let pending = backendList(), scheduled = false, serial = 0, report = () => {};
export function installMutationObserverReporter(callback) { report = callback; }
function requireObserver(observer) { const data = read(observer); if (!data) throw new NativeTypeError('A MutationObserver is required'); return data; }
function requireNode(node) { if (!nodeInfo(node)) throw new NativeTypeError('A Node is required'); }
function nodeRegistrations(node) { let list = readRegistrations(node); if (!list) { list = backendList(); saveRegistrations(node, list); } return list; }
function publicArray(list) { const result = []; for (let i = 0; i < list.length; i++) define(result, i, { __proto__: null, value: list[i], writable: true, enumerable: true, configurable: true }); return result; }
function pendingObserver(observer) {
  if (!isQueued(observer)) { markQueued(observer); pending[pending.length] = observer; }
  if (!scheduled) { scheduled = true; enqueue(notify); }
}
function removeTransient(data, source = null) {
  const keep = backendList();
  for (let i = 0; i < data.transients.length; i++) {
    const entry = data.transients[i];
    if (source && entry.registration.source !== source) { keep[keep.length] = entry; continue; }
    const node = deref(entry.node); if (!node) continue;
    const list = nodeRegistrations(node), next = backendList();
    for (let j = 0; j < list.length; j++) if (list[j] !== entry.registration) next[next.length] = list[j];
    saveRegistrations(node, next);
  }
  data.transients = keep;
}
function notify() {
  scheduled = false; const list = pending; pending = backendList();
  list.sort((a,b) => read(a).index - read(b).index);
  for (let i = 0; i < list.length; i++) clearQueued(list[i]);
  for (let i = 0; i < list.length; i++) {
    const observer = list[i], data = read(observer), delivered = data.queue; data.queue = backendList(); removeTransient(data);
    if (delivered.length) try { runDOMCallback(() => apply(data.callback, observer, [publicArray(delivered), observer])); } catch (error) { report(error); }
  }
}
function dictionary(value) {
  if (value == null) value = { __proto__: null };
  if (typeof value !== 'object' && typeof value !== 'function') throw new NativeTypeError('Observer options must be a dictionary');
  // Web IDL dictionary members are read and converted in lexical order.
  const filterValue = value.attributeFilter; let filter = null;
  if (filterValue !== undefined) { if (filterValue === null || typeof filterValue !== 'object' && typeof filterValue !== 'function') throw new NativeTypeError('attributeFilter must be a sequence'); filter = backendList(); for (const name of filterValue) filter[filter.length] = eventString(name); }
  const attributeOld = value.attributeOldValue, attributes = value.attributes, characters = value.characterData, characterOld = value.characterDataOldValue, children = value.childList, subtree = value.subtree;
  const options = { __proto__: null, filter, attributeOld: !!attributeOld, attributes: attributes === undefined ? attributeOld !== undefined || filter !== null : !!attributes, characters: characters === undefined ? characterOld !== undefined : !!characters, characterOld: !!characterOld, children: !!children, subtree: !!subtree };
  if (!options.attributes && !options.characters && !options.children || !options.attributes && (options.attributeOld || filter !== null) || !options.characters && options.characterOld) throw new NativeTypeError('Invalid observer options');
  return options;
}
export let MutationObserver = class MutationObserver {
  constructor(callback) { if (typeof callback !== 'function') throw new NativeTypeError('A callback is required'); markPlatform(this); save(this, { __proto__: null, callback, index: serial++, nodes: backendList(), transients: backendList(), queue: backendList() }); }
  observe(target, options = undefined) {
    const data = requireObserver(this); if (!arguments.length) throw new NativeTypeError('A target is required'); requireNode(target);
    const converted = runDOMCallback(() => dictionary(options)), list = nodeRegistrations(target); let existing = null;
    for (let i = 0; i < list.length; i++) if (list[i].observer === this && !list[i].source) { existing = list[i]; break; }
    if (existing) { removeTransient(data, existing); existing.options = converted; }
    else { list[list.length] = { __proto__: null, observer: this, options: converted, source: null }; data.nodes[data.nodes.length] = new NativeWeakRef(target); }
  }
  disconnect() {
    const data = requireObserver(this);
    for (let i = 0; i < data.nodes.length; i++) { const node = deref(data.nodes[i]); if (!node) continue; const list = nodeRegistrations(node), next = backendList(); for (let j = 0; j < list.length; j++) if (list[j].observer !== this) next[next.length] = list[j]; saveRegistrations(node, next); }
    data.nodes = backendList(); data.queue = backendList(); removeTransient(data);
  }
  takeRecords() { const data = requireObserver(this), list = data.queue; data.queue = backendList(); return publicArray(list); }
};
MutationObserver = platformConstructor(MutationObserver, 'MutationObserver', 1);
export let MutationRecord = class MutationRecord { constructor() { throw new NativeTypeError('Illegal constructor'); } };
MutationRecord = platformConstructor(MutationRecord, 'MutationRecord', 0, true);
const recordPrototype = MutationRecord.prototype;
for (const key of ['type','target','addedNodes','removedNodes','previousSibling','nextSibling','attributeName','attributeNamespace','oldValue']) { const get = function () { const data = readRecord(this); if (!data) throw new NativeTypeError('A MutationRecord is required'); return data[key]; }; define(get,'name',{ __proto__: null, value: 'get ' + key, configurable: true }); define(recordPrototype,key,{ __proto__: null, configurable: true, enumerable: true, get }); }
for (const [type,name] of [[MutationObserver,'MutationObserver'],[MutationRecord,'MutationRecord']]) define(type.prototype, Symbol.toStringTag, { __proto__: null, value: name, configurable: true });
function record(type, target, name, namespace, oldValue, added, removed, previous, next) {
  const result = create(recordPrototype); markPlatform(result); saveRecord(result, { __proto__: null, type, target, attributeName: name, attributeNamespace: namespace, oldValue, addedNodes: staticNodeList(added), removedNodes: staticNodeList(removed), previousSibling: previous, nextSibling: next }); return result;
}
function queue(type, target, name = null, namespace = null, oldValue = null, added = backendList(), removed = backendList(), previous = null, next = null) {
  const interested = backendList();
  for (let node = target; node; node = physicalParent(node)) {
    const list = readRegistrations(node); if (!list) continue;
    for (let i = 0; i < list.length; i++) {
      const registration = list[i], options = registration.options;
      if (node !== target && !options.subtree || type === 'attributes' && !options.attributes || type === 'characterData' && !options.characters || type === 'childList' && !options.children) continue;
      if (type === 'attributes' && options.filter !== null) { let found = false; if (namespace === null) for (let j = 0; j < options.filter.length; j++) if (options.filter[j] === name) found = true; if (!found) continue; }
      let entry = null; for (let j = 0; j < interested.length; j++) if (interested[j].observer === registration.observer) { entry = interested[j]; break; }
      if (!entry) { entry = { __proto__: null, observer: registration.observer, old: null }; interested[interested.length] = entry; }
      if (type === 'attributes' && options.attributeOld || type === 'characterData' && options.characterOld) entry.old = oldValue;
    }
  }
  for (let i = 0; i < interested.length; i++) { const item = interested[i], data = read(item.observer); data.queue[data.queue.length] = record(type,target,name,namespace,item.old,added,removed,previous,next); pendingObserver(item.observer); }
}
export function retainRemovedSubtree(node, parent) {
  for (let ancestor = parent; ancestor; ancestor = physicalParent(ancestor)) {
    const list = readRegistrations(ancestor); if (!list) continue;
    for (let i = 0; i < list.length; i++) {
      const registration = list[i]; if (!registration.options.subtree) continue;
      const source = registration.source || registration, current = nodeRegistrations(node); let exists = false;
      for (let j = 0; j < current.length; j++) if (current[j].source === source) exists = true;
      if (exists) continue;
      const transient = { __proto__: null, observer: registration.observer, options: source.options, source }; current[current.length] = transient;
      const data = read(transient.observer); data.transients[data.transients.length] = { __proto__: null, node: new NativeWeakRef(node), registration: transient }; pendingObserver(transient.observer);
    }
  }
}
export function attributeMutation(target, name, oldValue, namespace = null) { queue('attributes', target, name, namespace, oldValue); }
export function characterMutation(target, oldValue) { queue('characterData', target, null, null, oldValue); }
export function childMutation(target, added, removed, previous, next) { queue('childList', target, null, null, null, added, removed, previous, next); }
export function legacyChildMutation(element, parent, previous, next) {
  if (parent) { retainRemovedSubtree(element, parent); childMutation(parent, backendList(), [element], previous ?? null, next ?? null); }
  else { const target = physicalParent(element); if (target) childMutation(target, [element], backendList(), physicalPreviousSibling(element), physicalNextSibling(element)); }
}
// Linkedom's document facade asks for this constructor; observations themselves
// are agent state and require no document-owned public registries.
export class MutationObserverClass { constructor() { this.class = MutationObserver; } }
