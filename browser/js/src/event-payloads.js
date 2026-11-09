// Synthetic drag/clipboard stores and immutable event payloads. Native
// allocation uses captured prototypes and private brands, never public parents.
import { registerEventPayload } from './event-interfaces.js';
import { eventDictionary, eventString } from './event-state.js';
import { nullableTarget } from './event-target.js';
import { nodeInfo } from './dom-state.js';
import { blobRecord } from './blobs.js';
import { lowerASCII } from './names.js';
import { DOMException } from './dom-exception.js';
import { runDOMCallback } from './dom-callbacks.js';
import { markPlatform } from './platform-state.js';
import { indexedObject, indexedValues } from './indexed-list.js';
const NativeTypeError = TypeError, create = Object.create, define = Object.defineProperty;
const setPrototype = Object.setPrototypeOf, apply = Reflect.apply, freeze = Object.freeze, keys = Object.keys;
const iteratorSymbol = Symbol.iterator, tagSymbol = Symbol.toStringTag;
const finite = Number.isFinite, trunc = Math.trunc, fround = Math.fround, parseURL = globalThis.__native.url;
function list() { const result = []; setPrototype(result, null); return result; }
function copy(values) { const result = []; for (let i = 0; i < values.length; i++) define(result, i, { __proto__: null, value: values[i], writable: true, configurable: true, enumerable: true }); return result; }
function uint(value) { const n = +value; return finite(n) && n !== 0 ? ((trunc(n) % 4294967296) + 4294967296) % 4294967296 : 0; }
function signed(value) { const n = uint(value); return n >= 2147483648 ? n - 4294967296 : n; }
function numeric(value, single = false) { const n = single ? fround(+value) : +value; if (!finite(n)) throw new NativeTypeError('A finite number is required'); return n; }
function required(count, expected) { if (count < expected) throw new NativeTypeError('Missing required argument'); }
function identity(C, name, Parent = null) {
  define(C, 'name', { __proto__: null, value: name, configurable: true });
  define(C, 'prototype', { __proto__: null, writable: false });
  define(C.prototype, tagSymbol, { __proto__: null, value: name, configurable: true });
  if (Parent) { setPrototype(C, Parent); setPrototype(C.prototype, Parent.prototype); }
}
function attribute(prototype, key, getter, setter = undefined) {
  define(getter, 'name', { __proto__: null, value: 'get ' + key, configurable: true });
  if (setter) define(setter, 'name', { __proto__: null, value: 'set ' + key, configurable: true });
  define(prototype, key, { __proto__: null, get: getter, set: setter, enumerable: true, configurable: true });
}
function getter(prototype, key, read) { attribute(prototype, key, { get() { return read(this); } }.get); }
function methods(prototype, source) { const names = keys(source); for (let i = 0; i < names.length; i++) define(prototype, names[i], { __proto__: null, value: source[names[i]], writable: true, configurable: true, enumerable: true }); }
function need(read, value, name) { const data = read(value); if (!data) throw new NativeTypeError('A ' + name + ' is required'); return data; }

const ranges = new WeakMap(), rangeFor = ranges.get.bind(ranges), saveRange = ranges.set.bind(ranges);
export function AbstractRange() { throw new NativeTypeError('Illegal constructor'); }
export function NodeRange() { throw new NativeTypeError('Illegal constructor'); }
export function StaticRange(init) {
  if (!new.target) throw new NativeTypeError('StaticRange requires new');
  required(arguments.length, 1);
  const data = runDOMCallback(() => {
    const bag = eventDictionary(init), result = { __proto__: null };
    for (let i = 0; i < rangeKeys.length; i++) {
      const key = rangeKeys[i];
      const value = bag[key]; if (value === undefined) throw new NativeTypeError('Missing range member');
      if (key === 'startContainer' || key === 'endContainer') { if (!nodeInfo(value)) throw new NativeTypeError('A Node is required'); result[key] = value; }
      else result[key] = uint(value);
    }
    if (nodeInfo(result.startContainer).kind === 2 || nodeInfo(result.startContainer).kind === 10 || nodeInfo(result.endContainer).kind === 2 || nodeInfo(result.endContainer).kind === 10) throw new DOMException('Invalid range node', 'InvalidNodeTypeError');
    return result;
  });
  saveRange(this, data); registerEventPayload('range', this);
}
identity(AbstractRange, 'AbstractRange'); identity(NodeRange, 'NodeRange', AbstractRange); identity(StaticRange, 'StaticRange', NodeRange);
const rangeKeys = list(); rangeKeys[0] = 'endContainer'; rangeKeys[1] = 'endOffset'; rangeKeys[2] = 'startContainer'; rangeKeys[3] = 'startOffset';
for (const key of ['startOffset','endOffset']) getter(AbstractRange.prototype, key, value => need(rangeFor, value, 'AbstractRange')[key]);
getter(AbstractRange.prototype, 'collapsed', value => { const d = need(rangeFor, value, 'AbstractRange'); return d.startContainer === d.endContainer && d.startOffset === d.endOffset; });
for (const key of ['startContainer','endContainer']) getter(NodeRange.prototype, key, value => need(rangeFor, value, 'NodeRange')[key]);

const touches = new WeakMap(), touchFor = touches.get.bind(touches), saveTouch = touches.set.bind(touches);
const touchFields = { __proto__: null, altitudeAngle: 'double', azimuthAngle: 'double', clientX: 'double', clientY: 'double', force: 'float', identifier: 'long', pageX: 'double', pageY: 'double', radiusX: 'float', radiusY: 'float', rotationAngle: 'float', screenX: 'double', screenY: 'double', target: 'target', touchType: 'enum' };
const touchKeys = keys(touchFields); touchKeys.sort(); setPrototype(touchKeys, null);
export function Touch(init) {
  if (!new.target) throw new NativeTypeError('Touch requires new');
  required(arguments.length, 1);
  const data = runDOMCallback(() => {
    const bag = eventDictionary(init), result = { __proto__: null };
    for (let i = 0; i < touchKeys.length; i++) {
      const key = touchKeys[i], type = touchFields[key], value = bag[key];
      if (value === undefined) { if (type === 'long' || type === 'target') throw new NativeTypeError('Missing touch member'); result[key] = type === 'enum' ? 'direct' : 0; }
      else if (type === 'target') { result[key] = nullableTarget(value); if (result[key] === null) throw new NativeTypeError('An EventTarget is required'); }
      else if (type === 'long') result[key] = signed(value);
      else if (type === 'enum') { const s = eventString(value); if (s !== 'direct' && s !== 'stylus') throw new NativeTypeError('Invalid touch type'); result[key] = s; }
      else result[key] = numeric(value, type === 'float');
    }
    // The draft's angle getters have float precision, while their dictionary
    // members are double. Coordinates retain the declared double precision.
    result.altitudeAngle = fround(result.altitudeAngle); result.azimuthAngle = fround(result.azimuthAngle);
    return result;
  });
  saveTouch(this, data); registerEventPayload('touch', this);
}
identity(Touch, 'Touch');
for (let i = 0; i < touchKeys.length; i++) { const key = touchKeys[i]; getter(Touch.prototype, key, value => need(touchFor, value, 'Touch')[key]); }

const stores = new WeakMap(), storeFor = stores.get.bind(stores), saveStore = stores.set.bind(stores);
const itemLists = new WeakMap(), itemListFor = itemLists.get.bind(itemLists), saveItemList = itemLists.set.bind(itemLists);
const items = new WeakMap(), itemFor = items.get.bind(items), saveItem = items.set.bind(items);
const files = new WeakMap(), filesFor = files.get.bind(files), saveFiles = files.set.bind(files);
let enqueue = () => { throw new NativeTypeError('Task queue unavailable'); }, callbackError = () => {};
export function installPayloadTasks(queue, report) { enqueue = queue; callbackError = report; }
export function DataTransfer() {
  if (!new.target) throw new NativeTypeError('DataTransfer requires new');
  const data = { __proto__: null, entries: list(), fileEntries: list(), types: freeze([]), dropEffect: 'none', effectAllowed: 'none', image: null, itemList: null, fileList: null };
  data.itemList = indexedObject(itemListPrototype, () => data.entries); saveItemList(data.itemList, data); markPlatform(data.itemList);
  data.fileList = makeFileList(data.fileEntries);
  saveStore(this, data); registerEventPayload('transfer', this);
}
export function DataTransferItemList() { throw new NativeTypeError('Illegal constructor'); }
export function DataTransferItem() { throw new NativeTypeError('Illegal constructor'); }
export function FileList() { throw new NativeTypeError('Illegal constructor'); }
identity(DataTransfer, 'DataTransfer'); identity(DataTransferItemList, 'DataTransferItemList'); identity(DataTransferItem, 'DataTransferItem'); identity(FileList, 'FileList');
const itemListPrototype = DataTransferItemList.prototype, itemPrototype = DataTransferItem.prototype, fileListPrototype = FileList.prototype;
export function makeFileList(entries) { const value = indexedObject(fileListPrototype, () => entries); saveFiles(value, entries); return value; }
export function fileListEntries(value) { return filesFor(value); }
function rebuild(data) {
  const types = list(), fileEntries = data.fileEntries; fileEntries.length = 0;
  for (let i = 0; i < data.entries.length; i++) {
    const entry = itemFor(data.entries[i]);
    if (entry.kind === 'string') types[types.length] = entry.type;
    else fileEntries[fileEntries.length] = entry.value;
  }
  if (fileEntries.length) types[types.length] = 'Files';
  data.types = freeze(copy(types));
}
function append(data, kind, type, value) {
  const item = create(itemPrototype); saveItem(item, { __proto__: null, active: true, kind, type, value }); markPlatform(item);
  data.entries[data.entries.length] = item; return item;
}
function removeAt(data, index) {
  if (index >= data.entries.length) return;
  itemFor(data.entries[index]).active = false;
  for (let i = index + 1; i < data.entries.length; i++) data.entries[i - 1] = data.entries[i];
  data.entries.length--;
}
function find(data, type) { for (let i = 0; i < data.entries.length; i++) { const d = itemFor(data.entries[i]); if (d.kind === 'string' && d.type === type) return i; } return -1; }
function format(value) { const type = lowerASCII(value); return type === 'text' ? 'text/plain' : type === 'url' ? 'text/uri-list' : type; }
function firstURI(value) { let line = ''; for (let i = 0; i <= value.length; i++) { const c = value[i]; if (i === value.length || c === '\r' || c === '\n') { if (line && line[0] !== '#') { const url = parseURL(line, null); if (url) return url[0]; } line = ''; } else line += c; } return ''; }
for (const key of ['dropEffect','effectAllowed']) {
  const values = key === 'dropEffect' ? ['none','copy','link','move'] : ['none','copy','copyLink','copyMove','link','linkMove','move','all','uninitialized']; setPrototype(values, null);
  attribute(DataTransfer.prototype, key, { get() { return need(storeFor, this, 'DataTransfer')[key]; } }.get, { set(value) {
    const data = need(storeFor, this, 'DataTransfer'), s = runDOMCallback(() => eventString(value));
    for (let i = 0; i < values.length; i++) if (s === values[i]) { data[key] = s; break; }
  } }.set);
}
for (const key of ['items','files','types']) getter(DataTransfer.prototype, key, value => { const data = need(storeFor, value, 'DataTransfer'); return key === 'items' ? data.itemList : key === 'files' ? data.fileList : data.types; });
methods(DataTransfer.prototype, {
  getData(type) { const data = need(storeFor, this, 'DataTransfer'); required(arguments.length, 1); type = runDOMCallback(() => eventString(type)); const i = find(data, format(type)); if (i < 0) return ''; const value = itemFor(data.entries[i]).value; return lowerASCII(type) === 'url' ? firstURI(value) : value; },
  setData(type, value) { const data = need(storeFor, this, 'DataTransfer'); required(arguments.length, 2); const converted = runDOMCallback(() => ({ __proto__: null, type: format(eventString(type)), value: eventString(value) })); const i = find(data, converted.type); if (i >= 0) removeAt(data, i); append(data, 'string', converted.type, converted.value); rebuild(data); },
  clearData(type = undefined) { const data = need(storeFor, this, 'DataTransfer'), all = type === undefined; type = all ? '' : runDOMCallback(() => format(eventString(type))); for (let i = data.entries.length - 1; i >= 0; i--) { const entry = itemFor(data.entries[i]); if (entry.kind === 'string' && (all || entry.type === type)) removeAt(data, i); } rebuild(data); },
  setDragImage(image, x, y) { const data = need(storeFor, this, 'DataTransfer'); required(arguments.length, 3); const converted = runDOMCallback(() => { if (nodeInfo(image)?.kind !== 1) throw new NativeTypeError('An Element is required'); return { __proto__: null, image, x: signed(x), y: signed(y) }; }); data.image = converted; },
});
getter(itemListPrototype, 'length', value => need(itemListFor, value, 'DataTransferItemList').entries.length);
methods(itemListPrototype, {
  add(value, type = undefined) {
    const data = need(itemListFor, this, 'DataTransferItemList'); required(arguments.length, 1);
    const argc = arguments.length, converted = runDOMCallback(() => {
      if (argc === 1) { const record = blobRecord(value); if (!record || record.name === undefined) throw new NativeTypeError('A File is required'); return { __proto__: null, kind: 'file', type: record.type, value }; }
      return { __proto__: null, kind: 'string', value: eventString(value), type: lowerASCII(eventString(type)) };
    });
    if (converted.kind === 'string' && find(data, converted.type) >= 0) throw new DOMException('Duplicate string type', 'NotSupportedError');
    const item = append(data, converted.kind, converted.type, converted.value); rebuild(data); return item;
  },
  remove(index) { const data = need(itemListFor, this, 'DataTransferItemList'); required(arguments.length, 1); index = runDOMCallback(() => uint(index)); removeAt(data, index); rebuild(data); },
  clear() { const data = need(itemListFor, this, 'DataTransferItemList'); for (let i = 0; i < data.entries.length; i++) itemFor(data.entries[i]).active = false; data.entries.length = 0; rebuild(data); },
});
for (const key of ['kind','type']) getter(itemPrototype, key, value => { const item = need(itemFor, value, 'DataTransferItem'); return item.active ? item[key] : ''; });
methods(itemPrototype, {
  getAsFile() { const item = need(itemFor, this, 'DataTransferItem'); return item.active && item.kind === 'file' ? item.value : null; },
  getAsString(callback) {
    const item = need(itemFor, this, 'DataTransferItem'); required(arguments.length, 1);
    if (callback != null && typeof callback !== 'function') throw new NativeTypeError('A callback is required');
    if (callback == null || !item.active || item.kind !== 'string') return;
    const value = item.value;
    enqueue(() => { try { runDOMCallback(() => apply(callback, undefined, [value])); } catch (error) { callbackError(error); } });
  },
});
getter(fileListPrototype, 'length', value => need(filesFor, value, 'FileList').length);
methods(fileListPrototype, { item(index) { const entries = need(filesFor, this, 'FileList'); required(arguments.length, 1); index = runDOMCallback(() => uint(index)); return index < entries.length ? entries[index] : null; } });
for (const prototype of [itemListPrototype,fileListPrototype]) define(prototype, iteratorSymbol, { __proto__: null, value: indexedValues, writable: true, configurable: true });
// FileList is serializable, unlike the drag store and item wrappers. Its
// children use the surrounding clone operation's memory map (File API/HTML).
export function serializeFileList(value) {
  const entries = filesFor(value); if (!entries) return null;
  const result = list(), target = makeFileList(result), snapshot = list();
  for (let i = 0; i < entries.length; i++) snapshot[snapshot.length] = entries[i];
  return { __proto__: null, value: target, children: snapshot, receive(children) { for (let i = 0; i < children.length; i++) result[result.length] = children[i].value; } };
}
