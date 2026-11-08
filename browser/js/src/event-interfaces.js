// Web IDL conversion and private slots shared by public constructors and
// user-agent event creation. Constructor inheritance is ordinary public data;
// it never selects the native initializer.
import { Event, eventState, eventString, eventDictionary, initializeEvent, setRelatedTarget } from './event-state.js';
import { nullableTarget, nullableWindow } from './event-target.js';
import { nodeInfo, retarget } from './dom-state.js';
import { nameIdentity } from './names.js';
import { markPlatform } from './platform-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const NativeTypeError = TypeError, create = Object.create, define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor;
const setPrototype = Object.setPrototypeOf, ownKeys = Reflect.ownKeys, apply = Reflect.apply;
const finite = Number.isFinite, trunc = Math.trunc, floor = Math.floor, fround = Math.fround, max = Math.max, min = Math.min;
const abs = Math.abs, round = Math.round, tan = Math.tan, atan = Math.atan, atan2 = Math.atan2, sqrt = Math.sqrt, cos = Math.cos, sin = Math.sin, PI = Math.PI;
const arrayIterator = Array.prototype[Symbol.iterator];
const slots = new WeakMap(), read = slots.get.bind(slots), save = slots.set.bind(slots);
const types = new WeakMap(), typeFor = types.get.bind(types), saveType = types.set.bind(types);
const storage = new WeakSet(), isStorage = storage.has.bind(storage), saveStorage = storage.add.bind(storage);
const iteratorSymbol = Symbol.iterator;
const own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
export function registerStorageArea(value) { saveStorage(value); return value; }
const transfers = new WeakSet(), ranges = new WeakSet(), touches = new WeakSet();
const hasTransfer = transfers.has.bind(transfers), hasRange = ranges.has.bind(ranges), hasTouch = touches.has.bind(touches);
const addTransfer = transfers.add.bind(transfers), addRange = ranges.add.bind(ranges), addTouch = touches.add.bind(touches);
// These producer hooks remain internal to the bundle. The current realm has
// no DataTransfer, StaticRange or Touch producers; its null/empty payloads are
// valid, while object lookalikes fail interface conversion.
export function registerEventPayload(type, value) { if (type === 'transfer') addTransfer(value); else if (type === 'range') addRange(value); else if (type === 'touch') addTouch(value); else throw new NativeTypeError('Unknown event payload'); markPlatform(value); return value; }

function list() { const result = []; setPrototype(result, null); return result; }
function copy(sequence) { const result = []; for (let i = 0; i < sequence.length; i++) define(result, i, { __proto__: null, value: sequence[i], writable: true, configurable: true, enumerable: true }); return result; }
function requireData(value, spec) {
  const data = read(value); let actual = data?.spec;
  while (actual && actual !== spec) actual = actual.parent;
  if (!actual) throw new NativeTypeError('An ' + spec.name + ' is required');
  return data.values;
}
function integer(value, bits, signed) {
  let number = +value;
  if (!finite(number) || number === 0) return 0;
  const bound = bits === 16 ? 65536 : 4294967296;
  number = ((trunc(number) % bound) + bound) % bound;
  return signed && number >= bound / 2 ? number - bound : number;
}
function number(value, single = false) {
  let result = +value;
  if (single) result = fround(result);
  if (!finite(result)) throw new NativeTypeError('A finite number is required');
  return result;
}
function element(value, html = false) {
  if (value == null) return null;
  if (nodeInfo(value)?.kind !== 1 || (html && nameIdentity(value)?.namespace !== 'http://www.w3.org/1999/xhtml')) throw new NativeTypeError('An Element is required');
  return value;
}
function sequence(value, convert) {
  if (value == null || (typeof value !== 'object' && typeof value !== 'function')) throw new NativeTypeError('A sequence is required');
  const method = value[iteratorSymbol];
  if (typeof method !== 'function') throw new NativeTypeError('A sequence is required');
  const iterator = apply(method, value, []);
  if (iterator == null || (typeof iterator !== 'object' && typeof iterator !== 'function')) throw new NativeTypeError('An iterator is required');
  const next = iterator.next, result = list();
  while (true) {
    const step = apply(next, iterator, []);
    if (step == null || (typeof step !== 'object' && typeof step !== 'function')) throw new NativeTypeError('An iterator result is required');
    if (step.done) return result;
    result[result.length] = convert(step.value);
  }
}
const modifiers = {
  altKey: 'bool', ctrlKey: 'bool', metaKey: 'bool', modifierAltGraph: 'bool', modifierCapsLock: 'bool', modifierFn: 'bool',
  modifierNumLock: 'bool', modifierScrollLock: 'bool', modifierSymbol: 'bool', shiftKey: 'bool',
};
function convert(value, type) {
  switch (type) {
    case 'any': return value;
    case 'bool': return !!value;
    case 'long': return integer(value, 32, true);
    case 'ulong': return integer(value, 32, false);
    case 'short': return integer(value, 16, true);
    case 'ushort': return integer(value, 16, false);
    case 'double': return number(value);
    case 'float': return number(value, true);
    case 'string': return eventString(value);
    case 'usv': return wellFormed(eventString(value));
    case 'nullable-string': return value == null ? null : eventString(value);
    case 'target': return nullableTarget(value);
    case 'window': return nullableWindow(value);
    case 'element': return element(value);
    case 'html': return element(value, true);
    case 'required-object': if (value === null || (typeof value !== 'object' && typeof value !== 'function')) throw new NativeTypeError('An object is required'); return value;
    case 'storage': if (value == null) return null; if (!isStorage(value)) throw new NativeTypeError('A Storage is required'); return value;
    case 'transfer': if (value == null) return null; if (!hasTransfer(value)) throw new NativeTypeError('A DataTransfer is required'); return value;
    case 'ranges': return sequence(value, item => { if (!hasRange(item)) throw new NativeTypeError('A StaticRange is required'); return item; });
    case 'touches': return sequence(value, item => { if (!hasTouch(item)) throw new NativeTypeError('A Touch is required'); return item; });
    case 'pointers': return sequence(value, event => { requireData(event, pointerSpec); return event; });
  }
  throw new NativeTypeError('Unknown event member');
}
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
function fallback(type) { return type === 'bool' ? false : type === 'string' || type === 'usv' ? '' : type === 'any' || type === 'nullable-string' || type === 'target' || type === 'window' || type === 'element' || type === 'html' || type === 'transfer' || type === 'storage' ? null : type === 'ranges' || type === 'touches' || type === 'pointers' ? list() : 0; }
function fields(spec, dictionary, values, provided, native = false) {
  if (spec.parent) fields(spec.parent, dictionary, values, provided, native);
  for (let i = 0; i < spec.members.length; i++) {
    const key = spec.members[i], rule = spec.fields[key], type = typeof rule === 'string' ? rule : rule[0], value = dictionary[key];
    provided[key] = value !== undefined;
    if (value === undefined && type === 'required-object') throw new NativeTypeError('A promise is required');
    values[key] = value === undefined ? typeof rule === 'string' ? fallback(type) : rule[1] : native ? value : convert(value, type);
  }
}
function argumentsFor(spec, type, options, native = false) {
  if (!native) type = eventString(type);
  const dictionary = eventDictionary(options), values = { __proto__: null }, provided = { __proto__: null };
  values.bubbles = !!dictionary.bubbles; values.cancelable = !!dictionary.cancelable; values.composed = !!dictionary.composed;
  fields(spec, dictionary, values, provided, native); return { type, values, provided };
}
function initialize(event, spec, data) {
  const values = data.values;
  initializeEvent(event, data.type, values.bubbles, values.cancelable, values.composed);
  save(event, { spec, values });
  let parent = spec;
  while (parent) { if (parent.name === 'MouseEvent') eventState(event).mouse = true; parent = parent.parent; }
  if (spec.related) setRelatedTarget(event, values.relatedTarget);
  if (spec === pointerSpec) {
    const supplied = data.provided;
    values.tiltX = max(-90, min(90, values.tiltX)); values.tiltY = max(-90, min(90, values.tiltY));
    if (!supplied.altitudeAngle && !supplied.azimuthAngle) {
      const x = values.tiltX, y = values.tiltY, xr = x * PI / 180, yr = y * PI / 180;
      values.azimuthAngle = x === 0 ? y > 0 ? PI / 2 : y < 0 ? 3 * PI / 2 : 0 : y === 0 ? x < 0 ? PI : 0 : abs(x) === 90 || abs(y) === 90 ? 0 : atan2(tan(yr), tan(xr));
      if (values.azimuthAngle < 0) values.azimuthAngle += 2 * PI;
      values.altitudeAngle = abs(x) === 90 || abs(y) === 90 ? 0 : x === 0 ? PI / 2 - abs(yr) : y === 0 ? PI / 2 - abs(xr) : atan(1 / sqrt(tan(xr) ** 2 + tan(yr) ** 2));
    }
    if (!supplied.tiltX && !supplied.tiltY) {
      const a = values.altitudeAngle, z = values.azimuthAngle;
      if (a === 0) {
        values.tiltX = z === PI / 2 || z === 3 * PI / 2 ? 0 : z > PI / 2 && z < 3 * PI / 2 ? -90 : 90;
        values.tiltY = z === 0 || z === PI || z === 2 * PI ? 0 : z < PI ? 90 : -90;
      } else { values.tiltX = round(atan(cos(z) / tan(a)) * 180 / PI); values.tiltY = round(atan(sin(z) / tan(a)) * 180 / PI); }
    }
  }
}
function attribute(spec, key, readValue) {
  const getter = { get() { const values = requireData(this, spec); return readValue ? readValue(this, values) : values[key]; } }.get;
  define(getter, 'name', { __proto__: null, value: 'get ' + key, configurable: true });
  define(spec.prototype, key, { __proto__: null, enumerable: true, configurable: true, get: getter });
}
function nativeMethod(key, fn) {
  // A method definition has no [[Construct]] or public prototype object.
  const method = { [key](...args) { return apply(fn, this, args); } }[key];
  define(method, 'length', { __proto__: null, value: fn.length, configurable: true }); return method;
}
function operation(spec, key, fn) { define(spec.prototype, key, { __proto__: null, value: nativeMethod(key, fn), writable: true, configurable: true, enumerable: true }); }
function interfaceType(name, Parent, fieldTypes = { __proto__: null }) {
  const parent = typeFor(Parent), keys = Object.keys(fieldTypes); keys.sort(); setPrototype(keys, null);
  const spec = { name, parent, fields: fieldTypes, members: keys, prototype: create(Parent.prototype), related: name === 'FocusEvent' || name === 'MouseEvent' || !!parent?.related };
  function Interface(type, options = undefined) {
    if (!new.target) throw new NativeTypeError(name + ' requires new');
    if (!arguments.length) throw new NativeTypeError(name + ' requires a type');
    const data = runDOMCallback(() => argumentsFor(spec, type, options)); initialize(this, spec, data);
  }
  define(Interface, 'name', { __proto__: null, value: name, configurable: true });
  define(Interface, 'prototype', { __proto__: null, value: spec.prototype, writable: false });
  setPrototype(Interface, Parent); saveType(Interface, spec);
  define(spec.prototype, 'constructor', { __proto__: null, value: Interface, writable: true, configurable: true });
  define(spec.prototype, Symbol.toStringTag, { __proto__: null, value: name, configurable: true });
  for (let i = 0; i < keys.length; i++) attribute(spec, keys[i]);
  return Interface;
}
export const UIEvent = interfaceType('UIEvent', Event, { detail: 'long', view: 'window' });
attribute(typeFor(UIEvent), 'which', () => 0);
// EventModifierInit is a dictionary, not an exposed interface.
const ModifiedEvent = interfaceType('EventModifierInit', UIEvent, modifiers);
export const MouseEvent = interfaceType('MouseEvent', ModifiedEvent, {
  button: 'short', buttons: 'ushort', clientX: 'double', clientY: 'double', movementX: 'long', movementY: 'long',
  relatedTarget: 'target', screenX: 'double', screenY: 'double',
});
// The dictionary-only layer does not become a public prototype layer.
setPrototype(MouseEvent, UIEvent); setPrototype(MouseEvent.prototype, UIEvent.prototype);
const mouseSpec = typeFor(MouseEvent), coordinateKeys = ['clientX', 'clientY', 'screenX', 'screenY'];
for (let i = 0; i < coordinateKeys.length; i++) { const key = coordinateKeys[i]; attribute(mouseSpec, key, (event, values) => read(event).spec === pointerSpec ? values[key] : floor(values[key])); }
attribute(mouseSpec, 'relatedTarget', event => eventState(event).related);
attribute(mouseSpec, 'which', (event, values) => integer(values.button + 1, 32, false));
for (const [key, field] of [['pageX','clientX'],['pageY','clientY'],['offsetX','clientX'],['offsetY','clientY'],['x','clientX'],['y','clientY'],['layerX','clientX'],['layerY','clientY']]) attribute(mouseSpec, key, (event, values) => read(event).spec === pointerSpec ? values[field] : floor(values[field]));
for (const key of ['altKey','ctrlKey','metaKey','shiftKey']) attribute(mouseSpec, key);
const modifierNames = { __proto__: null, Alt: 'altKey', Control: 'ctrlKey', Meta: 'metaKey', Shift: 'shiftKey', AltGraph: 'modifierAltGraph', CapsLock: 'modifierCapsLock', Fn: 'modifierFn', NumLock: 'modifierNumLock', ScrollLock: 'modifierScrollLock', Symbol: 'modifierSymbol' };
operation(mouseSpec, 'getModifierState', function getModifierState(key) { const values = requireData(this, mouseSpec); if (!arguments.length) throw new NativeTypeError('A modifier is required'); return !!values[runDOMCallback(() => modifierNames[eventString(key)])]; });
export const PointerEvent = interfaceType('PointerEvent', MouseEvent, { altitudeAngle: ['double', Math.PI / 2], azimuthAngle: 'double', coalescedEvents: 'pointers', height: ['double', 1], isPrimary: 'bool', persistentDeviceId: 'long', pointerId: 'long', pointerType: 'string', predictedEvents: 'pointers', pressure: 'float', tangentialPressure: 'float', tiltX: 'long', tiltY: 'long', twist: 'long', width: ['double', 1] });
const pointerSpec = typeFor(PointerEvent);
delete PointerEvent.prototype.coalescedEvents; delete PointerEvent.prototype.predictedEvents;
operation(pointerSpec, 'getCoalescedEvents', function getCoalescedEvents() { return copy(requireData(this, pointerSpec).coalescedEvents); });
operation(pointerSpec, 'getPredictedEvents', function getPredictedEvents() { return copy(requireData(this, pointerSpec).predictedEvents); });
export const WheelEvent = interfaceType('WheelEvent', MouseEvent, { deltaMode: 'ulong', deltaX: 'double', deltaY: 'double', deltaZ: 'double' });
for (const [key,value] of [['DOM_DELTA_PIXEL',0],['DOM_DELTA_LINE',1],['DOM_DELTA_PAGE',2]]) { define(WheelEvent, key, { value, enumerable: true }); define(WheelEvent.prototype, key, { value, enumerable: true }); }
export const KeyboardEvent = interfaceType('KeyboardEvent', ModifiedEvent, { charCode: 'ulong', code: 'string', isComposing: 'bool', key: 'string', keyCode: 'ulong', location: 'ulong', repeat: 'bool' });
setPrototype(KeyboardEvent, UIEvent); setPrototype(KeyboardEvent.prototype, UIEvent.prototype);
const keyboardSpec = typeFor(KeyboardEvent);
for (const key of ['altKey','ctrlKey','metaKey','shiftKey']) attribute(keyboardSpec, key);
attribute(keyboardSpec, 'which', (event, values) => values.keyCode);
operation(keyboardSpec, 'getModifierState', function getModifierState(key) { const values = requireData(this, keyboardSpec); if (!arguments.length) throw new NativeTypeError('A modifier is required'); return !!values[runDOMCallback(() => modifierNames[eventString(key)])]; });
export const FocusEvent = interfaceType('FocusEvent', UIEvent, { relatedTarget: 'target' });
attribute(typeFor(FocusEvent), 'relatedTarget', event => eventState(event).related);
export const InputEvent = interfaceType('InputEvent', UIEvent, { data: 'nullable-string', dataTransfer: 'transfer', inputType: 'string', isComposing: 'bool', targetRanges: 'ranges' });
delete InputEvent.prototype.targetRanges;
operation(typeFor(InputEvent), 'getTargetRanges', function getTargetRanges() { return copy(requireData(this, typeFor(InputEvent)).targetRanges); });
export const SubmitEvent = interfaceType('SubmitEvent', Event, { submitter: 'html' });
export const ProgressEvent = interfaceType('ProgressEvent', Event, { lengthComputable: 'bool', loaded: 'double', total: 'double' });
export const HashChangeEvent = interfaceType('HashChangeEvent', Event, { newURL: 'string', oldURL: 'string' });
export const PopStateEvent = interfaceType('PopStateEvent', Event, { state: 'any' });
export const ErrorEvent = interfaceType('ErrorEvent', Event, { colno: 'ulong', error: ['any', undefined], filename: 'usv', lineno: 'ulong', message: 'string' });
const errorSpec = typeFor(ErrorEvent);
export const errorEventData = event => requireData(event, errorSpec);
export const isErrorEvent = event => read(event)?.spec === errorSpec;
export const PromiseRejectionEvent = interfaceType('PromiseRejectionEvent', Event, { promise: 'required-object', reason: ['any', undefined] });
define(PromiseRejectionEvent, 'length', { __proto__: null, value: 2, configurable: true });
export const ToggleEvent = interfaceType('ToggleEvent', Event, { newState: 'string', oldState: 'string', source: 'element' });
attribute(typeFor(ToggleEvent), 'source', (event, values) => retarget(values.source, eventState(event).current));
export const StorageEvent = interfaceType('StorageEvent', Event, { key: 'nullable-string', newValue: 'nullable-string', oldValue: 'nullable-string', storageArea: 'storage', url: 'usv' });
export const TransitionEvent = interfaceType('TransitionEvent', Event, { elapsedTime: 'double', propertyName: 'string', pseudoElement: 'string' });
export const AnimationEvent = interfaceType('AnimationEvent', Event, { animationName: 'string', elapsedTime: 'double', pseudoElement: 'string' });
export const CompositionEvent = interfaceType('CompositionEvent', UIEvent, { data: 'string' });
export const ClipboardEvent = interfaceType('ClipboardEvent', Event, { clipboardData: 'transfer' });
export const TouchEvent = interfaceType('TouchEvent', ModifiedEvent, { changedTouches: 'touches', targetTouches: 'touches', touches: 'touches' });
setPrototype(TouchEvent, UIEvent); setPrototype(TouchEvent.prototype, UIEvent.prototype);
const touchPrototype = TouchList.prototype;
define(TouchList, 'prototype', { value: touchPrototype, writable: false });
const touchLists = new WeakMap(), touchListFor = touchLists.get.bind(touchLists), saveTouchList = touchLists.set.bind(touchLists);
export function TouchList() { throw new NativeTypeError('Illegal constructor'); }
function requireTouchList(value) { const data = touchListFor(value); if (!data) throw new NativeTypeError('A TouchList is required'); return data; }
define(TouchList, 'name', { value: 'TouchList', configurable: true });
define(TouchList.prototype, Symbol.toStringTag, { value: 'TouchList', configurable: true });
define(TouchList.prototype, 'length', { enumerable: true, configurable: true, get() { return requireTouchList(this).length; } });
define(TouchList.prototype, 'item', { enumerable: true, configurable: true, writable: true, value: function item(index) { const data = requireTouchList(this); if (!arguments.length) throw new NativeTypeError('An index is required'); index = runDOMCallback(() => integer(index, 32, false)); return index < data.length ? data[index] : null; } });
define(TouchList.prototype, iteratorSymbol, { configurable: true, writable: true, value: function values() { const data = requireTouchList(this); return apply(arrayIterator, copy(data), []); } });
define(descriptor(touchPrototype, 'length').get, 'name', { value: 'get length', configurable: true });
define(touchPrototype, 'item', { value: nativeMethod('item', descriptor(touchPrototype, 'item').value), configurable: true, writable: true, enumerable: true });
define(touchPrototype, iteratorSymbol, { value: nativeMethod('values', descriptor(touchPrototype, iteratorSymbol).value), configurable: true, writable: true });
for (const key of ['touches','targetTouches','changedTouches']) {
  const cache = new WeakMap(), readList = cache.get.bind(cache), saveList = cache.set.bind(cache);
  attribute(typeFor(TouchEvent), key, (event, values) => { let list = readList(event); if (!list) { list = create(touchPrototype); markPlatform(list); saveTouchList(list, values[key]); for (let i = 0; i < values[key].length; i++) define(list, i, { __proto__: null, value: values[key][i], enumerable: true }); saveList(event, list); } return list; });
}

export const DragEvent = interfaceType('DragEvent', MouseEvent, { dataTransfer: 'transfer' });
// Only the implementation uses this path. Copy own data into a prototype-free
// dictionary, so platform-generated events never consult page option hooks.
export function createNativeUIEvent(Type, type, init = undefined) {
  const spec = typeFor(Type), dictionary = { __proto__: null };
  if (!spec) throw new NativeTypeError('Unknown event interface');
  if (init) { const keys = ownKeys(init); for (let i = 0; i < keys.length; i++) { const d = descriptor(init, keys[i]); if (d && own(d, 'value')) dictionary[keys[i]] = d.value; } }
  const event = create(spec.prototype), data = argumentsFor(spec, type, dictionary, true); initialize(event, spec, data); return event;
}
