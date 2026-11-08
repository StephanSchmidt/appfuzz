// HTML structured serialization: snapshot graphs before transfers, then
// deserialize with native brands and captured intrinsics. Never use toJSON,
// public constructors, prototype setters or author iterators for native data.
import { serializedDOMException, deserializeDOMException } from './dom-exception.js';
import { platformObject } from './platform-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const iteratorSymbol = Symbol.iterator;
const realm = globalThis, kindOf = globalThis.__native.cloneKind;
const apply = Reflect.apply, create = Object.create, define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor;
const keys = Object.keys, prototype = Object.getPrototypeOf, setPrototype = Object.setPrototypeOf;
const own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const NativeArray = Array, NativeMap = Map, NativeSet = Set, NativeDate = Date, NativeRegExp = RegExp;
const NativeArrayBuffer = ArrayBuffer, NativeUint8Array = Uint8Array, NativeObject = Object, string = String;
const mapGet = Function.prototype.call.bind(Map.prototype.get), mapHas = Function.prototype.call.bind(Map.prototype.has), mapSet = Function.prototype.call.bind(Map.prototype.set);
const mapEach = Function.prototype.call.bind(Map.prototype.forEach), setEach = Function.prototype.call.bind(Set.prototype.forEach), setAdd = Function.prototype.call.bind(Set.prototype.add);
const dateValue = Function.prototype.call.bind(Date.prototype.getTime);
const numberValue = Function.prototype.call.bind(Number.prototype.valueOf), booleanValue = Function.prototype.call.bind(Boolean.prototype.valueOf);
const stringValue = Function.prototype.call.bind(String.prototype.valueOf), bigintValue = Function.prototype.call.bind(BigInt.prototype.valueOf);
const constructors = { __proto__: null, Number, Boolean, String };
const errors = { __proto__: null, Error: Error.prototype, EvalError: EvalError.prototype, RangeError: RangeError.prototype,
  ReferenceError: ReferenceError.prototype, SyntaxError: SyntaxError.prototype, TypeError: TypeError.prototype, URIError: URIError.prototype };
const allocateError = globalThis.__native.allocateError;
// Weak storage retains the internal stack of deserialized errors independently
// of later public stack property replacements.
const cloneStacks = new WeakMap(), cloneStack = cloneStacks.get.bind(cloneStacks), hasCloneStack = cloneStacks.has.bind(cloneStacks), saveCloneStack = cloneStacks.set.bind(cloneStacks);
const get = (target, key) => descriptor(target, key)?.get;
const bufferLength = get(ArrayBuffer.prototype, 'byteLength'), bufferDetached = get(ArrayBuffer.prototype, 'detached');
const bufferResizable = get(ArrayBuffer.prototype, 'resizable'), bufferMaximum = get(ArrayBuffer.prototype, 'maxByteLength');
const transferBuffer = Function.prototype.call.bind(ArrayBuffer.prototype.transfer);
const copyBytes = Function.prototype.call.bind(Uint8Array.prototype.set);
const typed = prototype(Uint8Array.prototype), typedBuffer = get(typed, 'buffer'), typedLength = get(typed, 'length'), typedOffset = get(typed, 'byteOffset');
const validateTyped = Function.prototype.call.bind(typed.values);
const viewBuffer = get(DataView.prototype, 'buffer'), viewLength = get(DataView.prototype, 'byteLength'), viewOffset = get(DataView.prototype, 'byteOffset');
const viewConstructors = { __proto__: null, DataView, Uint8Array, Uint8ClampedArray, Int8Array, Int16Array, Uint16Array, Int32Array, Uint32Array, BigInt64Array, BigUint64Array, Float32Array, Float64Array };
if (typeof globalThis.Float16Array === 'function') viewConstructors.Float16Array = globalThis.Float16Array;
const regexpSource = get(RegExp.prototype, 'source'), regexpFlags = [];
for (const [key, letter] of [['hasIndices', 'd'], ['global', 'g'], ['ignoreCase', 'i'], ['multiline', 'm'], ['dotAll', 's'], ['unicode', 'u'], ['unicodeSets', 'v'], ['sticky', 'y']]) {
  const getter = get(RegExp.prototype, key); if (getter) regexpFlags[regexpFlags.length] = [getter, letter];
}
// Read native stack data, as in HTML/Firefox, without invoking an author
// stack accessor (Chrome currently invokes it).
const errorStack = get(Error.prototype, 'stack');
let platform = () => null, unsupported = () => {}, portTransfers = { isPort: () => false };
export function installPortTransfers(value) { portTransfers = value; }
export function installClonePlatform(clone, report) { platform = clone; unsupported = report; }
function list() { const value = []; setPrototype(value, null); return value; }
function push(values, value) { values[values.length] = value; }
function property(target, key, value, enumerable = true) {
  define(target, key, { __proto__: null, value, writable: true, enumerable, configurable: true });
}
function argumentError(message) {
  const value = allocateError(errors.TypeError); property(value, 'message', message, false); property(value, 'stack', '', false); return value;
}
function fail() {
  const value = deserializeDOMException({ name: 'DataCloneError', message: 'The value cannot be cloned', code: 25 });
  property(value, 'stack', '', false); throw value;
}
const object = value => value !== null && (typeof value === 'object' || typeof value === 'function');
function text(value) { if (typeof value === 'symbol') throw argumentError('A Symbol cannot be converted to a string'); return string(value); }
function detached(buffer) {
  if (bufferDetached) return apply(bufferDetached, buffer, []);
  try { new NativeUint8Array(buffer, 0, 0); return false; } catch { return true; }
}
function copyBuffer(buffer) {
  if (detached(buffer)) fail();
  const length = apply(bufferLength, buffer, []);
  const resizable = bufferResizable && apply(bufferResizable, buffer, []);
  const result = resizable ? new NativeArrayBuffer(length, { __proto__: null, maxByteLength: apply(bufferMaximum, buffer, []) }) : new NativeArrayBuffer(length);
  copyBytes(new NativeUint8Array(result), new NativeUint8Array(buffer));
  return result;
}
function optionsList(options) {
  const result = list();
  if (options == null) return result;
  if (!object(options)) throw argumentError('Structured serialize options must be a dictionary');
  const sequence = options.transfer;
  if (sequence === undefined) return result;
  if (!object(sequence)) throw argumentError('Transfer must be an iterable object');
  // Web IDL converts the complete sequence before transfer validation.
  // Element conversion errors do not perform IteratorClose.
  return transferSequence(sequence, sequence[iteratorSymbol]);
}
export function transferSequence(sequence, method) {
  if (!object(sequence) || typeof method !== 'function') throw argumentError('Transfer must be iterable');
  const result = list(), iterator = apply(method, sequence, []);
  if (!object(iterator)) throw argumentError('Invalid transfer iterator');
  const next = iterator.next;
  if (typeof next !== 'function') throw argumentError('Invalid transfer iterator');
  while (true) {
    const step = apply(next, iterator, []);
    if (!object(step)) throw argumentError('Invalid iterator result');
    if (step.done) break;
    const value = step.value;
    if (!object(value)) throw argumentError('Transfer items must be objects');
    push(result, value);
  }
  return result;
}
export { optionsList as transferOptions, fail as cloneFailure };

export function serializeMessage(value, transfers) {
  const memory = new NativeMap(), records = list(), frames = list();
  for (let i = 0; i < transfers.length; i++) {
    const input = transfers[i], kind = kindOf(input);
    if (kind !== 'ArrayBuffer' && !portTransfers.isPort(input)) fail();
    if (mapHas(memory, input)) fail();
    const record = { __proto__: null, kind: 'ready', value: null, children: null };
    mapSet(memory, input, record); push(records, record);
  }
  function visit(input) {
    if (!object(input)) {
      if (typeof input === 'symbol') fail();
      return { __proto__: null, kind: 'ready', value: input, children: null };
    }
    if (mapHas(memory, input)) return mapGet(memory, input);
    if (platformObject(input)) fail();
    const exception = serializedDOMException(input);
    const kind = exception ? 'DOMException' : kindOf(input), record = { __proto__: null, kind: 'ready', value: null, children: null };
    let entries = null, properties = false;
    switch (kind) {
      case 'Object': case 'Array': {
        const special = platform(input);
        if (special?.reject || platformObject(input)) fail();
        if (special) { record.value = special.value; break; }
        record.kind = 'properties'; record.value = kind === 'Array' ? new NativeArray(descriptor(input, 'length').value) : create(NativeObject.prototype);
        entries = keys(input); properties = true; break;
      }
      case 'Date': record.value = new NativeDate(dateValue(input)); break;
      case 'RegExp': {
        let flags = '';
        for (let i = 0; i < regexpFlags.length; i++) if (apply(regexpFlags[i][0], input, [])) flags += regexpFlags[i][1];
        record.value = new NativeRegExp(apply(regexpSource, input, []), flags); break;
      }
      case 'Number': record.value = new constructors.Number(numberValue(input)); break;
      case 'Boolean': record.value = new constructors.Boolean(booleanValue(input)); break;
      case 'String': record.value = new constructors.String(stringValue(input)); break;
      case 'BigInt': record.value = NativeObject(bigintValue(input)); break;
      case 'Map':
        record.kind = 'map'; record.value = new NativeMap(); entries = list();
        mapEach(input, (value, key) => { push(entries, key); push(entries, value); }); break;
      case 'Set':
        record.kind = 'set'; record.value = new NativeSet(); entries = list();
        setEach(input, value => push(entries, value)); break;
      case 'Error': {
        const name = input.name, proto = typeof name === 'string' && own(errors, name) ? errors[name] : errors.Error;
        const message = descriptor(input, 'message');
        const converted = message && own(message, 'value') ? text(message.value) : undefined;
        record.value = allocateError(proto);
        if (converted !== undefined) property(record.value, 'message', converted, false);
        const stack = hasCloneStack(input) ? cloneStack(input) : errorStack ? apply(errorStack, input, []) : undefined;
        saveCloneStack(record.value, stack);
        if (typeof stack === 'string') property(record.value, 'stack', stack, false);
        const cause = descriptor(input, 'cause');
        if (cause && own(cause, 'value')) { record.kind = 'error'; entries = [cause.value]; }
        break;
      }
      case 'DOMException': {
        record.value = deserializeDOMException(exception);
        const stack = descriptor(input, 'stack');
        const copy = hasCloneStack(input) ? cloneStack(input) : stack && own(stack, 'value') && typeof stack.value === 'string' ? stack.value : '';
        property(record.value, 'stack', copy, false); saveCloneStack(record.value, copy);
        break;
      }
      case 'ArrayBuffer': record.value = copyBuffer(input); break;
      case 'SharedArrayBuffer':
        // Browser sessions currently have no cross-origin isolated capability.
        fail(); break;
      default: {
        if (!own(viewConstructors, kind)) fail();
        let buffer, offset, length;
        try {
          if (kind === 'DataView') {
            buffer = apply(viewBuffer, input, []); offset = apply(viewOffset, input, []); length = apply(viewLength, input, []);
          } else {
            validateTyped(input); buffer = apply(typedBuffer, input, []); offset = apply(typedOffset, input, []); length = apply(typedLength, input, []);
          }
        } catch { fail(); }
        if (bufferResizable && apply(bufferResizable, buffer, [])) unsupported('structuredClone resizable ArrayBuffer view length tracking');
        record.kind = 'view'; record.constructor = viewConstructors[kind]; record.buffer = visit(buffer); record.offset = offset; record.length = length;
      }
    }
    mapSet(memory, input, record); push(records, record);
    if (entries !== null) {
      record.children = list();
      push(frames, { __proto__: null, input, record, entries, index: 0, properties });
    }
    return record;
  }
  const root = visit(value);
  // Depth-first traversal preserves getter order and Map/Set snapshots without
  // using the JavaScript call stack for arbitrarily deep ordinary graphs.
  while (frames.length) {
    const frame = frames[frames.length - 1];
    if (frame.index === frame.entries.length) { frames.length--; continue; }
    const item = frame.entries[frame.index++];
    if (frame.properties) {
      if (own(frame.input, item)) push(frame.record.children, [item, visit(frame.input[item])]);
    } else push(frame.record.children, visit(item));
  }
  // Transfers occur only after successful graph serialization, in list order.
  // A transferred buffer's final bytes include mutations made by getters.
  for (let i = 0; i < transfers.length; i++) {
    const input = transfers[i];
    const record = mapGet(memory, input);
    if (portTransfers.isPort(input)) { record.kind = 'port'; record.holder = portTransfers.take(input); }
    else {
      if (detached(input)) fail();
      try { record.value = transferBuffer(input); } catch { fail(); }
    }
  }
  let delivered = false, result;
  return () => {
    if (delivered) return result;
    const ports = [];
    for (let i = 0; i < records.length; i++) if (records[i].kind === 'port') {
      const record = records[i]; record.value = portTransfers.receive(record.holder);
      property(ports, ports.length, record.value);
    }
    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      if (record.kind === 'view') record.value = new record.constructor(record.buffer.value, record.offset, record.length);
    }
    for (let i = 0; i < records.length; i++) {
      const record = records[i], children = record.children;
      switch (record.kind) {
        case 'properties': for (let j = 0; j < children.length; j++) property(record.value, children[j][0], children[j][1].value); break;
        case 'map': for (let j = 0; j < children.length; j += 2) mapSet(record.value, children[j].value, children[j + 1].value); break;
        case 'set': for (let j = 0; j < children.length; j++) setAdd(record.value, children[j].value); break;
        case 'error': property(record.value, 'cause', children[0].value, false); break;
      }
    }
    delivered = true; result = { value: root.value, ports }; return result;
  };
}
export const structuredClone = { structuredClone(value, options = undefined) {
  if (this != null && this !== realm) throw argumentError('Illegal structuredClone receiver');
  if (!arguments.length) throw argumentError('structuredClone requires a value');
  return runDOMCallback(() => serializeMessage(value, optionsList(options))().value);
} }.structuredClone;
