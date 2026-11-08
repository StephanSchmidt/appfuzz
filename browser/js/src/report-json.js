// Reports contain platform records, never page-controlled serializers. Clone
// own data into objects without prototypes before using the captured encoder:
// Object/Array.prototype.toJSON and a replaced JSON.stringify must not erase
// evidence. Page-facing APIs still use their ordinary JavaScript semantics.
const stringify = JSON.stringify, ownKeys = Reflect.ownKeys;
const descriptor = Object.getOwnPropertyDescriptor, create = Object.create, setPrototype = Object.setPrototypeOf;
const array = Array.isArray, own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const string = String, finite = Number.isFinite, NativeTypeError = TypeError;
export function reportJSON(value) {
  const ancestors = []; setPrototype(ancestors, null);
  function snapshot(value) {
    if (typeof value === 'bigint') throw new NativeTypeError('Cannot serialize BigInt');
    if (value === null || typeof value !== 'object') return typeof value === 'function' ? undefined : value;
    for (let i = 0; i < ancestors.length; i++) if (ancestors[i] === value) throw new NativeTypeError('Cyclic browser record');
    ancestors[ancestors.length] = value;
    let result;
    if (array(value)) {
      result = []; setPrototype(result, null);
      const length = descriptor(value, 'length').value;
      for (let i = 0; i < length; i++) {
        const item = descriptor(value, string(i));
        result[i] = item && own(item, 'value') ? snapshot(item.value) : undefined;
      }
    } else {
      result = create(null);
      const keys = ownKeys(value);
      for (let i = 0; i < keys.length; i++) if (typeof keys[i] === 'string') {
        const item = descriptor(value, keys[i]);
        if (item && item.enumerable && own(item, 'value')) result[keys[i]] = snapshot(item.value);
      }
    }
    ancestors.length--; return result;
  }
  // QuickJS JSON.stringify uses an ordinary array as its cycle stack,
  // which can invoke page index setters even for null-prototype input.
  // Only primitive string quoting is delegated to that native encoder.
  function encode(value) {
    if (value === null) return 'null';
    if (typeof value === 'string') return stringify(value);
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return finite(value) ? string(value) : 'null';
    if (typeof value !== 'object') return undefined;
    let out;
    if (array(value)) {
      out = '[';
      for (let i = 0; i < value.length; i++) out += (i ? ',' : '') + (encode(value[i]) ?? 'null');
      return out + ']';
    }
    out = '{';
    const keys = ownKeys(value); let comma = '';
    for (let i = 0; i < keys.length; i++) if (typeof keys[i] === 'string') {
      const encoded = encode(value[keys[i]]);
      if (encoded !== undefined) { out += comma + stringify(keys[i]) + ':' + encoded; comma = ','; }
    }
    return out + '}';
  }
  return encode(snapshot(value));
}
