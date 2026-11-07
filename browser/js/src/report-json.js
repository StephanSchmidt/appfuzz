// Reports contain platform records, never page-controlled serializers. Clone
// own data into objects without prototypes before using the captured encoder:
// Object/Array.prototype.toJSON and a replaced JSON.stringify must not erase
// evidence. Page-facing APIs still use their ordinary JavaScript semantics.
const stringify = JSON.stringify, ownKeys = Reflect.ownKeys;
const descriptor = Object.getOwnPropertyDescriptor, create = Object.create, setPrototype = Object.setPrototypeOf;
const array = Array.isArray, own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const string = String, NativeTypeError = TypeError;
export function reportJSON(value) {
  const ancestors = [];
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
  return stringify(snapshot(value));
}
