// Read-only indexed platform properties stay live without publishing their
// backing lists. Ordinary expandos remain ordinary JavaScript properties.
const NativeProxy = Proxy, create = Object.create, keys = Reflect.ownKeys;
const get = Reflect.get, set = Reflect.set, remove = Reflect.deleteProperty, describe = Reflect.getOwnPropertyDescriptor, defineProperty = Reflect.defineProperty;
const text = String, number = Number, integer = Number.isInteger, setPrototype = Object.setPrototypeOf;
export const indexedValues = Array.prototype.values;
function index(key) {
  if (typeof key !== 'string') return -1;
  const value = number(key);
  return integer(value) && value >= 0 && value < 4294967295 && text(value) === key ? value : -1;
}
export function indexedObject(prototype, values) {
  const target = create(prototype);
  return new NativeProxy(target, { __proto__: null,
    get(target, key, receiver) { const i = index(key), data = values(); return i >= 0 && i < data.length ? data[i] : get(target, key, receiver); },
    has(target, key) { const i = index(key); return i >= 0 && i < values().length || ReflectHas(target, key); },
    getOwnPropertyDescriptor(target, key) { const i = index(key), data = values(); return i >= 0 && i < data.length ? { __proto__: null, value: data[i], writable: false, enumerable: true, configurable: true } : describe(target, key); },
    ownKeys(target) { const data = values(), result = []; setPrototype(result, null); for (let i = 0; i < data.length; i++) result[result.length] = text(i); const own = keys(target); for (let i = 0; i < own.length; i++) result[result.length] = own[i]; return result; },
    set(target, key, value, receiver) { return index(key) < 0 && set(target, key, value, receiver); },
    defineProperty(target, key, value) { return index(key) < 0 && defineProperty(target, key, value); },
    deleteProperty(target, key) { const i = index(key); return i >= 0 && i < values().length ? false : remove(target, key); },
    preventExtensions() { return false; },
  });
}
const ReflectHas = Reflect.has;
