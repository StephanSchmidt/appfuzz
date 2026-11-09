// The pinned DOM backend needs array operations, but a NodeList is not an
// Array exotic object. Ordinary array-like storage keeps ArraySpeciesCreate
// from consulting the public, nonconstructible interface or author species.
import { markPlatform } from './platform-state.js';
const NativeArray = Array, construct = Reflect.construct, create = Object.create, define = Object.defineProperty;
const ownKeys = Reflect.ownKeys, descriptor = Object.getOwnPropertyDescriptor, setPrototype = Object.setPrototypeOf;
const operations = create(null), names = ownKeys(NativeArray.prototype);
for (let i = 0; i < names.length; i++) {
  const key = names[i];
  if (key !== 'constructor' && key !== 'length' && key !== 'toString' && key !== 'toLocaleString') define(operations, key, descriptor(NativeArray.prototype, key));
}
Object.freeze(operations);
export function installNodeListPrototype(prototype) {
  setPrototype(prototype, operations);
  define(prototype, Symbol.toStringTag, { __proto__: null, value: 'NodeList', configurable: true });
}
export function initializeNodeList(value, values) {
  const array = construct(NativeArray, values), keys = ownKeys(array);
  for (let i = 0; i < keys.length; i++) {
    const d = descriptor(array, keys[i]);
    define(value, keys[i], { __proto__: null, value: d.value, writable: d.writable, enumerable: d.enumerable, configurable: d.configurable });
  }
  markPlatform(value);
}
