const values = new WeakMap(), read = values.get.bind(values), save = values.set.bind(values), string = String;
const define = Object.defineProperty, NativeTypeError = TypeError;
export const doctypeInfo = read;
export function initializeDoctype(node, name, publicId, systemId) { save(node, { __proto__: null, name: string(name), publicId: string(publicId), systemId: string(systemId) }); }
export function installDoctypeSlots(prototype) {
  for (const [key, field] of [['name','name'],['nodeName','name'],['publicId','publicId'],['systemId','systemId']]) define(prototype, key, { __proto__: null, configurable: true, enumerable: true, get() { const data = read(this); if (!data) throw new NativeTypeError('A DocumentType is required'); return data[field]; } });
}
