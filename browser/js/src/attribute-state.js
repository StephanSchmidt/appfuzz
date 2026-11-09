import { nodeInfo, rememberNodeDocument } from './dom-state.js';
// Attribute identity and ownership are native slots, independent of shadows.
const states = new WeakMap(), get = states.get.bind(states), save = states.set.bind(states);
const define = Object.defineProperty, NativeTypeError = TypeError;
export const attributeInfo = get;
export function requireAttribute(value) { const data = get(value); if (!data) throw new NativeTypeError('An Attr is required'); return data; }
export function initializeAttributeNode(value, document, local) {
  define(value, 'ownerDocument', { __proto__: null, value: document, writable: true, configurable: true, enumerable: true });
  define(value, 'localName', { __proto__: null, value: local, writable: true, configurable: true, enumerable: true });
  define(value, 'nodeType', { __proto__: null, value: 2, configurable: true, enumerable: true });
  define(value, 'parentNode', { __proto__: null, value: null, configurable: true, enumerable: true });
}
export function initializeAttribute(value, name) { const document = value.ownerDocument; delete value.localName; save(value, { __proto__: null, namespace: null, prefix: null, local: name, qualified: name, owner: null, document }); define(value, 'ownerDocument', { __proto__: null, configurable: true, enumerable: true, get() { return requireAttribute(this).document; } }); }
export function setAttributeOwner(value, owner) { requireAttribute(value).owner = owner; }
export function installAttributeSlots(prototype) {
  for (const [name, key] of [['name','qualified'],['nodeName','qualified'],['localName','local'],['prefix','prefix'],['namespaceURI','namespace'],['ownerElement','owner']]) {
    define(prototype, name, { __proto__: null, configurable: true, enumerable: true, get() { return requireAttribute(this)[key]; } });
  }
}

export function setNodeDocument(value, document) { const data = get(value); if (data) data.document = document; else if (nodeInfo(value)) rememberNodeDocument(value, document); else value.ownerDocument = document; }
