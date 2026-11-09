// DOM backend snapshots use captured operations; public live collections never
// expose these containers or depend on author collection methods.
import { END, NEXT, VALUE, MIME } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nodeInfo } from './dom-state.js';
import { attributeInfo } from './attribute-state.js';
import { nameIdentity } from './names.js';
import { documentMode } from './document-state.js';
const create = Object.create, define = Object.defineProperty, ownKeys = Reflect.ownKeys, descriptor = Object.getOwnPropertyDescriptor;
const setPrototype = Object.setPrototypeOf, apply = Reflect.apply, isArray = Array.isArray;
const ops = create(null), names = ownKeys(Array.prototype), iteratorProto = Object.getPrototypeOf([][Symbol.iterator]()), iteratorNext = iteratorProto.next;
const arrayResults = new Set(['map','filter','slice','concat','flat','flatMap','splice','toReversed','toSorted','toSpliced','with']), returnsArray = arrayResults.has.bind(arrayResults);
for (let i = 0; i < names.length; i++) {
  const key = names[i]; if (key === 'constructor' || key === 'length') continue;
  const d = descriptor(Array.prototype, key), method = d.value;
  if (key === Symbol.iterator || key === 'values' || key === 'keys' || key === 'entries') d.value = function (...args) {
    const iterator = apply(method, this, args);
    return { __proto__: null, next() { const result = apply(iteratorNext, iterator, []); if (isArray(result.value)) setPrototype(result.value, ops); return result; }, [Symbol.iterator]() { return this; } };
  };
  else if (returnsArray(key)) d.value = function (...args) { const result = apply(method, this, args); if (isArray(result)) setPrototype(result, ops); return result; };
  define(ops, key, d);
}
Object.freeze(ops);
export function backendList() { const result = []; setPrototype(result, ops); return result; }
export function backendChildNodes(root) {
  const result = backendList(), end = root?.[END]; if (!end) return result;
  for (let node = root[NEXT]; node && node !== end; node = (node[END] || node)[NEXT]) if (nodeInfo(node)?.kind !== 2) result[result.length] = node;
  return result;
}
export function backendChildren(root) { const all = backendChildNodes(root), result = backendList(); for (let i = 0; i < all.length; i++) if (nodeInfo(all[i])?.kind === 1) result[result.length] = all[i]; return result; }
export function backendAttributes(root) { const result = backendList(); for (let node = root[NEXT]; nodeInfo(node)?.kind === 2; node = node[NEXT]) result[result.length] = node; return result; }
export function collectionDocument(node) { return nodeInfo(node)?.kind === 9 ? node : (node[END] || node).ownerDocument; }
export function collectionHTMLDocument(document) { return documentMode(document) !== undefined || !!document?.[MIME]?.ignoreCase; }
export function collectionAttribute(node, local) {
  for (let attr = node[NEXT]; nodeInfo(attr)?.kind === 2; attr = attr[NEXT]) { const data = attributeInfo(attr); if (data.namespace === null && data.local === local) return attr[VALUE]; }
  return null;
}
export function collectionDescendants(root) {
  const result = backendList(), end = root[END]; if (!end) return result;
  for (let node = root[NEXT]; node && node !== end; node = node[NEXT]) if (nodeInfo(node)?.kind === 1) result[result.length] = node;
  return result;
}
export const collectionName = nameIdentity;
