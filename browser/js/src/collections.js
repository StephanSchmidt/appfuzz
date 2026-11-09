import { platformConstructor } from './constructors.js';
import { markPlatform } from './platform-state.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { nodeInfo } from './dom-state.js';
import { attributeInfo } from './attribute-state.js';
import { lowerASCII } from './names.js';
import { documentMode } from './document-state.js';
import { DOMException } from './dom-exception.js';
import { collectionVersion } from './collection-version.js';
import { backendList, backendChildNodes, backendChildren, backendAttributes, collectionDocument, collectionHTMLDocument, collectionAttribute, collectionDescendants, collectionName } from './collection-data.js';
import { attributeMethods } from './attributes.js';
import { NodeList as BackendNodeList } from '../node_modules/linkedom/esm/interface/node-list.js';
import { Node as BackendNode } from '../node_modules/linkedom/esm/interface/node.js';
import { ParentNode } from '../node_modules/linkedom/esm/mixin/parent-node.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
const NativeTypeError = TypeError, NativeProxy = Proxy, NativeWeakRef = WeakRef, NativeMap = Map;
const create = Object.create, define = Object.defineProperty, describe = Object.getOwnPropertyDescriptor, ownKeys = Reflect.ownKeys, prototype = Object.getPrototypeOf, freeze = Object.freeze;
const get = Reflect.get, set = Reflect.set, remove = Reflect.deleteProperty, defineProperty = Reflect.defineProperty, has = Reflect.has, apply = Reflect.apply;
const number = Number, integer = Number.isInteger, text = String, finite = Number.isFinite, trunc = Math.trunc;
const deref = Function.prototype.call.bind(WeakRef.prototype.deref), mapGet = Function.prototype.call.bind(Map.prototype.get), mapSet = Function.prototype.call.bind(Map.prototype.set);
const records = new WeakMap(), read = records.get.bind(records), save = records.set.bind(records);
const owners = new WeakMap(), ownerFor = owners.get.bind(owners), saveOwner = owners.set.bind(owners);
const HTML = 'http://www.w3.org/1999/xhtml';
function requireCollection(value, kind) { const record = read(value); if (!record || record.kind !== kind) throw new NativeTypeError('A ' + kind + ' is required'); return record; }
function requireNode(value, parent = false) { const kind = nodeInfo(value)?.kind; if (kind === undefined || kind < 1 || (parent && kind !== 1 && kind !== 9 && kind !== 11)) throw new NativeTypeError('A Node is required'); }
function required(count, min) { if (count < min) throw new NativeTypeError('Not enough arguments'); }
function uint(value) { const n = +value; return finite(n) && n ? ((trunc(n) % 4294967296) + 4294967296) % 4294967296 : 0; }
function index(key) { if (typeof key !== 'string') return -1; const n = number(key); return integer(n) && n >= 0 && n < 4294967295 && text(n) === key ? n : -1; }
// Mutation generations make repeated indexed reads constant time between changes.
function values(record) { const version = collectionVersion(record.sensitive); if (record.data === null || record.live && record.version !== version) { record.data = record.collect(); record.version = version; } return record.data; }
function publicItem(receiver, kind, index, count) { const record = requireCollection(receiver, kind); required(count, 1); index = runDOMCallback(() => uint(index)); return values(record)[index] ?? null; }
export let NodeList = class NodeList { constructor() { throw new NativeTypeError('Illegal constructor'); } get length() { return values(requireCollection(this, 'NodeList')).length; } item(index) { return publicItem(this, 'NodeList', index, arguments.length); } };
export let HTMLCollection = class HTMLCollection { constructor() { throw new NativeTypeError('Illegal constructor'); } get length() { return values(requireCollection(this, 'HTMLCollection')).length; } item(index) { return publicItem(this, 'HTMLCollection', index, arguments.length); } namedItem(name) { const record = requireCollection(this, 'HTMLCollection'); required(arguments.length, 1); name = runDOMCallback(() => eventString(name)); return named(record, name); } };
function mapCall(receiver, name, args, count, min) { const record = requireCollection(receiver, 'NamedNodeMap'); required(count, min); return apply(attributeMethods[name], record.owner, args); }
export let NamedNodeMap = class NamedNodeMap {
  constructor() { throw new NativeTypeError('Illegal constructor'); }
  get length() { return values(requireCollection(this, 'NamedNodeMap')).length; }
  item(index) { return publicItem(this, 'NamedNodeMap', index, arguments.length); }
  getNamedItem(name) { return mapCall(this, 'getAttributeNode', [name], arguments.length, 1); }
  getNamedItemNS(namespace, local) { return mapCall(this, 'getAttributeNodeNS', [namespace, local], arguments.length, 2); }
  setNamedItem(attr) { return mapCall(this, 'setAttributeNode', [attr], arguments.length, 1); }
  setNamedItemNS(attr) { return mapCall(this, 'setAttributeNodeNS', [attr], arguments.length, 1); }
  removeNamedItem(name) { const attr = mapCall(this, 'getAttributeNode', [name], arguments.length, 1); if (!attr) throw new DOMException('The attribute is absent', 'NotFoundError'); return mapCall(this, 'removeAttributeNode', [attr], 1, 1); }
  removeNamedItemNS(namespace, local) { const attr = mapCall(this, 'getAttributeNodeNS', [namespace, local], arguments.length, 2); if (!attr) throw new DOMException('The attribute is absent', 'NotFoundError'); return mapCall(this, 'removeAttributeNode', [attr], 1, 1); }
};
NodeList = platformConstructor(NodeList, 'NodeList', 0, true); HTMLCollection = platformConstructor(HTMLCollection, 'HTMLCollection', 0, true); NamedNodeMap = platformConstructor(NamedNodeMap, 'NamedNodeMap', 0, true);
const nodePrototype = NodeList.prototype, elementPrototype = HTMLCollection.prototype, attributePrototype = NamedNodeMap.prototype;
for (const [Class, name] of [[NodeList,'NodeList'],[HTMLCollection,'HTMLCollection'],[NamedNodeMap,'NamedNodeMap']]) {
  const p = Class.prototype; define(p, Symbol.toStringTag, { __proto__: null, value: name, configurable: true });
  const keys = ownKeys(p); for (let i = 0; i < keys.length; i++) if (typeof keys[i] === 'string' && keys[i] !== 'constructor') define(p, keys[i], { __proto__: null, enumerable: true });
  define(p, Symbol.iterator, { __proto__: null, value: Array.prototype.values, writable: true, configurable: true });
}
// These generic methods deliberately use public length/index access, as native
// NodeList does. Internal DOM algorithms use separate private snapshots.
for (const key of ['keys','values','entries','forEach']) define(nodePrototype, key, { __proto__: null, value: Array.prototype[key], writable: true, enumerable: true, configurable: true });
function names(record, data) {
  const result = backendList(), seen = create(null);
  function add(name) { if (name && !seen[name]) { seen[name] = true; result[result.length] = name; } }
  if (record.kind === 'NamedNodeMap') {
    const lower = collectionName(record.owner)?.namespace === HTML && collectionHTMLDocument(collectionDocument(record.owner));
    for (let i = 0; i < data.length; i++) { const name = attributeInfo(data[i]).qualified; if (!lower || lowerASCII(name) === name) add(name); }
  } else if (record.kind === 'HTMLCollection') for (let i = 0; i < data.length; i++) { add(collectionAttribute(data[i], 'id')); if (collectionName(data[i])?.namespace === HTML) add(collectionAttribute(data[i], 'name')); }
  return result;
}
function named(record, name) {
  if (!name) return null; const data = values(record);
  if (record.kind === 'NamedNodeMap') { for (let i = 0; i < data.length; i++) if (attributeInfo(data[i]).qualified === name) return data[i]; }
  else for (let i = 0; i < data.length; i++) if (collectionAttribute(data[i], 'id') === name || collectionName(data[i])?.namespace === HTML && collectionAttribute(data[i], 'name') === name) return data[i];
  return null;
}
function supported(record, key, data) { if (typeof key !== 'string' || record.kind === 'NodeList') return false; const list = names(record, data); for (let i = 0; i < list.length; i++) if (list[i] === key) return true; return false; }
function visible(target, key) { if (describe(target, key)) return false; for (let p = prototype(target); p !== null; p = prototype(p)) if (describe(p, key)) return false; return true; }
function collection(kind, owner, collect, sensitive = false, live = true) {
  const p = kind === 'NodeList' ? nodePrototype : kind === 'HTMLCollection' ? elementPrototype : attributePrototype, target = create(p);
  const record = { __proto__: null, kind, owner, collect, sensitive, live, data: null, version: -1 };
  // Web IDL legacy platform objects expose read-only virtual entries while
  // retaining ordinary expandos. Their indexed/named writes cannot replace nodes.
  const proxy = new NativeProxy(target, { __proto__: null,
    get(target, key, receiver) { const i = index(key); if (i >= 0) { const data = values(record); return i < data.length ? data[i] : get(target, key, receiver); } if (record.kind !== 'NodeList' && typeof key === 'string' && visible(target, key)) { const data = values(record); if (supported(record, key, data)) return named(record, key); } return get(target, key, receiver); },
    has(target, key) { const i = index(key); if (i >= 0) return i < values(record).length || has(target, key); return visible(target, key) && supported(record, key, values(record)) || has(target, key); },
    getOwnPropertyDescriptor(target, key) { const i = index(key), data = values(record); if (i >= 0) return i < data.length ? { __proto__: null, value: data[i], writable: false, enumerable: true, configurable: true } : describe(target, key); if (visible(target, key) && supported(record, key, data)) return { __proto__: null, value: named(record, key), writable: false, enumerable: false, configurable: true }; return describe(target, key); },
    ownKeys(target) { const data = values(record), result = backendList(), seen = create(null); for (let i = 0; i < data.length; i++) { const key = text(i); result[result.length] = key; seen[key] = true; } const list = names(record, data); for (let i = 0; i < list.length; i++) if (!seen[list[i]] && visible(target, list[i])) { result[result.length] = list[i]; seen[list[i]] = true; } const own = ownKeys(target); for (let i = 0; i < own.length; i++) if (!seen[own[i]]) { result[result.length] = own[i]; seen[own[i]] = true; } return result; },
    set(target, key, value, receiver) { const i = index(key); if (i >= 0 && i < values(record).length) return false; return set(target, key, value, receiver); },
    defineProperty(target, key, d) { if (index(key) >= 0) return false; if (!describe(target, key) && supported(record, key, values(record))) return false; return defineProperty(target, key, d); },
    deleteProperty(target, key) { const i = index(key); if (i >= 0) return i >= values(record).length; if (visible(target, key) && supported(record, key, values(record))) return false; return remove(target, key); },
    preventExtensions() { return false; },
  });
  save(proxy, record); markPlatform(proxy); return proxy;
}
function ownerRecord(owner) { let data = ownerFor(owner); if (!data) saveOwner(owner, data = { __proto__: null, nodes: null, children: null, attributes: null, queries: new NativeMap() }); return data; }
export function staticNodeList(input) { const data = backendList(); for (let i = 0; i < input.length; i++) data[i] = input[i]; return collection('NodeList', null, () => data, false, false); }
function tokens(value) { const result = backendList(); let token = ''; for (let i = 0; i <= value.length; i++) { const c = value[i]; if (i === value.length || c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f') { if (token) result[result.length] = token; token = ''; } else token += c; } return result; }
function query(root, kind, first, second = undefined) {
  // A collection's filter is fixed when it is created. Moving its root to
  // another document can select a different filter for a subsequent query.
  const html = collectionHTMLDocument(collectionDocument(root)), insensitive = documentMode(collectionDocument(root)) === 'BackCompat';
  const filter = kind + ':' + (html ? 'html' : 'xml') + ':' + (insensitive ? 'quirks' : 'standards');
  const table = ownerRecord(root).queries; let kinds = mapGet(table, filter); if (!kinds) mapSet(table, filter, kinds = new NativeMap());
  let level = mapGet(kinds, first); if (!level) mapSet(kinds, first, level = new NativeMap());
  const ref = mapGet(level, second), previous = ref && deref(ref); if (previous) return previous;
  const wanted = kind === 'class' ? tokens(first) : null;
  const result = collection('HTMLCollection', root, () => {
    const all = collectionDescendants(root), list = backendList(), folded = kind === 'tag' ? lowerASCII(first) : null;
    for (let i = 0; i < all.length; i++) {
      const node = all[i], id = collectionName(node); let match = false;
      if (kind === 'tag') match = first === '*' || id && id.qualified === (html && id.namespace === HTML ? folded : first);
      else if (kind === 'namespace') match = id && (first === '*' || id.namespace === first) && (second === '*' || id.local === second);
      else if (wanted.length) { const actual = tokens(collectionAttribute(node, 'class') || ''); match = true; for (let j = 0; j < wanted.length; j++) { let found = false; for (let k = 0; k < actual.length; k++) if ((insensitive ? lowerASCII(actual[k]) : actual[k]) === (insensitive ? lowerASCII(wanted[j]) : wanted[j])) found = true; if (!found) { match = false; break; } } }
      if (match) list[list.length] = node;
    }
    return list;
  }, kind === 'class');
  mapSet(level, second, new NativeWeakRef(result)); return result;
}
export function installCollections() {
  const fields = {
    get childNodes() { requireNode(this); const data = ownerRecord(this); return data.nodes || (data.nodes = collection('NodeList', this, () => backendChildNodes(this))); },
    get children() { requireNode(this, true); const data = ownerRecord(this); return data.children || (data.children = collection('HTMLCollection', this, () => backendChildren(this))); },
    get attributes() { if (nodeInfo(this)?.kind !== 1) throw new NativeTypeError('An Element is required'); const data = ownerRecord(this); return data.attributes || (data.attributes = collection('NamedNodeMap', this, () => backendAttributes(this))); },
  };
  define(BackendNode.prototype, 'childNodes', describe(fields, 'childNodes')); define(ParentNode.prototype, 'childNodes', describe(fields, 'childNodes')); define(ParentNode.prototype, 'children', describe(fields, 'children')); define(Element.prototype, 'attributes', describe(fields, 'attributes'));
  for (const [prototype, kind] of [[Element.prototype, 1], [Document.prototype, 9]]) {
    const check = node => { if (nodeInfo(node)?.kind !== kind) throw new NativeTypeError('An appropriate DOM receiver is required'); };
    const methods = {
      getElementsByTagName(name) { check(this); required(arguments.length, 1); name = runDOMCallback(() => eventString(name)); return query(this, 'tag', name); },
      getElementsByTagNameNS(namespace, local) { check(this); required(arguments.length, 2); const args = runDOMCallback(() => ({ __proto__: null, namespace: namespace == null ? null : eventString(namespace), local: eventString(local) })); return query(this, 'namespace', args.namespace === '' ? null : args.namespace, args.local); },
      getElementsByClassName(name) { check(this); required(arguments.length, 1); name = runDOMCallback(() => eventString(name)); return query(this, 'class', name); },
    };
    for (const key of ownKeys(methods)) { const d = describe(methods, key); d.enumerable = true; define(prototype, key, d); }
  }
  define(BackendNodeList.prototype, 'constructor', { __proto__: null, value: NodeList, configurable: true, writable: true }); freeze(BackendNodeList.prototype);
}
