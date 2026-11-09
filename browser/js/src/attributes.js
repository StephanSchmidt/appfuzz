import { Attr } from '../node_modules/linkedom/esm/interface/attr.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { NEXT, PREV, VALUE, CLASS_LIST } from '../node_modules/linkedom/esm/shared/symbols.js';
import { knownSiblings, knownAdjacent } from '../node_modules/linkedom/esm/shared/utils.js';
import { attributeChangedCallback as observeAttribute } from '../node_modules/linkedom/esm/interface/mutation-observer.js';
import { attributeReaction } from './ce-hooks.js';
import { attributeInfo, requireAttribute, setAttributeOwner, setNodeDocument } from './attribute-state.js';
import { nodeInfo, nodeDocument, physicalDocumentElement } from './dom-state.js';
import { nameIdentity, lowerASCII, qualifiedName, validAttributeLocalName } from './names.js';
import { DOMException } from './dom-exception.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor, ownKeys = Reflect.ownKeys;
const indexOf = Function.prototype.call.bind(String.prototype.indexOf), slice = Function.prototype.call.bind(String.prototype.slice);
const NativeTypeError = TypeError, isHTML = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const clear = Function.prototype.call.bind(Set.prototype.clear), add = Function.prototype.call.bind(Set.prototype.add);
const tails = new WeakMap(), tailFor = tails.get.bind(tails), saveTail = tails.set.bind(tails);
function requireElement(value) { if (nodeInfo(value)?.kind !== 1) throw new NativeTypeError('An Element is required'); }
function requireDocument(value) { if (nodeInfo(value)?.kind !== 9) throw new NativeTypeError('A Document is required'); }
const normalizedNS = value => value == null || value === '' ? null : value;
const html = element => nameIdentity(element)?.namespace === 'http://www.w3.org/1999/xhtml' && isHTML(nodeDocument(element));
function nameFor(element, value) { value = eventString(value); return html(element) ? lowerASCII(value) : value; }
function find(element, namespace, local, qualified = false) {
  for (let attr = element[NEXT]; nodeInfo(attr)?.kind === 2; attr = attr[NEXT]) {
    const data = requireAttribute(attr); if (qualified ? data.qualified === local : data.namespace === namespace && data.local === local) return attr;
  }
  return null;
}
function syncClass(element, data, value) {
  const tokens = element[CLASS_LIST]; if (data.namespace !== null || data.local !== 'class' || !tokens) return;
  clear(tokens); let token = '';
  for (let i = 0; i <= value.length; i++) { const c = value[i]; if (i === value.length || c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f') { if (token) add(tokens, token); token = ''; } else token += c; }
}
function notify(element, data, oldValue, value) { syncClass(element, data, value ?? ''); observeAttribute(element, data.local, oldValue, data.namespace); attributeReaction(element, data.local, oldValue, value, data.namespace); }
function write(attr, value) { const data = requireAttribute(attr), old = attr[VALUE]; attr[VALUE] = value; if (data.owner) notify(data.owner, data, old, value); }
function append(element, attr, notifications) {
  const data = requireAttribute(attr); let previous = tailFor(element);
  if (!previous || (previous !== element && attributeInfo(previous)?.owner !== element) || nodeInfo(previous[NEXT])?.kind === 2) { previous = element; while (nodeInfo(previous[NEXT])?.kind === 2) previous = previous[NEXT]; }
  setNodeDocument(attr, nodeDocument(element)); setAttributeOwner(attr, element); knownSiblings(previous, attr, previous[NEXT]); saveTail(element, attr);
  if (notifications) notify(element, data, null, attr[VALUE]);
}
function remove(element, attr) {
  const data = requireAttribute(attr); if (tailFor(element) === attr) saveTail(element, attr[PREV]); knownAdjacent(attr[PREV], attr[NEXT]); attr[PREV] = attr[NEXT] = null; setAttributeOwner(attr, null); notify(element, data, attr[VALUE], null);
}
export function nativeAttribute(owner, identity, value = '') {
  const attr = new Attr(owner, identity.qualified, value), data = requireAttribute(attr);
  data.namespace = identity.namespace; data.prefix = identity.prefix; data.local = identity.local; data.qualified = identity.qualified;
  return attr;
}
export function parsedAttribute(element, namespace, qualified, value) {
  const at = indexOf(qualified, ':'), prefix = namespace !== null && at >= 0 ? slice(qualified, 0, at) : null, local = prefix === null ? qualified : slice(qualified, at + 1);
  const attr = nativeAttribute(nodeDocument(element), { namespace, prefix, local, qualified }, value); append(element, attr, false); const data = requireAttribute(attr); syncClass(element, data, value); attributeReaction(element, local, null, value, namespace); return attr;
}
export function cloneAttribute(attr, owner) { const data = requireAttribute(attr); return nativeAttribute(owner, data, attr[VALUE]); }
function required(n, count) { if (n < count) throw new NativeTypeError('Not enough arguments'); }
function byName(element, value, count) { requireElement(element); required(count, 1); return runDOMCallback(() => nameFor(element, value)); }
function byNS(element, namespace, local, count) { requireElement(element); required(count, 2); return runDOMCallback(() => ({ __proto__: null, namespace: normalizedNS(namespace == null ? null : eventString(namespace)), local: eventString(local) })); }
export const attributeMethods = {
  getAttribute(name) { name = byName(this, name, arguments.length); return find(this, null, name, true)?.[VALUE] ?? null; },
  getAttributeNode(name) { name = byName(this, name, arguments.length); return find(this, null, name, true); },
  hasAttribute(name) { name = byName(this, name, arguments.length); return find(this, null, name, true) !== null; },
  getAttributeNS(namespace, local) { const key = byNS(this, namespace, local, arguments.length); return find(this, key.namespace, key.local)?.[VALUE] ?? null; },
  getAttributeNodeNS(namespace, local) { const key = byNS(this, namespace, local, arguments.length); return find(this, key.namespace, key.local); },
  hasAttributeNS(namespace, local) { const key = byNS(this, namespace, local, arguments.length); return find(this, key.namespace, key.local) !== null; },
  getAttributeNames() { requireElement(this); const result = []; let n = 0; for (let attr = this[NEXT]; nodeInfo(attr)?.kind === 2; attr = attr[NEXT]) define(result, n++, { __proto__: null, value: requireAttribute(attr).qualified, writable: true, enumerable: true, configurable: true }); return result; },
  setAttribute(name, value) {
    requireElement(this); required(arguments.length, 2); const args = runDOMCallback(() => ({ __proto__: null, name: nameFor(this, name), value: eventString(value) }));
    if (!validAttributeLocalName(args.name)) throw new DOMException('Invalid attribute name', 'InvalidCharacterError');
    const attr = find(this, null, args.name, true); if (attr) write(attr, args.value); else append(this, nativeAttribute(nodeDocument(this), { namespace: null, prefix: null, local: args.name, qualified: args.name }, args.value), true);
  },
  setAttributeNS(namespace, qualified, value) {
    requireElement(this); required(arguments.length, 3); const args = runDOMCallback(() => ({ __proto__: null, namespace: namespace == null ? null : eventString(namespace), qualified: eventString(qualified), value: eventString(value) }));
    const id = qualifiedName(args.namespace, args.qualified, 2, DOMException, true), attr = find(this, id.namespace, id.local);
    if (attr) write(attr, args.value);
    else append(this, nativeAttribute(nodeDocument(this), id, args.value), true);
  },
  removeAttribute(name) { name = byName(this, name, arguments.length); const attr = find(this, null, name, true); if (attr) remove(this, attr); },
  removeAttributeNS(namespace, local) { const key = byNS(this, namespace, local, arguments.length), attr = find(this, key.namespace, key.local); if (attr) remove(this, attr); },
  removeAttributeNode(attr) { requireElement(this); required(arguments.length, 1); if (requireAttribute(attr).owner !== this) throw new DOMException('The attribute does not belong to this element', 'NotFoundError'); remove(this, attr); return attr; },
  setAttributeNode(attr) { return setNode(this, attr, arguments.length); },
  setAttributeNodeNS(attr) { return setNode(this, attr, arguments.length); },
  toggleAttribute(name, force = undefined) {
    name = byName(this, name, arguments.length); if (!validAttributeLocalName(name)) throw new DOMException('Invalid attribute name', 'InvalidCharacterError');
    const attr = find(this, null, name, true); if (attr) { if (arguments.length < 2 || !force) { remove(this, attr); return false; } return true; }
    if (arguments.length < 2 || force) { append(this, nativeAttribute(nodeDocument(this), { namespace: null, prefix: null, local: name, qualified: name }), true); return true; } return false;
  },
};
function setNode(element, attr, count) {
  requireElement(element); required(count, 1); const data = requireAttribute(attr);
  if (data.owner && data.owner !== element) throw new DOMException('The attribute belongs to another element', 'InUseAttributeError');
  const old = find(element, data.namespace, data.local); if (old === attr) return attr;
  if (old) { const before = old[PREV], after = old[NEXT], previous = old[VALUE]; knownAdjacent(before, after); setAttributeOwner(old, null); old[PREV] = old[NEXT] = null; setNodeDocument(attr, nodeDocument(element)); setAttributeOwner(attr, element); knownSiblings(before, attr, after); if (tailFor(element) === old) saveTail(element, attr); notify(element, data, previous, attr[VALUE]); }
  else append(element, attr, true);
  return old;
}
export function installAttributes() {
  const roots = { get documentElement() { return physicalDocumentElement(this); } };
  define(Document.prototype, 'documentElement', descriptor(roots, 'documentElement'));
  for (const key of ownKeys(attributeMethods)) define(Element.prototype, key, { ...descriptor(attributeMethods, key), enumerable: true });
  define(Attr.prototype, 'cloneNode', { __proto__: null, value: function cloneNode() { requireAttribute(this); return cloneAttribute(this, requireAttribute(this).document); }, writable: true, enumerable: true, configurable: true });
  const fields = { get value() { requireAttribute(this); return this[VALUE]; }, set value(value) { requireAttribute(this); value = runDOMCallback(() => eventString(value)); write(this, value); } };
  define(Attr.prototype, 'value', { ...descriptor(fields, 'value'), enumerable: true });
  for (const name of ['nodeValue','textContent']) define(Attr.prototype, name, { __proto__: null, configurable: true, enumerable: true, get() { requireAttribute(this); return this[VALUE]; }, set(value) { requireAttribute(this); value = value == null ? '' : runDOMCallback(() => eventString(value)); write(this, value); } });
  Document.prototype.createAttribute = function (name) {
    requireDocument(this); required(arguments.length, 1); name = runDOMCallback(() => eventString(name)); if (isHTML(this)) name = lowerASCII(name);
    if (!validAttributeLocalName(name)) throw new DOMException('Invalid attribute name', 'InvalidCharacterError');
    return nativeAttribute(this, { namespace: null, prefix: null, local: name, qualified: name });
  };
  Document.prototype.createAttributeNS = function (namespace, qualified) {
    requireDocument(this); required(arguments.length, 2); const args = runDOMCallback(() => ({ __proto__: null, namespace: namespace == null ? null : eventString(namespace), qualified: eventString(qualified) }));
    return nativeAttribute(this, qualifiedName(args.namespace, args.qualified, 2, DOMException, true));
  };
}
