// Script preparation is a DOM mutation step, not an event-loop poll. Batch
// multi-node operations so all inserted scripts are prepared before any
// inline code runs, and keep native fragments before insertion empties them.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
import { scriptRecord } from './script-state.js';
import { documentMode } from './document.js';
import { setDOMCallbackBoundary } from './dom-callbacks.js';

const shadow = shadowRoots.get.bind(shadowRoots);
const apply = Reflect.apply;
const define = Object.defineProperty;
const descriptor = Object.getOwnPropertyDescriptor;
const add = Function.prototype.call.bind(Array.prototype.push);
const shadowHosts = new WeakMap();
const host = shadowHosts.get.bind(shadowHosts);
const rememberHost = shadowHosts.set.bind(shadowHosts);
const lowerASCII = value => value.replace(/[A-Z]/g, c => c.toLowerCase());
export const scriptShadowHost = host;

export function scriptAttribute(node, name) {
  for (let attr = node[NEXT]; attr && attr.nodeType === 2; attr = attr[NEXT]) {
    if (attr.localName === name) return attr[VALUE];
  }
  return null;
}

export function scriptText(node) {
  let text = '';
  for (let child = node[NEXT]; child !== node[END]; child = (child[END] || child)[NEXT]) {
    if (child.nodeType === 3 || child.nodeType === 4) text += child[VALUE];
  }
  return text;
}

export function installScriptMutations(L, changed) {
  let depth = 0, candidates = [];
  setDOMCallbackBoundary(callback => {
    const outerDepth = depth, outerCandidates = candidates;
    depth = 0; candidates = [];
    try { return callback(); }
    finally { depth = outerDepth; candidates = outerCandidates; }
  });
  const note = node => { if (node && scriptRecord(node)) add(candidates, node); };
  const collect = node => {
    if (!node || !node[NEXT]) { note(node); return; }
    const stop = (node[END] || node)[NEXT];
    for (let current = node; current !== stop; current = current[NEXT]) {
      note(current);
      const root = shadow(current)?.shadowRoot;
      if (root) collect(root);
    }
  };
  const finish = () => {
    if (--depth) return;
    const nodes = candidates;
    candidates = [];
    changed(nodes);
  };
  const wrap = (proto, key, after) => {
    const original = proto[key];
    if (typeof original !== 'function') return;
    proto[key] = function (...args) {
      depth++;
      try {
        const result = apply(original, this, args);
        if (after) after(this, args);
        return result;
      } finally { finish(); }
    };
  };
  const setter = (proto, key, after) => {
    const d = descriptor(proto, key);
    if (!d?.set) return;
    define(proto, key, { ...d, set(value) {
      depth++;
      try { apply(d.set, this, [value]); after(this); }
      finally { finish(); }
    } });
  };
  const parent = Object.getPrototypeOf(L.Element.prototype);
  const attach = L.Element.prototype.attachShadow;
  L.Element.prototype.attachShadow = function (options) {
    const root = apply(attach, this, [options]);
    rememberHost(root, this);
    return root;
  };
  const insert = parent.insertBefore;
  parent.insertBefore = function (node, before = null) {
    depth++;
    // Keep candidates separate until the primitive actually succeeds.
    const outer = candidates;
    candidates = [];
    if (node !== before) collect(node);
    const inserted = candidates;
    candidates = outer;
    try {
      const oldParent = node?.parentNode;
      const result = apply(insert, this, [node, before]);
      if (node !== before) {
        for (let i = 0; i < inserted.length; i++) note(inserted[i]);
        note(oldParent); note(this);
      }
      return result;
    } finally { finish(); }
  };
  for (const key of ['append', 'prepend', 'replaceChildren', 'appendChild', 'replaceChild', 'removeChild']) wrap(parent, key);
  const character = Object.getPrototypeOf(L.Text.prototype);
  for (const proto of [L.Element.prototype, character, L.DocumentType.prototype]) {
    for (const key of ['before', 'after', 'replaceWith']) wrap(proto, key);
    const remove = proto.remove;
    if (typeof remove === 'function') proto.remove = function () {
      depth++;
      const oldParent = this.parentNode;
      try { const result = apply(remove, this, []); note(oldParent); return result; }
      finally { finish(); }
    };
  }
  for (const proto of [L.Element.prototype, L.DocumentFragment.prototype]) setter(proto, 'textContent', note);
  setter(character, 'data', node => { if (node.nodeType === 3 || node.nodeType === 4) note(node.parentNode); });
  const sourceAttribute = (node, name) => {
    const identity = scriptRecord(node)?.identity;
    return identity && (identity.namespace === 'http://www.w3.org/2000/svg'
      ? name === 'href' || name === 'xlink:href' : name === 'src');
  };
  const setAttribute = L.Element.prototype.setAttribute;
  L.Element.prototype.setAttribute = function (name, value) {
    depth++;
    try {
      if (scriptRecord(this)) {
        name = String(name); value = String(value);
        if (scriptRecord(this).identity.namespace === 'http://www.w3.org/1999/xhtml' && documentMode(this.ownerDocument) !== undefined) name = lowerASCII(name);
      }
      const result = apply(setAttribute, this, [name, value]);
      if (sourceAttribute(this, name)) note(this);
      return result;
    } finally { finish(); }
  };
  wrap(L.Element.prototype, 'setAttributeNode', (node, args) => { if (sourceAttribute(node, args[0]?.name)) note(node); });
  setter(L.Attr.prototype, 'value', attr => { if (attr.ownerElement && sourceAttribute(attr.ownerElement, attr.name)) note(attr.ownerElement); });
}
