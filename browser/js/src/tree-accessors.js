// DOM tree accessors observe physical links, not page shadows of nodeType,
// firstChild, lastChild or parentNode. Root lookup crosses a shadow only when
// the caller requests a composed root.
import { Node } from '../node_modules/linkedom/esm/interface/node.js';
import { ParentNode } from '../node_modules/linkedom/esm/mixin/parent-node.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { CharacterData } from '../node_modules/linkedom/esm/interface/character-data.js';
import { END, NEXT, PREV, START } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nodeInfo, physicalParent, physicalRoot, shadowInfo } from './dom-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const define = Object.defineProperty, describe = Object.getOwnPropertyDescriptor, keys = Reflect.ownKeys, NativeTypeError = TypeError;
function requireNode(node) { if (!nodeInfo(node)) throw new NativeTypeError('A Node is required'); }
function requireParent(node) { const kind = nodeInfo(node)?.kind; if (kind !== 1 && kind !== 9 && kind !== 11) throw new NativeTypeError('A ParentNode is required'); }
function first(node) { if (!node[END]) return null; let value = node[NEXT]; while (nodeInfo(value)?.kind === 2) value = value[NEXT]; return value === node[END] ? null : value; }
function last(node) { if (!node[END]) return null; const value = node[END][PREV]; if (value === node || nodeInfo(value)?.kind === 2) return null; return value[START] || value; }
function next(node) { if (!physicalParent(node)) return null; const value = (node[END] || node)[NEXT]; return nodeInfo(value) ? value : null; }
function previous(node) { if (!physicalParent(node)) return null; const value = node[PREV]; if (value?.[START]) return value[START]; const kind = nodeInfo(value)?.kind; return kind === 3 || kind === 4 || kind === 7 || kind === 8 || kind === 10 ? value : null; }
function element(node, step) { for (let value = node; value; value = step(value)) if (nodeInfo(value)?.kind === 1) return value; return null; }
function root(node, composed) { let value = physicalRoot(node), shadow; while (composed && (shadow = shadowInfo(value))) value = physicalRoot(shadow.host); return value; }
export function installTreeAccessors() {
  const fields = {
    get firstChild() { requireNode(this); return first(this); },
    get lastChild() { requireNode(this); return last(this); },
    get parentElement() { requireNode(this); const parent = physicalParent(this); return nodeInfo(parent)?.kind === 1 ? parent : null; },
    get nextSibling() { requireNode(this); return next(this); },
    get previousSibling() { requireNode(this); return previous(this); },
    get nextElementSibling() { requireNode(this); return element(next(this), next); },
    get previousElementSibling() { requireNode(this); return element(previous(this), previous); },
    get isConnected() { requireNode(this); return nodeInfo(root(this, true))?.kind === 9; },
  };
  for (const key of keys(fields)) for (const prototype of [Node.prototype, Element.prototype, CharacterData.prototype]) {
    if (prototype === Node.prototype || describe(prototype, key)) define(prototype, key, { ...describe(fields, key), enumerable: true });
  }
  for (const key of ['firstChild', 'lastChild']) define(ParentNode.prototype, key, { ...describe(fields, key), enumerable: true });
  const parents = {
    get firstElementChild() { requireParent(this); return element(first(this), next); },
    get lastElementChild() { requireParent(this); return element(last(this), previous); },
    get childElementCount() { requireParent(this); let count = 0; for (let value = first(this); value; value = next(value)) if (nodeInfo(value)?.kind === 1) count++; return count; },
  };
  for (const key of keys(parents)) define(ParentNode.prototype, key, { ...describe(parents, key), enumerable: true });
  const methods = {
    hasChildNodes() { requireNode(this); return first(this) !== null; },
    getRootNode(options = undefined) { requireNode(this); const composed = runDOMCallback(() => { if (options == null) return false; if (typeof options !== 'object' && typeof options !== 'function') throw new NativeTypeError('Root options must be a dictionary'); return !!options.composed; }); return root(this, composed); },
  };
  for (const key of keys(methods)) define(Node.prototype, key, { ...describe(methods, key), enumerable: true });
}
