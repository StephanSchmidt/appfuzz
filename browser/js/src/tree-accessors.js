import { nameIdentity } from './names.js';
import { attributeInfo } from './attribute-state.js';
import { doctypeInfo } from './doctype-state.js';
import { collectionHTMLDocument } from './collection-data.js';
// DOM tree accessors observe physical links, not page shadows of nodeType,
// firstChild, lastChild or parentNode. Root lookup crosses a shadow only when
// the caller requests a composed root.
import { Node } from '../node_modules/linkedom/esm/interface/node.js';
import { ParentNode } from '../node_modules/linkedom/esm/mixin/parent-node.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { SVGElement } from '../node_modules/linkedom/esm/svg/element.js';
import { CharacterData } from '../node_modules/linkedom/esm/interface/character-data.js';
import { END, NEXT, PREV, START } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nodeInfo, physicalParent, physicalRoot, shadowInfo, nodeDocument, physicalOwnerSVG } from './dom-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const upper = Function.prototype.call.bind(String.prototype.toUpperCase);
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
  const svg = { get ownerSVGElement() { requireNode(this); if (nameIdentity(this)?.namespace !== 'http://www.w3.org/2000/svg') throw new NativeTypeError('An SVGElement is required'); return physicalOwnerSVG(this); } };
  define(SVGElement.prototype,'ownerSVGElement',{ ...describe(svg,'ownerSVGElement'), enumerable: true });
  const fields = {
    get nodeName() { requireNode(this); const data = nodeInfo(this), kind = data.kind;
      if (kind === 1) { const id = nameIdentity(this); if (!id) return data.local; if (id.namespace !== 'http://www.w3.org/1999/xhtml' || !collectionHTMLDocument(nodeDocument(this))) return id.qualified; let result = ''; for (let i = 0; i < id.qualified.length; i++) { const c = id.qualified[i]; result += c >= 'a' && c <= 'z' ? upper(c) : c; } return result; }
      if (kind === 2) return attributeInfo(this).qualified; if (kind === 10) return doctypeInfo(this).name;
      return kind === 3 ? '#text' : kind === 4 ? '#cdata-section' : kind === 7 ? data.local : kind === 8 ? '#comment' : kind === 9 ? '#document' : '#document-fragment';
    },
    get ownerDocument() { requireNode(this); return nodeInfo(this).kind === 9 ? null : nodeDocument(this); },
    get parentNode() { requireNode(this); return physicalParent(this); },
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
