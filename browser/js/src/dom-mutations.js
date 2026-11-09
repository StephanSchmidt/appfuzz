// Shared tree primitives observe physical identity and links. They never call
// a child's public remove/parentNode/nodeType properties during a native edit.
import { END, NEXT, PREV } from '../node_modules/linkedom/esm/shared/symbols.js';
import { setAdjacent, knownSiblings } from '../node_modules/linkedom/esm/shared/utils.js';
import { nodeInfo, nodeDocument, physicalParent, physicalPreviousSibling, physicalNextSibling } from './dom-state.js';
import { backendList, backendChildNodes } from './collection-data.js';
import { retainRemovedSubtree, childMutation } from './mutation-observers.js';
import { connectionReaction } from './ce-hooks.js';
import { DOMException } from './dom-exception.js';
import { withReactions } from './ce-reactions.js';
const NativeTypeError = TypeError, define = Object.defineProperty;
let newText, changed = () => {};
export function installChildrenChangedHook(callback) { changed = callback; }
export function childrenChanged(node) { if (node) changed(node); }
function requireNode(node) { if (!nodeInfo(node)) throw new NativeTypeError('A Node is required'); }
export function removeNativeNode(node, notify = true) {
  requireNode(node); const parent = physicalParent(node); if (!parent) return;
  const previous = physicalPreviousSibling(node), next = physicalNextSibling(node), end = node[END] || node;
  retainRemovedSubtree(node, parent); setAdjacent(node[PREV], end[NEXT]); node[PREV] = null; end[NEXT] = null;
  if (notify) childMutation(parent, backendList(), [node], previous, next);
  if (nodeInfo(node).kind === 1) connectionReaction(node, false);
  if (notify) childrenChanged(parent);
}
export function createNativeText(document, value) { return newText(document, value); }
export function insertNativeText(parent, text, before = null, notify = true) {
  const next = before || parent[END], previous = before ? physicalPreviousSibling(before) : backendChildNodes(parent).at(-1) || null;
  knownSiblings(next[PREV], text, next);
  if (notify) { childMutation(parent, [text], backendList(), previous, before); childrenChanged(parent); }
}
export function replaceAllText(parent, value) {
  const removed = backendChildNodes(parent), added = backendList(); if (value !== '') added[0] = newText(nodeDocument(parent), value);
  for (let i = 0; i < removed.length; i++) removeNativeNode(removed[i], false);
  if (added.length) insertNativeText(parent, added[0], null, false);
  if (removed.length || added.length) { childMutation(parent, added, removed, null, null); childrenChanged(parent); }
}
export function installDOMMutations(L) {
  const createText = L.Document.prototype.createTextNode, apply = Reflect.apply; newText = (document,value) => apply(createText,document,[value]);
  const removeChild = function (node) { return withReactions(() => { requireNode(this); if (!arguments.length) throw new NativeTypeError('A child is required'); requireNode(node); if (physicalParent(node) !== this) throw new DOMException('The node is not a child', 'NotFoundError'); removeNativeNode(node); return node; }); };
  for (const prototype of [L.Node.prototype,Object.getPrototypeOf(L.Element.prototype)]) define(prototype,'removeChild',{ __proto__: null, value: removeChild, enumerable: true, configurable: true, writable: true });
}
