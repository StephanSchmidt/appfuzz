// Shared tree primitives observe physical identity and links. They never call
// a child's public remove/parentNode/nodeType properties during a native edit.
import { END, NEXT, PREV } from '../node_modules/linkedom/esm/shared/symbols.js';
import { setAdjacent, knownSiblings, knownBoundaries } from '../node_modules/linkedom/esm/shared/utils.js';
import { nodeInfo, nodeDocument, physicalParent, physicalPreviousSibling, physicalNextSibling, physicalLastChild, shadowAncestor, rememberNodeParent } from './dom-state.js';
import { backendList, backendChildNodes } from './collection-data.js';
import { retainRemovedSubtree, childMutation } from './mutation-observers.js';
import { connectionReaction } from './ce-hooks.js';
import { DOMException } from './dom-exception.js';
import { withReactions } from './ce-reactions.js';
const NativeTypeError = TypeError, define = Object.defineProperty;
let newText, changed = () => {}, adopt, upgrade, inserted = () => {};
export function installTreeAdoption(onAdopt, onUpgrade) { adopt = onAdopt; upgrade = onUpgrade; }
export function installInsertedTreeHook(callback) { inserted = callback; }
export function installChildrenChangedHook(callback) { changed = callback; }
export function childrenChanged(node) { if (node) changed(node); }
function requireNode(node) { if (!nodeInfo(node)) throw new NativeTypeError('A Node is required'); }
export function removeNativeNode(node, notify = true) {
  requireNode(node); const parent = physicalParent(node); if (!parent) return;
  const previous = physicalPreviousSibling(node), next = physicalNextSibling(node), end = node[END] || node;
  retainRemovedSubtree(node, parent); setAdjacent(node[PREV], end[NEXT]); node[PREV] = null; end[NEXT] = null; rememberNodeParent(node,null);
  if (notify) childMutation(parent, backendList(), [node], previous, next);
  if (nodeInfo(node).kind === 1) connectionReaction(node, false);
  if (notify) childrenChanged(parent);
}
export function createNativeText(document, value) { return newText(document, value); }
export function insertNativeText(parent, text, before = null, notify = true) {
  const next = before || parent[END], previous = before ? physicalPreviousSibling(before) : physicalLastChild(parent);
  knownSiblings(next[PREV], text, next);
  if (notify) { childMutation(parent, [text], backendList(), previous, before); childrenChanged(parent); }
}
export function insertNativeNode(parent,node,before = null,notify = true) {
  const next = before || parent[END], previous = before ? physicalPreviousSibling(before) : physicalLastChild(parent);
  knownBoundaries(next[PREV],node,next);
  if (notify) childMutation(parent,[node],backendList(),previous,before);
  if (nodeInfo(node)?.kind === 1) connectionReaction(node,true);
  if (notify) childrenChanged(parent);
}
// DOM pre-insertion validation precedes adoption, removal, and script work.
// Replacement can exclude its old child when checking document constraints.
export function ensureInsertion(node, parent, child, excluded = backendList()) {
  const kind = nodeInfo(node)?.kind, parentKind = nodeInfo(parent)?.kind;
  const hierarchy = () => { throw new DOMException('The insertion would violate the node tree', 'HierarchyRequestError'); };
  if (parentKind !== 1 && parentKind !== 9 && parentKind !== 11) hierarchy();
  if (shadowAncestor(node,parent)) hierarchy();
  if (child !== null && physicalParent(child) !== parent) throw new DOMException('The reference is not a child', 'NotFoundError');
  if (kind !== 1 && kind !== 3 && kind !== 4 && kind !== 7 && kind !== 8 && kind !== 10 && kind !== 11) hierarchy();
  if (parentKind !== 9) { if (kind === 10) hierarchy(); return; }
  if (kind === 3 || kind === 4) hierarchy();
  if (kind === 7 || kind === 8) return;
  if (kind === 11) {
    const nodes = backendChildNodes(node); let elements = 0;
    for (let i = 0; i < nodes.length; i++) { const type = nodeInfo(nodes[i]).kind; if (type === 3 || type === 4 || (type === 1 && ++elements > 1)) hierarchy(); }
    if (!elements) return;
  }
  const children = backendChildNodes(parent);
  if (kind === 1 || kind === 11) {
    for (let i = 0; i < children.length; i++) if (nodeInfo(children[i]).kind === 1 && !excluded.includes(children[i])) hierarchy();
    for (let n = child; n; n = physicalNextSibling(n)) if (nodeInfo(n).kind === 10 && (n !== child || !excluded.includes(n))) hierarchy();
  } else {
    for (let i = 0; i < children.length; i++) if (nodeInfo(children[i]).kind === 10 && !excluded.includes(children[i])) hierarchy();
    if (child) { for (let n = physicalPreviousSibling(child); n; n = physicalPreviousSibling(n)) if (nodeInfo(n).kind === 1) hierarchy(); }
    else for (let i = 0; i < children.length; i++) if (nodeInfo(children[i]).kind === 1 && !excluded.includes(children[i])) hierarchy();
  }
}
export function insertionNodes(node) { if (nodeInfo(node).kind === 11) return backendChildNodes(node); const nodes = backendList(); nodes[0] = node; return nodes; }
export function insertTree(parent,node,before = null,notify = true) {
  const nodes = insertionNodes(node); if (!nodes.length) return;
  if (nodeInfo(node).kind === 11) {
    for (let i = 0; i < nodes.length; i++) removeNativeNode(nodes[i],false);
    // Fragment removal is observable even when a replacement suppresses its
    // destination's individual records. Transient registrations survive it.
    childMutation(node,backendList(),nodes,null,null); childrenChanged(node);
  }
  const document = nodeDocument(parent), fragment = nodeInfo(node).kind === 11;
  if (!fragment) adopt(document,node);
  const previous = before ? physicalPreviousSibling(before) : physicalLastChild(parent);
  for (let i = 0; i < nodes.length; i++) {
    if (fragment) adopt(document,nodes[i]);
    insertNativeNode(parent,nodes[i],before,false); upgrade(nodes[i]);
  }
  if (notify) childMutation(parent,nodes,backendList(),previous,before);
  for (let i = 0; i < nodes.length; i++) inserted(nodes[i]);
  childrenChanged(parent);
}
export function preInsert(node,parent,before = null) {
  ensureInsertion(node,parent,before);
  if (node === before) before = physicalNextSibling(node);
  insertTree(parent,node,before); return node;
}
export function replaceTreeChild(parent,node,child) {
  const excluded = backendList(); excluded[0] = child; ensureInsertion(node,parent,child,excluded);
  let next = physicalNextSibling(child); if (next === node) next = physicalNextSibling(node);
  const previous = physicalPreviousSibling(child), removed = backendList();
  // Insertion consumes a fragment's children without adopting its container.
  if (nodeInfo(node).kind !== 11) adopt(nodeDocument(parent),node);
  if (physicalParent(child)) { removed[0] = child; removeNativeNode(child,false); }
  const added = insertionNodes(node); insertTree(parent,node,next,false);
  childMutation(parent,added,removed,previous,next); childrenChanged(parent); return child;
}
export function replaceTreeChildren(parent,node) {
  const removed = backendChildNodes(parent); ensureInsertion(node,parent,null);
  const added = insertionNodes(node);
  for (let i = 0; i < removed.length; i++) removeNativeNode(removed[i],false);
  insertTree(parent,node,null,false);
  if (added.length || removed.length) childMutation(parent,added,removed,null,null);
  childrenChanged(parent);
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
