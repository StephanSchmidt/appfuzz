// Web IDL converts the entire variadic union before any DOM algorithm runs.
// Native tree steps use private identity and captured operations throughout.
import { nodeInfo, nodeDocument, physicalParent, physicalFirstChild, physicalPreviousSibling, physicalNextSibling } from './dom-state.js';
import { backendList } from './collection-data.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { withReactions } from './ce-reactions.js';
import { withScriptMutationBatch } from './script-mutations.js';
import { createNativeText, preInsert, replaceTreeChild, replaceTreeChildren } from './dom-mutations.js';
const NativeTypeError = TypeError, define = Object.defineProperty, apply = Reflect.apply;
function requireNode(node) { if (!nodeInfo(node)) throw new NativeTypeError('A Node is required'); }
function requireParent(node, expected) { const kind = nodeInfo(node)?.kind; if (expected ? kind !== expected : kind !== 1 && kind !== 9 && kind !== 11) throw new NativeTypeError('A ParentNode is required'); }
function requireChild(node, expected) { const kind = nodeInfo(node)?.kind; if (expected === 'character' ? kind !== 3 && kind !== 4 && kind !== 7 && kind !== 8 : kind !== expected) throw new NativeTypeError('A ChildNode is required'); }
function convert(args) {
  return runDOMCallback(() => { const nodes = backendList(); for (let i = 0; i < args.length; i++) nodes[i] = nodeInfo(args[i]) ? args[i] : eventString(args[i]); return nodes; });
}
function operation(callback) { return withReactions(() => withScriptMutationBatch(callback)); }
function install(prototype,key,value) { define(prototype,key,{ __proto__: null, value, configurable: true, writable: true, enumerable: true }); }
export function installMultiNode(L) {
  const createFragment = L.Document.prototype.createDocumentFragment;
  const asNode = (document,nodes) => {
    for (let i = 0; i < nodes.length; i++) if (typeof nodes[i] === 'string') nodes[i] = createNativeText(document,nodes[i]);
    if (nodes.length === 1) return nodes[0];
    const fragment = apply(createFragment,document,[]);
    for (let i = 0; i < nodes.length; i++) preInsert(nodes[i],fragment);
    return fragment;
  };
  const parent = Object.getPrototypeOf(L.Element.prototype), character = Object.getPrototypeOf(L.Text.prototype);
  const insertBefore = function (node,child) { requireNode(this); if (arguments.length < 2) throw new NativeTypeError('Two arguments are required'); requireNode(node); if (child == null) child = null; else requireNode(child); return operation(() => preInsert(node,this,child)); };
  const appendChild = function (node) { requireNode(this); if (!arguments.length) throw new NativeTypeError('A Node is required'); requireNode(node); return operation(() => preInsert(node,this)); };
  const replaceChild = function (node,child) { requireNode(this); if (arguments.length < 2) throw new NativeTypeError('Two Nodes are required'); requireNode(node); requireNode(child); return operation(() => replaceTreeChild(this,node,child)); };
  for (const proto of [L.Node.prototype,parent]) { install(proto,'insertBefore',insertBefore); install(proto,'appendChild',appendChild); install(proto,'replaceChild',replaceChild); }
  for (const [prototype,kind] of [[parent,undefined],[L.Element.prototype,1],[L.Document.prototype,9],[L.DocumentFragment.prototype,11]]) for (const key of ['append','prepend','replaceChildren']) install(prototype,key,function (...args) {
    requireParent(this,kind); const nodes = convert(args);
    return operation(() => {
      const node = asNode(nodeDocument(this),nodes);
      if (key === 'replaceChildren') replaceTreeChildren(this,node);
      else preInsert(node,this,key === 'prepend' ? physicalFirstChild(this) : null);
    });
  });
  for (const [proto,kind] of [[L.Element.prototype,1],[character,'character'],[L.DocumentType.prototype,10]]) for (const key of ['before','after','replaceWith']) install(proto,key,function (...args) {
    requireChild(this,kind); const nodes = convert(args);
    return operation(() => {
      const parent = physicalParent(this); if (!parent) return;
      let reference = key === 'before' ? physicalPreviousSibling(this) : physicalNextSibling(this);
      while (reference && nodes.includes(reference)) reference = key === 'before' ? physicalPreviousSibling(reference) : physicalNextSibling(reference);
      const node = asNode(nodeDocument(this),nodes);
      if (key === 'before') reference = reference ? physicalNextSibling(reference) : physicalFirstChild(parent);
      if (key === 'replaceWith' && physicalParent(this) === parent) replaceTreeChild(parent,node,this);
      else preInsert(node,parent,reference);
    });
  });
}
