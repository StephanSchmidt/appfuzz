import { backendList } from './collection-data.js';
import { nodeInfo, nodeDocument, physicalParent, shadowInfo } from './dom-state.js';
import { attributeInfo } from './attribute-state.js';
import { attributeMethods } from './attributes.js';
import { removeNativeNode, installTreeAdoption } from './dom-mutations.js';
import { setNodeDocument } from './attribute-state.js';
// Linkedom moves node ranges without adopting them. Use its private ranges
// and shadow-root/element records so attributes and closed trees move too.
import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
import { customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { templateContent, templateOwner } from './templates.js';
import { upgradeInserted, upgradeDefinition } from './upgrading.js';
import { enqueueReaction, withReactions, setReactionErrorHandler } from './ce-reactions.js';
import { elementDefinition } from './element-state.js';
import { installCEHooks } from './ce-hooks.js';
import { shadowTreeNodes } from './shadow-tree.js';

const shadowRoot = shadowRoots.get.bind(shadowRoots);
const customElement = customElements.get.bind(customElements);
const apply = Reflect.apply, removeAttribute = attributeMethods.removeAttributeNode;
let nativeAdopter;
export function adoptNativeNode(document,node) { return nativeAdopter(document,node); }

function treeNodes(root, document) {
  const nodes = backendList(), pending = backendList(); pending[0] = { __proto__: null, node: root, stop: (root[END] || root)[NEXT], document };
  while (pending.length) {
    const job = pending.pop(); let node = job.node; const stop = job.stop, document = job.document;
    while (node !== stop) {
      nodes[nodes.length] = { __proto__: null, node, document };
      const content = templateContent(node), shadow = shadowRoot(node)?.shadowRoot;
      if (content || shadow) {
        pending[pending.length] = { __proto__: null, node: node[NEXT], stop, document };
        if (content) pending[pending.length] = { __proto__: null, node: content, stop: content[END][NEXT], document: templateOwner(document) };
        if (shadow) pending[pending.length] = { __proto__: null, node: shadow, stop: shadow[END][NEXT], document };
        break;
      }
      node = node[NEXT];
    }
  }
  return nodes;
}

export function installAdoption(Element, shareObservers, onError, DOMError) {
  const connected = Object.getOwnPropertyDescriptor(Element.prototype, 'isConnected').get;
  const connectedNode = Function.prototype.call.bind(connected);
  // Physical ranges include end markers, which are not DOM Nodes.
  const isConnected = node => !!nodeInfo(node) && connectedNode(node);
  const callbackKeys = { connectedCallback: 'connected', disconnectedCallback: 'disconnected', adoptedCallback: 'adopted', attributeChangedCallback: 'attribute' };
  const enqueue = (node, name, args = [], selected) => {
    const definition = elementDefinition(node);
    const callback = selected !== undefined ? selected : definition ? definition[callbackKeys[name]] : node[name];
    enqueueReaction(node, callback, args);
  };
  const queueUpgrade = (node, prepared) => {
    const definition = prepared === undefined ? upgradeDefinition(node) : prepared;
    if (!definition) return;
    enqueueReaction(node, () => withReactions(() => upgradeInserted(node, isConnected, enqueue, onError, true, definition, DOMError)));
  };
  nativeAdopter = (document,node,internal = false) => withReactions(() => {
    if (nodeInfo(node)?.kind === 9) throw new DOMError('Documents cannot be adopted','NotSupportedError');
    if (internal && shadowInfo(node)) return node;
    if (shadowInfo(node)) throw new DOMError('Shadow roots cannot be adopted','HierarchyRequestError');
    shareObservers(document); shareObservers(nodeDocument(node));
    if (internal && nodeDocument(node) === document && (!node[END] || node[END].ownerDocument === document)) { if (physicalParent(node)) removeNativeNode(node); return node; }
    const nodes = treeNodes(node,document), oldDocuments = backendList();
    for (let i = 0; i < nodes.length; i++) oldDocuments[i] = nodeDocument(nodes[i].node);
    const attr = attributeInfo(node);
    if (attr?.owner) apply(removeAttribute,attr.owner,[node]);
    else if (physicalParent(node)) removeNativeNode(node);
    for (let i = 0; i < nodes.length; i++) {
      const item = nodes[i]; setNodeDocument(item.node,item.document);
      const info = customElement(item.node);
      if (info && oldDocuments[i] !== item.document) { info.owner = item.document; enqueue(item.node,'adoptedCallback',[oldDocuments[i],item.document]); }
    }
    return node;
  });
  setReactionErrorHandler(onError);
  const includes = Function.prototype.call.bind(Array.prototype.includes);
  installCEHooks((node, name, oldValue, value, namespace) => {
    const definition = elementDefinition(node);
    if (customElement(node) && definition && includes(definition.observed, name)) withReactions(() => enqueue(node, 'attributeChangedCallback', [name, oldValue, value, namespace]));
  }, root => {
    const nodes = shadowTreeNodes(root);
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i], info = customElement(node);
      if (!info) continue;
      const now = isConnected(node);
      if (now !== info.connected) {
        info.connected = now;
        enqueue(node, now ? 'connectedCallback' : 'disconnectedCallback');
      }
    }
  });
  installTreeAdoption((document,node) => nativeAdopter(document,node,true), root => {
    const nodes = shadowTreeNodes(root);
    for (let i = 0; i < nodes.length; i++) if (isConnected(nodes[i])) queueUpgrade(nodes[i]);
  });
  // cloneNode/importNode queue upgrades as they create elements, then run
  // them only after the complete detached copy has its attributes/children.
  const upgradeCopies = (nodes, registry) => withReactions(() => {
    const definitions = [];
    for (let i = 0; i < nodes.length; i++) definitions[i] = upgradeDefinition(nodes[i], registry);
    for (let i = 0; i < nodes.length; i++) queueUpgrade(nodes[i], definitions[i]);
  });
  upgradeCopies.tree = (root, registry) => upgradeCopies(shadowTreeNodes(root), registry);
  return upgradeCopies;
}
