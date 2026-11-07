// Linkedom moves node ranges without adopting them. Use its private ranges
// and shadow-root/element records so attributes and closed trees move too.
import { END, NEXT, PREV } from '../node_modules/linkedom/esm/shared/symbols.js';
import { getEnd } from '../node_modules/linkedom/esm/shared/utils.js';
import { remove as unlink } from '../node_modules/linkedom/esm/mixin/child-node.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
import { customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { templateContent, templateOwner } from './templates.js';
import { upgradeInserted } from './upgrading.js';
import { runDOMCallback } from './dom-callbacks.js';

// Takes any node out of its parent, as Element and CharacterData's own
// remove() do: an element ends at its end tag, text and comments at
// themselves. Element.prototype.remove alone breaks on a text node.
const detach = (node) => unlink(node[PREV], node, getEnd(node)[NEXT]);

const shadowRoot = shadowRoots.get.bind(shadowRoots);
const customElement = customElements.get.bind(customElements);
const queues = new WeakMap();
const reactionQueue = queues.get.bind(queues);
const rememberQueue = queues.set.bind(queues);

function treeNodes(root, document) {
  const nodes = [];
  const pending = [[root, (root[END] || root)[NEXT], document]];
  while (pending.length) {
    let [node, stop, document] = pending.pop();
    while (node !== stop) {
      nodes.push({ node, document });
      const content = templateContent(node);
      const shadow = shadowRoot(node)?.shadowRoot;
      if (content || shadow) {
        pending.push([node[NEXT], stop, document]);
        if (content) pending.push([content, content[END][NEXT], templateOwner(document)]);
        if (shadow) pending.push([shadow, shadow[END][NEXT], document]);
        break;
      }
      node = node[NEXT];
    }
  }
  return nodes;
}

export function installAdoption(Element, shareObservers, onError) {
  const parent = Object.getPrototypeOf(Element.prototype);
  const insert = parent.insertBefore;
  const connected = Object.getOwnPropertyDescriptor(Element.prototype, 'isConnected').get;
  const isConnected = Function.prototype.call.bind(connected);
  const invoke = (node, name, callback, args) => {
    try {
      runDOMCallback(() => callback.apply(node, args));
    } catch (e) { onError(name, e); }
  };
  const enqueue = (node, name, args = [], selected) => {
    try {
      const callback = selected === undefined ? node[name] : selected;
      if (typeof callback !== 'function') return;
      let queue = reactionQueue(node);
      if (!queue) rememberQueue(node, queue = { items: [], at: 0 });
      queue.items.push([name, callback, args]);
    } catch (e) { onError(name, e); }
  };
  const flush = (node) => {
    const queue = reactionQueue(node);
    if (!queue) return;
    // A callback may adopt another element whose earlier reactions are
    // already queued. Nested operations drain that same element queue.
    while (queue.at < queue.items.length) {
      const [name, callback, args] = queue.items[queue.at++];
      invoke(node, name, callback, args);
    }
    queue.items.length = queue.at = 0;
  };
  parent.insertBefore = function (node, before = null) {
    // Preserve the native no-op and self-insertion error. All ParentNode
    // and ChildNode insertion methods converge on this operation.
    if (node === before || node === this) return insert.call(this, node, before);
    const document = this.nodeType === 9 ? this : this.ownerDocument;
    shareObservers(document);
    shareObservers(node?.ownerDocument);
    if (!document || !node) {
      return insert.call(this, node, before);
    }
    const nodes = treeNodes(node, document);
    // A native XML setter/import can update just the public root owner,
    // leaving its end marker, attributes and descendants in the old document.
    if (node.ownerDocument === document && (!node[END] || node[END].ownerDocument === document)) {
      const result = insert.call(this, node, before);
      for (const { node } of nodes) { upgradeInserted(node, isConnected, enqueue, onError); flush(node); }
      return result;
    }
    const reactions = [];
    for (const { node: descendant } of nodes) {
      const info = customElement(descendant);
      if (info) reactions.push({ node: descendant, info, oldDocument: descendant.ownerDocument, wasConnected: connected.call(descendant) });
    }
    const oldParent = node.parentNode;
    let inserting = false;
    try {
      // Queue reactions across removal/adoption/insertion; callbacks must
      // observe the completed DOM operation. Removal observers still use
      // the old owner document before ownership changes.
      for (const reaction of reactions) reaction.info.connected = false;
      if (oldParent) detach(node);
      for (const { node: descendant, document: owner } of nodes) { shareObservers(owner); descendant.ownerDocument = owner; }
      for (const reaction of reactions) reaction.info.connected = true;
      inserting = true;
      return insert.call(this, node, before);
    } finally {
      const removed = oldParent && node.parentNode !== oldParent;
      for (const reaction of reactions) {
        reaction.isConnected = connected.call(reaction.node);
        reaction.newDocument = reaction.node.ownerDocument;
        reaction.info.connected = reaction.isConnected;
      }
      for (const reaction of reactions) {
        const { node: element, oldDocument, newDocument, wasConnected, isConnected } = reaction;
        if (wasConnected && removed) enqueue(element, 'disconnectedCallback');
        if (newDocument !== oldDocument) enqueue(element, 'adoptedCallback', [oldDocument, newDocument]);
        if (inserting && isConnected) enqueue(element, 'connectedCallback');
      }
      for (const { node } of nodes) { if (inserting) upgradeInserted(node, isConnected, enqueue, onError); flush(node); }
    }
  };
}
