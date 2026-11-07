// Linkedom moves node ranges without adopting them. Use its private ranges
// and shadow-root/element records so attributes and closed trees move too.
import { END, NEXT, PREV } from '../node_modules/linkedom/esm/shared/symbols.js';
import { getEnd } from '../node_modules/linkedom/esm/shared/utils.js';
import { remove as unlink } from '../node_modules/linkedom/esm/mixin/child-node.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
import { customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { templateContent, templateOwner } from './templates.js';
import { upgradeInserted, upgradeDefinition } from './upgrading.js';
import { enqueueReaction, withReactions, setReactionErrorHandler } from './ce-reactions.js';
import { elementDefinition } from './element-state.js';
import { installCEHooks } from './ce-hooks.js';
import { shadowTreeNodes } from './shadow-tree.js';

// Takes any node out of its parent, as Element and CharacterData's own
// remove() do: an element ends at its end tag, text and comments at
// themselves. Element.prototype.remove alone breaks on a text node.
const detach = (node) => unlink(node[PREV], node, getEnd(node)[NEXT]);

const shadowRoot = shadowRoots.get.bind(shadowRoots);
const customElement = customElements.get.bind(customElements);

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
  const callbackKeys = { connectedCallback: 'connected', disconnectedCallback: 'disconnected', adoptedCallback: 'adopted', attributeChangedCallback: 'attribute' };
  const enqueue = (node, name, args = [], selected) => {
    const definition = elementDefinition(node);
    const callback = selected !== undefined ? selected : definition ? definition[callbackKeys[name]] : node[name];
    enqueueReaction(node, callback, args);
  };
  const queueUpgrade = (node, prepared) => {
    const definition = prepared === undefined ? upgradeDefinition(node) : prepared;
    if (!definition) return;
    enqueueReaction(node, () => withReactions(() => upgradeInserted(node, isConnected, enqueue, onError, true, definition)));
  };
  setReactionErrorHandler(onError);
  const includes = Function.prototype.call.bind(Array.prototype.includes);
  installCEHooks((node, name, oldValue, value) => {
    const definition = elementDefinition(node);
    if (definition && includes(definition.observed, name)) withReactions(() => enqueue(node, 'attributeChangedCallback', [name, oldValue, value, null]));
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
      for (const { node } of nodes) if (isConnected(node)) queueUpgrade(node);
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
      for (const { node } of nodes) if (inserting && isConnected(node)) queueUpgrade(node);
    }
  };
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
