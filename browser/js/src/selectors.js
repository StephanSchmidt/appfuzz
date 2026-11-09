// Template contents have their own private tree. Query snapshots and traversal
// use physical nodes independently of public childNodes and iterator shadows.
import { ParentNode } from '../node_modules/linkedom/esm/mixin/parent-node.js';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { prepareMatch } from '../node_modules/linkedom/esm/shared/matches.js';
import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { staticNodeList } from './collections.js';
import { backendList } from './collection-data.js';
import { nodeInfo, physicalDocumentElement } from './dom-state.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
const NativeTypeError = TypeError, define = Object.defineProperty;
function match(root, selectors, count) {
  const kind = nodeInfo(root)?.kind;
  if (kind !== 1 && kind !== 9 && kind !== 11) throw new NativeTypeError('A ParentNode is required');
  if (!count) throw new NativeTypeError('Not enough arguments');
  selectors = runDOMCallback(() => eventString(selectors));
  const context = kind === 9 ? physicalDocumentElement(root) || { ownerDocument: root, [NEXT]: root[NEXT], [END]: root[END] } : root;
  return prepareMatch(context, selectors);
}
export function installSelectors() {
  const methods = {
    querySelector(selectors) {
      const matches = match(this, selectors, arguments.length);
      for (let node = this[NEXT]; node !== this[END]; node = node[NEXT]) if (nodeInfo(node)?.kind === 1 && matches(node)) return node;
      return null;
    },
    querySelectorAll(selectors) {
      const matches = match(this, selectors, arguments.length), nodes = backendList();
      for (let node = this[NEXT]; node !== this[END]; node = node[NEXT]) if (nodeInfo(node)?.kind === 1 && matches(node)) nodes[nodes.length] = node;
      return staticNodeList(nodes);
    },
  };
  for (const key of ['querySelector', 'querySelectorAll']) for (const prototype of [ParentNode.prototype, Document.prototype]) define(prototype, key, { __proto__: null, value: methods[key], writable: true, enumerable: true, configurable: true });
}
