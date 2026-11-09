// Public operations validate their own interface before selector conversion.
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { DocumentFragment } from '../node_modules/linkedom/esm/interface/document-fragment.js';
import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { staticNodeList } from './collections.js';
import { backendList } from './collection-data.js';
import { nodeInfo, physicalParent } from './dom-state.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { compileSelector } from './selector-engine.js';
const NativeTypeError = TypeError, define = Object.defineProperty;
function match(root, selectors, count, kind) {
  if (nodeInfo(root)?.kind !== kind) throw new NativeTypeError('An appropriate DOM receiver is required');
  if (!count) throw new NativeTypeError('Not enough arguments');
  selectors = runDOMCallback(() => eventString(selectors));
  return compileSelector(root, selectors);
}
export function installSelectors() {
  for (const [prototype, kind] of [[Element.prototype, 1], [Document.prototype, 9], [DocumentFragment.prototype, 11]]) {
    const methods = {
      querySelector(selectors) { const test = match(this, selectors, arguments.length, kind); for (let node = this[NEXT]; node !== this[END]; node = node[NEXT]) if (nodeInfo(node)?.kind === 1 && test(node)) return node; return null; },
      querySelectorAll(selectors) { const test = match(this, selectors, arguments.length, kind), nodes = backendList(); for (let node = this[NEXT]; node !== this[END]; node = node[NEXT]) if (nodeInfo(node)?.kind === 1 && test(node)) nodes[nodes.length] = node; return staticNodeList(nodes); },
    };
    for (const key of ['querySelector', 'querySelectorAll']) define(prototype, key, { __proto__: null, value: methods[key], writable: true, enumerable: true, configurable: true });
  }
  const methods = {
    matches(selectors) { return match(this, selectors, arguments.length, 1)(this); },
    closest(selectors) { const test = match(this, selectors, arguments.length, 1); for (let node = this; nodeInfo(node)?.kind === 1; node = physicalParent(node)) if (test(node)) return node; return null; },
  };
  for (const key of ['matches', 'closest']) define(Element.prototype, key, { __proto__: null, value: methods[key], writable: true, enumerable: true, configurable: true });
}
