// Template contents have their own private tree. All physical descendants
// are therefore ordinary DOM descendants, including light children of HTML
// templates and children of SVG elements whose local name is "template".
import { ParentNode } from '../node_modules/linkedom/esm/mixin/parent-node.js';
import { NodeList } from '../node_modules/linkedom/esm/interface/node-list.js';
import { prepareMatch } from '../node_modules/linkedom/esm/shared/matches.js';
import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';

const add = Function.prototype.call.bind(Array.prototype.push);
export function installSelectors() {
  ParentNode.prototype.querySelector = function (selectors) {
    const matches = prepareMatch(this, selectors);
    for (let node = this[NEXT]; node !== this[END]; node = node[NEXT]) {
      if (node.nodeType === 1 && matches(node)) return node;
    }
    return null;
  };
  ParentNode.prototype.querySelectorAll = function (selectors) {
    const matches = prepareMatch(this, selectors), nodes = new NodeList();
    for (let node = this[NEXT]; node !== this[END]; node = node[NEXT]) {
      if (node.nodeType === 1 && matches(node)) add(nodes, node);
    }
    return nodes;
  };
}
