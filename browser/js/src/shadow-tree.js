import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
const shadow = shadowRoots.get.bind(shadowRoots);
export function shadowTreeNodes(root) {
  const result = [], pending = [[root, (root[END] || root)[NEXT]]];
  while (pending.length) {
    let [node, stop] = pending.pop();
    while (node !== stop) {
      result[result.length] = node;
      const nested = shadow(node)?.shadowRoot;
      if (nested) {
        pending[pending.length] = [node[NEXT], stop];
        pending[pending.length] = [nested, nested[END][NEXT]];
        break;
      }
      node = node[NEXT];
    }
  }
  return result;
}
