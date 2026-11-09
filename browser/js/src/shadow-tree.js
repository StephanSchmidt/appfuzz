import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
const shadow = shadowRoots.get.bind(shadowRoots), setPrototype = Object.setPrototypeOf;
function list() { const result = []; setPrototype(result, null); return result; }
export function shadowTreeNodes(root) {
  const result = list(), pending = list(); pending[0] = { __proto__: null, node: root, stop: (root[END] || root)[NEXT] };
  while (pending.length) {
    const at = pending.length - 1, job = pending[at]; pending.length = at; let node = job.node; const stop = job.stop;
    while (node !== stop) {
      result[result.length] = node;
      const nested = shadow(node)?.shadowRoot;
      if (nested) {
        pending[pending.length] = { __proto__: null, node: node[NEXT], stop };
        pending[pending.length] = { __proto__: null, node: nested, stop: nested[END][NEXT] };
        break;
      }
      node = node[NEXT];
    }
  }
  return result;
}
