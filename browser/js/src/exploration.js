// Driver observations use native tree data. Reading public DOM properties or
// framework accessors while deciding what to click can execute page code that
// no browser would execute during its own element discovery.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nodeInfo, physicalParent, eventAttribute } from './dom-state.js';
import { htmlName, treeElements } from './controls.js';
import { lowerASCII } from './names.js';
const keys = Object.keys, descriptor = Object.getOwnPropertyDescriptor, prototype = Object.getPrototypeOf;
const own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const kind = globalThis.__native.cloneKind;
const codeAt = Function.prototype.call.bind(String.prototype.charCodeAt);
const startsWith = Function.prototype.call.bind(String.prototype.startsWith);
const handlers = ['onClick', 'onMouseDown', 'onPointerDown', 'onChange', 'onInput', 'onSubmit'];

export function frameworkCandidate(element) {
  const names = keys(element);
  for (let i = 0; i < names.length; i++) {
    const key = names[i];
    if (key === '__click' || key === '__input' || key === '__change' || key === '__pointerdown' || key === '__mousedown') return true;
    if (!startsWith(key, '__reactProps')) continue;
    const field = descriptor(element, key);
    // An accessor or proxy may represent a delegated handler. Include the
    // potential target without asking page code to enumerate or read it.
    if (!field || !own(field, 'value')) return true;
    let value = field.value;
    if (value === null || (typeof value !== 'object' && typeof value !== 'function')) continue;
    while (value && kind(value) === 'Object') {
      for (let j = 0; j < handlers.length; j++) {
        const handler = descriptor(value, handlers[j]);
        if (handler && (!own(handler, 'value') || handler.value)) return true;
      }
      value = prototype(value);
    }
    if (value) return true;
  }
  return false;
}
export function editable(element) {
  for (let node = element; node; node = physicalParent(node)) {
    if (!htmlName(node)) continue;
    const value = eventAttribute(node, 'contenteditable');
    if (value === null) continue;
    const state = lowerASCII(value);
    if (state === '' || state === 'true' || state === 'plaintext-only') return true;
    if (state === 'false') return false;
  }
  return false;
}
export function nodeText(root) {
  let result = '';
  for (let node = root[NEXT]; node && node !== root[END]; node = node[NEXT]) {
    const type = nodeInfo(node)?.kind;
    if (type === 3 || type === 4) result += node[VALUE];
  }
  return result;
}
export function normalizedText(value) {
  let result = '', space = false;
  for (let i = 0; i < value.length; i++) {
    const code = codeAt(value, i);
    if ((code >= 9 && code <= 13) || code === 32 || code === 160 || code === 5760 || (code >= 8192 && code <= 8202)
      || code === 8232 || code === 8233 || code === 8239 || code === 8287 || code === 12288 || code === 65279) space = !!result;
    else { result += (space ? ' ' : '') + value[i]; space = false; }
  }
  return result;
}
export function documentText(document) {
  const nodes = treeElements(document);
  for (let i = 0; i < nodes.length; i++) if ((htmlName(nodes[i]) === 'body' || htmlName(nodes[i]) === 'frameset')
    && htmlName(physicalParent(nodes[i])) === 'html' && physicalParent(physicalParent(nodes[i])) === document) return normalizedText(nodeText(nodes[i]));
  return '';
}
