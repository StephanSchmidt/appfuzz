import { runDOMCallback, setDOMCallbackBoundary } from './dom-callbacks.js';
const queues = new WeakMap();
const queueFor = queues.get.bind(queues), save = queues.set.bind(queues);
const apply = Reflect.apply;
let depth = 0, pending = [];
let reportError = () => {};
export function setReactionErrorHandler(report) { reportError = report; }

export function enqueueReaction(node, callback, args = []) {
  if (typeof callback !== 'function') return;
  let queue = queueFor(node);
  if (!queue) save(node, queue = { items: [], at: 0 });
  queue.items[queue.items.length] = [callback, args];
  pending[pending.length] = node;
}
export function flushReactions(node) {
  const queue = queueFor(node);
  if (!queue) return;
  while (queue.at < queue.items.length) {
    const [callback, args] = queue.items[queue.at++];
    try { runDOMCallback(() => apply(callback, node, args)); }
    catch (e) { reportError('reaction', e); }
  }
  queue.items.length = queue.at = 0;
}
export function withReactions(callback) {
  depth++;
  try { return callback(); }
  finally {
    if (!--depth) {
      const nodes = pending; pending = [];
      for (let i = 0; i < nodes.length; i++) flushReactions(nodes[i]);
    }
  }
}
export function installReactionBoundaries(L) {
  setDOMCallbackBoundary(callback => {
    const outerDepth = depth, outerPending = pending;
    depth = 0; pending = [];
    try { return callback(); }
    finally { depth = outerDepth; pending = outerPending; }
  });
  const wrap = (proto, key) => {
    const d = Object.getOwnPropertyDescriptor(proto, key);
    if (typeof d?.value === 'function') {
      const original = d.value;
      Object.defineProperty(proto, key, { ...d, value: function (...args) { return withReactions(() => apply(original, this, args)); } });
    } else if (d?.set) {
      const original = d.set;
      Object.defineProperty(proto, key, { ...d, set(value) { return withReactions(() => apply(original, this, [value])); } });
    }
  };
  const parent = Object.getPrototypeOf(L.Element.prototype), character = Object.getPrototypeOf(L.Text.prototype);
  for (const key of ['append','prepend','replaceChildren','appendChild','insertBefore','replaceChild','removeChild']) wrap(parent, key);
  for (const proto of [L.Element.prototype, character, L.DocumentType.prototype]) for (const key of ['before','after','replaceWith','remove']) wrap(proto, key);
  for (const proto of [L.Element.prototype,L.DocumentFragment.prototype,L.ShadowRoot.prototype,L.HTMLTemplateElement.prototype]) for (const key of ['innerHTML','outerHTML','textContent']) wrap(proto, key);
  for (const key of ['setAttribute','setAttributeNS','setAttributeNode','setAttributeNodeNS','removeAttribute','removeAttributeNS','removeAttributeNode','toggleAttribute','insertAdjacentHTML','insertAdjacentElement','className','id']) wrap(L.Element.prototype, key);
  wrap(L.Attr.prototype, 'value');
}
