// Checkedness, indeterminateness and radio grouping belong to the input,
// independently of public property shadows used by page code.
import { Attr } from '../node_modules/linkedom/esm/interface/attr.js';
import { setAttribute, removeAttribute } from '../node_modules/linkedom/esm/shared/attributes.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nameIdentity } from './names.js';
import { nodeInfo, physicalParent, physicalRoot, shadowInfo, eventAttribute } from './dom-state.js';
import { installControlHooks } from './ce-hooks.js';
const setAttributeValue = Function.prototype.call.bind(Object.getOwnPropertyDescriptor(Attr.prototype, 'value').set);
const states = new WeakMap(), get = states.get.bind(states), save = states.set.bind(states);
const NativeTypeError = TypeError, codeAt = Function.prototype.call.bind(String.prototype.charCodeAt), character = String.fromCharCode;
const inputTypes = new Set('hidden text search tel url email password date month week time datetime-local number range color checkbox radio file submit image reset button'.split(' '));
const validInputType = inputTypes.has.bind(inputTypes);
function lowerASCII(value) {
  let result = '';
  for (let i = 0; i < value.length; i++) { const c = codeAt(value, i); result += c >= 65 && c <= 90 ? character(c + 32) : value[i]; }
  return result;
}
export function htmlName(node) { const identity = nameIdentity(node); return identity?.namespace === 'http://www.w3.org/1999/xhtml' ? identity.local : null; }
export function controlType(node) {
  const type = lowerASCII(eventAttribute(node, 'type') || '');
  return htmlName(node) === 'input' ? (validInputType(type) ? type : 'text') : type;
}
export function treeElements(root) {
  const elements = [];
  if (!root) return elements;
  const stop = (root[END] || root)[NEXT];
  for (let current = root; current && current !== stop; current = current[NEXT]) if (nodeInfo(current)?.kind === 1) elements[elements.length] = current;
  return elements;
}
export function setControlAttribute(node, name, value) {
  if (value !== null) value = runDOMCallback(() => eventString(value));
  for (let attr = node[NEXT]; nodeInfo(attr)?.kind === 2; attr = attr[NEXT]) if (nodeInfo(attr).local === name) {
    if (value === null) removeAttribute(node, attr); else setAttributeValue(attr, value);
    return;
  }
  if (value !== null) setAttribute(node, new Attr(node[END].ownerDocument, name, value));
}
export function formOwner(node) {
  const id = eventAttribute(node, 'form');
  if (id !== null) {
    const root = physicalRoot(node);
    if (!id || nodeInfo(root)?.kind !== 9) return null;
    const nodes = treeElements(root);
    for (let i = 0; i < nodes.length; i++) if (eventAttribute(nodes[i], 'id') === id) return htmlName(nodes[i]) === 'form' ? nodes[i] : null;
    return null;
  }
  for (let parent = physicalParent(node); parent; parent = physicalParent(parent)) if (htmlName(parent) === 'form') return parent;
  return null;
}
export function connected(node) {
  let root = physicalRoot(node);
  while (shadowInfo(root)) root = physicalRoot(shadowInfo(root).host);
  return nodeInfo(root)?.kind === 9;
}
export function disabled(node) {
  const name = htmlName(node);
  if (name !== 'input' && name !== 'button' && name !== 'select' && name !== 'textarea' && name !== 'fieldset' && name !== 'option' && name !== 'optgroup') return false;
  if (eventAttribute(node, 'disabled') !== null) return true;
  for (let parent = physicalParent(node); parent; parent = physicalParent(parent)) {
    if (htmlName(parent) !== 'fieldset' || eventAttribute(parent, 'disabled') === null) continue;
    let firstLegend = null;
    const children = treeElements(parent);
    for (let i = 1; i < children.length; i++) if (physicalParent(children[i]) === parent && htmlName(children[i]) === 'legend') { firstLegend = children[i]; break; }
    let exempt = false;
    for (let ancestor = node; ancestor && ancestor !== parent; ancestor = physicalParent(ancestor)) if (ancestor === firstLegend) exempt = true;
    if (!exempt) return true;
  }
  return false;
}
function state(node) {
  if (htmlName(node) !== 'input') throw new NativeTypeError('An HTMLInputElement is required');
  let result = get(node);
  if (!result) { result = { checked: eventAttribute(node, 'checked') !== null, dirty: false, indeterminate: false }; save(node, result); }
  return result;
}
export const checked = node => state(node).checked;
export const indeterminate = node => state(node).indeterminate;
export function setIndeterminate(node, value) { state(node).indeterminate = !!value; }
function sameGroup(a, b) {
  const name = eventAttribute(a, 'name');
  return !!name && htmlName(b) === 'input' && controlType(b) === 'radio' && eventAttribute(b, 'name') === name && physicalRoot(a) === physicalRoot(b) && formOwner(a) === formOwner(b);
}
function uncheckPeers(node) {
  if (controlType(node) !== 'radio' || !eventAttribute(node, 'name')) return;
  const nodes = treeElements(physicalRoot(node));
  for (let i = 0; i < nodes.length; i++) if (nodes[i] !== node && sameGroup(node, nodes[i])) state(nodes[i]).checked = false;
}
export function setChecked(node, value, dirty = true) {
  const s = state(node); s.checked = !!value; if (dirty) s.dirty = true;
  if (s.checked) uncheckPeers(node);
}
export function beginInputActivation(node) {
  const type = controlType(node), s = state(node);
  const result = { checked: s.checked, indeterminate: s.indeterminate, previous: null, changed: false };
  if (type === 'checkbox') { setChecked(node, !s.checked); s.indeterminate = false; result.changed = true; }
  else if (type === 'radio') {
    const nodes = treeElements(physicalRoot(node));
    for (let i = 0; i < nodes.length; i++) if ((nodes[i] === node || sameGroup(node, nodes[i])) && checked(nodes[i])) { result.previous = nodes[i]; break; }
    result.changed = !s.checked; setChecked(node, true);
  }
  return result;
}
export function cancelInputActivation(node, before) {
  const type = controlType(node);
  if (type === 'checkbox') { setChecked(node, before.checked); setIndeterminate(node, before.indeterminate); }
  else if (type === 'radio') {
    if (before.previous && (before.previous === node || sameGroup(node, before.previous))) setChecked(before.previous, true);
    else setChecked(node, false);
  }
}
export function copyInputState(source, copy) {
  if (htmlName(source) === 'input') { const s = state(source); save(copy, { checked: s.checked, dirty: s.dirty, indeterminate: s.indeterminate }); }
}
export function installControlState(onDetailsChange) {
  installControlHooks((node, name, value, oldValue) => {
    if (htmlName(node) === 'details' && name === 'open' && (value === null) !== (oldValue === null)) onDetailsChange(node, oldValue !== null, value !== null);
    if (htmlName(node) !== 'input') return;
    const s = state(node);
    if (name === 'checked' && !s.dirty) s.checked = value !== null;
    if (s.checked && (name === 'checked' || name === 'name' || name === 'type' || name === 'form')) uncheckPeers(node);
  }, (root, nowConnected) => {
    if (!nowConnected) return;
    const nodes = treeElements(root);
    for (let i = 0; i < nodes.length; i++) if (htmlName(nodes[i]) === 'input' && checked(nodes[i])) uncheckPeers(nodes[i]);
  });
}
