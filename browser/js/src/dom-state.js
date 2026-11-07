// Allocation metadata and physical links provide event parents independently
// of public nodeType/parentNode/_getParent/host properties.
import { END, NEXT, PREV, START, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nameIdentity } from './names.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
const nodes = new WeakMap(), shadows = new WeakMap(), windows = new WeakMap();
const node = nodes.get.bind(nodes), saveNode = nodes.set.bind(nodes);
export function initializeNode(value, kind, local) { saveNode(value, { kind, local }); }
export const nodeInfo = node;
export const shadowInfo = shadows.get.bind(shadows);
export const rememberShadow = shadows.set.bind(shadows);
export const rememberDocumentWindow = windows.set.bind(windows);
const windowFor = windows.get.bind(windows), shadowFor = shadowRoots.get.bind(shadowRoots);
export function physicalParent(value) {
  const kind = node(value)?.kind;
  if (kind === undefined || kind === 2 || kind === 9) return null;
  for (let previous = value[PREV]; previous;) {
    const type = node(previous)?.kind, start = previous[START];
    if (start && start[END] === previous) previous = start[PREV];
    else if (type === 1 || type === 9 || type === 11) return previous;
    else previous = previous[PREV];
  }
  return null;
}
export function physicalRoot(value) {
  let result = value, parent;
  while ((parent = physicalParent(result))) result = parent;
  return result;
}
export function shadowAncestor(root, value) {
  for (let current = value; current;) {
    if (current === root) return true;
    current = physicalParent(current) || shadowInfo(current)?.host || null;
  }
  return false;
}
export function closedAncestors(value) {
  const roots = [];
  for (let current = value; current;) {
    const info = shadowInfo(current);
    if (info?.mode === 'closed') roots[roots.length] = current;
    current = physicalParent(current) || info?.host || null;
  }
  return roots;
}
export function eventAttribute(element, name) {
  for (let attr = element[NEXT]; node(attr)?.kind === 2; attr = attr[NEXT]) if (node(attr).local === name) return attr[VALUE];
  return null;
}
function assignedSlot(value) {
  const kind = node(value)?.kind;
  if (kind !== 1 && kind !== 3) return null;
  const parent = physicalParent(value), shadow = parent && shadowFor(parent)?.shadowRoot;
  if (!shadow) return null;
  const name = kind === 1 ? eventAttribute(value, 'slot') || '' : '';
  for (let current = shadow[NEXT]; current !== shadow[END]; current = current[NEXT]) {
    const identity = nameIdentity(current);
    if (identity?.namespace === 'http://www.w3.org/1999/xhtml' && identity.local === 'slot' && (eventAttribute(current, 'name') || '') === name) return current;
  }
  return null;
}
export function eventParent(value, originalRoot, composed, type) {
  const shadow = shadowInfo(value);
  if (shadow) return !composed && originalRoot === value ? null : shadow.host;
  if (node(value)?.kind === 9) return type === 'load' ? null : windowFor(value) || null;
  return assignedSlot(value) || physicalParent(value);
}
export function retarget(value, against) {
  for (let current = value; current;) {
    if (!node(current)) return current;
    const root = physicalRoot(current), shadow = shadowInfo(root);
    if (!shadow || (node(against) && shadowAncestor(root, against))) return current;
    current = shadow.host;
  }
  return null;
}
export function defaultPassiveTarget(value) {
  if (node(value)?.kind === 9) return true;
  const identity = nameIdentity(value), parent = physicalParent(value);
  return identity?.namespace === 'http://www.w3.org/1999/xhtml'
    && ((identity.local === 'html' && node(parent)?.kind === 9)
      || (identity.local === 'body' && nameIdentity(parent)?.local === 'html' && node(physicalParent(parent))?.kind === 9));
}
