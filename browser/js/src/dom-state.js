import { attributeInfo } from './attribute-state.js';
// Allocation metadata follows private links and provides parents independently
// of public nodeType/parentNode/_getParent/host properties.
import { END, NEXT, PREV, START, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nameIdentity } from './names.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
const setPrototype = Object.setPrototypeOf, NativeTypeError = TypeError;
const nodes = new WeakMap(), shadows = new WeakMap(), windows = new WeakMap();
const node = nodes.get.bind(nodes), saveNode = nodes.set.bind(nodes);
export function initializeNode(value, kind, local, document) { saveNode(value, { __proto__: null, kind, local, document, parent: null }); }
export function nodeDocument(value) { const data = node(value); return data?.kind === 9 ? value : attributeInfo(value)?.document ?? data?.document ?? null; }
export function rememberNodeDocument(value, document) { const data = node(value); if (data) data.document = document; }
export function physicalNextSibling(value) { if (!physicalParent(value)) return null; const next = (value[END] || value)[NEXT]; return node(next) ? next : null; }
export function physicalPreviousSibling(value) { if (!physicalParent(value)) return null; const previous = value[PREV]; if (previous?.[START]) return previous[START]; const kind = node(previous)?.kind; return kind === 3 || kind === 4 || kind === 7 || kind === 8 || kind === 10 ? previous : null; }
export const nodeInfo = node;
export const shadowInfo = shadows.get.bind(shadows);
export const rememberShadow = shadows.set.bind(shadows);
export const rememberDocumentWindow = windows.set.bind(windows);
const windowFor = windows.get.bind(windows), shadowFor = shadowRoots.get.bind(shadowRoots);
export function browsingDocument(value) { let root = physicalRoot(value); while (shadowInfo(root)) root = physicalRoot(shadowInfo(root).host); return windowFor(root) ? root : null; }
export function physicalParent(value) { return node(value)?.parent || null; }
export function rememberNodeParent(value, parent) {
  const data = node(value);
  if (data && data.kind !== 2 && data.kind !== 9) data.parent = parent;
}
// Serialized tree links distinguish an open parent, its attributes, a leaf,
// and a closed sibling's end marker. No page-visible accessor participates.
function parentAfter(previous) {
  const start = previous?.[START];
  if (start) return physicalParent(start);
  const kind = node(previous)?.kind;
  if (kind === 1 || kind === 9 || kind === 11) return previous;
  if (kind === 2) return attributeInfo(previous)?.owner || null;
  return physicalParent(previous);
}
export function rememberAdjacentParent(previous, next) { rememberNodeParent(next,parentAfter(previous)); }
export function rememberSegmentParent(previous, first, last) {
  const parent = parentAfter(previous);
  for (let value = first; value;) {
    rememberNodeParent(value,parent);
    if (value === last) return;
    value = (value[END] || value)[NEXT];
  }
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
  const roots = []; setPrototype(roots, null);
  for (let current = value; current;) {
    const info = shadowInfo(current);
    if (info?.mode === 'closed') roots[roots.length] = current;
    current = physicalParent(current) || info?.host || null;
  }
  return roots;
}
export function eventAttribute(element, name) {
  for (let attr = element[NEXT]; node(attr)?.kind === 2; attr = attr[NEXT]) if (node(attr).local === name && (attributeInfo(attr)?.namespace ?? null) === null) return attr[VALUE];
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

// Direct children can be visited without reading public DOM accessors or
// walking their descendants (for example a large body or stylesheet).
function firstElement(parent) {
  for (let value = parent[NEXT]; value && value !== parent[END]; value = value[END] ? value[END][NEXT] : value[NEXT]) if (node(value)?.kind === 1) return value;
  return null;
}
export function physicalDocumentElement(document) { if (node(document)?.kind !== 9) throw new NativeTypeError('A Document is required'); return firstElement(document); }

export function physicalBody(document) {
  const html = firstElement(document), identity = html && nameIdentity(html);
  if (identity?.namespace !== 'http://www.w3.org/1999/xhtml' || identity.local !== 'html') return null;
  for (let value = html[NEXT]; value && value !== html[END]; value = value[END] ? value[END][NEXT] : value[NEXT]) {
    const name = nameIdentity(value);
    if (name?.namespace === 'http://www.w3.org/1999/xhtml' && (name.local === 'body' || name.local === 'frameset')) return value;
  }
  return null;
}

export function physicalHead(document) {
  const html = firstElement(document), identity = html && nameIdentity(html);
  if (identity?.namespace !== 'http://www.w3.org/1999/xhtml' || identity.local !== 'html') return null;
  for (let value = html[NEXT]; value && value !== html[END]; value = value[END] ? value[END][NEXT] : value[NEXT]) {
    const name = nameIdentity(value);
    if (name?.namespace === 'http://www.w3.org/1999/xhtml' && name.local === 'head') return value;
  }
  return null;
}

export function physicalOwnerSVG(node) {
  for (let parent = physicalParent(node); parent; parent = physicalParent(parent)) {
    const id = nameIdentity(parent);
    if (id?.namespace === 'http://www.w3.org/2000/svg' && id.local === 'svg') return parent;
  }
  return null;
}

export function physicalFirstChild(value) {
  const end = value?.[END]; if (!end) return null;
  let child = value[NEXT];
  while (node(child)?.kind === 2) child = child[NEXT];
  return child === end ? null : child || null;
}
export function physicalLastChild(value) {
  const end = value?.[END]; if (!end) return null;
  const last = end[PREV];
  if (last === value || node(last)?.kind === 2) return null;
  return last?.[START] || last || null;
}
