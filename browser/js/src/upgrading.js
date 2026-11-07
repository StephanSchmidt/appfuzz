// Upgrade an element for a connection or queued clone reaction. Keep its
// completed attributes and children in place. The native upgrade removes
// and re-adds attributes, producing false mutations.
import { CUSTOM_ELEMENTS, END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { Classes, customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { nameIdentity } from './names.js';
import { templateContent } from './templates.js';
import { runDOMCallback } from './dom-callbacks.js';
import { elementIs, definitionForClass, beginConstruction, endConstruction } from './element-state.js';
import { markCustom } from './element-internals.js';

const known = customElements.has.bind(customElements);
const definition = Classes.get.bind(Classes);
const get = Function.prototype.call.bind(Map.prototype.get);
const construct = Reflect.construct;
const attempts = new WeakMap();
const attempted = attempts.has.bind(attempts), attemptedSet = attempts.set.bind(attempts);
const includes = Function.prototype.call.bind(Array.prototype.includes);
const HTML = 'http://www.w3.org/1999/xhtml';

export function upgradeDefinition(element, registryOverride) {
  const identity = nameIdentity(element);
  if (!identity || identity.namespace !== HTML || known(element) || attempted(element)) return null;
  const owner = element[END].ownerDocument, registry = registryOverride === undefined ? owner[CUSTOM_ELEMENTS] : registryOverride;
  if (!registry?.active) return null;
  const is = elementIs(element);
  const name = identity.local.includes('-') ? identity.local : is;
  const Class = get(registry.registry, name)?.Class;
  const info = Class && definition(Class);
  if (!info || info.localName !== identity.local || (info.options.is && info.options.is !== is)) return null;
  const snapshot = definitionForClass(Class);
  return snapshot ? { Class, info, snapshot } : null;
}

export function upgradeInserted(element, connected, enqueue, onError, allowDetached = false, prepared) {
  if (known(element) || attempted(element)) return;
  const definition = prepared === undefined ? upgradeDefinition(element) : prepared;
  if (!definition) return;
  const { Class, snapshot: callbacks } = definition;
  const wasConnected = connected(element);
  if (!wasConnected && !allowDetached) return;
  const attrs = [];
  for (let attr = element[NEXT]; attr.nodeType === 2; attr = attr[NEXT]) attrs.push([attr.localName, null, attr[VALUE], null]);
  attemptedSet(element, true);
  beginConstruction(Class, element);
  try {
    const result = runDOMCallback(() => construct(Class, []));
    if (result !== element) throw new TypeError('A custom-element constructor must return its element');
    templateContent(element);
    markCustom(element, callbacks, connected(element));
    for (let i = 0; i < attrs.length; i++) {
      if (typeof callbacks.attribute === 'function' && includes(callbacks.observed, attrs[i][0])) enqueue(element, 'attributeChangedCallback', attrs[i], callbacks.attribute);
    }
    if (wasConnected && typeof callbacks.connected === 'function') enqueue(element, 'connectedCallback', [], callbacks.connected);
  } catch (e) { onError('constructor', e); }
  finally { endConstruction(Class); }
}

export function markFailed(element) { attemptedSet(element, true); }
