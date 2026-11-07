// Upgrade an element for a connection or queued clone reaction. Keep its
// completed attributes and children in place. The native upgrade removes
// and re-adds attributes, producing false mutations.
import { CUSTOM_ELEMENTS, END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { Classes, customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { nameIdentity } from './names.js';
import { templateContent } from './templates.js';
import { runDOMCallback } from './dom-callbacks.js';
import { elementIs, definitionForClass, beginConstruction, endConstruction, rememberElementDefinition, forgetElementDefinition } from './element-state.js';
import { markCustom } from './element-internals.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';

const known = customElements.has.bind(customElements);
const definition = Classes.get.bind(Classes);
const get = Function.prototype.call.bind(Map.prototype.get);
const construct = Reflect.construct;
const attempts = new WeakMap();
const attempted = attempts.has.bind(attempts), attemptedSet = attempts.set.bind(attempts);
const includes = Function.prototype.call.bind(Array.prototype.includes);
const HTML = 'http://www.w3.org/1999/xhtml';
const hasShadow = shadowRoots.has.bind(shadowRoots);

export function lookupDefinition(element, registryOverride) {
  const identity = nameIdentity(element);
  if (!identity || identity.namespace !== HTML) return null;
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

export function upgradeDefinition(element, registryOverride) {
  return known(element) || attempted(element) ? null : lookupDefinition(element, registryOverride);
}

export function upgradeInserted(element, connected, enqueue, onError, allowDetached = false, prepared, DOMError) {
  if (known(element) || attempted(element)) return;
  const definition = prepared === undefined ? upgradeDefinition(element) : prepared;
  if (!definition) return;
  const { Class, snapshot: callbacks } = definition;
  const wasConnected = connected(element);
  if (!wasConnected && !allowDetached) return;
  const attrs = [];
  for (let attr = element[NEXT]; attr.nodeType === 2; attr = attr[NEXT]) attrs.push([attr.localName, null, attr[VALUE], null]);
  attemptedSet(element, true);
  rememberElementDefinition(element, callbacks);
  beginConstruction(Class, element);
  let failed = false, failure;
  try {
    if (callbacks.disableShadow && hasShadow(element)) throw new DOMError('The definition disables shadow roots', 'NotSupportedError');
    const result = runDOMCallback(() => construct(Class, []));
    if (result !== element) throw new TypeError('A custom-element constructor must return its element');
    templateContent(element);
    markCustom(element, callbacks, connected(element));
    for (let i = 0; i < attrs.length; i++) {
      if (typeof callbacks.attribute === 'function' && includes(callbacks.observed, attrs[i][0])) enqueue(element, 'attributeChangedCallback', attrs[i], callbacks.attribute);
    }
    if (wasConnected && typeof callbacks.connected === 'function') enqueue(element, 'connectedCallback', [], callbacks.connected);
  } catch (e) { forgetElementDefinition(element); failed = true; failure = e; }
  finally { endConstruction(Class); }
  // Reporting invokes author error handlers. They can construct this
  // same class, after the failed upgrade's construction frame is gone.
  if (failed) onError('constructor', failure);
}

export function markFailed(element) { attemptedSet(element, true); }
