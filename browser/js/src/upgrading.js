// Upgrade an element for a connection or queued clone reaction. Keep its
// completed attributes and children in place. The native upgrade removes
// and re-adds attributes, producing false mutations.
import { CUSTOM_ELEMENTS, UPGRADE, END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { Classes, customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { nameIdentity } from './names.js';
import { templateContent } from './templates.js';
import { runDOMCallback } from './dom-callbacks.js';

const known = customElements.has.bind(customElements);
const remember = customElements.set.bind(customElements);
const definition = Classes.get.bind(Classes);
const get = Function.prototype.call.bind(Map.prototype.get);
const construct = Reflect.construct, prototype = Object.setPrototypeOf;
const attempts = new WeakMap();
const attempted = attempts.has.bind(attempts), attemptedSet = attempts.set.bind(attempts);
const HTML = 'http://www.w3.org/1999/xhtml';

export function upgradeDefinition(element) {
  const identity = nameIdentity(element);
  if (!identity || identity.namespace !== HTML || known(element) || attempted(element)) return null;
  const owner = element[END].ownerDocument, registry = owner[CUSTOM_ELEMENTS];
  if (!registry?.active) return null;
  let is = null;
  for (let attr = element[NEXT]; attr.nodeType === 2; attr = attr[NEXT]) {
    if (attr.localName === 'is') is = attr[VALUE];
  }
  const name = identity.local.includes('-') ? identity.local : is;
  const Class = get(registry.registry, name)?.Class;
  const info = Class && definition(Class);
  if (!info || info.localName !== identity.local || (info.options.is && info.options.is !== is)) return null;
  return { Class, info };
}

export function upgradeInserted(element, connected, enqueue, onError, allowDetached = false, prepared) {
  if (known(element) || attempted(element)) return;
  const definition = prepared === undefined ? upgradeDefinition(element) : prepared;
  if (!definition) return;
  const { Class, info } = definition;
  const wasConnected = connected(element);
  if (!wasConnected && !allowDetached) return;
  const attrs = [];
  for (let attr = element[NEXT]; attr.nodeType === 2; attr = attr[NEXT]) attrs.push([attr.localName, null, attr[VALUE], null]);
  attemptedSet(element, true);
  // HTMLElement's construction stack belongs to the definition's realm,
  // even if an earlier reaction moved this element to another document.
  const constructionDocument = info.ownerDocument;
  const previous = constructionDocument[UPGRADE];
  try {
    prototype(element, Class.prototype);
    const callbacks = runDOMCallback(() => ({ attribute: Class.prototype.attributeChangedCallback, connected: Class.prototype.connectedCallback, observed: Class.observedAttributes || [] }));
    constructionDocument[UPGRADE] = { element, values: [] };
    const result = runDOMCallback(() => construct(Class, []));
    if (result !== element) throw new TypeError('A custom-element constructor must return its element');
    templateContent(element);
    remember(element, { connected: connected(element) });
    for (let i = 0; i < attrs.length; i++) {
      if (typeof callbacks.attribute === 'function' && callbacks.observed.includes(attrs[i][0])) enqueue(element, 'attributeChangedCallback', attrs[i], callbacks.attribute);
    }
    if (wasConnected && typeof callbacks.connected === 'function') enqueue(element, 'connectedCallback', [], callbacks.connected);
  } catch (e) { onError('constructor', e); }
  finally { constructionDocument[UPGRADE] = previous; }
}
