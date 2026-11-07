import { END } from '../node_modules/linkedom/esm/shared/symbols.js';
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { customElements } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { installName, nameIdentity } from './names.js';
import { rememberScript } from './script-state.js';
import { rememberIs, rememberElementDefinition } from './element-state.js';
import { templateContent } from './templates.js';

const isHTML = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const save = customElements.set.bind(customElements);
export function initializeElement(node, identity, is = null, started = false) {
  if (!nameIdentity(node)) installName(node, identity, isHTML);
  rememberIs(node, is);
  templateContent(node);
  if (identity.local === 'script') rememberScript(node, identity, started);
  return node;
}
export function markCustom(node, definition, connected = false) {
  rememberElementDefinition(node, definition);
  save(node, { connected, owner: node[END].ownerDocument });
}
