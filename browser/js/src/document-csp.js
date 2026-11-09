// Installed policies belong to an active document, not to mutable meta nodes.
// Removing or editing a processed meta cannot remove or replace its policy.
import { backendList, collectionAttribute } from './collection-data.js';
import { nodeDocument, physicalParent, physicalRoot, physicalHead } from './dom-state.js';
import { nameIdentity, lowerASCII } from './names.js';
import { documentURL } from './document-state.js';
const documents = new WeakMap(), read = documents.get.bind(documents), save = documents.set.bind(documents);
const allows = globalThis.__native.cspAllowsBase, HTML = 'http://www.w3.org/1999/xhtml';
export function initializeDocumentCSP(doc, policies) {
  const list = backendList();
  for (let i = 0; i < policies.length; i++) list[list.length] = policies[i];
  save(doc, { __proto__: null, origin: documentURL(doc), policies: list });
}
export function processDocumentMeta(node) {
  const identity = nameIdentity(node);
  if (identity?.namespace !== HTML || identity.local !== 'meta') return;
  const doc = nodeDocument(node), state = read(doc);
  if (!state || physicalRoot(node) !== doc) return;
  // Native browsers accept descendants of the document's actual head, while
  // detached heads, other head elements and shadow/template trees are inert.
  const head = physicalHead(doc); if (!head) return;
  let parent = physicalParent(node);
  while (parent && parent !== head) parent = physicalParent(parent);
  if (!parent || lowerASCII(collectionAttribute(node,'http-equiv') || '') !== 'content-security-policy') return;
  const policy = collectionAttribute(node,'content');
  if (policy) state.policies[state.policies.length] = policy;
}
export function baseAllowed(doc, url) {
  const state = read(doc); if (!state) return true;
  for (let i = 0; i < state.policies.length; i++) if (!allows(state.policies[i],url,state.origin)) return false;
  return true;
}
