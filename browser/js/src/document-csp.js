// Installed policies belong to an active document, not to mutable meta nodes.
// Removing or editing a processed meta cannot remove or replace its policy.
import { backendList, collectionAttribute } from './collection-data.js';
import { nodeDocument, physicalParent, physicalRoot, physicalHead } from './dom-state.js';
import { nameIdentity, lowerASCII } from './names.js';
import { documentURL } from './document-state.js';
const documents = new WeakMap(), read = documents.get.bind(documents), save = documents.set.bind(documents);
const evaluate = globalThis.__native.cspCheck, parse = JSON.parse, HTML = 'http://www.w3.org/1999/xhtml';
const wellFormed = Function.prototype.call.bind(String.prototype.toWellFormed);
let report = () => {};
export function installCSPReporter(callback) { report = callback; }
export function initializeDocumentCSP(doc, policies, reportOnly = []) {
  const list = backendList();
  for (let i = 0; i < policies.length; i++) list[list.length] = { __proto__: null, policy: policies[i], disposition: 'enforce', header: true };
  for (let i = 0; i < reportOnly.length; i++) list[list.length] = { __proto__: null, policy: reportOnly[i], disposition: 'report', header: true };
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
  if (policy) state.policies[state.policies.length] = { __proto__: null, policy, disposition: 'enforce', header: false };
}
export function checkCSP(doc, kind, candidate = '', nonce = '', source = '', parser = false, element = null) {
  const state = read(doc); if (!state) return true;
  let allowed = true;
  for (let i = 0; i < state.policies.length; i++) {
    const entry = state.policies[i], violations = parse(evaluate(entry.policy,kind,candidate,state.origin,nonce,wellFormed(source),parser));
    for (let j = 0; j < violations.length; j++) {
      if (entry.disposition === 'enforce') allowed = false;
      report(doc,element,violations[j],entry.disposition);
    }
  }
  return allowed;
}
export function baseAllowed(doc, url, element = null) { return checkCSP(doc,'base',url,'','',false,element); }
export function hasHeaderCSP(doc) { const state = read(doc); if (state) for (let i = 0; i < state.policies.length; i++) if (state.policies[i].header) return true; return false; }
