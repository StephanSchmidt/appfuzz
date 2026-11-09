import { baseAllowed, processDocumentMeta } from './document-csp.js';
import { nodeDocument, physicalRoot, nodeInfo } from './dom-state.js';
import { collectionVersion } from './collection-version.js';
import { documentURL } from './document-state.js';
import { collectionDescendants, collectionAttribute } from './collection-data.js';
import { nameIdentity } from './names.js';
const revisions = new WeakMap(), revision = revisions.get.bind(revisions), saveRevision = revisions.set.bind(revisions);
export function baseAttributeChanged(node,name,namespace) { const id = nameIdentity(node); if (namespace === null && name === 'href' && id?.namespace === 'http://www.w3.org/1999/xhtml' && id.local === 'base') { saveRevision(node,(revision(node) || 0) + 1); documentBaseURL(nodeDocument(node)); } }
const parse = globalThis.__native.url, cache = new WeakMap(), read = cache.get.bind(cache), save = cache.set.bind(cache);
export function resolveDocumentURL(value,doc) { const parsed = parse(value,documentURL(doc)); return parsed ? parsed[0] : value; }
export function documentBaseURL(doc) {
  const fallback = documentURL(doc), version = collectionVersion(true), previous = read(doc);
  if (previous && previous.version === version && previous.fallback === fallback) return previous.url;
  const store = (url,base = null,stamp = 0) => { save(doc,{ __proto__: null, version, fallback, url, base, stamp }); return url; };
  const nodes = collectionDescendants(doc);
  for (let i = 0; i < nodes.length; i++) {
    const id = nameIdentity(nodes[i]); if (id?.namespace !== 'http://www.w3.org/1999/xhtml' || id.local !== 'base') continue;
    const href = collectionAttribute(nodes[i],'href'); if (href === null) continue;
    const stamp = revision(nodes[i]) || 0;
    if (previous?.base === nodes[i] && previous.stamp === stamp) return store(previous.url,nodes[i],stamp);
    const parsed = parse(href,fallback), allowed = parsed && parsed[2] !== 'data:' && parsed[2] !== 'javascript:' && baseAllowed(doc,parsed[0]); return store(allowed ? parsed[0] : fallback,nodes[i],stamp);
  }
  return store(fallback);
}

// Set frozen bases and install meta policies at insertion time, in tree order.
// This must precede author callbacks and script preparation. A later policy
// does not retroactively invalidate a base established before that policy.
export function documentConnectionChanged(root, connected) {
  const nodes = collectionDescendants(root);
  for (let i = -1; i < nodes.length; i++) {
    const node = i < 0 ? root : nodes[i], id = nameIdentity(node);
    if (id?.namespace !== 'http://www.w3.org/1999/xhtml') continue;
    if (id.local === 'meta') { if (connected) processDocumentMeta(node); }
    else if (id.local === 'base') {
      saveRevision(node,(revision(node) || 0) + 1);
      const doc = nodeDocument(node);
      if (doc && (!connected || (physicalRoot(node) === doc && nodeInfo(doc)?.kind === 9))) documentBaseURL(doc);
    }
  }
}
