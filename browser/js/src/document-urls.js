import { collectionVersion } from './collection-version.js';
import { documentURL } from './document-state.js';
import { collectionDescendants, collectionAttribute } from './collection-data.js';
import { nameIdentity } from './names.js';
const parse = globalThis.__native.url, cache = new WeakMap(), read = cache.get.bind(cache), save = cache.set.bind(cache);
export function resolveDocumentURL(value,doc) { const parsed = parse(value,documentURL(doc)); return parsed ? parsed[0] : value; }
export function documentBaseURL(doc) {
  const fallback = documentURL(doc), version = collectionVersion(true), previous = read(doc);
  if (previous && previous.version === version && previous.fallback === fallback) return previous.url;
  const store = url => { save(doc,{ __proto__: null, version, fallback, url }); return url; };
  const nodes = collectionDescendants(doc);
  for (let i = 0; i < nodes.length; i++) {
    const id = nameIdentity(nodes[i]); if (id?.namespace !== 'http://www.w3.org/1999/xhtml' || id.local !== 'base') continue;
    const href = collectionAttribute(nodes[i],'href'); if (href === null) continue;
    const parsed = parse(href,fallback); return store(parsed ? parsed[0] : fallback);
  }
  return store(fallback);
}
