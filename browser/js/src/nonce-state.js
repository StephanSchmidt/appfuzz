// HTML's cryptographic nonce is a native slot, separate from the content
// attribute. Header policy delivery hides the attribute at connection time.
import { nodeInfo, browsingDocument } from './dom-state.js';
import { nameIdentity } from './names.js';
import { collectionAttribute } from './collection-data.js';
import { hasHeaderCSP } from './document-csp.js';
import { shadowTreeNodes } from './shadow-tree.js';
import { runDOMCallback } from './dom-callbacks.js';
const values = new WeakMap(), read = values.get.bind(values), save = values.set.bind(values);
const NativeTypeError = TypeError, define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor;
let setAttribute;
function eligible(node) { const ns = nameIdentity(node)?.namespace; return nodeInfo(node)?.kind === 1 && (ns === 'http://www.w3.org/1999/xhtml' || ns === 'http://www.w3.org/2000/svg' || ns === 'http://www.w3.org/1998/Math/MathML'); }
export function cryptographicNonce(node) { return read(node) || ''; }
export function nonceAttributeChanged(node,name,value,namespace) { if (name === 'nonce' && namespace === null && eligible(node)) save(node,value === null ? '' : value); }
export function copyNonce(original,copy) { if (eligible(original)) save(copy,cryptographicNonce(original)); }
export function nonceConnectionChanged(root,connected) {
  if (!connected) return;
  const doc = browsingDocument(root); if (!doc || !hasHeaderCSP(doc)) return;
  const nodes = shadowTreeNodes(root);
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i]; if (!eligible(node)) continue;
    const attribute = collectionAttribute(node,'nonce'); if (attribute === null || attribute === '') continue;
    const nonce = cryptographicNonce(node);
    setAttribute(node,'nonce',''); save(node,nonce);
  }
}
export function installNonceAPI(L,set,convert) {
  setAttribute = set;
  const fields = {
    get nonce() { if (!eligible(this)) throw new NativeTypeError('An HTML, SVG or MathML element is required'); return cryptographicNonce(this); },
    set nonce(value) { if (!eligible(this)) throw new NativeTypeError('An HTML, SVG or MathML element is required'); value = runDOMCallback(() => convert(value)); save(this,value); },
  };
  for (const prototype of [L.HTMLElement.prototype,L.SVGElement.prototype,L.HTMLScriptElement.prototype]) define(prototype,'nonce',descriptor(fields,'nonce'));
}
