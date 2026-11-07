// Serialize the existing tree. In particular, a text element must never
// clone itself (and run a custom constructor) to obtain its start tag.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { TextElement } from '../node_modules/linkedom/esm/html/text-element.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { nameIdentity } from './names.js';
import { documentScripting } from './document-state.js';
import { elementIs } from './element-state.js';
import { templateContent } from './templates.js';

const htmlDocument = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const nativeString = Element.prototype.toString;
const HTML = 'http://www.w3.org/1999/xhtml';
const voidNames = new Set(['area','base','basefont','bgsound','frame','link','meta','input','embed','param','hr','img','br','wbr','col','source','track','keygen']);
const rawNames = new Set(['style','script','xmp','iframe','noembed','noframes','plaintext']);
const rawText = (node, identity) => identity?.namespace === HTML && (isRaw(identity.local) || (identity.local === 'noscript' && documentScripting(node[END].ownerDocument)));
const isVoid = voidNames.has.bind(voidNames), isRaw = rawNames.has.bind(rawNames);
const escapeText = value => value.replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escapeAttribute = value => value.replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
function children(root, raw, stack) {
  const nodes = [];
  for (let node = root[NEXT]; node !== root[END]; node = (node[END] || node)[NEXT]) if (node.nodeType !== 2) nodes.push(node);
  for (let i = nodes.length - 1; i >= 0; i--) stack.push([nodes[i], raw]);
}
function serialize(root, inner) {
  const stack = [], out = [];
  const identity = nameIdentity(root);
  if (inner && identity?.namespace === HTML && isVoid(identity.local)) return '';
  if (inner) children(templateContent(root) || root, rawText(root, identity), stack);
  else stack.push([root, false]);
  while (stack.length) {
    const [node, raw] = stack.pop();
    if (typeof node === 'string') { out.push(node); continue; }
    if (node.nodeType === 3 || node.nodeType === 4) { out.push(raw ? node[VALUE] : escapeText(node[VALUE])); continue; }
    if (node.nodeType === 8) { out.push('<!--' + node[VALUE] + '-->'); continue; }
    if (node.nodeType === 10) { out.push('<!DOCTYPE ' + node.name + '>'); continue; }
    if (node.nodeType === 7) { out.push('<?' + node.target + ' ' + node[VALUE] + '?>'); continue; }
    if (node.nodeType !== 1) continue;
    const identity = nameIdentity(node) || { namespace: node.namespaceURI, local: node.localName, qualified: node.localName };
    const name = identity.namespace === HTML || identity.namespace === 'http://www.w3.org/2000/svg' || identity.namespace === 'http://www.w3.org/1998/Math/MathML' ? identity.local : identity.qualified;
    let start = '<' + name, attrs = '', hasIs = false;
    for (let attr = node[NEXT]; attr.nodeType === 2; attr = attr[NEXT]) {
      if (attr.localName === 'is') hasIs = true;
      attrs += ' ' + attr.localName + '="' + escapeAttribute(attr[VALUE]) + '"';
    }
    const is = elementIs(node);
    if (is !== null && !hasIs) start += ' is="' + escapeAttribute(is) + '"';
    out.push(start + attrs + '>');
    if (identity.namespace === HTML && isVoid(identity.local)) continue;
    stack.push(['</' + name + '>', false]);
    children(templateContent(node) || node, rawText(node, identity), stack);
  }
  return out.join('');
}
export const serializeNode = node => serialize(node, false);
export const serializeChildren = node => serialize(node, true);

export function installSerialization(L) {
  const define = Object.defineProperty;
  for (const proto of [L.Element.prototype, TextElement.prototype, L.ShadowRoot.prototype, L.DocumentFragment.prototype, L.HTMLTemplateElement.prototype]) {
    for (const key of ['innerHTML','outerHTML']) {
      const descriptor = Object.getOwnPropertyDescriptor(proto, key);
      if (!descriptor?.get) continue;
      define(proto, key, { ...descriptor, get() {
        if (!htmlDocument(this[END].ownerDocument)) return descriptor.get.call(this);
        return key === 'innerHTML' ? serializeChildren(this) : serializeNode(this);
      } });
    }
  }
  for (const proto of [L.Element.prototype, TextElement.prototype, L.HTMLTemplateElement.prototype]) {
    proto.toString = function () { return htmlDocument(this[END].ownerDocument) ? serializeNode(this) : nativeString.call(this); };
  }
}
