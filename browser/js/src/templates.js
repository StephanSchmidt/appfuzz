// Template contents are a separate tree, owned by a document without a
// browsing context or the page's custom-element registry. Nested templates
// share that inert document. Ordinary children of a template stay ordinary
// children; reading .content must never copy or move them.
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { XMLDocument } from '../node_modules/linkedom/esm/xml/document.js';
import { DocumentFragment } from '../node_modules/linkedom/esm/interface/document-fragment.js';
import { HTMLTemplateElement } from '../node_modules/linkedom/esm/html/template-element.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { TextElement } from '../node_modules/linkedom/esm/html/text-element.js';
import { Text } from '../node_modules/linkedom/esm/interface/text.js';
import { Comment } from '../node_modules/linkedom/esm/interface/comment.js';
import { CDATASection } from '../node_modules/linkedom/esm/interface/cdata-section.js';
import { CONTENT, END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { rememberDocumentMode } from './document-state.js';
import { nameIdentity } from './names.js';

const define = Object.defineProperty;
const isHTML = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const isTemplate = Object.prototype.isPrototypeOf.bind(HTMLTemplateElement.prototype);
const serializers = [TextElement, Element, Text, Comment, CDATASection].map(Class => ({ matches: Object.prototype.isPrototypeOf.bind(Class.prototype), serialize: Class.prototype.toString }));
const documents = new WeakMap(), contents = new WeakMap();
const owner = documents.get.bind(documents), saveOwner = documents.set.bind(documents);
const content = contents.get.bind(contents), saveContent = contents.set.bind(contents);
let shareObservers = () => {};

export function templateOwner(document) {
  let inert = owner(document);
  if (!inert) {
    const html = isHTML(document);
    inert = html ? new HTMLDocument() : new XMLDocument();
    saveOwner(document, inert); saveOwner(inert, inert);
    rememberDocumentMode(inert, 'CSS1Compat');
    define(inert, 'compatMode', { value: 'CSS1Compat' });
    define(inert, 'defaultView', { value: null });
    define(inert, 'contentType', { value: html ? 'text/html' : 'application/xml' });
  }
  shareObservers(inert);
  return inert;
}

export function templateContent(node) {
  if (!isTemplate(node)) return null;
  let result = content(node);
  if (!result) {
    result = new DocumentFragment(templateOwner(node[END].ownerDocument));
    saveContent(node, result);
  }
  // Linkedom's constructor and adoption helpers also consult this slot.
  // Do not set its PRIVATE slot: native fragment insertion would otherwise
  // delete the template's unrelated light children.
  node[CONTENT] = result;
  return result;
}

define(HTMLTemplateElement.prototype, 'content', { configurable: true, get() { return templateContent(this); } });

export function templateInnerHTML(node) {
  const root = templateContent(node);
  let result = '';
  for (let child = root[NEXT]; child !== root[END]; child = (child[END] || child)[NEXT]) {
    if (isTemplate(child)) result += serializeTemplate.call(child);
    else {
      for (let i = 0; i < serializers.length; i++) {
        if (serializers[i].matches(child)) { result += serializers[i].serialize.call(child); break; }
      }
    }
  }
  return result;
}

const escapeAttribute = value => value.replace(/&/g, '&amp;').replace(/\u00a0/g, '&nbsp;').replace(/"/g, '&quot;');
function serializeTemplate() {
  const identity = nameIdentity(this);
  const name = isHTML(this[END].ownerDocument) ? 'template' : (identity?.qualified || 'template');
  let result = '<' + name;
  for (let attr = this[NEXT]; attr.nodeType === 2; attr = attr[NEXT]) result += ' ' + attr.localName + '="' + escapeAttribute(attr[VALUE]) + '"';
  return result + '>' + templateInnerHTML(this) + '</' + name + '>';
}
HTMLTemplateElement.prototype.toString = serializeTemplate;

export function shareTemplateObservers(share) { shareObservers = share; }
