import { documentBaseURL, resolveDocumentURL } from './document-urls.js';
import { attributeMethods } from './attributes.js';
// DOMImplementation objects have stable per-document identity. Factories use
// captured primitives, never page replacements of document methods or globals.
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { SVGDocument } from '../node_modules/linkedom/esm/svg/document.js';
import { XMLDocument as NativeXMLDocument } from '../node_modules/linkedom/esm/xml/document.js';
import { DocumentType } from '../node_modules/linkedom/esm/interface/document-type.js';
import { createBareElement } from './creation.js';
import { createNativeText, insertNativeNode, replaceAllText } from './dom-mutations.js';
import { backendChildNodes, collectionDescendants } from './collection-data.js';
import { nodeInfo, nodeDocument, physicalDocumentElement, physicalHead, physicalBody } from './dom-state.js';
import { qualifiedName, nameIdentity } from './names.js';
import { rememberDocumentMode, rememberDocumentScripting, rememberDocumentURL, installDocumentFactory } from './document-state.js';
import { adoptNativeNode } from './adoption.js';
import { platformConstructor } from './constructors.js';
import { markPlatform } from './platform-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { eventString } from './event-state.js';
import { characterValue } from './character-data-state.js';
import { withReactions } from './ce-reactions.js';
import { DOMException } from './dom-exception.js';
const create = Object.create, define = Object.defineProperty, NativeTypeError = TypeError;
const implementations = new WeakMap(), read = implementations.get.bind(implementations), save = implementations.set.bind(implementations);
const documents = new WeakMap(), owner = documents.get.bind(documents), saveOwner = documents.set.bind(documents);
const HTML = 'http://www.w3.org/1999/xhtml', SVG = 'http://www.w3.org/2000/svg';
const apply = Reflect.apply, getAttribute = attributeMethods.getAttribute, setAttribute = attributeMethods.setAttribute;
function required(count,minimum) { if (count < minimum) throw new NativeTypeError('Not enough arguments'); }
function requireImplementation(value) { const document = owner(value); if (!document) throw new NativeTypeError('A DOMImplementation is required'); return document; }
function requireDocument(value) { if (nodeInfo(value)?.kind !== 9) throw new NativeTypeError('A Document is required'); }
function append(parent,node) { insertNativeNode(parent,node); }
function metadata(doc,mime,html) {
  const fields = ['URL','documentURI','characterSet','charset','inputEncoding','contentType','defaultView','compatMode'];
  const values = ['about:blank','about:blank','UTF-8','UTF-8','UTF-8',mime,null,'CSS1Compat'];
  for (let i = 0; i < fields.length; i++) define(doc,fields[i],{ __proto__: null, value: values[i], configurable: true });
  rememberDocumentURL(doc,'about:blank');
  if (html) rememberDocumentMode(doc,'CSS1Compat');
  rememberDocumentScripting(doc,false);
  define(doc,'doctype',{ __proto__: null, configurable: true, get() { const nodes = backendChildNodes(doc); for (let i = 0; i < nodes.length; i++) if (nodeInfo(nodes[i])?.kind === 10) return nodes[i]; return null; } });
  return doc;
}
function element(doc,local) { return createBareElement(doc,{ __proto__: null, namespace: HTML, prefix: null, local, qualified: local }); }
function matches(node,namespace,local) { const id = nameIdentity(node); return id?.namespace === namespace && id.local === local; }
function first(root,namespace,local,direct = false) { const nodes = direct ? backendChildNodes(root) : collectionDescendants(root); for (let i = 0; i < nodes.length; i++) if (matches(nodes[i],namespace,local)) return nodes[i]; return null; }
function titleNode(doc) { const root = physicalDocumentElement(doc); return matches(root,SVG,'svg') ? first(root,SVG,'title',true) : first(doc,HTML,'title'); }
function titleValue(doc) {
  const node = titleNode(doc); if (!node) return ''; const children = backendChildNodes(node); let value = '';
  for (let i = 0; i < children.length; i++) { const kind = nodeInfo(children[i])?.kind; if (kind === 3 || kind === 4) value += characterValue(children[i]); }
  let result = '', space = false; for (let i = 0; i < value.length; i++) { const c = value[i]; if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f') space = !!result; else { if (space) result += ' '; result += c; space = false; } } return result;
}
function setTitle(doc,value) {
  const root = physicalDocumentElement(doc); let node = titleNode(doc);
  if (matches(root,SVG,'svg')) { if (!node) { node = createBareElement(doc,{ __proto__: null, namespace: SVG, prefix: null, local: 'title', qualified: 'title' }); insertNativeNode(root,node,backendChildNodes(root)[0] || null); } }
  else if (nameIdentity(root)?.namespace === HTML) { if (!node) { const head = first(root,HTML,'head',true); if (!head) return; node = element(doc,'title'); append(head,node); } }
  else return;
  replaceAllText(node,value);
}
function validDoctype(name) { for (let i = 0; i < name.length; i++) { const c = name[i]; if (c === '\0' || c === ' ' || c === '\t' || c === '\n' || c === '\f' || c === '\r' || c === '>') return false; } return true; }
export let DOMImplementation = class DOMImplementation {
  constructor() { throw new NativeTypeError('Illegal constructor'); }
  createDocumentType(name,publicId,systemId) {
    const doc = requireImplementation(this); required(arguments.length,3);
    const args = runDOMCallback(() => ({ __proto__: null, name: eventString(name), publicId: eventString(publicId), systemId: eventString(systemId) }));
    if (!validDoctype(args.name)) throw new DOMException('Invalid doctype name','InvalidCharacterError');
    return new DocumentType(doc,args.name,args.publicId,args.systemId);
  }
  createDocument(namespace,name,doctype = null) {
    requireImplementation(this); required(arguments.length,2);
    const args = runDOMCallback(() => ({ __proto__: null, namespace: namespace == null ? null : eventString(namespace), name: name === null ? '' : eventString(name) }));
    if (doctype !== null && nodeInfo(doctype)?.kind !== 10) throw new NativeTypeError('A DocumentType is required');
    const mime = args.namespace === HTML ? 'application/xhtml+xml' : args.namespace === SVG ? 'image/svg+xml' : 'application/xml';
    const doc = metadata(new NativeXMLDocument(),mime,false);
    const root = args.name === '' ? null : createBareElement(doc,qualifiedName(args.namespace,args.name,2,DOMException));
    if (doctype) { adoptNativeNode(doc,doctype); append(doc,doctype); }
    if (root) append(doc,root);
    return doc;
  }
  createHTMLDocument(title = undefined) {
    requireImplementation(this); const given = title !== undefined; if (given) title = runDOMCallback(() => eventString(title));
    const doc = metadata(new HTMLDocument(),'text/html',true), html = element(doc,'html'), head = element(doc,'head');
    append(doc,new DocumentType(doc,'html','','')); append(doc,html); append(html,head);
    if (given) { const node = element(doc,'title'); append(head,node); append(node,createNativeText(doc,title)); }
    append(html,element(doc,'body')); return doc;
  }
  hasFeature() { requireImplementation(this); return true; }
};
DOMImplementation = platformConstructor(DOMImplementation,'DOMImplementation',0,true);
define(DOMImplementation.prototype,Symbol.toStringTag,{ __proto__: null, value: 'DOMImplementation', configurable: true });
const XMLConstructor = function XMLDocument() { throw new NativeTypeError('Illegal constructor'); };
XMLConstructor.prototype = NativeXMLDocument.prototype;
export const XMLDocument = platformConstructor(XMLConstructor,'XMLDocument',0,true);
define(XMLDocument.prototype,Symbol.toStringTag,{ __proto__: null, value: 'XMLDocument', configurable: true });
for (const key of ['createDocumentType','createDocument','createHTMLDocument','hasFeature']) define(DOMImplementation.prototype,key,{ ...Object.getOwnPropertyDescriptor(DOMImplementation.prototype,key), enumerable: true });
export function installDOMImplementation(L) {
  const html = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype), svg = Object.prototype.isPrototypeOf.bind(SVGDocument.prototype);
  installDocumentFactory(doc => html(doc) ? new HTMLDocument() : svg(doc) ? new SVGDocument() : new NativeXMLDocument());
  const tree = { get head() { requireDocument(this); return physicalHead(this); }, get body() { requireDocument(this); return physicalBody(this); } };
  for (const key of ['head','body']) { delete HTMLDocument.prototype[key]; define(L.Document.prototype,key,{ ...Object.getOwnPropertyDescriptor(tree,key), enumerable: true }); }
  const base = { get baseURI() { const kind = nodeInfo(this)?.kind; if (kind === undefined) throw new NativeTypeError('A Node is required'); return documentBaseURL(kind === 9 ? this : nodeDocument(this)); } };
  define(L.Node.prototype,'baseURI',Object.getOwnPropertyDescriptor(base,'baseURI'));
  const href = { get href() { if (!matches(this,HTML,'base')) throw new NativeTypeError('An HTMLBaseElement is required'); const href = apply(getAttribute,this,['href']); return href === null ? '' : resolveDocumentURL(href,nodeDocument(this)); }, set href(value) { if (!matches(this,HTML,'base')) throw new NativeTypeError('An HTMLBaseElement is required'); value = runDOMCallback(() => eventString(value)); withReactions(() => apply(setAttribute,this,['href',value])); } };
  define(L.HTMLBaseElement.prototype,'href',Object.getOwnPropertyDescriptor(href,'href'));
  const title = { get title() { requireDocument(this); return titleValue(this); }, set title(value) { requireDocument(this); value = runDOMCallback(() => eventString(value)); withReactions(() => setTitle(this,value)); } };
  for (const prototype of [L.Document.prototype,HTMLDocument.prototype]) define(prototype,'title',Object.getOwnPropertyDescriptor(title,'title'));
  const fields = { get implementation() { requireDocument(this); let value = read(this); if (!value) { value = create(DOMImplementation.prototype); markPlatform(value); saveOwner(value,this); save(this,value); } return value; } };
  define(L.Document.prototype,'implementation',{ ...Object.getOwnPropertyDescriptor(fields,'implementation'), enumerable: true });
  define(L.Document.prototype,'adoptNode',{ __proto__: null, configurable: true, enumerable: true, writable: true, value: function adoptNode(node) { requireDocument(this); required(arguments.length,1); if (!nodeInfo(node)) throw new NativeTypeError('A Node is required'); return adoptNativeNode(this,node); } });
}
