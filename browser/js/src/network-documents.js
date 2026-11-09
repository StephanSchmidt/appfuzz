import { rememberDocumentURL } from './document-state.js';
import { parsedAttribute } from './attributes.js';
// Network documents have no browsing context and execute no scripts. XML is
// validated and namespace-resolved in Rust before these DOM nodes are made.
import { DOMParser } from 'linkedom';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { CharacterData } from '../node_modules/linkedom/esm/interface/character-data.js';
import { createBareElement } from './creation.js';
import { parseHTML } from './document.js';
const xml = globalThis.__native.xmlTree, apply = Reflect.apply, setPrototype = Object.setPrototypeOf, define = Object.defineProperty;
const parse = DOMParser.prototype.parseFromString, parser = DOMParser;
const text = Document.prototype.createTextNode, comment = Document.prototype.createComment, cdata = Document.prototype.createCDATASection, doctype = Document.prototype.createDocumentType;
const insert = Object.getPrototypeOf(Element.prototype).insertBefore;
const indexOf = Function.prototype.call.bind(String.prototype.indexOf), slice = Function.prototype.call.bind(String.prototype.slice);
export function parseNetworkDocument(markup, mime, url, encoding = 'UTF-8') {
  let doc;
  if (mime === 'text/html') doc = parseHTML(markup, false);
  else {
    const tree = xml(markup); if (tree === null) return null;
    doc = apply(parse, new parser(), ['', 'text/xml']);
    const nodes = []; setPrototype(nodes, null); nodes[0] = doc;
    for (let i = 1; i < tree.length; i++) {
      const data = tree[i]; let node;
      if (data[0] === 'element') {
        const qualified = data[2], colon = indexOf(qualified, ':'), prefix = colon < 0 ? null : slice(qualified, 0, colon), local = colon < 0 ? qualified : slice(qualified, colon + 1);
        node = createBareElement(doc, { namespace: data[3], prefix, local, qualified });
        const attrs = data[4]; for (let j = 0; j < attrs.length; j++) parsedAttribute(node, attrs[j][1], attrs[j][0], attrs[j][2]);
      } else if (data[0] === 'text') node = apply(text, doc, [data[2]]);
      else if (data[0] === 'cdata') node = apply(cdata, doc, [data[2]]);
      else if (data[0] === 'doctype') node = apply(doctype, doc, [data[2], data[3], data[4]]);
      else if (data[0] === 'comment') node = apply(comment, doc, [data[2]]);
      else {
        node = new CharacterData(doc, data[2], 7, data[3]);
        define(node, 'target', { __proto__: null, value: data[2], enumerable: true });
      }
      nodes[i] = node; apply(insert, nodes[data[1]], [node]);
    }
  }
  rememberDocumentURL(doc,url);
  const urlKeys = ['URL','documentURI']; for (let i = 0; i < urlKeys.length; i++) define(doc, urlKeys[i], { __proto__: null, value: url, configurable: true });
  const encodingKeys = ['characterSet','charset','inputEncoding']; for (let i = 0; i < encodingKeys.length; i++) define(doc, encodingKeys[i], { __proto__: null, value: encoding, configurable: true });
  define(doc, 'contentType', { __proto__: null, value: mime, configurable: true });
  define(doc, 'defaultView', { __proto__: null, value: null, configurable: true });
  return doc;
}
