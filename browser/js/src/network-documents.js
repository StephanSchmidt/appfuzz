// Network documents have no browsing context and execute no scripts. XML is
// validated and namespace-resolved in Rust before these DOM nodes are made.
import { DOMParser } from 'linkedom';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { Attr } from '../node_modules/linkedom/esm/interface/attr.js';
import { NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { knownSiblings } from '../node_modules/linkedom/esm/shared/utils.js';
import { CharacterData } from '../node_modules/linkedom/esm/interface/character-data.js';
import { createBareElement } from './creation.js';
import { parseHTML } from './document.js';
const xml = globalThis.__native.xmlTree, apply = Reflect.apply, setPrototype = Object.setPrototypeOf, define = Object.defineProperty;
const parse = DOMParser.prototype.parseFromString, parser = DOMParser;
const text = Document.prototype.createTextNode, comment = Document.prototype.createComment;
const insert = Object.getPrototypeOf(Element.prototype).insertBefore;
const indexOf = Function.prototype.call.bind(String.prototype.indexOf), slice = Function.prototype.call.bind(String.prototype.slice);
export function parseNetworkDocument(markup, mime, url) {
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
        const attrs = data[4]; for (let j = 0; j < attrs.length; j++) {
          const item = attrs[j], attr = new Attr(doc, item[0], item[2]), at = indexOf(item[0], ':');
          define(attr, 'namespaceURI', { __proto__: null, value: item[1], configurable: true });
          define(attr, 'prefix', { __proto__: null, value: at < 0 ? null : slice(item[0], 0, at), configurable: true });
          attr.ownerElement = node; knownSiblings(node, attr, node[NEXT]);
        }
      } else if (data[0] === 'text') node = apply(text, doc, [data[2]]);
      else if (data[0] === 'comment') node = apply(comment, doc, [data[2]]);
      else {
        node = new CharacterData(doc, data[2], 7, data[3]);
        define(node, 'target', { __proto__: null, value: data[2], enumerable: true });
      }
      nodes[i] = node; apply(insert, nodes[data[1]], [node]);
    }
  }
  for (const key of ['URL','documentURI','baseURI']) define(doc, key, { __proto__: null, value: url, configurable: true });
  define(doc, 'contentType', { __proto__: null, value: mime, configurable: true });
  define(doc, 'defaultView', { __proto__: null, value: null, configurable: true });
  return doc;
}
