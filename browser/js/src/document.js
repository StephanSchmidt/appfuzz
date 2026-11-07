// Build the initial HTML document with the HTML tree-building rules, then
// copy its nodes into linkedom. No serialization/reparse: raw text,
// namespaces and inert template contents must keep their parsed meaning.
import { DOMParser } from 'linkedom';
import { parse } from 'parse5';
import { rememberName } from './names.js';

const nativeParse = DOMParser.prototype.parseFromString;
const HTML = 'http://www.w3.org/1999/xhtml';
const SVG = 'http://www.w3.org/2000/svg';

export function parseHTML(markup, scriptingEnabled) {
  const tree = parse(String(markup), { scriptingEnabled });
  const doc = nativeParse.call(new DOMParser(), '', 'text/html');
  const stack = [];
  const children = (parent, nodes, svg = null) => {
    for (let i = nodes.length - 1; i >= 0; i--) stack.push([parent, nodes[i], svg]);
  };
  children(doc, tree.childNodes);
  while (stack.length) {
    const [parent, source, svg] = stack.pop();
    let node;
    switch (source.nodeName) {
      case '#text': node = doc.createTextNode(source.value); break;
      case '#comment': node = doc.createComment(source.data); break;
      case '#documentType': node = doc.createDocumentType(source.name, source.publicId, source.systemId); break;
      default: {
        node = source.namespaceURI === HTML ? doc.createElement(source.tagName) : doc.createElementNS(source.namespaceURI, source.tagName);
        rememberName(node, { namespace: source.namespaceURI, prefix: null, local: source.tagName, qualified: source.tagName });
        if (source.namespaceURI === SVG) node.ownerSVGElement = svg;
        // linkedom has HTML and SVG element classes; other foreign nodes
        // still need their own namespace, notably MathML.
        if (source.namespaceURI !== HTML && source.namespaceURI !== SVG) {
          Object.defineProperty(node, 'namespaceURI', { value: source.namespaceURI });
        }
        for (const attr of source.attrs) {
          const name = attr.prefix ? attr.prefix + ':' + attr.name : attr.name;
          if (attr.namespace) node.setAttributeNS(attr.namespace, name, attr.value);
          else node.setAttribute(name, attr.value);
        }
        if (source.content) children(node.content, source.content.childNodes);
        else children(node, source.childNodes, source.namespaceURI === SVG && source.tagName === 'svg' ? node : svg);
      }
    }
    parent.appendChild(node);
  }
  Object.defineProperty(doc, 'compatMode', { value: tree.mode === 'quirks' ? 'BackCompat' : 'CSS1Compat' });
  // The native getter looks only at the first child; a leading comment
  // must not hide the actual doctype.
  Object.defineProperty(doc, 'doctype', { get: () => [...doc.childNodes].find(n => n.nodeType === 10) || null });
  return doc;
}
