// Build the initial HTML document with the HTML tree-building rules, then
// copy its nodes into linkedom. No serialization/reparse: raw text,
// namespaces and inert template contents must keep their parsed meaning.
import { DOMParser } from 'linkedom';
import { parse, parseFragment, defaultTreeAdapter } from 'parse5';
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { installName, nameIdentity } from './names.js';
import { rememberScript } from './script-state.js';

const nativeParse = DOMParser.prototype.parseFromString;
const HTML = 'http://www.w3.org/1999/xhtml';
const SVG = 'http://www.w3.org/2000/svg';
const createHTML = HTMLDocument.prototype.createElement;
const createXML = Document.prototype.createElement;
const createNS = Document.prototype.createElementNS;
const text = Document.prototype.createTextNode;
const comment = Document.prototype.createComment;
const doctype = Document.prototype.createDocumentType;
const fragment = Document.prototype.createDocumentFragment;
const insert = Object.getPrototypeOf(Element.prototype).insertBefore;
const setAttribute = Element.prototype.setAttribute;
const setAttributeNS = Element.prototype.setAttributeNS;
const isHTMLDocument = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const modes = new WeakMap();
export const documentMode = modes.get.bind(modes);
export const rememberDocumentMode = modes.set.bind(modes);

export function parseHTML(markup, scriptingEnabled) {
  const tree = parse(String(markup), { scriptingEnabled });
  const doc = nativeParse.call(new DOMParser(), '', 'text/html');
  appendTree(doc, doc, tree.childNodes, !scriptingEnabled);
  const mode = tree.mode === 'quirks' ? 'BackCompat' : 'CSS1Compat';
  rememberDocumentMode(doc, mode);
  Object.defineProperty(doc, 'compatMode', { value: mode });
  // The native getter looks only at the first child; a leading comment
  // must not hide the actual doctype.
  Object.defineProperty(doc, 'doctype', { get: () => [...doc.childNodes].find(n => n.nodeType === 10) || null });
  return doc;
}

function appendTree(doc, target, nodes, inertScripts, svg = null) {
  const stack = [];
  const children = (parent, nodes, svg = null) => {
    for (let i = nodes.length - 1; i >= 0; i--) stack.push([parent, nodes[i], svg]);
  };
  children(target, nodes, svg);
  while (stack.length) {
    const [parent, source, svg] = stack.pop();
    let node;
    switch (source.nodeName) {
      case '#text': node = text.call(doc, source.value); break;
      case '#comment': node = comment.call(doc, source.data); break;
      case '#documentType': node = doctype.call(doc, source.name, source.publicId, source.systemId); break;
      default: {
        const is = source.attrs.find(attr => attr.name === 'is' && !attr.namespace)?.value;
        node = source.namespaceURI === SVG ? createNS.call(doc, SVG, source.tagName)
          : (source.namespaceURI === HTML ? createHTML : createXML).call(doc, source.tagName, is == null ? undefined : { is });
        installName(node, { namespace: source.namespaceURI, prefix: null, local: source.tagName, qualified: source.tagName }, isHTMLDocument);
        if (source.tagName === 'script') rememberScript(node, { namespace: source.namespaceURI, local: source.tagName }, inertScripts);
        if (source.namespaceURI === SVG) node.ownerSVGElement = svg;
        for (const attr of source.attrs) {
          const name = attr.prefix ? attr.prefix + ':' + attr.name : attr.name;
          if (attr.namespace) setAttributeNS.call(node, attr.namespace, name, attr.value);
          else setAttribute.call(node, name, attr.value);
        }
        if (source.content) children(node.content, source.content.childNodes);
        else children(node, source.childNodes, source.namespaceURI === SVG && source.tagName === 'svg' ? node : svg);
      }
    }
    insert.call(parent, node);
  }
}

// Each copied script gets its parser state explicitly. API calls made by
// custom-element constructors during this work are ordinary fresh scripts.
export function parseHTMLFragment(markup, context, doc, inertScripts = true) {
  const svg = context?.namespaceURI === SVG ? (context.localName === 'svg' ? context : context.ownerSVGElement) : null;
  if (!context || context.nodeType !== 1) context = null;
  if (!context || (nameIdentity(context)?.namespace === HTML && context.localName === 'html')) {
    context = defaultTreeAdapter.createElement('body', HTML, []);
  } else {
    let ast = null, child = null;
    for (let node = context; node && node.nodeType === 1; node = node.parentNode) {
      const identity = nameIdentity(node) || { namespace: node.namespaceURI, local: node.localName };
      const attrs = [];
      for (let attr = node[NEXT]; attr && attr.nodeType === 2; attr = attr[NEXT]) attrs.push({ name: attr.localName, value: attr[VALUE] });
      const parent = defaultTreeAdapter.createElement(identity.local, identity.namespace, attrs);
      if (!ast) ast = parent;
      if (child) defaultTreeAdapter.appendChild(parent, child);
      child = parent;
    }
    context = ast;
  }
  const tree = parseFragment(context, String(markup), { scriptingEnabled: true });
  const result = fragment.call(doc);
  appendTree(doc, result, tree.childNodes, inertScripts, svg);
  return result;
}
