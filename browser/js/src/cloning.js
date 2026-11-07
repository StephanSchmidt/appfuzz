// Clone into the destination document from the start: copying a document
// must not construct its source document's custom elements and then adopt
// those copies. Local names also stay distinct from qualified names.
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { SVGDocument } from '../node_modules/linkedom/esm/svg/document.js';
import { XMLDocument } from '../node_modules/linkedom/esm/xml/document.js';
import { CUSTOM_ELEMENTS, END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nameIdentity } from './names.js';
import { documentMode, rememberDocumentMode } from './document.js';
import { templateContent } from './templates.js';
import { Attr } from '../node_modules/linkedom/esm/interface/attr.js';
import { Text } from '../node_modules/linkedom/esm/interface/text.js';
import { Comment } from '../node_modules/linkedom/esm/interface/comment.js';
import { CDATASection } from '../node_modules/linkedom/esm/interface/cdata-section.js';
import { DocumentType } from '../node_modules/linkedom/esm/interface/document-type.js';
import { DocumentFragment } from '../node_modules/linkedom/esm/interface/document-fragment.js';
import { createBareElement } from './creation.js';
import { elementIs } from './element-state.js';
import { CustomElementRegistry } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';

const HTML = 'http://www.w3.org/1999/xhtml';
const SVG = 'http://www.w3.org/2000/svg';
const NativeProxy = Proxy, read = Reflect.get;
const makeObject = Object.create, getPrototype = Object.getPrototypeOf;
const facade = target => makeObject(getPrototype(target));
const TypeErrorClass = TypeError;
const define = Object.defineProperty;
const NativeWeakMap = WeakMap;
const weakGet = Function.prototype.call.bind(WeakMap.prototype.get);
const weakSet = Function.prototype.call.bind(WeakMap.prototype.set);
const isHTMLDocument = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const isSVGDocument = Object.prototype.isPrototypeOf.bind(SVGDocument.prototype);

function ownNodes(root, owner) {
  const stop = (root[END] || root)[NEXT];
  let node = root;
  do {
    node.ownerDocument = owner;
    node = node[NEXT];
  } while (node !== stop);
}

export function installCloning(L, shareObservers, onScript, upgradeCopies, DOMError) {
  const cloneElement = L.Element.prototype.cloneNode;
  const insert = Object.getPrototypeOf(L.Element.prototype).insertBefore;
  const isElement = Object.prototype.isPrototypeOf.bind(L.Element.prototype);
  const isSVG = Object.prototype.isPrototypeOf.bind(L.SVGElement.prototype);
  const isDocument = Object.prototype.isPrototypeOf.bind(L.Document.prototype);
  const isNode = Object.prototype.isPrototypeOf.bind(L.Node.prototype);
  const isFragment = Object.prototype.isPrototypeOf.bind(DocumentFragment.prototype);
  const isShadow = Object.prototype.isPrototypeOf.bind(L.ShadowRoot.prototype);
  const isRegistry = Object.prototype.isPrototypeOf.bind(CustomElementRegistry.prototype);
  const plainCloners = [
    [Attr, 2, (node, owner) => new Attr(owner, node.localName, node[VALUE])],
    [CDATASection, 4, (node, owner) => new CDATASection(owner, node[VALUE])],
    [Text, 3, (node, owner) => new Text(owner, node[VALUE])],
    [Comment, 8, (node, owner) => new Comment(owner, node[VALUE])],
    [DocumentType, 10, (node, owner) => new DocumentType(owner, node.name, node.publicId, node.systemId)],
  ].map(([Class, type, copy]) => ({ matches: Object.prototype.isPrototypeOf.bind(Class.prototype), type, copy }));
  const plainCloner = node => {
    for (let i = 0; i < plainCloners.length; i++) if (plainCloners[i].matches(node)) return plainCloners[i];
    return null;
  };
  const identityOf = node => nameIdentity(node) || {
    namespace: isSVG(node) ? SVG : HTML,
    prefix: null, local: node.localName, qualified: node.localName,
  };
  const elementInto = (original, deep, owner, templateJobs, elements) => {
    const originals = [original];
    if (deep) {
      for (let node = original[NEXT]; node !== original[END]; node = node[NEXT]) {
        if (nameIdentity(node) || isElement(node)) originals.push(node);
      }
    }
    const copies = [], identities = [];
    const createCopy = () => {
      const original = originals[copies.length];
      const identity = identityOf(original);
      const { local } = identity;
      const copy = createBareElement(owner, identity, elementIs(original));
      copies.push(copy); identities.push(identity); elements.push(copy);
      if (local === 'script') onScript(copy, identity, original);
      return copy;
    };
    const document = new NativeProxy(facade(owner), {
      get(_target, key) {
        if (key === 'createElement' || key === 'createElementNS') return createCopy;
        return read(owner, key, owner);
      },
    });
    const views = new NativeWeakMap();
    const sourceView = node => {
      if (!node) return node;
      let view = weakGet(views, node);
      if (!view) {
        view = new NativeProxy(facade(node), { get(_target, key) {
          const target = node;
          if (key === NEXT || key === END) return sourceView(target[key]);
          if (key === 'ownerDocument') return document;
          if (key === 'localName' && (nameIdentity(target) || isElement(target))) return identityOf(target).local;
          if (key === 'nodeType') return nameIdentity(target) || isElement(target) ? 1 : (plainCloner(target)?.type ?? target.nodeType);
          if (key === 'cloneNode') return () => plainCloner(target).copy(target, owner);
          return read(target, key, target);
        }, has(_target, key) { return key in node; } });
        weakSet(views, node, view);
      }
      return view;
    };
    const source = sourceView(original);
    const clone = cloneElement.call(source, deep);
    ownNodes(clone, owner);
    const nearestSVG = new NativeWeakMap();
    for (let i = 0; i < copies.length; i++) {
      const copy = copies[i], identity = identities[i];
      const content = templateContent(copy);
      if (content && deep) templateJobs.push([templateContent(originals[i]), content]);
      const svg = weakGet(nearestSVG, copy.parentNode) || null;
      if (identity.namespace === SVG) copy.ownerSVGElement = svg;
      weakSet(nearestSVG, copy, identity.namespace === SVG && identity.local === 'svg' ? copy : svg);
    }
    return clone;
  };
  const nodeInto = (node, deep, owner, jobs, elements) => {
    if (nameIdentity(node) || isElement(node)) return elementInto(node, deep, owner, jobs, elements);
    if (isFragment(node)) {
      const copy = new DocumentFragment(owner);
      if (deep) for (let child = node[NEXT]; child !== node[END]; child = (child[END] || child)[NEXT]) insert.call(copy, nodeInto(child, true, owner, jobs, elements));
      return copy;
    }
    const cloner = plainCloner(node);
    if (!cloner) throw new TypeErrorClass('Unsupported node implementation');
    return cloner.copy(node, owner);
  };
  const treeInto = (node, deep, owner) => {
    const jobs = [], elements = [];
    const clone = nodeInto(node, deep, owner, jobs, elements);
    // A work list also handles deeply nested template contents without
    // recursing through the JavaScript stack.
    for (let i = 0; i < jobs.length; i++) {
      const [source, target] = jobs[i];
      for (let child = source[NEXT]; child !== source[END]; child = (child[END] || child)[NEXT]) {
        insert.call(target, nodeInto(child, true, target.ownerDocument, jobs, elements));
      }
    }
    upgradeCopies(elements);
    return clone;
  };
  L.Element.prototype.cloneNode = function (deep = false) {
    return treeInto(this, !!deep, this[END].ownerDocument);
  };
  L.DocumentFragment.prototype.cloneNode = function (deep = false) { return treeInto(this, !!deep, this[END].ownerDocument); };
  L.Document.prototype.importNode = function (node) {
    if (!isDocument(this) || !arguments.length || !isNode(node)) throw new TypeErrorClass('importNode requires a document and a Node');
    const options = arguments[1];
    let deep, registry;
    if (options === undefined) deep = false;
    else if (options === null || typeof options === 'object' || typeof options === 'function') {
      registry = options?.customElementRegistry;
      if (registry != null && !isRegistry(registry)) throw new TypeErrorClass('customElementRegistry must be a CustomElementRegistry');
      deep = !options?.selfOnly;
      if (registry != null && registry !== this[CUSTOM_ELEMENTS]) throw new DOMError('The global registry belongs to another document', 'NotSupportedError');
    } else deep = !!options;
    if (isDocument(node) || isShadow(node)) throw new DOMError('Documents and shadow roots cannot be imported', 'NotSupportedError');
    return treeInto(node, deep, this);
  };
  L.Document.prototype.cloneNode = function (deep = false) {
    const clone = isHTMLDocument(this) ? new HTMLDocument() : isSVGDocument(this) ? new SVGDocument() : new XMLDocument();
    shareObservers(clone);
    const mode = documentMode(this);
    if (mode !== undefined) {
      rememberDocumentMode(clone, mode);
      define(clone, 'compatMode', { value: mode });
    }
    define(clone, 'doctype', { get() {
      for (let node = clone[NEXT]; node !== clone[END]; node = (node[END] || node)[NEXT]) {
        if (node.nodeType === 10) return node;
      }
      return null;
    } });
    if (deep) {
      for (let node = this[NEXT]; node !== this[END]; node = (node[END] || node)[NEXT]) {
        const copy = treeInto(node, true, clone);
        // Cloning does not run insertion's script preparation steps.
        insert.call(clone, copy);
      }
    }
    return clone;
  };
}
