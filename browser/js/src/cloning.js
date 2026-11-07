// Clone into the destination document from the start: copying a document
// must not construct its source document's custom elements and then adopt
// those copies. Local names also stay distinct from qualified names.
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { SVGDocument } from '../node_modules/linkedom/esm/svg/document.js';
import { XMLDocument } from '../node_modules/linkedom/esm/xml/document.js';
import { END, NEXT } from '../node_modules/linkedom/esm/shared/symbols.js';
import { installName, nameIdentity } from './names.js';
import { documentMode, rememberDocumentMode } from './document.js';

const HTML = 'http://www.w3.org/1999/xhtml';
const SVG = 'http://www.w3.org/2000/svg';
const NativeProxy = Proxy, read = Reflect.get;
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

export function installCloning(L, factories, shareObservers, onScript) {
  const cloneElement = L.Element.prototype.cloneNode;
  const insert = Object.getPrototypeOf(L.Element.prototype).insertBefore;
  const isElement = Object.prototype.isPrototypeOf.bind(L.Element.prototype);
  const isSVG = Object.prototype.isPrototypeOf.bind(L.SVGElement.prototype);
  const plainCloners = [];
  // Capture the native classes and methods instead of consulting the
  // page's nodeType/cloneNode properties or collection helpers.
  for (const Class of [L.Text, L.Comment, L.DocumentType, L.CDATASection]) {
    if (Class) plainCloners.push({ matches: Object.prototype.isPrototypeOf.bind(Class.prototype), clone: Class.prototype.cloneNode });
  }
  const identityOf = node => nameIdentity(node) || {
    namespace: isSVG(node) ? SVG : HTML,
    prefix: null, local: node.localName, qualified: node.localName,
  };
  const elementInto = (original, deep, owner) => {
    const originals = [original];
    if (deep) {
      for (let node = original[NEXT]; node !== original[END]; node = node[NEXT]) {
        if (node.nodeType === 1) originals.push(node);
      }
    }
    const copies = [], identities = [];
    const createCopy = () => {
      const original = originals[copies.length];
      const identity = identityOf(original);
      const { namespace, local } = identity;
      const copy = namespace === SVG ? factories.svg.call(owner, namespace, local)
        : (namespace === HTML ? factories.html : factories.xml).call(owner, local);
      copies.push(copy); identities.push(identity);
      installName(copy, identity, isHTMLDocument);
      if (local === 'script') onScript(copy, identity, original);
      return copy;
    };
    const document = new NativeProxy(owner, {
      get(target, key) {
        if (key === 'createElement' || key === 'createElementNS') return createCopy;
        return read(target, key, target);
      },
    });
    const source = new NativeProxy(original, {
      get(target, key) { return key === 'ownerDocument' ? document : read(target, key, target); },
    });
    const clone = cloneElement.call(source, deep);
    ownNodes(clone, owner);
    const nearestSVG = new NativeWeakMap();
    for (let i = 0; i < copies.length; i++) {
      const copy = copies[i], identity = identities[i];
      const svg = weakGet(nearestSVG, copy.parentNode) || null;
      if (identity.namespace === SVG) copy.ownerSVGElement = svg;
      weakSet(nearestSVG, copy, identity.namespace === SVG && identity.local === 'svg' ? copy : svg);
    }
    return clone;
  };
  L.Element.prototype.cloneNode = function (deep = false) {
    return elementInto(this, deep, this.ownerDocument);
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
        let copy;
        if (nameIdentity(node) || isElement(node)) copy = elementInto(node, true, clone);
        else {
          let method;
          for (let i = 0; i < plainCloners.length; i++) {
            if (plainCloners[i].matches(node)) { method = plainCloners[i].clone; break; }
          }
          copy = method.call(node);
          ownNodes(copy, clone);
        }
        // Cloning does not run insertion's script preparation steps.
        insert.call(clone, copy);
      }
    }
    return clone;
  };
}
