// DOM name validation and extraction. These rules deliberately follow
// DOM's current name rules rather than the older XML NCName grammar.
const toString = String;
const TypeErrorClass = TypeError;
const apply = Reflect.apply;
const exec = RegExp.prototype.exec;
const indexOf = String.prototype.indexOf;
const slice = String.prototype.slice;
const define = Object.defineProperties;
const upper = String.prototype.toUpperCase;
const replace = String.prototype.replace;
const identities = new WeakMap();
export const nameIdentity = identities.get.bind(identities);
export const rememberName = identities.set.bind(identities);
const elementName = /^(?:[A-Za-z][^\0\t\n\f\r />]*|[:_\u0080-\u{10FFFF}][A-Za-z0-9-.:_\u0080-\u{10FFFF}]*)$/u;
const prefixName = /^[^\0\t\n\f\r />]+$/u;
const asciiLower = /[a-z]/g;
// Keep case folding independent of page overrides of regexp methods.
define(asciiLower, {
  [Symbol.replace]: { value: RegExp.prototype[Symbol.replace] },
  exec: { value: exec }, global: { value: true }, unicode: { value: false }, unicodeSets: { value: false },
});

export const validElementLocalName = name => apply(exec, elementName, [name]) !== null;

function domString(value) {
  if (typeof value === 'symbol') throw new TypeErrorClass('A Symbol cannot be converted to a DOMString');
  return toString(value);
}

export function qualifiedName(namespace, name, argumentCount, DOMError) {
  if (argumentCount < 2) throw new TypeErrorClass('createElementNS requires namespace and qualifiedName');
  namespace = namespace == null ? null : domString(namespace);
  if (namespace === '') namespace = null;
  const qualified = domString(name);
  const colon = apply(indexOf, qualified, [':']);
  const prefix = colon < 0 ? null : apply(slice, qualified, [0, colon]);
  const local = colon < 0 ? qualified : apply(slice, qualified, [colon + 1]);
  if ((prefix !== null && !apply(exec, prefixName, [prefix])) || !apply(exec, elementName, [local])) {
    throw new DOMError('Invalid element name', 'InvalidCharacterError');
  }
  if ((prefix !== null && namespace === null)
    || (prefix === 'xml' && namespace !== 'http://www.w3.org/XML/1998/namespace')
    || ((qualified === 'xmlns' || prefix === 'xmlns') && namespace !== 'http://www.w3.org/2000/xmlns/')
    || (namespace === 'http://www.w3.org/2000/xmlns/' && qualified !== 'xmlns' && prefix !== 'xmlns')) {
    throw new DOMError('Invalid namespace and prefix combination', 'NamespaceError');
  }
  return { namespace, prefix, local, qualified };
}

export function installName(element, name, isHTMLDocument) {
  rememberName(element, name);
  const { namespace, prefix, qualified } = name;
  const upperName = apply(replace, qualified, [asciiLower, c => apply(upper, c, [])]);
  const tagName = () => namespace === 'http://www.w3.org/1999/xhtml' && isHTMLDocument(element.ownerDocument) ? upperName : qualified;
  define(element, {
    namespaceURI: { configurable: true, value: namespace },
    prefix: { configurable: true, value: prefix },
    tagName: { configurable: true, get: tagName },
    nodeName: { configurable: true, get: tagName },
  });
}
