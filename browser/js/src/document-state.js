// Document metadata used by parsing, inert template documents and cloning.
const modes = new WeakMap();
export const documentMode = modes.get.bind(modes);
export const rememberDocumentMode = modes.set.bind(modes);

const scripting = new WeakMap();
export const documentScripting = scripting.get.bind(scripting);
export const rememberDocumentScripting = scripting.set.bind(scripting);

// Native URLs are independent of page shadows of Document.URL and baseURI.
const urls = new WeakMap(), readURL = urls.get.bind(urls);
export const rememberDocumentURL = urls.set.bind(urls);
export function documentURL(doc) { const value = readURL(doc); return typeof value === 'function' ? value() : value || 'about:blank'; }

let factory;
export function installDocumentFactory(value) { factory = value; }
export function createDocumentLike(doc) { return factory(doc); }
