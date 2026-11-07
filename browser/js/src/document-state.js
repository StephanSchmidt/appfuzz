// Document metadata used by parsing, inert template documents and cloning.
const modes = new WeakMap();
export const documentMode = modes.get.bind(modes);
export const rememberDocumentMode = modes.set.bind(modes);
