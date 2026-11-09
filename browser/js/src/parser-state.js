const parsers = new WeakSet(), save = parsers.add.bind(parsers), has = parsers.has.bind(parsers), NativeTypeError = TypeError;
export function initializeParser(value) { save(value); }
export function requireParser(value) { if (!has(value)) throw new NativeTypeError('A DOMParser is required'); }
