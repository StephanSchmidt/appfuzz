import { validElementLocalName } from './names.js';
const reserved = new Set(['annotation-xml','color-profile','font-face','font-face-src','font-face-uri','font-face-format','font-face-name','missing-glyph']);
const reservedName = reserved.has.bind(reserved);
const includes = Function.prototype.call.bind(String.prototype.includes);
const match = Function.prototype.call.bind(RegExp.prototype.exec);
const upper = /[A-Z]/;
// HTML uses DOM's current local-name grammar, a lowercase ASCII initial,
// a hyphen, and no uppercase ASCII letters or reserved names.
export function validName(name) {
  return name.length > 0 && name[0] >= 'a' && name[0] <= 'z'
    && validElementLocalName(name) && includes(name, '-') && match(upper, name) === null && !reservedName(name);
}
