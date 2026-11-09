// MIME Sniffing parsing/serialization and Fetch's Content-Type extraction.
// Native strings and private parameter lists do not consult page prototypes.
import { lowerASCII } from './names.js';
const codeAt = Function.prototype.call.bind(String.prototype.charCodeAt);
const slice = Function.prototype.call.bind(String.prototype.slice), create = Object.create, setPrototype = Object.setPrototypeOf;
const own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
const whitespace = c => c === ' ' || c === '\t' || c === '\r' || c === '\n';
function list() { const value = []; setPrototype(value, null); return value; }
function trim(value) { let a = 0, b = value.length; while (a < b && whitespace(value[a])) a++; while (b > a && whitespace(value[b - 1])) b--; return slice(value, a, b); }
function token(value) {
  if (!value.length) return false;
  for (let i = 0; i < value.length; i++) { const c = codeAt(value, i); if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 33 || (c >= 35 && c <= 39) || c === 42 || c === 43 || c === 45 || c === 46 || c === 94 || c === 95 || c === 96 || c === 124 || c === 126)) return false; }
  return true;
}
function quoted(value) { for (let i = 0; i < value.length; i++) { const c = codeAt(value, i); if (c !== 9 && !(c >= 32 && c <= 126) && !(c >= 128 && c <= 255)) return false; } return true; }
function parse(input) {
  input = trim(input); let p = 0, type = '';
  while (p < input.length && input[p] !== '/') type += input[p++];
  if (!token(type) || p === input.length) return null;
  p++; let subtype = '';
  while (p < input.length && input[p] !== ';') subtype += input[p++];
  while (subtype.length && whitespace(subtype[subtype.length - 1])) subtype = slice(subtype, 0, -1);
  if (!token(subtype)) return null;
  const result = { essence: lowerASCII(type) + '/' + lowerASCII(subtype), params: create(null), order: list() };
  while (p < input.length) {
    p++; while (p < input.length && whitespace(input[p])) p++;
    let name = '';
    while (p < input.length && input[p] !== ';' && input[p] !== '=') name += input[p++];
    name = lowerASCII(name);
    if (p === input.length) break;
    if (input[p] === ';') continue;
    p++; let value = '';
    if (input[p] === '"') {
      p++;
      while (p < input.length) { const c = input[p++]; if (c === '"') break; if (c === '\\' && p < input.length) value += input[p++]; else value += c; }
      while (p < input.length && input[p] !== ';') p++;
    } else {
      while (p < input.length && input[p] !== ';') value += input[p++];
      while (value.length && whitespace(value[value.length - 1])) value = slice(value, 0, -1);
      if (!value.length) continue;
    }
    if (token(name) && quoted(value) && !own(result.params, name)) { result.params[name] = value; result.order[result.order.length] = name; }
  }
  return result;
}
function serialize(mime) {
  let result = mime.essence;
  for (let i = 0; i < mime.order.length; i++) {
    const key = mime.order[i], value = mime.params[key]; let encoded = value;
    if (!token(value)) { encoded = '"'; for (let j = 0; j < value.length; j++) encoded += (value[j] === '"' || value[j] === '\\' ? '\\' : '') + value[j]; encoded += '"'; }
    result += ';' + key + '=' + encoded;
  }
  return result;
}
export function extractMime(value) {
  if (value === null) return '';
  const values = list(); let part = '', inQuote = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (inQuote && c === '\\' && i + 1 < value.length) { part += c + value[++i]; continue; }
    if (c === '"') inQuote = !inQuote;
    if (c === ',' && !inQuote) { values[values.length] = part; part = ''; } else part += c;
  }
  values[values.length] = part;
  let result = null, essence = null, charset = null;
  for (let i = 0; i < values.length; i++) {
    const mime = parse(values[i]); if (!mime || mime.essence === '*/*') continue;
    result = mime;
    if (mime.essence !== essence) { charset = own(mime.params, 'charset') ? mime.params.charset : null; essence = mime.essence; }
    else if (!own(mime.params, 'charset') && charset !== null) { mime.params.charset = charset; mime.order[mime.order.length] = 'charset'; }
  }
  return result ? serialize(result) : '';
}

// Private File API charset extraction reuses the MIME Sniffing parser.
export function mimeCharset(value) { const mime = parse(value); return mime && own(mime.params, 'charset') ? mime.params.charset : null; }

// XHR overrideMimeType parses one MIME type, unlike Fetch header extraction.
export function normalizeMime(value) { const mime = parse(value); return mime ? serialize(mime) : null; }
export function utf8Mime(value) {
  const mime = parse(value); if (!mime) return value;
  if (own(mime.params, 'charset') && lowerASCII(mime.params.charset) !== 'utf-8') mime.params.charset = 'UTF-8';
  return serialize(mime);
}
