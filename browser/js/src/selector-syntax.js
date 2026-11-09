// The backend parser expects nonempty strict lists. CSS :is() and :where()
// instead discard invalid branches, including malformed nested selectors.
import { parse } from 'css-what';
import { backendList } from './collection-data.js';
const slice = Function.prototype.call.bind(String.prototype.slice), indexOf = Function.prototype.call.bind(String.prototype.indexOf), codeAt = Function.prototype.call.bind(String.prototype.charCodeAt);
const NativeError = Error;
function quoteEnd(text, i) { const quote = text[i++]; for (; i < text.length; i++) { if (text[i] === '\\') i++; else if (text[i] === quote) return i; } return text.length; }
function functionEnd(text, i) { let depth = 1; for (; i < text.length; i++) { const c = text[i]; if (c === '\\') i++; else if (c === '"' || c === "'") i = quoteEnd(text, i); else if (c === '/' && text[i + 1] === '*') { const end = indexOf(text, '*/', i + 2); if (end < 0) return -1; i = end + 1; } else if (c === '(') depth++; else if (c === ')' && --depth === 0) return i; } return -1; }
function splitBranches(text) { const result = backendList(); let start = 0, square = 0; for (let i = 0; i < text.length; i++) { const c = text[i]; if (c === '\\') i++; else if (c === '"' || c === "'") i = quoteEnd(text, i); else if (c === '/' && text[i + 1] === '*') { const end = indexOf(text, '*/', i + 2); i = end < 0 ? text.length : end + 1; } else if (c === '(') { const end = functionEnd(text, i + 1); i = end < 0 ? text.length : end; } else if (c === '[') square++; else if (c === ']') square--; else if (c === ',' && square === 0) { result[result.length] = slice(text, start, i); start = i + 1; } } result[result.length] = slice(text, start); return result; }
export function forgivingSyntax(text) {
  let result = '', start = 0, square = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\') { i++; continue; }
    if (c === '"' || c === "'") { i = quoteEnd(text, i); continue; }
    if (c === '/' && text[i + 1] === '*') { const end = indexOf(text, '*/', i + 2); i = end < 0 ? text.length : end + 1; continue; }
    if (c === '[') square++; else if (c === ']') square--;
    if (c !== ':' || square) continue;
    let open = i + 1;
    while (open < text.length) { const k = text[open]; if (k === '\\') { open += 2; continue; } if (k === '-' || k === '_' || k >= '0' && k <= '9' || k >= 'a' && k <= 'z' || k >= 'A' && k <= 'Z' || codeAt(k, 0) >= 128) open++; else break; }
    if (text[open] !== '(') continue;
    const end = functionEnd(text, open + 1); if (end < 0) throw new NativeError('Unclosed selector function');
    let name = ''; try { name = parse(slice(text, i, open) + '(*)')[0][0].name; } catch {}
    const content = slice(text, open + 1, end); let replacement;
    if (name === 'is' || name === 'where') {
      const parts = splitBranches(content), valid = backendList();
      for (let j = 0; j < parts.length; j++) { try { const branch = forgivingSyntax(parts[j]); if (parse(branch).length) valid[valid.length] = branch; } catch {} }
      replacement = valid.length ? slice(text, i, open + 1) + valid.join(',') + ')' : ':not(*)';
    } else replacement = slice(text, i, open + 1) + forgivingSyntax(content) + ')';
    result += slice(text, start, i) + replacement; start = end + 1; i = end;
  }
  return result + slice(text, start);
}
