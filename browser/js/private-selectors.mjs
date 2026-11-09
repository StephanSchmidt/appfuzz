// Pinned selector dependencies execute as browser internals. Parse their JS so
// arrays/records/regexps and primitive method calls retain captured intrinsics.
// This avoids fragile textual rewrites of nested expressions or string literals.
import { parse } from 'acorn';
import { fileURLToPath } from 'node:url';
const intrinsics = fileURLToPath(new URL('./src/selector-intrinsics.js', import.meta.url));
const calls = new Set(['charAt','charCodeAt','codePointAt','concat','endsWith','includes','indexOf','lastIndexOf','localeCompare','match','matchAll','normalize','padEnd','padStart','repeat','replace','replaceAll','search','slice','split','startsWith','substring','substr','toLowerCase','toUpperCase','toLocaleLowerCase','toLocaleUpperCase','trim','trimEnd','trimStart','toString','valueOf','call','apply','bind']);
export function privateSelectors(source) {
  const tree = parse(source, { ecmaVersion: 'latest', sourceType: 'module' }), edits = [];
  const insert = (at, value, order) => edits.push({ start: at, end: at, value, order });
  function visit(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'ArrayExpression') { insert(node.start, 'afPrivateArray(', -node.end); insert(node.end, ')', 1); }
    else if (node.type === 'ObjectExpression') {
      const hasProto = node.properties.some(p => p.type === 'Property' && !p.computed && (p.key.name === '__proto__' || p.key.value === '__proto__'));
      if (!hasProto) insert(node.start + 1, '__proto__:null' + (node.properties.length ? ',' : ''), 0);
    } else if (node.type === 'Literal' && node.regex) { insert(node.start, 'afPrivateRegex(', -node.end); insert(node.end, ')', 1); }
    else if (node.type === 'CallExpression' && !node.optional && node.callee.type === 'MemberExpression' && !node.callee.computed && !node.callee.optional && calls.has(node.callee.property.name)) {
      const member = node.callee;
      insert(node.start, 'afPrivateCall(' + JSON.stringify(member.property.name) + ',', -node.end);
      edits.push({ start: member.object.end, end: node.arguments.length ? node.arguments[0].start : node.end - 1, value: node.arguments.length ? ',' : '', order: 0 });
    }
    for (const [key, value] of Object.entries(node)) { if (key === 'start' || key === 'end') continue; if (Array.isArray(value)) for (const child of value) visit(child); else if (value && typeof value === 'object' && typeof value.type === 'string') visit(value); }
  }
  visit(tree);
  edits.sort((a, b) => b.start - a.start || b.end - a.end || b.order - a.order);
  for (const edit of edits) source = source.slice(0, edit.start) + edit.value + source.slice(edit.end);
  return `import {privateArray as afPrivateArray,privateRegex as afPrivateRegex,privateCall as afPrivateCall,selectorArray as Array,selectorObject as Object,selectorString as String,selectorNumber as Number,selectorMath as Math,selectorRegExp as RegExp,selectorMap as Map,selectorSet as Set,selectorWeakMap as WeakMap,selectorError as Error,selectorTypeError as TypeError} from ${JSON.stringify(intrinsics)};\n${source}`;
}
