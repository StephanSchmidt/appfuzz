// Backend symbol properties are implementation slots, not properties of page
// objects. Parse the pinned sources so reads, lvalues, optional access and
// destructuring all use the same private state, including nested expressions.
import { parse } from 'acorn';
import { fileURLToPath } from 'node:url';
const state = fileURLToPath(new URL('./src/dom-slots.js', import.meta.url));
export function privateDOMSlots(source) {
  if (!source.includes('symbols.js')) return source;
  const tree = parse(source, { ecmaVersion: 'latest', sourceType: 'module' }), names = new Set();
  for (const node of tree.body) if (node.type === 'ImportDeclaration' && /(?:^|\/)symbols\.js$/.test(node.source.value)) for (const item of node.specifiers) {
    if (item.type !== 'ImportSpecifier') throw new Error('DOM slots require named imports');
    names.add(item.local.name);
  }
  if (!names.size) return source;
  let serial = 0, used = false;
  const privateKey = node => node?.type === 'Identifier' && names.has(node.name);
  const properties = node => node.properties.filter(p => p.type === 'Property' && p.computed && privateKey(p.key));
  const pattern = node => node?.type === 'ObjectPattern' && properties(node).length;
  const view = node => node.properties.every(p => p.type === 'Property' && p.computed && privateKey(p.key)) ? '__afDOMSlots' : '__afDOMSlotPattern';
  function children(node, overrides = new Map()) {
    const parts = new Map();
    for (const [key, value] of Object.entries(node)) {
      if (key === 'start' || key === 'end') continue;
      for (const child of Array.isArray(value) ? value : [value]) if (child && typeof child.type === 'string') parts.set(child.start + ':' + child.end, child);
    }
    let result = '', at = node.start;
    for (const child of [...parts.values()].sort((a,b) => a.start - b.start)) {
      if (child.start < at) throw new Error('Overlapping DOM syntax');
      result += source.slice(at,child.start) + (overrides.has(child) ? overrides.get(child) : render(child)); at = child.end;
    }
    return result + source.slice(at,node.end);
  }
  function render(node) {
    if (node.type === 'ChainExpression') {
      // Inserting a call into the middle of an optional chain would stop its
      // null short-circuit. Reject a new pinned-library site until ported.
      const optional = value => {
        if (!value || typeof value !== 'object') return false;
        return !!value.optional || optional(value.object) || optional(value.callee);
      };
      const check = value => {
        if (!value || typeof value !== 'object') return;
        if (value.type === 'MemberExpression' && value.computed && privateKey(value.property) && optional(value.object)) throw new Error('Unsupported nested optional DOM slot access');
        check(value.object); check(value.callee);
      };
      check(node.expression);
    }
    if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression' && node.callee.computed && privateKey(node.callee.property)) throw new Error('Unsupported DOM slot method call');
    if (node.type === 'MethodDefinition' && node.computed && privateKey(node.key)) throw new Error('DOM slot prototype method requires an explicit backend port');
    if (node.type === 'MemberExpression' && node.computed && privateKey(node.property)) {
      used = true; return (node.optional ? '__afDOMMaybeSlots(' : '__afDOMSlots(') + render(node.object) + ')' + (node.optional ? '?.' : '') + '[' + render(node.property) + ']';
    }
    if (node.type === 'ObjectExpression' && properties(node).length) { used = true; return '__afDOMSlotObject(' + children(node) + ')'; }
    if (node.type === 'VariableDeclarator' && pattern(node.id)) {
      if (!node.init) throw new Error('DOM slot destructuring needs an initializer');
      used = true; return children(node,new Map([[node.init,view(node.id) + '(' + render(node.init) + ')']]));
    }
    if (['FunctionExpression','FunctionDeclaration','ArrowFunctionExpression'].includes(node.type) && node.params.some(pattern)) {
      if (node.body.type !== 'BlockStatement') throw new Error('DOM slot parameter requires a block body');
      used = true; const changes = new Map(); let declarations = '';
      for (const parameter of node.params) if (pattern(parameter)) {
        const name = '__afDOMArgument' + serial++; if (source.includes(name)) throw new Error('DOM slot binding collision');
        changes.set(parameter,name); declarations += 'let ' + render(parameter) + '=' + view(parameter) + '(' + name + ');';
      }
      const body = render(node.body); changes.set(node.body,'{' + declarations + body.slice(1)); return children(node,changes);
    }
    return children(node);
  }
  const output = render(tree);
  return used ? `import {privateSlots as __afDOMSlots,maybeSlots as __afDOMMaybeSlots,slotObject as __afDOMSlotObject,slotPattern as __afDOMSlotPattern} from ${JSON.stringify(state)};\n${output}` : source;
}
