// XHR serializes a Document's physical tree. Public serializers, getters and
// iterators are not callbacks in this algorithm.
import { NEXT, END, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nodeInfo } from './dom-state.js';
import { nameIdentity } from './names.js';
import { requireAttribute } from './attribute-state.js';
import { doctypeInfo } from './doctype-state.js';
import { documentMode, documentScripting } from './document-state.js';
import { templateContent } from './templates.js';
import { elementIs } from './element-state.js';
const create = Object.create, setPrototype = Object.setPrototypeOf, keys = Object.keys;
const join = Function.prototype.call.bind(Array.prototype.join);
const HTML = 'http://www.w3.org/1999/xhtml', XML = 'http://www.w3.org/XML/1998/namespace', XMLNS = 'http://www.w3.org/2000/xmlns/';
const voids = new Set(['area','base','basefont','bgsound','link','meta','hr','input','img','embed','param','source','track','wbr','col','frame','keygen']), isVoid = voids.has.bind(voids);
const raws = new Set(['script','style','xmp','iframe','noembed','noframes','plaintext']), isRaw = raws.has.bind(raws);
function list() { const value = []; setPrototype(value, null); return value; }
function escape(value, attribute, html) {
  let out = ''; for (let i = 0; i < value.length; i++) { const c = value[i];
    out += c === '&' ? '&amp;' : c === '<' ? '&lt;' : c === '>' ? '&gt;' : attribute && c === '"' ? '&quot;' : html && c === '\u00a0' ? '&nbsp;' : !html && attribute && c === '\t' ? '&#9;' : !html && attribute && c === '\n' ? '&#xA;' : !html && attribute && c === '\r' ? '&#xD;' : c;
  } return out;
}
function context(parent) { const next = create(null), names = keys(parent); for (let i = 0; i < names.length; i++) next[names[i]] = parent[names[i]]; return next; }
function preferred(ns, prefix, map) { if (prefix && map[prefix] === ns) return prefix; const names = keys(map); for (let i = names.length - 1; i >= 0; i--) if (names[i] && map[names[i]] === ns) return names[i]; return null; }
export function serializeDocument(document) {
  const html = documentMode(document) !== undefined, out = list(), stack = list(), initial = create(null); initial[''] = null; initial.xml = XML; let counter = 1;
  function queueChildren(root, map, raw) {
    const nodes = list(); for (let child = root[NEXT]; child !== root[END]; child = (child[END] || child)[NEXT]) if (nodeInfo(child)?.kind !== 2) nodes[nodes.length] = child;
    for (let i = nodes.length - 1; i >= 0; i--) stack[stack.length] = { __proto__: null, node: nodes[i], map, raw };
  }
  queueChildren(document, initial, false);
  while (stack.length) {
    const index = stack.length - 1, job = stack[index]; stack.length = index; if (job.close !== undefined) { out[out.length] = job.close; continue; }
    const node = job.node, info = nodeInfo(node), type = info?.kind;
    if (type === 3 || type === 4) { out[out.length] = !html && type === 4 ? '<![CDATA[' + node[VALUE] + ']]>' : job.raw ? node[VALUE] : escape(node[VALUE], false, html); continue; }
    if (type === 8) { out[out.length] = '<!--' + node[VALUE] + '-->'; continue; }
    if (type === 7) { out[out.length] = '<?' + info.local + (node[VALUE] ? ' ' + node[VALUE] : '') + '?>'; continue; }
    if (type === 10) { const d = doctypeInfo(node); out[out.length] = '<!DOCTYPE ' + d.name + (html ? '' : d.publicId ? ' PUBLIC "' + d.publicId + '"' + (d.systemId ? ' "' + d.systemId + '"' : '') : d.systemId ? ' SYSTEM "' + d.systemId + '"' : '') + '>'; continue; }
    if (type !== 1) continue;
    const identity = nameIdentity(node) || { __proto__: null, namespace: null, prefix: null, local: info.local, qualified: info.local }, ns = identity.namespace;
    const map = context(job.map), declarations = create(null), attributes = list();
    for (let attr = node[NEXT]; nodeInfo(attr)?.kind === 2; attr = attr[NEXT]) { const a = requireAttribute(attr); attributes[attributes.length] = { __proto__: null, data: a, value: attr[VALUE] }; if (a.namespace === XMLNS) { const prefix = a.prefix === 'xmlns' ? a.local : ''; declarations[prefix] = attr[VALUE]; map[prefix] = attr[VALUE] || null; } }
    let name = identity.qualified, generated = '';
    function declare(prefix, namespace) { map[prefix] = namespace; generated += ' xmlns' + (prefix ? ':' + prefix : '') + '="' + escape(namespace ?? '', true, false) + '"'; }
    if (!html) {
      let prefix = preferred(ns, identity.prefix, map);
      if (job.map[''] === ns) name = identity.local;
      else if (prefix) name = prefix + ':' + identity.local;
      else if (identity.prefix) {
        prefix = identity.prefix;
        if (declarations[prefix] !== undefined && declarations[prefix] !== ns) { do { prefix = 'ns' + counter++; } while (map[prefix] !== undefined); }
        name = prefix + ':' + identity.local; declare(prefix, ns);
      } else { name = identity.local; if (map[''] !== ns) declare('', ns); }
    }
    let opening = '<' + name + generated, hasIs = false;
    const is = elementIs(node);
    for (let i = 0; i < attributes.length; i++) if (attributes[i].data.namespace === null && attributes[i].data.local === 'is') hasIs = true;
    if (html && is !== null && !hasIs) opening += ' is="' + escape(is, true, true) + '"';
    for (let i = 0; i < attributes.length; i++) {
      const a = attributes[i].data, value = attributes[i].value; let qualified = a.qualified;
      if (!html) {
        if (a.namespace === XMLNS) { const prefix = a.prefix === 'xmlns' ? a.local : ''; if (map[prefix] !== (value || null) || (prefix === '' && job.map[''] === ns && value !== ns)) continue; }
        else if (a.namespace !== null) { let prefix = preferred(a.namespace, a.prefix, map); if (!prefix) { prefix = a.prefix; if (!prefix || declarations[prefix] !== undefined) { do { prefix = 'ns' + counter++; } while (map[prefix] !== undefined); } opening += ' xmlns:' + prefix + '="' + escape(a.namespace, true, false) + '"'; map[prefix] = a.namespace; } qualified = prefix + ':' + a.local; }
      }
      opening += ' ' + qualified + '="' + escape(value, true, html) + '"';
    }
    const root = templateContent(node) || node; let first = root[NEXT]; while (nodeInfo(first)?.kind === 2) first = first[NEXT]; const empty = first === root[END];
    if (html && ns === HTML && isVoid(identity.local)) { out[out.length] = opening + '>'; continue; }
    if (!html && empty && (ns !== HTML || isVoid(identity.local))) { out[out.length] = opening + (ns === HTML ? ' />' : '/>'); continue; }
    out[out.length] = opening + '>'; stack[stack.length] = { __proto__: null, close: '</' + name + '>' };
    queueChildren(root, map, html && ns === HTML && (isRaw(identity.local) || (identity.local === 'noscript' && documentScripting(document))));
  }
  return join(out, '');
}
