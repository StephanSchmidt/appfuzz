import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// The pinned DOM library's native reaction sites are the reliable place
// to obtain attribute changes. Keep the DOM algorithms, while routing
// reactions through the browser guest's definition snapshots and queues.
const eventTarget = fileURLToPath(new URL('./src/event-target.js', import.meta.url));
const platformState = fileURLToPath(new URL('./src/platform-state.js', import.meta.url));
const domState = fileURLToPath(new URL('./src/dom-state.js', import.meta.url));
const nodeLists = fileURLToPath(new URL('./src/node-lists.js', import.meta.url));
const parserState = fileURLToPath(new URL('./src/parser-state.js', import.meta.url));
const doctypeState = fileURLToPath(new URL('./src/doctype-state.js', import.meta.url));
const attributeState = fileURLToPath(new URL('./src/attribute-state.js', import.meta.url));
const eventState = fileURLToPath(new URL('./src/event-state.js', import.meta.url));
const replace = (source, before, after) => {
  if (!source.includes(before)) throw new Error('The pinned DOM event sites changed: ' + before);
  return source.replace(before, after);
};
const hooks = fileURLToPath(new URL('./src/ce-hooks.js', import.meta.url));
await build({
  entryPoints: ['src/shim.js'], bundle: true, inject: ['src/weak-map.js'],
  format: 'iife', target: 'es2023', minify: true, legalComments: 'none',
  alias: { htmlparser2: './src/alias/htmlparser2.js', 'cssomnom/parse': './src/alias/cssom.js' },
  outfile: 'dist/shim.js',
  plugins: [{ name: 'dom-internals', setup(plugin) {
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\](dom[/\\](parser|token-list)|interface[/\\](range|tree-walker|node-list|mutation-observer))\.js$/ }, async ({ path }) => {
      let source = await readFile(path, 'utf8');
      if (path.endsWith('/dom/parser.js')) source = `import {initializeParser} from ${JSON.stringify(parserState)};\n` + replace(source, 'export class DOMParser {', 'export class DOMParser { constructor() { markPlatform(this); initializeParser(this); }');
      else if (path.endsWith('/interface/node-list.js')) {
        source = replace(source, 'export class NodeList extends Array {', 'export class NodeList { constructor(...values) { initializeNodeList(this, values); }');
        source = `import {initializeNodeList,installNodeListPrototype} from ${JSON.stringify(nodeLists)};\n${source}\ninstallNodeListPrototype(NodeList.prototype);`;
      }
      else if (path.endsWith('/dom/token-list.js')) source = replace(source, '    super();', '    super(); markPlatform(this);');
      else if (path.endsWith('/interface/range.js')) source = replace(source, '  constructor() {', '  constructor() { markPlatform(this);');
      else if (path.endsWith('/interface/tree-walker.js')) source = replace(source, '  constructor(root, whatToShow = SHOW_ALL) {', '  constructor(root, whatToShow = SHOW_ALL) { markPlatform(this);');
      else {
        source = replace(source, '      constructor(callback) {', '      constructor(callback) { markPlatform(this);');
        source = replace(source, 'attributeName, oldValue) =>', 'attributeName, oldValue, attributeNamespace = null) =>');
        source = replace(source, '  attributeName,\n  oldValue,', '  attributeName,\n  attributeNamespace,\n  oldValue,');
        source = replace(source, 'attributeOldValue, oldValue\n) =>', 'attributeOldValue, oldValue, attributeNamespace = null\n) =>');
        source = replace(source, '(!attributeFilter || attributeFilter.includes(attributeName))', '(!attributeFilter || (attributeNamespace === null && attributeFilter.includes(attributeName)))');
        source = replace(source, 'attributeName, attributeOldValue ? oldValue : void 0', 'attributeName, attributeOldValue ? oldValue : null, attributeNamespace');
        source = replace(source, 'attributeChangedCallback = (element, attributeName, oldValue) =>', 'attributeChangedCallback = (element, attributeName, oldValue, attributeNamespace = null) =>');
        source = source.replaceAll('attributeName, attributeFilter, attributeOldValue, oldValue\n', 'attributeName, attributeFilter, attributeOldValue, oldValue, attributeNamespace\n');
      }
      return { contents: `import {markPlatform} from ${JSON.stringify(platformState)};\n${source}`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\](interface[/\\](attr|element|document)|shared[/\\](attributes|parse-from-string|parse-json)|mixin[/\\]inner-html)\.js$/ }, async ({ path }) => {
      let source = await readFile(path, 'utf8');
      if (path.endsWith('/interface/attr.js')) {
        source = replace(source, '    this.ownerElement = null;', '');
        source = replace(source, '    this.name = String(name);', '    initializeAttribute(this, String(name));');
        source += '\ninstallAttributeSlots(Attr.prototype);';
      } else {
        source = source.replaceAll('attribute.ownerElement = element;', 'setAttributeOwner(attribute, element);')
          .replaceAll('attribute.ownerElement = attribute[PREV] = attribute[NEXT] = null;', 'setAttributeOwner(attribute, null); attribute[PREV] = attribute[NEXT] = null;')
          .replaceAll('attr.ownerElement = parentNode;', 'setAttributeOwner(attr, parentNode);')
          .replaceAll('next.parentNode = parentNode;', 'if (!attributeInfo(next)) next.parentNode = parentNode;')
          .replaceAll('node.ownerDocument = this;', 'setNodeDocument(node, this);').replaceAll('element.ownerDocument = this;', 'setNodeDocument(element, this);');
      }
      return { contents: `import {initializeAttribute,installAttributeSlots,setAttributeOwner,setNodeDocument,attributeInfo} from ${JSON.stringify(attributeState)};\n${source}`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]document-type\.js$/ }, async ({ path }) => {
      let source = await readFile(path, 'utf8');
      source = replace(source, '    this.name = name;\n    this.publicId = publicId;\n    this.systemId = systemId;', '    initializeDoctype(this, name, publicId, systemId);');
      return { contents: `import {initializeDoctype,installDoctypeSlots} from ${JSON.stringify(doctypeState)};\n${source}\ninstallDoctypeSlots(DocumentType.prototype);`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes('class GlobalEvent')) throw new Error('The pinned DOM Event changed');
      return { contents: `export {Event} from ${JSON.stringify(eventState)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]custom-event\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes('class CustomEvent extends Event')) throw new Error('The pinned DOM CustomEvent changed');
      return { contents: `export {CustomEvent} from ${JSON.stringify(eventState)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event-target\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes('class DOMEventTarget')) throw new Error('The pinned DOM EventTarget changed');
      return { contents: `export {EventTarget} from ${JSON.stringify(eventTarget)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]node\.js$/ }, async ({ path }) => {
      let source = replace(await readFile(path, 'utf8'), '    this.ownerDocument = ownerDocument;\n    this.localName = localName;\n    this.nodeType = nodeType;\n    this.parentNode = null;', '    if (nodeType === 2) initializeAttributeNode(this, ownerDocument, localName); else { this.ownerDocument = ownerDocument; this.localName = localName; this.nodeType = nodeType; this.parentNode = null; } initializeNode(this, nodeType, localName);');
      source = `import {initializeAttributeNode} from ${JSON.stringify(attributeState)};\n${source}`;
      return { contents: `import {initializeNode} from ${JSON.stringify(domState)};\n` + source, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]custom-element-registry\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      const start = source.indexOf('export const attributeChangedCallback =');
      const end = source.indexOf('/**\n * @implements globalThis.CustomElementRegistry', start);
      if (start < 0 || end < 0) throw new Error('The pinned DOM reaction sites changed');
      const ports = `export const attributeChangedCallback = attributeReaction;\nexport const connectedCallback = element => connectionReaction(element, true);\nexport const disconnectedCallback = element => connectionReaction(element, false);\n\n`;
      return { contents: `import {attributeReaction, connectionReaction} from ${JSON.stringify(hooks)};\n` + source.slice(0, start) + ports + source.slice(end), loader: 'js' };
    });
  } }],
});
