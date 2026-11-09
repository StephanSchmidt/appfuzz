import { build } from 'esbuild';
import { privateSelectors } from './private-selectors.mjs';
import { privateDOMSlots } from './private-dom-slots.mjs';
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
// Public collections implement Web IDL. Backend algorithms use private
// snapshots instead of calling page-visible collection methods or iterators.
const collectionData = fileURLToPath(new URL('./src/collection-data.js', import.meta.url));
const collectionVersion = fileURLToPath(new URL('./src/collection-version.js', import.meta.url));
const collectionSites = {
  'interface/custom-element-registry.js': [['const {attributes, isConnected} = element;', 'const attributes = backendAttributes(element), {isConnected} = element;']],
  'mixin/non-element-parent-node.js': [['this.childNodes', 'backendChildNodes(this)'], ['const {childNodes, localName} = this;', 'const childNodes = backendChildNodes(this), {localName} = this;']],
  'mixin/parent-node.js': [['this.children.length', 'backendChildren(this).length']],
  'mixin/inner-html.js': [['node.childNodes', 'backendChildNodes(node)'], ['const {childNodes} = parseFromString(document, ignoreCase(node), html);', 'const childNodes = backendChildNodes(parseFromString(document, ignoreCase(node), html));']],
  'dom/string-map.js': [['ref.attributes', 'backendAttributes(ref)']],
  'interface/document.js': [['const {childNodes} = this;', 'const childNodes = backendChildNodes(this);'], ['this.childNodes', 'backendChildNodes(this)']],
  'interface/mutation-observer.js': [['target.children.includes(element)', 'backendChildren(target).includes(element)'], ["target[characterData ? 'childNodes' : 'children'].includes(element)", '(characterData ? backendChildNodes(target) : backendChildren(target)).includes(element)']],
  'interface/node.js': [['const {childNodes} = this.parentNode;', 'const childNodes = backendChildNodes(this.parentNode);'], ['this.childNodes', 'backendChildNodes(this)'], ['node.childNodes', 'backendChildNodes(node)']],
  'interface/element.js': [['template.childNodes', 'backendChildNodes(template)']],
  'interface/range.js': [['node.childNodes', 'backendChildNodes(node)'], ['content.childNodes', 'backendChildNodes(content)']],
  'html/select-element.js': [['firstElementChild.children', 'backendChildren(firstElementChild)']],
  'html/slot-element.js': [['this.getRootNode().host?.childNodes ?? []', 'backendChildNodes(this.getRootNode().host)'], ['this.childNodes', 'backendChildNodes(this)'], ['this.children', 'backendChildren(this)']],
  'html/template-element.js': [['this.childNodes', 'backendChildNodes(this)']],
  'html/document.js': [["head.getElementsByTagName('title').at(0)", "head.getElementsByTagName('title')[0]"]],
};
async function readDOM(path) {
  let source = await readFile(path, 'utf8');
  const key = path.split('/linkedom/esm/')[1], sites = collectionSites[key];
  if (key === 'interface/css-style-declaration.js') { source = replace(source, '  get[PRIVATE]() { return this; }', ''); source = replace(source, '    refs.set(this, element);', '    refs.set(this, element); this[PRIVATE] = this;'); source = replace(source, '    return new Proxy(this, handler);', '    const proxy = new Proxy(this, handler); proxy[PRIVATE] = this; return proxy;'); }
  if (sites) {
    for (const [before, after] of sites) {
      if (!source.includes(before)) throw new Error('The pinned DOM collection sites changed: ' + key + ': ' + before);
      source = source.replaceAll(before, after);
    }
    source = `import {backendChildNodes,backendChildren,backendAttributes} from ${JSON.stringify(collectionData)};\n${source}`;
  }
  const parentWrites = ['node.parentNode = this;', 'firstChild.parentNode = this;', 'node.parentNode = self;', 'node.parentNode = parentNode;', 'element.parentNode = parentNode;', 'child.parentNode = fragment;', 'if (!attributeInfo(next)) next.parentNode = parentNode;'];
  for (const assignment of parentWrites) source = source.replaceAll(assignment, '');
  if (key === 'mixin/child-node.js') {
    const start = source.indexOf('export const remove = (prev, current, next) => {');
    if (start < 0) throw new Error('Pinned DOM removal changed');
    source = source.slice(0,start) + 'export const remove = (_prev,current,_next) => removeNativeNode(current);\n';
    source = `import {removeNativeNode} from ${JSON.stringify(fileURLToPath(new URL('./src/dom-mutations.js',import.meta.url)))};\n${source}`;
  }
  if (key === 'interface/character-data.js') {
    source = replace(source,'    this[VALUE] = String(data);','    initializeCharacterData(this, String(data));');
    source = `import {initializeCharacterData} from ${JSON.stringify(fileURLToPath(new URL('./src/character-data-state.js',import.meta.url)))};\n${source}`;
  }
  if (key === 'shared/utils.js') {
    source = replace(source, 'node => node.nodeType === ELEMENT_NODE ? node[END] : node;', 'node => (nodeInfo(node)?.kind ?? node.nodeType) === ELEMENT_NODE ? node[END] : node;');
    source = `import {nodeInfo} from ${JSON.stringify(domState)};\n${source}`;
  }
  if (key === 'html/element.js') { source = source.replace('this.ownerDocument = this[END].ownerDocument = ownerDocument;', 'setNodeDocument(this, ownerDocument); this[END].ownerDocument = ownerDocument;'); source = `import {setNodeDocument} from ${JSON.stringify(attributeState)};\n${source}`; }
  if (key === 'shared/utils.js') {
    source = replace(source, 'export const knownAdjacent = (prev, next) => {', 'export const knownAdjacent = (prev, next) => { collectionLinksChanged();');
    source = replace(source, 'export const setAdjacent = (prev, next) => {', 'export const setAdjacent = (prev, next) => { collectionLinksChanged();');
    source = `import {collectionLinksChanged} from ${JSON.stringify(collectionVersion)};\n${source}`;
  }
  return source;
}
const selectorEngine = fileURLToPath(new URL('./src/selector-engine.js', import.meta.url));
const hooks = fileURLToPath(new URL('./src/ce-hooks.js', import.meta.url));
const mutations = fileURLToPath(new URL('./src/mutation-observers.js', import.meta.url));
await build({
  entryPoints: ['src/shim.js'], bundle: true, inject: ['src/weak-map.js'],
  format: 'iife', target: 'es2023', minify: true, legalComments: 'none',
  alias: { htmlparser2: './src/alias/htmlparser2.js', 'cssomnom/parse': './src/alias/cssom.js' },
  outfile: 'dist/shim.js',
  plugins: [{ name: 'dom-internals', setup(plugin) {
    const onLoad = plugin.onLoad.bind(plugin);
    plugin = { onLoad(options,callback) { onLoad(options,async args => { const result = await callback(args); return result?.contents ? {...result,contents:privateDOMSlots(result.contents)} : result; }); } };
    plugin.onLoad({filter:/[/\\]browser[/\\]js[/\\]src[/\\].*\.js$/},async ({path}) => ({contents:await readFile(path,'utf8'),loader:'js'}));
    plugin.onLoad({ filter: /[/\\]node_modules[/\\](css-select|css-what|nth-check|boolbase)[/\\].*\.js$/ }, async ({ path }) => ({ contents: privateSelectors(await readFile(path, 'utf8')), loader: 'js' }));
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]mutation-observer\.js$/ }, async () => ({ contents: `export {MutationObserverClass,attributeMutation as attributeChangedCallback,legacyChildMutation as moCallback} from ${JSON.stringify(mutations)};`, loader: 'js' }));
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]shared[/\\]matches\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes('export const prepareMatch')) throw new Error('The pinned DOM selector entry changed');
      return { contents: `export {prepareMatch,matches} from ${JSON.stringify(selectorEngine)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\](dom[/\\](parser|token-list)|interface[/\\](range|tree-walker|node-list|mutation-observer))\.js$/ }, async ({ path }) => {
      let source = await readDOM(path);
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
      let source = await readDOM(path);
      if (path.endsWith('/interface/attr.js')) {
        source = replace(source, '    this.ownerElement = null;', '');
        source = replace(source, '    this.name = String(name);', '    initializeAttribute(this, String(name));');
        source += '\ninstallAttributeSlots(Attr.prototype);';
      } else {
        source = source.replaceAll('attribute.ownerElement = element;', 'setAttributeOwner(attribute, element);')
          .replaceAll('attribute.ownerElement = attribute[PREV] = attribute[NEXT] = null;', 'setAttributeOwner(attribute, null); attribute[PREV] = attribute[NEXT] = null;')
          .replaceAll('attr.ownerElement = parentNode;', 'setAttributeOwner(attr, parentNode);')
          .replaceAll('next.parentNode = parentNode;', '')
          .replaceAll('node.ownerDocument = this;', 'setNodeDocument(node, this);').replaceAll('element.ownerDocument = this;', 'setNodeDocument(element, this);');
      }
      return { contents: `import {initializeAttribute,installAttributeSlots,setAttributeOwner,setNodeDocument,attributeInfo} from ${JSON.stringify(attributeState)};\n${source}`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]document-type\.js$/ }, async ({ path }) => {
      let source = await readDOM(path);
      source = replace(source, '    this.name = name;\n    this.publicId = publicId;\n    this.systemId = systemId;', '    initializeDoctype(this, name, publicId, systemId);');
      return { contents: `import {initializeDoctype,installDoctypeSlots} from ${JSON.stringify(doctypeState)};\n${source}\ninstallDoctypeSlots(DocumentType.prototype);`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event\.js$/ }, async ({ path }) => {
      const source = await readDOM(path);
      if (!source.includes('class GlobalEvent')) throw new Error('The pinned DOM Event changed');
      return { contents: `export {Event} from ${JSON.stringify(eventState)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]custom-event\.js$/ }, async ({ path }) => {
      const source = await readDOM(path);
      if (!source.includes('class CustomEvent extends Event')) throw new Error('The pinned DOM CustomEvent changed');
      return { contents: `export {CustomEvent} from ${JSON.stringify(eventState)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event-target\.js$/ }, async ({ path }) => {
      const source = await readDOM(path);
      if (!source.includes('class DOMEventTarget')) throw new Error('The pinned DOM EventTarget changed');
      return { contents: `export {EventTarget} from ${JSON.stringify(eventTarget)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]node\.js$/ }, async ({ path }) => {
      let source = replace(await readDOM(path), '    this.ownerDocument = ownerDocument;\n    this.localName = localName;\n    this.nodeType = nodeType;\n    this.parentNode = null;', '    if (nodeType === 2) initializeAttributeNode(this, ownerDocument, localName); else { this.localName = localName; this.nodeType = nodeType; } initializeNode(this, nodeType, localName, ownerDocument);');
      source = `import {initializeAttributeNode} from ${JSON.stringify(attributeState)};\n${source}`;
      return { contents: `import {initializeNode} from ${JSON.stringify(domState)};\n` + source, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]custom-element-registry\.js$/ }, async ({ path }) => {
      const source = await readDOM(path);
      const start = source.indexOf('export const attributeChangedCallback =');
      const end = source.indexOf('/**\n * @implements globalThis.CustomElementRegistry', start);
      if (start < 0 || end < 0) throw new Error('The pinned DOM reaction sites changed');
      const ports = `export const attributeChangedCallback = attributeReaction;\nexport const connectedCallback = element => connectionReaction(element, true);\nexport const disconnectedCallback = element => connectionReaction(element, false);\n\n`;
      return { contents: `import {attributeReaction, connectionReaction} from ${JSON.stringify(hooks)};\n` + source.slice(0, start) + ports + source.slice(end), loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\].*\.js$/ }, async ({ path }) => ({ contents: await readDOM(path), loader: 'js' }));
  } }],
});
