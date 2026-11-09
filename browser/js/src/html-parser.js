// parse5's native tree adapter operates on private node identity and links.
// No public DOM method, metadata getter or live collection drives parsing.
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { Document } from '../node_modules/linkedom/esm/interface/document.js';
import { nodeInfo, nodeDocument, physicalParent, physicalPreviousSibling, physicalFirstChild, physicalLastChild } from './dom-state.js';
import { doctypeInfo, initializeDoctype } from './doctype-state.js';
import { attributeInfo } from './attribute-state.js';
import { backendList, backendChildNodes, backendAttributes } from './collection-data.js';
import { parsedAttribute } from './attributes.js';
import { nameIdentity } from './names.js';
import { characterValue, storeCharacterValue } from './character-data-state.js';
import { characterMutation } from './mutation-observers.js';
import { insertNativeNode, removeNativeNode, childrenChanged } from './dom-mutations.js';
import { adoptNativeNode } from './adoption.js';
import { withReactions } from './ce-reactions.js';
import { templateContent } from './templates.js';
import { rememberDocumentMode, documentMode, rememberDocumentScripting, rememberDocumentURL } from './document-state.js';
import { initializeDocumentCSP } from './document-csp.js';
import { initializeParsedValue } from './control-values.js';
import { rememberScript } from './script-state.js';
import { VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
const parser = globalThis.__native.htmlParser, apply = Reflect.apply, define = Object.defineProperty;
const text = Document.prototype.createTextNode, comment = Document.prototype.createComment, doctype = Document.prototype.createDocumentType, fragment = Document.prototype.createDocumentFragment;
const modes = new WeakMap(), readMode = modes.get.bind(modes), saveMode = modes.set.bind(modes);
function attrs(node) {
  const result = backendList(), attributes = backendAttributes(node);
  for (let i = 0; i < attributes.length; i++) {
    const attr = attributes[i], data = attributeInfo(attr);
    result[result.length] = { __proto__: null, name: data.local, value: attr[VALUE], namespace: data.namespace || undefined, prefix: data.prefix || undefined };
  }
  return result;
}
function qualified(attr) { return attr.prefix ? attr.prefix + ':' + attr.name : attr.name; }
export function beginHTML(active) {
  const doc = new HTMLDocument();
  rememberDocumentScripting(doc,true); rememberDocumentMode(doc,'CSS1Compat'); saveMode(doc,'no-quirks');
  rememberDocumentURL(doc,active.url); initializeDocumentCSP(doc,active.policies);
  define(doc,'compatMode',{ __proto__: null, get: () => documentMode(doc) });
  define(doc,'doctype',{ __proto__: null, get: () => { const nodes = backendChildNodes(doc); for (let i = 0; i < nodes.length; i++) if (nodeInfo(nodes[i])?.kind === 10) return nodes[i]; return null; } });
  const insert = (parent,node,before = null) => withReactions(() => {
    const owner = nodeDocument(parent);
    if (nodeDocument(node) !== owner) adoptNativeNode(owner,node);
    else if (physicalParent(node)) removeNativeNode(node);
    insertNativeNode(parent,node,before);
  });
  const insertText = (parent,value,before = null) => {
    const previous = before ? physicalPreviousSibling(before) : physicalLastChild(parent);
    if (nodeInfo(previous)?.kind === 3) { const old = characterValue(previous); characterMutation(previous,old); storeCharacterValue(previous,old + value); childrenChanged(parent); }
    else insert(parent,apply(text,nodeDocument(parent),[value]),before);
  };
  const adapter = { __proto__: null,
    createDocument: () => doc,
    createDocumentFragment: () => apply(fragment,doc,[]),
    createElement(local,namespace,attributes,intendedParent) { return withReactions(() => {
      const owner = nodeDocument(intendedParent) || doc;
      let is = null; for (let i = 0; i < attributes.length; i++) if (attributes[i].name === 'is' && !attributes[i].namespace) is = attributes[i].value;
      const node = active.create(owner,{ __proto__: null, namespace, prefix: null, local, qualified: local },is);
      if (local === 'script') rememberScript(node,{ __proto__: null, namespace, local }).parserPending = true;
      for (let i = 0; i < attributes.length; i++) { const attr = attributes[i]; parsedAttribute(node,attr.namespace || null,qualified(attr),attr.value); }
      initializeParsedValue(node); return node;
    }); },
    createCommentNode: value => apply(comment,doc,[value]),
    createTextNode: value => apply(text,doc,[value]),
    appendChild: (parent,node) => insert(parent,node), insertBefore: insert,
    detachNode: removeNativeNode,
    insertText: (parent,value) => insertText(parent,value), insertTextBefore: insertText,
    getChildNodes: backendChildNodes, getFirstChild: physicalFirstChild,
    getParentNode: physicalParent, getAttrList: attrs,
    getTagName: node => nameIdentity(node)?.local,
    getNamespaceURI: node => nameIdentity(node)?.namespace,
    getTextNodeContent: characterValue, getCommentNodeContent: characterValue,
    isTextNode: node => nodeInfo(node)?.kind === 3, isCommentNode: node => nodeInfo(node)?.kind === 8,
    isElementNode: node => nodeInfo(node)?.kind === 1, isDocumentTypeNode: node => nodeInfo(node)?.kind === 10,
    getTemplateContent: templateContent, setTemplateContent() {},
    getDocumentMode: readMode,
    setDocumentMode(document,mode) { saveMode(document,mode); rememberDocumentMode(document,mode === 'quirks' ? 'BackCompat' : 'CSS1Compat'); },
    setDocumentType(document,name,publicId,systemId) { const nodes = backendChildNodes(document); for (let i = 0; i < nodes.length; i++) if (nodeInfo(nodes[i])?.kind === 10) { initializeDoctype(nodes[i],name,publicId,systemId); return; } insert(document,apply(doctype,document,[name,publicId,systemId])); },
    getDocumentTypeNodeName: node => doctypeInfo(node).name,
    getDocumentTypeNodePublicId: node => doctypeInfo(node).publicId,
    getDocumentTypeNodeSystemId: node => doctypeInfo(node).systemId,
    adoptAttributes(node,attributes) { const existing = attrs(node); for (let i = 0; i < attributes.length; i++) { const attr = attributes[i]; let found = false; for (let j = 0; j < existing.length; j++) if (qualified(existing[j]) === qualified(attr)) found = true; if (!found) parsedAttribute(node,attr.namespace || null,qualified(attr),attr.value); } },
    getNodeSourceCodeLocation() { return null; }, setNodeSourceCodeLocation() {}, updateNodeSourceCodeLocation() {},
  };
  return { __proto__: null, doc, start(script) { return parser(adapter,doc,script); } };
}
