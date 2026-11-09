// Matching uses native identity, attributes and physical tree links. Page DOM
// properties and methods are not callbacks in the browser's selector algorithm.
import { compile } from 'css-select';
import { parse } from 'css-what';
import { selectorError, expectedSelectorError } from './selector-intrinsics.js';
import nthCheck from 'nth-check';
import { forgivingSyntax, installSyntaxReporter, isSelectorLimit } from './selector-syntax.js';
import { backendList, backendChildNodes, backendAttributes, collectionDocument, collectionHTMLDocument } from './collection-data.js';
import { nodeInfo, physicalParent, physicalRoot, physicalDocumentElement, eventAttribute } from './dom-state.js';
import { VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { attributeInfo } from './attribute-state.js';
import { nameIdentity, lowerASCII } from './names.js';
import { documentMode } from './document-state.js';
import { htmlName, controlType, checked, indeterminate, disabled, treeElements, formOwner } from './controls.js';
import { optionSelected } from './form-controls.js';
import { DOMException } from './dom-exception.js';
const NativeError = selectorError, isArray = Array.isArray, create = Object.create;
const includes = Function.prototype.call.bind(String.prototype.includes), starts = Function.prototype.call.bind(String.prototype.startsWith), ends = Function.prototype.call.bind(String.prototype.endsWith);
const exec = Function.prototype.call.bind(RegExp.prototype.exec), nthOf = /^([\s\S]*?)\s+of\s+([\s\S]+)$/i;
const HTML = 'http://www.w3.org/1999/xhtml';
let unsupported = () => {}, activeElement = () => null;
export function installSelectorPlatform(options) { unsupported = options.unsupported; installSyntaxReporter(unsupported); activeElement = options.active; }
function fail() { throw new NativeError('Invalid selector'); }
function tag(node) { return nodeInfo(node)?.kind === 1; }
function siblings(node) { const parent = physicalParent(node); if (parent) return backendChildNodes(parent); const result = backendList(); result[0] = node; return result; }
function sameType(a, b) { const x = nameIdentity(a), y = nameIdentity(b); return x?.namespace === y?.namespace && x?.local === y?.local; }
function attributeValue(node, name) { const all = backendAttributes(node); for (let i = 0; i < all.length; i++) if (attributeInfo(all[i]).qualified === name) return all[i][VALUE]; return null; }
const adapter = { __proto__: null, isTag: tag, equals: (a, b) => a === b, getChildren: backendChildNodes, getParent: physicalParent, getSiblings: siblings, getName: node => nameIdentity(node)?.local || '', getAttributeValue: attributeValue, hasAttrib: (node, name) => attributeValue(node, name) !== null };
const noArg = new Set('empty root scope any-link link visited hover active focus focus-visible focus-within checked indeterminate disabled enabled required optional read-only read-write placeholder-shown default valid invalid in-range out-of-range user-valid user-invalid defined target target-within fullscreen modal open popover-open playing paused seeking buffering stalled muted volume-locked picture-in-picture autofill'.split(' ')), hasNoArg = noArg.has.bind(noArg);
const pseudoElements = new Set('before after first-line first-letter selection marker backdrop placeholder file-selector-button details-content cue cue-region part slotted'.split(' ')), hasPseudoElement = pseudoElements.has.bind(pseudoElements);
const insensitiveAttributes = new Set('accept accept-charset align alink axis bgcolor charset checked clear codetype color compact declare defer dir direction disabled enctype face frame hreflang http-equiv lang language link media method multiple nohref noresize noshade nowrap readonly rel rev rules scope scrolling selected shape target text type valign valuetype vlink'.split(' ')), insensitiveAttribute = insensitiveAttributes.has.bind(insensitiveAttributes);
function whitespace(c) { return c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f'; }
function words(text) { const result = backendList(); let word = ''; for (let i = 0; i <= text.length; i++) { if (i === text.length || whitespace(text[i])) { if (word) result[result.length] = word; word = ''; } else word += text[i]; } return result; }
function attrMatch(token, node) {
  const html = collectionHTMLDocument(collectionDocument(node)) && nameIdentity(node)?.namespace === HTML, all = backendAttributes(node);
  for (let i = 0; i < all.length; i++) {
    const attr = all[i], id = attributeInfo(attr);
    const name = html && id.namespace === null ? lowerASCII(token.name) : token.name;
    if (id.local !== name || (token.namespace !== '*' && id.namespace !== null)) continue;
    const fold = token.ignoreCase === true || token.ignoreCase === 'quirks' && documentMode(collectionDocument(node)) === 'BackCompat' || token.ignoreCase === null && html && id.namespace === null && insensitiveAttribute(name);
    const value = fold ? lowerASCII(attr[VALUE]) : attr[VALUE], wanted = fold ? lowerASCII(token.value) : token.value;
    switch (token.action) {
      case 'exists': return true;
      case 'equals': if (value === wanted) return true; break;
      case 'start': if (wanted && starts(value, wanted)) return true; break;
      case 'end': if (wanted && ends(value, wanted)) return true; break;
      case 'any': if (wanted && includes(value, wanted)) return true; break;
      case 'hyphen': if (value === wanted || starts(value, wanted + '-')) return true; break;
      case 'element': { const parts = words(value); if (wanted && words(wanted).length === 1) for (let j = 0; j < parts.length; j++) if (parts[j] === wanted) return true; break; }
    }
  }
  return false;
}
function disabledState(node) { if (htmlName(node) === 'option' && htmlName(physicalParent(node)) === 'optgroup' && eventAttribute(physicalParent(node), 'disabled') !== null) return true; return disabled(node); }
function radioIndeterminate(node) { if (checked(node)) return false; const name = eventAttribute(node, 'name'); if (!name) return true; const nodes = treeElements(physicalRoot(node)), owner = formOwner(node); for (let i = 0; i < nodes.length; i++) if (nodes[i] !== node && htmlName(nodes[i]) === 'input' && controlType(nodes[i]) === 'radio' && eventAttribute(nodes[i], 'name') === name && formOwner(nodes[i]) === owner && checked(nodes[i])) return false; return true; }
function state(name, node) {
  const kind = htmlName(node), type = kind === 'input' ? controlType(node) : null;
  switch (name) {
    case 'root': return nodeInfo(physicalParent(node))?.kind === 9;
    case 'empty': { const children = backendChildNodes(node); for (let i = 0; i < children.length; i++) { const k = nodeInfo(children[i])?.kind; if (k === 1 || (k === 3 || k === 4) && children[i][VALUE].length) return false; } return true; }
    case 'checked': return kind === 'input' && (type === 'checkbox' || type === 'radio') ? checked(node) : kind === 'option' && optionSelected(node);
    case 'indeterminate': return kind === 'input' ? type === 'checkbox' ? indeterminate(node) : type === 'radio' && radioIndeterminate(node) : kind === 'progress' && eventAttribute(node, 'value') === null;
    case 'disabled': return disabledState(node);
    case 'enabled': return (kind === 'input' || kind === 'button' || kind === 'select' || kind === 'textarea' || kind === 'option' || kind === 'optgroup' || kind === 'fieldset') && !disabledState(node);
    case 'required': return (kind === 'input' || kind === 'select' || kind === 'textarea') && eventAttribute(node, 'required') !== null;
    case 'optional': return (kind === 'input' || kind === 'select' || kind === 'textarea') && eventAttribute(node, 'required') === null;
    case 'any-link': case 'link': return (kind === 'a' || kind === 'area') && eventAttribute(node, 'href') !== null;
    case 'visited': case 'hover': case 'active': return false;
    case 'focus': case 'focus-visible': return node === activeElement(physicalRoot(node));
    case 'focus-within': { const active = activeElement(physicalRoot(node)); for (let p = active; p; p = physicalParent(p)) if (p === node) return true; return false; }
    default: unsupported('selector:' + name); return false;
  }
}
export function compileSelector(root, text) {
  const scope = nodeInfo(root)?.kind === 9 ? physicalDocumentElement(root) : root, predicates = create(null); let serial = 0;
  function predicate(fn) { const name = '_appfuzz_selector_' + serial++; predicates[name] = fn; return { __proto__: null, type: 'pseudo', name, data: null }; }
  function compileList(list) { return compile(list, { __proto__: null, adapter, xmlMode: true, cacheResults: false, relativeSelector: false, context: scope || undefined, pseudos: predicates }); }
  function structural(name, data, inHas) {
    const reverse = includes(name, 'last'), ofType = includes(name, 'of-type'); let check, filter = null;
    if (starts(name, 'nth-')) { if (typeof data !== 'string') fail(); const of = exec(nthOf, data); if (of && ofType) fail(); check = nthCheck(of ? of[1] : data); if (of) filter = compileList(normalize(parse(forgivingSyntax(of[2])), inHas, false, true)); }
    else { if (data !== null) fail(); check = pos => pos === 0; }
    return node => { const all = siblings(node); let before = 0, after = 0, found = false; if (filter && !filter(node)) return false; for (let i = 0; i < all.length; i++) { const sibling = all[i]; if (sibling === node) { found = true; continue; } if (!tag(sibling) || ofType && !sameType(node, sibling) || filter && !filter(sibling)) continue; if (found) after++; else before++; } return starts(name, 'only-') ? !before && !after : check(reverse ? after : before); };
  }
  function normalize(list, inHas = false, relative = false, nested = false) {
    const result = backendList();
    for (let i = 0; i < list.length; i++) {
      const source = list[i], rules = backendList(); if (!source.length) fail();
      if (!relative && (source[0].type === 'child' || source[0].type === 'adjacent' || source[0].type === 'sibling' || source[0].type === 'descendant')) fail();
      for (let j = 0; j < source.length; j++) {
        const token = source[j], type = token.type;
        if (type === 'tag' || type === 'universal') {
          if (token.namespace !== null && token.namespace !== '*' && token.namespace !== '') fail();
          rules[rules.length] = predicate(node => { const id = nameIdentity(node); if (!id || token.namespace === '' && id.namespace !== null) return false; return type === 'universal' || (collectionHTMLDocument(collectionDocument(node)) && id.namespace === HTML ? id.local === lowerASCII(token.name) : id.local === token.name); });
        } else if (type === 'attribute') {
          if (token.action === 'not' || token.namespace !== null && token.namespace !== '*' && token.namespace !== '') fail(); rules[rules.length] = predicate(node => attrMatch(token, node));
        } else if (type === 'pseudo-element') {
          if (nested || !hasPseudoElement(token.name)) fail(); rules[rules.length] = predicate(() => false);
        } else if (type === 'pseudo') {
          const name = token.name, data = token.data;
          if (name === 'is' || name === 'where') {
            if (!isArray(data)) fail(); const branches = backendList();
            for (let k = 0; k < data.length; k++) { try { const one = backendList(); one[0] = data[k]; const branch = normalize(one, inHas, false, true); compileList(branch); branches[branches.length] = branch[0]; } catch (error) { if (!expectedSelectorError(error)) throw error; } }
            rules[rules.length] = branches.length ? { __proto__: null, type, name, data: branches } : predicate(() => false);
          } else if (name === 'not' || name === 'has') {
            if (!isArray(data) || !data.length || name === 'has' && inHas) fail(); rules[rules.length] = { __proto__: null, type, name, data: normalize(data, inHas || name === 'has', name === 'has', true) };
          } else if (name === 'first-child' || name === 'last-child' || name === 'only-child' || name === 'first-of-type' || name === 'last-of-type' || name === 'only-of-type' || name === 'nth-child' || name === 'nth-last-child' || name === 'nth-of-type' || name === 'nth-last-of-type') rules[rules.length] = predicate(structural(name, data, inHas));
          else if (name === 'lang') { if (typeof data !== 'string' || !data.length) fail(); rules[rules.length] = token; }
          else if (hasNoArg(name)) { if (data !== null) fail(); rules[rules.length] = name === 'scope' ? token : predicate(node => state(name, node)); }
          else fail();
        } else if (type === 'child' || type === 'adjacent' || type === 'descendant' || type === 'sibling') rules[rules.length] = token;
        else fail();
      }
      result[result.length] = rules;
    }
    return result;
  }
  try { return compileList(normalize(parse(forgivingSyntax(text)))); }
  catch (error) { if (isSelectorLimit(error)) throw error; if (!expectedSelectorError(error)) { unsupported('selector:parser execution'); throw error; } throw new DOMException('The selector is invalid', 'SyntaxError'); }
}
export function prepareMatch(root, text) { return compileSelector(root, text); }
export function matches(node, text) { return compileSelector(node, text)(node); }
