// CharacterData and Text algorithms use native strings and metadata. Explicit
// IDL argument conversion runs before reading data, so reentrant changes count.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { nodeInfo, nodeDocument, physicalParent, physicalPreviousSibling, physicalNextSibling } from './dom-state.js';
import { characterValue, storeCharacterValue } from './character-data-state.js';
import { characterMutation, childMutation } from './mutation-observers.js';
import { createNativeText, insertNativeText, replaceAllText, childrenChanged } from './dom-mutations.js';
import { DOMException } from './dom-exception.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { withReactions } from './ce-reactions.js';
const NativeTypeError = TypeError, define = Object.defineProperty, descriptors = Object.getOwnPropertyDescriptors, ownKeys = Reflect.ownKeys;
const slice = Function.prototype.call.bind(String.prototype.slice), apply = Reflect.apply;
function text(node) { const kind = nodeInfo(node)?.kind; return kind === 3 || kind === 4; }
function character(node) { const kind = nodeInfo(node)?.kind; return kind === 3 || kind === 4 || kind === 7 || kind === 8; }
function check(node) { if (!character(node)) throw new NativeTypeError('CharacterData is required'); }
function checkText(node) { if (!text(node)) throw new NativeTypeError('Text is required'); }
function required(count, minimum) { if (count < minimum) throw new NativeTypeError('Not enough arguments'); }
function uint(value) { return (+value) >>> 0; }
function replace(node, offset, count, value, notifyChildren = true) {
  const old = characterValue(node); if (offset > old.length) throw new DOMException('Offset exceeds the data length', 'IndexSizeError');
  characterMutation(node, old); storeCharacterValue(node, slice(old,0,offset) + value + slice(old,offset + count)); if (notifyChildren) childrenChanged(physicalParent(node));
}
function fields(prototype, object) { const all = descriptors(object), keys = ownKeys(all); for (let i = 0; i < keys.length; i++) define(prototype,keys[i],all[keys[i]]); }
export function installCharacterData(L) {
  const characterPrototype = Object.getPrototypeOf(L.Text.prototype), attributeSetter = Object.getOwnPropertyDescriptor(L.Attr.prototype,'value').set;
  const methods = {
    get data() { check(this); return characterValue(this); },
    set data(value) { check(this); value = runDOMCallback(() => value === null ? '' : eventString(value)); replace(this,0,characterValue(this).length,value); },
    get length() { check(this); return characterValue(this).length; },
    substringData(offset,count) { check(this); required(arguments.length,2); const args = runDOMCallback(() => ({ __proto__: null, offset: uint(offset), count: uint(count) })), value = characterValue(this); if (args.offset > value.length) throw new DOMException('Offset exceeds the data length','IndexSizeError'); return slice(value,args.offset,args.offset + args.count); },
    appendData(value) { check(this); required(arguments.length,1); value = runDOMCallback(() => eventString(value)); replace(this,characterValue(this).length,0,value); },
    insertData(offset,value) { check(this); required(arguments.length,2); const args = runDOMCallback(() => ({ __proto__: null, offset: uint(offset), value: eventString(value) })); replace(this,args.offset,0,args.value); },
    deleteData(offset,count) { check(this); required(arguments.length,2); const args = runDOMCallback(() => ({ __proto__: null, offset: uint(offset), count: uint(count) })); replace(this,args.offset,args.count,''); },
    replaceData(offset,count,value) { check(this); required(arguments.length,3); const args = runDOMCallback(() => ({ __proto__: null, offset: uint(offset), count: uint(count), value: eventString(value) })); replace(this,args.offset,args.count,args.value); },
  };
  fields(characterPrototype,methods);
  const nodeFields = {
    get nodeValue() { const kind = nodeInfo(this)?.kind; if (kind === undefined) throw new NativeTypeError('A Node is required'); return character(this) ? characterValue(this) : kind === 2 ? this[VALUE] : null; },
    set nodeValue(value) { const kind = nodeInfo(this)?.kind; if (kind === undefined) throw new NativeTypeError('A Node is required'); value = runDOMCallback(() => value == null ? '' : eventString(value)); return withReactions(() => { if (character(this)) replace(this,0,characterValue(this).length,value); else if (kind === 2) apply(attributeSetter,this,[value]); }); },
    get textContent() {
      const kind = nodeInfo(this)?.kind; if (kind === undefined) throw new NativeTypeError('A Node is required');
      if (character(this)) return characterValue(this); if (kind === 2) return this[VALUE]; if (kind !== 1 && kind !== 11) return null;
      let result = ''; for (let node = this[NEXT]; node && node !== this[END]; node = node[NEXT]) if (text(node)) result += characterValue(node); return result;
    },
    set textContent(value) { const kind = nodeInfo(this)?.kind; if (kind === undefined) throw new NativeTypeError('A Node is required'); value = runDOMCallback(() => value == null ? '' : eventString(value)); return withReactions(() => { if (character(this)) replace(this,0,characterValue(this).length,value); else if (kind === 2) apply(attributeSetter,this,[value]); else if (kind === 1 || kind === 11) replaceAllText(this,value); }); },
  };
  for (const prototype of [L.Node.prototype,characterPrototype,L.Element.prototype,L.DocumentFragment.prototype]) fields(prototype,nodeFields);
  fields(L.Text.prototype,{
    get wholeText() { checkText(this); let start = this, previous; while (text(previous = physicalPreviousSibling(start))) start = previous; let result = ''; for (let node = start; text(node); node = physicalNextSibling(node)) result += characterValue(node); return result; },
    splitText(offset) { checkText(this); required(arguments.length,1); offset = runDOMCallback(() => uint(offset)); const value = characterValue(this); if (offset > value.length) throw new DOMException('Offset exceeds the data length','IndexSizeError'); const copy = createNativeText(nodeDocument(this),slice(value,offset)), parent = physicalParent(this), before = physicalNextSibling(this); if (parent) insertNativeText(parent,copy,before,false); replace(this,offset,value.length - offset,'',false); if (parent) { childMutation(parent,[copy],[],this,before); childrenChanged(parent); } return copy; },
  });
}
