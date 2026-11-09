// Backend fields never reside on page-visible objects. Freezing a DOM wrapper
// must not freeze its native state or expose the tree's physical links.
import { CHANGED, CLASS_LIST, CUSTOM_ELEMENTS, CONTENT, DATASET, DOCTYPE, DOM_PARSER, END, EVENT_TARGET, GLOBALS, IMAGE, MIME, MUTATION_OBSERVER, NEXT, OWNER_ELEMENT, PREV, PRIVATE, SHEET, START, STYLE, UPGRADE, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
const states = new WeakMap(), read = states.get.bind(states), save = states.set.bind(states);
const create = Object.create, keys = Reflect.ownKeys, describe = Object.getOwnPropertyDescriptor, define = Object.defineProperty, get = Reflect.get;
const NativeProxy = Proxy, privateKeys = new Set([CHANGED, CLASS_LIST, CUSTOM_ELEMENTS, CONTENT, DATASET, DOCTYPE, DOM_PARSER, END, EVENT_TARGET, GLOBALS, IMAGE, MIME, MUTATION_OBSERVER, NEXT, OWNER_ELEMENT, PREV, PRIVATE, SHEET, START, STYLE, UPGRADE, VALUE]);
const isPrivate = privateKeys.has.bind(privateKeys);
export function privateSlots(value) { let state = read(value); if (!state) { state = create(null); save(value,state); } return state; }
export function maybeSlots(value) { return value == null ? undefined : privateSlots(value); }
export function slotObject(value) {
  const names = keys(value); for (let i = 0; i < names.length; i++) { const key = names[i]; if (isPrivate(key)) { define(privateSlots(value),key,describe(value,key)); delete value[key]; } }
  return value;
}
// Mixed backend destructuring retains ordinary getters' receiver and order.
// The facade is temporary and is never returned to the page.
export function slotPattern(value) {
  const slots = privateSlots(value);
  return new NativeProxy(create(null), { __proto__: null, get(_target,key) { return isPrivate(key) ? slots[key] : get(value,key,value); } });
}

// Internal clone facades inherit native slots without exposing them as public
// properties or dispatching symbol reads through a page-visible Proxy.
export function slotFacade(value, target) { const state = create(privateSlots(target)); save(value,state); return state; }
