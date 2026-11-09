// Native character data is not the page's data expando. The pinned backend
// can read its legacy value slot, but cannot delegate that read to author code.
import { privateSlots } from './dom-slots.js';
import { VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
const values = new WeakMap(), read = values.get.bind(values), save = values.set.bind(values), define = Object.defineProperty;
export function initializeCharacterData(node, value) { save(node, value); define(privateSlots(node), VALUE, { __proto__: null, get() { return read(node); } }); }
export const characterValue = read;
export function storeCharacterValue(node, value) { save(node, value); }
