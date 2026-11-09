import { replaceAllText as replaceControlText } from './dom-mutations.js';
export { replaceAllText as replaceControlText } from './dom-mutations.js';
import { clearInputFiles, copyInputFiles, fileInputValue } from './file-inputs.js';
// Current values and dirty flags are native control state. Default values
// remain attributes/child text, so serializing a page does not expose edits.
import { colorSpaceName } from './color-values.js';
import { sanitizeInputDomain } from './input-domains.js';
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { htmlName, controlType, inputTypeName, setControlAttribute, installValueAttributeHook } from './controls.js';
import { nodeInfo, eventAttribute } from './dom-state.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { withReactions } from './ce-reactions.js';
const values = new WeakMap(), read = values.get.bind(values), save = values.set.bind(values);
const define = Object.defineProperty, NativeTypeError = TypeError;
let DOMError = NativeTypeError;
function kind(node) {
  const name = htmlName(node);
  if (name !== 'input' && name !== 'textarea') throw new NativeTypeError('An input or textarea is required');
  return name;
}
function mode(type) {
  if (type === 'file') return 'filename';
  if (type === 'checkbox' || type === 'radio') return 'default/on';
  if (type === 'hidden' || type === 'submit' || type === 'reset' || type === 'button' || type === 'image') return 'default';
  return 'value';
}
function childText(node) {
  let result = '';
  for (let child = node[NEXT]; child !== node[END]; child = (child[END] || child)[NEXT]) {
    const type = nodeInfo(child)?.kind;
    if (type === 3 || type === 4) result += child[VALUE];
  }
  return result;
}
function defaultValue(node, name) { return name === 'input' ? eventAttribute(node, 'value') ?? '' : childText(node); }
function normalizeLines(value) {
  let result = '';
  for (let i = 0; i < value.length; i++) if (value[i] === '\r') { result += '\n'; if (value[i + 1] === '\n') i++; } else result += value[i];
  return result;
}
function whitespace(c) { return c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f'; }
function trimASCII(value) {
  let first = 0, last = value.length, result = '';
  while (first < last && whitespace(value[first])) first++;
  while (last > first && whitespace(value[last - 1])) last--;
  for (let i = first; i < last; i++) result += value[i];
  return result;
}
function sanitize(node, type, value) {
  if (type !== 'text' && type !== 'search' && type !== 'tel' && type !== 'password' && type !== 'url' && type !== 'email') return sanitizeInputDomain(node, type, value);
  let result = '';
  for (let i = 0; i < value.length; i++) if (value[i] !== '\r' && value[i] !== '\n') result += value[i];
  if (type === 'url' || type === 'email') result = trimASCII(result);
  if (type === 'email' && eventAttribute(node, 'multiple') !== null) {
    let field = '', joined = '';
    for (let i = 0; i <= result.length; i++) {
      if (i === result.length || result[i] === ',') { joined += trimASCII(field) + (i === result.length ? '' : ','); field = ''; }
      else field += result[i];
    }
    result = joined;
  }
  return result;
}
function state(node, previousType) {
  const name = kind(node); let s = read(node);
  if (!s) { const type = previousType ?? (name === 'input' ? controlType(node) : 'textarea'); s = { name, type, raw: sanitize(node, type, defaultValue(node, name)), dirty: false }; save(node, s); }
  return s;
}
export function controlValue(node) {
  const s = state(node);
  if (s.name === 'textarea') return normalizeLines(s.dirty ? s.raw : childText(node));
  const current = mode(s.type);
  if (current === 'filename') return fileInputValue(node);
  if (current === 'default' || current === 'default/on') return eventAttribute(node, 'value') ?? (current === 'default/on' ? 'on' : '');
  return s.raw;
}
export function setControlValue(node, raw) {
  kind(node);
  const value = runDOMCallback(() => raw === null ? '' : eventString(raw)), s = state(node);
  if (s.name === 'textarea') { s.raw = value; s.dirty = true; return; }
  const current = mode(s.type);
  if (current === 'filename') {
    if (value !== '') throw new DOMError('A file value can only be cleared', 'InvalidStateError');
    clearInputFiles(node); s.raw = ''; s.dirty = true;
  } else if (current === 'default' || current === 'default/on') setControlAttribute(node, 'value', value);
  else { s.raw = sanitize(node, s.type, value); s.dirty = true; }
}
function changedAttribute(node, name, value, oldValue) {
  if (htmlName(node) !== 'input') return;
  let s = read(node);
  if (name === 'type') {
    s = s || state(node, inputTypeName(oldValue));
    const oldMode = mode(s.type), next = controlType(node), nextMode = mode(next), previous = controlValue(node);
    s.type = next;
    if (next !== inputTypeName(oldValue) && (next === 'file' || inputTypeName(oldValue) === 'file')) clearInputFiles(node, true);
    if (oldMode === 'value' && (nextMode === 'default' || nextMode === 'default/on') && previous !== '') setControlAttribute(node, 'value', previous);
    else if (oldMode !== 'value' && nextMode === 'value') { s.raw = sanitize(node, next, defaultValue(node, 'input')); s.dirty = false; }
    else if (nextMode === 'filename') s.raw = '';
    else if (nextMode === 'value') s.raw = sanitize(node, next, s.dirty ? previous : defaultValue(node, 'input'));
  } else if (s && name === 'value' && !s.dirty && mode(s.type) === 'value') s.raw = sanitize(node, s.type, defaultValue(node, 'input'));
  else if (s && s.type === 'range' && (name === 'min' || name === 'max' || name === 'step')) s.raw = sanitize(node, s.type, s.raw);
  else if (s && s.type === 'color' && (name === 'alpha' || name === 'colorspace')) s.raw = sanitize(node, s.type, s.dirty ? s.raw : defaultValue(node, 'input'));
  else if (s && name === 'multiple' && s.type === 'email') s.raw = sanitize(node, s.type, s.raw);
}
// Parsing installs attributes as a unit. In particular a range's midpoint
// must use all min/max/step attributes, regardless of their markup order.
export function initializeParsedValue(node) {
  if (htmlName(node) === 'input') resetControlValue(node);
}
export function copyControlValue(source, copy) {
  const name = htmlName(source);
  if (name !== 'input' && name !== 'textarea') return;
  if (name === 'input' && controlType(source) === 'file') copyInputFiles(source, copy);
  const s = state(source); save(copy, { name: s.name, type: s.type, raw: s.raw, dirty: s.dirty });
}
export function resetControlValue(node) {
  if (htmlName(node) === 'input') clearInputFiles(node);
  const s = state(node); s.dirty = false; s.raw = sanitize(node, s.type, defaultValue(node, s.name));
}
export function installValueProperties(L, ErrorClass) {
  DOMError = ErrorClass;
  installValueAttributeHook(changedAttribute);
  for (const [Class, name] of [[L.HTMLInputElement, 'input'], [L.HTMLTextAreaElement, 'textarea']]) {
    const check = node => { if (htmlName(node) !== name) throw new NativeTypeError('Wrong control receiver'); };
    define(Class.prototype, 'value', { configurable: true, enumerable: true,
      get() { check(this); return controlValue(this); }, set(value) { return withReactions(() => { check(this); setControlValue(this, value); }); },
    });
    define(Class.prototype, 'readOnly', { configurable: true, enumerable: true,
      get() { check(this); return eventAttribute(this, 'readonly') !== null; },
      set(value) { return withReactions(() => { check(this); setControlAttribute(this, 'readonly', value ? '' : null); }); },
    });
    define(Class.prototype, 'defaultValue', { configurable: true, enumerable: true,
      get() { check(this); return defaultValue(this, name); },
      set(raw) { return withReactions(() => { check(this); const value = runDOMCallback(() => eventString(raw)); if (name === 'input') setControlAttribute(this, 'value', value); else replaceControlText(this, value); }); },
    });
  }
  for (const name of ['min', 'max', 'step']) define(L.HTMLInputElement.prototype, name, {
    configurable: true, enumerable: true,
    get() { if (htmlName(this) !== 'input') throw new NativeTypeError('An input is required'); return eventAttribute(this, name) ?? ''; },
    set(raw) { return withReactions(() => { if (htmlName(this) !== 'input') throw new NativeTypeError('An input is required'); const value = runDOMCallback(() => eventString(raw)); setControlAttribute(this, name, value); }); },
  });
  define(L.HTMLInputElement.prototype, 'alpha', { configurable: true, enumerable: true,
    get() { if (htmlName(this) !== 'input') throw new NativeTypeError('An input is required'); return eventAttribute(this, 'alpha') !== null; },
    set(value) { return withReactions(() => { if (htmlName(this) !== 'input') throw new NativeTypeError('An input is required'); setControlAttribute(this, 'alpha', value ? '' : null); }); },
  });
  define(L.HTMLInputElement.prototype, 'colorSpace', { configurable: true, enumerable: true,
    get() { if (htmlName(this) !== 'input') throw new NativeTypeError('An input is required'); return colorSpaceName(this); },
    set(raw) { return withReactions(() => { if (htmlName(this) !== 'input') throw new NativeTypeError('An input is required'); const value = runDOMCallback(() => eventString(raw)); setControlAttribute(this, 'colorspace', value); }); },
  });
  define(L.HTMLTextAreaElement.prototype, 'type', { configurable: true, enumerable: true, get() { if (htmlName(this) !== 'textarea') throw new NativeTypeError('A textarea is required'); return 'textarea'; } });
  define(L.HTMLTextAreaElement.prototype, 'textLength', { configurable: true, enumerable: true, get() { if (htmlName(this) !== 'textarea') throw new NativeTypeError('A textarea is required'); return controlValue(this).length; } });
}
