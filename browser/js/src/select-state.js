// Selectedness and dirtiness are private user-agent state shared by options,
// select APIs, selectors and form submission. Attribute and tree mutation ports
// apply the reset rules at mutation time, including in detached subtrees.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { htmlName, treeElements, formOwner, setControlAttribute } from './controls.js';
import { physicalParent, eventAttribute, nodeInfo } from './dom-state.js';
import { backendList } from './collection-data.js';
import { liveHTMLCollection } from './collections.js';
import { collectionVersion } from './collection-version.js';
import { installSelectHooks } from './ce-hooks.js';
import { eventString } from './event-state.js';
import { runDOMCallback } from './dom-callbacks.js';
import { withReactions } from './ce-reactions.js';
import { replaceControlText } from './control-values.js';
const NativeTypeError = TypeError, define = Object.defineProperty;
const states = new WeakMap(), read = states.get.bind(states), save = states.set.bind(states);
const initialized = new WeakSet(), has = initialized.has.bind(initialized), mark = initialized.add.bind(initialized);
const selections = new WeakMap(), selectedCollection = selections.get.bind(selections), saveCollection = selections.set.bind(selections);
let generation = 0;
function check(node, kind) { if (htmlName(node) !== kind) throw new NativeTypeError('An HTML ' + kind + ' element is required'); }
function state(option) {
  let data = read(option);
  if (!data) { data = { __proto__: null, selected: eventAttribute(option, 'selected') !== null, dirty: false, select: null }; save(option, data); }
  return data;
}
export function optionSelect(option) {
  let optgroup = false;
  for (let node = physicalParent(option); node; node = physicalParent(node)) {
    const name = htmlName(node);
    if (name === 'option' || name === 'datalist' || name === 'hr') return null;
    if (name === 'optgroup') { if (optgroup) return null; optgroup = true; }
    if (name === 'select') return node;
  }
  return null;
}
export function optionList(select) {
  const result = backendList();
  for (let node = select[NEXT]; node && node !== select[END]; node = node[NEXT]) {
    const name = htmlName(node);
    if (name === 'option') result[result.length] = node;
    let skip = name === 'select' || name === 'option' || name === 'datalist' || name === 'hr';
    if (name === 'optgroup') for (let parent = physicalParent(node); parent && parent !== select; parent = physicalParent(parent)) if (htmlName(parent) === 'optgroup') { skip = true; break; }
    if (skip) node = node[END];
  }
  return result;
}
export function optionDisabled(option) {
  if (eventAttribute(option, 'disabled') !== null) return true;
  for (let node = physicalParent(option); node; node = physicalParent(node)) {
    const name = htmlName(node);
    if (name === 'select' || name === 'hr' || name === 'datalist' || name === 'option') return false;
    if (name === 'optgroup') return eventAttribute(node, 'disabled') !== null;
  }
  return false;
}
function multiple(select) { return eventAttribute(select, 'multiple') !== null; }
function displaySize(select) {
  const raw = eventAttribute(select, 'size') || ''; let i = 0, value = 0, digits = false;
  while (raw[i] === ' ' || raw[i] === '\t' || raw[i] === '\n' || raw[i] === '\r' || raw[i] === '\f') i++;
  if (raw[i] === '+') i++;
  for (; i < raw.length && raw[i] >= '0' && raw[i] <= '9'; i++) { digits = true; value = value * 10 + (raw[i] - '0'); if (value > 2147483647) return multiple(select) ? 4 : 1; }
  return digits && value ? value : multiple(select) ? 4 : 1;
}
function change(option, value) { const data = state(option); if (data.selected !== value) { data.selected = value; generation++; } }
function resetSelectedness(select) {
  if (!select || multiple(select)) return;
  const options = optionList(select); let last = null, first = null;
  for (let i = 0; i < options.length; i++) {
    const option = options[i];
    if (state(option).selected) { if (last) change(last, false); last = option; }
    if (!first && !optionDisabled(option)) first = option;
  }
  if (!last && first && displaySize(select) === 1) change(first, true);
}
function ensure(select, initializeOwners = true) {
  if (!select || has(select)) return;
  mark(select);
  if (initializeOwners) { const options = optionList(select); for (let i = 0; i < options.length; i++) state(options[i]).select = select; resetSelectedness(select); }
}
function selectOnly(option, select) {
  if (!select || multiple(select)) return;
  const options = optionList(select);
  for (let i = 0; i < options.length; i++) if (options[i] !== option && state(options[i]).select === select) change(options[i], false);
}
export function optionSelected(option) { check(option, 'option'); ensure(optionSelect(option)); return state(option).selected; }
export function setOptionSelected(option, value) {
  check(option, 'option'); const select = optionSelect(option); ensure(select);
  change(option, !!value); state(option).dirty = true;
  if (value) selectOnly(option, select);
  resetSelectedness(select);
}
export function resetSelect(select) {
  check(select, 'select'); mark(select); const options = optionList(select);
  for (let i = 0; i < options.length; i++) { const option = options[i], data = state(option); change(option, eventAttribute(option, 'selected') !== null); data.dirty = false; data.select = select; }
  resetSelectedness(select);
}
export function optionText(option) {
  let result = '', space = false;
  for (let node = option[NEXT]; node && node !== option[END]; node = node[NEXT]) {
    if (htmlName(node) === 'script') { node = node[END]; continue; }
    const kind = nodeInfo(node)?.kind; if (kind !== 3 && kind !== 4) continue;
    const text = node[VALUE];
    for (let i = 0; i < text.length; i++) { const c = text[i]; if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f') space = !!result; else { result += (space ? ' ' : '') + c; space = false; } }
  }
  return result;
}
export function optionValue(option) { return eventAttribute(option, 'value') ?? optionText(option); }
function selectedIndex(select) { check(select, 'select'); ensure(select); const options = optionList(select); for (let i = 0; i < options.length; i++) if (state(options[i]).selected) return i; return -1; }
function setIndex(select, value) {
  check(select, 'select'); value = runDOMCallback(() => (+value) >> 0); ensure(select); const options = optionList(select);
  for (let i = 0; i < options.length; i++) { change(options[i], i === value); if (i === value) state(options[i]).dirty = true; }
}
// A user choice bypasses page IDL shadows and cannot pick a disabled option.
// Single selects move to another eligible option; multiple selects toggle an
// eligible option, as a control-click does, preserving the other selections.
export function chooseSelectOption(select, requested = undefined) {
  check(select, 'select');
  const preferred = requested == null ? null : runDOMCallback(() => (+requested) >> 0);
  ensure(select); const options = optionList(select); if (!options.length) return false;
  let current = -1;
  for (let i = 0; i < options.length; i++) if (state(options[i]).selected) { current = i; break; }
  const start = ((preferred ?? current + 1) % options.length + options.length) % options.length, many = multiple(select);
  for (let offset = 0; offset < options.length; offset++) {
    const option = options[(start + offset) % options.length];
    if (optionDisabled(option) || !many && state(option).selected) continue;
    setOptionSelected(option, many ? !state(option).selected : true); return true;
  }
  return false;
}
function selectValue(select) { check(select, 'select'); ensure(select); const options = optionList(select); for (let i = 0; i < options.length; i++) if (state(options[i]).selected) return optionValue(options[i]); return ''; }
function setValue(select, value) {
  check(select, 'select'); value = runDOMCallback(() => eventString(value)); ensure(select); const options = optionList(select); let matched = false;
  for (let i = 0; i < options.length; i++) { const chosen = !matched && optionValue(options[i]) === value; change(options[i], chosen); if (chosen) { matched = true; state(options[i]).dirty = true; } }
}
function attributeChanged(node, name, value, oldValue) {
  const kind = htmlName(node);
  if (kind === 'option' && name === 'selected' && (value === null) !== (oldValue === null)) {
    const data = state(node), select = optionSelect(node); ensure(select);
    if (!data.dirty) { change(node, value !== null); if (value !== null) selectOnly(node, select); }
    resetSelectedness(select);
  } else if (kind === 'option' && name === 'disabled' && (value === null) !== (oldValue === null)) resetSelectedness(optionSelect(node));
  else if (kind === 'select' && (name === 'size' || name === 'multiple' && (value === null) !== (oldValue === null))) {
    ensure(node);
    if (name === 'multiple' && value === null) { const options = optionList(node); let found = false; for (let i = 0; i < options.length; i++) if (state(options[i]).selected) { if (found) change(options[i], false); found = true; } }
    resetSelectedness(node);
  }
}
function treeChanged(root) {
  const nodes = treeElements(root), jobs = backendList();
  for (let i = 0; i < nodes.length; i++) if (htmlName(nodes[i]) === 'option') { const option = nodes[i], data = state(option); jobs[jobs.length] = { __proto__: null, option, selected: data.selected, old: data.select, next: optionSelect(option) }; }
  for (let i = 0; i < jobs.length; i++) {
    const job = jobs[i], data = state(job.option); data.select = job.next;
    if (job.old === job.next) continue;
    ensure(job.old, false); ensure(job.next, false);
    if (job.selected && job.next) { change(job.option, true); selectOnly(job.option, job.next); }
    resetSelectedness(job.old); resetSelectedness(job.next);
  }
}
installSelectHooks(attributeChanged, treeChanged);
export function installSelectProperties(L) {
  function properties(prototype, fields) { const keys = Reflect.ownKeys(fields); for (let i = 0; i < keys.length; i++) define(prototype, keys[i], { ...Object.getOwnPropertyDescriptor(fields, keys[i]), enumerable: true, configurable: true }); }
  properties(L.HTMLOptionElement.prototype, {
    get disabled() { check(this, 'option'); return eventAttribute(this, 'disabled') !== null; }, set disabled(value) { check(this, 'option'); return withReactions(() => setControlAttribute(this, 'disabled', value ? '' : null)); },
    get selected() { return optionSelected(this); }, set selected(value) { return withReactions(() => setOptionSelected(this, value)); },
    get value() { check(this, 'option'); return optionValue(this); }, set value(value) { check(this, 'option'); return withReactions(() => setControlAttribute(this, 'value', runDOMCallback(() => eventString(value)))); },
    get text() { check(this, 'option'); return optionText(this); }, set text(value) { check(this, 'option'); value = runDOMCallback(() => eventString(value)); return withReactions(() => replaceControlText(this, value)); },
    get label() { check(this, 'option'); return eventAttribute(this, 'label') ?? optionText(this); }, set label(value) { check(this, 'option'); return withReactions(() => setControlAttribute(this, 'label', runDOMCallback(() => eventString(value)))); },
    get defaultSelected() { check(this, 'option'); return eventAttribute(this, 'selected') !== null; }, set defaultSelected(value) { check(this, 'option'); return withReactions(() => setControlAttribute(this, 'selected', value ? '' : null)); },
    get index() { check(this, 'option'); const select = optionSelect(this); if (select) { const options = optionList(select); for (let i = 0; i < options.length; i++) if (options[i] === this) return i; } return 0; },
    get form() { check(this, 'option'); const select = optionSelect(this); return select ? formOwner(select) : null; },
  });
  properties(L.HTMLSelectElement.prototype, {
    get selectedIndex() { return selectedIndex(this); }, set selectedIndex(value) { setIndex(this, value); },
    get value() { return selectValue(this); }, set value(value) { setValue(this, value); },
    get selectedOptions() {
      check(this, 'select'); ensure(this); let collection = selectedCollection(this);
      if (!collection) { collection = liveHTMLCollection(this, () => { ensure(this); const options = optionList(this), result = backendList(); for (let i = 0; i < options.length; i++) if (state(options[i]).selected) result[result.length] = options[i]; return result; }, () => generation + collectionVersion(true)); saveCollection(this, collection); }
      return collection;
    },
  });
}
