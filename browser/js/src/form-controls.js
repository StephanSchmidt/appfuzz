import { selectedInputFiles } from './file-inputs.js';
// Submission reads user-agent state, independently of author property shadows.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { htmlName, controlType, treeElements, formOwner, disabled, checked } from './controls.js';
import { controlValue as currentValue } from './control-values.js';
import { nodeInfo, physicalParent, physicalRoot, shadowInfo, eventAttribute } from './dom-state.js';
const lower = Function.prototype.call.bind(String.prototype.toLowerCase);
const bidiDirection = globalThis.__native.bidiDirection, setPrototype = Object.setPrototypeOf;
const autoTypes = new Set(['hidden', 'text', 'search', 'tel', 'url', 'email', 'password', 'submit', 'reset', 'button']);
const autoType = autoTypes.has.bind(autoTypes);
// Existing DOM selectedness and submission share the same private state.
const selection = new WeakMap();
const hasSelection = selection.has.bind(selection), readSelection = selection.get.bind(selection), writeSelection = selection.set.bind(selection), clearSelection = selection.delete.bind(selection);
const NativeTypeError = TypeError;
export function optionSelected(option) {
  if (htmlName(option) !== 'option') throw new NativeTypeError('An HTMLOptionElement is required');
  return hasSelection(option) ? readSelection(option) : eventAttribute(option, 'selected') !== null;
}
export function setOptionSelected(option, value) {
  if (htmlName(option) !== 'option') throw new NativeTypeError('An HTMLOptionElement is required');
  writeSelection(option, !!value);
}

export function resetSelect(select) {
  const nodes = treeElements(select);
  for (let i = 1; i < nodes.length; i++) if (htmlName(nodes[i]) === 'option') {
    let parent = physicalParent(nodes[i]);
    while (parent && htmlName(parent) !== 'select') parent = physicalParent(parent);
    if (parent === select) clearSelection(nodes[i]);
  }
}

function text(node, directional = false) {
  let result = '';
  for (let child = node[NEXT]; child && child !== node[END]; child = child[NEXT]) {
    const name = htmlName(child);
    if (directional && name && (name === 'bdi' || name === 'script' || name === 'style' || name === 'textarea' || eventAttribute(child, 'dir') !== null)) { child = child[END]; continue; }
    const kind = nodeInfo(child)?.kind;
    if (kind === 3 || kind === 4) result += child[VALUE];
  }
  return result;
}
function collapseSpaces(value) {
  let result = '', space = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f') space = !!result;
    else { result += (space ? ' ' : '') + c; space = false; }
  }
  return result;
}
function controlValue(node) { if (htmlName(node) === 'button') return eventAttribute(node, 'value') ?? ''; return htmlName(node) === 'input' && controlType(node) === 'submit' && eventAttribute(node, 'value') === null ? 'Submit Query' : currentValue(node); }

function autoControl(node) { return htmlName(node) === 'textarea' || (htmlName(node) === 'input' && autoType(controlType(node))); }
function direction(node) {
  for (let current = node; current; current = physicalParent(current) || shadowInfo(current)?.host) {
    const name = htmlName(current), state = lower(eventAttribute(current, 'dir') || '');
    if (state === 'ltr' || state === 'rtl') return state;
    if (state === 'auto' || (name === 'bdi' && state !== 'ltr' && state !== 'rtl')) return bidiDirection(autoControl(current) ? controlValue(current) : text(current, true)) || 'ltr';
    if (name === 'input' && controlType(current) === 'tel') return 'ltr';
  }
  return 'ltr';
}
export function isSubmitButton(node) {
  const name = htmlName(node), type = controlType(node);
  return name === 'button' ? type !== 'button' && type !== 'reset' : name === 'input' && (type === 'submit' || type === 'image');
}
function optionDisabled(option) {
  if (eventAttribute(option, 'disabled') !== null) return true;
  const parent = physicalParent(option);
  return htmlName(parent) === 'optgroup' && eventAttribute(parent, 'disabled') !== null;
}
// HTML nonnegative integer attributes accept a leading sign and digit
// prefix; they do not use JavaScript's hexadecimal or fractional syntax.
function displaySize(select) {
  const raw = eventAttribute(select, 'size') || ''; let i = 0, value = 0, digits = false;
  while (raw[i] === ' ' || raw[i] === '\t' || raw[i] === '\n' || raw[i] === '\r' || raw[i] === '\f') i++;
  if (raw[i] === '+') i++;
  for (; i < raw.length && raw[i] >= '0' && raw[i] <= '9'; i++) {
    digits = true; value = value * 10 + (raw[i] - '0');
    if (value > 2147483647) return 0;
  }
  return digits ? value : 0;
}
function selectEntries(select, name, add) {
  const nodes = treeElements(select), options = []; setPrototype(options, null);
  for (let i = 1; i < nodes.length; i++) if (htmlName(nodes[i]) === 'option') {
    let parent = physicalParent(nodes[i]);
    while (parent && htmlName(parent) !== 'select') parent = physicalParent(parent);
    if (parent === select) options[options.length] = nodes[i];
  }
  const multiple = eventAttribute(select, 'multiple') !== null; let selected = -1, explicit = false;
  if (!multiple) {
    for (let i = 0; i < options.length; i++) { if (optionSelected(options[i])) selected = i; if (hasSelection(options[i])) explicit = true; }
    const size = displaySize(select);
    if (selected < 0 && !explicit && !(size > 1)) for (let i = 0; i < options.length; i++) if (!optionDisabled(options[i])) { selected = i; break; }
  }
  for (let i = 0; i < options.length; i++) {
    const option = options[i];
    if ((multiple ? optionSelected(option) : i === selected) && !optionDisabled(option)) add(name, eventAttribute(option, 'value') ?? collapseSpaces(text(option)));
  }
}
export function populateForm(form, submitter, add, emptyFile) {
  const nodes = treeElements(physicalRoot(form));
  for (let i = 0; i < nodes.length; i++) {
    const field = nodes[i], tag = htmlName(field);
    if (tag !== 'input' && tag !== 'select' && tag !== 'textarea' && tag !== 'button') continue;
    if (formOwner(field) !== form || disabled(field)) continue;
    const type = controlType(field), button = tag === 'button' || tag === 'input' && (type === 'button' || type === 'submit' || type === 'reset' || type === 'image');
    if (button && field !== submitter) continue;
    if (tag === 'input' && (type === 'checkbox' || type === 'radio') && !checked(field)) continue;
    const name = eventAttribute(field, 'name');
    if (tag === 'input' && type === 'image') { const prefix = name ? name + '.' : ''; add(prefix + 'x', '0'); add(prefix + 'y', '0'); continue; }
    if (!name) continue;
    if (tag === 'select') selectEntries(field, name, add);
    else if (tag === 'input' && (type === 'checkbox' || type === 'radio')) add(name, eventAttribute(field, 'value') ?? 'on');
    else if (tag === 'input' && type === 'file') { const files = selectedInputFiles(field); if (!files.length) add(name, emptyFile()); else for (let j = 0; j < files.length; j++) add(name, files[j]); }
    else if (tag === 'input' && type === 'hidden' && lower(name) === '_charset_') add(name, 'UTF-8');
    else add(name, controlValue(field));
    const dirname = eventAttribute(field, 'dirname');
    if (dirname && autoControl(field)) add(dirname, direction(field));
  }
}
