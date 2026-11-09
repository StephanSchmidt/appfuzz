import { optionList, optionSelected, optionDisabled, optionValue } from './select-state.js';
import { selectedInputFiles } from './file-inputs.js';
// Submission reads user-agent state, independently of author property shadows.
import { END, NEXT, VALUE } from '../node_modules/linkedom/esm/shared/symbols.js';
import { htmlName, controlType, treeElements, formOwner, disabled, checked } from './controls.js';
import { controlValue as currentValue } from './control-values.js';
import { nodeInfo, physicalParent, physicalRoot, shadowInfo, eventAttribute } from './dom-state.js';
const lower = Function.prototype.call.bind(String.prototype.toLowerCase);
const bidiDirection = globalThis.__native.bidiDirection;
const autoTypes = new Set(['hidden', 'text', 'search', 'tel', 'url', 'email', 'password', 'submit', 'reset', 'button']);
const autoType = autoTypes.has.bind(autoTypes);
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
function selectEntries(select, name, add) {
  const options = optionList(select);
  for (let i = 0; i < options.length; i++) if (optionSelected(options[i]) && !optionDisabled(options[i])) add(name, optionValue(options[i]));
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
