// Input file selection is user-agent state, independent of public files,
// value and File metadata accessors. Only synthetic FileList objects enter it.
import { htmlName, controlType } from './controls.js';
import { blobRecord } from './blobs.js';
import { makeFileList, fileListEntries } from './event-payloads.js';
const NativeTypeError = TypeError, define = Object.defineProperty, descriptor = Object.getOwnPropertyDescriptor, setPrototype = Object.setPrototypeOf;
const selections = new WeakMap(), read = selections.get.bind(selections), save = selections.set.bind(selections);
function empty() { const entries = []; setPrototype(entries, null); return makeFileList(entries); }
function check(node) { if (htmlName(node) !== 'input') throw new NativeTypeError('An HTMLInputElement is required'); }
function selection(node) { let value = read(node); if (!value) { value = empty(); save(node, value); } return value; }
export function selectedInputFiles(node) { return fileListEntries(selection(node)); }
export function clearInputFiles(node, force = false) { const previous = read(node); if (force || previous && fileListEntries(previous).length) save(node, empty()); }
export function fileInputValue(node) { const files = selectedInputFiles(node); return files.length ? 'C:\\fakepath\\' + blobRecord(files[0]).name : ''; }
export function copyInputFiles(source, target) {
  const files = selectedInputFiles(source), copy = []; setPrototype(copy, null);
  for (let i = 0; i < files.length; i++) copy[copy.length] = files[i];
  save(target, makeFileList(copy));
}
export function installFileInputs(prototype) {
  const methods = {
    get files() { check(this); return controlType(this) === 'file' ? selection(this) : null; },
    set files(value) { check(this); if (value != null && !fileListEntries(value)) throw new NativeTypeError('A FileList is required'); if (value != null && controlType(this) === 'file') save(this, value); },
  };
  define(prototype, 'files', descriptor(methods, 'files'));
}
