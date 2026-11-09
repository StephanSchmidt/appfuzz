import { baseAttributeChanged, documentConnectionChanged } from './document-urls.js';
import { collectionAttributesChanged } from './collection-version.js';
// Linkedom calls these ports at the actual mutation, preserving argument
// values (including a repeated assignment of the same attribute value).
let attribute = () => {}, connection = () => {}, scriptAttribute = () => {};
export function installScriptAttributeHook(value) { scriptAttribute = value; }
export function installCEHooks(onAttribute, onConnection) { attribute = onAttribute; connection = onConnection; }
let eventAttribute = () => {}, controlAttribute = () => {}, controlConnection = () => {};
export function installControlHooks(onAttribute, onConnection) { controlAttribute = onAttribute; controlConnection = onConnection; }
let selectAttribute = () => {}, selectConnection = () => {};
export function installSelectHooks(onAttribute, onConnection) { selectAttribute = onAttribute; selectConnection = onConnection; }
export function installEventAttributeHook(callback) { eventAttribute = callback; }
export function attributeReaction(element, name, oldValue, value, namespace = null) {
  collectionAttributesChanged();
  baseAttributeChanged(element,name,namespace);
  if (namespace === null) { eventAttribute(element, name, value); controlAttribute(element, name, value, oldValue); selectAttribute(element, name, value, oldValue); }
  scriptAttribute(element,name,namespace);
  attribute(element, name, oldValue, value, namespace);
}
export function connectionReaction(root, connected) { documentConnectionChanged(root, connected); controlConnection(root, connected); selectConnection(root, connected); connection(root, connected); }
