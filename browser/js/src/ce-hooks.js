// Linkedom calls these ports at the actual mutation, preserving argument
// values (including a repeated assignment of the same attribute value).
let attribute = () => {}, connection = () => {};
export function installCEHooks(onAttribute, onConnection) { attribute = onAttribute; connection = onConnection; }
let eventAttribute = () => {}, controlAttribute = () => {}, controlConnection = () => {};
export function installControlHooks(onAttribute, onConnection) { controlAttribute = onAttribute; controlConnection = onConnection; }
export function installEventAttributeHook(callback) { eventAttribute = callback; }
export function attributeReaction(element, name, oldValue, value) {
  eventAttribute(element, name, value);
  controlAttribute(element, name, value, oldValue);
  attribute(element, name, oldValue, value);
}
export function connectionReaction(root, connected) { controlConnection(root, connected); connection(root, connected); }
