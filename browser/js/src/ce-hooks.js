// Linkedom calls these ports at the actual mutation, preserving argument
// values (including a repeated assignment of the same attribute value).
let attribute = () => {}, connection = () => {};
export function installCEHooks(onAttribute, onConnection) { attribute = onAttribute; connection = onConnection; }
export function attributeReaction(element, name, oldValue, value) { attribute(element, name, oldValue, value); }
export function connectionReaction(root, connected) { connection(root, connected); }
