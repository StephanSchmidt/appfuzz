// The creation-time is value is an internal slot. An attribute mutation
// never changes it, and cloning copies it independently of the attributes.
const values = new WeakMap();
const has = values.has.bind(values), get = values.get.bind(values), set = values.set.bind(values);
export function rememberIs(node, value = null) { if (!has(node)) set(node, value); }
export function elementIs(node) { return get(node) ?? null; }

// An upgrade's construction stack is per definition, not per document.
const stacks = new WeakMap();
const stackFor = stacks.get.bind(stacks), saveStack = stacks.set.bind(stacks);
export function beginConstruction(Class, element) {
  let stack = stackFor(Class);
  if (!stack) saveStack(Class, stack = []);
  const frame = { element, consumed: false };
  stack[stack.length] = frame;
  return frame;
}
export function currentConstruction(Class) { const stack = stackFor(Class); return stack?.[stack.length - 1]; }
export function endConstruction(Class) { const stack = stackFor(Class); stack.length--; }

const definitions = new WeakMap(), instances = new WeakMap();
export const definitionForClass = definitions.get.bind(definitions);
export const rememberDefinition = definitions.set.bind(definitions);
export const elementDefinition = instances.get.bind(instances);
export const rememberElementDefinition = instances.set.bind(instances);
export const forgetElementDefinition = instances.delete.bind(instances);
