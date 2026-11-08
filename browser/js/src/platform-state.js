// A platform brand is independent of public prototypes and own properties.
// Structured cloning rejects nonserializable API objects, including empty ones.
const objects = new WeakMap(), get = objects.get.bind(objects), set = objects.set.bind(objects);
export function markPlatform(value, kind = true) { set(value, kind); return value; }
export const platformObject = value => get(value) !== undefined;
export const platformKind = get;
