// Keep native CSS color conversion independent of page-visible functions.
import { eventAttribute } from './dom-state.js';
import { lowerASCII } from './names.js';
const nativeColor = globalThis.__native.inputColor;
let reportUnsupported = () => {};
export function installColorReporter(callback) { reportUnsupported = callback; }
export function colorSpaceName(node) { return lowerASCII(eventAttribute(node, 'colorspace') ?? '') === 'display-p3' ? 'display-p3' : 'limited-srgb'; }
export function colorValue(node, value) {
  const result = nativeColor(value, eventAttribute(node, 'alpha') !== null, colorSpaceName(node) === 'display-p3');
  if (result.unsupported) reportUnsupported('input[type=color]:CSS color expression');
  return result.value;
}
