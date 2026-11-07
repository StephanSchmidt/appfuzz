// Diagnostic extraction must not replace the original exception with an
// exception from a name/message getter or a failing string conversion.
// Plain thrown objects use their string conversion, not Error properties.
import { runDOMCallback } from './dom-callbacks.js';
const isError = Error.isError;
const string = String;
const slice = Function.prototype.call.bind(String.prototype.slice);
const descriptor = Object.getOwnPropertyDescriptor;
const own = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
export const clipDiagnostic = (value, length = 400) => value.length > length ? slice(value, 0, length) + '…' : value;
function text(read, fallback) {
  try { return runDOMCallback(() => { const value = read(); return value === undefined ? fallback : string(value); }); }
  catch { return fallback; }
}
export function exceptionInfo(value) {
  if (!isError(value)) {
    const message = text(() => string(value), "unknown (can't convert to string)");
    return { name: 'Thrown', message, stack: '', eventMessage: 'uncaught exception: ' + message };
  }
  const name = text(() => value.name, 'Error'), message = text(() => value.message, '');
  // A stack is useful diagnostic data, but invoking an author stack getter
  // is not part of the browser's exception reporting algorithm.
  const property = descriptor(value, 'stack');
  const stack = property && own(property, 'value') && typeof property.value === 'string' ? property.value : '';
  return { name, message, stack, eventMessage: name ? (message ? name + ': ' + message : name) : message };
}
