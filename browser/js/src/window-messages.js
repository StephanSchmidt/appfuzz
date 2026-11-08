// Window messaging in the page's modeled browsing context. Origin validation
// precedes data serialization; delivery checks the target again before reading
// the serialized record. Self-messaging does not make a network request.
import { serializeMessage, transferOptions, transferSequence } from './structured-clone.js';
import { eventString } from './event-state.js';
import { createMessageEvent } from './message-events.js';
import { fireEvent } from './event-target.js';
import { runDOMCallback } from './dom-callbacks.js';
import { URL, urlPart } from './urls.js';
import { DOMException } from './dom-exception.js';
const iteratorSymbol = Symbol.iterator;
const realm = globalThis, NativeTypeError = TypeError;
let origin = () => '', enqueue = () => {}, checkpoint = () => {};
export function installWindowMessages(value) { origin = value.origin; enqueue = value.enqueue; checkpoint = value.checkpoint; }
function transferList(value) {
  if (value === undefined) return [];
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) throw new NativeTypeError('Transfer must be an iterable object');
  return transferSequence(value, value[iteratorSymbol]);
}
export const postMessage = {
  postMessage(message) {
    'use strict';
    if (this !== undefined && this !== null && this !== realm) throw new NativeTypeError('A Window is required');
    if (!arguments.length) throw new NativeTypeError('postMessage requires a message');
    const options = arguments[1], legacy = arguments.length >= 3, transfer = arguments[2];
    return runDOMCallback(() => {
      let target, transfers;
      if (!legacy && (options == null || typeof options === 'object' || typeof options === 'function')) {
        // StructuredSerializeOptions is the base dictionary: convert transfer
        // before the derived WindowPostMessageOptions.targetOrigin member.
        transfers = transferOptions(options);
        const value = options == null ? undefined : options.targetOrigin;
        target = value === undefined ? '/' : eventString(value);
      } else {
        target = eventString(options);
        transfers = transferList(transfer);
      }
      const senderOrigin = origin();
      if (target === '/') target = senderOrigin;
      else if (target !== '*') {
        let parsed;
        try { parsed = new URL(target); }
        catch { throw new DOMException('Invalid target origin', 'SyntaxError'); }
        target = urlPart(parsed, 'origin');
        // Each parsed opaque origin is distinct, even when both origins
        // serialize to the string "null".
        if (target === 'null') target = null;
      }
      const deliver = serializeMessage(message, transfers);
      enqueue(() => {
        if (target !== '*' && (target === null || target !== origin())) return;
        let event;
        try { const data = deliver(); event = createMessageEvent('message', { data: data.value, ports: data.ports }, senderOrigin, realm); }
        catch { event = createMessageEvent('messageerror', { data: null, ports: [] }, senderOrigin, realm); }
        fireEvent(realm, event, true, null, checkpoint);
      });
    });
  },
}.postMessage;
