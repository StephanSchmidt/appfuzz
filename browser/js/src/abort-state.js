// Abort algorithms run before the public abort event. They cannot be
// prevented by stopImmediatePropagation or public signal property shadows.
const signals = new WeakMap();
const get = signals.get.bind(signals), save = signals.set.bind(signals);
const NativeTypeError = TypeError;
export function initializeSignal(signal) { save(signal, { aborted: false, reason: undefined, algorithms: [] }); }
export function signalState(signal) {
  const state = get(signal);
  if (!state) throw new NativeTypeError('An AbortSignal is required');
  return state;
}
export function onSignalAbort(signal, callback) {
  const s = signalState(signal), record = { callback };
  if (s.aborted) { callback(); return () => {}; }
  s.algorithms[s.algorithms.length] = record;
  return () => {
    record.callback = null;
    const records = s.algorithms;
    for (let i = 0; i < records.length; i++) if (records[i] === record) {
      for (let j = i + 1; j < records.length; j++) records[j - 1] = records[j];
      records.length--; break;
    }
  };
}
export function abortSignal(signal, reason) {
  const s = signalState(signal);
  if (s.aborted) return false;
  s.aborted = true; s.reason = reason;
  const records = s.algorithms; s.algorithms = [];
  for (let i = 0; i < records.length; i++) if (records[i].callback) records[i].callback();
  return true;
}
