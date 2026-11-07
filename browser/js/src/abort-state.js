// Source/dependent state changes precede all public abort events. Edges are
// weak unless a dependent has listeners or abort algorithms to keep alive.
const signals = new WeakMap();
const get = signals.get.bind(signals), save = signals.set.bind(signals);
const NativeTypeError = TypeError, NativeWeakRef = WeakRef;
const deref = Function.prototype.call.bind(WeakRef.prototype.deref);
let dispatchAbort = () => {};
export function setAbortEventDispatcher(callback) { dispatchAbort = callback; }
export function initializeSignal(signal) { save(signal, { aborted: false, reason: undefined, algorithms: [], dependent: false, sources: [], dependents: [], abortListener: false }); }
export function signalState(signal) {
  const state = get(signal);
  if (!state) throw new NativeTypeError('An AbortSignal is required');
  return state;
}
function retain(signal, s) {
  const strong = s.abortListener || s.algorithms.length ? signal : null;
  for (let i = 0; i < s.sources.length; i++) s.sources[i].edge.strong = strong;
}
export function signalListenersChanged(signal, types) {
  const s = get(signal); if (!s) return;
  s.abortListener = false;
  for (let i = 0; i < types.length; i++) if (types[i] === 'abort') s.abortListener = true;
  retain(signal, s);
}
export function onSignalAbort(signal, callback) {
  const s = signalState(signal), record = { callback };
  if (s.aborted) { callback(); return () => {}; }
  s.algorithms[s.algorithms.length] = record; retain(signal, s);
  return () => {
    record.callback = null;
    const records = s.algorithms;
    for (let i = 0; i < records.length; i++) if (records[i] === record) {
      for (let j = i + 1; j < records.length; j++) records[j - 1] = records[j];
      records.length--; break;
    }
    retain(signal, s);
  };
}
function prune(source) {
  const records = source.dependents; let length = 0;
  for (let i = 0; i < records.length; i++) {
    const signal = records[i].ref && deref(records[i].ref);
    if (signal && !signalState(signal).aborted) records[length++] = records[i];
  }
  records.length = length;
}
export function dependSignal(signal, inputs) {
  const s = signalState(signal);
  for (let i = 0; i < inputs.length; i++) {
    const source = signalState(inputs[i]);
    if (source.aborted) { s.aborted = true; s.reason = source.reason; return signal; }
  }
  s.dependent = true;
  const roots = [];
  const append = root => {
    for (let i = 0; i < roots.length; i++) if (roots[i] === root) return;
    roots[roots.length] = root;
  };
  for (let i = 0; i < inputs.length; i++) {
    const source = signalState(inputs[i]);
    if (!source.dependent) append(inputs[i]);
    else for (let j = 0; j < source.sources.length; j++) { const root = deref(source.sources[j].source); if (root) append(root); }
  }
  for (let i = 0; i < roots.length; i++) {
    const root = signalState(roots[i]); prune(root);
    const edge = { ref: new NativeWeakRef(signal), strong: null };
    root.dependents[root.dependents.length] = edge;
    s.sources[s.sources.length] = { source: new NativeWeakRef(roots[i]), edge };
  }
  retain(signal, s); return signal;
}
function detach(s) {
  for (let i = 0; i < s.sources.length; i++) {
    const entry = s.sources[i], source = deref(entry.source);
    entry.edge.strong = entry.edge.ref = null;
    if (source) prune(signalState(source));
  }
  s.sources = [];
}
function runSteps(signal) {
  const s = signalState(signal), records = s.algorithms;
  s.algorithms = [];
  for (let i = 0; i < records.length; i++) if (records[i].callback) records[i].callback();
  dispatchAbort(signal);
}
export function abortSignal(signal, reason) {
  const s = signalState(signal);
  if (s.aborted) return false;
  s.aborted = true; s.reason = reason;
  const dependents = [], edges = s.dependents; s.dependents = [];
  for (let i = 0; i < edges.length; i++) {
    const dependent = edges[i].ref && deref(edges[i].ref);
    if (dependent) {
      const state = signalState(dependent);
      if (!state.aborted) { state.aborted = true; state.reason = reason; dependents[dependents.length] = dependent; }
    }
  }
  detach(s);
  for (let i = 0; i < dependents.length; i++) detach(signalState(dependents[i]));
  runSteps(signal);
  for (let i = 0; i < dependents.length; i++) runSteps(dependents[i]);
  return true;
}
