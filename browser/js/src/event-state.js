// Event flags and timestamps are browser state. Public property shadows
// and replacements of Date.now cannot change native dispatch/cancellation.
const states = new WeakMap();
const save = states.set.bind(states), get = states.get.bind(states);
const NativeTypeError = TypeError;
let clock = () => 0;
export function setEventClock(read) { clock = read; }
export function initializeEvent(event, cancelable) { save(event, { cancelable, canceled: false, timeStamp: clock() }); }
function state(event) {
  const result = get(event);
  if (!result) throw new NativeTypeError('An Event is required');
  return result;
}
export function assertEvent(event) { state(event); }
export function eventCancelable(event) { return state(event).cancelable; }
export function eventCanceled(event) { return state(event).canceled; }
export function eventTimeStamp(event) { return state(event).timeStamp; }
export function cancelEvent(event) {
  const record = state(event);
  if (record.cancelable) record.canceled = true;
}
