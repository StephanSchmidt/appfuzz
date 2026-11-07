// DOM callbacks can call DOM APIs again. Their mutations form a new batch,
// so inline scripts they insert run before control returns to the callback.
let boundary = callback => callback();
export function setDOMCallbackBoundary(run) { const outer = boundary; boundary = callback => outer(() => run(callback)); }
export function runDOMCallback(callback) { return boundary(callback); }
