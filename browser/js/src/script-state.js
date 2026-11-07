// The script element's preparation state is independent of whether its
// code ran. In particular, disabled documents, fragment parsers and
// nomodule scripts can set alreadyStarted without executing anything.
import { END } from '../node_modules/linkedom/esm/shared/symbols.js';

const records = new WeakMap();
export const scriptRecord = records.get.bind(records);
const save = records.set.bind(records);
// Adoption and cloning update the private end marker along with the
// element. A page can shadow the public ownerDocument accessor.
export const scriptOwner = node => node[END].ownerDocument;

export function rememberScript(node, identity, alreadyStarted = false) {
  let record = scriptRecord(node);
  if (!record) save(node, record = { identity, alreadyStarted, prepared: null });
  else { record.identity = identity; if (alreadyStarted) record.alreadyStarted = true; }
  return record;
}
