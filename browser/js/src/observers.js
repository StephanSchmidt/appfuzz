// Observers belong to this window's agent, rather than the target's current
// owner document. A target remains observed after cross-document adoption.
import { MUTATION_OBSERVER } from '../node_modules/linkedom/esm/shared/symbols.js';
import { MutationObserverClass } from '../node_modules/linkedom/esm/interface/mutation-observer.js';

export function installObservers(document) {
  const domain = document[MUTATION_OBSERVER].class ? document[MUTATION_OBSERVER]
    : (document[MUTATION_OBSERVER] = new MutationObserverClass(document));
  const patched = new WeakSet();
  const share = (document) => {
    const current = document?.[MUTATION_OBSERVER];
    if (!current) return;
    const prototype = current.class?.prototype;
    if (prototype && !patched.has(prototype)) {
      patched.add(prototype);
      const observe = prototype.observe, disconnect = prototype.disconnect;
      prototype.observe = function (...args) {
        const result = observe.apply(this, args);
        domain.observers.add(this);
        domain.active = true;
        return result;
      };
      prototype.disconnect = function () {
        disconnect.call(this);
        domain.observers.delete(this);
        domain.active = domain.observers.size !== 0;
      };
    }
    if (current !== domain) {
      for (const observer of current.observers || []) domain.observers.add(observer);
      document[MUTATION_OBSERVER] = domain;
      domain.active = domain.observers.size !== 0;
    }
  };
  share(document);
  return share;
}
