import { HTMLElement } from '../node_modules/linkedom/esm/html/element.js';
import { Classes } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { builtinInterface, additionalInterfaces } from './creation.js';
import { initializeElement, markCustom } from './element-internals.js';
import { currentConstruction, definitionForClass } from './element-state.js';
const infoFor = Classes.get.bind(Classes);
const isHTML = Object.prototype.isPrototypeOf.bind(HTMLElement.prototype);
const construct = Reflect.construct, define = Object.defineProperty;
const setPrototype = Object.setPrototypeOf;
const TypeErrorClass = TypeError, NativeProxy = Proxy;

export function installHTMLConstructors(G, L) {
  const wrappers = new WeakMap();
  const get = wrappers.get.bind(wrappers), save = wrappers.set.bind(wrappers);
  for (const [name, Class] of Object.entries({ ...L, ...additionalInterfaces })) {
    if (typeof Class !== 'function' || (Class !== HTMLElement && !isHTML(Class.prototype))) continue;
    let wrapped = get(Class);
    if (!wrapped) {
      wrapped = new NativeProxy(Class, { construct(_target, _args, NewTarget) {
        if (NewTarget === wrapped) throw new TypeErrorClass('Illegal HTML constructor');
        const info = infoFor(NewTarget), definition = definitionForClass(NewTarget);
        if (!info || !definition) throw new TypeErrorClass('Illegal HTML constructor');
        const expected = info.options.is ? builtinInterface(info.localName) : HTMLElement;
        if (expected !== Class) throw new TypeErrorClass('The constructor does not match the registered element interface');
        const identity = { namespace: 'http://www.w3.org/1999/xhtml', prefix: null, local: info.localName, qualified: info.localName };
        const frame = currentConstruction(NewTarget);
        if (frame) {
          if (frame.consumed) throw new TypeErrorClass('The element has already been constructed');
          frame.consumed = true;
          setPrototype(frame.element, NewTarget.prototype);
          return initializeElement(frame.element, identity, info.options.is || null);
        }
        const node = construct(Class, [info.ownerDocument, info.localName], NewTarget);
        initializeElement(node, identity, info.options.is || null);
        markCustom(node, definition);
        return node;
      } });
      save(Class, wrapped);
      define(Class.prototype, 'constructor', { configurable: true, writable: true, value: wrapped });
    }
    G[name] = wrapped;
  }
}
