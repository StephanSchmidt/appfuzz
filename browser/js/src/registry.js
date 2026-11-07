import { CustomElementRegistry, Classes } from '../node_modules/linkedom/esm/interface/custom-element-registry.js';
import { Element } from '../node_modules/linkedom/esm/interface/element.js';
import { Node } from '../node_modules/linkedom/esm/interface/node.js';
import { CUSTOM_ELEMENTS, END, NEXT, PREV } from '../node_modules/linkedom/esm/shared/symbols.js';
import { validName } from './custom-name.js';
import { HTMLUnknownElement } from '../node_modules/linkedom/esm/html/unknown-element.js';
import { builtinInterface, createBareElement } from './creation.js';
import { upgradeDefinition, markFailed } from './upgrading.js';
import { definitionForClass, rememberDefinition } from './element-state.js';
import { nameIdentity, installName } from './names.js';
import { HTMLDocument } from '../node_modules/linkedom/esm/html/document.js';
import { withReactions } from './ce-reactions.js';
import { runDOMCallback } from './dom-callbacks.js';

const saveClass = Classes.set.bind(Classes);
const mapGet = Function.prototype.call.bind(Map.prototype.get);
const mapSet = Function.prototype.call.bind(Map.prototype.set);
const mapHas = Function.prototype.call.bind(Map.prototype.has);
const mapDelete = Function.prototype.call.bind(Map.prototype.delete);
const hasClass = Classes.has.bind(Classes);
const isNode = Object.prototype.isPrototypeOf.bind(Node.prototype);
const isElement = Object.prototype.isPrototypeOf.bind(Element.prototype);
const isHTML = Object.prototype.isPrototypeOf.bind(HTMLDocument.prototype);
const NativeTypeError = TypeError, NativeProxy = Proxy, NativePromise = Promise, string = String, construct = Reflect.construct;
const rejected = Promise.reject.bind(Promise), resolved = Promise.resolve.bind(Promise);
export function domString(value) { if (typeof value === 'symbol') throw new NativeTypeError('A Symbol cannot be converted to a DOMString'); return string(value); }

function stringSequence(value) {
  if (value === undefined) return [];
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) throw new NativeTypeError('A sequence requires an iterable object');
  const result = [];
  for (const item of value) result[result.length] = domString(item);
  return result;
}

export function installRegistry(upgradeCopies, DOMError, report) {
  const proto = CustomElementRegistry.prototype;
  const running = new WeakMap(), promises = new WeakMap();
  const promiseMap = promises.get.bind(promises), savePromises = promises.set.bind(promises);
  const isRunning = running.get.bind(running), setRunning = running.set.bind(running);
  const check = registry => { if (!registry?.ownerDocument || registry.ownerDocument[CUSTOM_ELEMENTS] !== registry) throw new NativeTypeError('Illegal registry receiver'); };
  proto.define = function (rawName, Class, options = {}) {
    check(this);
    const name = domString(rawName);
    if (options != null && typeof options !== 'object' && typeof options !== 'function') throw new NativeTypeError('Definition options must be a dictionary');
    const rawExtend = options?.extends, extend = rawExtend === undefined ? undefined : domString(rawExtend);
    if (typeof Class !== 'function') throw new NativeTypeError('A constructor is required');
    try { construct(new NativeProxy(Class, { construct: () => ({}) }), []); } catch { throw new NativeTypeError('A constructor is required'); }
    if (!validName(name)) throw new DOMError('Invalid custom element name', 'SyntaxError');
    if (mapHas(this.registry, name) || hasClass(Class)) throw new DOMError('The definition is already registered', 'NotSupportedError');
    if (extend !== undefined && (validName(extend) || builtinInterface(extend) === HTMLUnknownElement)) throw new DOMError('Invalid built-in extension', 'NotSupportedError');
    if (isRunning(this)) throw new DOMError('An element definition is already running', 'NotSupportedError');
    setRunning(this, true);
    let snapshot;
    try { snapshot = runDOMCallback(() => {
      const p = Class.prototype;
      if (!p || (typeof p !== 'object' && typeof p !== 'function')) throw new NativeTypeError('A constructor prototype is required');
      const callbacks = { name, Class, registry: this, observed: [] };
      for (const [key, field] of [['connectedCallback','connected'],['disconnectedCallback','disconnected'],['connectedMoveCallback','moved'],['adoptedCallback','adopted'],['attributeChangedCallback','attribute']]) {
        const callback = p[key];
        if (callback !== undefined && typeof callback !== 'function') throw new NativeTypeError('Lifecycle callbacks must be functions');
        callbacks[field] = callback;
      }
      if (callbacks.attribute) {
        callbacks.observed = stringSequence(Class.observedAttributes);
      }
      const disabled = stringSequence(Class.disabledFeatures);
      for (let i = 0; i < disabled.length; i++) {
        if (disabled[i] === 'shadow') callbacks.disableShadow = true;
        if (disabled[i] === 'internals') callbacks.disableInternals = true;
      }
      callbacks.formAssociated = !!Class.formAssociated;
      if (callbacks.formAssociated) {
        for (const name of ['formAssociatedCallback','formResetCallback','formDisabledCallback','formStateRestoreCallback']) {
          const callback = p[name];
          if (callback !== undefined && typeof callback !== 'function') throw new NativeTypeError('Lifecycle callbacks must be functions');
          callbacks[name] = callback;
        }
      }
      return callbacks;
    }); } finally { setRunning(this, false); }
    return withReactions(() => {
      // Register without a CSS query: custom-element names are not
      // necessarily valid CSS identifiers, and author selectors are mutable.
      saveClass(Class, { ownerDocument: this.ownerDocument, localName: extend ?? name, options: { is: extend === undefined ? '' : name } });
      rememberDefinition(Class, snapshot);
      mapSet(this.registry, name, { Class });
      this.active = true;
      const waiting = mapGet(this.waiting, name);
      if (waiting) {
        for (let i = 0; i < waiting.length; i++) waiting[i](Class);
        mapDelete(this.waiting, name);
        const cache = promiseMap(this);
        if (cache) mapDelete(cache, name);
      }
      upgradeCopies.tree(this.ownerDocument, this);
    });
  };
  proto.upgrade = function (root) {
    check(this); if (!isNode(root)) throw new NativeTypeError('upgrade requires a Node');
    return upgradeCopies.tree(root, this);
  };
  proto.getName = function (Class) { check(this); const definition = definitionForClass(Class); return definition?.registry === this ? definition.name : null; };
  proto.get = function (rawName) {
    check(this); if (!arguments.length) throw new NativeTypeError('get requires a name');
    return mapGet(this.registry, domString(rawName))?.Class;
  };
  proto.whenDefined = function (rawName) {
    try {
      check(this); if (!arguments.length) throw new NativeTypeError('whenDefined requires a name');
      const name = domString(rawName);
      if (!validName(name)) throw new DOMError('Invalid custom element name', 'SyntaxError');
      const definition = mapGet(this.registry, name);
      if (definition) return resolved(definition.Class);
      let cache = promiseMap(this);
      if (!cache) savePromises(this, cache = new Map());
      let promise = mapGet(cache, name);
      if (!promise) {
        promise = new NativePromise(resolve => {
          const definition = mapGet(this.registry, name);
          if (definition) resolve(definition.Class);
          else {
            let waiting = mapGet(this.waiting, name);
            if (!waiting) mapSet(this.waiting, name, waiting = []);
            waiting[waiting.length] = resolve;
          }
        });
        mapSet(cache, name, promise);
      }
      return promise;
    } catch (e) { return rejected(e); }
  };

  return (owner, identity, is = null) => withReactions(() => {
    const bare = createBareElement(owner, identity, is), definition = upgradeDefinition(bare);
    if (!definition) return bare;
    if (definition.info.options.is) { upgradeCopies([bare]); return bare; }
    try {
      const node = runDOMCallback(() => construct(definition.Class, [])), actual = nameIdentity(node);
      if (!isElement(node) || !actual || actual.namespace !== identity.namespace || actual.local !== identity.local || node[END].ownerDocument !== owner || node[PREV] || node[END][NEXT] || node[NEXT] !== node[END]) throw new DOMError('The custom-element constructor returned an element with an invalid tree or attributes', 'NotSupportedError');
      installName(node, identity, isHTML);
      return node;
    } catch (e) {
      report('constructor', e);
      const failed = createBareElement(owner, identity, null, true);
      markFailed(failed); return failed;
    }
  });
}
