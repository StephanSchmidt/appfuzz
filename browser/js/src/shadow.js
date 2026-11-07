import { rememberShadow, shadowInfo } from './dom-state.js';
import { nameIdentity } from './names.js';
import { validName } from './custom-name.js';
import { domString } from './registry.js';
import { elementDefinition } from './element-state.js';
import { lookupDefinition } from './upgrading.js';
import { ShadowRoot } from '../node_modules/linkedom/esm/interface/shadow-root.js';
import { shadowRoots } from '../node_modules/linkedom/esm/shared/shadow-roots.js';
const hasShadow = shadowRoots.has.bind(shadowRoots), apply = Reflect.apply;
const NativeTypeError = TypeError;

const hosts = new Set('article aside blockquote body div footer h1 h2 h3 h4 h5 h6 header main nav p section span'.split(' '));
const validHost = hosts.has.bind(hosts);
export function installShadowConstraints(Element, DOMError) {
  const attach = Element.prototype.attachShadow;
  const isElement = Object.prototype.isPrototypeOf.bind(Element.prototype);
  Object.defineProperty(ShadowRoot.prototype, 'mode', { configurable: true, enumerable: true, get() {
    const mode = shadowInfo(this)?.mode;
    if (mode === undefined) throw new NativeTypeError('Illegal shadow root receiver');
    return mode;
  } });
  Element.prototype.attachShadow = function (options) {
    if (!isElement(this)) throw new NativeTypeError('Illegal element receiver');
    if (options == null || (typeof options !== 'object' && typeof options !== 'function')) throw new NativeTypeError('Shadow options require a mode');
    const rawMode = options.mode;
    if (rawMode === undefined) throw new NativeTypeError('Shadow options require a mode');
    const mode = domString(rawMode);
    if (mode !== 'open' && mode !== 'closed') throw new NativeTypeError('Invalid shadow root mode');
    const identity = nameIdentity(this);
    if (!identity || identity.namespace !== 'http://www.w3.org/1999/xhtml' || (!validName(identity.local) && !validHost(identity.local))) throw new DOMError('This element cannot host a shadow root', 'NotSupportedError');
    const definition = elementDefinition(this) || lookupDefinition(this)?.snapshot;
    if (definition?.disableShadow) throw new DOMError('The definition disables shadow roots', 'NotSupportedError');
    if (hasShadow(this)) throw new DOMError('The element already has a shadow root', 'NotSupportedError');
    const root = apply(attach, this, [{ mode }]);
    rememberShadow(root, { host: this, mode });
    return root;
  };
}
