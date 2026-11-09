// URL attributes resolve from native ownership and content attributes. Page
// shadows of href/src, getAttribute, ownerDocument or baseURI are not inputs.
import { documentBaseURL } from './document-urls.js';
import { documentURL } from './document-state.js';
import { nodeDocument, nodeInfo } from './dom-state.js';
import { nameIdentity, lowerASCII } from './names.js';
import { collectionAttribute } from './collection-data.js';
import { attributeMethods } from './attributes.js';
import { runDOMCallback } from './dom-callbacks.js';
import { eventString } from './event-state.js';
import { withReactions } from './ce-reactions.js';
const parse = globalThis.__native.url, update = globalThis.__native.urlSet;
const define = Object.defineProperty, apply = Reflect.apply, NativeTypeError = TypeError, set = attributeMethods.setAttribute;
function requireElement(node,tag) { const id = nameIdentity(node); if (nodeInfo(node)?.kind !== 1 || id?.namespace !== 'http://www.w3.org/1999/xhtml' || id.local !== tag && !(tag === 'blockquote' && id.local === 'q')) throw new NativeTypeError('An HTML ' + tag + ' element is required'); }
function parsed(node,attribute) { const value = collectionAttribute(node,attribute); return value === null ? null : parse(value,documentBaseURL(nodeDocument(node))); }
export function reflectedURL(node,attribute,emptyDocument = false) {
  const value = collectionAttribute(node,attribute);
  if (emptyDocument && (value === null || value === '')) return documentURL(nodeDocument(node));
  if (value === null) return '';
  const url = parse(value,documentBaseURL(nodeDocument(node))); return url ? url[0] : value;
}
function write(node,attribute,value) { withReactions(() => apply(set,node,[attribute,value])); }
function field(prototype,key,descriptor) { if (descriptor.get) define(descriptor.get,'name',{ __proto__: null, value: 'get ' + key, configurable: true }); if (descriptor.set) define(descriptor.set,'name',{ __proto__: null, value: 'set ' + key, configurable: true }); define(prototype,key,descriptor); }
export function installElementURLs(L) {
  const entries = [['HTMLAnchorElement','a','href'],['HTMLAreaElement','area','href'],['HTMLScriptElement','script','src'],['HTMLImageElement','img','src'],['HTMLIFrameElement','iframe','src'],['HTMLLinkElement','link','href'],['HTMLSourceElement','source','src'],['HTMLTrackElement','track','src'],['HTMLEmbedElement','embed','src'],['HTMLObjectElement','object','data'],['HTMLVideoElement','video','src'],['HTMLAudioElement','audio','src'],['HTMLFormElement','form','action'],['HTMLInputElement','input','formAction','formaction'],['HTMLButtonElement','button','formAction','formaction'],['HTMLQuoteElement','blockquote','cite']];
  for (let i = 0; i < entries.length; i++) {
    const [name,tag,key,attribute = key] = entries[i]; if (!L[name]) continue;
    const fields = { get value() { requireElement(this,tag); return reflectedURL(this,attribute,key === 'action' || key === 'formAction'); }, set value(value) { requireElement(this,tag); value = runDOMCallback(() => eventString(value)); write(this,attribute,value); } };
    field(L[name].prototype,key,{ ...Object.getOwnPropertyDescriptor(fields,'value'), enumerable: true });
  }
  // Form and submitter methods use the declared value, including invalid-value
  // defaults; a missing submitter override remains the empty string.
  for (const [name,tag,key,attribute] of [['HTMLFormElement','form','method','method'],['HTMLInputElement','input','formMethod','formmethod'],['HTMLButtonElement','button','formMethod','formmethod']]) {
    const method = { get value() { requireElement(this,tag); const raw = collectionAttribute(this,attribute); if (raw === null && tag !== 'form') return ''; const value = lowerASCII(raw || ''); return value === 'post' || value === 'dialog' ? value : 'get'; }, set value(value) { requireElement(this,tag); value = runDOMCallback(() => eventString(value)); write(this,attribute,value); } };
    field(L[name].prototype,key,{ ...Object.getOwnPropertyDescriptor(method,'value'), enumerable: true });
  }
  const components = ['origin','protocol','username','password','host','hostname','port','pathname','search','hash'];
  for (const [name,tag] of [['HTMLAnchorElement','a'],['HTMLAreaElement','area']]) {
    for (let i = 0; i < components.length; i++) {
      const key = components[i], index = i + 1;
      field(L[name].prototype,key,{ __proto__: null, configurable: true, enumerable: true,
        get() { requireElement(this,tag); const url = parsed(this,'href'); return url ? url[index] : key === 'protocol' ? ':' : ''; },
        set: key === 'origin' ? undefined : function (value) { requireElement(this,tag); value = runDOMCallback(() => eventString(value)); const url = parsed(this,'href'); if (url) { const next = update(url[0],key,value); if (next) write(this,'href',next[0]); } },
      });
    }
    define(L[name].prototype,'toString',{ __proto__: null, configurable: true, writable: true, enumerable: true, value: function toString() { requireElement(this,tag); return reflectedURL(this,'href'); } });
  }
}
