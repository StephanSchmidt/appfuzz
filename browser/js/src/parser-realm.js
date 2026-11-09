// This bundle runs in a separate, private QuickJS context. A page never gets
// its parser, arrays, maps, prototypes or global object. Resuming the parser
// therefore cannot call author replacements of ECMAScript intrinsics.
import { Parser } from 'parse5';

globalThis.__appfuzzParser = function (native, document, script) {
  const adapter = Object.create(null);
  for (const key of Object.keys(native)) {
    const callback = native[key];
    adapter[key] = (...args) => callback(...args);
  }
  let parser;
  const reachedScript = node => {
    if (script(node)) parser.tokenizer.pause();
  };
  // The pinned parser exposes the intended insertion parent here. Supplying
  // it at allocation time preserves template ownership and custom-element
  // construction in the right document, before attributes are installed.
  class NativeParser extends Parser {
    _createElement(name, namespace, attrs, intendedParent) {
      return adapter.createElement(name, namespace, attrs, intendedParent);
    }
  }
  adapter.onItemPop = node => {
    if (adapter.getTagName(node) === 'script' && adapter.getNamespaceURI(node) === 'http://www.w3.org/2000/svg') reachedScript(node);
  };
  parser = new NativeParser({ treeAdapter: adapter, scriptingEnabled: true }, document, null, reachedScript);
  return {
    start(markup) { parser.tokenizer.write(markup, true); return parser.tokenizer.paused; },
    resume() { parser.tokenizer.resume(); return parser.tokenizer.paused; },
  };
};
