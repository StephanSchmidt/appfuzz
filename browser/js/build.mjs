import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// The pinned DOM library's native reaction sites are the reliable place
// to obtain attribute changes. Keep the DOM algorithms, while routing
// reactions through the browser guest's definition snapshots and queues.
const eventState = fileURLToPath(new URL('./src/event-state.js', import.meta.url));
const replace = (source, before, after) => {
  if (!source.includes(before)) throw new Error('The pinned DOM event sites changed: ' + before);
  return source.replace(before, after);
};
const hooks = fileURLToPath(new URL('./src/ce-hooks.js', import.meta.url));
await build({
  entryPoints: ['src/shim.js'], bundle: true, inject: ['src/weak-map.js'],
  format: 'iife', target: 'es2023', minify: true, legalComments: 'none',
  alias: { htmlparser2: './src/alias/htmlparser2.js', 'cssomnom/parse': './src/alias/cssom.js' },
  outfile: 'dist/shim.js',
  plugins: [{ name: 'dom-internals', setup(plugin) {
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event\.js$/ }, async ({ path }) => {
      let source = await readFile(path, 'utf8');
      source = replace(source, 'this.cancelable = !!eventInitDict.cancelable;', 'initializeEvent(this, !!eventInitDict.cancelable);');
      source = replace(source, 'this.timeStamp = Date.now();', '');
      source = replace(source, 'this.defaultPrevented = false;', '');
      source = replace(source, 'this.returnValue = null;', '');
      source = replace(source, 'this.eventPhase = this.NONE;', 'this.eventPhase = NONE;');
      source = replace(source, 'preventDefault() { this.defaultPrevented = true; }', `get timeStamp() { return eventTimeStamp(this); }
    get cancelable() { return eventCancelable(this); }
    get defaultPrevented() { return eventCanceled(this); }
    get returnValue() { return !eventCanceled(this); }
    set returnValue(value) { if (!value) cancelEvent(this); }
    preventDefault() { cancelEvent(this); }`);
      return { contents: `import {initializeEvent, eventTimeStamp, eventCancelable, eventCanceled, cancelEvent} from ${JSON.stringify(eventState)};\n` + source, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event-target\.js$/ }, async ({ path }) => {
      let source = await readFile(path, 'utf8');
      source = replace(source, 'dispatchEvent(event) {', 'dispatchEvent(event) { assertEvent(event);');
      source = replace(source, 'return !event.defaultPrevented;', 'return !eventCanceled(event);');
      source = replace(source, 'this.eventPhase = this.AT_TARGET;', 'this.eventPhase = 2;');
      source = replace(source, 'this.eventPhase = this.BUBBLING_PHASE;', 'this.eventPhase = 3;');
      source = replace(source, 'event.eventPhase = event.CAPTURING_PHASE;', 'event.eventPhase = 1;');
      source = replace(source, 'event.eventPhase = event.NONE;', 'event.eventPhase = 0;');
      return { contents: `import {assertEvent, eventCanceled} from ${JSON.stringify(eventState)};\n` + source, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]custom-element-registry\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      const start = source.indexOf('export const attributeChangedCallback =');
      const end = source.indexOf('/**\n * @implements globalThis.CustomElementRegistry', start);
      if (start < 0 || end < 0) throw new Error('The pinned DOM reaction sites changed');
      const ports = `export const attributeChangedCallback = attributeReaction;\nexport const connectedCallback = element => connectionReaction(element, true);\nexport const disconnectedCallback = element => connectionReaction(element, false);\n\n`;
      return { contents: `import {attributeReaction, connectionReaction} from ${JSON.stringify(hooks)};\n` + source.slice(0, start) + ports + source.slice(end), loader: 'js' };
    });
  } }],
});
