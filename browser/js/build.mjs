import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// The pinned DOM library's native reaction sites are the reliable place
// to obtain attribute changes. Keep the DOM algorithms, while routing
// reactions through the browser guest's definition snapshots and queues.
const eventTarget = fileURLToPath(new URL('./src/event-target.js', import.meta.url));
const domState = fileURLToPath(new URL('./src/dom-state.js', import.meta.url));
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
      const source = await readFile(path, 'utf8');
      if (!source.includes('class GlobalEvent')) throw new Error('The pinned DOM Event changed');
      return { contents: `export {Event} from ${JSON.stringify(eventState)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]custom-event\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes('class CustomEvent extends Event')) throw new Error('The pinned DOM CustomEvent changed');
      return { contents: `export {CustomEvent} from ${JSON.stringify(eventState)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]event-target\.js$/ }, async ({ path }) => {
      const source = await readFile(path, 'utf8');
      if (!source.includes('class DOMEventTarget')) throw new Error('The pinned DOM EventTarget changed');
      return { contents: `export {EventTarget} from ${JSON.stringify(eventTarget)};`, loader: 'js' };
    });
    plugin.onLoad({ filter: /[/\\]linkedom[/\\]esm[/\\]interface[/\\]node\.js$/ }, async ({ path }) => {
      const source = replace(await readFile(path, 'utf8'), 'this.nodeType = nodeType;', 'this.nodeType = nodeType; initializeNode(this, nodeType, localName);');
      return { contents: `import {initializeNode} from ${JSON.stringify(domState)};\n` + source, loader: 'js' };
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
