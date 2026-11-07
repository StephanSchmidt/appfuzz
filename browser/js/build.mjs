import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// The pinned DOM library's native reaction sites are the reliable place
// to obtain attribute changes. Keep the DOM algorithms, while routing
// reactions through the browser guest's definition snapshots and queues.
const hooks = fileURLToPath(new URL('./src/ce-hooks.js', import.meta.url));
await build({
  entryPoints: ['src/shim.js'], bundle: true, inject: ['src/weak-map.js'],
  format: 'iife', target: 'es2023', minify: true, legalComments: 'none',
  alias: { htmlparser2: './src/alias/htmlparser2.js', 'cssomnom/parse': './src/alias/cssom.js' },
  outfile: 'dist/shim.js',
  plugins: [{ name: 'dom-reaction-ports', setup(plugin) {
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
