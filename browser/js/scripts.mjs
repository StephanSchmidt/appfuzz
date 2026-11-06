// An app's static scripts, for a snapshot that holds them compiled:
// node scripts.mjs session.json > scripts.json
// Scripts the page loads with <script src> (no type=module) are classic;
// every other .js file is a module (an entry or a chunk it imports).
import { readFileSync } from 'node:fs';

const s = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const base = new URL(s.url);
const classic = new Set();
for (const m of s.html.matchAll(/<script\b([^>]*)>/gi)) {
  const attrs = m[1];
  const src = /\bsrc\s*=\s*["']?([^"'\s>]+)/i.exec(attrs);
  if (src && !/\btype\s*=\s*["']?module/i.test(attrs)) classic.add(new URL(src[1], base).pathname);
}
const out = { modules: {}, classic: {} };
for (const [path, code] of Object.entries(s.files)) {
  if (!/\.m?js$/.test(path)) continue;
  out[classic.has(path) ? 'classic' : 'modules'][new URL(path, base).href] = code;
}
process.stdout.write(JSON.stringify(out));
