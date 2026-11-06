// Turns a built page (a directory with index.html and its assets) into a
// session input: node session.mjs <dir> [responses.json] > session.json
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const [dir, responses] = process.argv.slice(2);
if (!dir) {
  console.error('usage: node session.mjs <dir> [responses.json]');
  process.exit(2);
}
const files = {};
const walk = (d) => {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(m?js|css|json|html)$/.test(name)) files['/' + relative(dir, p).split('\\').join('/')] = readFileSync(p, 'utf8');
  }
};
walk(dir);
const html = files['/index.html'];
const session = {
  url: 'https://app.example/',
  html,
  files,
  responses: responses ? JSON.parse(readFileSync(responses, 'utf8')) : {},
  now: Date.UTC(2026, 10, 2, 10),
  seed: 1,
};
process.stdout.write(JSON.stringify(session));
