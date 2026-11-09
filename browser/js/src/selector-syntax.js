// CSS component values preserve native EOF recovery, decoded function names
// and bad-token boundaries before the strict selector parser sees the input.
import { parse } from 'css-what';
import { selectorError, expectedSelectorError } from './selector-intrinsics.js';
import { backendList } from './collection-data.js';
const components = globalThis.__native.cssComponents, NativeError = selectorError, NativeRangeError = RangeError;
const limits = new WeakSet(), saveLimit = limits.add.bind(limits);
export const isSelectorLimit = limits.has.bind(limits);
let report = () => {};
export function installSyntaxReporter(callback) { report = callback; }
export function forgivingSyntax(text) {
  const data = components(text);
  if (data.limited) { report('selector:CSS nesting depth'); const error = new NativeRangeError('CSS nesting exceeds the supported depth'); saveLimit(error); throw error; }
  const tokens = data.tokens, children = backendList(), values = backendList();
  for (let i = 0; i < tokens.length; i++) { children[i] = backendList(); if (i) { const list = children[tokens[i][1]]; list[list.length] = i; } }
  for (let i = tokens.length - 1; i >= 0; i--) {
    const token = tokens[i], list = children[i];
    if (token[0] === 'token' || token[0] === 'comma' || token[0] === 'comment') { values[i] = { __proto__: null, text: token[0] === 'comment' ? '' : token[2], bad: token[5] === true }; continue; }
    const forgiving = token[0] === 'function' && (token[4] === 'is' || token[4] === 'where');
    let content = '', bad = false, invalidValue = false; const valid = backendList();
    const branch = () => { if (!bad) { try { if (parse(content).length) valid[valid.length] = content; } catch (error) { if (!expectedSelectorError(error)) throw error; } } content = ''; bad = false; };
    for (let j = 0; j < list.length; j++) {
      const child = list[j];
      if (forgiving && tokens[child][4] === true) invalidValue = true;
      if (forgiving && tokens[child][0] === 'comma') branch();
      else { content += values[child].text; bad = bad || values[child].bad; }
    }
    if (forgiving) { branch(); values[i] = { __proto__: null, text: valid.length ? token[2] + valid.join(',') + token[3] : 'not(*)', bad: token[5] === true || invalidValue }; }
    else values[i] = { __proto__: null, text: token[2] + content + token[3], bad: bad || token[5] === true };
  }
  if (values[0].bad) throw new NativeError('Invalid CSS token');
  return values[0].text;
}
