// Exercise source-transform semantics with real objects, side effects and
// frozen wrappers. This protects the build-time boundary, not a text snapshot.
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { privateDOMSlots } from './private-dom-slots.mjs';
const symbols = new URL('./node_modules/linkedom/esm/shared/symbols.js',import.meta.url).href;
let serial = 0;
async function module(body) {
  const source = `import {NEXT,PREV,END,VALUE} from ${JSON.stringify(symbols)};\n${body}`;
  const output = privateDOMSlots(source).replace(/from "(\/[^\"]*)"/g,(_match,path)=>'from '+JSON.stringify(pathToFileURL(path).href));
  return import('data:text/javascript;base64,' + Buffer.from(output + '\n//' + serial++).toString('base64'));
}
test('frozen wrapper lvalues preserve chained assignments and evaluation order',async () => {
  const m = await module(`const events=[],a=Object.freeze({}),b=Object.freeze({});let reads=0;function receiver(){events.push('receiver');reads++;return a}function value(){events.push('value');return 2}receiver()[NEXT]=b[PREV]=value();a[NEXT]+=3;export const result=[a[NEXT],b[PREV],reads,events,Object.getOwnPropertySymbols(a).length];`);
  assert.deepEqual(m.result,[5,2,1,['receiver','value'],0]);
});
test('object literals and mixed destructuring preserve getters and mutable parameters',async () => {
  const m = await module(`const events=[],a={[NEXT]:2,[END]:7,get value(){events.push(this===a);return 4}};function edit({[NEXT]:next,value},suffix){next++;return [next,value,suffix]}const {[END]:end,value}=a;export const result=[edit(a,9),end,value,events,Object.getOwnPropertySymbols(a).length];`);
  assert.deepEqual(m.result,[[3,4,9],7,4,[true,true],0]);
});
test('nested links and optional reads distinguish null from a missing slot',async () => {
  const m = await module(`const a={},b={};a[NEXT]=b;b[PREV]=a;const nil=null;export const result=[a[NEXT][PREV]===a,nil?.[END],a?.[END],a[NEXT]?.[PREV]===a];`);
  assert.deepEqual(m.result,[true,undefined,undefined,true]);
});
test('author symbols stay ordinary and private reads ignore prototype hooks',async () => {
  const m = await module(`let calls=0;const authored=Symbol('next'),a={[authored]:'author'};Object.defineProperty(Object.prototype,NEXT,{configurable:true,get(){calls++;return 99},set(){calls++}});let result;try{a[NEXT]=2;Object.freeze(a);a[NEXT]=3;result=[a[NEXT],a[authored],Object.getOwnPropertySymbols(a)[0]===authored,calls]}finally{delete Object.prototype[NEXT]}export {result};`);
  assert.deepEqual(m.result,[3,'author',true,0]);
});
test('private object transfer ignores author array iteration and reflection helpers',async () => {
  const m = await module(`export function run(){let calls=0;const iter=Array.prototype[Symbol.iterator],own=Reflect.ownKeys,get=Object.getOwnPropertyDescriptor;Array.prototype[Symbol.iterator]=function(){calls++;throw Error('page iterator')};Reflect.ownKeys=Object.getOwnPropertyDescriptor=()=>{calls++;throw Error('page reflection')};try{const a={[NEXT]:3};return [a[NEXT],calls]}finally{Array.prototype[Symbol.iterator]=iter;Reflect.ownKeys=own;Object.getOwnPropertyDescriptor=get}}`);
  assert.deepEqual(m.run(),[3,0]);
});
test('new unsupported backend syntax fails the build instead of changing semantics',() => {
  const source=body=>`import {NEXT,PREV} from './shared/symbols.js';${body}`;
  assert.throws(()=>privateDOMSlots(source('let value=a?.[NEXT][PREV]')),/nested optional/);
  assert.throws(()=>privateDOMSlots(source('a[NEXT]()')),/method call/);
  assert.throws(()=>privateDOMSlots(source('class X{get [NEXT](){return this}}')),/prototype method/);
});
