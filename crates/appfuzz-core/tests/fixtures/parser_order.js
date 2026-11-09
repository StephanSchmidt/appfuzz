const groups={},tests=[];let lines=[];const test=(name,run)=>tests.push({name,run});const log=(...args)=>lines.push(args.join(' '));async function runTests(){for(const {name,run}of tests){if(CASE&&name!==CASE)continue;lines=[];try{await run()}catch(e){log('ERROR',e.name,e.message)}groups[name]=lines.slice()}return groups}const attempt=fn=>{try{const v=fn();return v===undefined?'ok':v}catch(e){return e.name}};


const meta=(policy="base-uri 'none'",parent=document.head)=>{const m=document.createElement('meta');m.setAttribute('http-equiv','Content-Security-Policy');m.setAttribute('content',policy);if(parent)parent.append(m);return m};
const base=(href='/nested/',parent=document.head)=>{const b=document.createElement('base');b.href=href;if(parent)parent.append(b);return b};
const path=()=>new URL(document.baseURI).pathname;
const probe=(policy,href)=>{const b=base(href,null);meta(policy);document.head.append(b);log(path());b.remove()};

test('parser-policy-after-script',()=>{log('before',globalThis.beforePolicy,'after',new URL(document.baseURI).pathname)});
test('head-blocking-visibility',()=>{log(globalThis.headVisibility)});
test('blocking-script-and-microtask',()=>{log(globalThis.visibility)});
test('removed-open-ancestor',()=>{log(globalThis.keptHost.querySelector('b')?.textContent,document.querySelector('#late')===null)});
test('native-parser-intrinsics',()=>{log(globalThis.nativeCalls)});
test('native-parser-methods',()=>{log(globalThis.nativeCalls)});
test('deferred-script-base-preparation',async()=>{if(document.readyState==='loading')await new Promise(resolve=>document.addEventListener('DOMContentLoaded',resolve,{once:true}));log(globalThis.externalPath)});
test('inline-module-base-preparation',async()=>{if(document.readyState==='loading')await new Promise(resolve=>document.addEventListener('DOMContentLoaded',resolve,{once:true}));log(globalThis.inlineModuleBase)});
test('svg-parser-script',()=>{log(globalThis.svgParserRan===true)});
test('parser-custom-element-timing',()=>{log(globalThis.customTiming)});
test('parser-template-isolation',()=>{log(globalThis.inertScriptRan===true,document.querySelector('template').content.querySelector('b').ownerDocument===document)});
test('native-parser-table-fostering',()=>{log(document.querySelector('table').previousSibling.textContent,document.querySelector('tbody td').textContent)});

test('native-parser-private-node-metadata',()=>{log(globalThis.nativeCalls,document.querySelector('#native-after').textContent)});
test('native-parser-string-intrinsics',()=>{log(globalThis.nativeCalls)});
test('parser-head-body-descriptors',()=>{log(Object.hasOwn(document,'head'),Object.hasOwn(document,'body'))});

test('svg-owner-live',()=>{const a=document.createElementNS('http://www.w3.org/2000/svg','svg'),b=document.createElementNS('http://www.w3.org/2000/svg','svg'),g=document.createElementNS('http://www.w3.org/2000/svg','g');document.body.append(a,b);a.append(g);log(g.ownerSVGElement===a,Object.hasOwn(g,'ownerSVGElement'));b.append(g);log(g.ownerSVGElement===b);g.remove();log(g.ownerSVGElement===null)});
test('svg-owner-private-parent',()=>{const a=document.createElementNS('http://www.w3.org/2000/svg','svg'),g=document.createElementNS('http://www.w3.org/2000/svg','g');a.append(g);let calls=0;Object.defineProperty(g,'parentNode',{get(){calls++;return null}});Object.defineProperty(a,'localName',{get(){calls++;return 'not-svg'}});log(g.ownerSVGElement===a,calls)});
