const groups={},tests=[];let lines=[];const test=(name,run)=>tests.push({name,run});const log=(...args)=>lines.push(args.join(' '));async function runTests(){for(const {name,run}of tests){if(CASE&&name!==CASE)continue;lines=[];try{await run()}catch(e){log('ERROR',e.name,e.message)}groups[name]=lines.slice()}return groups}const attempt=fn=>{try{const v=fn();return v===undefined?'ok':v}catch(e){return e.name}};





const named=(...names)=>names.map(name=>{const n=document.createElement('b');n.id=name;return n});const ids=p=>[...p.childNodes].map(n=>n.id||n.nodeName).join(',');const records=o=>o.takeRecords().map(r=>[r.target.id||r.target.nodeName,[...r.addedNodes].map(n=>n.id||n.nodeName).join(','),[...r.removedNodes].map(n=>n.id||n.nodeName).join(','),r.previousSibling?.id||'-',r.nextSibling?.id||'-'].join('|')).join(';');const watch=p=>{const o=new MutationObserver(()=>{});o.observe(p,{childList:true,subtree:true});return o};


const restrict=policy=>{const m=document.createElement('meta');m.setAttribute('http-equiv','Content-Security-Policy');m.setAttribute('content',policy);document.head.append(m);return m};const inline=(policy,nonce=null,source='globalThis.cspHit=true')=>{restrict(policy);globalThis.cspHit=false;const s=document.createElement('script');if(nonce!==null)s.setAttribute('nonce',nonce);s.textContent=source;document.body.append(s);return cspHit};const attr=policy=>{restrict(policy);globalThis.cspHit=false;const b=document.createElement('button');b.setAttribute('onclick','globalThis.cspHit=true');document.body.append(b);b.click();return cspHit};const external=async(policy,nonce=null,integrity=null,path='/part.js')=>{restrict(policy);delete globalThis.externalPath;const s=document.createElement('script');if(nonce!==null)s.setAttribute('nonce',nonce);if(integrity!==null)s.integrity=integrity;await new Promise(resolve=>{s.onload=s.onerror=resolve;s.src=path;document.body.append(s)});return typeof externalPath==='string'};const tick=()=>new Promise(resolve=>setTimeout(resolve,20));

test('inline-none',async()=>{log(inline("script-src 'none'",null))});
test('inline-empty',async()=>{log(inline("script-src",null))});
test('inline-fallback',async()=>{log(inline("default-src 'none'",null))});
test('inline-unsafe-inline',async()=>{log(inline("script-src 'unsafe-inline'",null))});
test('inline-matching-nonce',async()=>{log(inline("script-src 'nonce-abCD'","abCD"))});
test('inline-nonce-case-mismatch',async()=>{log(inline("script-src 'nonce-abCD'","ABCD"))});
test('inline-nonce-disables-inline',async()=>{log(inline("script-src 'unsafe-inline' 'nonce-abCD'",null))});
test('inline-invalid-nonce-keeps-inline',async()=>{log(inline("script-src 'unsafe-inline' 'nonce-?'",null))});
test('inline-strict-disables-inline',async()=>{log(inline("script-src 'strict-dynamic' 'unsafe-inline'",null))});
test('inline-element-override',async()=>{log(inline("script-src 'none'; script-src-elem 'unsafe-inline'",null))});
test('inline-attribute-does-not-override-element',async()=>{log(inline("script-src 'none'; script-src-attr 'unsafe-inline'",null))});
test('inline-first-duplicate-wins',async()=>{log(inline("script-src 'unsafe-inline'; script-src 'none'",null))});
test('inline-sha256',async()=>{log(inline("script-src 'sha256-ce8Azhvw4FAiZUAaipYEWR+/5waZ4A58k+7KSgE05V4='"))});
test('inline-sha384',async()=>{log(inline("script-src 'sha384-soWlpd9RL8CRYWlZY3r8lGEL1MgO72dbTjHH4Iye4zrn7N6VWiz6+bkG7lSJRLy5'"))});
test('inline-sha512',async()=>{log(inline("script-src 'sha512-rVbhS8qhf+cu8NRNgWa85pVq0RhcpLW6kf+xCryCHzkmsSEkYoAcjSgqz9dE0IeZ2eD9HQTpu4TxIe6mnZXi6g=='"))});
test('hash-unpadded',async()=>{log(inline("script-src 'sha256-ce8Azhvw4FAiZUAaipYEWR+/5waZ4A58k+7KSgE05V4'"))});
test('hash-url-safe',async()=>{log(inline("script-src 'sha256-ce8Azhvw4FAiZUAaipYEWR-_5waZ4A58k-7KSgE05V4='"))});
test('hash-wrong',async()=>{log(inline("script-src 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='"))});
test('handler-none',async()=>{log(attr("script-src 'none'"))});
test('handler-unsafe-inline',async()=>{log(attr("script-src 'unsafe-inline'"))});
test('handler-nonce-is-not-handler',async()=>{log(attr("script-src 'nonce-abCD'"))});
test('handler-unsafe-hashes',async()=>{log(attr("script-src 'unsafe-hashes' 'sha256-ce8Azhvw4FAiZUAaipYEWR+/5waZ4A58k+7KSgE05V4='"))});
test('handler-hash-without-opt-in',async()=>{log(attr("script-src 'sha256-ce8Azhvw4FAiZUAaipYEWR+/5waZ4A58k+7KSgE05V4='"))});
test('handler-attribute-override',async()=>{log(attr("script-src 'none'; script-src-attr 'unsafe-inline'"))});
test('handler-element-is-not-handler',async()=>{log(attr("script-src 'none'; script-src-elem 'unsafe-inline'"))});
test('eval-none',async()=>{restrict("script-src 'none'");log(attempt(()=>eval('2+3')),attempt(()=>Function('return 5')()),attempt(()=>(async function(){}).constructor('return 5')),attempt(()=>(function*(){}).constructor('yield 5')))});
test('eval-unsafe-eval',async()=>{restrict("script-src 'unsafe-eval'");log(attempt(()=>eval('2+3')),attempt(()=>Function('return 5')()),attempt(()=>(async function(){}).constructor('return 5')),attempt(()=>(function*(){}).constructor('yield 5')))});
test('eval-default-none',async()=>{restrict("default-src 'none'");log(attempt(()=>eval('2+3')),attempt(()=>Function('return 5')()),attempt(()=>(async function(){}).constructor('return 5')),attempt(()=>(function*(){}).constructor('yield 5')))});
test('eval-default-eval',async()=>{restrict("default-src 'unsafe-eval'");log(attempt(()=>eval('2+3')),attempt(()=>Function('return 5')()),attempt(()=>(async function(){}).constructor('return 5')),attempt(()=>(function*(){}).constructor('yield 5')))});
test('eval-element-only',async()=>{restrict("script-src-elem 'none'");log(attempt(()=>eval('2+3')),attempt(()=>Function('return 5')()),attempt(()=>(async function(){}).constructor('return 5')),attempt(()=>(function*(){}).constructor('yield 5')))});
test('eval-attr-only',async()=>{restrict("script-src-attr 'none'");log(attempt(()=>eval('2+3')),attempt(()=>Function('return 5')()),attempt(()=>(async function(){}).constructor('return 5')),attempt(()=>(function*(){}).constructor('yield 5')))});
test('timer-blocked',async()=>{restrict("script-src 'none'");globalThis.cspHit=false;let id;log('schedule',attempt(()=>{id=setTimeout('globalThis.cspHit=true',0)}),typeof id);await tick();log('executed',cspHit)});
test('timer-allowed',async()=>{restrict("script-src 'unsafe-eval'");globalThis.cspHit=false;let id;log('schedule',attempt(()=>{id=setTimeout('globalThis.cspHit=true',0)}),typeof id);await tick();log('executed',cspHit)});
test('fetch-none',async()=>{restrict("connect-src 'none'");try{const r=await fetch('/data');log('allowed',r.status)}catch(e){log('blocked',e.name)}});
test('fetch-self',async()=>{restrict("connect-src 'self'");try{const r=await fetch('/data');log('allowed',r.status)}catch(e){log('blocked',e.name)}});
test('fetch-default-none',async()=>{restrict("default-src 'none'");try{const r=await fetch('/data');log('allowed',r.status)}catch(e){log('blocked',e.name)}});
test('fetch-overrides-default',async()=>{restrict("default-src 'none';connect-src 'self'");try{const r=await fetch('/data');log('allowed',r.status)}catch(e){log('blocked',e.name)}});
test('fetch-empty',async()=>{restrict("connect-src");try{const r=await fetch('/data');log('allowed',r.status)}catch(e){log('blocked',e.name)}});
test('fetch-first-duplicate',async()=>{restrict("connect-src 'self';connect-src 'none'");try{const r=await fetch('/data');log('allowed',r.status)}catch(e){log('blocked',e.name)}});
test('external-none',async()=>{log(await external("script-src 'none'",null))});
test('external-self',async()=>{log(await external("script-src 'self'",null))});
test('external-valid-nonce',async()=>{log(await external("script-src 'nonce-abCD'","abCD"))});
test('external-wrong-nonce',async()=>{log(await external("script-src 'nonce-abCD'","wrong"))});
test('external-strict-dynamic',async()=>{log(await external("script-src 'strict-dynamic'",null))});
test('external-element-override',async()=>{log(await external("script-src 'none';script-src-elem 'self'",null))});
test('external-hash-with-integrity',async()=>{log(await external("script-src 'sha256-rlAeVoKI4KyiVM9yulaqiFUhpZ4bLGOW6/hDW+dRyl0='",null,"sha256-rlAeVoKI4KyiVM9yulaqiFUhpZ4bLGOW6/hDW+dRyl0="))});
test('external-hash-needs-integrity',async()=>{log(await external("script-src 'sha256-rlAeVoKI4KyiVM9yulaqiFUhpZ4bLGOW6/hDW+dRyl0='",null,null))});
test('external-nonce-does-not-skip-sri',async()=>{log(await external("script-src 'nonce-abCD'","abCD","sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))});
test('violation-event-constructor',async()=>{const e=new SecurityPolicyViolationEvent('v',{effectiveDirective:'x',violatedDirective:'y',statusCode:65537,lineNumber:-1});log(e instanceof Event,e.effectiveDirective,e.violatedDirective,e.disposition,e.statusCode,e.lineNumber);log(attempt(()=>new SecurityPolicyViolationEvent('v',{disposition:'invalid'})))});
test('violation-inline-event',async()=>{const rows=[];document.addEventListener('securitypolicyviolation',e=>{if(e.effectiveDirective==='script-src-elem')rows.push([e instanceof SecurityPolicyViolationEvent,e.blockedURI,e.effectiveDirective,e.violatedDirective,e.disposition,e.bubbles,e.composed,e.cancelable,e.isTrusted,e.statusCode].join(' '))});restrict("script-src 'none'");const s=document.createElement('script');s.textContent='globalThis.cspHit=true';document.body.append(s);await tick();log(rows.join(';'))});
test('violation-fetch-event',async()=>{const rows=[];document.addEventListener('securitypolicyviolation',e=>{if(e.effectiveDirective==='connect-src')rows.push([e.blockedURI.endsWith('/data'),e.effectiveDirective,e.disposition,e.statusCode].join(' '))});restrict("connect-src 'none'");try{await fetch('/data')}catch{}await tick();log(rows.join(';'))});
test('violation-sample',async()=>{const rows=[];document.addEventListener('securitypolicyviolation',e=>{if(e.effectiveDirective==='script-src-elem')rows.push(e.sample)});restrict("script-src 'report-sample'");const s=document.createElement('script');s.textContent='globalThis.cspHit=true';document.body.append(s);await tick();log(rows.join(';'))});
test('function-conversion-order',async()=>{restrict("script-src 'none'");const rows=[];log(attempt(()=>Function({toString(){rows.push('parameter');return 'a'}},{toString(){rows.push('body');return 'return a'}})),rows.join(','))});
test('eval-non-string-does-not-compile',async()=>{restrict("script-src 'none'");const value={toString(){throw new Error('coercion')}};log(eval(value)===value)});
test('violation-dictionary-order',async()=>{const rows=[],o={};for(const key of ['blockedURI','bubbles','cancelable','columnNumber','composed','disposition','documentURI','effectiveDirective','lineNumber','originalPolicy','referrer','sample','sourceFile','statusCode','violatedDirective'])Object.defineProperty(o,key,{get(){rows.push(key);return undefined}});new SecurityPolicyViolationEvent('x',o);log(rows.join(','))});
test('timer-policy-is-captured-at-scheduling',async()=>{restrict("script-src 'unsafe-eval'");globalThis.cspHit=false;setTimeout('globalThis.cspHit=true',0);restrict("script-src 'none'");await tick();log(cspHit)});
test('nonce-property-after-connection',async()=>{const s=document.createElement('script');s.nonce='abCD';s.textContent='void 0';restrict("script-src 'nonce-abCD'");document.body.append(s);log(s.nonce,s.getAttribute('nonce'),s.cloneNode().nonce)});
test('direct-eval-retains-lexical-bindings',async()=>{function run(){const lexicalValue=23;return eval('lexicalValue')}log(attempt(run))});
test('direct-eval-can-change-its-local-binding',async()=>{function run(){let localCounter=1;eval('localCounter=3');return localCounter}log(run())});
test('module-external-nonce-inherits',async()=>{restrict("script-src 'nonce-abCD'");delete globalThis.modulePath;delete globalThis.dependencyPath;const n=document.createElement('script');n.type='module';n.nonce='abCD';n.src='/part.mjs';await new Promise(resolve=>{n.onload=n.onerror=resolve;document.body.append(n)});log(typeof modulePath==='string',typeof dependencyPath==='string')});
test('module-inline-nonce-inherits',async()=>{restrict("script-src 'nonce-abCD'");delete globalThis.modulePath;delete globalThis.dependencyPath;const n=document.createElement('script');n.type='module';n.nonce='abCD';n.textContent="import './dep.mjs';globalThis.modulePath='inline'";document.body.append(n);for(let i=0;i<20&&typeof modulePath!=='string';i++)await tick();log(typeof modulePath==='string',typeof dependencyPath==='string')});
test('module-strict-dynamic-inherits',async()=>{restrict("script-src 'strict-dynamic'");delete globalThis.modulePath;delete globalThis.dependencyPath;const n=document.createElement('script');n.type='module';n.src='/part.mjs';await new Promise(resolve=>{n.onload=n.onerror=resolve;document.body.append(n)});log(typeof modulePath==='string',typeof dependencyPath==='string')});
test('nonce-idl-does-not-reflect',async()=>{const n=document.createElement('script');n.nonce='abCD';log(n.nonce,n.getAttribute('nonce')===null,n.cloneNode().nonce)});
test('nonce-content-change-after-connection',async()=>{const n=document.createElement('script');n.setAttribute('nonce','first');document.body.append(n);n.setAttribute('nonce','second');log(n.nonce,n.getAttribute('nonce'));n.remove();document.body.append(n);log(n.nonce,n.getAttribute('nonce'))});
test('function-keeps-lone-surrogate-source',async()=>{const n=Function("return '"+String.fromCharCode(0xd800)+"'");log(n().charCodeAt(0))});
test('hash-source-replaces-lone-surrogate',async()=>{restrict("script-src 'sha256-QBGbsezuDBdev3Tf0uGGa+2pqEOMW52nxzOnohsONEY='");globalThis.cspHit=null;const n=document.createElement('script');n.textContent="globalThis.cspHit='"+String.fromCharCode(0xd800)+"'";document.body.append(n);log(cspHit===null?null:cspHit.charCodeAt(0))});
test('base-has-no-default-source-fallback',async()=>{restrict("default-src 'none'");const b=document.createElement('base');b.href='/nested/';document.head.append(b);log(new URL(document.baseURI).pathname)});
test('report-only-script-still-runs',async()=>{const rows=[];document.addEventListener('securitypolicyviolation',e=>{if(e.disposition==='report'&&e.sample==='globalThis.cspHit=true')rows.push(e.effectiveDirective)});globalThis.cspHit=false;const n=document.createElement('script');n.textContent='globalThis.cspHit=true';document.body.append(n);await tick();log(cspHit,rows.join(','))});
test('report-only-fetch-still-connects',async()=>{const rows=[];document.addEventListener('securitypolicyviolation',e=>{if(e.effectiveDirective==='connect-src')rows.push(e.disposition)});const r=await fetch('/data');await tick();log(r.status,rows.join(','))});
test('report-only-eval-still-compiles',async()=>{const rows=[];document.addEventListener('securitypolicyviolation',e=>{if(e.blockedURI==='eval')rows.push(e.disposition)});log(eval('2+3'));await tick();log(rows.join(','))});
