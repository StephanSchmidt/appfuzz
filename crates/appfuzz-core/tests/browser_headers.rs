use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(html: &str) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    (run, report)
}

fn logs(report: &Value) -> Vec<&str> {
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect()
}

#[test]
fn invalid_header_names_values_and_non_byte_strings_are_rejected_and_ows_is_trimmed() {
    let (_, report) = visit(
        r#"<script>
for(const [label,pairs]of[['spaces',[['bad name','x']]],['newline',[['x','a\nb']]],['nul',[['x','a\0b']]],['unicode',[['x',String.fromCharCode(256)]]],['trim',[['X',' \tyes\t ']]]])try{const h=new Headers(pairs);console.log(label,h.get('x'))}catch(e){console.log(label,e.name)}
</script>"#,
    );
    assert_eq!(logs(&report), ["spaces TypeError", "newline TypeError", "nul TypeError", "unicode TypeError", "trim yes"]);
}

#[test]
fn request_headers_filter_forbidden_names_during_construction_and_mutation() {
    let (_, report) = visit(
        r#"<script>
const h=new Headers({'Cookie':'secret','Host':'evil.example','Content-Length':'99','X-Data':'allowed','Referer':'https://evil.example/'}),r=new Request('/missing.js',{headers:h});for(const key of ['cookie','host','content-length','x-data','referer'])console.log(key,r.headers.get(key));r.headers.set('Host','evil.example');r.headers.set('Cookie','secret');console.log('after',r.headers.get('host'),r.headers.get('cookie'));
</script>"#,
    );
    assert_eq!(logs(&report), ["cookie null", "host null", "content-length null", "x-data allowed", "referer null", "after null null"]);
}

#[test]
fn header_sequence_conversion_reads_the_iterator_getter_once() {
    let (_, report) = visit(
        r#"<script>
let reads=0;const pairs={get[Symbol.iterator](){reads++;return function*(){yield ['x','y']}}};const h=new Headers(pairs);console.log(reads,h.get('x'));
</script>"#,
    );
    assert_eq!(logs(&report), ["1 y"]);
}

#[test]
fn headers_foreach_visits_the_live_sorted_header_list() {
    let (_, report) = visit(
        r#"<script>
const h=new Headers([['b','2'],['d','4']]),seen=[];h.forEach((value,key)=>{seen.push(key);if(key==='b')h.append('c','3')});console.log(seen.join('/'));
</script>"#,
    );
    assert_eq!(logs(&report), ["b/c/d"]);
}

#[test]
fn fetched_response_headers_are_immutable() {
    let (_, report) = visit(
        r#"<script>
fetch('/missing.js').then(response=>{for(const name of ['append','set','delete'])try{response.headers[name]('x','mutable');console.log('unexpected')}catch(e){console.log(name,e.name)}});
</script>"#,
    );
    assert_eq!(logs(&report), ["append TypeError", "set TypeError", "delete TypeError"]);
}

#[test]
fn constructed_response_headers_do_not_expose_set_cookie() {
    let (_, report) = visit(
        r#"<script>
const response=new Response('',{headers:{'set-cookie':'session=value'}});console.log(response.headers.get('set-cookie'),response.headers.getSetCookie().length);
</script>"#,
    );
    assert_eq!(logs(&report), ["null 0"]);
}

#[test]
fn set_cookie_values_remain_separate_during_iteration_and_set_delete() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const h=new Headers([['Set-Cookie','a=1'],['X','one'],['set-cookie','b=2'],['X','two']]);log('cookies',h.get('set-cookie'),h.getSetCookie().join('/'),JSON.stringify([...h]));h.set('set-cookie','c=3');log('set-cookie',h.getSetCookie().join('/'));h.delete('SET-cookie');log('delete-cookie',h.getSetCookie().length);
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["cookies a=1, b=2 a=1/b=2 [[\"set-cookie\",\"a=1\"],[\"set-cookie\",\"b=2\"],[\"x\",\"one, two\"]]", "set-cookie c=3", "delete-cookie 0"]
    );
}

#[test]
fn headers_init_and_methods_validate_types_required_arguments_and_names() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
for(const [label,value]of[['null',null],['undefined',undefined],['iterator-null',{[Symbol.iterator]:null}],['iterator-bad',{[Symbol.iterator]:1}]])try{log('init',label,JSON.stringify([...new Headers(value)]))}catch(e){log('init',label,e.name)}
const h=new Headers();for(const method of ['get','has','delete','set','append']){try{h[method]();log('unexpected-required')}catch(e){log('required',method,e.name)}try{h[method]('bad name','x');log('unexpected-name')}catch(e){log('invalid',method,e.name)}}
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "init null TypeError",
            "init undefined []",
            "init iterator-null TypeError",
            "init iterator-bad TypeError",
            "required get TypeError",
            "invalid get TypeError",
            "required has TypeError",
            "invalid has TypeError",
            "required delete TypeError",
            "invalid delete TypeError",
            "required set TypeError",
            "invalid set TypeError",
            "required append TypeError",
            "invalid append TypeError"
        ]
    );
}

#[test]
fn header_iterators_track_mutation_and_can_resume_when_headers_are_added() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const state=record=>record.done?'done':record.value.join(':');const h=new Headers([['a','1'],['c','3']]),it=h.entries();log('iter-first',state(it.next()));h.append('b','2');log('iter-second',state(it.next()));h.delete('c');log('iter-end',state(it.next()));h.append('d','4');log('iter-still-end',state(it.next()));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["iter-first a:1", "iter-second b:2", "iter-end done", "iter-still-end d:4"]);
}

#[test]
fn no_cors_headers_apply_safelists_to_initial_and_combined_values() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const r=new Request('/missing.js',{method:'POST',mode:'no-cors',headers:{'Accept':'text/plain','Accept-Language':'en-US','Content-Type':'application/json','Range':'bytes=0-1','X-Private':'secret'}});log('no-cors',JSON.stringify([...r.headers]));r.headers.set('Content-Type','text/plain');r.headers.append('Accept','text/html');log('no-cors-change',r.headers.get('content-type'),r.headers.get('accept'));r.headers.set('Accept-Language','x'.repeat(129));log('too-long',r.headers.get('accept-language'));
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["no-cors [[\"accept\",\"text/plain\"],[\"accept-language\",\"en-US\"]]", "no-cors-change text/plain text/plain, text/html", "too-long en-US"]
    );
}

#[test]
fn forbidden_method_override_values_are_filtered_without_rejecting_quoted_values() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
for(const value of ['TRACE','GET','POST, TRACE','"TRACE"','trace']){const r=new Request('/missing.js',{headers:{'X-HTTP-Method-Override':value}});log('method-override',value,r.headers.get('x-http-method-override'))}
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "method-override TRACE null",
            "method-override GET GET",
            "method-override POST, TRACE null",
            "method-override \"TRACE\" \"TRACE\"",
            "method-override trace null"
        ]
    );
}

#[test]
fn request_and_response_clones_preserve_guards_while_detached_headers_are_mutable() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const r=new Request('/missing.js',{headers:{'Sec-Secret':'x','Proxy-Secret':'x','X-Data':'yes'}}),clone=r.clone();clone.headers.set('Host','evil.example');log('request-clone',clone.headers.get('host'),clone.headers.get('x-data'));const response=await fetch('/missing.js'),copy=response.clone();try{copy.headers.set('x','mutable');log('unexpected-mutable')}catch(e){log('response-clone',e.name)}const detached=new Headers(response.headers);detached.set('x','allowed');log('detached',detached.get('x'));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["request-clone null yes", "response-clone TypeError", "detached allowed"]);
}

#[test]
fn header_argument_conversion_runs_before_guard_and_format_validation() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const r=await fetch('/missing.js');for(const name of ['append','set'])try{r.headers[name]('bad name',{toString(){log('value-before-guard',name);return 'x'}})}catch(e){log('guard-error',name,e.name)}try{r.headers.delete('bad name')}catch(e){log('delete-error',e.name)}
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["value-before-guard append", "guard-error append TypeError", "value-before-guard set", "guard-error set TypeError", "delete-error TypeError"]
    );
}

#[test]
fn all_header_init_values_convert_before_header_list_validation() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const order=[];try{new Headers([['bad name','x'],['x',{toString(){order.push('converted-later');return 'y'}}]])}catch(e){log('conversion-order',order.join('/'),e.name)}const symbol=Symbol('header');try{new Headers({[symbol]:'value'})}catch(e){log('symbol-key',e.name)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["conversion-order converted-later TypeError", "symbol-key TypeError"]);
}

#[test]
fn no_cors_header_byte_and_combined_length_boundaries_are_enforced() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
for(const [name,values]of[['accept',['x'.repeat(128),'x'.repeat(129),'text/plain(','text/plain']],['accept-language',['en-US','en_US','a'.repeat(129)]],['content-type',['text/plain; charset=utf-8','text/plain, application/json','text/plain;charset="utf-8"','application/x-www-form-urlencoded','multipart/form-data; boundary=x']]])for(const value of values){const h=new Request('/missing.js',{mode:'no-cors',headers:{[name]:value}}).headers;log('safe',name,value.length,h.has(name))}const r=new Request('/missing.js',{mode:'no-cors',headers:{accept:'x'.repeat(127)}});r.headers.append('accept','a');log('combined-boundary',r.headers.get('accept').length);r.headers.delete('accept');log('delete-safe',r.headers.has('accept'));
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "safe accept 128 true",
            "safe accept 129 false",
            "safe accept 11 false",
            "safe accept 10 true",
            "safe accept-language 5 true",
            "safe accept-language 5 false",
            "safe accept-language 129 false",
            "safe content-type 25 true",
            "safe content-type 28 false",
            "safe content-type 26 false",
            "safe content-type 33 true",
            "safe content-type 31 true",
            "combined-boundary 127",
            "delete-safe false"
        ]
    );
}

#[test]
fn set_cookie_arrays_are_copies_and_response_mutations_filter_cookie_headers() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const h=new Headers([['set-cookie','a=1'],['set-cookie','b=2']]),copy=h.getSetCookie();copy[0]='changed';log('cookie-copy',h.getSetCookie().join('/'));const r=new Response('',{headers:h});r.headers.append('set-cookie','c=3');log('response-cookie',r.headers.get('set-cookie'),r.headers.getSetCookie().length);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["cookie-copy a=1/b=2", "response-cookie null 0"]);
}

#[test]
fn body_types_supply_content_type_and_response_json_preserves_custom_headers() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
for(const [label,body]of[['text','hello'],['form',new URLSearchParams({x:'y'})],['blob',new Blob(['hello'],{type:'text/custom'})]]){const r=new Request('/missing.js',{method:'POST',body});log('body-type',label,r.headers.get('content-type'))}const r=Response.json({ok:true},{headers:{'x-custom':'yes','content-type':'text/custom'}});log('json-headers',r.headers.get('x-custom'),r.headers.get('content-type'));
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "body-type text text/plain;charset=UTF-8",
            "body-type form application/x-www-form-urlencoded;charset=UTF-8",
            "body-type blob text/custom",
            "json-headers yes text/custom"
        ]
    );
}

#[test]
fn multipart_bodies_use_matching_boundaries_and_escape_names_and_filenames() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const form=new FormData();form.append('name','a\nb');form.append('quote"field','v');form.append('file',new Blob(['file-text'],{type:'text/custom'}),'name"file.txt');const r=new Request('/missing.js',{method:'POST',body:form}),type=r.headers.get('content-type'),boundary=type.split('boundary=')[1],text=await r.text();log('multipart',type.startsWith('multipart/form-data; boundary='),text.startsWith('--'+boundary+'\r\n'),text.endsWith('--'+boundary+'--\r\n'),text.includes('name="name"\r\n\r\na\r\nb\r\n'),text.includes('name="quote%22field"'),text.includes('filename="name%22file.txt"'),text.includes('Content-Type: text/custom\r\n\r\nfile-text'));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["multipart true true true true true true true"]);
}

#[test]
fn body_extraction_ignores_public_blob_metadata_and_form_iterators() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const b=new Blob(['data'],{type:'TEXT/CUSTOM'});Object.defineProperty(b,'type',{get(){log('unexpected-type');return 'text/fake'}});Object.defineProperty(b,'_text',{value:'fake'});const r=new Request('/missing.js',{method:'POST',body:b});log('private-blob',r.headers.get('content-type'),await r.text());const f=new FormData();f.append('name','real');f[Symbol.iterator]=()=>{throw Error('public iterator')};f._l=[['name','fake']];const copy=new Request('/missing.js',{method:'POST',body:f});log('private-form',copy.headers.get('content-type').startsWith('multipart/form-data; boundary='),(await copy.text()).includes('\r\n\r\nreal\r\n'));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["private-blob text/custom data", "private-form true true"]);
}

#[test]
fn response_body_types_and_json_content_types_are_preserved() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const a=new Response('text'),b=new Response(new URLSearchParams({x:'y'})),c=Response.json({ok:true},{headers:{'x-custom':'yes'}});log('response-types',a.headers.get('content-type'),b.headers.get('content-type'),c.headers.get('content-type'),c.headers.get('x-custom'));try{Response.json(undefined);log('unexpected-json')}catch(e){log('undefined-json',e.name)}
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["response-types text/plain;charset=UTF-8 application/x-www-form-urlencoded;charset=UTF-8 application/json yes", "undefined-json TypeError"]
    );
}

#[test]
fn mutating_iterator_entry_arrays_cannot_change_header_lists_or_guards() {
    let (_, report) = visit(
        r#"<script>
const r=new Request('/missing.js',{headers:{'x-data':'real'}}),entry=r.headers.entries().next().value;entry[0]='host';entry[1]='evil.example';console.log(r.headers.get('x-data'),r.headers.get('host'));r.headers.guard=r.headers._guard='none';r.headers.set('host','evil.example');console.log(r.headers.get('host'));
</script>"#,
    );
    assert_eq!(logs(&report), ["real null", "null"]);
}

#[test]
fn forbidden_request_headers_never_reach_the_host_but_allowed_headers_and_body_types_do() {
    let (run, report) = visit(
        r#"<script>
fetch('/actual',{method:'POST',body:'data',headers:{Host:'evil.example','Content-Length':'999',Cookie:'fake=secret',Referer:'https://evil.example/','Sec-Private':'x','Proxy-Private':'x','X-Data':'allowed'}}).then(r=>console.log(r.status));
</script>"#,
    );
    assert_eq!(logs(&report), ["200"]);
    let call = run.events.iter().find(|event| event.func == FETCH_OWN).unwrap();
    let headers = call.args["headers"].as_array().unwrap();
    assert!(headers.contains(&json!(["x-data", "allowed"])));
    assert!(headers.contains(&json!(["content-type", "text/plain;charset=UTF-8"])));
    for name in ["host", "content-length", "cookie", "referer", "sec-private", "proxy-private"] {
        assert!(!headers.iter().any(|pair| pair[0] == name), "{headers:?}");
    }
}

#[test]
fn object_prototype_properties_cannot_forge_cached_native_header_pairs() {
    let (_, report) = visit(
        r#"<script>
Object.prototype.pairs=[['host','evil.example']];try{const h=new Headers({'x-data':'real'});console.log(h.get('x-data'),JSON.stringify([...h]));const r=new Request('/missing.js',{headers:h});console.log(r.headers.get('host'),r.headers.get('x-data'))}finally{delete Object.prototype.pairs}
</script>"#,
    );
    assert_eq!(logs(&report), [r#"real [["x-data","real"]]"#, "null real"]);
}

#[test]
fn invalid_host_response_headers_reject_fetch_instead_of_leaving_it_pending() {
    let browser = Browser::shared().unwrap();
    for headers in
        [json!([["set-cookie", "rejected=bad; Path=/"], ["bad name", "x"]]), json!([["set-cookie", "rejected=bad; Path=/"], ["x-data", "bad\u{0}value"]])]
    {
        let input = json!({"url":"https://app.example/","html":r#"<script>fetch('/bad').then(()=>console.log('unexpected'),e=>console.log(e.name));setTimeout(()=>console.log('checkpoint',document.cookie),50);</script>"#});
        let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":headers,"body":"ok"}}}}).to_string()).unwrap();
        let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
        assert_eq!(run.outcome.kind, OutcomeKind::Ok);
        let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
        assert_eq!(report["errors"], json!([]), "{report}");
        assert_eq!(logs(&report), ["TypeError", "checkpoint "]);
    }
}
