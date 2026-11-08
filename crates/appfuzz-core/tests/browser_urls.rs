use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(html: &str) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
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

// Expectations checked against Firefox and the URL/Web IDL standards.

#[test]
fn url_slots_are_private() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/a?x=1');u._p=['https://evil.example/'];u._sp=new URLSearchParams('evil=1');u._update=()=>{};u.pathname='/safe';return [u.href,u.searchParams.get('x'),u.toJSON()];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["https://app.example/safe?x=1","1","https://app.example/safe?x=1"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn params_slots_are_private() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1');p._l=[['evil','2']];p._u={_update(){throw Error('public')}};p._sync=()=>{};p.append('b','3');return [p.get('a'),p.toString()];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["1","a=1&b=3"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn bound_params_ignore_public_helpers() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/?a=1'),p=u.searchParams;p.toString=()=> 'evil=1';p._sync=()=>{};u._update=()=>{};p.append('b','2');p._parse=()=>{};u.search='c=3';return [u.href,p.get('c'),p.size];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["https://app.example/?c=3","3",1]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn entries_are_live() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1&b=2'),it=p.entries();const first=it.next().value;p.set('b','3');p.append('c','4');return [first,it.next().value,it.next().value,it.next().done];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[["a","1"],["b","3"],["c","4"],true]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn iterators_follow_replaced_lists() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/?a=1&b=2'),p=u.searchParams,k=p.keys(),v=p.values();k.next();v.next();u.search='x=3&y=4&z=5';return [k.next().value,v.next().value,k.next().value,v.next().value];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["y","4","z","5"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn iterators_resume_after_done() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams(),out=[];for(const m of ['entries','keys','values']){const it=p[m]();out.push(it.next().done);p.append(m,'v');out.push(it.next().value);p.delete(m)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[true,["entries","v"],true,"keys",true,"v"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn foreach_follows_deleted_and_appended_entries() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1&b=2&c=3'),out=[];p.forEach((v,k,self)=>{out.push([k,v,self===p]);if(k==='a'){p.delete('b');p.append('d','4')}});return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[["a","1",true],["c","3",true],["d","4",true]]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn optional_values_convert_once_before_lookup() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const m of ['delete','has']){for(const init of ['', 'a=1&a=2&a=3']){let n=0;const p=new URLSearchParams(init),v={toString(){n++;return '2'}};const result=p[m]('a',v);out.push([m,init,n,result===undefined?null:result,p.toString()])}}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(
        r#"[["delete","",1,null,""],["delete","a=1&a=2&a=3",1,null,"a=1&a=3"],["has","",1,false,""],["has","a=1&a=2&a=3",1,true,"a=1&a=2&a=3"]]"#,
    )
    .unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn set_converts_before_lookup() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1&b=2');p.set('a',{toString(){p.delete('a');return '3'}});return p.toString();})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#""b=2&a=3""#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn required_arguments_throw() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const m of ['append','delete','get','getAll','has','set','forEach']){try{new URLSearchParams()[m]();out.push(m+':accepted')}catch(e){out.push(m+':'+e.name)}}for(const C of [()=>new URL(),()=>URL.canParse(),()=>URL.parse()]){try{C();out.push('accepted')}catch(e){out.push(e.name)}}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["append:TypeError","delete:TypeError","get:TypeError","getAll:TypeError","has:TypeError","set:TypeError","forEach:TypeError","TypeError","TypeError","TypeError"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn url_parsers_propagate_conversion_errors() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const C of [v=>new URL(v),v=>URL.canParse(v),v=>URL.parse(v)])for(const v of [Symbol('x'),{toString(){throw 77}}])try{C(v);out.push('accepted')}catch(e){out.push(e===77?77:e.name)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["TypeError",77,"TypeError",77,"TypeError",77]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn symbols_and_surrogates_follow_webidl() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const fn of [()=>new URLSearchParams(Symbol()),()=>new URLSearchParams().append(Symbol(),'x'),()=>new URLSearchParams().get(Symbol()),()=>new URLSearchParams({[Symbol()]:'x'})])try{fn();out.push('accepted')}catch(e){out.push(e.name)}const p=new URLSearchParams([['\ud800','\udfff']]);out.push(p.toString());return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["TypeError","TypeError","TypeError","TypeError","%EF%BF%BD=%EF%BF%BD"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn constructor_reads_iterators_once() {
    let (_, report) = visit(
        r#"<script>(async()=>{let outer=0,inner=0;const pair={get[Symbol.iterator](){inner++;return function*(){yield 'a';yield '1'}}},init={get[Symbol.iterator](){outer++;return function*(){yield pair}}};return [new URLSearchParams(init).toString(),outer,inner];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["a=1",1,1]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn constructor_converts_each_sequence_item() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];try{new URLSearchParams([['a','b',{toString(){out.push('third');return 'c'}}]])}catch(e){out.push(e.name)}for(const v of [['ab'],{[Symbol.iterator]:1}])try{new URLSearchParams(v);out.push('accepted')}catch(e){out.push(e.name)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["third","TypeError","TypeError","TypeError"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn constructor_uses_public_iteration() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1');p[Symbol.iterator]=function*(){yield ['b','2']};const f=()=>{};f.x='3';return [new URLSearchParams(p).toString(),new URLSearchParams(f).toString(),new URLSearchParams(null).toString()];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["b=2","x=3","null="]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn record_keys_collapse_after_usv_conversion() {
    let (_, report) = visit(
        r#"<script>(async()=>{const init={'\ud800':'1','\udfff':'2','b':'3'};return [...new URLSearchParams(init)];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[["�","2"],["b","3"]]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn wrong_receivers_fail_before_conversion() {
    let (_, report) = visit(
        r#"<script>(async()=>{let n=0;const v={toString(){n++;return 'a'}},out=[];for(const m of ['append','delete','get','getAll','has','set','sort','entries','keys','values','forEach','toString'])try{URLSearchParams.prototype[m].call({_l:[]},v,v);out.push('accepted')}catch(e){out.push(e.name)}try{URL.prototype.toJSON.call({_p:['evil']})}catch(e){out.push(e.name)}out.push(n);return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError",0]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn foreach_checks_empty_callbacks_and_ignores_call_shadow() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams(),out=[];try{p.forEach(null);out.push('accepted')}catch(e){out.push(e.name)}p.append('a','1');function callback(v,k){out.push([k,v,this===p])}callback.call=()=>out.push('shadow');p.forEach(callback,p);return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["TypeError",["a","1",true]]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn iteration_does_not_call_public_entries() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1');p.entries=function*(){yield ['evil','2']};return [URLSearchParams.prototype[Symbol.iterator]===URLSearchParams.prototype.entries,[...p]];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[true,[["a","1"]]]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn body_serialization_uses_private_params() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams('a=1');p._l=[['evil','2']];p.toString=()=> 'evil=3';p[Symbol.iterator]=function*(){yield ['evil','4']};return new Response(p).text().then(text=>[text,new Response(p).headers.get('content-type')]);})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["a=1","application/x-www-form-urlencoded;charset=UTF-8"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn setters_use_private_state_and_check_brand() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/'),out=[];u._update=()=>{};u.search='a=1';out.push(u.href);let n=0;try{Object.getOwnPropertyDescriptor(URL.prototype,'href').set.call({_p:[u.href]}, {toString(){n++;return u.href}});out.push('accepted')}catch(e){out.push(e.name)}out.push(n);return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["https://app.example/?a=1","TypeError",0]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn params_sort_and_encoding_controls() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/?z=~%20&a=1&a=2');const p=u.searchParams;p.sort();const empty=new URL('https://app.example/?#');empty.searchParams.delete('absent');return [u.href,[...p],empty.href];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["https://app.example/?a=1&a=2&z=%7E+",[["a","1"],["a","2"],["z","~ "]],"https://app.example/#"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn prototype_accessors_do_not_change_native_locations() {
    let (_, report) = visit(
        r#"<script>(async()=>{const original=Object.getOwnPropertyDescriptor(URL.prototype,'href'),out=[],base=location.origin,hostname=location.hostname;Object.defineProperty(URL.prototype,'href',{configurable:true,get(){return 'https://evil.example/'}});try{out.push(location.hostname===hostname,document.domain===hostname);out.push(new Request('/missing.js').url===base+'/missing.js');const r=await fetch('/missing.js');out.push(r.status>0)}finally{Object.defineProperty(URL.prototype,'href',original)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    assert_eq!(report["requests"][0]["url"], "https://app.example/missing.js", "{report}");
    assert_eq!(report["requests"][0]["own"], true, "{report}");
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[true,true,true,true]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn prototype_origin_cannot_bypass_history_origin_checks() {
    let (_, report) = visit(
        r#"<script>(async()=>{const origin=location.origin,original=Object.getOwnPropertyDescriptor(URL.prototype,'origin');Object.defineProperty(URL.prototype,'origin',{configurable:true,get(){return origin}});let out;try{history.pushState(null,'','https://evil.example/');out='accepted'}catch(e){out=e.name}finally{Object.defineProperty(URL.prototype,'origin',original)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#""SecurityError""#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn foreach_reads_updated_url_query() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/?a=1&b=2'),out=[];u.searchParams.forEach((v,k)=>{out.push([k,v]);if(k==='a')u.search='x=3&y=4&z=5'});return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[["a","1"],["y","4"],["z","5"]]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn conversion_side_effects_keep_current_bound_query() {
    let (_, report) = visit(
        r#"<script>(async()=>{const u=new URL('https://app.example/?a=1&b=2'),p=u.searchParams;p.append({toString(){u.search='c=3';return 'd'}},{toString(){return '4'}});const out=[u.href];u.href='https://app.example/?a=1&b=2';p.delete('b',{toString(){u.search='b=4&b=2';return '2'}});out.push(u.href);return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["https://app.example/?c=3&d=4","https://app.example/?b=4"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn surrogate_conversion_and_sort_ignore_public_intrinsics() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=String.prototype.toWellFormed,sort=Array.prototype.sort;let out;try{String.prototype.toWellFormed=()=> 'evil';Array.prototype.sort=()=>[];const p=new URLSearchParams([['z','\ud800'],['a','1']]);p.sort();out=[p.toString(),new URL('https://app.example/').hostname]}finally{String.prototype.toWellFormed=old;Array.prototype.sort=sort}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["a=1&z=%EF%BF%BD","app.example"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn url_conversion_is_once_and_in_order() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const f of [(a,b)=>new URL(a,b),(a,b)=>URL.parse(a,b),(a,b)=>URL.canParse(a,b)]){let n=0;try{f({toString(){n++;return 'invalid'}},{toString(){n++;return 'also invalid'}})}catch{}out.push(n)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[2,2,2]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn invalid_url_does_not_reconvert_input_for_diagnostics() {
    let (_, report) = visit(
        r#"<script>(async()=>{let n=0;try{new URL({toString(){n++;return 'invalid'}})}catch{}return n;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"1"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn opaque_query_and_fragment_updates_strip_spaces() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const action of ['params','search','hash']){const u=new URL('data:x  ?a=1');if(action==='params')u.searchParams.delete('a');if(action==='search')u.search='';if(action==='hash'){u.hash='#';u.searchParams.delete('a');u.hash=''}out.push(u.href)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["data:x","data:x","data:x"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn query_sort_preserves_duplicate_and_utf16_order() {
    let (_, report) = visit(
        r#"<script>(async()=>{const p=new URLSearchParams([['\ue000','a'],['\ud83d\ude00','b'],['a','2'],['a','1']]);p.sort();return [...p];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[["a","2"],["a","1"],["😀","b"],["","a"]]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn static_url_parse_has_platform_slots_and_ignores_subclass() {
    let (_, report) = visit(
        r#"<script>(async()=>{class U extends URL{}const u=U.parse('/x','https://app.example/');return [u.href,u instanceof U,u instanceof URL,URL.canParse('invalid'),URL.parse('invalid'),Object.prototype.toString.call(u),Object.prototype.toString.call(u.searchParams)];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["https://app.example/x",false,true,false,null,"[object URL]","[object URLSearchParams]"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn params_mutations_ignore_replaced_array_iteration() {
    let (_, report) = visit(
        r#"<script>
const p=new URLSearchParams('a=1&a=2&b=3'),old=Array.prototype[Symbol.iterator];let out;
try{Array.prototype[Symbol.iterator]=function*(){yield 'evil';yield 'value'};p.set('a','4');p.delete('b','3');out=p.has('a','4')+':'+p.toString()}finally{Array.prototype[Symbol.iterator]=old}console.log(out);
</script>"#,
    );
    assert_eq!(logs(&report), ["true:a=4"]);
}

#[test]
fn native_url_routing_ignores_replaced_prototype_accessors() {
    let (_, report) = visit(
        r#"<script>
const descriptors={};for(const k of ['href','origin','pathname','search']){descriptors[k]=Object.getOwnPropertyDescriptor(URL.prototype,k);Object.defineProperty(URL.prototype,k,{configurable:true,get(){return k==='href'?'https://evil.example/':k==='origin'?'https://evil.example':k==='pathname'?'/wrong':'?wrong=1'}})}
fetch('/safe?x=1').then(()=>{for(const k of Object.keys(descriptors))Object.defineProperty(URL.prototype,k,descriptors[k]);console.log('done')});
</script>"#,
    );
    assert_eq!(logs(&report), ["done"]);
    assert_eq!(report["requests"][0]["url"], "https://app.example/safe?x=1", "{report}");
    assert_eq!(report["requests"][0]["own"], true, "{report}");
}

#[test]
fn object_urls_require_real_blobs_and_required_arguments() {
    let (_, report) = visit(
        r#"<script>
const attempt=f=>{try{f();return 'accepted'}catch(e){return e.name}};
console.log(JSON.stringify([attempt(()=>URL.createObjectURL({})),attempt(()=>URL.createObjectURL()),attempt(()=>URL.revokeObjectURL()),attempt(()=>URL.revokeObjectURL(Symbol())),URL.createObjectURL(new Blob(['x'])).startsWith('blob:'+location.origin+'/')]));
</script>"#,
    );
    assert_eq!(logs(&report), [r#"["TypeError","TypeError","TypeError","TypeError",true]"#]);
}

#[test]
fn url_interfaces_expose_webidl_method_metadata() {
    let (_, report) = visit(
        r#"<script>
console.log(JSON.stringify([URL.length,URLSearchParams.length,URLSearchParams.prototype.delete.length,URLSearchParams.prototype.has.length,URL.canParse.length,URL.parse.length,Object.getOwnPropertyDescriptor(URLSearchParams.prototype,'append').enumerable,Object.getOwnPropertyDescriptor(URL.prototype,'toJSON').enumerable]));
</script>"#,
    );
    assert_eq!(logs(&report), ["[1,0,1,1,1,1,true,true]"]);
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
