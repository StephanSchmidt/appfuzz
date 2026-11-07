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
fn requests_and_clones_follow_distinct_signals_and_null_detaches_the_source() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=new Request('/missing.js',{signal:c.signal}),clone=r.clone();log('request-signals',r.signal instanceof AbortSignal,r.signal!==c.signal,clone.signal!==r.signal,clone.signal.aborted);c.abort('source');log('followed',r.signal.aborted,r.signal.reason,clone.signal.aborted,clone.signal.reason);
const detached=new Request(r,{signal:null});log('detached',detached.signal instanceof AbortSignal,detached.signal.aborted);const fresh=new Request('/missing.js');log('fresh',fresh.signal instanceof AbortSignal,fresh.signal.aborted);try{new Request('/missing.js',{signal:{aborted:false}})}catch(e){log('invalid-signal',e.name)}
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["request-signals true true true false", "followed true source true source", "detached true false", "fresh true false", "invalid-signal TypeError"]
    );
    let _ = run;
}

#[test]
fn preaborted_fetch_uses_private_signal_state_and_never_reaches_the_host() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController();c.abort('private');Object.defineProperty(c.signal,'aborted',{value:false});Object.defineProperty(c.signal,'reason',{value:'fake'});try{await fetch('/missing.js',{signal:c.signal});log('unexpected-fetch')}catch(e){log('preaborted',e)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["preaborted private"]);
    assert!(!run.events.iter().any(|e| e.func == FETCH_OWN));
}

#[test]
fn fetch_preserves_request_conversion_exception_identity() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const reason={marker:1},input={toString(){throw reason}};try{await fetch(input);log('unexpected-input')}catch(e){log('conversion-error',e===reason)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["conversion-error true"]);
    let _ = run;
}

#[test]
fn dependent_signals_are_marked_before_source_events_and_notify_after_them() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),events=[];c.signal.addEventListener('abort',()=>events.push('source'));const combined=AbortSignal.any([c.signal]);combined.addEventListener('abort',()=>events.push('combined'));c.signal.addEventListener('abort',()=>log('dependent-ready',combined.aborted,combined.reason));c.abort('first');log('combined-order',events.join('/'),combined.reason);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["dependent-ready true first", "combined-order source/combined first"]);
    let _ = run;
}

#[test]
fn combined_signals_pick_the_first_aborted_reason_after_validating_every_input() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const a=AbortSignal.abort('a'),b=AbortSignal.abort('b'),combined=AbortSignal.any([b,a]);log('already-aborted',combined.aborted,combined.reason);try{AbortSignal.any([a,{}])}catch(e){log('validate-all',e.name)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["already-aborted true b", "validate-all TypeError"]);
    let _ = run;
}

#[test]
fn nested_combined_signals_abort_once_and_preserve_the_first_reason() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const a=new AbortController(),b=new AbortController(),ab=AbortSignal.any([a.signal,b.signal]),nested=AbortSignal.any([ab,a.signal]);let n=0;nested.onabort=()=>n++;a.abort('a');b.abort('b');log('nested',n,ab.reason,nested.reason);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["nested 1 a a"]);
    let _ = run;
}

#[test]
fn fetch_cancellation_runs_at_abort_time_despite_stopped_abort_events() {
    let (run, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),order=[];c.signal.addEventListener('abort',e=>e.stopImmediatePropagation());const promise=fetch('/missing.js',{signal:c.signal});promise.catch(e=>order.push(e));c.abort('abort');await Promise.resolve();order.push('checkpoint');await promise.catch(()=>{});log('abort-order',order.join('/'));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["abort-order abort/checkpoint"]);
    let _ = run;
}

#[test]
fn aborting_after_fetch_resolution_errors_an_unread_response_body_with_the_original_reason() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),reason={marker:1},r=await fetch('/missing.js',{signal:c.signal});c.abort(reason);try{await r.text();log('unexpected-body')}catch(e){log('aborted-body',e===reason,(e.name===undefined?'undefined':e.name))}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["aborted-body true undefined"]);
}

#[test]
fn cloned_response_bodies_preserve_fetch_cancellation() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=await fetch('/missing.js',{signal:c.signal}),clone=r.clone();c.abort('reason');for(const [label,response]of[['original',r],['clone',clone]])try{await response.text();log('unexpected-clone')}catch(e){log('aborted-clone',label,e==='reason',(e.name===undefined?'undefined':e.name))}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["aborted-clone original true undefined", "aborted-clone clone true undefined"]);
}

#[test]
fn request_signal_shadows_do_not_change_request_copying_or_fetching() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=new Request('/missing.js',{signal:c.signal});Object.defineProperty(r,'signal',{get(){log('unexpected-signal-getter');return null}});const copy=new Request(r);c.abort('original');log('private-request-signal',copy.signal.aborted,copy.signal.reason);try{await fetch(r)}catch(e){log('private-fetch',e)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["private-request-signal true original", "private-fetch original"]);
}

#[test]
fn request_url_and_method_shadows_do_not_change_internal_request_copying() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=new Request('/missing.js',{signal:c.signal});Object.defineProperty(r,'url',{value:'https://evil.example/'});Object.defineProperty(r,'method',{value:'DELETE'});const copy=new Request(r);log('private-request',copy.url.endsWith('/missing.js'),copy.method);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["private-request true GET"]);
}

#[test]
fn fetch_preserves_signal_dictionary_getter_exceptions() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const reason={marker:1};try{await fetch('/missing.js',{get signal(){throw reason}})}catch(e){log('signal-error',e===reason)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["signal-error true"]);
}

#[test]
fn request_header_shadows_do_not_change_native_header_copying() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const h=new Headers({'x-test':'real'});h.forEach=()=>log('unexpected-foreach');const r=new Request('/missing.js',{headers:h});Object.defineProperty(r,'headers',{get(){log('unexpected-header-getter');return new Headers()}});const copy=new Request(r);log('private-headers',copy.headers.get('x-test'));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["private-headers real"]);
}

#[test]
fn undefined_signal_options_keep_following_the_input_request() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=new Request('/missing.js',{signal:c.signal}),a=new Request(r,{signal:undefined});c.abort('source');log('undefined-signal',a.signal.aborted,a.signal.reason);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["undefined-signal true source"]);
}

#[test]
fn reentrant_source_aborts_preserve_already_assigned_dependent_reasons_and_event_order() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const a=new AbortController(),b=new AbortController(),ab=AbortSignal.any([a.signal,b.signal]),nested=AbortSignal.any([ab,a.signal]);a.signal.onabort=()=>{log('a-event',ab.aborted,nested.aborted);b.abort('b')};b.signal.onabort=()=>log('b-event',ab.reason,nested.reason);ab.onabort=()=>log('ab-event',ab.reason);nested.onabort=()=>log('nested-event',nested.reason);a.abort('a');
})();</script>"#,
    );
    assert_eq!(logs(&report), ["a-event true true", "b-event a a", "ab-event a", "nested-event a"]);
}

#[test]
fn combined_signal_sequence_conversion_does_not_close_iterators_on_element_type_errors() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
let closed=0,next=0;const seq={[Symbol.iterator](){return{next(){next++;return{value:{},done:false}},return(){closed++;return {done:true}}}}};try{AbortSignal.any(seq)}catch(e){log('invalid-iterator',e.name,next,closed)}
for(const [label,value]of[['missing',undefined],['null',null],['primitive',''],['array-like',{length:0}]])try{AbortSignal.any(value);log('unexpected-sequence')}catch(e){log('sequence',label,e.name)}log('empty',AbortSignal.any([]).aborted);
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "invalid-iterator TypeError 1 0",
            "sequence missing TypeError",
            "sequence null TypeError",
            "sequence primitive TypeError",
            "sequence array-like TypeError",
            "empty false"
        ]
    );
}

#[test]
fn combined_signals_ignore_public_source_getters_and_registration_overrides() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController();Object.defineProperty(c.signal,'aborted',{get(){log('unexpected-aborted');return true}});Object.defineProperty(c.signal,'reason',{get(){log('unexpected-reason');return 'fake'}});Object.defineProperty(c.signal,'addEventListener',{value(){log('unexpected-registration')}});const combined=AbortSignal.any([c.signal,c.signal]);log('before',combined.aborted);c.abort(null);log('after',combined.aborted,combined.reason);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["before false", "after true null"]);
}

#[test]
fn request_following_flattens_dependencies_without_reordering_source_events() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=new Request('/missing.js',{signal:c.signal}),clone=r.clone();const order=[];for(const [name,s]of[['root',c.signal],['request',r.signal],['clone',clone.signal]])s.onabort=()=>order.push(name);c.abort('reason');log('follow-order',order.join('/'));
})();</script>"#,
    );
    assert_eq!(logs(&report), ["follow-order root/request/clone"]);
}

#[test]
fn request_clones_tee_bodies_while_construction_consumes_the_source() {
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const r=new Request('/missing.js',{method:'POST',body:'text'}),clone=r.clone();log('clone-used-before',r.bodyUsed,clone.bodyUsed);log('clone-text',await clone.text(),r.bodyUsed,clone.bodyUsed);const copy=new Request(r);log('copy-used',r.bodyUsed,copy.bodyUsed);log('copy-text',await copy.text());try{r.clone()}catch(e){log('used-clone',e.name)}
})();</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["clone-used-before false false", "clone-text text false true", "copy-used true false", "copy-text text", "used-clone TypeError"]
    );
}

#[test]
fn an_aborted_non_null_body_becomes_used_on_read_as_required_by_fetch() {
    // Fetch consume-body requires disturbing a non-null body and consuming null bodies as empty.
    // Firefox differs here; these expected results also match Node Fetch.
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=await fetch('/missing.js',{signal:c.signal});log('body-before',r.bodyUsed);c.abort('reason');try{await r.text()}catch(e){log('body-after',r.bodyUsed,e)}try{await r.text()}catch(e){log('body-repeat',e.name)}
})();</script>"#,
    );
    assert_eq!(logs(&report), ["body-before false", "body-after true reason", "body-repeat TypeError"]);
}

#[test]
fn aborting_a_head_response_does_not_error_its_null_body() {
    // Fetch consume-body requires disturbing a non-null body and consuming null bodies as empty.
    // Firefox differs here; these expected results also match Node Fetch.
    let (_, report) = visit(
        r#"<script>(async()=>{const log=(...x)=>console.log(...x);
const c=new AbortController(),r=await fetch('/missing.js',{method:'HEAD',signal:c.signal});c.abort('reason');log('null-body',await r.text(),r.bodyUsed);
})();</script>"#,
    );
    assert_eq!(logs(&report), ["null-body  false"]);
}

#[test]
fn canceled_fetch_delivery_does_not_apply_response_cookies() {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":r#"<script>const c=new AbortController();fetch('/canceled',{signal:c.signal}).catch(()=>{});c.abort();setTimeout(()=>console.log('cookie',document.cookie),50);</script>"#});
    let plan = Plan::parse(
        &json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[["set-cookie","canceled=bad; Path=/"]],"body":"ok"}},"latency_ms":20}}).to_string(),
    )
    .unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert_eq!(report["errors"], json!([]));
    assert_eq!(logs(&report), ["cookie "]);
    assert_eq!(run.events.iter().filter(|e| e.func == FETCH_OWN).count(), 1);
}

#[test]
fn fetch_routes_the_internal_request_and_headers_despite_public_property_shadows() {
    let (run, report) = visit(
        r#"<script>
const request=new Request('/actual',{method:'POST',body:'body',headers:{'x-data':'real'},credentials:'omit'}),headers=request.headers;headers.forEach=()=>{throw Error('public headers')};Object.defineProperties(request,{url:{value:'https://evil.example/fake'},method:{value:'DELETE'},headers:{value:new Headers()},signal:{value:AbortSignal.abort('fake')}});fetch(request).then(response=>console.log(response.status));
</script>"#,
    );
    assert_eq!(logs(&report), ["200"]);
    let calls: Vec<_> = run.events.iter().filter(|event| event.func == FETCH_OWN).collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args["path"], "/actual");
    assert_eq!(calls[0].args["method"], "POST");
    assert_eq!(calls[0].args["body"], json!({"some":"body"}));
    assert!(calls[0].args["headers"].as_array().unwrap().contains(&json!(["x-data", "real"])));
    assert!(!run.events.iter().any(|event| event.func == appfuzz_core::browser::FETCH_OTHER));
}
