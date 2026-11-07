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
fn capture_precedes_target_and_bubbling_and_also_runs_for_non_bubbling_events() {
    let (_, report) = visit(
        r#"<script>
    const root=document.createElement('div'),child=document.createElement('span');root.append(child);document.body.append(root);
    for(const [name,node]of[['window',window],['doc',document],['root',root],['child',child]])for(const capture of [true,false])node.addEventListener('order',function(e){console.log(name,capture,e.eventPhase,e.target===child,e.currentTarget===node,this===node)},{capture});
    child.dispatchEvent(new Event('order',{bubbles:true}));child.dispatchEvent(new Event('order'));root.remove();
    </script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "window true 1 true true true",
            "doc true 1 true true true",
            "root true 1 true true true",
            "child true 2 true true true",
            "child false 2 true true true",
            "root false 3 true true true",
            "doc false 3 true true true",
            "window false 3 true true true",
            "window true 1 true true true",
            "doc true 1 true true true",
            "root true 1 true true true",
            "child true 2 true true true",
            "child false 2 true true true"
        ]
    );
}

#[test]
fn stopping_propagation_preserves_same_phase_listeners_but_cannot_be_undone() {
    let (_, report) = visit(
        r#"<script>
    const root=document.createElement('div'),child=document.createElement('span');root.append(child);document.body.append(root);
    root.addEventListener('stop',e=>{console.log('root-first');e.cancelBubble=true;e.cancelBubble=false},true);root.addEventListener('stop',()=>console.log('root-second'),true);child.addEventListener('stop',()=>console.log('unexpected-target'));child.dispatchEvent(new Event('stop',{bubbles:true}));
    child.addEventListener('self',e=>{console.log('target-capture');e.stopPropagation()},true);child.addEventListener('self',()=>console.log('unexpected-bubble'));child.dispatchEvent(new Event('self',{bubbles:true}));root.remove();
    </script>"#,
    );
    assert_eq!(logs(&report), ["root-first", "root-second", "target-capture"]);
}

#[test]
fn listener_options_are_snapshotted_and_duplicate_registration_does_not_change_them() {
    let (_, report) = visit(
        r#"<script>
    const target=new EventTarget(),options={once:true,passive:true},handler=e=>{console.log('called');e.preventDefault()};target.addEventListener('snapshot',handler,options);target.addEventListener('snapshot',handler,{once:false,passive:false});options.once=false;options.passive=false;const event=new Event('snapshot',{cancelable:true});console.log('returned',target.dispatchEvent(event),event.defaultPrevented);target.dispatchEvent(new Event('snapshot'));
    </script>"#,
    );
    assert_eq!(logs(&report), ["called", "returned true false"]);
}

#[test]
fn current_listener_lists_are_snapshotted_while_later_phases_see_new_listeners() {
    let (_, report) = visit(
        r#"<script>
    const target=new EventTarget(),later=()=>console.log('unexpected-later');target.addEventListener('mutate',()=>{console.log('first');target.removeEventListener('mutate',later);target.addEventListener('mutate',()=>console.log('unexpected-added'))});target.addEventListener('mutate',later);target.dispatchEvent(new Event('mutate'));
    target.addEventListener('phase',()=>{console.log('capture');target.addEventListener('phase',()=>console.log('new-bubble'))},true);target.dispatchEvent(new Event('phase'));
    </script>"#,
    );
    assert_eq!(logs(&report), ["first", "capture", "new-bubble"]);
}

#[test]
fn event_type_bubbles_and_parent_shadows_do_not_change_native_routing() {
    let (_, report) = visit(
        r#"<script>
    const root=document.createElement('div'),child=document.createElement('span');root.append(child);document.body.append(root);child.addEventListener('real',e=>console.log('child',e.type,e.eventPhase));root.addEventListener('real',()=>console.log('parent'));const event=new Event('real',{bubbles:true});Object.defineProperty(event,'type',{value:'fake'});Object.defineProperty(event,'bubbles',{value:false});Object.defineProperty(child,'_getParent',{value:()=>{console.log('unexpected-parent');return null}});child.dispatchEvent(event);console.log('after',event.target===child,event.currentTarget,event.eventPhase);root.remove();
    </script>"#,
    );
    assert_eq!(logs(&report), ["child fake 2", "parent", "after true null 0"]);
}

#[test]
fn an_event_cannot_be_redispatched_while_its_listener_is_running() {
    let (_, report) = visit(
        r#"<script>
    const target=new EventTarget();let count=0;target.addEventListener('recursive',event=>{count++;try{target.dispatchEvent(event)}catch(e){console.log(e.name)}},{once:true});target.dispatchEvent(new Event('recursive'));console.log(count);
    </script>"#,
    );
    assert_eq!(logs(&report), ["InvalidStateError", "1"]);
}

#[test]
fn aborted_signals_remove_listeners_independently_of_abort_event_propagation() {
    let (_, report) = visit(
        r#"<script>
    const target=new EventTarget(),early=new AbortController();let count=0;early.abort();target.addEventListener('test',()=>count++,{signal:early.signal});target.dispatchEvent(new Event('test'));console.log('early',count);const late=new AbortController();late.signal.addEventListener('abort',e=>e.stopImmediatePropagation());target.addEventListener('test',()=>count++,{signal:late.signal});late.abort();target.dispatchEvent(new Event('test'));console.log('late',count);
    </script>"#,
    );
    assert_eq!(logs(&report), ["early 0", "late 0"]);
}

#[test]
fn composed_shadow_events_retarget_at_hosts_and_closed_paths_hide_private_descendants() {
    let (_, report) = visit(
        r#"<script>
    for(const mode of ['open','closed']){const host=document.createElement('div');document.body.append(host);const shadow=host.attachShadow({mode}),child=document.createElement('span');shadow.append(child);const name=n=>n===child?'child':n===shadow?'shadow':n===host?'host':n===document.body?'body':n===document.documentElement?'html':n===document?'doc':'window';
    for(const [label,node]of[['host',host],['shadow',shadow],['child',child]])for(const capture of [true,false])node.addEventListener('test',event=>console.log(mode,label,capture,event.eventPhase,name(event.target),event.composedPath().map(name).join('/')),{capture});child.dispatchEvent(new Event('test',{bubbles:true,composed:true}));host.remove()}
    </script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "open host true 2 host child/shadow/host/body/html/doc/window",
            "open shadow true 1 child child/shadow/host/body/html/doc/window",
            "open child true 2 child child/shadow/host/body/html/doc/window",
            "open child false 2 child child/shadow/host/body/html/doc/window",
            "open shadow false 3 child child/shadow/host/body/html/doc/window",
            "open host false 2 host child/shadow/host/body/html/doc/window",
            "closed host true 2 host host/body/html/doc/window",
            "closed shadow true 1 child child/shadow/host/body/html/doc/window",
            "closed child true 2 child child/shadow/host/body/html/doc/window",
            "closed child false 2 child child/shadow/host/body/html/doc/window",
            "closed shadow false 3 child child/shadow/host/body/html/doc/window",
            "closed host false 2 host host/body/html/doc/window"
        ]
    );
}

#[test]
fn capture_and_bubble_registrations_have_distinct_identity_and_ignore_callback_call_shadows() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
 const root=document.createElement('div'),child=document.createElement('span');root.append(child);document.body.append(root);const fn=function(e){log('dual',e.eventPhase)};fn.call=()=>log('unexpected-call');root.addEventListener('dual',fn,true);root.addEventListener('dual',fn,false);child.dispatchEvent(new Event('dual',{bubbles:true}));root.removeEventListener('dual',fn,true);child.dispatchEvent(new Event('dual',{bubbles:true}));root.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["dual 1", "dual 3", "dual 3"]);
}

#[test]
fn listener_dictionary_conversion_and_duplicate_signals_follow_registration_order() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
 const target=new EventTarget();let count=0;target.addEventListener({toString(){log('type');return 'options'}},()=>log('options-listener'),{get capture(){log('capture');return true},get once(){log('once');return true},get passive(){log('passive');return false},get signal(){log('signal');return undefined}});target.dispatchEvent(new Event('options'));target.dispatchEvent(new Event('options'));const a=new AbortController(),b=new AbortController(),fn=()=>count++;target.addEventListener('duplicate',fn,{signal:a.signal});target.addEventListener('duplicate',fn,{signal:b.signal});b.abort();target.dispatchEvent(new Event('duplicate'));log('duplicate-signal',count);a.abort();target.dispatchEvent(new Event('duplicate'));log('original-signal',count);
 try{target.addEventListener('null',null,{signal:null})}catch(e){log('null-signal',e.name)}
 try{target.addEventListener('bad',null,{signal:{aborted:false}})}catch(e){log('invalid-signal',e.name)}
</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "type",
            "capture",
            "once",
            "passive",
            "signal",
            "options-listener",
            "duplicate-signal 1",
            "original-signal 1",
            "null-signal TypeError",
            "invalid-signal TypeError"
        ]
    );
}

#[test]
fn default_passive_listeners_apply_only_at_document_and_window_targets() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
 for(const [label,target]of[['window',window],['document',document],['html',document.documentElement],['body',document.body],['local',document.createElement('span')]]){const fn=e=>e.preventDefault();target.addEventListener('wheel',fn);const event=new Event('wheel',{cancelable:true});log('default-passive',label,target.dispatchEvent(event),event.defaultPrevented);target.removeEventListener('wheel',fn)}
</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "default-passive window true false",
            "default-passive document true false",
            "default-passive html true false",
            "default-passive body true false",
            "default-passive local false true"
        ]
    );
}

#[test]
fn non_bubbling_composed_events_reach_hosts_and_related_targets_remain_private() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
 const host=document.createElement('div');document.body.append(host);const root=host.attachShadow({mode:'closed'}),a=document.createElement('span'),b=document.createElement('span');root.append(a,b);for(const [label,target]of[['host',host],['root',root],['child',a]])for(const capture of [true,false])target.addEventListener('composed',e=>log('nonbubble',label,capture,e.eventPhase),{capture});const event=new Event('composed',{composed:true});a.dispatchEvent(event);log('nonbubble-after',event.target===host,event.currentTarget,event.composedPath().length);host.addEventListener('related',()=>log('unexpected-related'));root.addEventListener('related',e=>log('related',e.target===a,e.relatedTarget===b));const mouse=new MouseEvent('related',{bubbles:true,composed:true,relatedTarget:b});a.dispatchEvent(mouse);log('related-after',mouse.target,mouse.relatedTarget);host.remove();
</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "nonbubble host true 2",
            "nonbubble root true 1",
            "nonbubble child true 2",
            "nonbubble child false 2",
            "nonbubble host false 2",
            "nonbubble-after true null 0",
            "related true true",
            "related-after null null"
        ]
    );
}

#[test]
fn slotted_light_dom_events_cross_closed_roots_without_exposing_private_path_entries() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
 const host=document.createElement('div');document.body.append(host);const light=document.createElement('span');light.id='light';light.slot='named';host.append(light);const root=host.attachShadow({mode:'closed'}),slot=document.createElement('slot');slot.name='named';root.append(slot);const name=n=>n===light?'light':n===slot?'slot':n===root?'root':n===host?'host':n===document.body?'body':n===document.documentElement?'html':n===document?'doc':'window';for(const [label,target]of[['light',light],['slot',slot],['host',host]])target.addEventListener('slot',e=>log('slot',label,name(e.target),e.composedPath().map(name).join('/')));light.dispatchEvent(new Event('slot',{bubbles:true}));host.remove();
</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "slot light light light/host/body/html/doc/window",
            "slot slot light light/slot/root/host/body/html/doc/window",
            "slot host light light/host/body/html/doc/window"
        ]
    );
}

#[test]
fn content_and_property_handlers_share_one_stable_listener_position() {
    let (_, report) = visit(
        r#"<!doctype html><meta charset=utf-8><body><button id=b onclick="log('attribute')"></button><script>
const log=(...x)=>console.log(...x),b=document.getElementById('b');
b.addEventListener('click',()=>log('listener'));b.dispatchEvent(new MouseEvent('click'));log('getter',typeof b.onclick);b.onclick=()=>log('property');b.addEventListener('click',()=>log('last'));b.dispatchEvent(new MouseEvent('click'));b.setAttribute('onclick',"log('replacement')");b.dispatchEvent(new MouseEvent('click'));b.onclick=null;b.dispatchEvent(new MouseEvent('click'));b.setAttribute('onclick',"log('restored');return false");log('cancel',b.dispatchEvent(new MouseEvent('click',{cancelable:true})));b.removeAttribute('onclick');b.dispatchEvent(new MouseEvent('click'));
const c=document.createElement('div');c.addEventListener('click',()=>log('first'));c.onclick=()=>log('old');c.addEventListener('click',()=>log('third'));c.onclick=()=>{log('new');return false};log('return',c.dispatchEvent(new Event('click',{cancelable:true})));c.onclick=null;c.onclick=()=>log('reactivated');c.dispatchEvent(new Event('click'));c.onclick={handleEvent(){log('unexpected-object')}};log('null',typeof c.onclick);c.dispatchEvent(new Event('click'));b.remove();

</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "attribute",
            "listener",
            "getter function",
            "property",
            "listener",
            "last",
            "replacement",
            "listener",
            "last",
            "listener",
            "last",
            "listener",
            "last",
            "restored",
            "cancel false",
            "listener",
            "last",
            "first",
            "new",
            "third",
            "return false",
            "first",
            "third",
            "reactivated",
            "null object",
            "first",
            "third"
        ]
    );
}

#[test]
fn legacy_initialization_dispatch_cleanup_and_abort_brands_match_the_browser() {
    let (_, report) = visit(
        r#"<!doctype html><meta charset=utf-8><body><script>
const log=(...a)=>console.log(...a),target=new EventTarget(),event=new Event('old',{bubbles:true,cancelable:true,composed:true});event.preventDefault();event.stopImmediatePropagation();event.initEvent({toString(){log('type');return 'new'}},false,true);log('init',event.type,event.bubbles,event.cancelable,event.defaultPrevented,event.cancelBubble,event.target);target.addEventListener('new',e=>{e.initEvent({toString(){log('during-type');return 'ignored'}},true,false);log('during',e.type,e.bubbles,e.cancelable,e.eventPhase,e.currentTarget===target);e.preventDefault()});log('dispatch',target.dispatchEvent(event));log('after',event.type,event.target===target,event.currentTarget,event.eventPhase,event.composedPath().length,event.defaultPrevented);log('again',target.dispatchEvent(event));
for(const type of ['Event','CustomEvent','constructor','toString']){try{const e=document.createEvent(type);try{target.dispatchEvent(e)}catch(error){log('uninitialized',type,error.name)}e.initEvent('init',false,false);log('initialized',type,target.dispatchEvent(e))}catch(error){log('unsupported',type,error.name)}}
const c=new AbortController();let count=0;Object.defineProperty(c.signal,'aborted',{value:false});Object.defineProperty(c.signal,'addEventListener',{value:()=>log('unexpected-signal-listener')});c.abort('private');target.addEventListener('signal',()=>count++,{signal:c.signal});target.dispatchEvent(new Event('signal'));log('private-signal',count,c.signal.reason);try{c.signal.throwIfAborted()}catch(error){log('reason',error)}

</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "type",
            "init new false true false false null",
            "during-type",
            "during new false true 2 true",
            "dispatch false",
            "after new true null 0 0 true",
            "during-type",
            "during new false true 2 true",
            "again false",
            "uninitialized Event InvalidStateError",
            "initialized Event true",
            "uninitialized CustomEvent InvalidStateError",
            "initialized CustomEvent true",
            "unsupported constructor NotSupportedError",
            "unsupported toString NotSupportedError",
            "private-signal 0 private",
            "reason private"
        ]
    );
}

#[test]
fn native_xhr_events_use_listener_order_private_dispatch_and_trusted_targets() {
    let (_, report) = visit(
        r#"<script>
const xhr=new XMLHttpRequest();xhr.addEventListener('readystatechange',e=>console.log('listener',e.target===xhr,e.currentTarget===xhr,e.isTrusted));xhr.onreadystatechange=e=>console.log('property',e.target===xhr,e.currentTarget===xhr,e.isTrusted);xhr.dispatchEvent=()=>console.log('unexpected-public');xhr.open('GET','/missing.js');
</script>"#,
    );
    assert_eq!(logs(&report), ["listener true true true", "property true true true"]);
}

#[test]
fn native_message_events_use_listener_order_private_dispatch_and_trusted_targets() {
    let (_, report) = visit(
        r#"<script>
const channel=new MessageChannel();channel.port2.addEventListener('message',e=>console.log('listener',e.target===channel.port2,e.currentTarget===channel.port2,e.isTrusted));channel.port2.onmessage=e=>console.log('property',e.target===channel.port2,e.currentTarget===channel.port2,e.isTrusted);channel.port2.dispatchEvent=()=>console.log('unexpected-public');channel.port1.postMessage('hello');
</script>"#,
    );
    assert_eq!(logs(&report), ["listener true true true", "property true true true"]);
}

#[test]
fn native_file_reader_events_use_listener_order_private_dispatch_and_trusted_targets() {
    let (_, report) = visit(
        r#"<script>
const reader=new FileReader();reader.addEventListener('load',e=>console.log('listener',e.target===reader,e.currentTarget===reader,e.isTrusted));reader.onload=e=>console.log('property',e.target===reader,e.currentTarget===reader,e.isTrusted);reader.dispatchEvent=()=>console.log('unexpected-public');reader.readAsText(new Blob(['hello']));
</script>"#,
    );
    assert_eq!(logs(&report), ["listener true true true", "property true true true"]);
}

#[test]
fn trusted_events_keep_their_brand_during_reentrant_dispatch_and_become_synthetic_on_redispatch() {
    let (_, report) = visit(
        r#"<script>
const controller=new AbortController();let event;controller.signal.onabort=e=>{event=e;console.log('trusted',e.isTrusted,Object.getOwnPropertyDescriptor(e,'isTrusted').configurable);try{controller.signal.dispatchEvent(e)}catch(error){console.log('reentrant',error.name,e.isTrusted)}};controller.abort();controller.signal.onabort=null;controller.signal.dispatchEvent(event);console.log('synthetic',event.isTrusted,event.currentTarget,event.eventPhase);
const target=new EventTarget(),object={handleEvent(e){console.log('object',this===object,e.currentTarget===target)}};target.addEventListener('object',object);target.dispatchEvent(new Event('object'));object.handleEvent=e=>console.log('replacement',e.type);target.dispatchEvent(new Event('object'));
</script>"#,
    );
    assert_eq!(logs(&report), ["trusted true false", "reentrant InvalidStateError true", "synthetic false null 0", "object true true", "replacement object"]);
}

#[test]
fn legacy_initialization_preserves_the_composed_flag_as_required_by_the_dom_standard() {
    // DOM's initialize algorithm changes type/bubbles/cancelable and flags,
    // but does not unset composed. Firefox currently also resets composed.
    let (_, report) = visit(
        r#"<script>
const event=new Event('old',{composed:true});event.initEvent('new');console.log(event.type,event.composed);const custom=new CustomEvent('old',{composed:true,detail:1});custom.initCustomEvent('new',false,false,2);console.log(custom.type,custom.composed,custom.detail);
</script>"#,
    );
    assert_eq!(logs(&report), ["new true", "new true 2"]);
}

#[test]
fn abort_timeout_truncates_fractional_delays_before_enforcing_the_unsigned_range() {
    let (_, report) = visit(
        r#"<script>
for(const [label,args]of[['missing',[]],['fraction',[-0.5]],['negative',[-1]],['infinite',[Infinity]],['nan',[NaN]],['bigint',[1n]],['symbol',[Symbol()]]])try{const signal=AbortSignal.timeout(...args);console.log(label,'accepted',signal.aborted)}catch(e){console.log(label,e.name)}
</script>"#,
    );
    assert_eq!(
        logs(&report),
        ["missing TypeError", "fraction accepted false", "negative TypeError", "infinite TypeError", "nan TypeError", "bigint TypeError", "symbol TypeError"]
    );
}
