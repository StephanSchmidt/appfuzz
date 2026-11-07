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
fn mouse_clicks_toggle_checkboxes_before_listeners_and_emit_trusted_change_events() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox'});c.indeterminate=true;for(const t of ['click','input','change'])c.addEventListener(t,e=>log('checkbox',t,c.checked,c.indeterminate,e.isTrusted,e.bubbles,e.composed,e.eventPhase));const generic=new Event('click',{bubbles:true,cancelable:true});log('generic',c.dispatchEvent(generic),c.checked,c.indeterminate);const event=new MouseEvent('click',{bubbles:true,cancelable:true});log('mouse',c.dispatchEvent(event),c.checked,c.indeterminate,event.eventPhase,event.currentTarget);c.remove();
</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "checkbox click false true false true false 2",
            "generic true false true",
            "checkbox click true false false true false 2",
            "checkbox input true false true true true 2",
            "checkbox change true false true true false 2",
            "mouse true true false 0 null"
        ]
    );
}

#[test]
fn canceling_a_mouse_click_restores_checkedness_and_indeterminateness() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox'});c.indeterminate=true;c.addEventListener('click',e=>{log('cancel-during',c.checked,c.indeterminate);e.preventDefault()});for(const t of ['input','change'])c.addEventListener(t,()=>log('unexpected-canceled',t));log('canceled',c.dispatchEvent(new MouseEvent('click',{cancelable:true})),c.checked,c.indeterminate);c.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["cancel-during true false", "canceled false false true"]);
}

#[test]
fn canceling_a_radio_click_restores_the_previous_radio_in_its_group() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const a=make('input',{type:'radio',name:'group'}),b=make('input',{type:'radio',name:'group'});a.checked=true;b.addEventListener('click',e=>{log('radio-during',a.checked,b.checked);e.preventDefault()});log('radio-cancel',b.dispatchEvent(new MouseEvent('click',{cancelable:true})),a.checked,b.checked);a.remove();b.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["radio-during false true", "radio-cancel false true false"]);
}

#[test]
fn disabled_click_methods_are_suppressed_while_dispatched_mouse_events_still_activate() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox',disabled:''});c.addEventListener('click',e=>log('disabled-event',c.checked,e.isTrusted));c.click();log('disabled-click',c.checked);c.dispatchEvent(new MouseEvent('click'));log('disabled-dispatch',c.checked);c.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["disabled-click false", "disabled-event true false", "disabled-dispatch true"]);
}

#[test]
fn programmatic_clicks_ignore_reentrant_click_calls_and_have_zero_detail() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox'});let count=0;c.addEventListener('click',e=>{log('method-click',++count,e.isTrusted,e.bubbles,e.composed,e.detail,c.checked);if(count<3)c.click()});c.click();log('recursive-after',count,c.checked);c.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["method-click 1 false true true 0 true", "recursive-after 1 true"]);
}

#[test]
fn checkbox_input_events_cross_shadow_roots_while_change_events_stay_inside() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const h=make('div'),r=h.attachShadow({mode:'open'}),c=document.createElement('input');c.type='checkbox';r.append(c);h.addEventListener('input',e=>log('shadow-input',e.target===h,e.composed,e.isTrusted));h.addEventListener('change',()=>log('unexpected-change'));c.addEventListener('change',e=>log('shadow-change',e.composed,e.isTrusted));c.dispatchEvent(new MouseEvent('click'));h.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["shadow-input true true true", "shadow-change false true"]);
}

#[test]
fn detached_checkboxes_toggle_without_firing_input_or_change() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=document.createElement('input');c.type='checkbox';for(const t of ['click','input','change'])c.addEventListener(t,e=>log('detached',t,c.checked,e.isTrusted));c.dispatchEvent(new MouseEvent('click'));log('detached-after',c.checked);
</script>"#,
    );
    assert_eq!(logs(&report), ["detached click true false", "detached-after true"]);
}

#[test]
fn checkbox_change_notifications_survive_listener_state_changes_but_selected_radios_do_not_repeat_them() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox'});c.addEventListener('click',()=>{c.checked=false});c.addEventListener('input',()=>log('restored-input',c.checked));c.dispatchEvent(new MouseEvent('click'));c.remove();
const a=make('input',{type:'radio',name:'a'});a.checked=true;for(const t of ['click','input','change'])a.addEventListener(t,()=>log('already',t,a.checked));a.dispatchEvent(new MouseEvent('click'));a.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["restored-input false", "already click true"]);
}

#[test]
fn disabled_fieldsets_suppress_clicks_except_inside_the_first_legend() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const fs=make('fieldset',{disabled:''}),legend=document.createElement('legend'),a=document.createElement('button'),b=document.createElement('button');legend.append(a);fs.append(legend,b);for(const [label,button]of[['legend',a],['disabled',b]]){button.addEventListener('click',()=>log('fieldset',label));button.click()}fs.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["fieldset legend"]);
}

#[test]
fn radio_groups_are_separate_in_different_shadow_trees() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const host=make('div'),shadow=host.attachShadow({mode:'open'}),a=document.createElement('input'),b=make('input',{type:'radio',name:'isolated'});a.type='radio';a.name='isolated';shadow.append(a);b.checked=true;a.checked=true;log('shadow-group',a.checked,b.checked);host.remove();b.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["shadow-group true true"]);
}

#[test]
fn explicit_form_owners_determine_radio_groups_instead_of_ancestor_forms() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const f=make('form'),g=make('form'),a=document.createElement('input'),b=document.createElement('input');a.type=b.type='radio';a.name=b.name='cross';f.id='first';g.id='second';a.setAttribute('form','first');b.setAttribute('form','first');f.append(a);g.append(b);a.checked=true;b.checked=true;log('form-owner',a.checked,b.checked);f.remove();g.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["form-owner false true"]);
}

#[test]
fn nested_synthetic_click_dispatches_have_independent_activation_state() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox'});let count=0;c.addEventListener('click',()=>{if(++count===1){c.checked=false;c.dispatchEvent(new MouseEvent('click'))}log('nested',count,c.checked)});c.dispatchEvent(new MouseEvent('click'));log('nested-after',c.checked);c.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["nested 2 true", "nested 2 true", "nested-after true"]);
}

#[test]
fn cloned_inputs_preserve_checked_dirty_and_indeterminate_state() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const c=document.createElement('input');c.type='checkbox';c.checked=true;c.indeterminate=true;const clone=c.cloneNode();log('clone',clone.checked,clone.indeterminate,clone.defaultChecked);clone.defaultChecked=false;log('dirty-clone',clone.checked);
</script>"#,
    );
    assert_eq!(logs(&report), ["clone true true false", "dirty-clone true"]);
}

#[test]
fn radio_checkedness_tracks_default_attributes_and_name_changes() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const host=document.createElement('div');host.innerHTML='<input type=radio name=x checked><input type=radio name=x checked>';document.body.append(host);const [a,b]=host.querySelectorAll('input');log('defaults',a.checked,b.checked);a.checked=true;log('assigned',a.checked,b.checked);b.name='other';b.checked=true;log('split',a.checked,b.checked);b.name='x';log('renamed',a.checked,b.checked);host.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["defaults false true", "assigned true false", "split true true", "renamed false true"]);
}

#[test]
fn activation_ignores_public_checked_type_and_cancellation_shadows() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const host=document.createElement('div');document.body.append(host);const c=document.createElement('input');c.type='checkbox';host.append(c);const event=new MouseEvent('click',{cancelable:true,bubbles:true});Object.defineProperty(c,'checked',{get(){log('unexpected-getter');return false},set(){log('unexpected-setter')}});Object.defineProperty(event,'type',{value:'fake'});Object.defineProperty(event,'defaultPrevented',{value:true});host.addEventListener('click',()=>log('private-activation',Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'checked').get.call(c)));c.dispatchEvent(event);host.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["private-activation true"]);
}

#[test]
fn input_type_matching_uses_ascii_case_folding_and_invalid_types_default_to_text() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:String.fromCharCode(99,104,101,99,0x212a,98,111,120)});c.dispatchEvent(new MouseEvent('click'));log('invalid-type',c.type,c.checked);c.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["invalid-type text false"]);
}

#[test]
fn only_the_current_first_summary_can_toggle_its_details() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const d=make('details'),s=document.createElement('summary'),second=document.createElement('summary'),child=document.createElement('span');s.append(child);d.append(s,second);second.dispatchEvent(new MouseEvent('click'));log('second-summary',d.open);child.dispatchEvent(new MouseEvent('click'));log('nonbubble-summary',d.open);child.dispatchEvent(new MouseEvent('click',{bubbles:true}));log('bubble-summary',d.open);d.open=false;s.addEventListener('click',()=>{d.prepend(document.createElement('summary'))},{once:true});s.dispatchEvent(new MouseEvent('click'));log('moved-summary',d.open);d.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["second-summary false", "nonbubble-summary false", "bubble-summary true", "moved-summary false"]);
}

#[test]
fn label_default_actions_activate_the_control_once_and_avoid_forwarding_control_clicks() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const label=make('label'),c=document.createElement('input'),child=document.createElement('span');c.type='checkbox';label.append(c,child);let n=0;c.addEventListener('click',()=>{log('label-control',++n,c.checked)});child.dispatchEvent(new MouseEvent('click',{bubbles:true}));log('label-after',c.checked);c.dispatchEvent(new MouseEvent('click',{bubbles:true}));log('direct-after',c.checked);label.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["label-control 1 true", "label-after true", "label-control 2 false", "direct-after false"]);
}

#[test]
fn the_activation_target_survives_parent_changes_during_dispatch() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const host=make('div'),old=document.createElement('details'),fresh=document.createElement('details'),s=document.createElement('summary'),child=document.createElement('span');s.append(child);old.append(s);host.append(old,fresh);child.addEventListener('click',()=>fresh.append(s));child.dispatchEvent(new MouseEvent('click',{bubbles:true}));log('activation-node',old.open,fresh.open);host.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["activation-node false true"]);
}

#[test]
fn public_default_prevented_shadows_do_not_uncancel_default_actions() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a),make=(tag,attrs={})=>{const node=document.createElement(tag);for(const [k,v]of Object.entries(attrs))node.setAttribute(k,v);document.body.append(node);return node};
const c=make('input',{type:'checkbox'});c.addEventListener('click',e=>{e.preventDefault();Object.defineProperty(e,'defaultPrevented',{value:false})});log('private-cancel',c.dispatchEvent(new MouseEvent('click',{cancelable:true})),c.checked);c.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["private-cancel false false"]);
}

#[test]
fn details_toggle_notifications_are_trusted_and_coalesce_changes_in_one_task() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const d=document.createElement('details'),s=document.createElement('summary');d.append(s);document.body.append(d);d.addEventListener('toggle',e=>{log('toggle',e.oldState,e.newState,e.isTrusted,e.bubbles,e.cancelable,e.composed,e.source===null,e.target===d);d.remove()});s.dispatchEvent(new MouseEvent('click'));log('toggle-before',d.open);d.open=false;d.open=true;
</script>"#,
    );
    assert_eq!(logs(&report), ["toggle-before true", "toggle closed open true false false false true true"]);
}

#[test]
fn label_forwarded_clicks_do_not_claim_the_programmatic_click_recursion_flag() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const label=document.createElement('label'),c=document.createElement('input');c.type='checkbox';label.append(c);document.body.append(label);let n=0;c.addEventListener('click',()=>{log('forwarded',++n);if(n<3)c.click()});label.dispatchEvent(new MouseEvent('click'));log('forwarded-after',n,c.checked);label.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["forwarded 1", "forwarded 2", "forwarded-after 2 false"]);
}

#[test]
fn link_activation_queues_navigation_after_the_dispatching_script() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const a=document.createElement('a'),child=document.createElement('span');a.href='#activated';a.append(child);document.body.append(a);child.dispatchEvent(new MouseEvent('click'));log('link-nonbubble',location.hash);child.dispatchEvent(new MouseEvent('click',{bubbles:true}));log('link-before',location.hash);setTimeout(()=>{log('link-after',location.hash);a.remove()},0);
</script>"#,
    );
    assert_eq!(logs(&report), ["link-nonbubble ", "link-before ", "link-after #activated"]);
}

#[test]
fn toggle_events_validate_dictionaries_and_element_sources_in_web_idl_order() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
for(const [label,construct]of[['missing',()=>new ToggleEvent()],['null-options',()=>new ToggleEvent('toggle',null)],['invalid-options',()=>new ToggleEvent('toggle',1)],['invalid-source',()=>new ToggleEvent('toggle',{source:new EventTarget()})]])try{const e=construct();log(label,e.type,e.oldState,e.newState,e.source)}catch(e){log(label,e.name)}
new ToggleEvent({toString(){log('type');return 'toggle'}},{get bubbles(){log('bubbles')},get cancelable(){log('cancelable')},get composed(){log('composed')},get newState(){log('newState');return null},get oldState(){log('oldState');return 'closed'},get source(){log('source');return null}});
</script>"#,
    );
    assert_eq!(
        logs(&report),
        [
            "missing TypeError",
            "null-options toggle   null",
            "invalid-options TypeError",
            "invalid-source TypeError",
            "type",
            "bubbles",
            "cancelable",
            "composed",
            "newState",
            "oldState",
            "source"
        ]
    );
}

#[test]
fn toggle_event_sources_retarget_across_closed_shadow_roots() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const host=document.createElement('div');document.body.append(host);const root=host.attachShadow({mode:'closed'}),child=document.createElement('span');root.append(child);for(const [label,target]of[['host',host],['child',child]])target.addEventListener('toggle',e=>log('source',label,e.source===host?'host':e.source===child?'child':'other'));const event=new ToggleEvent('toggle',{source:child,bubbles:true,composed:true});child.dispatchEvent(event);log('source-after',event.source===host);host.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["source child child", "source host host", "source-after true"]);
}

#[test]
fn details_activation_bypasses_public_attribute_helper_overrides() {
    let (_, report) = visit(
        r#"<script>const log=(...a)=>console.log(...a);
const d=document.createElement('details'),s=document.createElement('summary');d.append(s);document.body.append(d);for(const name of ['getAttribute','hasAttribute','setAttribute','toggleAttribute'])d[name]=()=>{log('unexpected-helper');throw Error('public helper')};s.dispatchEvent(new MouseEvent('click'));log('private-open',Object.getOwnPropertyDescriptor(HTMLDetailsElement.prototype,'open').get.call(d));d.remove();
</script>"#,
    );
    assert_eq!(logs(&report), ["private-open true"]);
}
