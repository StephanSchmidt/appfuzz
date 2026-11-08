//! Native Chrome/Firefox event references and trusted-input Chrome CDP controls.
//! Use Web IDL/Firefox for signed MouseEvent.button, arbitrary InputEvent.inputType,
//! ErrorEvent.filename, and the required object promise member; native Firefox
//! coordinate rounding is also used. DOM composed flags, legacy which, focused
//! window behavior and current CSS elapsed-time doubles follow Chrome/specs.
use appfuzz_core::{
    browser::{Browser, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/event_construction.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = Plan::default();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["requests"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn event_empty_dictionaries() {
    assert_eq!(
        visit("event-empty-dictionaries"),
        [
            "Event omitted  false false false",
            "Event undefined  false false false",
            "Event null  false false false",
            "Event object bubbles,cancelable,composed true true true",
            "CustomEvent omitted  false false false",
            "CustomEvent undefined  false false false",
            "CustomEvent null  false false false",
            "CustomEvent object bubbles,cancelable,composed true true true",
            "UIEvent omitted  false false false",
            "UIEvent undefined  false false false",
            "UIEvent null  false false false",
            "UIEvent object bubbles,cancelable,composed true true true",
            "MouseEvent omitted  false false false",
            "MouseEvent undefined  false false false",
            "MouseEvent null  false false false",
            "MouseEvent object bubbles,cancelable,composed true true true",
            "PointerEvent omitted  false false false",
            "PointerEvent undefined  false false false",
            "PointerEvent null  false false false",
            "PointerEvent object bubbles,cancelable,composed true true true",
            "KeyboardEvent omitted  false false false",
            "KeyboardEvent undefined  false false false",
            "KeyboardEvent null  false false false",
            "KeyboardEvent object bubbles,cancelable,composed true true true",
            "FocusEvent omitted  false false false",
            "FocusEvent undefined  false false false",
            "FocusEvent null  false false false",
            "FocusEvent object bubbles,cancelable,composed true true true",
            "InputEvent omitted  false false false",
            "InputEvent undefined  false false false",
            "InputEvent null  false false false",
            "InputEvent object bubbles,cancelable,composed true true true",
            "SubmitEvent omitted  false false false",
            "SubmitEvent undefined  false false false",
            "SubmitEvent null  false false false",
            "SubmitEvent object bubbles,cancelable,composed true true true",
            "ProgressEvent omitted  false false false",
            "ProgressEvent undefined  false false false",
            "ProgressEvent null  false false false",
            "ProgressEvent object bubbles,cancelable,composed true true true",
            "MessageEvent omitted  false false false",
            "MessageEvent undefined  false false false",
            "MessageEvent null  false false false",
            "MessageEvent object bubbles,cancelable,composed true true true"
        ]
    );
}

#[test]
fn event_constructor_parents() {
    assert_eq!(
        visit("event-constructor-parents"),
        [
            "CustomEvent true 0",
            "UIEvent true 0",
            "MouseEvent true 0",
            "PointerEvent true 0",
            "KeyboardEvent true 0",
            "FocusEvent true 0",
            "InputEvent true 0",
            "SubmitEvent true 0",
            "ProgressEvent true 0",
            "MessageEvent true 0"
        ]
    );
}

#[test]
fn listener_empty_dictionaries() {
    assert_eq!(visit("listener-empty-dictionaries"), ["omitted  1", "undefined  1", "null  1", "object capture,once,passive,signal 1"]);
}

#[test]
fn event_constructor_metadata() {
    assert_eq!(
        visit("event-constructor-metadata"),
        [
            "Event Event 1 [object Event] TypeError TypeError",
            "CustomEvent CustomEvent 1 [object CustomEvent] TypeError TypeError",
            "UIEvent UIEvent 1 [object UIEvent] TypeError TypeError",
            "MouseEvent MouseEvent 1 [object MouseEvent] TypeError TypeError",
            "PointerEvent PointerEvent 1 [object PointerEvent] TypeError TypeError",
            "WheelEvent WheelEvent 1 [object WheelEvent] TypeError TypeError",
            "KeyboardEvent KeyboardEvent 1 [object KeyboardEvent] TypeError TypeError",
            "FocusEvent FocusEvent 1 [object FocusEvent] TypeError TypeError",
            "InputEvent InputEvent 1 [object InputEvent] TypeError TypeError",
            "SubmitEvent SubmitEvent 1 [object SubmitEvent] TypeError TypeError",
            "ProgressEvent ProgressEvent 1 [object ProgressEvent] TypeError TypeError",
            "HashChangeEvent HashChangeEvent 1 [object HashChangeEvent] TypeError TypeError",
            "PopStateEvent PopStateEvent 1 [object PopStateEvent] TypeError TypeError",
            "ErrorEvent ErrorEvent 1 [object ErrorEvent] TypeError TypeError",
            "ToggleEvent ToggleEvent 1 [object ToggleEvent] TypeError TypeError",
            "MessageEvent MessageEvent 1 [object MessageEvent] TypeError TypeError"
        ]
    );
}

#[test]
fn event_dictionary_order() {
    assert_eq!(
        visit("event-dictionary-order"),
        [
            "Event bubbles,cancelable,composed",
            "CustomEvent bubbles,cancelable,composed,detail",
            "UIEvent bubbles,cancelable,composed,detail,view",
            "MouseEvent bubbles,cancelable,composed,detail,view,altKey,ctrlKey,metaKey,modifierAltGraph,modifierCapsLock,modifierFn,modifierNumLock,modifierScrollLock,modifierSymbol,shiftKey,button,buttons,clientX,clientY,movementX,movementY,relatedTarget,screenX,screenY",
            "PointerEvent bubbles,cancelable,composed,detail,view,altKey,ctrlKey,metaKey,modifierAltGraph,modifierCapsLock,modifierFn,modifierNumLock,modifierScrollLock,modifierSymbol,shiftKey,button,buttons,clientX,clientY,movementX,movementY,relatedTarget,screenX,screenY,altitudeAngle,azimuthAngle,height,isPrimary,pointerId,pointerType,pressure,tangentialPressure,tiltX,tiltY,twist,width",
            "WheelEvent bubbles,cancelable,composed,detail,view,altKey,ctrlKey,metaKey,modifierAltGraph,modifierCapsLock,modifierFn,modifierNumLock,modifierScrollLock,modifierSymbol,shiftKey,button,buttons,clientX,clientY,movementX,movementY,relatedTarget,screenX,screenY",
            "KeyboardEvent bubbles,cancelable,composed,detail,view,altKey,ctrlKey,metaKey,modifierAltGraph,modifierCapsLock,modifierFn,modifierNumLock,modifierScrollLock,modifierSymbol,shiftKey,charCode,code,isComposing,key,keyCode,location,repeat",
            "FocusEvent bubbles,cancelable,composed,detail,view,relatedTarget",
            "InputEvent bubbles,cancelable,composed,detail,view,data,dataTransfer,inputType,isComposing,targetRanges",
            "SubmitEvent bubbles,cancelable,composed,submitter",
            "ProgressEvent bubbles,cancelable,composed,lengthComputable,loaded,total",
            "HashChangeEvent bubbles,cancelable,composed,newURL,oldURL",
            "PopStateEvent bubbles,cancelable,composed,state",
            "ErrorEvent bubbles,cancelable,composed,colno,error,filename,lineno,message",
            "ToggleEvent bubbles,cancelable,composed,newState,oldState,source",
            "MessageEvent bubbles,cancelable,composed,data,lastEventId,origin,ports,source"
        ]
    );
}

#[test]
fn event_scalar_conversion() {
    assert_eq!(
        visit("event-scalar-conversion"),
        [
            "UIEvent detail=-2,view=null",
            "MouseEvent button=-1,buttons=1,clientX=2,screenY=-3",
            "PointerEvent pointerId=0,pointerType=,isPrimary=false,width=1,height=1,pressure=0,tiltX=0,twist=0",
            "PointerEvent pointerId=2,width=1.9,height=3,pressure=0.5",
            "KeyboardEvent key=7,code=5,location=2,repeat=true,isComposing=true",
            "ProgressEvent loaded=3.7,total=9.8,lengthComputable=true",
            "HashChangeEvent oldURL=null,newURL=7",
            "InputEvent data=7,inputType=8,isComposing=true"
        ]
    );
}

#[test]
fn event_private_click() {
    assert_eq!(visit("event-private-click"), ["click,-1,,false,0 0"]);
}

#[test]
fn event_readonly_and_brand() {
    assert_eq!(
        visit("event-readonly-and-brand"),
        [
            "UIEvent detail true false TypeError",
            "MouseEvent clientX true false TypeError",
            "PointerEvent pointerId true false TypeError",
            "KeyboardEvent key true false TypeError",
            "ProgressEvent loaded true false TypeError",
            "InputEvent data true false TypeError"
        ]
    );
}

#[test]
fn event_numeric_domains() {
    assert_eq!(
        visit("event-numeric-domains"),
        [
            "MouseEvent -2.9 -2 -3 -3",
            "MouseEvent -1 -1 -1 -1",
            "MouseEvent 6 6 6 6",
            "MouseEvent 65535 -1 65535 65535",
            "MouseEvent Infinity TypeError",
            "MouseEvent NaN TypeError",
            "PointerEvent -2.9 -2 -2.9 -2.9",
            "PointerEvent -1 -1 -1 -1",
            "PointerEvent 6 6 6 6",
            "PointerEvent 65535 -1 65535 65535",
            "PointerEvent Infinity TypeError",
            "PointerEvent NaN TypeError",
            "ProgressEvent 0.3 0.3 0.3",
            "ProgressEvent Infinity TypeError",
            "ProgressEvent NaN TypeError",
            "PointerEvent 0.3 0.30000001192092896 0.3",
            "PointerEvent Infinity TypeError",
            "PointerEvent NaN TypeError"
        ]
    );
}

#[test]
fn event_promise_required() {
    assert_eq!(
        visit("event-promise-required"),
        ["missing TypeError", "null TypeError", "number TypeError", "object ok true undefined", "promise ok true function"]
    );
}

#[test]
fn event_coordinates() {
    assert_eq!(
        visit("event-coordinates"),
        [
            "MouseEvent clientX=2,clientY=-3,screenX=3,screenY=-4,pageX=2,pageY=-3,x=2,y=-3,offsetX=2,offsetY=-3,movementX=0,movementY=0",
            "PointerEvent clientX=2.9,clientY=-2.9,screenX=3.5,screenY=-3.5,pageX=2.9,pageY=-2.9,x=2.9,y=-2.9,offsetX=2.9,offsetY=-2.9,movementX=0,movementY=0",
            "WheelEvent clientX=2,clientY=-3,screenX=3,screenY=-4,pageX=2,pageY=-3,x=2,y=-3,offsetX=2,offsetY=-3,movementX=0,movementY=0",
            "DragEvent clientX=2,clientY=-3,screenX=3,screenY=-4,pageX=2,pageY=-3,x=2,y=-3,offsetX=2,offsetY=-3,movementX=0,movementY=0"
        ]
    );
}

#[test]
fn event_pointer_orientation() {
    assert_eq!(
        visit("event-pointer-orientation"),
        [
            "{} 0,0,1.57079633,0",
            "{\"tiltX\":45} 45,0,0.78539816,0",
            "{\"tiltY\":45} 0,45,0.78539816,1.57079633",
            "{\"tiltX\":90,\"tiltY\":0} 90,0,0,0",
            "{\"altitudeAngle\":0.7853981633974483,\"azimuthAngle\":0} 45,0,0.78539816,0",
            "{\"altitudeAngle\":0.7853981633974483,\"azimuthAngle\":1.5707963267948966} 0,45,0.78539816,1.57079633"
        ]
    );
}

#[test]
fn event_internal_promise() {
    assert_eq!(visit("event-internal-promise"), ["true 0"]);
}

#[test]
fn event_focus_fields() {
    assert_eq!(
        visit("event-focus-fields"),
        [
            "focus,one,,false,true,true",
            "focusin,one,,true,true,true",
            "blur,one,two,false,true,true",
            "focusout,one,two,true,true,true",
            "focus,two,one,false,true,true",
            "focusin,two,one,true,true,true",
            "blur,two,,false,true,true",
            "focusout,two,,true,true,true"
        ]
    );
}

#[test]
fn event_extra_constructors() {
    assert_eq!(
        visit("event-extra-constructors"),
        [
            "HashChangeEvent [object HashChangeEvent] 0",
            "PopStateEvent [object PopStateEvent] 0",
            "ErrorEvent [object ErrorEvent] 0",
            "ToggleEvent [object ToggleEvent] 0",
            "StorageEvent [object StorageEvent] 0",
            "TransitionEvent [object TransitionEvent] 0",
            "AnimationEvent [object AnimationEvent] 0",
            "CompositionEvent [object CompositionEvent] 0",
            "ClipboardEvent [object ClipboardEvent] 0",
            "DragEvent [object DragEvent] 0",
            "FormDataEvent true 0"
        ]
    );
}

#[test]
fn event_reflect_order() {
    assert_eq!(
        visit("event-reflect-order"),
        ["Event prototype,type,bubbles", "CustomEvent prototype,type,bubbles", "MouseEvent prototype,type,bubbles", "MessageEvent prototype,type,bubbles"]
    );
}

#[test]
fn event_signal_parents() {
    assert_eq!(visit("event-signal-parents"), ["false false 0"]);
}

#[test]
fn event_private_brand_record() {
    assert_eq!(visit("event-private-brand-record"), ["TypeError TypeError 0"]);
}

#[test]
fn event_legacy_which() {
    assert_eq!(
        visit("event-legacy-which"),
        [
            "UIEvent probe 0",
            "UIEvent click 0",
            "UIEvent keydown 0",
            "UIEvent keypress 0",
            "MouseEvent probe 2",
            "MouseEvent click 2",
            "MouseEvent keydown 2",
            "MouseEvent keypress 2",
            "PointerEvent probe 2",
            "PointerEvent click 2",
            "PointerEvent keydown 2",
            "PointerEvent keypress 2",
            "KeyboardEvent probe 7",
            "KeyboardEvent click 7",
            "KeyboardEvent keydown 7",
            "KeyboardEvent keypress 7"
        ]
    );
}

#[test]
fn event_focus_receivers() {
    assert_eq!(visit("event-focus-receivers"), ["focus TypeError", "blur TypeError", "true 1"]);
}

#[test]
fn event_focusability() {
    assert_eq!(
        visit("event-focusability"),
        [
            "input true 1",
            "disabled false 0",
            "hidden-input false 0",
            "div false 0",
            "tab true 1",
            "bad-tab false 0",
            "anchor true 1",
            "no-href false 0",
            "hidden false 0",
            "inert false 0",
            "detached false 0"
        ]
    );
}

#[test]
fn event_active_element_private() {
    assert_eq!(visit("event-active-element-private"), ["connected true 0", "body true 0"]);
}

#[test]
fn event_shadow_active_element() {
    assert_eq!(visit("event-shadow-active-element"), ["true true", "true"]);
}

#[test]
fn event_pointer_init_members() {
    assert_eq!(visit("event-pointer-init-members"), ["coalescedEvents,persistentDeviceId,predictedEvents number function function"]);
}

#[test]
fn event_member_metadata() {
    assert_eq!(
        visit("event-member-metadata"),
        [
            "UIEvent detail get detail 0 false true true",
            "MouseEvent clientX get clientX 0 false true true",
            "PointerEvent pointerId get pointerId 0 false true true",
            "KeyboardEvent key get key 0 false true true",
            "InputEvent data get data 0 false true true",
            "MouseEvent getModifierState getModifierState 1 false",
            "KeyboardEvent getModifierState getModifierState 1 false",
            "PointerEvent getCoalescedEvents getCoalescedEvents 0 false",
            "PointerEvent getPredictedEvents getPredictedEvents 0 false",
            "InputEvent getTargetRanges getTargetRanges 0 false"
        ]
    );
}

#[test]
fn event_string_scalars() {
    assert_eq!(
        visit("event-string-scalars"),
        [
            "InputEvent data 55296",
            "StorageEvent url 65533",
            "HashChangeEvent newURL 55296",
            "ErrorEvent filename 65533",
            "CompositionEvent data 55296",
            "KeyboardEvent key 55296"
        ]
    );
}

#[test]
fn event_extra_scalars() {
    assert_eq!(
        visit("event-extra-scalars"),
        ["AnimationEvent 0.3", "TransitionEvent 0.3", "StorageEvent string 7 2 3 true", "TouchEvent [object TouchList] 0  get length item"]
    );
}

fn physical_pointer(html: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["requests"], json!([]), "{report}");
    assert_eq!(report["actions"].as_array().unwrap().len(), 1, "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn physical_pointer_normal() {
    assert_eq!(
        physical_pointer(include_str!("fixtures/physical_pointer_normal.html")),
        [
            "pointerdown 0 1 1 mouse true 0.5 0 true true true",
            "mousedown 0 1     1 true true true",
            "focus       0 true true true",
            "pointerup 0 0 1 mouse true 0 0 true true true",
            "mouseup 0 0     1 true true true",
            "click 0 0 1 mouse false 0 1 true true true",
            "reads 0"
        ]
    );
}

#[test]
fn physical_pointer_pointerdown() {
    assert_eq!(
        physical_pointer(include_str!("fixtures/physical_pointer_pointerdown.html")),
        [
            "pointerdown 0 1 1 mouse true 0.5 0 true true true",
            "pointerup 0 0 1 mouse true 0 0 true true true",
            "click 0 0 1 mouse false 0 1 true true true",
            "reads 0"
        ]
    );
}

#[test]
fn physical_pointer_mousedown() {
    assert_eq!(
        physical_pointer(include_str!("fixtures/physical_pointer_mousedown.html")),
        [
            "pointerdown 0 1 1 mouse true 0.5 0 true true true",
            "mousedown 0 1     1 true true true",
            "pointerup 0 0 1 mouse true 0 0 true true true",
            "mouseup 0 0     1 true true true",
            "click 0 0 1 mouse false 0 1 true true true",
            "reads 0"
        ]
    );
}
