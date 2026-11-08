use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(html: &str) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"real answer"}}}}).to_string()).unwrap();
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
fn callback_receiver() {
    let (_, report) = visit(
        r#"<script>(async()=>{return await new Promise(resolve=>setTimeout(function(){'use strict';resolve(this===window)},0));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"true"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn callback_arguments() {
    let (_, report) = visit(
        r#"<script>(async()=>{const arg={x:1};return await new Promise(resolve=>setTimeout(function(a,b){resolve([a===arg,b])},0,arg,'second'));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[true,"second"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn clear_string_id() {
    let (_, report) = visit(
        r#"<script>(async()=>{let ran=false;const id=setTimeout(()=>ran=true,0);clearTimeout(String(id));return await new Promise(resolve=>setTimeout(()=>resolve(ran),20));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"false"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn clear_object_id() {
    let (_, report) = visit(
        r#"<script>(async()=>{let ran=false,n=0;const id=setTimeout(()=>ran=true,0);clearInterval({valueOf(){n++;return id}});return await new Promise(resolve=>setTimeout(()=>resolve([ran,n]),20));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[false,1]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn required_and_idl() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const f of [()=>setTimeout(),()=>setInterval(),()=>setTimeout(Symbol()),()=>setTimeout(()=>{},1n),()=>clearTimeout(Symbol()),()=>clearTimeout(1n),()=>requestAnimationFrame(),()=>requestAnimationFrame('bad')])try{f();out.push('accepted')}catch(e){out.push(e.name)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError","TypeError"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn timer_receivers() {
    let (_, report) = visit(
        r#"<script>(async()=>{const out=[];for(const obj of [null,undefined,{},window])try{const id=setTimeout.call(obj,()=>{},0);clearTimeout(id);out.push('accepted')}catch(e){out.push(e.name)}return out;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["accepted","accepted","TypeError","accepted"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn map_values() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Map.prototype.values;Map.prototype.values=function(){throw Error('public values')};return await new Promise(resolve=>setTimeout(()=>{Map.prototype.values=old;resolve('ran')},0));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#""ran""#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn map_set() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Map.prototype.set;Map.prototype.set=function(){return this};return await new Promise(resolve=>setTimeout(()=>{Map.prototype.set=old;resolve('ran')},0));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#""ran""#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn map_delete() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Map.prototype.delete;Map.prototype.delete=()=>false;let ran=false;const id=setTimeout(()=>ran=true,0);clearTimeout(id);return await new Promise(resolve=>setTimeout(()=>{Map.prototype.delete=old;resolve(ran)},20));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"false"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn math_max() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Math.max;Math.max=()=>Infinity;return await new Promise(resolve=>setTimeout(()=>{Math.max=old;resolve('ran')},0));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#""ran""#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn number_constructor() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Number;window.Number=()=>Infinity;return await new Promise(resolve=>setTimeout(()=>{window.Number=old;resolve('ran')},0));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#""ran""#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn array_iterator_arguments() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Array.prototype[Symbol.iterator];Array.prototype[Symbol.iterator]=function*(){yield 'forged'};return await new Promise(resolve=>setTimeout(function(a,b){Array.prototype[Symbol.iterator]=old;resolve([a,b])},0,'real','second'));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"["real","second"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn date_constructor_and_subclass() {
    let (_, report) = visit(
        r#"<script>(async()=>{class D extends Date{}const d=new D(0);return [Date.prototype.constructor===Date,d instanceof D,d instanceof Date,d.getTime(),Date.length,Date.name];})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[true,true,true,0,7,"Date"]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn date_function_ignores_public_tostring() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Date.prototype.toString;Date.prototype.toString=()=> 'forged';const value=Date();Date.prototype.toString=old;return value==='forged';})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"false"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn date_arguments_ignore_array_iterator() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Array.prototype[Symbol.iterator];Array.prototype[Symbol.iterator]=function*(){yield 999};const value=new Date(0).getTime();Array.prototype[Symbol.iterator]=old;return value;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"0"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn crypto_ignores_math_floor() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Math.floor;Math.floor=()=>0;const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);Math.floor=old;return new Set(bytes).size>1;})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"true"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn random_ignores_math_imul() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=Math.imul;Math.imul=()=>0;const out=[Math.random(),Math.random()];Math.imul=old;return out.some(x=>x!==0);})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"true"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn raf_private_time() {
    let (_, report) = visit(
        r#"<script>(async()=>{const old=performance.now;performance.now=()=>777;return await new Promise(resolve=>requestAnimationFrame(function(value){performance.now=old;resolve([this===window,typeof value==='number'&&value!==777])}));})().then(value=>console.log(JSON.stringify(value)));</script>"#,
    );
    let output = logs(&report);
    assert_eq!(output.len(), 1, "{report}");
    let actual: Value = serde_json::from_str(output[0]).unwrap();
    let expected: Value = serde_json::from_str(r#"[true,true]"#).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn timer_nesting_uses_the_html_seventh_generation_boundary() {
    let (_, report) = visit(
        r#"<script>
const start=Date.now(),out=[];let n=0;function tick(){out.push(Date.now()-start);if(++n<8)setTimeout(tick,0);else console.log(JSON.stringify(out))}setTimeout(tick,0);
</script>"#,
    );
    assert_eq!(logs(&report), ["[0,0,0,0,0,0,4,8]"]);
}

#[test]
fn zero_interval_repeats_enter_timer_nesting_clamping() {
    let (_, report) = visit(
        r#"<script>
const start=Date.now(),out=[];let n=0;const id=setInterval(()=>{out.push(Date.now()-start);if(++n===8){clearInterval(id);console.log(JSON.stringify(out))}},0);
</script>"#,
    );
    assert_eq!(logs(&report), ["[0,0,0,0,0,0,4,8]"]);
}

#[test]
fn interval_rescheduling_follows_the_callback_and_timeout_registration() {
    // HTML initializes a repeated timer after invoking its callback. A new
    // zero-delay timeout registered in that callback precedes the repeat.
    // Firefox currently prioritizes the interval at the same deadline.
    let (_, report) = visit(
        r#"<script>
const out=[];let n=0;const id=setInterval(()=>{out.push('interval');if(++n===1)setTimeout(()=>out.push('timeout'),0);if(n===2){clearInterval(id);setTimeout(()=>console.log(JSON.stringify(out)),20)}},0);
</script>"#,
    );
    assert_eq!(logs(&report), [r#"["interval","timeout","interval"]"#]);
}

#[test]
fn native_timer_count_ignores_public_map_size_getters() {
    let (_, report) = visit(
        r#"<script>
Object.defineProperty(Map.prototype,'size',{get(){return 0}});setInterval(()=>{},604800000);
</script>"#,
    );
    assert_eq!(report["timers"], 1);
}

#[test]
fn unsupported_api_markers_ignore_public_set_methods() {
    let (_, report) = visit(
        r#"<script>
Set.prototype.add=function(){return this};Set.prototype[Symbol.iterator]=function*(){};void crypto.subtle;
</script>"#,
    );
    assert_eq!(report["unmodelled"], json!(["crypto.subtle"]));
}

#[test]
fn date_constructor_cannot_escape_the_virtual_clock() {
    let (_, report) = visit(
        r#"<script>
setTimeout(()=>console.log(new Date().constructor.now()===Date.now()),86400000);
</script>"#,
    );
    assert_eq!(logs(&report), ["true"]);
}

#[test]
fn timer_delay_is_converted_to_a_signed_32_bit_integer() {
    let (_, report) = visit(
        r#"<script>
const start=Date.now();for(const delay of [2.9,2147483648,4294967297,Infinity])setTimeout(()=>console.log(delay,Date.now()-start),delay);
</script>"#,
    );
    assert_eq!(logs(&report), ["2147483648 0", "Infinity 0", "4294967297 1", "2.9 2"]);
}

#[test]
fn date_and_timer_functions_expose_native_metadata() {
    let (_, report) = visit(
        r#"<script>
console.log(JSON.stringify([Object.keys(Date),Object.getOwnPropertyDescriptor(Date,'prototype').writable,setTimeout.length,setInterval.length,clearTimeout.length,clearInterval.length,clearTimeout===clearInterval,Date.now.name]));
</script>"#,
    );
    assert_eq!(logs(&report), [r#"[[],false,1,1,0,0,false,"now"]"#]);
}

#[test]
fn handler_conversion_precedes_delay_conversion_and_execution() {
    let (_, report) = visit(
        r#"<script>
const order=[];window.timerMore=()=>order.push('run');setTimeout({toString(){order.push('handler');return 'timerMore()'}},{valueOf(){order.push('delay');return 0}});setTimeout(()=>console.log(JSON.stringify(order)),20);
</script>"#,
    );
    assert_eq!(logs(&report), [r#"["handler","delay","run"]"#]);
}

#[test]
fn an_interval_can_be_cleared_from_its_callback_with_a_string_id() {
    let (_, report) = visit(
        r#"<script>
let count=0;const id=setInterval(()=>{count++;clearTimeout(String(id));setTimeout(()=>console.log(count),20)},0);
</script>"#,
    );
    assert_eq!(logs(&report), ["1"]);
}

#[test]
fn error_handlers_can_cancel_an_interval_before_it_is_rescheduled() {
    let (_, report) = visit(
        r#"<script>
let n=0,id;window.onerror=()=>{clearInterval(id);setTimeout(()=>console.log(n),20);return true};id=setInterval(()=>{n++;throw Error('expected')},0);
</script>"#,
    );
    assert_eq!(logs(&report), ["1"]);
}

#[test]
fn non_finite_console_numbers_are_not_reported_as_null() {
    let (_, report) = visit(r#"<script>console.log(Infinity,-Infinity,NaN);</script>"#);
    assert_eq!(logs(&report), ["Infinity -Infinity NaN"]);
}

#[test]
fn event_candidates_ignore_public_map_lookup_and_set_membership() {
    let (_, report) = visit(
        r#"<span id=target>tap</span><script>
document.getElementById('target').addEventListener('click',()=>console.log('clicked'));Map.prototype.get=()=>undefined;Set.prototype.has=()=>false;
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked"]);
}

#[test]
fn event_candidates_ignore_public_set_iteration() {
    let (_, report) = visit(
        r#"<span id=target>tap</span><script>
document.getElementById('target').addEventListener('click',()=>console.log('clicked'));Set.prototype[Symbol.iterator]=function*(){};
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked"]);
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
