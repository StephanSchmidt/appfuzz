//! Input/textarea current values, defaults, cloning and resets in the bundled browser.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};

fn visit(script: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/", "html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn input_dirty() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('input-dirty',()=>{const b=mount('<form><input name=a value=original></form>'),i=b.querySelector('input');i.value='typed';i.setAttribute('value','changed');log('input-dirty',inputState(i),entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["input-dirty [\"typed\",\"changed\",\"changed\"] [[\"a\",\"typed\"]]"]);
}

#[test]
fn textarea_dirty() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('textarea-dirty',()=>{const b=mount('<form><textarea name=a>original</textarea></form>'),i=b.querySelector('textarea');i.value='typed';i.textContent='changed';log('textarea-dirty',areaState(i),entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["textarea-dirty [\"typed\",\"changed\",\"changed\"] [[\"a\",\"typed\"]]"]);
}

#[test]
fn input_default() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('input-default',()=>{const b=mount('<form><input name=a value=original></form>'),i=b.querySelector('input');i.defaultValue='updated';log('input-default-clean',inputState(i));i.value='typed';i.defaultValue='later';log('input-default-dirty',inputState(i));i.removeAttribute('value');log('input-default-removed',inputState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "input-default-clean [\"updated\",\"updated\",\"updated\"]",
            "input-default-dirty [\"typed\",\"later\",\"later\"]",
            "input-default-removed [\"typed\",\"\",null]"
        ]
    );
}

#[test]
fn textarea_default() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('textarea-default',()=>{const b=mount('<form><textarea name=a>original</textarea></form>'),i=b.querySelector('textarea');i.defaultValue='updated';log('textarea-default-clean',areaState(i));i.value='typed';i.defaultValue='later';log('textarea-default-dirty',areaState(i));i.firstChild.data='changed';log('textarea-default-character',areaState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "textarea-default-clean [\"updated\",\"updated\",\"updated\"]",
            "textarea-default-dirty [\"typed\",\"later\",\"later\"]",
            "textarea-default-character [\"typed\",\"changed\",\"changed\"]"
        ]
    );
}

#[test]
fn null_conversion() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('null-conversion',()=>{const b=mount('<input value=old><textarea>old</textarea>');for(const i of b.querySelectorAll('input,textarea')){i.value=null;log('null-conversion-value',i.localName,JSON.stringify(i.value));i.defaultValue=null;log('null-conversion-default',i.localName,JSON.stringify(i.defaultValue))}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "null-conversion-value input \"\"",
            "null-conversion-default input \"null\"",
            "null-conversion-value textarea \"\"",
            "null-conversion-default textarea \"null\""
        ]
    );
}

#[test]
fn failed_conversion() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('failed-conversion',()=>{const b=mount('<input value=old><textarea>old</textarea>');for(const i of b.querySelectorAll('input,textarea')){try{i.value={toString(){throw Error('stop')}}}catch(e){log('failed-conversion-error',i.localName,e.name)}i.defaultValue='new';log('failed-conversion',i.localName,i.value)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        ["failed-conversion-error input Error", "failed-conversion input new", "failed-conversion-error textarea Error", "failed-conversion textarea new"]
    );
}

#[test]
fn coercion_once() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('coercion-once',()=>{const b=mount('<input><textarea></textarea>');for(const i of b.querySelectorAll('input,textarea')){let reads=0;i.value={toString(){reads++;return 'set'}};log('coercion-once',i.localName,reads,i.value)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["coercion-once input 1 set", "coercion-once textarea 1 set"]);
}

#[test]
fn value_modes() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('value-modes',()=>{const b=mount('<form></form>'),f=b.querySelector('form');for(const type of ['text','hidden','checkbox','radio','submit','reset','button','image','file']){const i=document.createElement('input');i.type=type;i.name=type;f.append(i);log('value-modes-default',type,inputState(i));try{i.value='set';log('value-modes-set',type,inputState(i))}catch(e){log('value-modes-error',type,e.name)}}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "value-modes-default text [\"\",\"\",null]",
            "value-modes-set text [\"set\",\"\",null]",
            "value-modes-default hidden [\"\",\"\",null]",
            "value-modes-set hidden [\"set\",\"set\",\"set\"]",
            "value-modes-default checkbox [\"on\",\"\",null]",
            "value-modes-set checkbox [\"set\",\"set\",\"set\"]",
            "value-modes-default radio [\"on\",\"\",null]",
            "value-modes-set radio [\"set\",\"set\",\"set\"]",
            "value-modes-default submit [\"\",\"\",null]",
            "value-modes-set submit [\"set\",\"set\",\"set\"]",
            "value-modes-default reset [\"\",\"\",null]",
            "value-modes-set reset [\"set\",\"set\",\"set\"]",
            "value-modes-default button [\"\",\"\",null]",
            "value-modes-set button [\"set\",\"set\",\"set\"]",
            "value-modes-default image [\"\",\"\",null]",
            "value-modes-set image [\"set\",\"set\",\"set\"]",
            "value-modes-default file [\"\",\"\",null]",
            "value-modes-error file InvalidStateError"
        ]
    );
}

#[test]
fn type_transitions() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('type-transitions',()=>{const b=mount('<input value=original>'),i=b.querySelector('input');i.value='typed';i.type='hidden';log('type-transitions-hidden',inputState(i));i.type='text';i.defaultValue='later';log('type-transitions-text',inputState(i));i.value='secret';i.type='file';log('type-transitions-file',inputState(i));i.type='text';log('type-transitions-restored',inputState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "type-transitions-hidden [\"typed\",\"typed\",\"typed\"]",
            "type-transitions-text [\"later\",\"later\",\"later\"]",
            "type-transitions-file [\"\",\"later\",\"later\"]",
            "type-transitions-restored [\"later\",\"later\",\"later\"]"
        ]
    );
}

#[test]
fn type_attribute_transition() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('type-attribute-transition',()=>{const b=mount('<input value=original>'),i=b.querySelector('input');i.value='typed';i.setAttribute('type','checkbox');log('type-attribute-transition',inputState(i));i.setAttribute('value','checked-value');i.removeAttribute('type');log('type-attribute-transition-restored',inputState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "type-attribute-transition [\"typed\",\"typed\",\"typed\"]",
            "type-attribute-transition-restored [\"checked-value\",\"checked-value\",\"checked-value\"]"
        ]
    );
}

#[test]
fn file_empty() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('file-empty',()=>{const b=mount('<input type=file value=not-a-file>'),i=b.querySelector('input');for(const v of ['x',null,''])try{i.value=v;log('file-empty-value',JSON.stringify(v),inputState(i))}catch(e){log('file-empty-error',JSON.stringify(v),e.name)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "file-empty-error \"x\" InvalidStateError",
            "file-empty-value null [\"\",\"not-a-file\",\"not-a-file\"]",
            "file-empty-value \"\" [\"\",\"not-a-file\",\"not-a-file\"]"
        ]
    );
}

#[test]
fn input_clone() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('input-clone',()=>{const b=mount('<input value=original>'),i=b.querySelector('input');i.value='typed';i.defaultValue='default';for(const deep of [false,true]){const c=i.cloneNode(deep);c.setAttribute('value','changed');log('input-clone',deep,inputState(c))}const c=document.importNode(i,true);log('input-clone-import',inputState(c))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "input-clone false [\"typed\",\"changed\",\"changed\"]",
            "input-clone true [\"typed\",\"changed\",\"changed\"]",
            "input-clone-import [\"typed\",\"default\",\"default\"]"
        ]
    );
}

#[test]
fn textarea_clone() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('textarea-clone',()=>{const b=mount('<textarea>original</textarea>'),i=b.querySelector('textarea');i.value='typed';for(const deep of [false,true]){const c=i.cloneNode(deep);log('textarea-clone',deep,areaState(c));c.defaultValue='changed';log('textarea-clone-default',deep,areaState(c))}log('textarea-clone-import',areaState(document.importNode(i,true)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "textarea-clone false [\"typed\",\"\",\"\"]",
            "textarea-clone-default false [\"typed\",\"changed\",\"changed\"]",
            "textarea-clone true [\"typed\",\"original\",\"original\"]",
            "textarea-clone-default true [\"typed\",\"changed\",\"changed\"]",
            "textarea-clone-import [\"typed\",\"original\",\"original\"]"
        ]
    );
}

#[test]
fn textarea_clean_clone() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('textarea-clean-clone',()=>{const b=mount('<textarea>original</textarea>'),i=b.querySelector('textarea'),c=i.cloneNode(false);log('textarea-clean-clone',areaState(c));c.textContent='';log('textarea-clean-clone-empty',areaState(c))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["textarea-clean-clone [\"\",\"\",\"\"]", "textarea-clean-clone-empty [\"\",\"\",\"\"]"]);
}

#[test]
fn textarea_newlines() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('textarea-newlines',()=>{const b=mount('<form><textarea name=a></textarea></form>'),i=b.querySelector('textarea');i.value='a\r\nb\rc\nd';log('textarea-newlines',areaState(i),i.textLength,entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["textarea-newlines [\"a\\nb\\nc\\nd\",\"\",\"\"] 7 [[\"a\",\"a\\nb\\nc\\nd\"]]"]);
}

#[test]
fn text_newlines() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('text-newlines',()=>{const b=mount('<form><input name=a value="a&#13;&#10;b"></form>'),i=b.querySelector('input');log('text-newlines-initial',inputState(i));i.value='c\r\nd\re\nf';log('text-newlines-set',inputState(i),entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["text-newlines-initial [\"ab\",\"a\\r\\nb\",\"a\\r\\nb\"]", "text-newlines-set [\"cdef\",\"a\\r\\nb\",\"a\\r\\nb\"] [[\"a\",\"cdef\"]]"]);
}

#[test]
fn textarea_descendants() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('textarea-descendants',()=>{const b=mount('<textarea>first</textarea>'),i=b.querySelector('textarea'),span=document.createElement('span');span.textContent='not-direct';i.append(span,document.createTextNode('last'));log('textarea-descendants',areaState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["textarea-descendants [\"firstlast\",\"firstlast\",\"firstnot-directlast\"]"]);
}

#[test]
fn reset_values() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-values',()=>{const b=mount('<form id=f><input name=a value=initial><textarea name=b>original</textarea><input type=checkbox name=c checked></form><input form=f name=outside value=first>'),f=b.querySelector('form'),i=f.querySelector('input'),t=f.querySelector('textarea'),c=f.querySelector('[type=checkbox]'),o=b.querySelector('[name=outside]');i.value='typed';t.value='typed-area';o.value='typed-out';c.checked=false;f.reset();log('reset-values',inputState(i),areaState(t),inputState(o),c.checked,entries(new FormData(f)));i.defaultValue='later';log('reset-values-clean',i.value)});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "reset-values [\"initial\",\"initial\",\"initial\"] [\"original\",\"original\",\"original\"] [\"first\",\"first\",\"first\"] true [[\"a\",\"initial\"],[\"b\",\"original\"],[\"c\",\"on\"],[\"outside\",\"first\"]]",
            "reset-values-clean later"
        ]
    );
}

#[test]
fn reset_cancel() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-cancel',()=>{const b=mount('<form><input name=a value=initial></form>'),f=b.querySelector('form'),i=f.querySelector('input');i.value='typed';f.addEventListener('reset',e=>{log('reset-cancel-flags',e.bubbles,e.cancelable,e.composed,e.isTrusted);e.preventDefault()});f.reset();log('reset-cancel',inputState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-cancel-flags true true false true", "reset-cancel [\"typed\",\"initial\",\"initial\"]"]);
}

#[test]
fn reset_event_order() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-event-order',()=>{const b=mount('<form><input name=a value=initial></form>'),f=b.querySelector('form'),i=f.querySelector('input');i.value='typed';f.addEventListener('reset',()=>{log('reset-event-order-before',i.value);i.defaultValue='event-default'});f.reset();log('reset-event-order-after',inputState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-event-order-before typed", "reset-event-order-after [\"event-default\",\"event-default\",\"event-default\"]"]);
}

#[test]
fn reset_reentrant() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-reentrant',()=>{const b=mount('<form><input value=initial></form>'),f=b.querySelector('form');let calls=0;f.addEventListener('reset',()=>{calls++;if(calls<3)f.reset()});f.reset();log('reset-reentrant',calls)});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-reentrant 1"]);
}

#[test]
fn reset_private() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-private',()=>{const b=mount('<form><input name=a value=initial></form>'),f=b.querySelector('form'),i=f.querySelector('input');i.value='typed';Object.defineProperty(i,'value',{get(){throw Error('public value')},set(){throw Error('public value')}});f.querySelectorAll=()=>{throw Error('public query')};f.dispatchEvent=()=>{throw Error('public event')};f.reset();log('reset-private',entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-private [[\"a\",\"initial\"]]"]);
}

#[test]
fn reset_click() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-click',()=>{const b=mount('<form><input name=a value=initial><button type=reset>Reset</button></form>'),f=b.querySelector('form'),i=f.querySelector('input');i.value='typed';f.reset=()=>{throw Error('public reset')};f.querySelector('button').click();log('reset-click',i.value)});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-click initial"]);
}

#[test]
fn value_brand() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('value-brand',()=>{for(const [label,C] of [['input',HTMLInputElement],['textarea',HTMLTextAreaElement]])for(const key of ['value','defaultValue']){const d=Object.getOwnPropertyDescriptor(C.prototype,key);log('value-brand-descriptor',label,key,typeof d?.get,typeof d?.set);for(const operation of ['get','set'])try{d[operation].call({},'x');log('value-brand','accepted')}catch(e){log('value-brand',label,key,operation,e.name)}}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "value-brand-descriptor input value function function",
            "value-brand input value get TypeError",
            "value-brand input value set TypeError",
            "value-brand-descriptor input defaultValue function function",
            "value-brand input defaultValue get TypeError",
            "value-brand input defaultValue set TypeError",
            "value-brand-descriptor textarea value function function",
            "value-brand textarea value get TypeError",
            "value-brand textarea value set TypeError",
            "value-brand-descriptor textarea defaultValue function function",
            "value-brand textarea defaultValue get TypeError",
            "value-brand textarea defaultValue set TypeError"
        ]
    );
}

#[test]
fn value_mutations() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('value-mutations',()=>{const b=mount('<input value=default><textarea>default</textarea>'),observer=new MutationObserver(()=>{});observer.observe(b,{subtree:true,attributes:true,childList:true,characterData:true});b.querySelector('input').value='typed';b.querySelector('textarea').value='typed';log('value-mutations',observer.takeRecords().length,b.querySelector('input').outerHTML,b.querySelector('textarea').outerHTML);observer.disconnect()});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["value-mutations 0 <input value=\"default\"> <textarea>default</textarea>"]);
}

#[test]
fn default_private() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('default-private',()=>{const b=mount('<input value=old><textarea>old</textarea>'),i=b.querySelector('input'),t=b.querySelector('textarea');i.setAttribute=()=>{throw Error('public attr')};t.appendChild=t.replaceChildren=()=>{throw Error('public children')};i.defaultValue='new';t.defaultValue='new';log('default-private',inputState(i),areaState(t))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["default-private [\"new\",\"new\",\"new\"] [\"new\",\"new\",\"new\"]"]);
}

#[test]
fn adoption_value() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('adoption-value',()=>{const b=mount('<input value=default><textarea>default</textarea>'),other=new DOMParser().parseFromString('<!doctype html><title>other</title>','text/html');for(const i of b.querySelectorAll('input,textarea')){i.value='typed';other.body.appendChild(i);i.defaultValue='new';log('adoption-value',i.localName,i.value,i.defaultValue)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["adoption-value input typed new", "adoption-value textarea typed new"]);
}

#[test]
fn reset_select() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-select',()=>{const b=mount('<form><select name=a><option value=one>One</option><option value=two selected>Two</option></select></form>'),f=b.querySelector('form'),s=b.querySelector('select');s.value='one';f.reset();log('reset-select',s.value,entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-select two [[\"a\",\"two\"]]"]);
}

#[test]
fn conversion_type_change() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('conversion-type-change',()=>{const b=mount('<input value=default>'),i=b.querySelector('input');i.value={toString(){i.type='hidden';return 'set'}};log('conversion-type-change',inputState(i),i.type)});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["conversion-type-change [\"set\",\"set\",\"set\"] hidden"]);
}

#[test]
fn reset_foreign() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-foreign',()=>{const b=mount('<form id=f><input name=own value=default><input name=foreign form=g value=original></form><form id=g></form>'),f=b.querySelector('#f'),i=f.querySelector('[name=own]'),foreign=f.querySelector('[name=foreign]');i.value='typed';foreign.value='foreign-typed';f.reset();log('reset-foreign',i.value,foreign.value,entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-foreign default foreign-typed [[\"own\",\"default\"]]"]);
}

#[test]
fn reset_nested_foreign_select() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('reset-nested-foreign-select',()=>{const b=mount('<form id=f><select name=own><option value=a selected>A</option></select></form><form id=g></form>'),f=b.querySelector('#f'),outer=f.querySelector('select'),inner=document.createElement('select');inner.name='foreign';inner.setAttribute('form','g');inner.innerHTML='<option selected value=x>X</option><option value=y>Y</option>';outer.appendChild(inner);inner.value='y';f.reset();log('reset-nested-foreign-select',inner.value,entries(new FormData(b.querySelector('#g'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["reset-nested-foreign-select y [[\"foreign\",\"y\"]]"]);
}

#[test]
fn input_text_types() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('input-text-types',()=>{const b=mount('<form></form>'),f=b.querySelector('form');for(const type of ['text','search','tel','password','url','email']){const i=document.createElement('input');i.type=type;i.name=type;f.append(i);i.value=' \ta\r\nb \t';log('input-text-types',type,JSON.stringify(i.value))}const i=document.createElement('input');i.type='email';i.multiple=true;i.setAttribute('multiple','');i.value=' a@x , b@y \t';log('input-text-types-multiple',i.value)});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "input-text-types text \" \\tab \\t\"",
            "input-text-types search \" \\tab \\t\"",
            "input-text-types tel \" \\tab \\t\"",
            "input-text-types password \" \\tab \\t\"",
            "input-text-types url \"ab\"",
            "input-text-types email \"ab\"",
            "input-text-types-multiple a@x,b@y"
        ]
    );
}

#[test]
fn text_type_preserve() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('text-type-preserve',()=>{const b=mount('<input type=url value="  x  ">'),i=b.querySelector('input');log('text-type-preserve-url',inputState(i));i.type='text';log('text-type-preserve-text',inputState(i))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["text-type-preserve-url [\"x\",\"  x  \",\"  x  \"]", "text-type-preserve-text [\"  x  \",\"  x  \",\"  x  \"]"]);
}

#[test]
fn value_reentrant_default() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('value-reentrant-default',()=>{const b=mount('<input value=old><textarea>old</textarea>');for(const i of b.querySelectorAll('input,textarea')){i.value={toString(){i.defaultValue='new-default';return 'converted'}};log('value-reentrant-default',i.localName,i.value,i.defaultValue)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["value-reentrant-default input converted new-default", "value-reentrant-default textarea converted new-default"]);
}

#[test]
fn private_current() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('private-current',()=>{const b=mount('<form><input name=a value=default><textarea name=b>default</textarea></form>'),f=b.querySelector('form');for(const i of f.querySelectorAll('input,textarea')){i.value='typed';Object.defineProperty(i,'value',{get(){throw Error('public value')},set(){throw Error('public value')}});i.defaultValue='changed'}log('private-current',entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["private-current [[\"a\",\"typed\"],[\"b\",\"typed\"]]"]);
}

#[test]
fn value_type_matrix() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('value-type-matrix',()=>{for(const dirty of [false,true])for(const from of ['text','url','email','hidden','checkbox','file'])for(const to of ['text','url','email','hidden','checkbox','file']){const b=mount('<input type="'+from+'" value="  original  ">'),i=b.querySelector('input');if(dirty)i.value=from==='file'?'':'  typed  ';i.type=to;log('value-type-matrix',dirty,from,to,inputState(i));b.remove();active=null}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "value-type-matrix false text text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false text url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false text email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false text hidden [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false text checkbox [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false text file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix false url text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false url url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false url email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false url hidden [\"original\",\"original\",\"original\"]",
            "value-type-matrix false url checkbox [\"original\",\"original\",\"original\"]",
            "value-type-matrix false url file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix false email text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false email url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false email email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false email hidden [\"original\",\"original\",\"original\"]",
            "value-type-matrix false email checkbox [\"original\",\"original\",\"original\"]",
            "value-type-matrix false email file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix false hidden text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false hidden url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false hidden email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false hidden hidden [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false hidden checkbox [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false hidden file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix false checkbox text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false checkbox url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false checkbox email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false checkbox hidden [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false checkbox checkbox [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false checkbox file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix false file text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false file url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false file email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix false file hidden [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false file checkbox [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix false file file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix true text text [\"  typed  \",\"  original  \",\"  original  \"]",
            "value-type-matrix true text url [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true text email [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true text hidden [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true text checkbox [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true text file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix true url text [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true url url [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true url email [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true url hidden [\"typed\",\"typed\",\"typed\"]",
            "value-type-matrix true url checkbox [\"typed\",\"typed\",\"typed\"]",
            "value-type-matrix true url file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix true email text [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true email url [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true email email [\"typed\",\"  original  \",\"  original  \"]",
            "value-type-matrix true email hidden [\"typed\",\"typed\",\"typed\"]",
            "value-type-matrix true email checkbox [\"typed\",\"typed\",\"typed\"]",
            "value-type-matrix true email file [\"\",\"  original  \",\"  original  \"]",
            "value-type-matrix true hidden text [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true hidden url [\"typed\",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true hidden email [\"typed\",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true hidden hidden [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true hidden checkbox [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true hidden file [\"\",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true checkbox text [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true checkbox url [\"typed\",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true checkbox email [\"typed\",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true checkbox hidden [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true checkbox checkbox [\"  typed  \",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true checkbox file [\"\",\"  typed  \",\"  typed  \"]",
            "value-type-matrix true file text [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix true file url [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix true file email [\"original\",\"  original  \",\"  original  \"]",
            "value-type-matrix true file hidden [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix true file checkbox [\"  original  \",\"  original  \",\"  original  \"]",
            "value-type-matrix true file file [\"\",\"  original  \",\"  original  \"]"
        ]
    );
}

#[test]
fn driver_typing_uses_native_values_and_preserves_defaults() {
    let logs = visit(
        r#"
const form=document.createElement('form');document.body.append(form);
for(const [tag,Class]of [['input',HTMLInputElement],['textarea',HTMLTextAreaElement]]){
 const node=document.createElement(tag);node.name=tag;node.defaultValue='default';form.append(node);
 if(tag==='textarea')node.setAttribute('contenteditable','true');
 let setters=0;const get=Object.getOwnPropertyDescriptor(Class.prototype,'value').get;
 Object.defineProperty(node,'value',{configurable:true,get(){return 'author-shadow'},set(){setters++}});
 node.addEventListener('input',event=>console.log('driver',tag,JSON.stringify([get.call(node),node.defaultValue,setters,event.isTrusted,new FormData(form).get(tag)])));
}
"#,
    );
    assert_eq!(logs, ["driver input [\"x\",\"default\",0,true,\"x\"]", "driver textarea [\"x\",\"default\",0,true,\"x\"]"]);
}

#[test]
fn driver_preserves_readonly_and_disabled_values() {
    let logs = visit(
        r#"
const b=document.createElement('div');b.innerHTML='<form><input id=ro name=ro value=input><textarea id=area name=area>area</textarea><fieldset disabled><input id=blocked value=disabled-input><textarea id=blockedarea>disabled-area</textarea></fieldset><input id=live name=live></form>';document.body.append(b);
for(const id of ['ro','area','blocked','blockedarea']){const node=b.querySelector('#'+id);for(const type of ['input','change'])node.addEventListener(type,()=>console.log('unexpected',id,type));if(id==='ro'||id==='area')node.addEventListener('click',()=>console.log('clicked',id))}
b.querySelector('#ro').readOnly=true;b.querySelector('#area').readOnly=true;Object.defineProperty(b.querySelector('#ro'),'readOnly',{value:false});Object.defineProperty(b.querySelector('#blocked'),'disabled',{value:false});
b.querySelector('#live').addEventListener('input',()=>console.log('values',JSON.stringify(['ro','area','blocked','blockedarea','live'].map(id=>b.querySelector('#'+id).value))));
"#,
    );
    assert_eq!(logs, ["clicked ro", "clicked area", "values [\"input\",\"area\",\"disabled-input\",\"disabled-area\",\"x\"]"]);
}

#[test]
fn readonly_reflection() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
const inputState=i=>JSON.stringify([i.value,i.defaultValue,i.getAttribute('value')]);
const areaState=i=>JSON.stringify([i.value,i.defaultValue,i.textContent]);
test('readonly-reflection',()=>{const b=mount('<input><textarea></textarea>');for(const node of b.querySelectorAll('input,textarea')){log('readonly-reflection-default',node.localName,node.readOnly,node.hasAttribute('readonly'));node.readOnly=true;node.value='script';log('readonly-reflection-set',node.localName,JSON.stringify([node.readOnly,node.getAttribute('readonly'),node.value]));node.readOnly=false;log('readonly-reflection-clear',node.localName,node.readOnly,node.hasAttribute('readonly'))}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "readonly-reflection-default input false false",
            "readonly-reflection-set input [true,\"\",\"script\"]",
            "readonly-reflection-clear input false false",
            "readonly-reflection-default textarea false false",
            "readonly-reflection-set textarea [true,\"\",\"script\"]",
            "readonly-reflection-clear textarea false false"
        ]
    );
}
