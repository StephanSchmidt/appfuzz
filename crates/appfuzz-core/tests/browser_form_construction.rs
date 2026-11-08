//! Form construction is checked against Firefox using the bundled Wasm browser.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};

fn visit(script: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/", "html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn invalid_form() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('invalid-form',()=>{for(const [label,v]of [['null',null],['false',false],['zero',0],['empty',''],['object',{}],['element',document.createElement('div')]])try{log('invalid-form',label,entries(new FormData(v)))}catch(e){log('invalid-form',label,e.name)}log('invalid-form-undefined',entries(new FormData(undefined)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "invalid-form null TypeError",
            "invalid-form false TypeError",
            "invalid-form zero TypeError",
            "invalid-form empty TypeError",
            "invalid-form object TypeError",
            "invalid-form element TypeError",
            "invalid-form-undefined []"
        ]
    );
}

#[test]
fn submitter() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('submitter',()=>{const b=mount('<form id=f><input name=a value=1><button name=go value=yes>send</button><input type=reset><input type=image name=pic></form><form id=g><button>other</button></form>'),f=b.querySelector('#f');for(const [label,v]of [['object',{}],['element',document.createElement('div')],['reset',f.querySelector('[type=reset]')],['other',b.querySelector('#g button')],['button',f.querySelector('button')],['image',f.querySelector('[type=image]')]])try{log('submitter',label,entries(new FormData(f,v)))}catch(e){log('submitter',label,e.name)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "submitter object TypeError",
            "submitter element TypeError",
            "submitter reset TypeError",
            "submitter other NotFoundError",
            "submitter button [[\"a\",\"1\"],[\"go\",\"yes\"]]",
            "submitter image [[\"a\",\"1\"],[\"pic.x\",\"0\"],[\"pic.y\",\"0\"]]"
        ]
    );
}

#[test]
fn association() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('association',()=>{const b=mount('<input form=f name=before value=0><form id=f><input name=inside value=1><input form=g name=foreign value=bad></form><form id=g></form><input form=f name=after value=2>');log('association',entries(new FormData(b.querySelector('#f'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["association [[\"before\",\"0\"],[\"inside\",\"1\"],[\"after\",\"2\"]]"]);
}

#[test]
fn disabled_fieldset() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('disabled-fieldset',()=>{const b=mount('<form><fieldset disabled><legend><input name=legend value=keep></legend><input name=blocked value=bad><legend><input name=later value=bad></legend></fieldset><input name=normal value=yes></form>');log('disabled-fieldset',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["disabled-fieldset [[\"legend\",\"keep\"],[\"normal\",\"yes\"]]"]);
}

#[test]
fn datalist() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('datalist',()=>{const b=mount('<form><datalist><input name=hint value=bad></datalist><input name=normal value=yes></form>');log('datalist',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["datalist [[\"hint\",\"bad\"],[\"normal\",\"yes\"]]"]);
}

#[test]
fn select_default() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-default',()=>{const b=mount('<form><select name=s><option> First  value </option><option value=two>Two</option></select><select name=multiple multiple><option value=a selected>A</option><option value=b selected>B</option></select></form>');log('select-default',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["select-default [[\"s\",\"First value\"],[\"multiple\",\"a\"],[\"multiple\",\"b\"]]"]);
}

#[test]
fn select_disabled() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-disabled',()=>{const b=mount('<form><select name=s multiple><option value=good selected>Good</option><option disabled selected value=bad>Bad</option><optgroup disabled><option selected value=group>Group</option></optgroup></select></form>');log('select-disabled',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["select-disabled [[\"s\",\"good\"]]"]);
}

#[test]
fn file_empty() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('file-empty',()=>{const b=mount('<form><input type=file name=upload><input type=file name=multi multiple></form>');log('file-empty',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "file-empty [[\"upload\",{\"name\":\"\",\"type\":\"application/octet-stream\",\"size\":0}],[\"multi\",{\"name\":\"\",\"type\":\"application/octet-stream\",\"size\":0}]]"
        ]
    );
}

#[test]
fn image_unnamed() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('image-unnamed',()=>{const b=mount('<form><input type=image></form>'),f=b.querySelector('form');log('image-unnamed',entries(new FormData(f,f.querySelector('input'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["image-unnamed [[\"x\",\"0\"],[\"y\",\"0\"]]"]);
}

#[test]
fn charset() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('charset',()=>{const b=mount('<form><input type=hidden name=_charset_ value=wrong><input type=text name=_charset_ value=visible></form>');log('charset',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["charset [[\"_charset_\",\"UTF-8\"],[\"_charset_\",\"visible\"]]"]);
}

#[test]
fn direction() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('direction',()=>{const b=mount('<form dir=rtl><input name=a value=hello dirname=a.dir><textarea name=b dirname=b.dir dir=ltr>text</textarea></form>');log('direction',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["direction [[\"a\",\"hello\"],[\"a.dir\",\"rtl\"],[\"b\",\"text\"],[\"b.dir\",\"ltr\"]]"]);
}

#[test]
fn native_checked() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('native-checked',()=>{const b=mount('<form><input type=checkbox name=checked checked><input type=checkbox name=unchecked></form>'),f=b.querySelector('form');Object.defineProperty(f.querySelector('[name=checked]'),'checked',{value:false});Object.defineProperty(f.querySelector('[name=unchecked]'),'checked',{value:true});log('native-checked',entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["native-checked [[\"checked\",\"on\"]]"]);
}

#[test]
fn native_properties() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('native-properties',()=>{const b=mount('<form><input name=a value=real></form>'),f=b.querySelector('form'),i=f.querySelector('input');for(const key of ['name','value','disabled','form'])Object.defineProperty(i,key,{get(){throw Error('public '+key)}});i.getAttribute=()=>{throw Error('public attr')};f.querySelectorAll=()=>{throw Error('public query')};log('native-properties',entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["native-properties [[\"a\",\"real\"]]"]);
}

#[test]
fn event_mutation() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('event-mutation',()=>{const b=mount('<form><input name=a value=old></form>'),f=b.querySelector('form');f.addEventListener('formdata',e=>{log('event-mutation-flags',e.bubbles,e.cancelable,e.composed,e.formData instanceof FormData);e.formData.set('a','new');e.formData.append('added','yes')});log('event-mutation',entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["event-mutation-flags true false false true", "event-mutation [[\"a\",\"new\"],[\"added\",\"yes\"]]"]);
}

#[test]
fn event_snapshot() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('event-snapshot',()=>{const b=mount('<form><input name=a value=old></form>'),f=b.querySelector('form');let captured;f.addEventListener('formdata',e=>{captured=e.formData;try{new FormData(f)}catch(e){log('event-snapshot-nested',e.name)}});const out=new FormData(f);captured.append('late','no');out.append('out','yes');log('event-snapshot',entries(out),entries(captured))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["event-snapshot-nested InvalidStateError", "event-snapshot [[\"a\",\"old\"],[\"out\",\"yes\"]] [[\"a\",\"old\"],[\"late\",\"no\"]]"]);
}

#[test]
fn event_api() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('event-api',()=>{for(const args of [[],['formdata'],['formdata',{}],['formdata',{formData:{}}]])try{new FormDataEvent(...args);log('event-api','accepted')}catch(e){log('event-api',e.name)}const data=new FormData,event=new FormDataEvent('custom',{formData:data,bubbles:true});log('event-api-good',event.type,event.formData===data,event.bubbles);try{Object.getOwnPropertyDescriptor(FormDataEvent.prototype,'formData').get.call({})}catch(e){log('event-api-brand',e.name)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "event-api TypeError",
            "event-api TypeError",
            "event-api TypeError",
            "event-api TypeError",
            "event-api-good custom true true",
            "event-api-brand TypeError"
        ]
    );
}

#[test]
fn shadow_ownership() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('shadow-ownership',()=>{const b=mount('<form id=f><input name=outer value=yes></form><div id=host></div>'),root=b.querySelector('#host').attachShadow({mode:'open'});root.innerHTML='<input form=f name=cross value=bad><form id=g><input name=inner value=yes></form>';log('shadow-ownership',entries(new FormData(b.querySelector('form'))),entries(new FormData(root.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["shadow-ownership [[\"outer\",\"yes\"]] [[\"inner\",\"yes\"]]"]);
}

#[test]
fn duplicate_form_id() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('duplicate-form-id',()=>{const b=mount('<div id=f></div><form id=f><input name=own value=yes></form><input form=f name=external value=bad>');log('duplicate-form-id',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["duplicate-form-id [[\"own\",\"yes\"]]"]);
}

#[test]
fn undefined_form() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('undefined-form',()=>{for(const [label,submitter]of [['undefined',undefined],['null',null],['html',document.createElement('div')],['object',{}]])try{log('undefined-form',label,entries(new FormData(undefined,submitter)))}catch(e){log('undefined-form',label,e.name)}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["undefined-form undefined []", "undefined-form null []", "undefined-form html []", "undefined-form object TypeError"]);
}

#[test]
fn event_handler() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('event-handler',()=>{const b=mount('<form><input name=a value=old></form>'),f=b.querySelector('form');f.onformdata=e=>{log('event-handler-flags',e.isTrusted,e.target===f,e.currentTarget===f);e.formData.set('a','new')};b.addEventListener('formdata',e=>{e.formData.append('parent','yes');e.preventDefault();log('event-handler-parent',e.defaultPrevented)});log('event-handler',entries(new FormData(f)))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["event-handler-flags true true true", "event-handler-parent false", "event-handler [[\"a\",\"new\"],[\"parent\",\"yes\"]]"]);
}

#[test]
fn direction_auto() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('direction-auto',()=>{const b=mount('<form dir=rtl><input name=a value="123 שלום" dirname=a.dir dir=auto><input name=b value="123 abc" dirname=b.dir dir=auto><input name=c value="123" dirname=c.dir dir=auto><input type=tel name=d value="123" dirname=d.dir><input name=e value="𞤀" dirname=e.dir dir=auto></form>');log('direction-auto',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "direction-auto [[\"a\",\"123 שלום\"],[\"a.dir\",\"rtl\"],[\"b\",\"123 abc\"],[\"b.dir\",\"ltr\"],[\"c\",\"123\"],[\"c.dir\",\"ltr\"],[\"d\",\"123\"],[\"d.dir\",\"ltr\"],[\"e\",\"𞤀\"],[\"e.dir\",\"rtl\"]]"
        ]
    );
}

#[test]
fn select_fallback() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-fallback',()=>{const b=mount('<form><select name=a><option disabled>bad</option><optgroup disabled><option>bad-group</option></optgroup><option>yes</option></select><select name=b size=2><option>none</option></select><select name=c><option selected value=one>One</option><option selected value=two>Two</option></select></form>');log('select-fallback',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["select-fallback [[\"a\",\"yes\"],[\"c\",\"two\"]]"]);
}

#[test]
fn basic_values() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('basic-values',()=>{const b=mount('<form><input name=readonly value=kept readonly><input name=disabled value=bad disabled><input type=submit name=go><button name=ordinary value=bad>skip</button><textarea name=message>hello\nworld</textarea><input name="" value=bad></form>'),f=b.querySelector('form');log('basic-values',entries(new FormData(f,f.querySelector('[type=submit]'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["basic-values [[\"readonly\",\"kept\"],[\"go\",\"Submit Query\"],[\"message\",\"hello\\nworld\"]]"]);
}

#[test]
fn event_dictionary() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('event-dictionary',()=>{const seen=[],data=new FormData,options={};for(const key of ['bubbles','cancelable','composed','formData'])Object.defineProperty(options,key,{get(){seen.push(key);return key==='formData'?data:true}});const event=new FormDataEvent({toString(){seen.push('type');return 'custom'}},options);log('event-dictionary',seen.join('/'),event.formData===data,event.cancelable,event.composed,Object.prototype.toString.call(event))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["event-dictionary type/bubbles/cancelable/composed/formData true true true [object FormDataEvent]"]);
}

#[test]
fn select_updated_value() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-updated-value',()=>{const b=mount('<form><select name=a><option value=one>One</option><option value=two>Two</option></select></form>'),s=b.querySelector('select');s.value='two';log('select-updated-value',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["select-updated-value [[\"a\",\"two\"]]"]);
}

#[test]
fn select_updated_multiple() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-updated-multiple',()=>{const b=mount('<form><select name=a multiple><option value=one>One</option><option value=two>Two</option></select></form>'),o=b.querySelectorAll('option');o[0].selected=true;o[1].selected=true;log('select-updated-multiple',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["select-updated-multiple [[\"a\",\"one\"],[\"a\",\"two\"]]"]);
}

#[test]
fn select_cleared() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-cleared',()=>{const b=mount('<form><select name=a><option value=one>One</option></select></form>');b.querySelector('select').selectedIndex=-1;log('select-cleared',entries(new FormData(b.querySelector('form'))))});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(logs, ["select-cleared []"]);
}

#[test]
fn select_size_parsing() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));let active=null;
function mount(html){active=document.createElement('div');active.innerHTML=html;document.body.appendChild(active);return active}
function test(label,callback){try{callback()}catch(e){log(label,'ERROR',e.name)}finally{if(active)active.remove();active=null}}
const entries=f=>JSON.stringify([...f].map(([k,v])=>[k,typeof v==='string'?v:{name:v.name,type:v.type,size:v.size}]));
test('select-size-parsing',()=>{for(const size of ['2junk','0x2','  +2','-2','2147483648','4294967295','9999999999999999999','1.5']){const b=mount('<form><select name=a size="'+size+'"><option value=one>One</option></select></form>');log('select-size-parsing',size,entries(new FormData(b.querySelector('form'))));b.remove();active=null}});for(const line of lines)console.log(line)"#,
    );
    assert_eq!(
        logs,
        [
            "select-size-parsing 2junk []",
            "select-size-parsing 0x2 [[\"a\",\"one\"]]",
            "select-size-parsing   +2 []",
            "select-size-parsing -2 [[\"a\",\"one\"]]",
            "select-size-parsing 2147483648 [[\"a\",\"one\"]]",
            "select-size-parsing 4294967295 [[\"a\",\"one\"]]",
            "select-size-parsing 9999999999999999999 [[\"a\",\"one\"]]",
            "select-size-parsing 1.5 [[\"a\",\"one\"]]"
        ]
    );
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
