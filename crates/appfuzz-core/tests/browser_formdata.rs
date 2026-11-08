//! Browser-reference regressions for FormData updates, conversions and live iteration.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};

fn visit(script: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/", "html":format!("<script>{script}</script>")});
    let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn set_order() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');f.append('b','2');f.append('a','3');f.append('c','4');f.set('a','new');log('set-order',JSON.stringify([...f]))}catch(e){log('set-order','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["set-order [[\"a\",\"new\"],[\"b\",\"2\"],[\"c\",\"4\"]]"]);
}

#[test]
fn set_atomic() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');try{f.set('a','new','file')}catch(e){log('set-atomic-error',e.name)}log('set-atomic',f.get('a'))}catch(e){log('set-atomic','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["set-atomic-error TypeError", "set-atomic old"]);
}

#[test]
fn public_methods() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');f.delete=()=>{throw Error('public delete')};f.append=()=>{throw Error('public append')};f.set('a','new');log('public-methods',f.get('a'))}catch(e){log('public-methods','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["public-methods new"]);
}

#[test]
fn coercion() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('42','yes');for(const method of ['get','getAll','has','delete']){let reads=0;const key={toString(){reads++;return '42'}};log('coercion',method,JSON.stringify(f[method](key)),reads)}}catch(e){log('coercion','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["coercion get \"yes\" 1", "coercion getAll [\"yes\"] 1", "coercion has true 1", "coercion delete  1"]);
}

#[test]
fn conversion_failure() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');try{f.set('a',{toString(){throw Error('stop')}})}catch(e){log('conversion-failure',e.name,f.get('a'))}}catch(e){log('conversion-failure','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["conversion-failure Error old"]);
}

#[test]
fn iterator_brand() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{try{const i=FormData.prototype.entries.call({});log('iterator-brand','accepted')}catch(e){log('iterator-brand',e.name)}}catch(e){log('iterator-brand','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["iterator-brand TypeError"]);
}

#[test]
fn iterator_public() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','yes');f.entries=()=>{throw Error('public entries')};log('iterator-public',JSON.stringify([...f]))}catch(e){log('iterator-public','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["iterator-public [[\"a\",\"yes\"]]"]);
}

#[test]
fn iterator_live() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');f.append('b','2');const i=f.entries();log('iterator-live-first',JSON.stringify(i.next().value));f.delete('b');f.append('c','3');log('iterator-live-rest',JSON.stringify([...i]))}catch(e){log('iterator-live','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["iterator-live-first [\"a\",\"1\"]", "iterator-live-rest [[\"c\",\"3\"]]"]);
}

#[test]
fn foreach_live() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');f.append('b','2');const seen=[];f.forEach((v,k)=>{seen.push(k);if(k==='a'){f.delete('b');f.append('c','3')}});log('foreach-live',seen.join('/'))}catch(e){log('foreach-live','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["foreach-live a/c"]);
}

#[test]
fn foreach_call() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');function cb(v,k,obj){log('foreach-call',v,k,obj===f,this===receiver)}const receiver={};cb.call=()=>{throw Error('public call')};f.forEach(cb,receiver)}catch(e){log('foreach-call','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["foreach-call 1 a true true"]);
}

#[test]
fn required() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{for(const method of ['append','set','get','getAll','has','delete','forEach'])try{new FormData()[method]();log('required',method,'accepted')}catch(e){log('required',method,e.name)}}catch(e){log('required','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(
        logs,
        [
            "required append TypeError",
            "required set TypeError",
            "required get TypeError",
            "required getAll TypeError",
            "required has TypeError",
            "required delete TypeError",
            "required forEach TypeError"
        ]
    );
}

#[test]
fn undefined_filename() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{for(const method of ['append','set'])try{new FormData()[method]('a','text',undefined);log('undefined-filename',method,'accepted')}catch(e){log('undefined-filename',method,e.name)}}catch(e){log('undefined-filename','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["undefined-filename append TypeError", "undefined-filename set TypeError"]);
}

#[test]
fn overload_order() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{for(const method of ['append','set']){const f=new FormData,seen=[];try{f[method]({toString(){seen.push('key');return 'k'}},'v',{toString(){seen.push('file');return 'f'}})}catch(e){log('overload-order',method,e.name,seen.join('/'))}}}catch(e){log('overload-order','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["overload-order append TypeError key", "overload-order set TypeError key"]);
}

#[test]
fn blob_file() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{for(const kind of ['Blob','File'])for(const supplied of [false,true]){const f=new FormData,v=kind==='File'?new File(['x'],'original'):new Blob(['x']);if(supplied)f.append('a',v,undefined);else f.append('a',v);const stored=f.get('a');log('blob-file',kind,supplied,stored.name,stored===v)}}catch(e){log('blob-file','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(
        logs,
        ["blob-file Blob false blob false", "blob-file Blob true blob false", "blob-file File false original true", "blob-file File true original true"]
    );
}

#[test]
fn foreach_coercion() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{for(const callback of [null,{},'x'])try{new FormData().forEach(callback);log('foreach-coercion','accepted')}catch(e){log('foreach-coercion',typeof callback,e.name)}}catch(e){log('foreach-coercion','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["foreach-coercion object TypeError", "foreach-coercion object TypeError", "foreach-coercion string TypeError"]);
}

#[test]
fn conversion_reentry() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');f.append('b','kept');const key={toString(){f.delete('a');f.append('c','added');return 'a'}};f.set(key,'new');log('conversion-reentry',JSON.stringify([...f]))}catch(e){log('conversion-reentry','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["conversion-reentry [[\"b\",\"kept\"],[\"c\",\"added\"],[\"a\",\"new\"]]"]);
}

#[test]
fn scalars_usv() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append(42,7);f.append('\ud800','\udc00');f.append(undefined,null);log('scalars-usv',f.get(42),f.get('\udc00'),f.has({toString(){return '42'}}),f.get(undefined));try{f.has(Symbol())}catch(e){log('scalars-symbol',e.name)}}catch(e){log('scalars-usv','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["scalars-usv 7 \u{fffd} true null", "scalars-symbol TypeError"]);
}

#[test]
fn brand_conversion() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{for(const method of ['append','set','get','getAll','has','delete']){let calls=0;try{FormData.prototype[method].call({}, {toString(){calls++;return 'a'}},'b')}catch(e){log('brand-conversion',method,e.name,calls)}}}catch(e){log('brand-conversion','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(
        logs,
        [
            "brand-conversion append TypeError 0",
            "brand-conversion set TypeError 0",
            "brand-conversion get TypeError 0",
            "brand-conversion getAll TypeError 0",
            "brand-conversion has TypeError 0",
            "brand-conversion delete TypeError 0"
        ]
    );
}

#[test]
fn filename_atomic() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');let calls=0;try{f.set({toString(){calls++;return 'a'}},new Blob(['data']),{toString(){calls++;throw Error('stop')}})}catch(e){log('filename-atomic',e.name,calls,f.get('a'))}}catch(e){log('filename-atomic','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["filename-atomic Error 2 old"]);
}

#[test]
fn file_metadata() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData,source=new File(['abc'],'old',{type:'text/plain',lastModified:77});f.append('a',source,'renamed');const value=f.get('a');log('file-metadata',value.name,value.type,value.lastModified,value.size,value===source)}catch(e){log('file-metadata','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["file-metadata renamed text/plain 77 3 false"]);
}

#[test]
fn iterator_types() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');f.append('b','2');log('iterator-types',f[Symbol.iterator]===FormData.prototype.entries,Object.prototype.toString.call(f.entries()));for(const name of ['keys','values']){const i=f[name]();log('iterator-types-first',name,i.next().value);f.delete('b');f.append('c','3');log('iterator-types-rest',name,JSON.stringify([...i]));f.delete('c');f.append('b','2')}try{f.entries().next.call({})}catch(e){log('iterator-types-brand',e.name)}}catch(e){log('iterator-types','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(
        logs,
        [
            "iterator-types true [object FormData Iterator]",
            "iterator-types-first keys a",
            "iterator-types-rest keys [\"c\"]",
            "iterator-types-first values 1",
            "iterator-types-rest values [\"3\"]",
            "iterator-types-brand TypeError"
        ]
    );
}

#[test]
fn iterator_finished() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');const i=f.entries();log('iterator-finished',i.next().done,i.next().done);f.append('b','2');log('iterator-finished-after',i.next().done)}catch(e){log('iterator-finished','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["iterator-finished false true", "iterator-finished-after false"]);
}

#[test]
fn result_copies() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');const p=f.entries().next().value;p[0]='b';p[1]='changed';const values=f.getAll('a');values[0]='changed';log('result-copies',JSON.stringify([...f]),f.get('a'))}catch(e){log('result-copies','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["result-copies [[\"a\",\"old\"]] old"]);
}

#[test]
fn array_helpers() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','1');f.append('b','2');const old={};for(const method of ['filter','map','find','some']){old[method]=Array.prototype[method];Array.prototype[method]=()=>{throw Error('public helper')}}try{f.delete('b');f.set('a','new');log('array-helpers',f.get('a'),f.has('a'),JSON.stringify(f.getAll('a')),JSON.stringify([...f]))}finally{for(const method of ['filter','map','find','some'])Array.prototype[method]=old[method]}}catch(e){log('array-helpers','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["array-helpers new true [\"new\"] [[\"a\",\"new\"]]"]);
}

#[test]
fn reentry_value() {
    let logs = visit(
        r#"const lines=[],log=(...args)=>lines.push(args.join(' '));try{const f=new FormData;f.append('a','old');f.append('b','kept');f.set('a',{toString(){f.delete('a');f.append('c','added');return 'new'}});log('reentry-value',JSON.stringify([...f]))}catch(e){log('reentry-value','ERROR',e.name)}for(const line of lines)console.log(line);"#,
    );
    assert_eq!(logs, ["reentry-value [[\"b\",\"kept\"],[\"c\",\"added\"],[\"a\",\"new\"]]"]);
}

#[test]
fn serialized_request_keeps_order_and_values_after_rejected_update() {
    let logs = visit(
        r#"(async()=>{const f=new FormData;f.append('first','old');f.append('middle','kept');f.append('first','duplicate');f.append('last','tail');f.set('first','new');try{f.set('middle',{toString(){throw Error('rejected')}})}catch{}const text=await new Request('/submit',{method:'POST',body:f}).text(),a=text.indexOf('name="first"'),b=text.indexOf('name="middle"'),c=text.indexOf('name="last"');console.log('multipart',a>=0&&a<b&&b<c,text.includes('\r\n\r\nnew\r\n'),text.includes('\r\n\r\nkept\r\n'),!text.includes('duplicate'))})();"#,
    );
    assert_eq!(logs, ["multipart true true true true"]);
}

#[test]
fn creating_file_entries_uses_private_blob_data() {
    let logs = visit(
        r#"const blob=new Blob(['real'],{type:'text/plain'}),f=new FormData,old=Array.prototype[Symbol.iterator];try{Array.prototype[Symbol.iterator]=()=>{throw Error('public iterator')};f.append('a',blob,'name.txt')}finally{Array.prototype[Symbol.iterator]=old}const file=f.get('a');console.log(file.name,file.type,file.size);file.text().then(text=>console.log(text));"#,
    );
    assert_eq!(logs, ["name.txt text/plain 4", "real"]);
}
