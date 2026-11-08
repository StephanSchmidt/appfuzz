//! Controller exploration must not call page-defined property hooks.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};

fn visit(html: &str) -> Value {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["requests"], json!([]), "{report}");
    report
}
fn logs(report: &Value) -> Vec<&str> {
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect()
}

#[test]
fn candidate_discovery_does_not_invoke_inherited_array_setters() {
    let report = visit(
        r#"<button type=button>tap</button><script>
const button=document.querySelector('button'),channel=new MessageChannel(),define=Object.defineProperty;let calls=0;
button.addEventListener('click',()=>console.log('clicked'));channel.port2.onmessage=()=>{};
define(Array.prototype,'0',{configurable:true,set(value){define(this,'0',{value,writable:true,enumerable:true,configurable:true});calls++}});
channel.port1.postMessage('go');setTimeout(()=>console.log('callbacks',calls),2000);
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked", "callbacks 0"], "{report}");
    assert_eq!(report["actions"][0]["tag"], "button", "{report}");
}

#[test]
fn controller_uses_physical_nodes_instead_of_public_dom_hooks() {
    let report = visit(
        r#"<button type=button id=target>tap</button><script>
const target=document.getElementById('target'),define=Object.defineProperty;let calls=0;
target.addEventListener('click',()=>console.log('clicked'));
for(const key of ['localName','id','type','textContent','isContentEditable','hasAttribute','getAttribute','parentNode','focus','dispatchEvent'])define(target,key,{configurable:true,get(){calls++;throw Error('public '+key)}});
for(const key of ['querySelectorAll','body'])define(document,key,{configurable:true,get(){calls++;throw Error('public document '+key)}});
setTimeout(()=>console.log('callbacks',calls),2000);
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked", "callbacks 0"], "{report}");
    assert_eq!(report["actions"][0]["id"], "target", "{report}");
    assert!(report["text"].as_str().unwrap().starts_with("tap"), "{report}");
}

#[test]
fn delegated_candidate_discovery_does_not_read_framework_getters() {
    let report = visit(
        r#"<span id=target>tap</span><script>
const target=document.getElementById('target');let calls=0;
document.addEventListener('click',e=>{if(e.target===target)console.log('clicked')});
Object.defineProperty(target,'__reactProps_fixture',{enumerable:true,get(){calls++;throw Error('framework getter')}});
setTimeout(()=>console.log('callbacks',calls),2000);
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked", "callbacks 0"], "{report}");
}

#[test]
fn framework_objects_keep_delegated_targets_without_running_proxy_traps() {
    let report = visit(
        r#"<span id=quiet>quiet</span><span id=target>tap</span><script>
const quiet=document.getElementById('quiet'),target=document.getElementById('target');let calls=0;
quiet.__reactProps_fixture={title:'ordinary props'};
target.__reactProps_fixture=new Proxy({}, {get(){calls++;throw Error('proxy get')},getPrototypeOf(){calls++;throw Error('proxy prototype')},getOwnPropertyDescriptor(){calls++;throw Error('proxy descriptor')}});
document.addEventListener('click',e=>console.log('clicked',e.target.id));
Object.keys=()=>{calls++;throw Error('public keys')};Object.getOwnPropertyDescriptor=()=>{calls++;throw Error('public descriptor')};
setTimeout(()=>console.log('callbacks',calls),2000);
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked target", "callbacks 0"], "{report}");
    assert_eq!(report["actions"].as_array().unwrap().len(), 1, "{report}");
}

#[test]
fn foreign_elements_with_control_names_are_clicked_as_foreign_elements() {
    let report = visit(
        r#"<svg><input role=button id=target></input></svg><script>
const target=document.getElementById('target');target.addEventListener('click',()=>console.log('clicked'));
</script>"#,
    );
    assert_eq!(logs(&report), ["clicked"], "{report}");
    assert_eq!(report["actions"][0]["tag"], "input", "{report}");
    assert_eq!(report["actions"][0]["kind"], "click", "{report}");
}

#[test]
fn page_text_normalizes_native_whitespace_without_public_string_hooks() {
    let report = visit(
        r#"<body> A&#xA0;&#x1680;&#x2000;B<!-- ignored -->&#x2028;C <script>
String.prototype.replace=()=>{throw Error('public replace')};String.prototype.trim=()=>{throw Error('public trim')};RegExp.prototype.exec=()=>{throw Error('public regexp')};
</script></body>"#,
    );
    assert!(report["text"].as_str().unwrap().starts_with("A B C "), "{report}");
}
