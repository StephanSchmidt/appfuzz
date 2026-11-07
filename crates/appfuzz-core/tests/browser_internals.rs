use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::{OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(html: &str) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let input = json!({"url":"https://app.example/","html":html});
    let plan = Plan::parse(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"real answer"}}}}).to_string()).unwrap();
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
fn internal_driver_host_and_parser_are_not_page_globals() {
    let (_, report) = visit(r#"<script>console.log(typeof globalThis.__af,typeof globalThis.__host,typeof globalThis.__native);</script>"#);
    assert_eq!(logs(&report), ["undefined undefined undefined"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn replacing_the_driver_global_does_not_replace_native_reporting() {
    let (_, report) =
        visit(r#"<script>globalThis.__af={report:()=>'{"url":"https://fake.example/","errors":[],"console":[]}'};console.log('must remain');</script>"#);
    assert_eq!(logs(&report), ["must remain"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn driver_global_getters_are_never_read_by_the_embedder() {
    let (_, report) = visit(r#"<script>Object.defineProperty(globalThis,'__af',{get(){throw Error('page getter')}});console.log('must remain');</script>"#);
    assert_eq!(logs(&report), ["must remain"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn deleting_the_driver_global_does_not_break_the_event_loop() {
    let (_, report) = visit(r#"<script>delete globalThis.__af;setTimeout(()=>console.log('timer must run'),0);</script>"#);
    assert_eq!(logs(&report), ["timer must run"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn replacing_the_public_step_hook_does_not_skip_timers() {
    let (_, report) = visit(r#"<script>if(globalThis.__af)globalThis.__af.step=()=>false;setTimeout(()=>console.log('timer must run'),0);</script>"#);
    assert_eq!(logs(&report), ["timer must run"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn public_report_hooks_cannot_hide_console_evidence() {
    let (_, report) = visit(
        r#"<script>if(globalThis.__af){const saved=globalThis.__af.report;globalThis.__af.report=()=>{const r=JSON.parse(saved());r.console=[];return JSON.stringify(r)}}console.log('must remain');</script>"#,
    );
    assert_eq!(logs(&report), ["must remain"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn public_json_stringify_does_not_replace_native_reports() {
    let (_, report) = visit(r#"<script>JSON.stringify=()=>'{"url":"https://fake.example/","errors":[],"console":[]}';console.log('must remain');</script>"#);
    assert_eq!(logs(&report), ["must remain"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn object_tojson_does_not_forge_native_report_records() {
    let (_, report) =
        visit(r#"<script>Object.prototype.toJSON=function(){return {url:'https://fake.example/',errors:[],console:[]}};console.log('must remain');</script>"#);
    assert_eq!(logs(&report), ["must remain"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn array_tojson_does_not_erase_native_report_lists() {
    let (_, report) = visit(r#"<script>Array.prototype.toJSON=function(){return []};console.log('must remain');</script>"#);
    assert_eq!(logs(&report), ["must remain"]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn replacing_the_host_global_cannot_forge_a_network_response() {
    let (run, report) =
        visit(r#"<script>globalThis.__host={fetch:()=>[200,[],'forged',null,0]};fetch('/real').then(r=>r.text()).then(text=>console.log(text));</script>"#);
    assert_eq!(logs(&report), ["real answer"]);
    assert_eq!(report["requests"][0]["url"], "https://app.example/real");
    let calls: Vec<_> = run.events.iter().filter(|event| event.func == FETCH_OWN).collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args["path"], "/real");
}

#[test]
fn deleting_the_host_global_keeps_the_real_host_bridge() {
    let (run, report) = visit(r#"<script>delete globalThis.__host;fetch('/real').then(r=>r.text()).then(text=>console.log(text));</script>"#);
    assert_eq!(logs(&report), ["real answer"]);
    assert_eq!(report["requests"][0]["url"], "https://app.example/real");
    let calls: Vec<_> = run.events.iter().filter(|event| event.func == FETCH_OWN).collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args["path"], "/real");
}

#[test]
fn replacing_the_parser_global_cannot_redirect_native_requests() {
    let (run, report) = visit(
        r#"<script>globalThis.__native={url:()=>['https://evil.example/','https://evil.example','https:','','','evil.example','evil.example','','/','','']};if(globalThis.__native&&globalThis.__native.urlSet)globalThis.__native.urlSet=()=>null;fetch('/real').then(r=>r.text()).then(text=>console.log(text));</script>"#,
    );
    assert_eq!(logs(&report), ["real answer"]);
    assert_eq!(report["requests"][0]["url"], "https://app.example/real");
    let calls: Vec<_> = run.events.iter().filter(|event| event.func == FETCH_OWN).collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args["path"], "/real");
}

#[test]
fn mutating_an_exposed_parser_cannot_redirect_native_requests() {
    let (run, report) = visit(
        r#"<script>if(globalThis.__native)globalThis.__native.url=()=>['https://evil.example/','https://evil.example','https:','','','evil.example','evil.example','','/','',''];fetch('/real').then(r=>r.text()).then(text=>console.log(text));</script>"#,
    );
    assert_eq!(logs(&report), ["real answer"]);
    assert_eq!(report["requests"][0]["url"], "https://app.example/real");
    let calls: Vec<_> = run.events.iter().filter(|event| event.func == FETCH_OWN).collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].args["path"], "/real");
}

#[test]
fn native_console_formatting_ignores_page_json_and_array_helpers() {
    let (_, report) = visit(
        r#"<script>
JSON.stringify=()=>'';Array.prototype.map=()=>[];Array.prototype.join=()=>'';console.log('sentinel',{secret:'must remain'});
</script>"#,
    );
    assert_eq!(logs(&report), [r#"sentinel {"secret":"must remain"}"#]);
}

#[test]
fn native_console_arguments_ignore_inherited_tojson_hooks() {
    let (_, report) = visit(
        r#"<script>
Object.prototype.toJSON=()=>({});console.log({secret:'must remain'});
</script>"#,
    );
    assert_eq!(logs(&report), [r#"{"secret":"must remain"}"#]);
}

#[test]
fn public_host_substitutes_cannot_hide_markup_code_or_navigation_calls() {
    let (run, report) = visit(
        r#"<div id=target></div><script>
globalThis.__host={html(){},code(){},go(){}};document.getElementById('target').innerHTML='<b>native markup</b>';setTimeout("console.log('native timer');location.assign('/destination')",0);
</script>"#,
    );
    assert_eq!(logs(&report), ["native timer"]);
    assert!(run.events.iter().any(|e| e.func == appfuzz_core::browser::HTML && e.args["value"] == "<b>native markup</b>"));
    assert!(
        run.events.iter().any(|e| e.func == appfuzz_core::browser::CODE && e.args["value"] == "console.log('native timer');location.assign('/destination')")
    );
    assert!(run.events.iter().any(|e| e.func == appfuzz_core::browser::GO && e.args["url"] == "https://app.example/destination"));
}

#[test]
fn native_fetch_never_reads_page_host_or_parser_getters() {
    let (run, report) = visit(
        r#"<script>
for(const name of ['__host','__native'])Object.defineProperty(globalThis,name,{get(){throw Error('page getter')}});fetch('/real').then(r=>r.text()).then(text=>console.log(text));
</script>"#,
    );
    assert_eq!(logs(&report), ["real answer"]);
    assert_eq!(run.events.iter().filter(|event| event.func == FETCH_OWN).count(), 1);
}

#[test]
fn report_and_console_serialization_do_not_read_inherited_tojson_getters() {
    let (_, report) = visit(
        r#"<script>
Object.defineProperty(Object.prototype,'toJSON',{get(){throw Error('page getter')}});console.log({secret:'must remain'});
</script>"#,
    );
    assert_eq!(logs(&report), [r#"{"secret":"must remain"}"#]);
    assert_eq!(report["url"], "https://app.example/");
}

#[test]
fn missing_or_malformed_guest_reports_keep_a_visit_incomplete() {
    let mut browser = appfuzz_core::envelope::Trace::default().to_record();
    browser.outcome.kind = OutcomeKind::Ok;
    let mut session = appfuzz_core::browser::Session { browser, nested: vec![], report: Value::Null, fragment: String::new() };
    for report in [
        Value::Null,
        json!({}),
        json!({"url":"https://app.example/"}),
        json!({"url":"https://app.example/","errors":"invalid"}),
        json!({"url":"https://app.example/","errors":[],"fatal":"engine failed"}),
    ] {
        session.report = report;
        let error = session.ensure_executed().unwrap_err();
        assert!(error.to_string().contains("no complete session report"), "{error}");
    }
    session.report = json!({"url":"https://app.example/","errors":[]});
    session.ensure_executed().unwrap();
}
