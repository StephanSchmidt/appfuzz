//! Cookie behavior is exercised in the bundled Wasm browser, including
//! the headers that reach its network imports rather than only DOM state.
use appfuzz_core::{
    browser::{Browser, FETCH_OTHER, FETCH_OWN, SESSION},
    plan::Plan,
    record::{HostCall, OutcomeKind, RunRecord},
};
use serde_json::{Value, json};

fn visit(script: &str, cookies: Value, extra: Value) -> (RunRecord, Value) {
    let answer = json!({"return":{"ok":{"status":200,"headers":[],"body":""}}});
    visit_planned(script, cookies, extra, json!({FETCH_OWN:answer,FETCH_OTHER:answer}))
}
fn visit_planned(script: &str, cookies: Value, extra: Value, plan: Value) -> (RunRecord, Value) {
    let browser = Browser::shared().unwrap();
    let mut input = json!({"url":"https://app.example/account/page", "html":format!("<!doctype html><html><head><title>cookies</title></head><body><p id=c></p><script>{script}</script></body></html>"), "cookies":cookies});
    input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    let plan = Plan::parse(&plan.to_string()).unwrap();
    let mut spec = browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1);
    spec.now = "2026-11-02T10:00:00".into();
    let r = browser.app.run(&spec);
    assert_eq!(r.outcome.kind, OutcomeKind::Ok, "{:?}", r.outcome);
    let report: Value = serde_json::from_str(r.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert_eq!(report["errors"], json!([]), "{report}");
    (r, report)
}
fn cookie(e: &HostCall) -> Option<&str> {
    e.args["headers"].as_array().unwrap().iter().find(|p| p[0].as_str().unwrap().eq_ignore_ascii_case("cookie")).and_then(|p| p[1].as_str())
}
fn request<'a>(r: &'a RunRecord, path: &str) -> &'a HostCall {
    r.events.iter().find(|e| e.func == FETCH_OWN && e.args["path"] == path).unwrap_or_else(|| panic!("missing {path}: {:?}", r.events))
}
#[test]
fn same_origin_network_requests_include_httponly_cookies_without_exposing_them_to_scripts() {
    let (r, report) = visit(
        r#"
        document.getElementById('c').textContent=document.cookie;
        fetch('/api');
        const x=new XMLHttpRequest();x.open('GET','/xhr');x.send();
        navigator.sendBeacon('/beacon','hello');
        const s=document.createElement('script');s.src='/app.js';document.body.append(s);
    "#,
        json!({"sid":{"value":"real-session","httpOnly":true},"public":"hello"}),
        json!({}),
    );
    assert!(report["text"].as_str().unwrap().starts_with("public=hello"), "{report}");
    assert!(!report["text"].as_str().unwrap().contains("sid=real-session"), "{report}");
    for path in ["/api", "/xhr", "/beacon", "/app.js"] {
        let value = cookie(request(&r, path)).unwrap_or_else(|| panic!("no Cookie on {path}"));
        assert!(value.contains("sid=real-session"), "{path}: {value}");
        assert!(value.contains("public=hello"), "{path}: {value}");
    }
}
#[test]
fn credentials_omit_survives_request_cloning_and_host_cookies_stay_on_their_host() {
    let (r, _) = visit(
        r#"
        fetch('/default');
        fetch('/omit',{credentials:'omit'});
        const r=new Request('/cloned',{credentials:'omit'});fetch(r.clone());
        fetch('https://evil.example/other',{credentials:'include'});
    "#,
        json!({"sid":"real-session"}),
        json!({}),
    );
    assert_eq!(cookie(request(&r, "/default")), Some("sid=real-session"));
    for path in ["/omit", "/cloned"] {
        assert_eq!(cookie(request(&r, path)), None, "{path}");
    }
    assert!(r.events.iter().filter(|e| e.func == FETCH_OTHER).all(|e| cookie(e).is_none()));
}
#[test]
fn initial_response_cookie_attributes_control_visibility_and_scope() {
    let (r, report) = visit(
        r#"
        document.getElementById('c').textContent=document.cookie;
        fetch('/account/api');fetch('/public');fetch('http://app.example/account/api',{credentials:'include'});
    "#,
        json!({}),
        json!({"set_cookies":[
            "sid=real-session; HttpOnly; Secure; Path=/account",
            "public=hello; Path=/",
            "dead=old; Max-Age=0; Expires=Wed, 01 Jan 2099 00:00:00 GMT; Path=/",
            "wrong=no; Domain=evil.example; Path=/"
        ]}),
    );
    assert!(report["text"].as_str().unwrap().starts_with("public=hello"), "{report}");
    assert!(!report["text"].as_str().unwrap().contains("sid=real-session"), "{report}");
    assert_eq!(cookie(request(&r, "/account/api")), Some("sid=real-session; public=hello"));
    assert_eq!(cookie(request(&r, "/public")), Some("public=hello"));
    let insecure = r.events.iter().find(|e| e.func == FETCH_OTHER).unwrap();
    assert!(!cookie(insecure).unwrap_or_default().contains("sid="));
}
#[test]
fn script_cookie_writes_cannot_replace_httponly_cookies_and_expire_in_virtual_time() {
    let (r, _) = visit(
        r#"
        document.cookie='sid=forged; Path=/';
        document.cookie='short=one; Max-Age=2; Path=/';
        fetch('/before');setTimeout(()=>fetch('/after'),3000);
    "#,
        json!({"sid":{"value":"real-session","httpOnly":true}}),
        json!({}),
    );
    let before = cookie(request(&r, "/before")).unwrap();
    assert!(before.contains("sid=real-session") && before.contains("short=one"), "{before}");
    assert_eq!(cookie(request(&r, "/after")), Some("sid=real-session"));
}

#[test]
fn fetch_and_xhr_deliver_each_response_after_its_measured_host_latency() {
    for script in [
        "const start=Date.now();for(const path of ['/slow','/fast'])fetch(path).then(()=>fetch('/after'+path+'?elapsed='+(Date.now()-start)));",
        "const start=Date.now();for(const path of ['/slow','/fast']){const x=new XMLHttpRequest();x.open('GET',path);x.onload=()=>fetch('/after'+path+'?elapsed='+(Date.now()-start));x.send();}",
    ] {
        let answer = json!({"ok":{"status":200,"headers":[],"body":"ok"}});
        let plan = json!({FETCH_OWN:{"rules":[
            {"when":{"path":"/slow"},"return":answer,"latency_ms":2500},
            {"when":{"path":"/fast"},"return":answer,"latency_ms":50}
        ],"default":{"return":answer,"latency_ms":0}}});
        let (r, _) = visit_planned(script, json!({}), json!({}), plan);
        for (path, latency) in [("/slow", 2500.0), ("/fast", 50.0)] {
            let prefix = format!("/after{path}?elapsed=");
            let elapsed: f64 = r
                .events
                .iter()
                .filter(|e| e.func == FETCH_OWN)
                .find_map(|e| e.args["path"].as_str()?.strip_prefix(&prefix)?.parse().ok())
                .unwrap_or_else(|| panic!("missing {prefix}: {:?}", r.events));
            assert!((elapsed - latency).abs() < 1.0, "{path} was delivered after {elapsed}ms instead of {latency}ms");
        }
        let sends: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OWN && matches!(e.args["path"].as_str(), Some("/slow" | "/fast"))).collect();
        assert_eq!(sends[0].args["now-ms"], sends[1].args["now-ms"], "parallel requests start together");
    }
}

#[test]
fn fetch_response_cookies_are_stored_but_set_cookie_is_not_script_readable() {
    let (r, report) = visit_planned(
        r#"
        fetch('/login').then(r=>{
            document.getElementById('c').textContent=String(r.headers.get('set-cookie'));
            return fetch('/after');
        });
    "#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"rules":[{"when":{"path":"/login"},"return":{"ok":{"status":200,"headers":[["set-cookie","sid=real-session; HttpOnly; Path=/"]],"body":""}}}],"default":{"return":{"ok":{"status":200,"headers":[],"body":""}}}}}),
    );
    assert!(report["text"].as_str().unwrap().starts_with("null"), "{report}");
    assert_eq!(cookie(request(&r, "/after")), Some("sid=real-session"));
}

#[test]
fn a_blocking_script_load_advances_the_page_clock_before_the_next_script() {
    let answer = json!({"ok":{"status":200,"headers":[],"body":""}});
    let plan = json!({FETCH_OWN:{"rules":[{"when":{"path":"/blocking.js"},
        "return":{"ok":{"status":200,"headers":[],"body":"globalThis.loaded=true;"}},"latency_ms":2500}],
        "default":{"return":answer,"latency_ms":0}}});
    let html = "<!doctype html><script>const start=Date.now();</script><script src='/blocking.js'></script><script>if(loaded)fetch('/after?elapsed='+(Date.now()-start));</script>";
    let (r, _) = visit_planned("", json!({}), json!({"html":html}), plan);
    let elapsed: f64 =
        r.events.iter().filter(|e| e.func == FETCH_OWN).find_map(|e| e.args["path"].as_str()?.strip_prefix("/after?elapsed=")?.parse().ok()).unwrap();
    assert!((elapsed - 2500.0).abs() < 1.0, "the script loaded in {elapsed}ms");
}

#[test]
fn beacon_response_cookies_wait_for_the_measured_response_time() {
    let answer = json!({"ok":{"status":200,"headers":[],"body":""}});
    let plan = json!({FETCH_OWN:{"rules":[{"when":{"path":"/login"},
        "return":{"ok":{"status":200,"headers":[["set-cookie","sid=after-response; Path=/"]],"body":""}},"latency_ms":2500}],
        "default":{"return":answer,"latency_ms":0}}});
    let (r, _) =
        visit_planned("navigator.sendBeacon('/login');setTimeout(()=>fetch('/before'),100);setTimeout(()=>fetch('/after'),3000);", json!({}), json!({}), plan);
    assert_eq!(cookie(request(&r, "/before")), None);
    assert_eq!(cookie(request(&r, "/after")), Some("sid=after-response"));
}
#[test]
fn xhr_response_cookies_update_the_jar_without_exposing_set_cookie() {
    let (r, report) = visit_planned(
        r#"
        const x=new XMLHttpRequest();x.open('GET','/login');
        x.onload=()=>{
            document.getElementById('c').textContent=String(x.getResponseHeader('set-cookie'))+'|'+x.getAllResponseHeaders();
            fetch('/after');
        };x.send();
    "#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"rules":[{"when":{"path":"/login"},"return":{"ok":{"status":200,"headers":[["set-cookie","sid=real-session; HttpOnly; Path=/"]],"body":""}}}],"default":{"return":{"ok":{"status":200,"headers":[],"body":""}}}}}),
    );
    assert!(report["text"].as_str().unwrap().starts_with("null|"), "{report}");
    assert!(!report["text"].as_str().unwrap().contains("sid=real-session"), "{report}");
    assert_eq!(cookie(request(&r, "/after")), Some("sid=real-session"));
}
#[test]
fn credentialless_fetch_does_not_accept_set_cookie() {
    let (r, _) = visit_planned(
        r#"
        fetch('/login',{credentials:'omit'}).then(()=>fetch('/after'));
    "#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[["set-cookie","sid=real-session; HttpOnly; Path=/"]],"body":""}}}}),
    );
    assert_eq!(cookie(request(&r, "/after")), None);
}

#[test]
fn cookie_domain_path_secure_and_samesite_scopes_do_not_leak_credentials() {
    let (r, _) = visit(
        r#"
        fetch('https://sub.app.example/api',{credentials:'include'});
        fetch('http://sub.app.example/api',{credentials:'include'});
        fetch('https://evil.example/api',{credentials:'include'});
    "#,
        json!({}),
        json!({"set_cookies":[
            "shared=S; Domain=app.example; Secure; SameSite=None; Path=/",
            "lax=L; Domain=app.example; Path=/",
            "suffix=bad; Domain=example; Secure; SameSite=None; Path=/"
        ]}),
    );
    let calls: Vec<_> = r.events.iter().filter(|e| e.func == FETCH_OTHER).collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(cookie(calls[0]), Some("shared=S; lax=L"));
    assert_eq!(cookie(calls[1]), None);
    assert_eq!(cookie(calls[2]), None);
    let (r, _) = visit(
        "fetch('https://other.github.io/api',{credentials:'include'})",
        json!({}),
        json!({"url":"https://mine.github.io/","set_cookies":["suffix=bad; Domain=github.io; Secure; SameSite=None; Path=/"]}),
    );
    assert!(r.events.iter().filter(|e| e.func == FETCH_OTHER).all(|e| cookie(e).is_none()));
}
#[test]
fn same_named_cookies_at_different_paths_remain_distinct_and_ordered() {
    let (r, _) = visit("fetch('/account/api');fetch('/accountant')", json!({}), json!({"set_cookies":["sid=root; Path=/","sid=account; Path=/account"]}));
    assert_eq!(cookie(request(&r, "/account/api")), Some("sid=account; sid=root"));
    assert_eq!(cookie(request(&r, "/accountant")), Some("sid=root"));
}
#[test]
fn probe_cookie_names_do_not_overwrite_real_authentication_cookies() {
    let (r, _) = visit("fetch('/api')", json!({}), json!({"request_cookies":["af_session=real"],"probe_cookie":{"name":"af_session","value":"sk_probe"}}));
    assert_eq!(cookie(request(&r, "/api")), Some("af_session=real; af_session_1=sk_probe"));
}
#[test]
fn cookies_from_pending_fetch_responses_apply_when_the_response_arrives() {
    let (r, _) = visit_planned(
        r#"
        const a=fetch('/login');fetch('/before');a.then(()=>fetch('/after'));
    "#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"rules":[{"when":{"path":"/login"},"return":{"ok":{"status":200,"headers":[["set-cookie","sid=real; HttpOnly; Path=/"]],"body":""}}}],"default":{"return":{"ok":{"status":200,"headers":[],"body":""}}}}}),
    );
    assert_eq!(cookie(request(&r, "/before")), None);
    assert_eq!(cookie(request(&r, "/after")), Some("sid=real"));
}
#[test]
fn scripts_cannot_forge_a_cookie_header_or_override_credentials_omit() {
    let (r, _) = visit(
        r#"
        fetch('/omit',{credentials:'omit',headers:{Cookie:'sid=forged'}});
        fetch('/real',{headers:{Cookie:'sid=forged'}});
    "#,
        json!({"sid":"real"}),
        json!({}),
    );
    assert_eq!(cookie(request(&r, "/omit")), None);
    assert_eq!(cookie(request(&r, "/real")), Some("sid=real"));
}

#[test]
fn beacon_response_cookies_are_not_visible_before_the_response_arrives() {
    let (r, _) = visit_planned(
        r#"
        navigator.sendBeacon('/beacon','hello');fetch('/before');
        setTimeout(()=>fetch('/after'),50);
    "#,
        json!({}),
        json!({}),
        json!({FETCH_OWN:{"rules":[{"when":{"path":"/beacon"},"return":{"ok":{"status":200,"headers":[["set-cookie","sid=real; HttpOnly; Path=/"]],"body":""}}}],"default":{"return":{"ok":{"status":200,"headers":[],"body":""}}}}}),
    );
    assert_eq!(cookie(request(&r, "/before")), None);
    assert_eq!(cookie(request(&r, "/after")), Some("sid=real"));
}

#[test]
fn cookie_prefixes_and_httponly_cannot_be_forged_by_script_writes() {
    let (r, _) = visit(
        r#"
        document.cookie='js=hidden; HttpOnly; Path=/';fetch('/api');
    "#,
        json!({}),
        json!({"set_cookies":[
            "__Host-good=G; Secure; Path=/",
            "__Host-domain=bad; Secure; Domain=app.example; Path=/",
            "__Secure-insecure=bad; Path=/"
        ]}),
    );
    assert_eq!(cookie(request(&r, "/api")), Some("__Host-good=G"));
}
