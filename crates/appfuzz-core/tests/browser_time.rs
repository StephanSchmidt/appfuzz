use appfuzz_core::{
    browser::Browser,
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
    wasi::{format_datetime, parse_datetime},
};
use serde_json::json;

fn app(script: &str, latency_ms: u64) -> App {
    let html = format!("<!doctype html><html><head><title>clock</title></head><body><p id=result></p><script>{script}</script></body></html>");
    let m: Manifest = serde_json::from_value(json!({
        "app":{"wasm":"clock.wasm"},
        "entry":{"export":"run","request":{"method":"GET","url":"/","stamp":"","day":"","minute":""},
            "fields":{"stamp":"clock.datetime","day":"clock.date","minute":"clock.time"},
            "output":{"status":"status","body":"body","body_format":"html"}},
        "functions":{"test:clock/delay#wait":{"latency_ms":latency_ms}}
    }))
    .unwrap();
    let source = format!(
        r#"(component
      (import "test:clock/delay" (instance $delay (export "wait" (func))))
      (core func $wait (canon lower (func $delay "wait")))
      (core module $guest
       (import "env" "wait" (func $wait))
       (memory (export "memory") 1)
       (global $next (mut i32) (i32.const 16384))
       (func (export "realloc") (param i32 i32 i32) (param $size i32) (result i32) (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.and (i32.add (i32.add (global.get $next) (local.get $size)) (i32.const 15)) (i32.const -16)))
        (local.get $ptr))
       (data (i32.const 128) {html})
       (func (export "run") (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
        (i32.store (i32.const 0) (i32.const 200))
        (if (i32.eq (local.get 3) (i32.const 1))
         (then (call $wait)
          (i32.store (i32.const 4) (i32.const 128))
          (i32.store (i32.const 8) (i32.const {len})))
         (else
          (i32.store (i32.const 4) (local.get 4))
          (i32.store (i32.const 8) (local.get 5))))
        (i32.const 0)))
      (core instance $guest (instantiate $guest (with "env" (instance (export "wait" (func $wait))))))
      (alias core export $guest "memory" (core memory $memory))
      (alias core export $guest "realloc" (core func $realloc))
      (type $request (record (field "method" string) (field "url" string) (field "stamp" string) (field "day" string) (field "minute" string)))
      (export $public-request "request" (type $request))
      (type $response (record (field "status" u16) (field "body" string)))
      (export $public-response "response" (type $response))
      (func (export "run") (param "request" $public-request) (result $public-response)
       (canon lift (core func $guest "run") (memory $memory) (realloc $realloc))))"#,
        html = serde_json::to_string(&html).unwrap(),
        len = html.len()
    );
    App::from_bytes(m, wat::parse_str(source).unwrap()).unwrap()
}

#[test]
fn page_loading_time_advances_the_browser_clock_before_scripts_run() {
    let app = app("fetch('/api?at='+Date.now());", 2500);
    let export = app.default_export().unwrap();
    let now = "2026-12-31T23:59:58";
    let mut spec = app.spec(export, app.default_args(export, now).unwrap(), Plan::default(), 1);
    spec.now = now.into();
    let page = app.run(&spec);
    assert_eq!(page.outcome.kind, OutcomeKind::Ok, "{:?}", page.outcome);
    let session = Browser::shared().unwrap().session(&app, &page, &|s| app.run(s)).unwrap();
    session.ensure_executed().unwrap();
    assert_eq!(session.report["errors"], json!([]));
    let request = &session.nested[0].spec.args[0];
    let sent_ms: i64 = request["url"].as_str().unwrap().split_once("?at=").unwrap().1.parse().unwrap();
    assert!(sent_ms >= parse_datetime(now).unwrap() * 1000 + 2500, "page loading time was lost: {request}");
}

#[test]
fn timed_browser_requests_advance_server_clocks_and_all_declared_clock_fields() {
    let app = app(
        "function ask(){fetch('/api?at='+Date.now()).then(r=>r.text()).then(t=>document.getElementById('result').textContent+=t+'|');}ask();setTimeout(ask,61000);setTimeout(ask,8*86400000);",
        0,
    );
    let export = app.default_export().unwrap();
    let now = "2026-12-31T23:59:58";
    let mut spec = app.spec(export, app.default_args(export, now).unwrap(), Plan::default(), 1);
    spec.now = now.into();
    let page = app.run(&spec);
    assert_eq!(page.outcome.kind, OutcomeKind::Ok, "{:?}", page.outcome);
    let session = Browser::shared().unwrap().session(&app, &page, &|s| app.run(s)).unwrap();
    session.ensure_executed().unwrap();
    assert_eq!(session.report["errors"], json!([]));
    assert_eq!(session.nested.len(), 3, "{:?}", session.report);
    for r in &session.nested {
        let request = &r.spec.args[0];
        let sent_ms: i64 = request["url"].as_str().unwrap().split_once("?at=").unwrap().1.parse().unwrap();
        let seconds = sent_ms.div_euclid(1000);
        let (day, minute, time) = format_datetime(seconds);
        assert_eq!(parse_datetime(&r.spec.now), Some(seconds), "server run starts at the browser request's time: {request}");
        assert_eq!(request["stamp"], format!("{day}T{time}"));
        assert_eq!(request["day"], day);
        assert_eq!(request["minute"], minute);
        assert_eq!(r.result.as_ref().unwrap()["body"], request["stamp"]);
        assert!(session.report["text"].as_str().unwrap().contains(request["stamp"].as_str().unwrap()), "{:?}", session.report);
        assert_eq!(app.run(&r.spec).result, r.result, "each timed request remains independently replayable");
    }
    assert!(session.nested[2].spec.now.starts_with("2027-01-08"));
}

#[test]
fn response_times_outside_the_browser_date_range_cannot_fall_back_to_the_old_time() {
    let app = app("", 0);
    let export = app.default_export().unwrap();
    let now = "2026-12-31T23:59:58";
    let mut spec = app.spec(export, app.default_args(export, now).unwrap(), Plan::default(), 1);
    spec.now = now.into();
    let mut page = app.run(&spec);
    page.totals.virtual_ns = u128::MAX.into();
    assert!(Browser::shared().unwrap().session(&app, &page, &|s| app.run(s)).is_err());
}

#[test]
fn a_timer_past_the_servers_supported_calendar_makes_the_visit_incomplete() {
    let app = app("setTimeout(()=>fetch('/api'),3000);", 0);
    let export = app.default_export().unwrap();
    let now = "9999-12-31T23:59:58";
    let mut spec = app.spec(export, app.default_args(export, now).unwrap(), Plan::default(), 1);
    spec.now = now.into();
    let page = app.run(&spec);
    let session = Browser::shared().unwrap().session(&app, &page, &|s| app.run(s)).unwrap();
    assert_eq!(session.nested.len(), 1);
    assert_eq!(session.nested[0].outcome.kind, OutcomeKind::Error);
    assert!(session.ensure_executed().is_err());
}
