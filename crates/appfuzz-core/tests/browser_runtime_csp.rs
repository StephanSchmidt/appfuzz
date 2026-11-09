//! Runtime CSP references checked against native browsers and current standards.
//! Explicit standard expectations cover hash padding, event integers, nonce
//! copying and the pre-request/post-response checks for report-only fetch.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/runtime_csp.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let mut input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script nonce=local-test>{script}</script>"),"csp":["default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self' https://sink.example"]});
    if case.starts_with("report-only-") {
        input["csp_report_only"] = json!(["script-src 'none' 'report-sample';connect-src 'none'"]);
    }
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], network_plan(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    if case == "function-keeps-lone-surrogate-source" || case == "hash-source-replaces-lone-surrogate" {
        assert!(
            report["code"].as_array().unwrap().iter().any(|entry| entry["code_utf16"].as_array().is_some_and(|units| units.contains(&json!(0xd800)))),
            "{report}"
        );
    }
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

fn network_plan() -> Plan {
    let mut rules = vec![];
    for prefix in ["/", "/nested/", "/changed/", "/headers/"] {
        for (name, body) in [
            ("data", json!({"path":format!("{prefix}data")}).to_string()),
            ("part.js", format!("globalThis.externalPath={};", json!(format!("{prefix}part.js")))),
            ("part.mjs", format!("import './dep.mjs';globalThis.modulePath={};", json!(format!("{prefix}part.mjs")))),
            ("dep.mjs", format!("globalThis.dependencyPath={};", json!(format!("{prefix}dep.mjs")))),
        ] {
            rules.push(json!({"when":{"path":format!("{prefix}{name}")},"return":{"ok":{"status":200,"headers":[],"body":body.as_bytes()}}}));
        }
    }
    Plan::parse(&json!({FETCH_OWN:{"rules":rules,"default":{"return":{"ok":{"status":404,"headers":[],"body":[]}}}}}).to_string()).unwrap()
}

#[test]
fn inline_none() {
    visit("inline-none", &["false"]);
}

#[test]
fn inline_empty() {
    visit("inline-empty", &["false"]);
}

#[test]
fn inline_fallback() {
    visit("inline-fallback", &["false"]);
}

#[test]
fn inline_unsafe_inline() {
    visit("inline-unsafe-inline", &["true"]);
}

#[test]
fn inline_matching_nonce() {
    visit("inline-matching-nonce", &["true"]);
}

#[test]
fn inline_nonce_case_mismatch() {
    visit("inline-nonce-case-mismatch", &["false"]);
}

#[test]
fn inline_nonce_disables_inline() {
    visit("inline-nonce-disables-inline", &["false"]);
}

#[test]
fn inline_invalid_nonce_keeps_inline() {
    visit("inline-invalid-nonce-keeps-inline", &["true"]);
}

#[test]
fn inline_strict_disables_inline() {
    visit("inline-strict-disables-inline", &["true"]);
}

#[test]
fn inline_element_override() {
    visit("inline-element-override", &["true"]);
}

#[test]
fn inline_attribute_does_not_override_element() {
    visit("inline-attribute-does-not-override-element", &["false"]);
}

#[test]
fn inline_first_duplicate_wins() {
    visit("inline-first-duplicate-wins", &["true"]);
}

#[test]
fn inline_sha256() {
    visit("inline-sha256", &["true"]);
}

#[test]
fn inline_sha384() {
    visit("inline-sha384", &["true"]);
}

#[test]
fn inline_sha512() {
    visit("inline-sha512", &["true"]);
}

#[test]
fn hash_unpadded() {
    visit("hash-unpadded", &["false"]);
}

#[test]
fn hash_url_safe() {
    visit("hash-url-safe", &["true"]);
}

#[test]
fn hash_wrong() {
    visit("hash-wrong", &["false"]);
}

#[test]
fn handler_none() {
    visit("handler-none", &["false"]);
}

#[test]
fn handler_unsafe_inline() {
    visit("handler-unsafe-inline", &["true"]);
}

#[test]
fn handler_nonce_is_not_handler() {
    visit("handler-nonce-is-not-handler", &["false"]);
}

#[test]
fn handler_unsafe_hashes() {
    visit("handler-unsafe-hashes", &["true"]);
}

#[test]
fn handler_hash_without_opt_in() {
    visit("handler-hash-without-opt-in", &["false"]);
}

#[test]
fn handler_attribute_override() {
    visit("handler-attribute-override", &["true"]);
}

#[test]
fn handler_element_is_not_handler() {
    visit("handler-element-is-not-handler", &["false"]);
}

#[test]
fn eval_none() {
    visit("eval-none", &["EvalError EvalError EvalError EvalError"]);
}

#[test]
fn eval_unsafe_eval() {
    visit("eval-unsafe-eval", &["5 5 async function anonymous(\n) {\nreturn 5\n} function* anonymous(\n) {\nyield 5\n}"]);
}

#[test]
fn eval_default_none() {
    visit("eval-default-none", &["EvalError EvalError EvalError EvalError"]);
}

#[test]
fn eval_default_eval() {
    visit("eval-default-eval", &["5 5 async function anonymous(\n) {\nreturn 5\n} function* anonymous(\n) {\nyield 5\n}"]);
}

#[test]
fn eval_element_only() {
    visit("eval-element-only", &["5 5 async function anonymous(\n) {\nreturn 5\n} function* anonymous(\n) {\nyield 5\n}"]);
}

#[test]
fn eval_attr_only() {
    visit("eval-attr-only", &["5 5 async function anonymous(\n) {\nreturn 5\n} function* anonymous(\n) {\nyield 5\n}"]);
}

#[test]
fn timer_blocked() {
    visit("timer-blocked", &["schedule ok number", "executed false"]);
}

#[test]
fn timer_allowed() {
    visit("timer-allowed", &["schedule ok number", "executed true"]);
}

#[test]
fn fetch_none() {
    visit("fetch-none", &["blocked TypeError"]);
}

#[test]
fn fetch_self() {
    visit("fetch-self", &["allowed 200"]);
}

#[test]
fn fetch_default_none() {
    visit("fetch-default-none", &["blocked TypeError"]);
}

#[test]
fn fetch_overrides_default() {
    visit("fetch-overrides-default", &["allowed 200"]);
}

#[test]
fn fetch_empty() {
    visit("fetch-empty", &["blocked TypeError"]);
}

#[test]
fn fetch_first_duplicate() {
    visit("fetch-first-duplicate", &["allowed 200"]);
}

#[test]
fn external_none() {
    visit("external-none", &["false"]);
}

#[test]
fn external_self() {
    visit("external-self", &["true"]);
}

#[test]
fn external_valid_nonce() {
    visit("external-valid-nonce", &["true"]);
}

#[test]
fn external_wrong_nonce() {
    visit("external-wrong-nonce", &["false"]);
}

#[test]
fn external_strict_dynamic() {
    visit("external-strict-dynamic", &["true"]);
}

#[test]
fn external_element_override() {
    visit("external-element-override", &["true"]);
}

#[test]
fn external_hash_with_integrity() {
    visit("external-hash-with-integrity", &["true"]);
}

#[test]
fn external_hash_needs_integrity() {
    visit("external-hash-needs-integrity", &["false"]);
}

#[test]
fn external_nonce_does_not_skip_sri() {
    visit("external-nonce-does-not-skip-sri", &["false"]);
}

#[test]
fn violation_event_constructor() {
    visit("violation-event-constructor", &["true x y enforce 1 4294967295", "TypeError"]);
}

#[test]
fn violation_inline_event() {
    visit("violation-inline-event", &["true inline script-src-elem script-src-elem enforce true true false true 200"]);
}

#[test]
fn violation_fetch_event() {
    visit("violation-fetch-event", &["true connect-src enforce 200"]);
}

#[test]
fn violation_sample() {
    visit("violation-sample", &["globalThis.cspHit=true"]);
}

#[test]
fn function_conversion_order() {
    visit("function-conversion-order", &["EvalError parameter,body"]);
}

#[test]
fn eval_non_string_does_not_compile() {
    visit("eval-non-string-does-not-compile", &["true"]);
}

#[test]
fn violation_dictionary_order() {
    visit(
        "violation-dictionary-order",
        &[
            "bubbles,cancelable,composed,blockedURI,columnNumber,disposition,documentURI,effectiveDirective,lineNumber,originalPolicy,referrer,sample,sourceFile,statusCode,violatedDirective",
        ],
    );
}

#[test]
fn timer_policy_is_captured_at_scheduling() {
    visit("timer-policy-is-captured-at-scheduling", &["true"]);
}

#[test]
fn nonce_property_after_connection() {
    visit("nonce-property-after-connection", &["abCD  abCD"]);
}

#[test]
fn direct_eval_retains_lexical_bindings() {
    visit("direct-eval-retains-lexical-bindings", &["23"]);
}

#[test]
fn direct_eval_can_change_its_local_binding() {
    visit("direct-eval-can-change-its-local-binding", &["3"]);
}

// Module, report-only and Unicode references checked in both native browsers.
// Report-only fetch reports at both pre-request and post-response checks.
#[test]
fn module_external_nonce_inherits() {
    visit("module-external-nonce-inherits", &["true true"]);
}

#[test]
fn module_inline_nonce_inherits() {
    visit("module-inline-nonce-inherits", &["true true"]);
}

#[test]
fn module_strict_dynamic_inherits() {
    visit("module-strict-dynamic-inherits", &["true true"]);
}

#[test]
fn nonce_idl_does_not_reflect() {
    visit("nonce-idl-does-not-reflect", &["abCD true abCD"]);
}

#[test]
fn nonce_content_change_after_connection() {
    visit("nonce-content-change-after-connection", &["second second", "second "]);
}

#[test]
fn function_keeps_lone_surrogate_source() {
    visit("function-keeps-lone-surrogate-source", &["55296"]);
}

#[test]
fn hash_source_replaces_lone_surrogate() {
    visit("hash-source-replaces-lone-surrogate", &["55296"]);
}

#[test]
fn base_has_no_default_source_fallback() {
    visit("base-has-no-default-source-fallback", &["/nested/"]);
}

#[test]
fn report_only_script_still_runs() {
    visit("report-only-script-still-runs", &["true script-src-elem"]);
}

#[test]
fn report_only_fetch_still_connects() {
    visit("report-only-fetch-still-connects", &["200 report,report"]);
}

#[test]
fn report_only_eval_still_compiles() {
    visit("report-only-eval-still-compiles", &["5", "report"]);
}
