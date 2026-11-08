//! Blob/File byte storage, conversions and private operations. Native Chrome
//! and Firefox agree except the signed64 boundary, where WebIDL matches Chrome.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    visit_at(case, None)
}
fn visit_at(case: &str, now: Option<f64>) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/blobs.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"now":now,"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["requests"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn blob_binary() {
    assert_eq!(visit("blob-binary"), ["5 0,128,255,195,169 \"\\u0000��é\"", "true 5 5"]);
}

#[test]
fn blob_views() {
    assert_eq!(visit("blob-views"), ["3 255,0,128", "3 255,0,128", "5 9,255,0,128,9"]);
}

#[test]
fn blob_nesting() {
    assert_eq!(visit("blob-nesting"), ["4 120,255,128,121 \"x��y\""]);
}

#[test]
fn blob_unicode_slices() {
    assert_eq!(
        visit("blob-unicode-slices"),
        [
            "6",
            "1 text/plain 195 \"�\"",
            "2 text/plain 169,240 \"��\"",
            "4 text/plain 240,159,166,128 \"🦀\"",
            "2 text/plain 166,128 \"��\"",
            "0 text/plain  \"\""
        ]
    );
}

#[test]
fn blob_endings() {
    assert_eq!(
        visit("blob-endings"),
        ["transparent 97,13,10,98,13,99,10,100 \"a\\r\\nb\\rc\\nd\"", "native 97,10,98,10,99,10,100 \"a\\nb\\nc\\nd\"", "bad TypeError", " TypeError"]
    );
}

#[test]
fn blob_parts_validation() {
    assert_eq!(visit("blob-parts-validation"), ["TypeError", "TypeError", "TypeError", "TypeError", "TypeError", "defaults 0 0"]);
}

#[test]
fn blob_conversion_order() {
    assert_eq!(visit("blob-conversion-order"), ["part,endings,type,mime text/plain 1"]);
}

#[test]
fn file_required() {
    assert_eq!(visit("file-required"), ["TypeError", "TypeError", "TypeError", "default-now true number"]);
}

#[test]
fn file_last_modified() {
    assert_eq!(
        visit("file-last-modified"),
        [
            "object number 0",
            "number number 0",
            "number number 0",
            "number number 0",
            "number number 1",
            "number number -1",
            "number number -9223372036854776000",
            "number number 0",
            "bigint TypeError",
            "symbol TypeError",
            "coerced 1 13 1"
        ]
    );
}

#[test]
fn file_conversion_order() {
    assert_eq!(visit("file-conversion-order"), ["part,name,endings,type,lastModified,number name text/plain 2"]);
}

#[test]
fn file_private_super() {
    assert_eq!(visit("file-private-super"), ["name 1 5 0"]);
}

#[test]
fn blob_private_codecs() {
    assert_eq!(visit("blob-private-codecs"), ["3 255,0,128 \"�\\u0000�\" 0"]);
}

#[test]
fn blob_clone_bytes() {
    assert_eq!(visit("blob-clone-bytes"), ["true 3 text/plain   255,0,128 \"�\\u0000�\"", "true 3  name 5 255,0,128 \"�\\u0000�\""]);
}

#[test]
fn file_reader_bytes() {
    assert_eq!(
        visit("file-reader-bytes"),
        ["readAsArrayBuffer 255,0,128", "readAsText \"�\\u0000�\"", "readAsDataURL \"data:application/octet-stream;base64,/wCA\""]
    );
}

#[test]
fn blob_copy_after_options() {
    assert_eq!(visit("blob-copy-after-options"), ["9,2 text/plain"]);
}

#[test]
fn blob_detach_after_conversion() {
    assert_eq!(visit("blob-detach-after-conversion"), ["false 0 ", "true 0 "]);
}

#[test]
fn blob_options_dictionary() {
    assert_eq!(visit("blob-options-dictionary"), ["undefined 0", "object 0", "number TypeError", "boolean TypeError", "string TypeError"]);
}

#[test]
fn blob_private_buffer_brands() {
    assert_eq!(visit("blob-private-buffer-brands"), ["3 255,0,128 0"]);
}

#[test]
fn blob_initially_detached() {
    assert_eq!(visit("blob-initially-detached"), ["false 0 ", "true 0 "]);
}

#[test]
fn blob_bom_and_invalid() {
    assert_eq!(
        visit("blob-bom-and-invalid"),
        ["239,187,191,120 \"x\"", "239,187,191,239,187,191,120 \"﻿x\"", "224,128,128 \"���\"", "240,159 \"�\"", "237,160,128 \"���\""]
    );
}

#[test]
fn blob_promise_brands() {
    assert_eq!(
        visit("blob-promise-brands"),
        ["text promise true", "text TypeError", "arrayBuffer promise true", "arrayBuffer TypeError", "bytes promise true", "bytes TypeError"]
    );
}

#[test]
fn blob_private_view_length() {
    assert_eq!(visit("blob-private-view-length"), ["3 3 3 0"]);
}

#[test]
fn blob_resizable_sources() {
    assert_eq!(visit("blob-resizable-sources"), ["buffer TypeError 0", "typed TypeError 0", "view TypeError 0"]);
}

#[test]
fn blob_default_dictionaries() {
    assert_eq!(visit("blob-default-dictionaries"), ["0 0 name number 0"]);
}

#[test]
fn blob_bytes_copy() {
    assert_eq!(visit("blob-bytes-copy"), ["true 255 128 255,0,128"]);
}

#[test]
fn file_reader_base64_padding() {
    assert_eq!(
        visit("file-reader-base64-padding"),
        [
            "data:application/octet-stream;base64,",
            "data:application/octet-stream;base64,AA==",
            "data:application/octet-stream;base64,/w==",
            "data:application/octet-stream;base64,/4A=",
            "data:application/octet-stream;base64,/4AAQA=="
        ]
    );
}

#[test]
fn file_default_integer() {
    assert_eq!(visit("file-default-integer"), ["true true true"]);
}

#[test]
fn default_file_metadata_uses_integer_virtual_milliseconds() {
    for now in [1.75, -1.75] {
        assert_eq!(visit_at("file-default-integer", Some(now)), ["true true true"]);
    }
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
