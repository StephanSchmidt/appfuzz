//! Synthetic native-browser references for CSS Syntax component values and
//! Selectors forgiving lists. Quoted language ranges and top-level any-value
//! failures follow Firefox and the current CSS rules; Chromium 128 differs.
//! https://www.w3.org/TR/css-syntax-3/#any-value
use appfuzz_core::{
    browser::{Browser, HTML, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str, expected: &[&str]) {
    let browser = Browser::shared().unwrap();
    let fixture = include_str!("fixtures/css_components.js");
    let helpers = fixture.split("test('").next().unwrap();
    let selected = fixture.lines().find(|line| line.starts_with(&format!("test('{case}',"))).unwrap();
    let script = format!("const CASE={};{helpers}{selected};runTests().then(()=>{{for(const line of groups[CASE])console.log(line)}})", json!(case));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!([]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    assert!(run.events.iter().all(|event| event.func == HTML), "{:?}", run.events);
    assert_eq!(report["requests"], json!([]), "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, expected, "{case}");
}

#[test]
fn query_eof_blocks() {
    visit(
        "query-eof-blocks",
        &[
            ":is(.a 1",
            ":where(.a 1",
            ":not(.a 0",
            ":is(.a, 1",
            ":is(.a,[data-x 1",
            "[data-x 1",
            "[data-x=yes 1",
            "[data-x=\"yes 1",
            ":lang(\"en 0",
            ":is(.a/*unfinished 1",
            ":not(:is(.a 0",
        ],
    );
}

#[test]
fn query_escaped_function_space() {
    visit("query-escaped-function-space", &[":\\69 s(.a,:unknown) 1", ":\\69 s() 0", ":\\77 here(.a,[) 1", ":IS(.a,:unknown) 1"]);
}

#[test]
fn css_eof_and_bad_blocks() {
    visit(
        "css-eof-and-bad-blocks",
        &[
            "\":is(.a,[)\" 1",
            "\":is(.a,[class)\" 1",
            "\":is([class),.a)\" 0",
            "\":is(.a,[class))\" 1",
            "\":not([class\" 0",
            "\":not([class)\" SyntaxError",
            "\":is(.a,)\" 1",
            "\":is(.a))\" SyntaxError",
            "\"[data-x=\\\"yes\\n\" SyntaxError",
            "\"[data-x=\\\"yes\\\\\\n\\\"]\" 1",
            "\":is(.a/*end\" 1",
            "\".a/*end\" 1",
            "\"[data-x=yes/*end\" 1",
            "\":is([bad=],.a)\" 1",
            "\":where([bad=],.a)\" 1",
        ],
    );
}

#[test]
fn css_numeric_identifiers() {
    visit(
        "css-numeric-identifiers",
        &[
            "#123 SyntaxError",
            ".123 SyntaxError",
            "123 SyntaxError",
            "123abc SyntaxError",
            "[x=123] SyntaxError",
            "#\\31 23 1",
            ".\\31 23 1",
            "[x=\\31 23] 1",
            ":is(#123,.a) 1",
            ":is(.123,.a) 1",
            ":not(#123) SyntaxError",
        ],
    );
}

#[test]
fn css_comments_and_boundaries() {
    visit(
        "css-comments-and-boundaries",
        &[
            "\"b/**/.a\" 1",
            "\"b/**/b\" SyntaxError",
            "\":/**/is(.a)\" 1",
            "\":is/**/(.a)\" SyntaxError",
            "\":is(.a/**/,:unknown)\" 1",
            "\"b /*c*/ .a\" 0",
            "\"b/**/> i\" 0",
            "\".a/**/\" 1",
            "\"/*x*/.a\" 1",
            "\":\\\\69\\r\\ns(.a,:unknown)\" 1",
        ],
    );
}

#[test]
fn css_nth_token_values() {
    visit(
        "css-nth-token-values",
        &[
            ":nth-child(1) 1",
            ":nth-child(1.0) SyntaxError",
            ":nth-child(1.0n) SyntaxError",
            ":nth-child(1e0) SyntaxError",
            ":nth-child(+n) 2",
            ":nth-child(2n+1) 1",
            ":nth-child(2n + 1) 1",
            ":nth-child(1 of .a 1",
            ":nth-child(1 of :is(.a,:unknown) 1",
            ":nth-child(2n/**/+1) 1",
        ],
    );
}

#[test]
fn css_string_escapes() {
    visit(
        "css-string-escapes",
        &[
            "\"[data-x=\\\"yes\" 1",
            "\"[data-x='yes\" 1",
            "\"[data-x=\\\"y\\\\65 s\\\"]\" 1",
            "\":lang(\\\"en\" 1",
            "\":lang(\\\"en\\\")\" 1",
            "\":lang(en-US)\" 1",
            "\":lang(\\\"en\\\", \\\"fr\\\")\" 1",
            "\":is(.a,\\\"bad)\" 1",
            "\":is(.a,\\\"bad\\n)\" SyntaxError",
            "\":is(.a,[data-x=\\\"yes)\" 1",
        ],
    );
}

#[test]
fn css_input_normalization() {
    visit(
        "css-input-normalization",
        &[
            "\"#replacement\\u0000\" 1",
            "\"#replacement\\\\0 \" 1",
            "\".a\\r\\n\" 1",
            "\".a\\f\" 1",
            "\":\\\\000069 s()\" 0",
            "\":\\\\000069 s(.a,[)\" 1",
            "\":\\\\69\\ts(.a,[)\" 1",
            "\":IS(.a,[broken)\" 1",
        ],
    );
}

#[test]
fn css_bad_tokens_in_functions() {
    visit(
        "css-bad-tokens-in-functions",
        &[
            "\":is(.a,\\\"bad\\n)\" SyntaxError",
            "\":where(.a,\\\"bad\\n)\" SyntaxError",
            "\":is(.a,[x=\\\"bad\\n])\" 1",
            "\":is(.a,url(bad\\\"))\" SyntaxError",
            "\":where(.a,url(bad\\\"))\" SyntaxError",
            "\":is(.a,])\" SyntaxError",
            "\":where(.a,])\" SyntaxError",
            "\":is(.a,})\" SyntaxError",
        ],
    );
}

#[test]
fn css_comment_token_joins() {
    visit(
        "css-comment-token-joins",
        &[
            "#/**/id SyntaxError",
            "[x~/**/=yes] SyntaxError",
            "[x=y/**/es] SyntaxError",
            ":nth-child(2/**/n) SyntaxError",
            ":nth-child(2n/**/+1) 1",
            ":nth-child(n/**/-1) 2",
            ":nth-child(+/**/n) 2",
            ":nth-child(n-/**/1) 2",
            ":nth-child(1/**/of/**/.a) 1",
            ":nth-child(1 of.a) 1",
            ":nth-child(1 of b/**/b) SyntaxError",
            "[x=\"yes\"/**/i] 1",
            ":/**/is(.a) 1",
            "b/**/b SyntaxError",
            ":is(b/**/b,.a) 1",
        ],
    );
}

#[test]
fn css_attribute_value_grammar() {
    visit(
        "css-attribute-value-grammar",
        &[
            "[x=foo:bar] SyntaxError",
            "[x=foo/bar] SyntaxError",
            "[x=#abc] SyntaxError",
            "[x=foo()] SyntaxError",
            "[x=:is()] SyntaxError",
            "[x=*] SyntaxError",
            "[x=] SyntaxError",
            "[x=foo bar] SyntaxError",
            "[x=\"foo:bar\"] true",
            "[x=foo\\:bar] true",
            "[x=foo/**/bar] SyntaxError",
            "[x=\"foo:bar\"i] true",
            "[*|x] true",
            "[|x] true",
            "[x s] SyntaxError",
        ],
    );
}

#[test]
fn css_nesting_limit_remains_explicit_and_is_not_a_syntax_error() {
    let browser = Browser::shared().unwrap();
    let script = "const e=document.createElement('b');const q=':is('.repeat(100)+'.a'+')'.repeat(100);try{e.querySelectorAll(q)}catch(error){console.log(error.name)}console.log('continued')";
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert_eq!(report["errors"], json!([]), "{report}");
    assert_eq!(report["unmodelled"], json!(["selector:CSS nesting depth"]), "{report}");
    assert_eq!(report["busy"]["cut"], false, "{report}");
    let actual: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(actual, ["RangeError", "continued"]);
    assert!(run.events.is_empty());
}
