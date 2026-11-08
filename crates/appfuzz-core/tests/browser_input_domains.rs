//! Native numeric/calendar input domains, defaults and attribute mutations.
//! Ordinary cases were compared with Chrome 157 and Firefox 158 (Firefox does
//! not support month/week). Calendar strings use HTML's lexical year domain,
//! independently of Date/Chrome's TimeClip bound; normalization preserves a
//! valid date spelling and shortens the time as specified by WHATWG HTML.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let script = format!("const CASE={};{};for(const line of lines)console.log(line)", json!(case), include_str!("fixtures/input_domains.js"));
    let input = json!({"url":"https://app.example/","html":format!("<!doctype html><body><script>{script}</script>")});
    let plan = net_plan(&json!({FETCH_OWN:{"return":{"ok":{"status":200,"headers":[],"body":"ok"}}}}).to_string()).unwrap();
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], plan, 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert!(report.get("fatal").is_none(), "{report}");
    assert_eq!(report["errors"], json!([]), "{report}");
    report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap().to_owned()).collect()
}

#[test]
fn number_values() {
    assert_eq!(
        visit("number-values"),
        [
            "number-values [\"\",\"\"]",
            "number-values [\"bad\",\"\"]",
            "number-values [\"0\",\"0\"]",
            "number-values [\"-0\",\"-0\"]",
            "number-values [\"+1\",\"\"]",
            "number-values [\"01\",\"01\"]",
            "number-values [\"1.\",\"\"]",
            "number-values [\"1.0\",\"1.0\"]",
            "number-values [\".5\",\".5\"]",
            "number-values [\"-.5\",\"-.5\"]",
            "number-values [\"1e2\",\"1e2\"]",
            "number-values [\"1E+2\",\"1E+2\"]",
            "number-values [\"1e\",\"\"]",
            "number-values [\"1e309\",\"\"]",
            "number-values [\"1e-400\",\"1e-400\"]",
            "number-values [\" 1\",\"\"]",
            "number-values [\"1 \",\"\"]",
            "number-values [\"0x10\",\"\"]",
            "number-values [\"Infinity\",\"\"]",
            "number-values [\"NaN\",\"\"]",
            "number-values [\"1_000\",\"\"]",
            "number-values [\"--1\",\"\"]",
            "number-values [\"1\\n2\",\"\"]"
        ]
    );
}

#[test]
fn number_constraints() {
    assert_eq!(
        visit("number-constraints"),
        [
            "number-constraints [\"-1\",\"-1\"]",
            "number-constraints [\"0\",\"0\"]",
            "number-constraints [\"0.5\",\"0.5\"]",
            "number-constraints [\"5\",\"5\"]",
            "number-constraints [\"10\",\"10\"]",
            "number-constraints [\"11\",\"11\"]"
        ]
    );
}

#[test]
fn range_values() {
    assert_eq!(
        visit("range-values"),
        [
            "range-values [\"\",\"50\"]",
            "range-values [\"bad\",\"50\"]",
            "range-values [\"-1\",\"0\"]",
            "range-values [\"0\",\"0\"]",
            "range-values [\"0.5\",\"1\"]",
            "range-values [\"1\",\"1\"]",
            "range-values [\"49.4\",\"49\"]",
            "range-values [\"49.5\",\"50\"]",
            "range-values [\"50.5\",\"51\"]",
            "range-values [\"99.7\",\"100\"]",
            "range-values [\"100\",\"100\"]",
            "range-values [\"101\",\"100\"]",
            "range-values [\"1e309\",\"50\"]"
        ]
    );
}

#[test]
fn range_fractions() {
    assert_eq!(
        visit("range-fractions"),
        [
            "range-fractions [\"\",\"0.5\"]",
            "range-fractions [\"0.05\",\"0.1\"]",
            "range-fractions [\"0.15\",\"0.2\"]",
            "range-fractions [\"0.25\",\"0.3\"]",
            "range-fractions [\"0.35\",\"0.4\"]",
            "range-fractions [\"0.99\",\"1\"]",
            "range-fractions [\"-1\",\"0\"]",
            "range-fractions [\"1.2\",\"1\"]"
        ]
    );
}

#[test]
fn range_base() {
    assert_eq!(
        visit("range-base"),
        [
            "range-base [\"\",\"7\"]",
            "range-base [\"1\",\"1\"]",
            "range-base [\"2\",\"1\"]",
            "range-base [\"4\",\"4\"]",
            "range-base [\"5\",\"4\"]",
            "range-base [\"6\",\"7\"]",
            "range-base [\"8\",\"7\"]",
            "range-base [\"10\",\"10\"]",
            "range-base [\"11\",\"10\"]"
        ]
    );
}

#[test]
fn range_any() {
    assert_eq!(
        visit("range-any"),
        [
            "range-any [\"\",\"0.5\"]",
            "range-any [\"bad\",\"0.5\"]",
            "range-any [\"0.125\",\"0.125\"]",
            "range-any [\"-1\",\"0\"]",
            "range-any [\"2\",\"1\"]",
            "range-any [\"1e-20\",\"1e-20\"]"
        ]
    );
}

#[test]
fn range_initial() {
    assert_eq!(
        visit("range-initial"),
        [
            "range-initial <input type=range> 50",
            "range-initial <input type=range max=200> 100",
            "range-initial <input max=200 type=range> 100",
            "range-initial <input type=range min=10 max=20> 15",
            "range-initial <input min=10 max=20 type=range> 15",
            "range-initial <input value=50 type=range min=0 max=100 step=20> 60",
            "range-initial <input type=range value=10 min=5 max=15 step=3> 11",
            "range-initial <input type=range min=10 max=5> 10",
            "range-initial <input type=range min=0 max=1 step=2> 0"
        ]
    );
}

#[test]
fn range_attribute_numbers() {
    assert_eq!(
        visit("range-attribute-numbers"),
        [
            "range-attribute-numbers [\"+2\",\"0\"]",
            "range-attribute-numbers [\" 2\",\"0\"]",
            "range-attribute-numbers [\"2junk\",\"0\"]",
            "range-attribute-numbers [\"0x2\",\"0\"]",
            "range-attribute-numbers [\"1.5\",\"1.5\"]",
            "range-attribute-numbers [\"Infinity\",\"0\"]",
            "range-attribute-numbers [\"1e309\",\"0\"]",
            "range-attribute-numbers [\"-3\",\"-3\"]"
        ]
    );
}

#[test]
fn range_step_values() {
    assert_eq!(
        visit("range-step-values"),
        [
            "range-step-values [\"0\",\"0\"]",
            "range-step-values [\"-1\",\"0\"]",
            "range-step-values [\"bad\",\"0\"]",
            "range-step-values [\"ANY\",\"0.35\"]",
            "range-step-values [\"0.2junk\",\"0\"]",
            "range-step-values [\" 0.2\",\"0\"]",
            "range-step-values [\"+0.2\",\"0\"]",
            "range-step-values [\"1e-1\",\"0.4\"]"
        ]
    );
}

#[test]
fn range_dynamic() {
    assert_eq!(
        visit("range-dynamic"),
        ["range-dynamic initial 50", "range-dynamic max 50", "range-dynamic clamp 100", "range-dynamic step 80", "range-dynamic value-attr 80 91"]
    );
}

#[test]
fn range_base_attribute() {
    assert_eq!(visit("range-base-attribute"), ["range-base-attribute before 0.8", "range-base-attribute after 0.8 0.1", "range-base-attribute set 0.7"]);
}

#[test]
fn date_values() {
    assert_eq!(
        visit("date-values"),
        [
            "date-values [\"\",\"\"]",
            "date-values [\"bad\",\"\"]",
            "date-values [\"2024-02-29\",\"2024-02-29\"]",
            "date-values [\"2023-02-29\",\"\"]",
            "date-values [\"2000-02-29\",\"2000-02-29\"]",
            "date-values [\"1900-02-29\",\"\"]",
            "date-values [\"2024-2-01\",\"\"]",
            "date-values [\"2024-01-1\",\"\"]",
            "date-values [\"0000-01-01\",\"\"]",
            "date-values [\"0001-01-01\",\"0001-01-01\"]",
            "date-values [\"00001-01-01\",\"00001-01-01\"]",
            "date-values [\"99999-12-31\",\"99999-12-31\"]",
            "date-values [\"275760-09-13\",\"275760-09-13\"]",
            "date-values [\"275760-09-14\",\"275760-09-14\"]",
            "date-values [\"999999999999-01-01\",\"999999999999-01-01\"]",
            "date-values [\"2024-13-01\",\"\"]",
            "date-values [\"2024-04-31\",\"\"]",
            "date-values [\"2024-01-01Z\",\"\"]"
        ]
    );
}

#[test]
fn month_values() {
    assert_eq!(
        visit("month-values"),
        [
            "month-values [\"\",\"\"]",
            "month-values [\"bad\",\"\"]",
            "month-values [\"2024-02\",\"2024-02\"]",
            "month-values [\"2024-2\",\"\"]",
            "month-values [\"0000-01\",\"\"]",
            "month-values [\"0001-01\",\"0001-01\"]",
            "month-values [\"00001-01\",\"00001-01\"]",
            "month-values [\"99999-12\",\"99999-12\"]",
            "month-values [\"2024-00\",\"\"]",
            "month-values [\"2024-13\",\"\"]",
            "month-values [\"2024-02-01\",\"\"]"
        ]
    );
}

#[test]
fn week_values() {
    assert_eq!(
        visit("week-values"),
        [
            "week-values [\"\",\"\"]",
            "week-values [\"bad\",\"\"]",
            "week-values [\"2020-W53\",\"2020-W53\"]",
            "week-values [\"2021-W53\",\"\"]",
            "week-values [\"2015-W53\",\"2015-W53\"]",
            "week-values [\"2009-W53\",\"2009-W53\"]",
            "week-values [\"2024-W01\",\"2024-W01\"]",
            "week-values [\"2024-W00\",\"\"]",
            "week-values [\"2024-W54\",\"\"]",
            "week-values [\"2024-W1\",\"\"]",
            "week-values [\"0001-W01\",\"0001-W01\"]",
            "week-values [\"0000-W01\",\"\"]",
            "week-values [\"00001-W01\",\"00001-W01\"]",
            "week-values [\"2024-w01\",\"\"]"
        ]
    );
}

#[test]
fn time_values() {
    assert_eq!(
        visit("time-values"),
        [
            "time-values [\"\",\"\"]",
            "time-values [\"bad\",\"\"]",
            "time-values [\"00:00\",\"00:00\"]",
            "time-values [\"23:59\",\"23:59\"]",
            "time-values [\"24:00\",\"\"]",
            "time-values [\"12:34:56\",\"12:34:56\"]",
            "time-values [\"12:34:60\",\"\"]",
            "time-values [\"12:34:56.1\",\"12:34:56.1\"]",
            "time-values [\"12:34:56.120\",\"12:34:56.120\"]",
            "time-values [\"12:34:56.1234\",\"\"]",
            "time-values [\"1:02\",\"\"]",
            "time-values [\"12:3\",\"\"]",
            "time-values [\"12:34Z\",\"\"]",
            "time-values [\"12:34:00.000\",\"12:34:00.000\"]",
            "time-values [\"12:34.5\",\"\"]"
        ]
    );
}

#[test]
fn datetime_values() {
    assert_eq!(
        visit("datetime-values"),
        [
            "datetime-values [\"\",\"\"]",
            "datetime-values [\"bad\",\"\"]",
            "datetime-values [\"2024-02-29T12:34\",\"2024-02-29T12:34\"]",
            "datetime-values [\"2024-02-29 12:34\",\"2024-02-29T12:34\"]",
            "datetime-values [\"2024-02-29T12:34:00\",\"2024-02-29T12:34\"]",
            "datetime-values [\"2024-02-29T12:34:00.100\",\"2024-02-29T12:34:00.1\"]",
            "datetime-values [\"2024-02-29T12:34:56.120\",\"2024-02-29T12:34:56.12\"]",
            "datetime-values [\"2023-02-29T12:34\",\"\"]",
            "datetime-values [\"2024-01-01T24:00\",\"\"]",
            "datetime-values [\"2024-01-01t12:34\",\"\"]",
            "datetime-values [\"2024-01-01T12:34Z\",\"\"]",
            "datetime-values [\"00001-01-01T00:00\",\"00001-01-01T00:00\"]"
        ]
    );
}

#[test]
fn typed_parse_order() {
    assert_eq!(
        visit("typed-parse-order"),
        [
            "typed-parse-order [\"number\",\"bad\",false,\"\"]",
            "typed-parse-order [\"number\",\"bad\",true,\"\"]",
            "typed-parse-order [\"range\",\"bad\",false,\"50\"]",
            "typed-parse-order [\"range\",\"bad\",true,\"50\"]",
            "typed-parse-order [\"date\",\"2024-02-29\",false,\"2024-02-29\"]",
            "typed-parse-order [\"date\",\"2024-02-29\",true,\"2024-02-29\"]",
            "typed-parse-order [\"date\",\"bad\",false,\"\"]",
            "typed-parse-order [\"date\",\"bad\",true,\"\"]",
            "typed-parse-order [\"time\",\"12:34:56.120\",false,\"12:34:56.120\"]",
            "typed-parse-order [\"time\",\"12:34:56.120\",true,\"12:34:56.120\"]",
            "typed-parse-order [\"datetime-local\",\"2024-02-29 12:34:00.100\",false,\"2024-02-29T12:34:00.1\"]",
            "typed-parse-order [\"datetime-local\",\"2024-02-29 12:34:00.100\",true,\"2024-02-29T12:34:00.1\"]"
        ]
    );
}

#[test]
fn typed_defaults() {
    assert_eq!(
        visit("typed-defaults"),
        [
            "typed-defaults number  bad",
            "typed-defaults range 50 bad",
            "typed-defaults date  bad",
            "typed-defaults month  bad",
            "typed-defaults week  bad",
            "typed-defaults time  bad",
            "typed-defaults datetime-local  bad"
        ]
    );
}

#[test]
fn range_decimals() {
    assert_eq!(
        visit("range-decimals"),
        [
            "range-decimals [{\"min\":\"-1\",\"max\":\"1\",\"step\":\".1\"},\"-.15\",\"-0.1\"]",
            "range-decimals [{\"min\":\"-.35\",\"max\":\".35\",\"step\":\".1\"},\"0\",\"0.05\"]",
            "range-decimals [{\"min\":\"0\",\"max\":\"1\",\"step\":\".3\"},\".99\",\"0.9\"]",
            "range-decimals [{\"value\":\".2\",\"min\":\"bad\",\"max\":\".25\",\"step\":\".3\"},\".1\",\"0.2\"]",
            "range-decimals [{\"value\":\"1\",\"max\":\".5\",\"step\":\"2\"},\".25\",\"0.25\"]",
            "range-decimals [{\"min\":\"-1e308\",\"max\":\"1e308\",\"step\":\"any\"},\"\",\"0\"]",
            "range-decimals [{\"min\":\"1e308\",\"max\":\"1.7e308\",\"step\":\"any\"},\"\",\"1.35e+308\"]",
            "range-decimals [{\"min\":\"0\",\"max\":\"1e-300\",\"step\":\"1e-301\"},\"1.5e-301\",\"2e-301\"]",
            "range-decimals [{\"min\":\"0\",\"max\":\"1\",\"step\":\"1e-320\"},\".123\",\"0.123\"]",
            "range-decimals [{\"min\":\"-100\",\"max\":\"100\",\"step\":\"2\"},\"-3\",\"-2\"]",
            "range-decimals [{\"min\":\"0\",\"max\":\"1\",\"step\":\".1\"},\"0.30000000000000004\",\"0.3\"]"
        ]
    );
}

#[test]
fn range_reflection() {
    assert_eq!(
        visit("range-reflection"),
        [
            "range-reflection min 10 10 50",
            "range-reflection max 20 20 20",
            "range-reflection step 3 3 19",
            "range-reflection changed 16",
            "range-reflection removed  15",
            "range-reflection coerced 1 15",
            "range-reflection brand min TypeError",
            "range-reflection brand max TypeError",
            "range-reflection brand step TypeError"
        ]
    );
}

#[test]
fn domain_copies_reset() {
    assert_eq!(
        visit("domain-copies-reset"),
        [
            "domain-copies-reset initial n  bad",
            "domain-copies-reset copy n   bad",
            "domain-copies-reset initial r 7 8",
            "domain-copies-reset copy r 4 4 8",
            "domain-copies-reset initial d  2023-02-29",
            "domain-copies-reset copy d   2023-02-29",
            "domain-copies-reset initial t 2024-02-29T12:34:00.1 2024-02-29 12:34:00.100",
            "domain-copies-reset copy t   2024-02-29 12:34:00.100",
            "domain-copies-reset data [[\"n\",\"\"],[\"r\",\"4\"],[\"d\",\"\"],[\"t\",\"\"]]",
            "domain-copies-reset reset [[\"n\",\"\"],[\"r\",\"7\"],[\"d\",\"\"],[\"t\",\"2024-02-29T12:34:00.1\"]]"
        ]
    );
}

#[test]
fn domain_type_changes() {
    assert_eq!(
        visit("domain-type-changes"),
        [
            "domain-type-changes [\"text\",\"number\",\"bad\",\"\",\"\"]",
            "domain-type-changes [\"text\",\"number\",\"1e2\",\"1e2\",\"\"]",
            "domain-type-changes [\"text\",\"range\",\"2.5\",\"3\",\"\"]",
            "domain-type-changes [\"number\",\"text\",\"bad\",\"\",\"\"]",
            "domain-type-changes [\"range\",\"text\",\"bad\",\"50\",\"\"]",
            "domain-type-changes [\"text\",\"date\",\"2023-02-29\",\"\",\"\"]",
            "domain-type-changes [\"text\",\"week\",\"2021-W53\",\"\",\"\"]",
            "domain-type-changes [\"text\",\"datetime-local\",\"2024-02-29 12:34:00.100\",\"2024-02-29T12:34:00.1\",\"\"]"
        ]
    );
}

#[test]
fn domain_intrinsics() {
    assert_eq!(visit("domain-intrinsics"), ["domain-intrinsics [\"\",\"-0.1\",\"\",\"2024-02-29T12:34:00.1\",0]"]);
}

#[test]
fn week_year_matrix() {
    assert_eq!(
        visit("week-year-matrix"),
        [
            "week-year-matrix 1 00010000100000100001000001000001000010000010000100000100000100001000001000010000",
            "week-year-matrix 81 01000001000010000010000010000010000100000100000100001000001000010000010000010000",
            "week-year-matrix 161 10000010000100000100000100001000001000001000001000010000010000010000100000100001",
            "week-year-matrix 241 00000100000100001000001000010000010000010000100000100001000000100001000001000001",
            "week-year-matrix 321 00001000001000010000010000010000100000100001000001000001000010000010000100000100"
        ]
    );
}

#[test]
fn domain_line_endings() {
    assert_eq!(
        visit("domain-line-endings"),
        [
            "domain-line-endings [\"number\",\"1\\n\",\"\"]",
            "domain-line-endings [\"number\",\"1\\r\",\"\"]",
            "domain-line-endings [\"number\",\"１\",\"\"]",
            "domain-line-endings [\"number\",\"1 \",\"\"]",
            "domain-line-endings [\"range\",\"1\\n\",\"50\"]",
            "domain-line-endings [\"date\",\"2024-01-01\\n\",\"\"]",
            "domain-line-endings [\"month\",\"2024-01\\n\",\"\"]",
            "domain-line-endings [\"week\",\"2024-W01\\n\",\"\"]",
            "domain-line-endings [\"time\",\"12:00\\n\",\"\"]",
            "domain-line-endings [\"datetime-local\",\"2024-01-01T12:00\\n\",\"\"]"
        ]
    );
}

#[test]
fn driver_types_representative_numeric_calendar_values() {
    let browser = Browser::shared().unwrap();
    let html = r#"<!doctype html><body><form><script>
 for(const type of ['number','date','month','week','time','datetime-local','text']){
  const i=document.createElement('input');i.type=type;i.name=type;document.querySelector('form').append(i);
  i.addEventListener('input',event=>console.log('typed',type,JSON.stringify([i.value,new FormData(i.form).get(type),event.isTrusted])));
 }
 </script>"#;
    let input = json!({"url":"https://app.example/","html":html});
    let run = browser.app.run(&browser.app.spec(browser.app.export(SESSION).unwrap(), vec![json!(input.to_string())], Plan::default(), 1));
    assert_eq!(run.outcome.kind, OutcomeKind::Ok, "{:?}", run.outcome);
    let report: Value = serde_json::from_str(run.result.as_ref().unwrap().as_str().unwrap()).unwrap();
    assert_eq!(report["errors"], json!([]), "{report}");
    let logs: Vec<_> = report["console"].as_array().unwrap().iter().map(|v| v["text"].as_str().unwrap()).collect();
    assert_eq!(
        logs,
        [
            "typed number [\"1\",\"1\",true]",
            "typed date [\"2024-01-01\",\"2024-01-01\",true]",
            "typed month [\"2024-01\",\"2024-01\",true]",
            "typed week [\"2024-W01\",\"2024-W01\",true]",
            "typed time [\"12:00\",\"12:00\",true]",
            "typed datetime-local [\"2024-01-01T12:00\",\"2024-01-01T12:00\",true]",
            "typed text [\"x\",\"x\",true]",
        ]
    );
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
