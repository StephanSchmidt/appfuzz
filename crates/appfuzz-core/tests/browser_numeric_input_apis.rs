//! HTML input numeric/date APIs checked against a local Chrome reference.
//! Month counts and Gregorian numeric conversions use HTML's unbounded positive
//! year domain. Date objects separately obey JavaScript's TimeClip limit.
//! Out-of-range Date objects and setter applicability order follow Firefox/HTML.
use appfuzz_core::{
    browser::{Browser, FETCH_OWN, SESSION},
    plan::Plan,
    record::OutcomeKind,
};
use serde_json::{Value, json};
fn visit(case: &str) -> Vec<String> {
    let browser = Browser::shared().unwrap();
    let script = format!("const CASE={};{};for(const line of lines)console.log(line)", json!(case), include_str!("fixtures/numeric_input_apis.js"));
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
fn numeric_api_types() {
    assert_eq!(
        visit("numeric-api-types"),
        [
            "numeric-api-types number 17 null",
            "numeric-api-types range 17 null",
            "numeric-api-types text NaN null",
            "numeric-api-types hidden NaN null",
            "numeric-api-types checkbox NaN null",
            "numeric-api-types date 1709164800000 2024-02-29T00:00:00.000Z",
            "numeric-api-types month 649 2024-02-01T00:00:00.000Z",
            "numeric-api-types week 1609113600000 2020-12-28T00:00:00.000Z",
            "numeric-api-types time 45296120 1970-01-01T12:34:56.120Z",
            "numeric-api-types datetime-local 1709210040000 null"
        ]
    );
}

#[test]
fn numeric_api_set() {
    assert_eq!(
        visit("numeric-api-set"),
        [
            "numeric-api-set NaN  ",
            "numeric-api-set Infinity 17 TypeError",
            "numeric-api-set -Infinity 17 TypeError",
            "numeric-api-set 0 0 ",
            "numeric-api-set 0.5 0.5 ",
            "numeric-api-set 25 25 ",
            "numeric-api-set null 0 ",
            "numeric-api-set undefined  ",
            "numeric-api-set 1 17 TypeError"
        ]
    );
}

#[test]
fn numeric_api_inapplicable() {
    assert_eq!(
        visit("numeric-api-inapplicable"),
        [
            "numeric-api-inapplicable text 5  InvalidStateError",
            "numeric-api-inapplicable text NaN  InvalidStateError",
            "numeric-api-inapplicable text Infinity  TypeError",
            "numeric-api-inapplicable hidden 5  InvalidStateError",
            "numeric-api-inapplicable hidden NaN  InvalidStateError",
            "numeric-api-inapplicable hidden Infinity  TypeError",
            "numeric-api-inapplicable checkbox 5  InvalidStateError",
            "numeric-api-inapplicable checkbox NaN  InvalidStateError",
            "numeric-api-inapplicable checkbox Infinity  TypeError",
            "numeric-api-inapplicable color 5 #000000 InvalidStateError",
            "numeric-api-inapplicable color NaN #000000 InvalidStateError",
            "numeric-api-inapplicable color Infinity #000000 TypeError",
            "numeric-api-inapplicable file 5  InvalidStateError",
            "numeric-api-inapplicable file NaN  InvalidStateError",
            "numeric-api-inapplicable file Infinity  TypeError"
        ]
    );
}

#[test]
fn numeric_api_brand() {
    assert_eq!(visit("numeric-api-brand"), ["numeric-api-brand get TypeError 0", "numeric-api-brand set TypeError 0"]);
}

#[test]
fn numeric_api_private() {
    assert_eq!(visit("numeric-api-private"), ["numeric-api-private get 17 0", "numeric-api-private set 23 0"]);
}

#[test]
fn numeric_api_date_values() {
    assert_eq!(
        visit("numeric-api-date-values"),
        [
            "numeric-api-date-values [\"date\",\"0001-01-01\",\"-62135596800000\",\"0001-01-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"date\",\"00001-01-01\",\"-62135596800000\",\"0001-01-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"date\",\"2000-02-29\",\"951782400000\",\"2000-02-29T00:00:00.000Z\"]",
            "numeric-api-date-values [\"date\",\"275760-09-13\",\"8640000000000000\",\"+275760-09-13T00:00:00.000Z\"]",
            "numeric-api-date-values [\"date\",\"275760-09-14\",\"8640000086400000\",\"invalid-date\"]",
            "numeric-api-date-values [\"month\",\"0001-01\",\"-23628\",\"0001-01-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"month\",\"1969-12\",\"-1\",\"1969-12-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"month\",\"2024-02\",\"649\",\"2024-02-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"week\",\"0001-W01\",\"-62135596800000\",\"0001-01-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"week\",\"1970-W01\",\"-259200000\",\"1969-12-29T00:00:00.000Z\"]",
            "numeric-api-date-values [\"week\",\"2020-W53\",\"1609113600000\",\"2020-12-28T00:00:00.000Z\"]",
            "numeric-api-date-values [\"time\",\"00:00\",\"0\",\"1970-01-01T00:00:00.000Z\"]",
            "numeric-api-date-values [\"time\",\"00:00:00.001\",\"1\",\"1970-01-01T00:00:00.001Z\"]",
            "numeric-api-date-values [\"time\",\"23:59:59.999\",\"86399999\",\"1970-01-01T23:59:59.999Z\"]",
            "numeric-api-date-values [\"datetime-local\",\"0001-01-01T00:00\",\"-62135596800000\",null]",
            "numeric-api-date-values [\"datetime-local\",\"2024-02-29T12:34:56.123\",\"1709210096123\",null]"
        ]
    );
}

#[test]
fn numeric_api_temporal_set() {
    assert_eq!(
        visit("numeric-api-temporal-set"),
        [
            "numeric-api-temporal-set [\"date\",-1,\"1969-12-31\",\"-86400000\",\"\"]",
            "numeric-api-temporal-set [\"date\",-0.5,\"1969-12-31\",\"-86400000\",\"\"]",
            "numeric-api-temporal-set [\"date\",0,\"1970-01-01\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"date\",0.5,\"1970-01-01\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"date\",1,\"1970-01-01\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"date\",1.5,\"1970-01-01\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"date\",86400000,\"1970-01-02\",\"86400000\",\"\"]",
            "numeric-api-temporal-set [\"date\",86400000.5,\"1970-01-02\",\"86400000\",\"\"]",
            "numeric-api-temporal-set [\"date\",-86400000.5,\"1969-12-30\",\"-172800000\",\"\"]",
            "numeric-api-temporal-set [\"date\",1709210096123,\"2024-02-29\",\"1709164800000\",\"\"]",
            "numeric-api-temporal-set [\"month\",-1,\"1969-12\",\"-1\",\"\"]",
            "numeric-api-temporal-set [\"month\",-0.5,\"1969-12\",\"-1\",\"\"]",
            "numeric-api-temporal-set [\"month\",0,\"1970-01\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"month\",0.5,\"1970-02\",\"1\",\"\"]",
            "numeric-api-temporal-set [\"month\",1,\"1970-02\",\"1\",\"\"]",
            "numeric-api-temporal-set [\"month\",1.5,\"1970-03\",\"2\",\"\"]",
            "numeric-api-temporal-set [\"month\",86400000,\"7201970-01\",\"86400000\",\"\"]",
            "numeric-api-temporal-set [\"month\",86400000.5,\"7201970-02\",\"86400001\",\"\"]",
            "numeric-api-temporal-set [\"month\",-86400000.5,\"\",\"NaN\",\"\"]",
            "numeric-api-temporal-set [\"month\",1709210096123,\"142434176646-12\",\"1709210096123\",\"\"]",
            "numeric-api-temporal-set [\"week\",-1,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",-0.5,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",0,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",0.5,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",1,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",1.5,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",86400000,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",86400000.5,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",-86400000.5,\"1970-W01\",\"-259200000\",\"\"]",
            "numeric-api-temporal-set [\"week\",1709210096123,\"2024-W09\",\"1708905600000\",\"\"]",
            "numeric-api-temporal-set [\"time\",-1,\"23:59:59.999\",\"86399999\",\"\"]",
            "numeric-api-temporal-set [\"time\",-0.5,\"23:59:59.999\",\"86399999\",\"\"]",
            "numeric-api-temporal-set [\"time\",0,\"00:00\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"time\",0.5,\"00:00\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"time\",1,\"00:00:00.001\",\"1\",\"\"]",
            "numeric-api-temporal-set [\"time\",1.5,\"00:00:00.001\",\"1\",\"\"]",
            "numeric-api-temporal-set [\"time\",86400000,\"00:00\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"time\",86400000.5,\"00:00\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"time\",-86400000.5,\"23:59:59.999\",\"86399999\",\"\"]",
            "numeric-api-temporal-set [\"time\",1709210096123,\"12:34:56.123\",\"45296123\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",-1,\"1969-12-31T23:59:59.999\",\"-1\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",-0.5,\"1969-12-31T23:59:59.999\",\"-1\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",0,\"1970-01-01T00:00\",\"0\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",0.5,\"1970-01-01T00:00:00.001\",\"1\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",1,\"1970-01-01T00:00:00.001\",\"1\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",1.5,\"1970-01-01T00:00:00.002\",\"2\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",86400000,\"1970-01-02T00:00\",\"86400000\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",86400000.5,\"1970-01-02T00:00:00.001\",\"86400001\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",-86400000.5,\"1969-12-30T23:59:59.999\",\"-86400001\",\"\"]",
            "numeric-api-temporal-set [\"datetime-local\",1709210096123,\"2024-02-29T12:34:56.123\",\"1709210096123\",\"\"]"
        ]
    );
}

#[test]
fn numeric_api_date_set() {
    assert_eq!(
        visit("numeric-api-date-set"),
        [
            "numeric-api-date-set [\"date\",null,\"\",\"\"]",
            "numeric-api-date-set [\"date\",\"undefined\",\"\",\"\"]",
            "numeric-api-date-set [\"date\",\"2024-02-29T23:59:56.123Z\",\"2024-02-29\",\"\"]",
            "numeric-api-date-set [\"date\",\"invalid-date\",\"\",\"\"]",
            "numeric-api-date-set [\"date\",{},\"\",\"TypeError\"]",
            "numeric-api-date-set [\"date\",5,\"\",\"TypeError\"]",
            "numeric-api-date-set [\"month\",null,\"\",\"\"]",
            "numeric-api-date-set [\"month\",\"undefined\",\"\",\"\"]",
            "numeric-api-date-set [\"month\",\"2024-02-29T23:59:56.123Z\",\"2024-02\",\"\"]",
            "numeric-api-date-set [\"month\",\"invalid-date\",\"\",\"\"]",
            "numeric-api-date-set [\"month\",{},\"\",\"TypeError\"]",
            "numeric-api-date-set [\"month\",5,\"\",\"TypeError\"]",
            "numeric-api-date-set [\"week\",null,\"\",\"\"]",
            "numeric-api-date-set [\"week\",\"undefined\",\"\",\"\"]",
            "numeric-api-date-set [\"week\",\"2024-02-29T23:59:56.123Z\",\"2024-W09\",\"\"]",
            "numeric-api-date-set [\"week\",\"invalid-date\",\"\",\"\"]",
            "numeric-api-date-set [\"week\",{},\"\",\"TypeError\"]",
            "numeric-api-date-set [\"week\",5,\"\",\"TypeError\"]",
            "numeric-api-date-set [\"time\",null,\"\",\"\"]",
            "numeric-api-date-set [\"time\",\"undefined\",\"\",\"\"]",
            "numeric-api-date-set [\"time\",\"2024-02-29T23:59:56.123Z\",\"23:59:56.123\",\"\"]",
            "numeric-api-date-set [\"time\",\"invalid-date\",\"\",\"\"]",
            "numeric-api-date-set [\"time\",{},\"\",\"TypeError\"]",
            "numeric-api-date-set [\"time\",5,\"\",\"TypeError\"]",
            "numeric-api-date-set [\"datetime-local\",null,\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"datetime-local\",\"undefined\",\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"datetime-local\",\"2024-02-29T23:59:56.123Z\",\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"datetime-local\",\"invalid-date\",\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"datetime-local\",{},\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"datetime-local\",5,\"\",\"TypeError\"]",
            "numeric-api-date-set [\"number\",null,\"17\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"number\",\"undefined\",\"17\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"number\",\"2024-02-29T23:59:56.123Z\",\"17\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"number\",\"invalid-date\",\"17\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"number\",{},\"17\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"number\",5,\"17\",\"TypeError\"]",
            "numeric-api-date-set [\"text\",null,\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"text\",\"undefined\",\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"text\",\"2024-02-29T23:59:56.123Z\",\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"text\",\"invalid-date\",\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"text\",{},\"\",\"InvalidStateError\"]",
            "numeric-api-date-set [\"text\",5,\"\",\"TypeError\"]"
        ]
    );
}

#[test]
fn numeric_api_range_nan() {
    assert_eq!(visit("numeric-api-range-nan"), ["numeric-api-range-nan 50 50", "numeric-api-range-nan step 6 6"]);
}

#[test]
fn numeric_api_date_private() {
    assert_eq!(
        visit("numeric-api-date-private"),
        ["numeric-api-date-private 2025-03-01 2025-03-01T00:00:00.000Z 0", "numeric-api-date-private fresh false 2025-03-01T00:00:00.000Z 2025-03-01"]
    );
}

#[test]
fn numeric_api_number_coercion() {
    assert_eq!(
        visit("numeric-api-number-coercion"),
        [
            "numeric-api-number-coercion once 1 3",
            "numeric-api-number-coercion change text 3 InvalidStateError",
            "numeric-api-number-coercion brand-first 1 TypeError"
        ]
    );
}

#[test]
fn numeric_api_civil_cycle() {
    assert_eq!(
        visit("numeric-api-civil-cycle"),
        [
            "numeric-api-civil-cycle 1 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-civil-cycle 81 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-civil-cycle 161 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-civil-cycle 241 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-civil-cycle 321 11111111111111111111111111111111111111111111111111111111111111111111111111111111"
        ]
    );
}

#[test]
fn numeric_api_week_cycle() {
    assert_eq!(
        visit("numeric-api-week-cycle"),
        [
            "numeric-api-week-cycle 1 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-week-cycle 81 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-week-cycle 161 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-week-cycle 241 11111111111111111111111111111111111111111111111111111111111111111111111111111111",
            "numeric-api-week-cycle 321 11111111111111111111111111111111111111111111111111111111111111111111111111111111"
        ]
    );
}

#[test]
fn numeric_api_date_brand() {
    assert_eq!(
        visit("numeric-api-date-brand"),
        [
            "numeric-api-date-brand get TypeError",
            "numeric-api-date-brand set TypeError",
            "numeric-api-date-brand TypeError 2024-02-29 0",
            "numeric-api-date-brand TypeError 2024-02-29 0",
            "numeric-api-date-brand TypeError 2024-02-29 0",
            "numeric-api-date-brand TypeError 2024-02-29 0"
        ]
    );
}

#[test]
fn numeric_api_native_intrinsics() {
    assert_eq!(
        visit("numeric-api-native-intrinsics"),
        ["numeric-api-native-intrinsics [\"2024-02-29\",1709164800000,1709164800000,\"2024-02\",\"2020-W53\",\"12:34:56.120\",\"23\",0]"]
    );
}

#[test]
fn numeric_api_dirty_state() {
    assert_eq!(
        visit("numeric-api-dirty-state"),
        [
            "numeric-api-dirty-state TypeError",
            "numeric-api-dirty-state failed-number 22 22",
            "numeric-api-dirty-state cleared-number  23",
            "numeric-api-dirty-state TypeError",
            "numeric-api-dirty-state failed-date 2025-03-01 2025-03-01",
            "numeric-api-dirty-state cleared-date  2025-03-02"
        ]
    );
}

#[test]
fn numeric_api_no_events() {
    assert_eq!(
        visit("numeric-api-no-events"),
        ["numeric-api-no-events 0 [[\"number\",\"3\"],[\"date\",\"2024-02-29\"],[\"month\",\"2024-02\"],[\"week\",\"2024-W09\"],[\"time\",\"12:34:56.123\"]]"]
    );
}

#[test]
fn numeric_api_large_calendars() {
    assert_eq!(
        visit("numeric-api-large-calendars"),
        [
            "numeric-api-large-calendars date true true true",
            "numeric-api-large-calendars month true true true",
            "numeric-api-large-calendars week true true true",
            "numeric-api-large-calendars datetime-local true true true",
            "numeric-api-large-calendars date-boundary 8640000086400000 true",
            "numeric-api-large-calendars roundtrip 275760-09-14",
        ]
    );
}

#[path = "support/browser_plan.rs"]
mod browser_plan;
fn net_plan(text: &str) -> anyhow::Result<Plan> {
    browser_plan::parse(text)
}
