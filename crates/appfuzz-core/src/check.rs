//! Properties an agent states about an app (`value_range .usage 0 100`),
//! checked on every fuzz run like a detector: a run that breaks one gives
//! a `check_failed` finding.

use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail};
use regex::Regex;
use serde_json::{Value, json};

use crate::detect::{Finding, Severity};
use crate::harness::field;
use crate::manifest::Manifest;
use crate::output::response;
use crate::record::{OutcomeKind, RunRecord};
use crate::value_contract::Decimal;

type Test = dyn Fn(&RunRecord, &Manifest) -> Option<(String, Value)> + Send + Sync;
type Scope = dyn Fn(&RunRecord, &Manifest) -> bool + Send + Sync;

/// A property: a test that says how a run breaks it, if it does.
#[derive(Clone)]
pub struct Property {
    /// As given (`value_range .usage 0 100`).
    pub text: String,
    test: Arc<Test>,
    selector: Option<Selector>,
    numeric: bool,
    scope: Option<Arc<Scope>>,
    /// Exercised values when not counted by a selector (assertions).
    count: Option<Arc<Count>>,
}
type Count = dyn Fn(&RunRecord, &Manifest) -> usize + Send + Sync;

impl std::fmt::Debug for Property {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Property({})", self.text)
    }
}

pub const HELP: &str = "value_range <selector> <lo> <hi> | max_calls <fn> <n> | no_crash | not_contains <regex> | max <metric> <n>. \
Selectors: `.class`, `#id`, `tag` (HTML body), `$.path` (result field), `/regex/` (first group in the body). \
Metrics: fuel, memory, host_calls, virtual_ms, cost, output_bytes, clock_reads.";

impl Property {
    pub fn parse(words: &[String]) -> Result<Self> {
        let text = words.join(" ");
        let w: Vec<&str> = words.iter().map(String::as_str).collect();
        let num = |s: &str| -> Result<f64> {
            let n = s.parse::<f64>().map_err(|_| anyhow!("{s:?} is not a number"))?;
            if !n.is_finite() {
                bail!("{s:?} must be finite");
            }
            Ok(n)
        };
        let test: Arc<Test> = match w.as_slice() {
            ["value_range", sel, lo, hi] => range_test(sel, lo, hi)?,
            ["max_calls", f, n] => {
                let count = num(n)?;
                if count < 0.0 || count > u32::MAX as f64 || count.fract() != 0.0 {
                    bail!("max_calls requires a non-negative u32 integer");
                }
                let (f, n) = (f.to_string(), count as u32);
                Arc::new(move |r, _| {
                    let c = r.events.iter().filter(|e| e.func.contains(&f)).count() as u32;
                    (c > n).then(|| (format!("{c} calls to {f}, at most {n} allowed"), json!({"calls": c, "max": n})))
                })
            }
            ["no_crash"] => Arc::new(|r, _| {
                (!matches!(r.outcome.kind, OutcomeKind::Ok | OutcomeKind::Error | OutcomeKind::PlanError))
                    .then(|| (format!("the run ends with {:?}", r.outcome.kind), json!({"outcome": r.outcome.kind, "message": r.outcome.message})))
            }),
            ["not_contains", re] => {
                let re = Regex::new(re)?;
                Arc::new(move |r, m| {
                    let text = response(r, m).body.or_else(|| r.result.as_ref().map(Value::to_string)).unwrap_or_default();
                    re.find(&text)
                        .or_else(|| r.guest_error.as_deref().and_then(|error| re.find(error)))
                        .map(|x| (format!("the output contains {:?}", x.as_str()), json!({"match": x.as_str()})))
                })
            }
            ["max", metric, n] => maximum_test(metric, n)?,
            _ => bail!("unknown property {text:?}. {HELP}"),
        };
        let selector = if let ["value_range", sel, ..] = w.as_slice() { Some(Selector::parse(sel)?) } else { None };
        Ok(Property { text, test, selector, numeric: true, scope: None, count: None })
    }

    /// Exact expectations preserve JSON types for field selectors and text for HTML selectors.
    pub fn expect(selector: &str, expected: Value) -> Result<Self> {
        let sel = Selector::parse(selector)?;
        let selected = sel.clone();
        let text = format!("expect {selector} = {expected}");
        Ok(Self {
            text,
            selector: Some(sel),
            numeric: false,
            scope: None,
            count: None,
            test: Arc::new(move |r, m| {
                selected
                    .selected(r, m)
                    .into_iter()
                    .find(|v| v != &expected)
                    .map(|actual| (format!("{} is {actual}, expected {expected}", selected.text), json!({"actual":actual,"expected":expected})))
            }),
        })
    }

    /// A `let` + `assert` property: broken when the expression is false on a
    /// completed run; exercised when it holds non-vacuously or breaks.
    pub fn assertion(a: Arc<crate::assertion::Assertion>) -> Self {
        let (t, c) = (a.clone(), a.clone());
        Self {
            text: format!("assert {}", a.expr.text),
            selector: None,
            numeric: false,
            scope: None,
            count: Some(Arc::new(move |r, m| crate::assertion::status(&c, r, m).1)),
            test: Arc::new(move |r, m| match crate::assertion::status(&t, r, m) {
                ("broken", _, d) => Some((d["why"].as_str().unwrap_or("the assertion is false").to_string(), d)),
                _ => None,
            }),
        }
    }

    /// Numeric values actually exercised, rather than vacuous successes.
    pub fn matches(&self, r: &RunRecord, m: &Manifest) -> usize {
        if self.scope.as_ref().is_some_and(|s| !s(r, m)) {
            return 0;
        }
        if matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            return 0;
        }
        if let Some(c) = &self.count {
            return c(r, m);
        }
        self.selector.as_ref().map_or(1, |s| if self.numeric { s.numeric_values(r, m).len() } else { s.selected(r, m).len() })
    }

    /// How the run breaks the property, if it does.
    pub fn broken(&self, r: &RunRecord, m: &Manifest) -> Option<(String, Value)> {
        if self.scope.as_ref().is_some_and(|s| !s(r, m)) {
            return None;
        }
        (self.test)(r, m)
    }

    pub fn scoped(mut self, scope: impl Fn(&RunRecord, &Manifest) -> bool + Send + Sync + 'static) -> Self {
        self.scope = Some(Arc::new(scope));
        self
    }
    pub fn forbid_effects(mut self, effects: Vec<crate::manifest::Effect>) -> Self {
        if effects.is_empty() {
            return self;
        }
        let previous = self.test.clone();
        self.test = Arc::new(move |r, m| {
            previous(r, m).or_else(|| {
                r.events
                    .iter()
                    .find(|e| m.function(&e.func).and_then(|f| f.effect).is_some_and(|effect| effects.contains(&effect)))
                    .map(|e| (format!("forbidden effect in {}", e.func), json!({"func":e.func,"n":e.n,"effect":m.function(&e.func).and_then(|f|f.effect)})))
            })
        });
        self
    }

    /// The finding for a run that breaks the property.
    pub fn finding(&self, r: &RunRecord, m: &Manifest) -> Option<Finding> {
        let (why, mut detail) = self.broken(r, m)?;
        if let Value::Object(o) = &mut detail {
            o.insert("property".into(), json!(self.text));
        }
        Some(Finding::new("check_failed", &format!("{}\0{}", r.spec.export, self.text), Severity::Fail, format!("{}: {why}", self.text), detail, Some(&r.id)))
    }
}

fn range_test(selector: &str, lo: &str, hi: &str) -> Result<Arc<Test>> {
    let (lo_text, hi_text) = (lo.to_string(), hi.to_string());
    let lo = Decimal::parse(lo).ok_or_else(|| anyhow!("{lo:?} is not a finite decimal number"))?;
    let hi = Decimal::parse(hi).ok_or_else(|| anyhow!("{hi:?} is not a finite decimal number"))?;
    if lo.cmp(&hi).is_gt() {
        bail!("lower bound exceeds upper bound");
    }
    let selector = Selector::parse(selector)?;
    Ok(Arc::new(move |r, m| {
        for (text, token, value) in selector.numeric_values(r, m) {
            if value.cmp(&lo).is_lt() || value.cmp(&hi).is_gt() {
                return Some((
                    format!("{} is {token}, outside {lo_text}–{hi_text}", selector.text),
                    json!({"value": exact_json_number(&token), "text": text, "lo": exact_json_number(&lo_text), "hi": exact_json_number(&hi_text)}),
                ));
            }
        }
        None
    }))
}

fn maximum_test(metric: &str, bound: &str) -> Result<Arc<Test>> {
    let (metric, bound_text) = (metric.to_string(), bound.to_string());
    let bound = Decimal::parse(bound).ok_or_else(|| anyhow!("{bound:?} is not a finite decimal number"))?;
    if !METRICS.contains(&metric.as_str()) {
        bail!("unknown metric {metric:?}. {HELP}");
    }
    Ok(Arc::new(move |r, _| {
        let value_text = metric_of(&metric, r)?;
        let value = Decimal::parse(&value_text)?;
        (!matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) && value.cmp(&bound).is_gt()).then(|| {
            (
                format!("{metric} is {value_text}, at most {bound_text} allowed"),
                json!({"metric": metric, "value": exact_json_number(&value_text), "max": exact_json_number(&bound_text)}),
            )
        })
    }))
}

const METRICS: &[&str] = &["fuel", "memory", "host_calls", "virtual_ms", "cost", "clock_reads", "output_bytes"];

fn metric_of(name: &str, r: &RunRecord) -> Option<String> {
    let t = &r.totals;
    Some(match name {
        "fuel" => t.fuel.to_string(),
        "memory" => t.peak_memory.to_string(),
        "host_calls" => t.host_calls.to_string(),
        "virtual_ms" => format!("{}.{:06}", t.virtual_ns / 1_000_000, t.virtual_ns % 1_000_000),
        "cost" => t.cost.to_string(),
        "clock_reads" => t.clock_reads.to_string(),
        "output_bytes" => r.result.as_ref().map_or(0, |v| v.to_string().len()).to_string(),
        _ => return None,
    })
}

/// Keep exact evidence even when a JSON floating-point number cannot hold it.
fn exact_json_number(text: &str) -> Value {
    if let Ok(number) = text.parse::<serde_json::Number>()
        && let (Some(original), Some(serialized)) = (Decimal::parse(text), Decimal::parse(&number.to_string()))
        && original.cmp(&serialized).is_eq()
    {
        return Value::Number(number);
    }
    json!(text)
}

static NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-?(?:\d[\d,]*(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?").unwrap());
pub(crate) fn scalar_number(value: &Value) -> Option<f64> {
    let n = match value {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => match s.replace(',', "").trim().parse::<f64>() {
            Ok(n) => n,
            Err(_) if NUMBER.find_iter(s).count() == 1 => number(s)?,
            _ => return None,
        },
        _ => return None,
    };
    // Beyond this range distinct integer outputs can collapse to the same f64.
    (n.is_finite() && !(n.fract() == 0.0 && n.abs() > 9_007_199_254_740_991.0)).then_some(n)
}

/// The first number in a text (`1,234.5 %` → 1234.5).
fn number(t: &str) -> Option<f64> {
    NUMBER.find(t)?.as_str().replace(',', "").parse().ok()
}

/// Where a value is read from.
#[derive(Debug, Clone)]
pub struct Selector {
    pub text: String,
    kind: SelKind,
}

#[derive(Debug, Clone)]
enum SelKind {
    Class(String),
    Id(String),
    Tag(String),
    Field(String),
    Pattern(Regex),
}

impl Selector {
    fn numeric_values(&self, r: &RunRecord, m: &Manifest) -> Vec<(String, String, Decimal)> {
        self.selected(r, m)
            .into_iter()
            .filter_map(|value| {
                let text = match value {
                    Value::String(s) => s,
                    Value::Number(n) => n.to_string(),
                    _ => return None,
                };
                let token = NUMBER.find(&text)?.as_str().replace(',', "");
                let number = Decimal::parse(&token)?;
                Some((text, token, number))
            })
            .collect()
    }

    pub fn parse(s: &str) -> Result<Self> {
        let kind = if let Some(c) = s.strip_prefix('.') {
            SelKind::Class(c.to_string())
        } else if let Some(i) = s.strip_prefix('#') {
            SelKind::Id(i.to_string())
        } else if let Some(p) = s.strip_prefix("$.").or(s.strip_prefix('$')) {
            SelKind::Field(p.to_string())
        } else if s.len() > 2 && s.starts_with('/') && s.ends_with('/') {
            SelKind::Pattern(Regex::new(&s[1..s.len() - 1])?)
        } else if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            SelKind::Tag(s.to_ascii_lowercase())
        } else {
            bail!("bad selector {s:?}. {HELP}");
        };
        Ok(Selector { text: s.to_string(), kind })
    }

    pub fn selected(&self, r: &RunRecord, m: &Manifest) -> Vec<Value> {
        if let SelKind::Field(path) = &self.kind {
            return r.result.as_ref().and_then(|v| field(v, path)).cloned().into_iter().collect();
        }
        self.values(r, m).into_iter().map(Value::String).collect()
    }

    /// Relations require an unambiguous, finite scalar number.
    pub fn scalar(&self, r: &RunRecord, m: &Manifest) -> Option<f64> {
        let values = self.selected(r, m);
        if values.len() != 1 {
            return None;
        }
        scalar_number(&values[0])
    }

    /// Every text the selector picks out of a run's output.
    pub fn values(&self, r: &RunRecord, m: &Manifest) -> Vec<String> {
        static START: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"<([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*/?>"#).unwrap());
        static ATTR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"([^\s=>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?"#).unwrap());
        static TAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());
        if let SelKind::Field(p) = &self.kind {
            return r.result.as_ref().and_then(|v| field(v, p)).map(|v| vec![v.as_str().map_or_else(|| v.to_string(), str::to_string)]).unwrap_or_default();
        }
        let Some(body) = response(r, m).body else { return vec![] };
        if let SelKind::Pattern(re) = &self.kind {
            return re.captures_iter(&body).map(|c| c.get(1).or(c.get(0)).map_or("", |x| x.as_str()).to_string()).collect();
        }
        let mut out = Vec::new();
        for c in START.captures_iter(&body) {
            let tag = c[1].to_ascii_lowercase();
            let attr = |name: &str| {
                ATTR.captures_iter(c.get(2).map_or("", |x| x.as_str()))
                    .find(|a| a[1].eq_ignore_ascii_case(name))
                    .map(|a| a.get(2).or(a.get(3)).or(a.get(4)).map_or("", |x| x.as_str()).to_string())
            };
            let hit = match &self.kind {
                SelKind::Class(k) => attr("class").is_some_and(|v| v.split_whitespace().any(|x| x == k)),
                SelKind::Id(i) => attr("id").as_deref() == Some(i.as_str()),
                SelKind::Tag(t) => tag == *t,
                _ => false,
            };
            if !hit {
                continue;
            }
            let rest = &body[c.get(0).map_or(0, |x| x.end())..];
            let end = rest.find(&format!("</{tag}")).unwrap_or(rest.len());
            let text = TAGS.replace_all(&rest[..end], " ");
            // A value attribute (meter, progress, input) counts too.
            out.push(attr("value").unwrap_or_else(|| text.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_preserve_large_integers_and_precise_decimals() {
        let m = Manifest::for_wasm(std::path::Path::new("x.wasm"));
        for (lo, hi, value) in [
            ("0", "9007199254740992", json!(9007199254740993u64)),
            ("0", "18446744073709551614", json!(u64::MAX)),
            ("-9007199254740992", "0", json!(-9007199254740993i64)),
            ("0", "0.1", json!("0.10000000000000000001")),
            ("0.10000000000000000001", "1", json!("0.1")),
        ] {
            let property = Property::parse(&["value_range".into(), "$.usage".into(), lo.into(), hi.into()]).unwrap();
            let record = crate::envelope::Trace { result: Some(json!({"usage":value})), ..Default::default() }.to_record();
            assert_eq!(property.matches(&record, &m), 1);
            let (_, detail) = property.broken(&record, &m).unwrap_or_else(|| panic!("accepted {value} in {lo}..{hi}"));
            if value == json!("0.10000000000000000001") || value.is_u64() || value.is_i64() {
                assert_eq!(detail["value"], value);
            }
        }
        for (lo, hi) in [("9007199254740993", "9007199254740992"), ("0.10000000000000000001", "0.1")] {
            assert!(Property::parse(&["value_range".into(), "$".into(), lo.into(), hi.into()]).is_err());
        }
    }

    #[test]
    fn maximum_metrics_compare_exact_values_and_keep_boundary_evidence() {
        let m = Manifest::for_wasm(std::path::Path::new("x.wasm"));
        let mut record = crate::envelope::Trace::default().to_record();
        record.totals.fuel = u64::MAX;
        record.totals.cost = u64::MAX;
        record.totals.peak_memory = u64::MAX;
        record.totals.clock_reads = u64::MAX;
        record.totals.virtual_ns = u64::MAX;
        for metric in ["fuel", "memory", "cost", "clock_reads"] {
            let property = Property::parse(&["max".into(), metric.into(), (u64::MAX - 1).to_string()]).unwrap();
            let (_, detail) = property.broken(&record, &m).unwrap_or_else(|| panic!("accepted {metric}"));
            assert_eq!(detail["value"], u64::MAX);
            assert_eq!(detail["max"], u64::MAX - 1);
            let equal = Property::parse(&["max".into(), metric.into(), u64::MAX.to_string()]).unwrap();
            assert!(equal.broken(&record, &m).is_none());
        }
        let latency = Property::parse(&["max".into(), "virtual_ms".into(), "18446744073709.551614".into()]).unwrap();
        let (_, detail) = latency.broken(&record, &m).unwrap();
        assert_eq!(detail["value"], "18446744073709.551615");
        assert_eq!(detail["max"], "18446744073709.551614");
        record.result = Some(json!("12345678"));
        let bytes = Property::parse(&["max".into(), "output_bytes".into(), "9.99999999999999999999".into()]).unwrap();
        assert!(bytes.broken(&record, &m).is_some());
    }

    #[test]
    fn structured_fields_are_not_exercised_as_scalar_numbers() {
        let m = Manifest::for_wasm(std::path::Path::new("x.wasm"));
        let p = Property::parse(&["value_range".into(), "$.usage".into(), "0".into(), "100".into()]).unwrap();
        for value in [json!({"count":12}), json!([12]), Value::Null, json!(false)] {
            let record = crate::envelope::Trace { result: Some(json!({"usage":value})), ..Default::default() }.to_record();
            assert_eq!(p.matches(&record, &m), 0, "{value}");
            assert!(p.broken(&record, &m).is_none());
        }
    }

    #[test]
    fn maximum_metrics_include_work_performed_before_a_trap() {
        let m = Manifest::for_wasm(std::path::Path::new("x.wasm"));
        let p = Property::parse(&["max".into(), "cost".into(), "0".into()]).unwrap();
        let mut record = crate::envelope::Trace::default().to_record();
        record.totals.cost = 1;
        for outcome in [OutcomeKind::Trap, OutcomeKind::HostTrap, OutcomeKind::OutOfFuel, OutcomeKind::Timeout] {
            record.outcome.kind = outcome;
            assert_eq!(p.matches(&record, &m), 1);
            assert!(p.broken(&record, &m).is_some(), "ignored {outcome:?}");
        }
        for outcome in [OutcomeKind::Error, OutcomeKind::PlanError] {
            record.outcome.kind = outcome;
            assert_eq!(p.matches(&record, &m), 0);
            assert!(p.broken(&record, &m).is_none());
        }
    }

    #[test]
    fn numbers() {
        assert_eq!(number("used 1,234.5 %"), Some(1234.5));
        assert_eq!(number("-3 left"), Some(-3.0));
        assert_eq!(number("none"), None);
    }

    #[test]
    fn ranges_check_complete_scientific_and_fractional_values() {
        let m = Manifest::for_wasm(std::path::Path::new("x.wasm"));
        let p = Property::parse(&["value_range".into(), "$.usage".into(), "0".into(), "100".into()]).unwrap();
        for value in [json!(1e100), json!("1e3"), json!("1e3 %"), json!("-.5")] {
            let r = crate::envelope::Trace { result: Some(json!({"usage":value})), ..Default::default() }.to_record();
            assert!(p.broken(&r, &m).is_some(), "range accepted {value}");
        }
        let fraction = Property::parse(&["value_range".into(), "$.usage".into(), "0".into(), "1".into()]).unwrap();
        for value in [json!(".5"), json!("5e-1 %"), json!("100e-3")] {
            let r = crate::envelope::Trace { result: Some(json!({"usage":value})), ..Default::default() }.to_record();
            assert_eq!(fraction.matches(&r, &m), 1);
            assert!(fraction.broken(&r, &m).is_none(), "range rejected {value}");
        }
    }

    #[test]
    fn relational_numbers_are_unambiguous_and_do_not_round_large_integers() {
        assert_eq!(scalar_number(&json!("3 of 5")), None);
        assert_eq!(scalar_number(&json!("1,234.5 rooms")), Some(1234.5));
        assert_eq!(scalar_number(&json!("1e3")), Some(1000.0));
        assert_eq!(scalar_number(&json!(9007199254740993u64)), None);
        assert_eq!(scalar_number(&json!("NaN")), None);
        assert!(Property::parse(&["max_calls".into(), "x".into(), "-1".into()]).is_err());
        assert!(Property::parse(&["max_calls".into(), "x".into(), "1.5".into()]).is_err());
    }

    #[test]
    fn parse() {
        assert!(Property::parse(&["value_range".into(), ".big-number".into(), "0".into(), "100".into()]).is_ok());
        assert!(Property::parse(&["max".into(), "speed".into(), "1".into()]).is_err());
        assert!(Selector::parse("a b").is_err());
    }
}
