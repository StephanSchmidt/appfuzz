//! Host plans: how an agent scripts what simulated host functions return.
//!
//! ```json
//! {
//!   "_defaults": { "generate": { "list_len": 2 }, "latency_ms": 2 },
//!   "acme:web/items#all": { "return": [{"id": 1, "name": "A"}] },
//!   "acme:web/items#by-date": {
//!     "rules": [ { "when": {"date": {"regex": "^2026-"}}, "return": {"ok": []} } ],
//!     "on_call": { "3": { "trap": "db gone" } },
//!     "default": { "return": {"err": "not a date"} },
//!     "latency_ms": 40
//!   }
//! }
//! ```
//!
//! Precedence per call: `on_call[n]` > latest applicable `on_call["N+"]` > first matching rule > `default` >
//! the function's own `return`/`generate`/`trap` > `_defaults` > values
//! generated from the WIT type. Keys starting with `_` inside a function
//! entry (`_sig`, `_example`) are notes and ignored.

use std::borrow::Cow;
use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::fn_key;
use crate::value::GenOpts;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Plan(pub BTreeMap<String, FnPlan>);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Response {
    #[serde(rename = "return", default, skip_serializing_if = "Option::is_none")]
    pub ret: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generate: Option<GenOpts>,
    /// The host function traps with this message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_then_trap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
}

impl Response {
    pub fn decides(&self) -> bool {
        self.ret.is_some() || self.generate.is_some() || self.trap.is_some() || self.commit_then_trap.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    /// Parameter name or index → matcher. All must match.
    #[serde(default)]
    pub when: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub response: Response,
    /// Manifest only: the labels of results for these arguments, instead of
    /// the function's (`variables#get` is secret for `api-token` only). A
    /// rule with labels and no answer only labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<crate::labels::ResultLabels>,
}

impl Rule {
    /// Whether the rule answers the call, not only labels it.
    fn answers(&self) -> bool {
        self.result.is_none() || self.response.decides()
    }
}

/// The result labels of one call: the first rule with labels whose `when`
/// matches the arguments, else the function's own.
pub fn result_labels_for(default: Option<&crate::labels::ResultLabels>, rules: &[Rule], args: &[(String, Value)]) -> Vec<(String, crate::labels::Label)> {
    rules
        .iter()
        .find(|r| r.result.is_some() && r.when.iter().all(|(p, m)| arg(args, p).is_some_and(|a| matches(m, a))))
        .and_then(|r| r.result.as_ref())
        .or(default)
        .map(crate::labels::ResultLabels::paths)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FnPlan {
    #[serde(flatten)]
    pub response: Response,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// 1-based call number of this function → response.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub on_call: BTreeMap<String, Response>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Response>,
    /// Overrides the manifest's cost for this function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<u64>,
    /// Collection sizes for the shared world, only valid under `_defaults`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dataset_rows: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_seed: Option<u64>,
    /// Notes such as `_sig` and `_example`.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub notes: BTreeMap<String, Value>,
}

/// What the plan decided for one call.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Return(Value),
    Generate(GenOpts),
    Trap(String),
    CommitThenTrap(String),
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub decision: Decision,
    pub latency_ms: Option<f64>,
    pub cost: Option<u64>,
    /// Which part of the plan decided: `on_call 3`, `rule 0`, `default`,
    /// `plan`, `_defaults`, `generated`.
    pub source: String,
}

impl Plan {
    pub fn parse(text: &str) -> Result<Self> {
        let plan: Plan = serde_json::from_str(text).context("host plan is not valid JSON in the plan format")?;
        plan.validate()?;
        Ok(plan)
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        Self::parse(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
    }

    pub fn validate(&self) -> Result<()> {
        for (key, f) in &self.0 {
            if (!f.dataset_rows.is_empty() || f.dataset_seed.is_some()) && key != "_defaults" {
                bail!("dataset_rows belongs under _defaults");
            }
            for k in f.notes.keys() {
                if !k.starts_with('_') {
                    bail!("{key}: unknown plan field {k:?} (notes must start with _)");
                }
            }
            for n in f.on_call.keys() {
                if call_start(n).is_none() {
                    bail!("{key}: on_call key {n:?} must be a positive call number or N+");
                }
            }
            for (i, r) in f.rules.iter().enumerate() {
                for m in r.when.values() {
                    matcher_ok(m).with_context(|| format!("{key}: rule {i}"))?;
                }
                if r.result.is_some() {
                    bail!("{key}: rule {i} labels results; labels belong in the manifest (appfuzz.toml), not in a plan");
                }
            }
        }
        Ok(())
    }

    /// Checks the plan against the app's imports: a key that misspells a
    /// function the app imports, or a rule on a parameter the function
    /// doesn't have, would never apply. Other keys may describe functions
    /// of the platform the app doesn't call.
    pub fn check_wit(&self, imports: &[crate::wit::Interface]) -> Result<()> {
        let keys: Vec<String> = self.0.keys().filter(|k| !k.starts_with('_')).cloned().collect();
        if let Some((k, real)) = crate::labels::misspelling(&keys, imports) {
            bail!("the plan names {k}, which the app doesn't import: did you mean {real}?");
        }
        let funcs: Vec<&crate::wit::FuncInfo> = imports.iter().flat_map(|i| &i.funcs).collect();
        for (key, f) in self.0.iter().filter(|(k, _)| !k.starts_with('_')) {
            let (i, n) = key.split_once('#').unwrap_or(("", key));
            let Some(func) = funcs.iter().find(|x| x.key == fn_key(i, n)) else { continue };
            for (i, r) in f.rules.iter().enumerate() {
                if let Some(p) = r.when.keys().find(|p| !crate::labels::names_param(func, p)) {
                    bail!("{key}: rule {i} matches the parameter {p}, but {} has no such parameter", func.signature());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn get(&self, key: &str) -> Option<&FnPlan> {
        self.0.get(key).or_else(|| {
            self.0
                .iter()
                .find(|(k, _)| {
                    let (i, f) = k.split_once('#').unwrap_or(("", k));
                    fn_key(i, f) == key
                })
                .map(|(_, v)| v)
        })
    }

    /// Decides one call. `call` is the 1-based number of calls to this
    /// function in the run; `args` are named by parameter.
    pub fn resolve(&self, key: &str, call: u32, args: &[(String, Value)]) -> Resolved {
        let defaults = self.0.get("_defaults");
        let fp = self.get(key);
        let fn_latency = fp.and_then(|f| f.response.latency_ms);
        let cost = fp.and_then(|f| f.cost);
        let finish = |r: &Response, source: String| -> Option<Resolved> {
            let decision = if let Some(msg) = &r.commit_then_trap {
                Decision::CommitThenTrap(msg.clone())
            } else if let Some(msg) = &r.trap {
                Decision::Trap(msg.clone())
            } else if let Some(v) = &r.ret {
                Decision::Return(v.clone())
            } else if let Some(g) = &r.generate {
                Decision::Generate(g.clone())
            } else {
                return None;
            };
            Some(Resolved { decision, latency_ms: r.latency_ms.or(fn_latency).or(defaults.and_then(|d| d.response.latency_ms)), cost, source })
        };
        if let Some(f) = fp {
            if let Some(r) = f.on_call.get(&call.to_string())
                && let Some(res) = finish(r, format!("on_call {call}"))
            {
                return res;
            }
            // Exact positions win; otherwise the latest starting range wins.
            let range = f
                .on_call
                .iter()
                .filter_map(|(key, response)| {
                    let (start, tail) = call_start(key)?;
                    (tail && start <= call).then_some((start, response))
                })
                .max_by_key(|(start, _)| *start);
            if let Some((start, response)) = range
                && let Some(res) = finish(response, format!("on_call {start}+"))
            {
                return res;
            }
            for (i, rule) in f.rules.iter().enumerate() {
                if rule.when.iter().all(|(param, m)| arg(args, param).is_some_and(|a| matches(m, a)))
                    && let Some(res) = finish(&rule.response, format!("rule {i}"))
                {
                    return res;
                }
            }
            if let Some(r) = &f.default
                && let Some(res) = finish(r, "default".into())
            {
                return res;
            }
            if f.response.decides()
                && let Some(res) = finish(&f.response, "plan".into())
            {
                return res;
            }
        }
        if let Some(d) = defaults
            && let Some(res) = finish(&d.response, "_defaults".into())
        {
            return res;
        }
        Resolved {
            decision: Decision::Generate(GenOpts::default()),
            latency_ms: fn_latency.or(defaults.and_then(|d| d.response.latency_ms)),
            cost,
            source: "generated".into(),
        }
    }
}

/// Exact call or an outage starting at that call. Calls are one-based.
pub(crate) fn call_start(key: &str) -> Option<(u32, bool)> {
    let (number, tail) = key.strip_suffix('+').map_or((key, false), |number| (number, true));
    let start = number.parse::<u32>().ok()?;
    (start > 0 && number == start.to_string()).then_some((start, tail))
}

/// Checks a rule's matchers (a bad regex is an error).
pub fn check_rule(r: &Rule) -> Result<()> {
    r.when.values().try_for_each(matcher_ok)
}

/// The first of the manifest's rules for a function that matches the
/// arguments. These are the platform's promises: they come before any plan.
pub fn resolve_rules(rules: &[Rule], args: &[(String, Value)], fn_latency: Option<f64>) -> Option<Resolved> {
    let (i, rule) = rules.iter().enumerate().find(|(_, r)| r.answers() && r.when.iter().all(|(param, m)| arg(args, param).is_some_and(|a| matches(m, a))))?;
    let r = &rule.response;
    let decision = if let Some(msg) = &r.commit_then_trap {
        Decision::CommitThenTrap(msg.clone())
    } else if let Some(msg) = &r.trap {
        Decision::Trap(msg.clone())
    } else if let Some(v) = &r.ret {
        Decision::Return(v.clone())
    } else {
        Decision::Generate(r.generate.clone()?)
    };
    Some(Resolved { decision, latency_ms: r.latency_ms.or(fn_latency), cost: None, source: format!("manifest rule {i}") })
}

/// Manifest rules are fixed for a loaded component. Compile their regular
/// expressions once, rather than compiling them at every host boundary.
pub(crate) struct CompiledRule {
    when: Vec<(String, CompiledMatcher)>,
    response: Response,
    answers: bool,
}
enum CompiledMatcher {
    Any,
    Regex(Option<Regex>),
    Contains(Option<String>),
    Range(Option<(f64, f64)>),
    Not(Box<CompiledMatcher>),
    Equal(Value),
}
impl CompiledMatcher {
    fn new(value: &Value) -> Self {
        if let Value::Object(o) = value
            && o.len() == 1
        {
            let (key, v) = o.iter().next().unwrap();
            match key.as_str() {
                "any" => return Self::Any,
                "regex" => return Self::Regex(v.as_str().and_then(|s| Regex::new(s).ok())),
                "contains" => return Self::Contains(v.as_str().map(str::to_owned)),
                "range" => return Self::Range(v.as_array().and_then(|r| Some((r.first()?.as_f64()?, r.get(1)?.as_f64()?)))),
                "not" => return Self::Not(Box::new(Self::new(v))),
                _ => {}
            }
        }
        Self::Equal(value.clone())
    }
    fn matches(&self, value: &Value) -> bool {
        match self {
            Self::Any => true,
            Self::Regex(re) => re.as_ref().is_some_and(|re| re.is_match(&text(value))),
            Self::Contains(s) => s.as_ref().is_some_and(|s| text(value).contains(s)),
            Self::Range(bounds) => bounds.is_some_and(|(lo, hi)| value.as_f64().is_some_and(|n| n >= lo && n <= hi)),
            Self::Not(m) => !m.matches(value),
            Self::Equal(v) => matches(v, value),
        }
    }
}
pub(crate) fn compile_rules(rules: &[Rule]) -> Vec<CompiledRule> {
    rules
        .iter()
        .map(|r| CompiledRule {
            when: r.when.iter().map(|(p, m)| (p.clone(), CompiledMatcher::new(m))).collect(),
            response: r.response.clone(),
            answers: r.answers(),
        })
        .collect()
}
pub(crate) fn resolve_compiled_rules(rules: &[CompiledRule], args: &[(String, Value)], fn_latency: Option<f64>) -> Option<Resolved> {
    let (i, rule) = rules.iter().enumerate().find(|(_, r)| r.answers && r.when.iter().all(|(p, m)| arg(args, p).is_some_and(|v| m.matches(v))))?;
    let r = &rule.response;
    let decision = if let Some(msg) = &r.commit_then_trap {
        Decision::CommitThenTrap(msg.clone())
    } else if let Some(msg) = &r.trap {
        Decision::Trap(msg.clone())
    } else if let Some(v) = &r.ret {
        Decision::Return(v.clone())
    } else {
        Decision::Generate(r.generate.clone()?)
    };
    Some(Resolved { decision, latency_ms: r.latency_ms.or(fn_latency), cost: None, source: format!("manifest rule {i}") })
}

fn arg<'a>(args: &'a [(String, Value)], param: &str) -> Option<&'a Value> {
    if let Ok(i) = param.parse::<usize>() {
        return args.get(i).map(|(_, v)| v);
    }
    args.iter().find(|(n, _)| n == param || n.replace('-', "_") == param).map(|(_, v)| v)
}

fn matcher_ok(m: &Value) -> Result<()> {
    if let Some(Value::String(re)) = m.as_object().and_then(|o| o.get("regex")) {
        Regex::new(re).with_context(|| format!("bad regex {re:?}"))?;
    }
    Ok(())
}

/// A matcher is a plain JSON value (equality), or an object with one of:
/// `{"regex": "…"}`, `{"any": true}`, `{"range": [lo, hi]}`,
/// `{"contains": "…"}`, `{"not": matcher}`.
pub fn matches(m: &Value, v: &Value) -> bool {
    if let Value::Object(o) = m
        && o.len() == 1
    {
        let (k, x) = o.iter().next().expect("one entry");
        match k.as_str() {
            "any" => return true,
            "regex" => {
                return x.as_str().and_then(|re| Regex::new(re).ok()).is_some_and(|re| re.is_match(&text(v)));
            }
            "contains" => return x.as_str().is_some_and(|s| text(v).contains(s)),
            "range" => {
                let r = x.as_array();
                let (lo, hi) = match r.map(|r| (r.first().and_then(Value::as_f64), r.get(1).and_then(Value::as_f64))) {
                    Some((Some(lo), Some(hi))) => (lo, hi),
                    _ => return false,
                };
                return v.as_f64().is_some_and(|n| n >= lo && n <= hi);
            }
            "not" => return !matches(x, v),
            _ => {}
        }
    }
    if m == v {
        return true;
    }
    // `{"some": x}` args also match a plain `x`.
    if let Value::Object(o) = v
        && o.len() == 1
        && let Some(inner) = o.get("some")
    {
        return m == inner;
    }
    false
}

fn text(v: &Value) -> Cow<'_, str> {
    match v {
        Value::String(s) => Cow::Borrowed(s),
        other => Cow::Owned(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rule_labels_by_argument() {
        use crate::labels::{Label, ResultLabels};
        let rules: Vec<Rule> = serde_json::from_value(serde_json::json!([
            {"when": {"key": "api_token"}, "result": "secret"},
            {"when": {"key": "greeting"}, "return": {"ok": "Hello"}}
        ]))
        .unwrap();
        let args = |k: &str| vec![("key".to_string(), serde_json::json!(k))];
        assert_eq!(result_labels_for(None, &rules, &args("api_token")), vec![(String::new(), Label::Secret)]);
        assert!(result_labels_for(None, &rules, &args("greeting")).is_empty());
        let own = ResultLabels::Whole(Label::Pii);
        assert_eq!(result_labels_for(Some(&own), &rules, &args("other")), vec![(String::new(), Label::Pii)]);
        // A rule that only labels does not answer: the next rule does.
        let r = resolve_rules(&rules, &args("api_token"), None);
        assert!(r.is_none());
        assert!(resolve_rules(&rules, &args("greeting"), None).is_some());
        let plan = Plan::parse(r#"{"a:b/c#d": {"rules": [{"when": {"x": 1}, "result": "secret"}]}}"#);
        assert!(plan.is_err());
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn compiled_platform_matchers_preserve_literal_recursive_and_regex_semantics() {
        let patterns = [
            json!("x"),
            json!({"some":"x"}),
            json!({"regex":"^x+$"}),
            json!({"not":{"regex":"^x+$"}}),
            json!({"regex":"["}),
            json!({"any":false}),
            json!({"range":[1,6]}),
            json!({"contains":"x"}),
            json!({"other":"x"}),
        ];
        let values = [Value::Null, json!("x"), json!("xx"), json!("z"), json!("é"), json!({"some":"x"}), json!(0), json!(6), json!(7)];
        for pattern in &patterns {
            let compiled = CompiledMatcher::new(pattern);
            for value in &values {
                assert_eq!(compiled.matches(value), matches(pattern, value), "{pattern} {value}");
            }
        }
        let rules = vec![Rule {
            when: BTreeMap::from([("date".into(), json!({"not":{"regex":"^2026-"}}))]),
            response: Response { ret: Some(json!({"err":"date"})), latency_ms: Some(2.0), ..Default::default() },
            result: None,
        }];
        let compiled = compile_rules(&rules);
        for value in ["2026-11-02", "bad"] {
            let args = vec![("date".into(), json!(value))];
            let old = resolve_rules(&rules, &args, Some(1.0));
            let new = resolve_compiled_rules(&compiled, &args, Some(1.0));
            assert_eq!(old.as_ref().map(|r| &r.decision), new.as_ref().map(|r| &r.decision));
            assert_eq!(old.as_ref().map(|r| r.latency_ms), new.as_ref().map(|r| r.latency_ms));
            assert_eq!(old.as_ref().map(|r| &r.source), new.as_ref().map(|r| &r.source));
        }
    }

    #[test]
    fn outage_ranges_are_numeric_and_exact_positions_override_them() {
        let p = Plan::parse(r#"{"x:y/a#get":{"return":0,"on_call":{"2+":{"return":2},"10+":{"return":10},"12":{"return":12}}}}"#).unwrap();
        for (n, expected) in [(1, 0), (2, 2), (9, 2), (10, 10), (11, 10), (12, 12), (13, 10)] {
            let Decision::Return(value) = p.resolve("x:y/a#get", n, &[]).decision else {
                panic!("literal");
            };
            assert_eq!(value, json!(expected));
        }
        for key in ["0", "0+", "-1+", "1++", "4294967296+", "01+"] {
            assert!(Plan::parse(&json!({"x:y/a#get":{"on_call":{key:{"return":1}}}}).to_string()).is_err());
        }
    }

    fn plan() -> Plan {
        Plan::parse(
            r#"{
              "_defaults": {"latency_ms": 2},
              "x:y/b#list": {
                "rules": [{"when": {"date": {"regex": "^2026-"}}, "return": {"ok": [1]}}],
                "on_call": {"3": {"trap": "gone"}},
                "default": {"return": {"err": "nope"}},
                "latency_ms": 40,
                "_sig": "list: func(date: string)"
              },
              "x:y/a#all@0.1.0": {"return": []}
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn manifest_rules() {
        let rules: Vec<Rule> = serde_json::from_value(json!([
            {"when": {"hour": {"not": {"range": [8, 16]}}}, "return": {"err": "closed"}},
            {"when": {"subject": {"regex": "^\\s*$"}}, "trap": "empty"}
        ]))
        .unwrap();
        let args = |h: u64, s: &str| vec![("hour".to_string(), json!(h)), ("subject".to_string(), json!(s))];
        let r = resolve_rules(&rules, &args(20, "x"), None).unwrap();
        assert_eq!(r.decision, Decision::Return(json!({"err": "closed"})));
        assert_eq!(r.source, "manifest rule 0");
        assert_eq!(resolve_rules(&rules, &args(9, " "), None).unwrap().decision, Decision::Trap("empty".into()));
        assert!(resolve_rules(&rules, &args(9, "x"), None).is_none());
    }

    #[test]
    fn precedence() {
        let p = plan();
        let args = vec![("date".to_string(), json!("2026-01-01"))];
        let r = p.resolve("x:y/b#list", 1, &args);
        assert_eq!(r.decision, Decision::Return(json!({"ok": [1]})));
        assert_eq!(r.latency_ms, Some(40.0));
        assert_eq!(p.resolve("x:y/b#list", 3, &args).decision, Decision::Trap("gone".into()));
        let other = vec![("date".to_string(), json!("1999-01-01"))];
        assert_eq!(p.resolve("x:y/b#list", 1, &other).decision, Decision::Return(json!({"err": "nope"})));
        let unknown = p.resolve("x:y/c#z", 1, &[]);
        assert_eq!(unknown.source, "generated");
        assert_eq!(unknown.latency_ms, Some(2.0));
    }

    #[test]
    fn matchers() {
        assert!(matches(&json!({"range": [1, 3]}), &json!(2)));
        assert!(!matches(&json!({"range": [1, 3]}), &json!(5)));
        assert!(matches(&json!({"not": {"contains": "x"}}), &json!("abc")));
        assert!(matches(&json!("a"), &json!({"some": "a"})));
    }

    #[test]
    fn rejects_typos() {
        assert!(Plan::parse(r#"{"f": {"retrun": 1}}"#).is_err());
    }
}
