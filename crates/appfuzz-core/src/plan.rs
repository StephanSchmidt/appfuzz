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
//! Precedence per call: `on_call[n]` > first matching rule > `default` >
//! the function's own `return`/`generate`/`trap` > `_defaults` > values
//! generated from the WIT type. Keys starting with `_` inside a function
//! entry (`_sig`, `_example`) are notes and ignored.

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
    pub latency_ms: Option<f64>,
}

impl Response {
    fn decides(&self) -> bool {
        self.ret.is_some() || self.generate.is_some() || self.trap.is_some()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    /// Parameter name or index → matcher. All must match.
    #[serde(default)]
    pub when: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub response: Response,
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

    fn validate(&self) -> Result<()> {
        for (key, f) in &self.0 {
            for k in f.notes.keys() {
                if !k.starts_with('_') {
                    bail!("{key}: unknown plan field {k:?} (notes must start with _)");
                }
            }
            for n in f.on_call.keys() {
                n.parse::<u32>().with_context(|| format!("{key}: on_call key {n:?} must be a call number"))?;
            }
            for (i, r) in f.rules.iter().enumerate() {
                for m in r.when.values() {
                    matcher_ok(m).with_context(|| format!("{key}: rule {i}"))?;
                }
            }
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Option<&FnPlan> {
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
            let decision = if let Some(msg) = &r.trap {
                Decision::Trap(msg.clone())
            } else if let Some(v) = &r.ret {
                Decision::Return(v.clone())
            } else if let Some(g) = &r.generate {
                Decision::Generate(g.clone())
            } else {
                return None;
            };
            Some(Resolved {
                decision,
                latency_ms: r.latency_ms.or(fn_latency).or(defaults.and_then(|d| d.response.latency_ms)),
                cost,
                source,
            })
        };
        if let Some(f) = fp {
            if let Some(r) = f.on_call.get(&call.to_string())
                && let Some(res) = finish(r, format!("on_call {call}"))
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

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
