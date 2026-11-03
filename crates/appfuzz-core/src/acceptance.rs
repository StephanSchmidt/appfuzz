//! Explicit, versioned acceptance requirements. Observed behavior never creates requirements.
use crate::{
    check::{Property, Selector},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord, RunSpec},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub version: u32,
    pub checks: BTreeMap<String, Check>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Marketing,
    Platform,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub origin: Origin,
    #[serde(default)]
    pub description: String,
    pub property: Option<Vec<String>>,
    pub expect: Option<Expectation>,
    pub relation: Option<Relation>,
    /// Default: examples are fixed, properties and relations search.
    pub search: Option<bool>,
    pub export: Option<String>,
    pub request: Option<Value>,
    pub args: Option<Vec<Value>>,
    pub now: Option<String>,
    pub seed: Option<u64>,
    #[serde(default)]
    pub plan: Plan,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub selector: String,
    pub equals: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Equal,
    NonDecreasing,
    NonIncreasing,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub selector: String,
    pub comparison: Comparison,
    pub dataset: Option<String>,
    #[serde(default = "one")]
    pub add: usize,
    /// JSON pointers into the argument array.
    #[serde(default)]
    pub set: BTreeMap<String, Value>,
}
fn one() -> usize {
    1
}
impl Suite {
    pub fn validate(&self, m: &Manifest) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported acceptance suite version {}; expected 1", self.version);
        }
        if self.checks.is_empty() {
            bail!("acceptance suite must contain at least one check");
        }
        for (name, c) in &self.checks {
            c.validate(m).with_context(|| format!("acceptance check {name}"))?;
        }
        Ok(())
    }
}
impl Check {
    pub fn searches(&self) -> bool {
        self.search.unwrap_or(self.expect.is_none())
    }
    pub fn property(&self) -> Result<Option<Property>> {
        if let Some(words) = &self.property {
            return Ok(Some(Property::parse(words)?));
        }
        self.expect.as_ref().map(|e| Property::expect(&e.selector, e.equals.clone())).transpose()
    }
    pub fn validate(&self, m: &Manifest) -> Result<()> {
        if usize::from(self.property.is_some()) + usize::from(self.expect.is_some()) + usize::from(self.relation.is_some()) != 1 {
            bail!("specify exactly one of property, expect, relation");
        }
        if self.request.is_some() && self.args.is_some() {
            bail!("specify request or args, not both");
        }
        self.plan.validate()?;
        self.property()?;
        if let Some(r) = &self.relation {
            Selector::parse(&r.selector)?;
            if r.dataset.is_some() == !r.set.is_empty() {
                bail!("relation requires either a dataset increment or argument set");
            }
            if let Some(d) = &r.dataset
                && (!m.datasets.contains_key(d) || r.add == 0 || r.add > crate::dataset::MAX_ROWS)
            {
                bail!("invalid relation dataset or increment");
            }
            if r.set.keys().any(|p| !p.starts_with('/')) {
                bail!("relation set keys must be JSON pointers");
            }
        }
        Ok(())
    }
    pub fn spec(&self, app: &App, base: &RunSpec) -> Result<RunSpec> {
        let export = app.export(self.export.as_deref().unwrap_or(&base.export))?;
        let mut spec = base.clone();
        spec.export = export.key.clone();
        spec.now = self.now.clone().unwrap_or_else(|| base.now.clone());
        spec.seed = self.seed.unwrap_or(base.seed);
        spec.args = if let Some(a) = &self.args {
            a.clone()
        } else if let Some(r) = &self.request {
            vec![r.clone()]
        } else if spec.export != base.export || self.now.is_some() {
            app.default_args(export, &spec.now)?
        } else {
            base.args.clone()
        };
        for (k, v) in &self.plan.0 {
            spec.plan.0.insert(k.clone(), v.clone());
        }
        Ok(spec)
    }
    pub fn variant(&self, app: &App, base: &RunSpec) -> Result<RunSpec> {
        let r = self.relation.as_ref().context("not a relational check")?;
        let mut spec = base.clone();
        if let Some(name) = &r.dataset {
            let defaults = spec.plan.0.entry("_defaults".into()).or_default();
            let n = defaults.dataset_rows.get(name).copied().unwrap_or(app.manifest.datasets[name].rows);
            let next = n.checked_add(r.add).context("relation size overflow")?;
            if next > crate::dataset::MAX_ROWS {
                bail!("relation size exceeds dataset limit");
            }
            defaults.dataset_rows.insert(name.clone(), next);
        } else {
            let mut args = Value::Array(spec.args);
            for (p, v) in &r.set {
                *args.pointer_mut(p).with_context(|| format!("relation argument path {p} is absent"))? = v.clone();
            }
            spec.args = args.as_array().unwrap().clone();
            if spec.args == base.args {
                bail!("relation transform made no change");
            }
        }
        Ok(spec)
    }
}
#[derive(Serialize, Deserialize)]
pub struct Evaluation {
    pub status: String,
    pub matches: usize,
    pub detail: Value,
    pub records: Vec<RunRecord>,
}
pub fn evaluate(app: &App, check: &Check, spec: &RunSpec) -> Result<Evaluation> {
    let record = app.run(spec);
    evaluate_record(app, check, record)
}
pub fn evaluate_record(app: &App, check: &Check, record: RunRecord) -> Result<Evaluation> {
    let mut records = vec![record];
    if let Some(r) = &check.relation {
        let spec = check.variant(app, &records[0].spec)?;
        records.push(app.run(&spec));
        if records.iter().any(|r| matches!(r.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError)) {
            return Ok(Evaluation { status: "error".into(), matches: 0, detail: json!({"reason":"a comparison run could not execute"}), records });
        }
        let selector = Selector::parse(&r.selector)?;
        let numbers = if records.iter().all(|r| {
            r.outcome.kind == OutcomeKind::Ok
                && !r.result.as_ref().is_some_and(|v| v.get("err").is_some())
                && !crate::output::response(r, &app.manifest).status.is_some_and(|s| s >= 400)
        }) {
            selector.scalar(&records[0], &app.manifest).zip(selector.scalar(&records[1], &app.manifest))
        } else {
            None
        };
        if let Some((a, b)) = numbers {
            let holds = match r.comparison {
                Comparison::Equal => a == b,
                Comparison::NonDecreasing => b >= a,
                Comparison::NonIncreasing => b <= a,
            };
            return Ok(Evaluation {
                status: if holds { "holds" } else { "broken" }.into(),
                matches: 1,
                detail: json!({"before":a,"after":b,"comparison":r.comparison}),
                records,
            });
        }
        return Ok(Evaluation {
            status: "not_exercised".into(),
            matches: 0,
            detail: json!({"reason":"both runs must succeed and select exactly one finite number"}),
            records,
        });
    }
    if matches!(records[0].outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
        return Ok(Evaluation { status: "error".into(), matches: 0, detail: json!({"reason":"the request could not execute"}), records });
    }
    let property = check.property()?.context("missing property")?;
    let matches = property.matches(&records[0], &app.manifest);
    let broken = property.broken(&records[0], &app.manifest);
    Ok(Evaluation {
        status: if broken.is_some() {
            "broken"
        } else if matches == 0 {
            "not_exercised"
        } else {
            "holds"
        }
        .into(),
        matches,
        detail: broken.map_or_else(|| json!({}), |(why, detail)| json!({"why":why,"evidence":detail})),
        records,
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub kind: String,
    pub version: u32,
    pub component: String,
    pub contract: String,
    pub name: String,
    pub check: Check,
    pub spec: RunSpec,
}
