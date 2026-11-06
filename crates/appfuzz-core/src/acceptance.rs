//! Explicit, versioned acceptance requirements. Observed behavior never creates requirements.
use crate::{
    assertion::Assertion,
    check::{Property, Selector},
    harness::App,
    manifest::Manifest,
    plan::Plan,
    record::{OutcomeKind, RunRecord, RunSpec},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub version: u32,
    pub checks: BTreeMap<String, Check>,
}
/// Who owns a requirement: the app's owners, whichever team that is, or the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Intended app behavior. `marketing`, the former spelling, still reads.
    #[serde(alias = "marketing")]
    App,
    Platform,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InputClass {
    Valid,
    Invalid,
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
    /// Scope to an explicitly declared guest acceptance domain, not a platform filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_class: Option<InputClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_fields: Vec<String>,
    /// Exact request-field scope (for example method=POST and a route).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub when: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbid_effects: Vec<crate::manifest::Effect>,
    /// Named values for `assert` and `assume`: `name = "host.items#all.result"`.
    #[serde(default, rename = "let", skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, String>,
    /// A CEL expression over the bindings, or a table of named ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assert: Option<Assert>,
    /// Precondition: runs where it is false are rejected, never passing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assume: Option<String>,
    #[serde(skip)]
    compiled: OnceLock<Arc<Assertion>>,
}
/// One assertion, or named ones that share the check's scope and bindings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Assert {
    One(String),
    Named(BTreeMap<String, String>),
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
/// A binding no property reads is a leftover or a typo.
fn unused(bindings: &BTreeMap<String, String>, used: &BTreeSet<String>) -> Result<()> {
    let idle: Vec<&str> = bindings.keys().filter(|k| !used.contains(*k)).map(String::as_str).collect();
    if !idle.is_empty() {
        bail!("let binds {} but no assert or assume uses it", idle.join(", "));
    }
    Ok(())
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
    /// Checks with one property each: a named `assert` table becomes one
    /// check per property, `check.property`, sharing scope and bindings.
    pub fn expanded(&self) -> Vec<(String, Check)> {
        let mut out = Vec::new();
        for (name, c) in &self.checks {
            match &c.assert {
                Some(Assert::Named(props)) => out.extend(props.iter().map(|(k, e)| (format!("{name}.{k}"), c.single(e)))),
                _ => out.push((name.clone(), c.clone())),
            }
        }
        out
    }
    /// Asserts any run of `export` can judge: searching, with no inputs or
    /// scope of their own. Fuzzing judges them on every run.
    pub fn shared_asserts(&self, export: &str, default_export: Option<&str>) -> Vec<(String, Arc<Assertion>)> {
        self.expanded()
            .into_iter()
            .filter(|(_, c)| {
                c.assert.is_some()
                    && c.searches()
                    && c.export.as_deref().or(default_export) == Some(export)
                    && c.request.is_none()
                    && c.args.is_none()
                    && c.now.is_none()
                    && c.seed.is_none()
                    && c.plan.0.is_empty()
                    && c.input_class.is_none()
                    && c.input_fields.is_empty()
                    && c.when.is_empty()
                    && c.forbid_effects.is_empty()
            })
            .filter_map(|(n, c)| c.assertion().ok().flatten().map(|a| (n, a)))
            .collect()
    }
    /// Binding paths against the component's imports and exports.
    pub fn validate_wit(&self, m: &Manifest, imports: &[crate::wit::Interface], exports: &[crate::wit::FuncInfo]) -> Result<()> {
        for (name, c) in self.expanded() {
            let Some(a) = c.assertion()? else { continue };
            let export = c.export.as_deref().or(m.entry.as_ref().map(|e| e.export.as_str()));
            crate::assertion::validate_wit(&a.bindings, imports, exports, export).with_context(|| format!("acceptance check {name}"))?;
        }
        Ok(())
    }
}
impl Check {
    fn single(&self, expr: &str) -> Check {
        let mut c = self.clone();
        c.assert = Some(Assert::One(expr.to_string()));
        c.compiled = OnceLock::new();
        // Each property keeps the bindings it or `assume` reads: a run is not
        // unexercised for one property because another one's value is missing.
        let names: BTreeSet<String> = self.bindings.keys().cloned().collect();
        let mut used = BTreeSet::new();
        for text in std::iter::once(expr).chain(self.assume.as_deref()) {
            match crate::assertion::Expression::compile(text, &names) {
                Ok(e) => used.extend(e.uses),
                Err(_) => return c,
            }
        }
        c.bindings.retain(|k, _| used.contains(k));
        c
    }
    /// The compiled assertion of a single-property assert check.
    pub fn assertion(&self) -> Result<Option<Arc<Assertion>>> {
        match &self.assert {
            None => Ok(None),
            Some(Assert::Named(_)) => bail!("a named assert table runs as one check per property; use Suite::expanded"),
            Some(Assert::One(e)) => {
                if let Some(a) = self.compiled.get() {
                    return Ok(Some(a.clone()));
                }
                let a = Arc::new(Assertion::new(&self.bindings, e, self.assume.as_deref())?);
                let _ = self.compiled.set(a.clone());
                Ok(Some(a))
            }
        }
    }
    pub fn searches(&self) -> bool {
        self.search.unwrap_or(self.expect.is_none())
    }
    pub fn property(&self) -> Result<Option<Property>> {
        let property = if let Some(words) = &self.property {
            Some(Property::parse(words)?)
        } else if let Some(a) = self.assertion()? {
            Some(Property::assertion(a))
        } else {
            self.expect.as_ref().map(|e| Property::expect(&e.selector, e.equals.clone())).transpose()?
        };
        let property = property.map(|p| p.forbid_effects(self.forbid_effects.clone()));
        if self.input_class.is_none() && self.when.is_empty() && self.forbid_effects.is_empty() {
            return Ok(property);
        }
        let check = self.clone();
        Ok(property.map(|p| p.scoped(move |r, m| check.applies(r, m))))
    }
    pub fn applies(&self, r: &RunRecord, m: &Manifest) -> bool {
        if !self.forbid_effects.is_empty() && r.events.iter().any(|e| m.function(&e.func).and_then(|f| f.effect).is_none()) {
            return false;
        }
        let Some(req) = r.spec.args.first() else {
            return self.when.is_empty() && self.input_class.is_none();
        };
        if !self.when.iter().all(|(path, v)| crate::harness::field(req, path) == Some(v)) {
            return false;
        }
        let Some(class) = self.input_class else {
            return true;
        };
        if !crate::constraints::broken_request_for(r, m).is_empty() {
            return false;
        }
        let Some(entry) = &m.entry else {
            return false;
        };
        let fields: Vec<_> = if self.input_fields.is_empty() { entry.input_values.keys().collect() } else { self.input_fields.iter().collect() };
        if fields.is_empty() {
            return false;
        }
        let mut invalid = false;
        let mut exercised = false;
        for path in fields {
            let Some(domain) = entry.input_values.get(path) else {
                return false;
            };
            let value = crate::harness::field(req, path);
            if !domain.exercised(value) {
                continue;
            }
            exercised = true;
            invalid |= !domain.holds(value);
        }
        exercised && invalid == (class == InputClass::Invalid)
    }
    pub fn validate(&self, m: &Manifest) -> Result<()> {
        if usize::from(self.property.is_some()) + usize::from(self.expect.is_some()) + usize::from(self.relation.is_some()) + usize::from(self.assert.is_some())
            != 1
        {
            bail!("specify exactly one of property, expect, relation, assert");
        }
        if (!self.bindings.is_empty() || self.assume.is_some()) && self.assert.is_none() {
            bail!("let and assume belong to an assert check");
        }
        if self.assert.is_some() && self.bindings.is_empty() {
            bail!("assert needs let bindings: expressions see only the values let names");
        }
        if self.request.is_some() && self.args.is_some() {
            bail!("specify request or args, not both");
        }
        if let Some(Assert::Named(props)) = &self.assert {
            if props.is_empty() {
                bail!("the assert table names no property");
            }
            let mut used = BTreeSet::new();
            for (k, e) in props {
                if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    bail!("assert property name {k:?} may hold letters, digits, - and _");
                }
                let one = self.single(e);
                one.validate(m).with_context(|| format!("assert {k}"))?;
                used.extend(one.assertion()?.map(|a| a.uses()).unwrap_or_default());
            }
            return unused(&self.bindings, &used);
        }
        self.plan.validate()?;
        self.property()?;
        if let Some(a) = self.assertion()? {
            unused(&self.bindings, &a.uses())?;
        }
        if (!self.input_fields.is_empty() && self.input_class.is_none())
            || self.input_class.is_some() && m.entry.as_ref().is_none_or(|e| e.input_values.is_empty())
        {
            bail!("input_class needs declared entry.input_values; input_fields needs input_class");
        }
        for path in &self.input_fields {
            if m.entry.as_ref().is_none_or(|e| !e.input_values.contains_key(path)) {
                bail!("undeclared input field {path}");
            }
        }
        if self.input_class.is_some() && self.export.as_deref().is_some_and(|x| m.entry.as_ref().is_none_or(|e| !crate::harness::fn_key_eq(x, &e.export))) {
            bail!("input_class applies to the declared entry export");
        }
        if self.relation.is_some() && (self.input_class.is_some() || !self.when.is_empty() || !self.forbid_effects.is_empty()) {
            bail!("input scopes and forbidden effects require a single-run acceptance check");
        }
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
        if self.input_class.is_some() && app.manifest.entry.as_ref().is_none_or(|e| !crate::harness::fn_key_eq(&export.key, &e.export)) {
            bail!("input_class applies to the declared entry export");
        }
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
    if !check.applies(&records[0], &app.manifest) {
        return Ok(Evaluation {
            status: "not_exercised".into(),
            matches: 0,
            detail: json!({"reason":"input is outside this check's declared scope"}),
            records,
        });
    }
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
    if let Some(a) = check.assertion()? {
        let (status, matches, mut detail) = crate::assertion::status(&a, &records[0], &app.manifest);
        if status != "broken"
            && !check.forbid_effects.is_empty()
            && let Some((why, evidence)) = check.property()?.context("missing property")?.broken(&records[0], &app.manifest)
            && evidence.get("effect").is_some()
        {
            return Ok(Evaluation { status: "broken".into(), matches: 1, detail: json!({"why":why,"evidence":evidence}), records });
        }
        if status == "broken"
            && let Some(o) = detail.as_object_mut()
        {
            o.insert("property".into(), json!(a.expr.text));
        }
        return Ok(Evaluation { status: status.into(), matches, detail, records });
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
