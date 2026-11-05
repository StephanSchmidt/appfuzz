//! Explicit semantic value contracts. Declarations are compiled once against
//! WIT; host arguments are checked before their trace representation is cut.
use std::{cmp::Ordering, collections::BTreeMap};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use wasmtime::component::Type;

use crate::constraints::Constraint;

#[derive(Debug, Clone)]
enum Rule {
    Existing(Constraint),
    Range(Option<Decimal>, Option<Decimal>),
    Bytes(Option<usize>, Option<usize>),
    Required,
    Uuid,
}

/// A decimal represented without rounding integer bounds through f64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decimal {
    negative: bool,
    digits: String,
    exponent: i64,
    integer: Option<i128>,
}
impl Decimal {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let negative = text.starts_with('-');
        let text = text.strip_prefix(['-', '+']).unwrap_or(text);
        let (mantissa, exponent) = match text.split_once(['e', 'E']) {
            Some((m, e)) => (m, e.parse::<i64>().ok()?),
            None => (text, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if (whole.is_empty() && fraction.is_empty()) || !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut digits = format!("{whole}{fraction}").trim_start_matches('0').to_string();
        let mut exponent = exponent.checked_sub(fraction.len() as i64)?;
        while digits.ends_with('0') {
            digits.pop();
            exponent = exponent.checked_add(1)?;
        }
        if digits.is_empty() {
            return Some(Self { negative: false, digits: "0".into(), exponent: 0, integer: Some(0) });
        }
        exponent.checked_add(digits.len() as i64)?;
        let integer = u32::try_from(exponent)
            .ok()
            .and_then(|e| 10i128.checked_pow(e))
            .and_then(|scale| digits.parse::<i128>().ok()?.checked_mul(scale))
            .and_then(|n| if negative { n.checked_neg() } else { Some(n) });
        Some(Self { negative, digits, exponent, integer })
    }
    pub(crate) fn cmp(&self, other: &Self) -> Ordering {
        let zero = self.digits == "0";
        let other_zero = other.digits == "0";
        if zero && other_zero {
            return Ordering::Equal;
        }
        if self.negative != other.negative {
            return other.negative.cmp(&self.negative);
        }
        let order = match (zero, other_zero) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => (self.exponent + self.digits.len() as i64).cmp(&(other.exponent + other.digits.len() as i64)).then_with(|| {
                let n = self.digits.len().max(other.digits.len());
                self.digits.bytes().chain(std::iter::repeat(b'0')).take(n).cmp(other.digits.bytes().chain(std::iter::repeat(b'0')).take(n))
            }),
        };
        if self.negative { order.reverse() } else { order }
    }

    pub(crate) fn rounded_integer(&self, up: bool) -> Option<i128> {
        if let Some(integer) = self.integer {
            return Some(integer);
        }
        if self.exponent >= 0 {
            return None;
        }
        let point = self.exponent + self.digits.len() as i64;
        let whole = if point <= 0 { 0 } else { self.digits[..point as usize].parse::<i128>().ok()? };
        if self.negative {
            if up { whole.checked_neg() } else { whole.checked_neg()?.checked_sub(1) }
        } else if up {
            whole.checked_add(1)
        } else {
            Some(whole)
        }
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(integer) = self.integer {
            return write!(f, "{integer}");
        }
        let sign = if self.negative { "-" } else { "" };
        let point = self.exponent + self.digits.len() as i64;
        if self.exponent < 0 && point > 0 {
            let point = point as usize;
            write!(f, "{sign}{}.{}", &self.digits[..point], &self.digits[point..])
        } else if self.exponent < 0 && point > -8 {
            write!(f, "{sign}0.{}{}", "0".repeat((-point) as usize), self.digits)
        } else {
            write!(f, "{sign}{}e{}", self.digits, self.exponent)
        }
    }
}

/// A single constraint string, or an array whose constraints all apply.
#[derive(Debug, Clone)]
pub struct Domain {
    text: Vec<String>,
    rules: Vec<Rule>,
    input_option_depth: usize,
}
impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            One(String),
            Many(Vec<String>),
        }
        let text = match Raw::deserialize(d)? {
            Raw::One(s) => vec![s],
            Raw::Many(v) => v,
        };
        Self::parse(text).map_err(serde::de::Error::custom)
    }
}
impl Serialize for Domain {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if self.text.len() == 1 { self.text[0].serialize(s) } else { self.text.serialize(s) }
    }
}
impl Domain {
    pub fn required(&self) -> bool {
        self.rules.iter().any(|r| matches!(r, Rule::Required))
    }
    pub fn validate_input_type(&mut self, ty: &Type, path: &str) -> Result<()> {
        fn resolve(ty: &Type, path: &[&str]) -> Result<Type> {
            if path.is_empty() {
                return Ok(ty.clone());
            }
            match ty {
                Type::Record(r) => resolve(&r.fields().find(|f| f.name == path[0]).context("unknown input field")?.ty, &path[1..]),
                Type::Option(o) => resolve(&o.ty(), path),
                Type::List(l) => {
                    if let Type::Tuple(t) = l.ty() {
                        let parts: Vec<_> = t.types().collect();
                        if parts.len() == 2 && parts[0] == Type::String {
                            return resolve(&parts[1], &path[1..]);
                        }
                        bail!("named input fields require key/value string pairs")
                    } else {
                        bail!("input path cannot select this list")
                    }
                }
                _ => bail!("input path does not exist in WIT"),
            }
        }
        let segs: Vec<_> = if path.is_empty() { vec![] } else { path.split('.').collect() };
        if segs.iter().any(|p| p.is_empty()) {
            bail!("empty input path segment");
        }
        let mut selected = resolve(ty, &segs)?;
        self.input_option_depth = 0;
        while let Type::Option(o) = selected {
            self.input_option_depth += 1;
            selected = o.ty();
        }
        if !self.accepts_type(&selected) {
            bail!("input domain is incompatible with the selected WIT field");
        }
        Ok(())
    }
    pub fn parse(text: Vec<String>) -> Result<Self> {
        if text.is_empty() {
            bail!("a value domain needs at least one constraint");
        }
        let mut rules = Vec::new();
        for t in &text {
            let bounds = |s: &str| -> Result<(Option<String>, Option<String>)> {
                let (a, b) = s.split_once("..").context("write bounds as a..b")?;
                Ok(((!a.is_empty()).then(|| a.to_string()), (!b.is_empty()).then(|| b.to_string())))
            };
            let rule = if let Some(s) = t.strip_prefix("range:") {
                let (a, b) = bounds(s)?;
                let parse = |s: String| Decimal::parse(&s).with_context(|| format!("invalid finite numeric bound {s:?}"));
                let (a, b) = (a.map(parse).transpose()?, b.map(parse).transpose()?);
                if a.as_ref().zip(b.as_ref()).is_some_and(|(a, b)| a.cmp(b).is_gt()) {
                    bail!("lower bound exceeds upper bound");
                }
                Rule::Range(a, b)
            } else if let Some(s) = t.strip_prefix("bytes:") {
                let (a, b) = bounds(s)?;
                let (a, b) = (a.map(|s| s.parse::<usize>()).transpose()?, b.map(|s| s.parse::<usize>()).transpose()?);
                if a.zip(b).is_some_and(|(a, b)| a > b) {
                    bail!("lower length exceeds upper length");
                }
                Rule::Bytes(a, b)
            } else if t == "required" {
                Rule::Required
            } else if t == "format:uuid" {
                Rule::Uuid
            } else {
                let c = Constraint::parse(t)?;
                if matches!(&c, Constraint::Len(Some(a),Some(b)) if a>b) {
                    bail!("lower length exceeds upper length");
                }
                Rule::Existing(c)
            };
            rules.push(rule);
        }
        let domain = Self { text, rules, input_option_depth: 0 };
        domain.check_consistency()?;
        Ok(domain)
    }
    fn check_consistency(&self) -> Result<()> {
        let formats: Vec<_> = self.text.iter().filter(|s| s.starts_with("format:")).collect();
        if formats.windows(2).any(|p| p[0] != p[1]) {
            bail!("a field cannot have conflicting formats");
        }
        if self.rules.iter().any(|r| matches!(r, Rule::Range(..))) && formats.iter().any(|s| s.as_str() != "format:int") {
            bail!("numeric bounds conflict with a nonnumeric format");
        }
        let mut low: Option<&Decimal> = None;
        let mut high: Option<&Decimal> = None;
        let (mut len_lo, mut len_hi, mut byte_lo, mut byte_hi) = (0, usize::MAX, 0, usize::MAX);
        for rule in &self.rules {
            match rule {
                Rule::Range(a, b) => {
                    if let Some(a) = a
                        && low.is_none_or(|l| a.cmp(l).is_gt())
                    {
                        low = Some(a);
                    }
                    if let Some(b) = b
                        && high.is_none_or(|h| b.cmp(h).is_lt())
                    {
                        high = Some(b);
                    }
                }
                Rule::Existing(Constraint::Len(a, b)) => {
                    len_lo = len_lo.max(a.unwrap_or(0));
                    len_hi = len_hi.min(b.unwrap_or(usize::MAX));
                }
                Rule::Bytes(a, b) => {
                    byte_lo = byte_lo.max(a.unwrap_or(0));
                    byte_hi = byte_hi.min(b.unwrap_or(usize::MAX));
                }
                _ => {}
            }
        }
        if low.zip(high).is_some_and(|(a, b)| a.cmp(b).is_gt())
            || len_lo > len_hi
            || byte_lo > byte_hi
            || len_lo > byte_hi
            || byte_lo > len_hi.saturating_mul(4)
        {
            bail!("contradictory value constraints");
        }
        let format_len = formats.first().and_then(|f| match f.as_str() {
            "format:date" => Some((10, 10)),
            "format:time" => Some((5, 8)),
            "format:datetime" => Some((16, 19)),
            "format:uuid" => Some((36, 36)),
            "format:int" => Some((1, usize::MAX)),
            _ => None,
        });
        if format_len.is_some_and(|(a, b)| len_lo > b || len_hi < a || byte_lo > b || byte_hi < a) {
            bail!("length constraints contradict the declared format");
        }
        for rule in &self.rules {
            if let Rule::Existing(Constraint::Enum(values)) = rule
                && !values.iter().any(|s| self.holds(Some(&json!(s))))
            {
                bail!("enum has no value satisfying its other constraints");
            }
        }
        Ok(())
    }
    fn rule_holds(rule: &Rule, value: Option<&Value>) -> bool {
        if matches!(rule, Rule::Required) {
            return value.is_some_and(|v| !v.is_null());
        }
        let Some(v) = value.filter(|v| !v.is_null()) else {
            return true;
        };
        match rule {
            Rule::Range(a, b) => {
                if a.as_ref().is_none_or(|a| a.integer.is_some()) && b.as_ref().is_none_or(|b| b.integer.is_some()) {
                    let n = v.as_i64().map(i128::from).or_else(|| v.as_u64().map(i128::from)).or_else(|| v.as_str()?.trim().parse::<i128>().ok());
                    if let Some(n) = n {
                        return a.as_ref().is_none_or(|a| n >= a.integer.unwrap()) && b.as_ref().is_none_or(|b| n <= b.integer.unwrap());
                    }
                }
                let text = v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
                Decimal::parse(&text).is_some_and(|n| a.as_ref().is_none_or(|a| n.cmp(a).is_ge()) && b.as_ref().is_none_or(|b| n.cmp(b).is_le()))
            }
            Rule::Bytes(a, b) => v.as_str().is_some_and(|s| a.is_none_or(|a| s.len() >= a) && b.is_none_or(|b| s.len() <= b)),
            Rule::Uuid => v.as_str().is_some_and(crate::constraints::uuid_ok),
            Rule::Existing(Constraint::Format(crate::constraints::Format::Date)) => v.as_str().is_some_and(date_ok),
            Rule::Existing(Constraint::Format(crate::constraints::Format::Time)) => v.as_str().is_some_and(time_ok),
            Rule::Existing(Constraint::Format(crate::constraints::Format::DateTime)) => {
                v.as_str().is_some_and(|s| (s.len() == 16 || s.len() == 19) && s.as_bytes()[10] == b'T' && date_ok(&s[..10]) && time_ok(&s[11..]))
            }
            Rule::Existing(c) => c.holds(v),
            Rule::Required => unreachable!(),
        }
    }
    fn input_leaf<'a>(&self, value: Option<&'a Value>) -> Option<&'a Value> {
        let mut value = value;
        for _ in 0..self.input_option_depth {
            value = value.map(|v| v.as_object().filter(|o| o.len() == 1).and_then(|o| o.get("some")).unwrap_or(v));
        }
        value
    }
    pub fn exercised(&self, value: Option<&Value>) -> bool {
        self.required() || self.input_leaf(value).is_some_and(|v| !v.is_null())
    }
    pub fn holds(&self, value: Option<&Value>) -> bool {
        let value = self.input_leaf(value);
        self.rules.iter().all(|r| Self::rule_holds(r, value))
    }
    fn reason(rule: &Rule, value: Option<&Value>) -> &'static str {
        match rule {
            Rule::Required => "missing",
            Rule::Range(low, _) => {
                let text = value.map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())).unwrap_or_default();
                match Decimal::parse(&text) {
                    None => "not_numeric",
                    Some(n) if low.as_ref().is_some_and(|lo| n.cmp(lo).is_lt()) => "below_minimum",
                    _ => "above_maximum",
                }
            }
            Rule::Bytes(low, _) => {
                if value.and_then(Value::as_str).is_some_and(|s| low.is_some_and(|lo| s.len() < lo)) {
                    "below_minimum"
                } else {
                    "above_maximum"
                }
            }
            Rule::Existing(Constraint::Len(low, _)) => {
                let n = value.and_then(|v| v.as_str().map(|s| s.chars().count()).or_else(|| v.as_array().map(Vec::len)));
                if n.is_some_and(|n| low.is_some_and(|lo| n < lo)) { "below_minimum" } else { "above_maximum" }
            }
            Rule::Existing(Constraint::Enum(_)) => "outside_enum",
            _ => "invalid_format",
        }
    }
    fn accepts_type(&self, ty: &Type) -> bool {
        self.rules.iter().all(|r| match r {
            Rule::Required => true,
            Rule::Range(..) | Rule::Existing(Constraint::Enum(_)) => matches!(
                ty,
                Type::String | Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::S8 | Type::S16 | Type::S32 | Type::S64 | Type::Float32 | Type::Float64
            ),
            Rule::Existing(Constraint::Len(..)) => {
                matches!(ty, Type::String | Type::List(_) | Type::FixedLengthList(_))
            }
            _ => matches!(ty, Type::String),
        })
    }
}

fn date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' || b.iter().enumerate().any(|(i, c)| i != 4 && i != 7 && !c.is_ascii_digit()) {
        return false;
    }
    let y = b[..4].iter().fold(0u32, |n, c| n * 10 + u32::from(c - b'0'));
    let m = (b[5] - b'0') * 10 + b[6] - b'0';
    let d = (b[8] - b'0') * 10 + b[9] - b'0';
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    y > 0 && d > 0 && d <= days
}
fn time_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() == 5 || b.len() == 8)
        && b[2] == b':'
        && (b.len() == 5 || b[5] == b':')
        && b.iter().enumerate().all(|(i, c)| i == 2 || i == 5 || c.is_ascii_digit())
        && (b[0] - b'0') * 10 + b[1] - b'0' < 24
        && (b[3] - b'0') * 10 + b[4] - b'0' < 60
        && (b.len() == 5 || (b[6] - b'0') * 10 + b[7] - b'0' < 60)
}

#[derive(Debug)]
enum Node {
    Leaf(Domain),
    Field(String, Box<Node>),
    Index(usize, Box<Node>),
    Each(Box<Node>),
    Option(Box<Node>, bool),
    Ok(Box<Node>),
}
impl Node {
    fn compile(ty: &Type, path: &[&str], domain: &Domain) -> Result<Self> {
        if let Type::Option(o) = ty {
            return Ok(Self::Option(Box::new(Self::compile(&o.ty(), path, domain)?), path.is_empty() && domain.text.iter().any(|s| s == "required")));
        }
        if let Type::Result(r) = ty {
            return Ok(Self::Ok(Box::new(Self::compile(&r.ok().context("result has no ok value")?, path, domain)?)));
        }
        if path.is_empty() && domain.accepts_type(ty) {
            return Ok(Self::Leaf(domain.clone()));
        }
        match ty {
            Type::List(l) => Ok(Self::Each(Box::new(Self::compile(&l.ty(), path, domain)?))),
            Type::FixedLengthList(l) => Ok(Self::Each(Box::new(Self::compile(&l.ty(), path, domain)?))),
            Type::Record(r) if !path.is_empty() => {
                let f = r.fields().find(|f| f.name == path[0]).context("unknown record field")?;
                Ok(Self::Field(f.name.to_string(), Box::new(Self::compile(&f.ty, &path[1..], domain)?)))
            }
            Type::Tuple(t) if !path.is_empty() => {
                let i = path[0].parse::<usize>()?;
                let ty = t.types().nth(i).context("tuple index out of range")?;
                Ok(Self::Index(i, Box::new(Self::compile(&ty, &path[1..], domain)?)))
            }
            _ => bail!("unknown path or constraints incompatible with {}", crate::wit::type_str(ty)),
        }
    }
    fn check(&self, value: Option<&Value>, path: &mut Vec<String>, declared: &str, out: &mut Evidence) {
        if out.violations.len() >= 16 {
            out.truncated = true;
            return;
        }
        match self {
            Self::Leaf(d) => {
                for (text, rule) in d.text.iter().zip(&d.rules) {
                    out.checked += 1;
                    if !Domain::rule_holds(rule, value) {
                        out.violations.push(Violation {
                            declaration: declared.into(),
                            path: path.join("."),
                            constraint: text.clone(),
                            reason: Domain::reason(rule, value).into(),
                            value: summary(value),
                            bytes: value.and_then(Value::as_str).map(str::len),
                        });
                        if out.violations.len() >= 16 {
                            out.truncated = true;
                            break;
                        }
                    }
                }
            }
            Self::Field(name, next) => {
                path.push(name.clone());
                next.check(value.and_then(|v| v.get(name)), path, declared, out);
                path.pop();
            }
            Self::Index(i, next) => {
                path.push(i.to_string());
                next.check(value.and_then(|v| v.get(i)), path, declared, out);
                path.pop();
            }
            Self::Each(next) => {
                if let Some(a) = value.and_then(Value::as_array) {
                    for (i, v) in a.iter().enumerate() {
                        path.push(i.to_string());
                        next.check(Some(v), path, declared, out);
                        path.pop();
                        if out.truncated {
                            break;
                        }
                    }
                }
            }
            Self::Option(next, required) => {
                if value.is_some_and(|v| !v.is_null()) {
                    let inner = value.map(|v| v.as_object().filter(|o| o.len() == 1).and_then(|o| o.get("some")).unwrap_or(v));
                    next.check(inner, path, declared, out);
                } else if *required {
                    out.checked += 1;
                    out.violations.push(Violation {
                        declaration: declared.into(),
                        path: path.join("."),
                        constraint: "required".into(),
                        reason: "missing".into(),
                        value: Value::Null,
                        bytes: None,
                    });
                }
            }
            Self::Ok(next) => {
                if let Some(v) = value.and_then(|v| v.get("ok")) {
                    next.check(Some(v), path, declared, out);
                }
            }
        }
    }
}
fn summary(value: Option<&Value>) -> Value {
    match value {
        Some(Value::String(s)) if s.len() > 256 => {
            json!({"prefix":s.chars().take(128).collect::<String>(),"bytes":s.len()})
        }
        Some(v) if v.is_array() => json!({"elements":v.as_array().unwrap().len()}),
        Some(v) => v.clone(),
        None => Value::Null,
    }
}
#[derive(Debug)]
pub struct HostChecks {
    checks: Vec<(usize, String, Node)>,
}
impl HostChecks {
    pub fn compile(params: &[(String, Type)], domains: &BTreeMap<String, Domain>) -> Result<Self> {
        let mut checks = Vec::new();
        for (path, domain) in domains {
            let parts: Vec<_> = path.split('.').collect();
            if parts.iter().any(|p| p.is_empty()) {
                bail!("empty value path segment");
            }
            let (index, (_, ty)) =
                params.iter().enumerate().find(|(_, (name, _))| name == parts[0]).with_context(|| format!("unknown parameter in {path:?}"))?;
            checks.push((index, path.clone(), Node::compile(ty, &parts[1..], domain).with_context(|| format!("parameter {path}"))?));
        }
        Ok(Self { checks })
    }
    pub fn check(&self, args: &[(String, Value)]) -> Evidence {
        let mut out = Evidence::default();
        for (index, declared, node) in &self.checks {
            let mut path = vec![args[*index].0.clone()];
            node.check(Some(&args[*index].1), &mut path, declared, &mut out);
            if out.truncated {
                break;
            }
        }
        out
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub checked: u64,
    pub violations: Vec<Violation>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub declaration: String,
    pub path: String,
    pub constraint: String,
    #[serde(default)]
    pub reason: String,
    pub value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
}

/// Function-level coverage of declared checks; an absent optional/list value
/// does not count as testing the constraints on its contents.
pub fn coverage(app: &crate::harness::App, runs: &[crate::record::RunRecord]) -> Value {
    let mut functions = Vec::new();
    for f in app.imports.iter().flat_map(|i| &i.funcs) {
        let Some(spec) = app.manifest.function(&f.key).filter(|s| !s.param_values.is_empty()) else {
            continue;
        };
        let mut calls = 0u64;
        let mut checked = 0u64;
        let mut violations = 0u64;
        for e in runs.iter().flat_map(|r| &r.events).filter(|e| e.func == f.key) {
            if let Some(c) = &e.value_checks {
                calls += 1;
                checked += c.checked;
                violations += c.violations.len() as u64;
            }
        }
        functions.push(json!({"func":f.key,"declared_paths":spec.param_values.keys().collect::<Vec<_>>(),"calls_with_evidence":calls,"checked_rules":checked,"violations":violations}));
    }
    let unreached: Vec<_> = functions.iter().filter(|f| f["checked_rules"] == 0).map(|f| &f["func"]).collect();
    json!({"scope":"recorded runs, function-level checks","declared_functions":functions.len(),"unexercised_functions":unreached,"functions":functions})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_rounding_and_serialization_agree_with_integer_arithmetic() {
        for coefficient in -1000i128..=1000 {
            for exponent in 0..=5 {
                let scale = 10i128.pow(exponent);
                let decimal = Decimal::parse(&format!("{coefficient}e-{exponent}")).unwrap();
                let floor = coefficient.div_euclid(scale);
                let ceil = floor + i128::from(coefficient.rem_euclid(scale) != 0);
                assert_eq!(decimal.rounded_integer(false), Some(floor));
                assert_eq!(decimal.rounded_integer(true), Some(ceil));
                assert!(decimal.cmp(&Decimal::parse(&decimal.to_string()).unwrap()).is_eq());
            }
        }
    }

    #[test]
    fn decimal_comparison_agrees_with_scaled_integer_arithmetic() {
        use rand::{RngExt, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7241);
        for _ in 0..5000 {
            let a = rng.random_range(-1_000_000i128..=1_000_000);
            let b = rng.random_range(-1_000_000i128..=1_000_000);
            let a_exp = rng.random_range(-6i32..=6);
            let b_exp = rng.random_range(-6i32..=6);
            let a_text = format!("{a}e{a_exp}");
            let b_text = format!("{b}e{b_exp}");
            let scaled_a = a * 10i128.pow((a_exp + 6) as u32);
            let scaled_b = b * 10i128.pow((b_exp + 6) as u32);
            assert_eq!(Decimal::parse(&a_text).unwrap().cmp(&Decimal::parse(&b_text).unwrap()), scaled_a.cmp(&scaled_b), "{a_text} versus {b_text}");
        }
        for (a, b) in [(".5", "5e-1"), ("-.5", "-0.50"), ("-0", ".0"), ("+1.", "01")] {
            assert!(Decimal::parse(a).unwrap().cmp(&Decimal::parse(b).unwrap()).is_eq());
        }
        for text in [".", "-.", "NaN", "inf", "1e9223372036854775807"] {
            assert!(Decimal::parse(text).is_none(), "{text}");
        }
    }

    fn domain(rules: &[&str]) -> Domain {
        Domain::parse(rules.iter().map(|s| s.to_string()).collect()).unwrap()
    }
    #[test]
    fn ranges_preserve_integer_precision_and_decimal_order() {
        let d = domain(&["range:18446744073709551614..18446744073709551614"]);
        assert!(d.holds(Some(&json!(u64::MAX - 1))));
        assert!(!d.holds(Some(&json!(u64::MAX))));
        assert!(!d.holds(Some(&json!(u64::MAX - 2))));
        let d = domain(&["range:-9223372036854775808..-9223372036854775807"]);
        assert!(d.holds(Some(&json!(i64::MIN))));
        assert!(!d.holds(Some(&json!(i64::MIN + 2))));
        for (s, valid) in [("0.10", true), ("1e-1", true), ("0.0999", false), ("0.10001", false), ("NaN", false), ("Infinity", false)] {
            assert_eq!(domain(&["range:0.1..0.1"]).holds(Some(&json!(s))), valid, "{s}");
        }
        assert!(domain(&["range:-1..0"]).holds(Some(&json!(-0.1))));
        for rules in [
            vec!["range:NaN..1"],
            vec!["range:10..1"],
            vec!["bytes:5..1"],
            vec!["range:0..2", "range:3..4"],
            vec!["format:date", "len:..9"],
            vec!["enum:a,b", "format:int"],
            vec!["format:date", "format:uuid"],
        ] {
            assert!(Domain::parse(rules.iter().map(|s| s.to_string()).collect()).is_err(), "{rules:?}");
        }
    }
    #[test]
    fn explicit_formats_lengths_presence_and_sets() {
        for s in ["0.0.0000", "0000-00-00", "2027-02-29", "2026-04-31", "2026-2-01", "0000-01-01"] {
            assert!(!domain(&["format:date"]).holds(Some(&json!(s))), "{s}");
        }
        assert!(domain(&["format:date"]).holds(Some(&json!("2028-02-29"))));
        assert!(!domain(&["format:uuid"]).holds(Some(&json!("0000-0000-0000-0000"))));
        assert!(domain(&["format:uuid"]).holds(Some(&json!("00000000-0000-0000-0000-000000000000"))));
        assert!(domain(&["len:1..1"]).holds(Some(&json!("é"))));
        assert!(!domain(&["bytes:..1"]).holds(Some(&json!("é"))));
        assert!(domain(&["format:date"]).holds(None));
        assert!(!domain(&["required", "format:date"]).holds(None));
        assert!(!domain(&["format:int"]).holds(Some(&json!("--1"))));
        assert!(!domain(&["enum:EUR,USD"]).holds(Some(&json!("GBP"))));
        assert!(domain(&["required", "format:int", "range:1..6"]).holds(Some(&json!("6"))));
    }
}
