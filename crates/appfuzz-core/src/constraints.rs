//! Value constraints: what the platform promises about a value.
//!
//! `values = { score = "range:0..100" }` on a host function says the host
//! never returns a score outside 0..100. `[entry] values = { "query.days" =
//! "range:1..31" }` says the platform rejects other requests before the app
//! sees them. Generated values keep to the constraints, so findings are
//! about inputs that can happen. A run whose request breaks a constraint
//! (a plan or `--set` can still make one) has its findings lowered to info.
//!
//! Forms: `range:a..b` (numbers, or text holding a number; either end may
//! be left out), `len:a..b` (characters of text, elements of a list),
//! `enum:x,y,z`, `format:date|time|datetime|email|int`.

use std::fmt;

use crate::value_contract::Decimal;

#[path = "constraints_typed.rs"]
mod typed;
use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
pub(crate) use typed::{conform_host, conform_request_typed, validate_type};

#[derive(Debug, Clone, PartialEq)]
pub enum Constraint {
    Range(Option<Decimal>, Option<Decimal>),
    Len(Option<usize>, Option<usize>),
    Enum(Vec<String>),
    Format(Format),
    /// No two elements of a list alike, as a whole or by these fields
    /// together (`unique:pod,date,hour`, a unique key of the platform).
    Unique(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Date,
    Time,
    DateTime,
    Email,
    Int,
    Uuid,
    /// An absolute http(s) URL, as the `url` crate parses it.
    Url,
    /// An HTTP token (a method or header name).
    Token,
}

impl Constraint {
    pub fn parse(s: &str) -> Result<Self> {
        let (kind, arg) = s.split_once(':').unwrap_or((s, ""));
        let bounds = |a: &str| -> Result<(Option<String>, Option<String>)> {
            let Some((lo, hi)) = a.split_once("..") else { bail!("{s:?}: write the bounds as a..b, a.. or ..b") };
            let opt = |x: &str| (!x.trim().is_empty()).then(|| x.trim().to_string());
            Ok((opt(lo), opt(hi)))
        };
        Ok(match kind {
            "range" => {
                let (lo, hi) = bounds(arg)?;
                let num = |x: Option<String>| -> Result<Option<Decimal>> {
                    x.map(|x| Decimal::parse(&x).ok_or_else(|| anyhow::anyhow!("{s:?}: {x:?} is not a finite decimal number"))).transpose()
                };
                let (lo, hi) = (num(lo)?, num(hi)?);
                if lo.as_ref().zip(hi.as_ref()).is_some_and(|(lo, hi)| lo.cmp(hi).is_gt()) {
                    bail!("{s:?}: lower bound exceeds upper bound");
                }
                Constraint::Range(lo, hi)
            }
            "len" => {
                let (lo, hi) = bounds(arg)?;
                let num = |x: Option<String>| -> Result<Option<usize>> {
                    x.map(|x| x.parse::<usize>().map_err(|_| anyhow::anyhow!("{s:?}: {x:?} is not a length"))).transpose()
                };
                let (lo, hi) = (num(lo)?, num(hi)?);
                if lo.zip(hi).is_some_and(|(lo, hi)| lo > hi) {
                    bail!("{s:?}: lower length exceeds upper length");
                }
                Constraint::Len(lo, hi)
            }
            "unique" => Constraint::Unique(arg.split(',').map(str::trim).filter(|x| !x.is_empty()).map(str::to_string).collect()),
            "enum" if !arg.is_empty() => Constraint::Enum(arg.split(',').map(|x| x.trim().to_string()).collect()),
            "format" => Constraint::Format(match arg {
                "date" => Format::Date,
                "time" => Format::Time,
                "datetime" => Format::DateTime,
                "email" => Format::Email,
                "int" => Format::Int,
                "uuid" => Format::Uuid,
                "url" => Format::Url,
                "token" => Format::Token,
                _ => bail!("{s:?}: a format is one of date, time, datetime, email, int, uuid, url, token"),
            }),
            _ => bail!("{s:?}: a value constraint is range:a..b, len:a..b, enum:x,y, format:<f> or unique[:fields]"),
        })
    }

    /// Whether a value keeps to the constraint. Values of another kind (a
    /// list for `range`) do.
    pub fn holds(&self, v: &Value) -> bool {
        match (self, v) {
            (Constraint::Range(lo, hi), _) => match number(v) {
                Some(n) => lo.as_ref().is_none_or(|l| n.cmp(l).is_ge()) && hi.as_ref().is_none_or(|h| n.cmp(h).is_le()),
                None => !v.is_string(),
            },
            (Constraint::Len(lo, hi), Value::String(s)) => in_len(s.chars().count(), *lo, *hi),
            (Constraint::Len(lo, hi), Value::Array(a)) => in_len(a.len(), *lo, *hi),
            (Constraint::Enum(xs), Value::String(s)) => xs.contains(s),
            (Constraint::Enum(xs), x @ Value::Number(_)) => number(x).is_some_and(|n| xs.iter().filter_map(|s| Decimal::parse(s)).any(|x| n.cmp(&x).is_eq())),
            (Constraint::Format(f), Value::String(s)) => format_ok(*f, s),
            (Constraint::Unique(fields), Value::Array(a)) => {
                let mut seen = std::collections::BTreeSet::new();
                a.iter().all(|x| seen.insert(unique_key(x, fields)))
            }
            _ => true,
        }
    }

    /// A value that keeps to the constraint, close to `v`, chosen by `seed`.
    pub fn conform(&self, v: &Value, seed: u64) -> Value {
        if self.holds(v) {
            return v.clone();
        }
        match (self, v) {
            (Constraint::Range(lo, hi), _) => self.conform_range(v, lo.as_ref(), hi.as_ref()),
            (Constraint::Len(lo, hi), Value::String(s)) => {
                let mut t: String = s.chars().take(hi.unwrap_or(usize::MAX)).collect();
                t.extend(std::iter::repeat_n('a', lo.unwrap_or(0).saturating_sub(t.chars().count())));
                json!(t)
            }
            (Constraint::Len(lo, hi), Value::Array(a)) => {
                let mut a: Vec<Value> = a.iter().take(hi.unwrap_or(usize::MAX)).cloned().collect();
                while a.len() < lo.unwrap_or(0) {
                    a.push(a.last().cloned().unwrap_or(Value::Null));
                }
                Value::Array(a)
            }
            (Constraint::Enum(xs), Value::Number(_)) => {
                let numbers: Vec<_> = xs.iter().filter_map(|s| s.parse::<serde_json::Number>().ok()).map(Value::Number).filter(|v| self.holds(v)).collect();
                if numbers.is_empty() { json!(xs[(seed % xs.len() as u64) as usize]) } else { numbers[(seed % numbers.len() as u64) as usize].clone() }
            }
            (Constraint::Enum(xs), _) => json!(xs[(seed % xs.len() as u64) as usize]),
            (Constraint::Format(f), _) => json!(example(*f, seed)),
            (Constraint::Unique(fields), Value::Array(a)) => {
                let mut seen = std::collections::BTreeSet::new();
                Value::Array(a.iter().filter(|x| seen.insert(unique_key(x, fields))).cloned().collect())
            }
            (Constraint::Len(..) | Constraint::Unique(_), _) => v.clone(),
        }
    }

    fn conform_range(&self, value: &Value, lo: Option<&Decimal>, hi: Option<&Decimal>) -> Value {
        let original = number(value).unwrap_or_else(|| Decimal::parse("0").unwrap());
        let target = if let Some(lo) = lo.filter(|lo| original.cmp(lo).is_lt()) {
            lo
        } else if let Some(hi) = hi.filter(|hi| original.cmp(hi).is_gt()) {
            hi
        } else {
            &original
        };
        if value.is_string() {
            return json!(target.to_string());
        }
        if !value.as_number().is_some_and(serde_json::Number::is_f64) {
            for up in [true, false] {
                if let Some(integer) = target.rounded_integer(up)
                    && let Some(candidate) = integer_json(integer)
                    && self.holds(&candidate)
                {
                    return candidate;
                }
            }
        }
        if let Ok(float) = target.to_string().parse::<f64>() {
            for n in [float, float.next_up(), float.next_down()] {
                if n.is_finite() {
                    let candidate = json!(n);
                    if self.holds(&candidate) {
                        return candidate;
                    }
                }
            }
        }
        json!(target.to_string())
    }
}

fn integer_json(value: i128) -> Option<Value> {
    i64::try_from(value).map(Value::from).ok().or_else(|| u64::try_from(value).map(Value::from).ok())
}

/// What makes a list element unique: the element, or its `fields`.
fn unique_key(x: &Value, fields: &[String]) -> String {
    let mut key = if fields.is_empty() { x.clone() } else { json!(fields.iter().map(|field| (x.get(field).is_some(), x.get(field))).collect::<Vec<_>>()) };
    key.sort_all_objects();
    key.to_string()
}

fn in_len(n: usize, lo: Option<usize>, hi: Option<usize>) -> bool {
    lo.is_none_or(|l| n >= l) && hi.is_none_or(|h| n <= h)
}

fn number(v: &Value) -> Option<Decimal> {
    match v {
        Value::Number(n) => Decimal::parse(&n.to_string()),
        Value::String(s) => Decimal::parse(s),
        _ => None,
    }
}

pub(crate) fn format_ok(f: Format, s: &str) -> bool {
    let digits = |x: &str, n: usize| x.len() == n && x.bytes().all(|b| b.is_ascii_digit());
    let date = |x: &str| {
        let p: Vec<&str> = x.split('-').collect();
        p.len() == 3
            && digits(p[0], 4)
            && p[0] != "0000"
            && digits(p[1], 2)
            && digits(p[2], 2)
            && crate::wasi::parse_datetime(&format!("{x}T00:00:00")).is_some_and(|t| crate::wasi::format_datetime(t).0 == x)
    };
    let time = |x: &str| {
        let p: Vec<&str> = x.split(':').collect();
        (p.len() == 2 || p.len() == 3)
            && p.iter().all(|q| digits(q, 2))
            && p[0].parse::<u8>().is_ok_and(|h| h < 24)
            && p[1..].iter().all(|q| q.parse::<u8>().is_ok_and(|m| m < 60))
    };
    match f {
        Format::Date => date(s),
        Format::Time => time(s),
        Format::DateTime => s.split_once('T').is_some_and(|(d, t)| date(d) && time(t)),
        Format::Email => s.split_once('@').is_some_and(|(a, b)| !a.is_empty() && b.contains('.') && !s.contains(char::is_whitespace)),
        Format::Int => {
            let digits = s.strip_prefix('-').unwrap_or(s);
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        Format::Uuid => uuid_ok(s),
        Format::Url => url::Url::parse(s).is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some()),
        Format::Token => !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
    }
}

pub(crate) fn uuid_ok(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() })
}

fn example(f: Format, seed: u64) -> String {
    let day = 1 + seed % 28;
    let month = 1 + (seed / 28) % 12;
    match f {
        Format::Date => format!("2026-{month:02}-{day:02}"),
        Format::Time => format!("{:02}:{:02}", seed % 24, (seed / 24) % 60),
        Format::DateTime => format!("2026-{month:02}-{day:02}T{:02}:{:02}:00", seed % 24, (seed / 24) % 60),
        Format::Email => format!("user{}@mail.example", seed % 1000),
        Format::Int => (seed % 1000).to_string(),
        Format::Uuid => format!("00000000-0000-4000-8000-{:012x}", seed & 0x0000_ffff_ffff_ffff),
        Format::Url => format!("https://app.example/p{}", seed % 100),
        Format::Token => ["GET", "HEAD", "POST", "PUT", "DELETE"][(seed % 5) as usize].to_string(),
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = |lo: Option<String>, hi: Option<String>| format!("{}..{}", lo.unwrap_or_default(), hi.unwrap_or_default());
        match self {
            Constraint::Range(lo, hi) => write!(f, "range:{}", b(lo.as_ref().map(ToString::to_string), hi.as_ref().map(ToString::to_string))),
            Constraint::Len(lo, hi) => write!(f, "len:{}", b(lo.map(|x| x.to_string()), hi.map(|x| x.to_string()))),
            Constraint::Enum(xs) => write!(f, "enum:{}", xs.join(",")),
            Constraint::Unique(xs) if xs.is_empty() => write!(f, "unique"),
            Constraint::Unique(xs) => write!(f, "unique:{}", xs.join(",")),
            Constraint::Format(x) => write!(
                f,
                "format:{}",
                match x {
                    Format::Date => "date",
                    Format::Time => "time",
                    Format::DateTime => "datetime",
                    Format::Email => "email",
                    Format::Int => "int",
                    Format::Uuid => "uuid",
                    Format::Url => "url",
                    Format::Token => "token",
                }
            ),
        }
    }
}

impl Serialize for Constraint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Constraint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Constraint::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Makes the values at each path keep to its constraint (paths as in
/// result labels: through lists, options and `ok`).
pub fn conform_at(v: &mut Value, constraints: &[(String, Constraint)], seed: u64) {
    for (p, c) in constraints {
        let segs: Vec<&str> = p.split('.').filter(|s| !s.is_empty()).collect();
        let mut n = 0u64;
        // A `len` or `unique` on a list applies to the list, not its elements.
        conform_node(v, &segs, c, seed, &mut n);
    }
}

fn conform_node(v: &mut Value, segs: &[&str], c: &Constraint, seed: u64, n: &mut u64) {
    if segs.is_empty()
        && let (Constraint::Len(..) | Constraint::Unique(_), Value::Array(_)) = (c, &v)
    {
        *v = c.conform(v, seed);
        return;
    }
    match v {
        Value::Array(a) => a.iter_mut().for_each(|x| conform_node(x, segs, c, seed, n)),
        Value::Object(o) if o.len() == 1 && o.contains_key("ok") && segs.first() != Some(&"ok") => {
            conform_node(o.get_mut("ok").expect("checked"), segs, c, seed, n)
        }
        Value::Object(o) if o.len() == 1 && o.contains_key("some") && segs.first() != Some(&"some") => {
            conform_node(o.get_mut("some").expect("checked"), segs, c, seed, n)
        }
        Value::Object(o) if o.len() == 1 && (o.contains_key("err") || o.contains_key("none")) => {}
        Value::Object(o) if !segs.is_empty() => {
            if let Some(x) = o.get_mut(segs[0]) {
                conform_node(x, &segs[1..], c, seed, n)
            }
        }
        Value::Null | Value::Object(_) => {}
        x => {
            *n += 1;
            *x = c.conform(x, seed.wrapping_add(*n));
        }
    }
}

/// The request fields that break their constraint: (path, constraint, value).
pub fn broken_request(args: &[Value], m: &crate::manifest::Manifest) -> Vec<(String, String, Value)> {
    let Some(e) = &m.entry else { return Vec::new() };
    let Some(req) = args.first() else { return Vec::new() };
    e.values
        .iter()
        .filter_map(|(p, c)| {
            let v = crate::harness::field(req, p)?;
            (!c.holds(v)).then(|| (p.clone(), c.to_string(), v.clone()))
        })
        .collect()
}

/// The request fields of a run that break their constraint, and the inputs
/// Shopify would not send: findings of such a run are only hints.
pub fn broken_request_for(record: &crate::record::RunRecord, m: &crate::manifest::Manifest) -> Vec<(String, String, Value)> {
    let mut out = if m.entry.as_ref().is_some_and(|entry| crate::harness::fn_key_eq(&entry.export, &record.spec.export)) {
        broken_request(&record.spec.args, m)
    } else {
        Vec::new()
    };
    // Shopify does not run a function on an input over its limit.
    if let Some(s) = record.shopify.as_ref().filter(|s| s.input_refused()) {
        out.push(("input".into(), format!("at most {} bytes (Shopify's input limit for this cart)", s.input_limit), Value::from(s.input_bytes)));
    }
    // Nor does it send a negative price or a quantity of 0.
    if record.shopify.is_some()
        && let Some(f) = m.shopify.as_ref().and_then(|s| s.function.as_ref())
    {
        out.extend(f.unsendable(&record.spec.export, &record.spec.args).into_iter().take(5));
    }
    out
}

/// Makes the request's constrained fields keep to their constraints.
pub fn conform_request(args: &mut [Value], m: &crate::manifest::Manifest, seed: u64) {
    let Some(e) = &m.entry else { return };
    let Some(req) = args.first_mut() else { return };
    for (i, (p, c)) in e.values.iter().enumerate() {
        if let Some(slot) = crate::harness::field_mut(req, p) {
            *slot = c.conform(slot, seed.wrapping_add(i as u64));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_record_uniqueness_ignores_json_object_key_order() {
        let c = Constraint::parse("unique").unwrap();
        let rows = json!([{"id":1,"name":"A"},{"name":"A","id":1}]);
        assert!(!c.holds(&rows));
        assert_eq!(c.conform(&rows, 1), json!([{"id":1,"name":"A"}]));
    }

    #[test]
    fn range_constraints_keep_exact_integer_bounds_when_checked_and_serialized() {
        let text = "range:9007199254740993..9007199254740993";
        let c = Constraint::parse(text).unwrap();
        assert!(!c.holds(&json!(9007199254740992u64)));
        assert!(c.holds(&json!(9007199254740993u64)));
        assert_eq!(c.to_string(), text);
        let repaired = c.conform(&json!(0), 1);
        assert_eq!(repaired, json!(9007199254740993u64));
        let max = Constraint::parse("range:18446744073709551615..18446744073709551615").unwrap();
        assert_eq!(max.conform(&json!(0), 1), json!(u64::MAX));
    }

    #[test]
    fn fractional_range_repairs_stay_inside_the_declared_range() {
        for (domain, value) in [("range:0.1..0.2", json!("0")), ("range:0.1..0.2", json!(0.0)), ("range:1.2..2.2", json!(0)), ("range:-2.2..-1.2", json!(0))] {
            let c = Constraint::parse(domain).unwrap();
            let repaired = c.conform(&value, 1);
            assert!(c.holds(&repaired), "{domain} repaired {value} to {repaired}");
        }
    }

    #[test]
    fn numeric_enums_repair_unsigned_and_fractional_values() {
        for (domain, expected) in [("enum:18446744073709551615", json!(u64::MAX)), ("enum:0.25", json!(0.25))] {
            let c = Constraint::parse(domain).unwrap();
            assert_eq!(c.conform(&json!(0), 1), expected);
        }
    }

    #[test]
    fn impossible_or_nonfinite_bounds_are_rejected() {
        for text in ["range:10..1", "range:NaN..1", "range:1..NaN", "range:-inf..1", "range:1..inf", "len:10..1"] {
            assert!(Constraint::parse(text).is_err(), "accepted {text}");
        }
        for text in ["range:1..1", "range:..", "range:-1.5..2.5", "range:1e999..1e1000", "len:0..0", "len:.."] {
            assert!(Constraint::parse(text).is_ok(), "rejected {text}");
        }
    }

    #[test]
    fn nonfinite_text_is_not_a_number_in_a_value_domain() {
        for domain in ["range:..", "range:1..", "range:..10"] {
            let c = Constraint::parse(domain).unwrap();
            for value in ["NaN", "inf", "-inf"] {
                assert!(!c.holds(&json!(value)), "{value} satisfies {domain}");
                assert!(c.holds(&c.conform(&json!(value), 0)), "could not repair {value} for {domain}");
            }
        }
    }

    #[test]
    fn constraints() {
        let r = Constraint::parse("range:1..31").unwrap();
        assert!(r.holds(&json!(5)) && r.holds(&json!("31")) && !r.holds(&json!(0)) && !r.holds(&json!("400")) && !r.holds(&json!("x")));
        assert_eq!(r.conform(&json!(400), 0), json!(31));
        assert_eq!(r.conform(&json!("-3"), 0), json!("1"));
        assert_eq!(r.to_string(), "range:1..31");
        let l = Constraint::parse("len:..3").unwrap();
        assert_eq!(l.conform(&json!("abcdef"), 0), json!("abc"));
        assert_eq!(l.conform(&json!([1, 2, 3, 4]), 0), json!([1, 2, 3]));
        let e = Constraint::parse("enum:open,closed").unwrap();
        assert!(e.holds(&json!("open")) && !e.holds(&json!("x")));
        let d = Constraint::parse("format:date").unwrap();
        assert!(d.holds(&json!("2028-02-29")) && !d.holds(&json!("2027-02-29")) && !d.holds(&json!("today")));
        assert!(d.holds(&d.conform(&json!("x"), 7)));
        assert!(Constraint::parse("range:a..b").is_err() && Constraint::parse("between:1,2").is_err());
        let mut v = json!({"ok": [{"score": 500}, {"score": 7}]});
        conform_at(&mut v, &[("score".into(), Constraint::parse("range:0..100").unwrap())], 1);
        assert_eq!(v, json!({"ok": [{"score": 100}, {"score": 7}]}));
        let mut v = json!([1, 2, 3, 4, 5]);
        conform_at(&mut v, &[(String::new(), Constraint::parse("len:..2").unwrap())], 1);
        assert_eq!(v, json!([1, 2]));
        // A unique key: the second booking of pod 1 at 9 goes.
        let u = Constraint::parse("unique:pod,hour").unwrap();
        assert_eq!(u.to_string(), "unique:pod,hour");
        let mut v = json!({"ok": [{"pod": 1, "hour": 9, "by": "a"}, {"pod": 1, "hour": 9, "by": "b"}, {"pod": 2, "hour": 9, "by": "a"}]});
        assert!(!u.holds(&v["ok"]));
        conform_at(&mut v, &[(String::new(), u)], 1);
        assert_eq!(v, json!({"ok": [{"pod": 1, "hour": 9, "by": "a"}, {"pod": 2, "hour": 9, "by": "a"}]}));
        assert!(Constraint::parse("unique").unwrap().holds(&json!([1, 2])) && !Constraint::parse("unique").unwrap().holds(&json!([1, 1])));
    }
}
