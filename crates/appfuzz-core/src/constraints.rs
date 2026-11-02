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

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub enum Constraint {
    Range(Option<f64>, Option<f64>),
    Len(Option<usize>, Option<usize>),
    Enum(Vec<String>),
    Format(Format),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Date,
    Time,
    DateTime,
    Email,
    Int,
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
                let num = |x: Option<String>| -> Result<Option<f64>> {
                    x.map(|x| x.parse::<f64>().map_err(|_| anyhow::anyhow!("{s:?}: {x:?} is not a number"))).transpose()
                };
                Constraint::Range(num(lo)?, num(hi)?)
            }
            "len" => {
                let (lo, hi) = bounds(arg)?;
                let num = |x: Option<String>| -> Result<Option<usize>> {
                    x.map(|x| x.parse::<usize>().map_err(|_| anyhow::anyhow!("{s:?}: {x:?} is not a length"))).transpose()
                };
                Constraint::Len(num(lo)?, num(hi)?)
            }
            "enum" if !arg.is_empty() => Constraint::Enum(arg.split(',').map(|x| x.trim().to_string()).collect()),
            "format" => Constraint::Format(match arg {
                "date" => Format::Date,
                "time" => Format::Time,
                "datetime" => Format::DateTime,
                "email" => Format::Email,
                "int" => Format::Int,
                _ => bail!("{s:?}: a format is one of date, time, datetime, email, int"),
            }),
            _ => bail!("{s:?}: a value constraint is range:a..b, len:a..b, enum:x,y or format:<f>"),
        })
    }

    /// Whether a value keeps to the constraint. Values of another kind (a
    /// list for `range`) do.
    pub fn holds(&self, v: &Value) -> bool {
        match (self, v) {
            (Constraint::Range(lo, hi), _) => match number(v) {
                Some(n) => lo.is_none_or(|l| n >= l) && hi.is_none_or(|h| n <= h),
                None => !v.is_string(),
            },
            (Constraint::Len(lo, hi), Value::String(s)) => in_len(s.chars().count(), *lo, *hi),
            (Constraint::Len(lo, hi), Value::Array(a)) => in_len(a.len(), *lo, *hi),
            (Constraint::Enum(xs), Value::String(s)) => xs.contains(s),
            (Constraint::Enum(xs), x @ Value::Number(_)) => xs.contains(&x.to_string()),
            (Constraint::Format(f), Value::String(s)) => format_ok(*f, s),
            _ => true,
        }
    }

    /// A value that keeps to the constraint, close to `v`, chosen by `seed`.
    pub fn conform(&self, v: &Value, seed: u64) -> Value {
        if self.holds(v) {
            return v.clone();
        }
        match (self, v) {
            (Constraint::Range(lo, hi), _) => {
                let n = number(v).unwrap_or(lo.unwrap_or(0.0)).clamp(lo.unwrap_or(f64::MIN), hi.unwrap_or(f64::MAX));
                let n = if v.as_f64().is_some_and(|x| x.fract() != 0.0) { n } else { n.round() };
                match v {
                    Value::String(_) => json!(fmt_num(n)),
                    Value::Number(x) if x.is_f64() => json!(n),
                    _ => json!(n as i64),
                }
            }
            (Constraint::Len(lo, hi), Value::String(s)) => {
                let mut t: String = s.chars().take(hi.unwrap_or(usize::MAX)).collect();
                while t.chars().count() < lo.unwrap_or(0) {
                    t.push('a');
                }
                json!(t)
            }
            (Constraint::Len(lo, hi), Value::Array(a)) => {
                let mut a: Vec<Value> = a.iter().take(hi.unwrap_or(usize::MAX)).cloned().collect();
                while a.len() < lo.unwrap_or(0) && !a.is_empty() {
                    a.push(a[a.len() - 1].clone());
                }
                Value::Array(a)
            }
            (Constraint::Enum(xs), Value::Number(_)) => xs[(seed % xs.len() as u64) as usize].parse::<i64>().map(Value::from).unwrap_or(v.clone()),
            (Constraint::Enum(xs), _) => json!(xs[(seed % xs.len() as u64) as usize]),
            (Constraint::Format(f), _) => json!(example(*f, seed)),
            (Constraint::Len(..), _) => v.clone(),
        }
    }
}

fn in_len(n: usize, lo: Option<usize>, hi: Option<usize>) -> bool {
    lo.is_none_or(|l| n >= l) && hi.is_none_or(|h| n <= h)
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 { format!("{}", n as i64) } else { n.to_string() }
}

fn format_ok(f: Format, s: &str) -> bool {
    let digits = |x: &str, n: usize| x.len() == n && x.bytes().all(|b| b.is_ascii_digit());
    let date = |x: &str| {
        let p: Vec<&str> = x.split('-').collect();
        p.len() == 3
            && digits(p[0], 4)
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
        Format::Int => !s.is_empty() && s.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()) && !s.trim_start_matches('-').is_empty(),
    }
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
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = |lo: Option<String>, hi: Option<String>| format!("{}..{}", lo.unwrap_or_default(), hi.unwrap_or_default());
        match self {
            Constraint::Range(lo, hi) => write!(f, "range:{}", b(lo.map(fmt_num), hi.map(fmt_num))),
            Constraint::Len(lo, hi) => write!(f, "len:{}", b(lo.map(|x| x.to_string()), hi.map(|x| x.to_string()))),
            Constraint::Enum(xs) => write!(f, "enum:{}", xs.join(",")),
            Constraint::Format(x) => write!(
                f,
                "format:{}",
                match x {
                    Format::Date => "date",
                    Format::Time => "time",
                    Format::DateTime => "datetime",
                    Format::Email => "email",
                    Format::Int => "int",
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
        // A `len` on a list applies to the list, not its elements.
        conform_node(v, &segs, c, seed, &mut n);
    }
}

fn conform_node(v: &mut Value, segs: &[&str], c: &Constraint, seed: u64, n: &mut u64) {
    if segs.is_empty()
        && let (Constraint::Len(..), Value::Array(_)) = (c, &v)
    {
        *v = c.conform(v, seed);
        return;
    }
    match v {
        Value::Array(a) => a.iter_mut().for_each(|x| conform_node(x, segs, c, seed, n)),
        Value::Object(o) if o.len() == 1 && o.contains_key("ok") && segs.first() != Some(&"ok") => {
            conform_node(o.get_mut("ok").expect("checked"), segs, c, seed, n)
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
    }
}
