//! WIT values as JSON, and values generated from WIT types.
//!
//! JSON shape (both directions):
//! - records: objects with the WIT field names (`item-id`; `item_id` is
//!   accepted on input)
//! - lists, tuples, fixed-length lists: arrays; maps: arrays of `[k, v]`
//! - `option`: `null` or `{"some": v}` (a bare non-null value is accepted on
//!   input)
//! - `result`: `{"ok": v}` / `{"err": v}` (`null` payload for no type)
//! - variants: `"case"` or `{"case": payload}`; enums: `"case"`
//! - flags: arrays of names; chars: one-character strings

use anyhow::{Context, Result, anyhow, bail};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use wasmtime::component::{Type, Val};

/// For fields where a missing value and an explicit JSON null are distinct.
/// `default` on the field handles absence; this runs only for a present field.
pub(crate) fn present_json_value<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// The value inside an option argument: `{"some": v}` is `v`, `null` is none.
pub fn some(v: &Value) -> Option<&Value> {
    match v {
        Value::Null => None,
        Value::Object(m) if m.len() == 1 && m.contains_key("some") => some(&m["some"]),
        _ => Some(v),
    }
}

/// The length of `v` as compact JSON, without building the text.
pub fn json_len<T: Serialize + ?Sized>(v: &T) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    let _ = serde_json::to_writer(&mut c, v);
    c.0
}

/// A total order on JSON values, as a database sorts a column: null, then
/// booleans, numbers by value, strings by bytes, then lists and records.
pub fn cmp_json(a: &Value, b: &Value) -> std::cmp::Ordering {
    fn rank(v: &Value) -> u8 {
        match v {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Number(_) => 2,
            Value::String(_) => 3,
            Value::Array(_) => 4,
            Value::Object(_) => 5,
        }
    }
    let exact = |n: &serde_json::Number| n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from));
    match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        (Value::Number(x), Value::Number(y)) => match (exact(x), exact(y)) {
            (Some(x), Some(y)) => x.cmp(&y),
            _ => x.as_f64().unwrap_or(f64::NAN).total_cmp(&y.as_f64().unwrap_or(f64::NAN)),
        },
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Array(_), Value::Array(_)) | (Value::Object(_), Value::Object(_)) => a.to_string().cmp(&b.to_string()),
        _ => rank(a).cmp(&rank(b)),
    }
}

pub fn val_to_json(v: &Val) -> Value {
    val_to_json_with(v, &|s| json!(s))
}

/// `val_to_json` with strings converted by `text`.
pub fn val_to_json_with(v: &Val, text: &impl Fn(&str) -> Value) -> Value {
    let conv = |v: &Val| val_to_json_with(v, text);
    match v {
        Val::Bool(b) => json!(b),
        Val::S8(n) => json!(n),
        Val::U8(n) => json!(n),
        Val::S16(n) => json!(n),
        Val::U16(n) => json!(n),
        Val::S32(n) => json!(n),
        Val::U32(n) => json!(n),
        Val::S64(n) => json!(n),
        Val::U64(n) => json!(n),
        Val::Float32(f) => float_json(*f as f64),
        Val::Float64(f) => float_json(*f),
        Val::Char(c) => json!(c.to_string()),
        Val::String(s) => text(s),
        Val::List(items) | Val::Tuple(items) | Val::FixedLengthList(items) => Value::Array(items.iter().map(conv).collect()),
        Val::Map(pairs) => Value::Array(pairs.iter().map(|(k, v)| json!([conv(k), conv(v)])).collect()),
        Val::Record(fields) => Value::Object(fields.iter().map(|(k, v)| (k.clone(), conv(v))).collect::<Map<_, _>>()),
        Val::Variant(case, None) => json!(case),
        Val::Variant(case, Some(p)) => json!({ case: conv(p) }),
        Val::Enum(case) => json!(case),
        Val::Option(None) => Value::Null,
        Val::Option(Some(v)) => json!({ "some": conv(v) }),
        Val::Result(Ok(v)) => json!({ "ok": v.as_ref().map(|v| conv(v)).unwrap_or(Value::Null) }),
        Val::Result(Err(v)) => json!({ "err": v.as_ref().map(|v| conv(v)).unwrap_or(Value::Null) }),
        Val::Flags(names) => json!(names),
        Val::Resource(_) => json!("<resource>"),
        Val::Future(_) => json!("<future>"),
        Val::Stream(_) => json!("<stream>"),
        Val::ErrorContext(_) => json!("<error-context>"),
    }
}

fn float_json(f: f64) -> Value {
    serde_json::Number::from_f64(f).map(Value::Number).unwrap_or_else(|| json!(f.to_string()))
}

pub fn json_to_val(v: &Value, ty: &Type) -> Result<Val> {
    Ok(match ty {
        Type::Bool => Val::Bool(v.as_bool().ok_or_else(|| expected("bool", v))?),
        Type::S8 => Val::S8(int(v)?.try_into().context("out of range for s8")?),
        Type::U8 => Val::U8(uint(v)?.try_into().context("out of range for u8")?),
        Type::S16 => Val::S16(int(v)?.try_into().context("out of range for s16")?),
        Type::U16 => Val::U16(uint(v)?.try_into().context("out of range for u16")?),
        Type::S32 => Val::S32(int(v)?.try_into().context("out of range for s32")?),
        Type::U32 => Val::U32(uint(v)?.try_into().context("out of range for u32")?),
        Type::S64 => Val::S64(int(v)?),
        Type::U64 => Val::U64(uint(v)?),
        Type::Float32 => Val::Float32(float(v)? as f32),
        Type::Float64 => Val::Float64(float(v)?),
        Type::Char => {
            let s = v.as_str().ok_or_else(|| expected("char (one-character string)", v))?;
            let mut chars = s.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => Val::Char(c),
                _ => bail!("expected exactly one character, got {s:?}"),
            }
        }
        Type::String => Val::String(v.as_str().ok_or_else(|| expected("string", v))?.to_string()),
        Type::List(l) => {
            let inner = l.ty();
            let items = v.as_array().ok_or_else(|| expected("array", v))?;
            Val::List(items.iter().enumerate().map(|(i, x)| json_to_val(x, &inner).with_context(|| format!("[{i}]"))).collect::<Result<_>>()?)
        }
        // A stream is written as the list of its items and a future as its
        // value; the harness turns them into a real stream or future.
        Type::Stream(s) if s.ty().is_some() => {
            let inner = s.ty().expect("checked");
            let items = v.as_array().ok_or_else(|| expected("array (stream)", v))?;
            Val::List(items.iter().enumerate().map(|(i, x)| json_to_val(x, &inner).with_context(|| format!("[{i}]"))).collect::<Result<_>>()?)
        }
        Type::Future(f) if f.ty().is_some() => json_to_val(v, &f.ty().expect("checked"))?,
        Type::FixedLengthList(l) => {
            let inner = l.ty();
            let items = v.as_array().ok_or_else(|| expected("array", v))?;
            if items.len() != l.len() as usize {
                bail!("expected {} items, got {}", l.len(), items.len());
            }
            Val::FixedLengthList(items.iter().map(|x| json_to_val(x, &inner)).collect::<Result<_>>()?)
        }
        Type::Map(m) => {
            let (kt, vt) = (m.key(), m.value());
            let pairs = match v {
                Value::Object(o) => o.iter().map(|(k, x)| Ok((json_to_val(&json!(k), &kt)?, json_to_val(x, &vt)?))).collect::<Result<_>>()?,
                Value::Array(a) => a
                    .iter()
                    .map(|p| {
                        let p = p.as_array().filter(|p| p.len() == 2).ok_or_else(|| expected("[key, value]", p))?;
                        Ok((json_to_val(&p[0], &kt)?, json_to_val(&p[1], &vt)?))
                    })
                    .collect::<Result<_>>()?,
                _ => bail!("expected a map as object or array of pairs, got {v}"),
            };
            Val::Map(pairs)
        }
        Type::Record(r) => {
            let obj = v.as_object().ok_or_else(|| expected("object (record)", v))?;
            let mut fields = Vec::new();
            for f in r.fields() {
                let value = obj.get(f.name).or_else(|| obj.get(&f.name.replace('-', "_"))).ok_or_else(|| anyhow!("missing field {:?}", f.name))?;
                fields.push((f.name.to_string(), json_to_val(value, &f.ty).with_context(|| format!(".{}", f.name))?));
            }
            Val::Record(fields)
        }
        Type::Tuple(t) => {
            let items = v.as_array().ok_or_else(|| expected("array (tuple)", v))?;
            let types: Vec<Type> = t.types().collect();
            if items.len() != types.len() {
                bail!("expected a tuple of {}, got {} items", types.len(), items.len());
            }
            Val::Tuple(items.iter().zip(&types).map(|(x, t)| json_to_val(x, t)).collect::<Result<_>>()?)
        }
        Type::Variant(var) => {
            let (case, payload) = single_case(v)?;
            let c = var.cases().find(|c| c.name == case).ok_or_else(|| anyhow!("unknown variant case {case:?}"))?;
            match (&c.ty, payload) {
                (None, _) => Val::Variant(case, None),
                (Some(t), Some(p)) => Val::Variant(case, Some(Box::new(json_to_val(p, t)?))),
                (Some(_), None) => bail!("variant case {case:?} needs a payload"),
            }
        }
        Type::Enum(e) => {
            let s = v.as_str().ok_or_else(|| expected("string (enum)", v))?;
            if !e.names().any(|n| n == s) {
                bail!("unknown enum case {s:?}; one of {}", e.names().collect::<Vec<_>>().join(", "));
            }
            Val::Enum(s.to_string())
        }
        Type::Option(o) => match v {
            Value::Null => Val::Option(None),
            Value::Object(m) if m.len() == 1 && m.contains_key("some") => Val::Option(Some(Box::new(json_to_val(&m["some"], &o.ty())?))),
            other => Val::Option(Some(Box::new(json_to_val(other, &o.ty())?))),
        },
        Type::Result(r) => {
            let (case, payload) = single_case(v)?;
            let null = Value::Null;
            let payload = payload.unwrap_or(&null);
            match case.as_str() {
                "ok" => Val::Result(Ok(match r.ok() {
                    Some(t) => Some(Box::new(json_to_val(payload, &t).context("ok")?)),
                    None => None,
                })),
                "err" => Val::Result(Err(match r.err() {
                    Some(t) => Some(Box::new(json_to_val(payload, &t).context("err")?)),
                    None => None,
                })),
                other => bail!("expected {{\"ok\": …}} or {{\"err\": …}}, got case {other:?}"),
            }
        }
        Type::Flags(f) => {
            let names = v.as_array().ok_or_else(|| expected("array of flag names", v))?;
            let mut out = Vec::new();
            for n in names {
                let n = n.as_str().ok_or_else(|| expected("flag name", n))?;
                if !f.names().any(|x| x == n) {
                    bail!("unknown flag {n:?}");
                }
                out.push(n.to_string());
            }
            Val::Flags(out)
        }
        // A placeholder: the harness gives the guest a fresh handle here.
        Type::Own(_) => Val::Bool(false),
        Type::Borrow(_) | Type::Future(_) | Type::Stream(_) | Type::ErrorContext => {
            bail!("appfuzz can't simulate resources, futures or streams yet ({})", crate::wit::type_str(ty))
        }
    })
}

fn single_case(v: &Value) -> Result<(String, Option<&Value>)> {
    match v {
        Value::String(s) => Ok((s.clone(), None)),
        Value::Object(m) if m.len() == 1 => {
            let (k, p) = m.iter().next().expect("one entry");
            Ok((k.clone(), Some(p)))
        }
        _ => bail!("expected \"case\" or {{\"case\": payload}}, got {v}"),
    }
}

fn expected(what: &str, got: &Value) -> anyhow::Error {
    let mut s = got.to_string();
    if s.len() > 80 {
        s.truncate(s.floor_char_boundary(80));
        s.push('…');
    }
    anyhow!("expected {what}, got {s}")
}

fn int(v: &Value) -> Result<i64> {
    v.as_i64().ok_or_else(|| expected("integer", v))
}
fn uint(v: &Value) -> Result<u64> {
    v.as_u64().ok_or_else(|| expected("non-negative integer", v))
}
fn float(v: &Value) -> Result<f64> {
    v.as_f64().ok_or_else(|| expected("number", v))
}

/// How to generate values.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GenOpts {
    /// Length of every generated list (default: 0 to 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_len: Option<usize>,
    /// Kind of strings: `words` (default), `empty`, `long`, `unicode`, `html`,
    /// `utf8-2`/`utf8-3`/`utf8-4`/`utf8-3o` (40 chars of that byte width,
    /// `o`: after one ASCII byte), `=text` (always that text),
    /// `canary` (unique markers), `canary-sink` (markers that also carry
    /// `../;$(x)`), `edge` (a mix of the above).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<String>,
    /// Numbers: `small` (default), `edge` (0, 1, max, min), `=13` (fixed),
    /// or `cast:-1` (wrap an integer constant to the WIT integer width).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub numbers: Option<String>,
    /// For `result`: `ok` (default), `err`, `mixed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<String>,
    /// For `option`: unset (mostly some), `some` (always), `none`, `mixed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

impl GenOpts {
    pub fn validate(&self) -> Result<()> {
        if let Some(mode) = self.numbers.as_deref() {
            let fixed =
                mode.strip_prefix('=').is_some_and(|n| crate::value_contract::Decimal::parse(n).is_some() && n.trim().parse::<f64>().is_ok_and(f64::is_finite));
            let cast = mode.strip_prefix("cast:").is_some_and(|n| fixed_integer(n).is_some());
            if !matches!(mode, "small" | "edge") && !fixed && !cast {
                bail!("unknown number generation mode {mode:?}: use small, edge, =NUMBER (finite) or cast:INTEGER");
            }
        }
        for (name, mode, choices) in [
            (
                "strings",
                self.strings.as_deref(),
                &["words", "empty", "long", "unicode", "html", "utf8-2", "utf8-3", "utf8-4", "utf8-3o", "canary", "canary-sink", "edge"][..],
            ),
            ("results", self.results.as_deref(), &["ok", "err", "mixed"][..]),
            ("options", self.options.as_deref(), &["some", "none", "mixed"][..]),
        ] {
            if let Some(mode) = mode
                && !choices.contains(&mode)
                && !(name == "strings" && mode.starts_with('='))
            {
                bail!("unknown {name} generation mode {mode:?}");
            }
        }
        Ok(())
    }

    /// Check fixed values against the types this configuration may generate.
    pub fn validate_for_type(&self, ty: &Type) -> Result<()> {
        self.validate()?;
        let Some(text) = self.numbers.as_deref().and_then(|n| n.strip_prefix('=')).map(str::trim) else { return Ok(()) };
        self.fixed_fits(ty, text)
    }

    fn fixed_fits(&self, ty: &Type, text: &str) -> Result<()> {
        match ty {
            Type::Float32 => {
                if !text.parse::<f32>()?.is_finite() {
                    bail!("fixed number {text:?} overflows WIT f32");
                }
            }
            Type::Float64 => {
                if !text.parse::<f64>()?.is_finite() {
                    bail!("fixed number {text:?} overflows WIT f64");
                }
            }
            Type::S8 | Type::U8 | Type::S16 | Type::U16 | Type::S32 | Type::U32 | Type::S64 | Type::U64 => {
                let n = fixed_integer(text).with_context(|| format!("fixed number {text:?} is not a representable WIT integer"))?;
                let value = if let Ok(n) = i64::try_from(n) { json!(n) } else { json!(u64::try_from(n)?) };
                json_to_val(&value, ty).with_context(|| format!("fixed number {text:?} cannot fit {ty:?}"))?;
            }
            Type::List(l) if self.list_len != Some(0) => self.fixed_fits(&l.ty(), text)?,
            Type::FixedLengthList(l) if l.len() > 0 => self.fixed_fits(&l.ty(), text)?,
            Type::Map(m) if self.list_len != Some(0) => {
                self.fixed_fits(&m.key(), text)?;
                self.fixed_fits(&m.value(), text)?;
            }
            Type::Tuple(t) => t.types().try_for_each(|t| self.fixed_fits(&t, text))?,
            Type::Record(r) => r.fields().try_for_each(|f| self.fixed_fits(&f.ty, text).with_context(|| format!("field {}", f.name)))?,
            Type::Variant(v) => v.cases().filter_map(|c| c.ty).try_for_each(|t| self.fixed_fits(&t, text))?,
            Type::Option(o) if self.options.as_deref() != Some("none") => self.fixed_fits(&o.ty(), text)?,
            Type::Result(r) => {
                let mode = self.results.as_deref().unwrap_or("ok");
                if mode != "err"
                    && let Some(t) = r.ok()
                {
                    self.fixed_fits(&t, text)?;
                }
                if mode != "ok"
                    && let Some(t) = r.err()
                {
                    self.fixed_fits(&t, text)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn fixed_integer(text: &str) -> Option<i128> {
    if let Ok(n) = text.parse() {
        return Some(n);
    }
    let number = crate::value_contract::Decimal::parse(text)?;
    let n = number.rounded_integer(true)?;
    number.cmp(&crate::value_contract::Decimal::parse(&n.to_string())?).is_eq().then_some(n)
}

const WORDS: &[&str] = &[
    "alpha", "birch", "cedar", "delta", "ember", "fjord", "grove", "harbor", "iris", "juniper", "kestrel", "linden", "maple", "north", "orchid", "pine",
    "quartz", "river", "sage", "tundra",
];
const UNICODE: &[&str] = &["Zoë", "東京", "مرحبا", "e\u{301}", "👩‍💻", "\u{200b}", "Ω≈ç√", "\u{feff}x"];
const HTML: &[&str] = &["<b>bold</b>", "<script>x</script>", "\"quoted\"", "a & b", "<img src=x>", "'single'"];

pub struct Generator {
    rng: StdRng,
    opts: GenOpts,
    canary: u32,
}

impl Generator {
    pub fn new(seed: u64, opts: GenOpts) -> Self {
        let seed = opts.seed.unwrap_or(seed);
        Generator { rng: StdRng::seed_from_u64(seed), opts, canary: 0 }
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.rng.random_range(0..items.len())]
    }

    pub fn gen_json(&mut self, ty: &Type) -> Value {
        val_to_json(&self.gen_val(ty))
    }

    pub fn gen_val(&mut self, ty: &Type) -> Val {
        let edge = self.opts.numbers.as_deref() == Some("edge");
        let fixed_text = self.opts.numbers.as_deref().and_then(|s| s.strip_prefix('=').or_else(|| s.strip_prefix("cast:"))).map(str::trim);
        let fixed = fixed_text.and_then(fixed_integer);
        macro_rules! num {
            ($t:ty, $v:ident) => {{
                let n: $t = if let Some(c) = fixed {
                    c as $t
                } else if edge {
                    *[0 as $t, 1 as $t, <$t>::MAX, <$t>::MIN].get(self.rng.random_range(0..4)).unwrap()
                } else {
                    self.rng.random_range(0..100u8) as $t
                };
                Val::$v(n)
            }};
        }
        macro_rules! float {
            ($t:ty, $v:ident) => {{
                let n: $t = if let Some(n) = fixed_text.and_then(|s| s.parse::<$t>().ok()) {
                    n
                } else if edge {
                    [0.0, 1.0, <$t>::MAX, <$t>::MIN][self.rng.random_range(0..4)]
                } else {
                    self.rng.random_range(0.0..100.0)
                };
                Val::$v(n)
            }};
        }
        match ty {
            Type::Bool => Val::Bool(self.rng.random_bool(0.5)),
            Type::S8 => num!(i8, S8),
            Type::U8 => num!(u8, U8),
            Type::S16 => num!(i16, S16),
            Type::U16 => num!(u16, U16),
            Type::S32 => num!(i32, S32),
            Type::U32 => num!(u32, U32),
            Type::S64 => num!(i64, S64),
            Type::U64 => num!(u64, U64),
            Type::Float32 => float!(f32, Float32),
            Type::Float64 => float!(f64, Float64),
            Type::Char => Val::Char(self.pick(&["a", "z", "é", "\u{0}"]).chars().next().unwrap()),
            Type::String => Val::String(self.gen_string()),
            Type::List(l) => {
                let n = self.list_len();
                let inner = l.ty();
                Val::List((0..n).map(|_| self.gen_val(&inner)).collect())
            }
            Type::Stream(s) if s.ty().is_some() => {
                let n = self.list_len();
                let inner = s.ty().expect("checked");
                Val::List((0..n).map(|_| self.gen_val(&inner)).collect())
            }
            Type::Future(f) if f.ty().is_some() => self.gen_val(&f.ty().expect("checked")),
            Type::FixedLengthList(l) => {
                let inner = l.ty();
                Val::FixedLengthList((0..l.len()).map(|_| self.gen_val(&inner)).collect())
            }
            Type::Map(m) => {
                let n = self.list_len();
                let (k, v) = (m.key(), m.value());
                Val::Map((0..n).map(|_| (self.gen_val(&k), self.gen_val(&v))).collect())
            }
            Type::Record(r) => Val::Record(r.fields().map(|f| (f.name.to_string(), self.gen_val(&f.ty))).collect()),
            Type::Tuple(t) => Val::Tuple(t.types().map(|t| self.gen_val(&t)).collect()),
            Type::Variant(v) => {
                let cases: Vec<_> = v.cases().map(|c| (c.name.to_string(), c.ty)).collect();
                let (name, ty) = &cases[self.rng.random_range(0..cases.len())];
                Val::Variant(name.clone(), ty.as_ref().map(|t| Box::new(self.gen_val(t))))
            }
            Type::Enum(e) => {
                let names: Vec<_> = e.names().collect();
                Val::Enum(names[self.rng.random_range(0..names.len())].to_string())
            }
            Type::Option(o) => {
                let some = match self.opts.options.as_deref() {
                    Some("none") => false,
                    Some("some") => true,
                    Some("mixed") => self.rng.random_bool(0.5),
                    _ => self.rng.random_bool(0.9),
                };
                Val::Option(some.then(|| Box::new(self.gen_val(&o.ty()))))
            }
            Type::Result(r) => {
                let ok = match self.opts.results.as_deref() {
                    Some("err") => false,
                    Some("mixed") => self.rng.random_bool(0.5),
                    _ => true,
                };
                if ok { Val::Result(Ok(r.ok().map(|t| Box::new(self.gen_val(&t))))) } else { Val::Result(Err(r.err().map(|t| Box::new(self.gen_val(&t))))) }
            }
            Type::Flags(f) => Val::Flags(f.names().filter(|_| self.rng.random_bool(0.3)).map(str::to_string).collect()),
            // Not fakeable; callers check types before generating.
            Type::Own(_) | Type::Borrow(_) | Type::Future(_) | Type::Stream(_) | Type::ErrorContext => Val::Bool(false),
        }
    }

    fn list_len(&mut self) -> usize {
        self.opts.list_len.unwrap_or_else(|| self.rng.random_range(0..=3))
    }

    fn gen_string(&mut self) -> String {
        let mode = self.opts.strings.clone().unwrap_or_else(|| "words".into());
        let mode = if mode == "edge" { self.pick(&["words", "empty", "long", "unicode", "html"]).to_string() } else { mode };
        if let Some(fixed) = mode.strip_prefix('=') {
            return fixed.to_string();
        }
        match mode.as_str() {
            "empty" => String::new(),
            // Multi-byte characters, so byte slicing hits a char boundary.
            "utf8-2" => "é".repeat(40),
            "utf8-3" => "日".repeat(40),
            "utf8-4" => "😀".repeat(40),
            "utf8-3o" => format!("a{}", "日".repeat(40)),
            "long" => "x".repeat(10_000),
            "unicode" => self.pick(UNICODE).to_string(),
            "html" => self.pick(HTML).to_string(),
            "canary" | "canary-sink" => {
                self.canary += 1;
                let tail = if mode == "canary-sink" { crate::output::SINK_TAIL } else { "" };
                format!("cnry{:04x}{}<i>'\"{tail}", self.rng.random_range(0..0xffffu32), self.canary)
            }
            _ => {
                let a = self.pick(WORDS);
                let b = self.pick(WORDS);
                format!("{a} {b}")
            }
        }
    }
}

/// Whether appfuzz can build values of this type (no resources or streams).
pub fn fakeable(ty: &Type) -> bool {
    match ty {
        Type::Own(_) | Type::Borrow(_) | Type::Future(_) | Type::Stream(_) | Type::ErrorContext => false,
        Type::List(l) => fakeable(&l.ty()),
        Type::FixedLengthList(l) => fakeable(&l.ty()),
        Type::Map(m) => fakeable(&m.key()) && fakeable(&m.value()),
        Type::Record(r) => r.fields().all(|f| fakeable(&f.ty)),
        Type::Tuple(t) => t.types().all(|t| fakeable(&t)),
        Type::Variant(v) => v.cases().all(|c| c.ty.as_ref().is_none_or(fakeable)),
        Type::Option(o) => fakeable(&o.ty()),
        Type::Result(r) => r.ok().as_ref().is_none_or(fakeable) && r.err().as_ref().is_none_or(fakeable),
        _ => true,
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    #[test]
    fn fixed_integral_notation_is_exact_and_casting_is_explicit() {
        for number in ["=13.0", "=13e0", "=+13", "= 13 ", "cast: 13 "] {
            let opts = GenOpts { numbers: Some(number.into()), ..Default::default() };
            opts.validate_for_type(&Type::U8).unwrap();
            assert_eq!(Generator::new(1, opts.clone()).gen_json(&Type::U8), json!(13));
            assert_eq!(Generator::new(1, opts).gen_json(&Type::Float32), json!(13.0));
        }
        let opts = GenOpts { numbers: Some("cast:-1".into()), ..Default::default() };
        opts.validate_for_type(&Type::U8).unwrap();
        assert_eq!(Generator::new(1, opts).gen_json(&Type::U8), json!(u8::MAX));
        for number in ["=256", "=-1", "=13.5"] {
            assert!(GenOpts { numbers: Some(number.into()), ..Default::default() }.validate_for_type(&Type::U8).is_err());
        }
    }

    #[test]
    fn fixed_numbers_apply_to_floating_point_values() {
        for ty in [Type::Float32, Type::Float64] {
            let mut generator = Generator::new(1, GenOpts { numbers: Some("=13".into()), ..Default::default() });
            for _ in 0..16 {
                assert_eq!(generator.gen_json(&ty), json!(13.0));
            }
        }
    }

    #[test]
    fn fixed_unsigned_numbers_keep_all_sixty_four_bits() {
        let mut generator = Generator::new(1, GenOpts { numbers: Some(format!("={}", u64::MAX)), ..Default::default() });
        assert_eq!(generator.gen_json(&Type::U64), json!(u64::MAX));
    }

    #[test]
    fn edge_generation_reaches_both_floating_point_limits() {
        for (ty, min, max) in [(Type::Float32, f32::MIN as f64, f32::MAX as f64), (Type::Float64, f64::MIN, f64::MAX)] {
            let mut generator = Generator::new(1, GenOpts { numbers: Some("edge".into()), ..Default::default() });
            let values: Vec<_> = (0..128).map(|_| generator.gen_json(&ty).as_f64().unwrap()).collect();
            assert!(values.contains(&min), "{ty:?}: minimum was never generated");
            assert!(values.contains(&max), "{ty:?}: maximum was never generated");
        }
    }
}
