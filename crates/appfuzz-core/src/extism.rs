//! Extism plugins: plain modules that talk to their host in JSON.
//!
//! An Extism plugin passes no strings or records across the boundary. It
//! writes bytes into a store the host keeps outside the plugin (the kernel,
//! `extism:host/env`), and every call passes i64 offsets into it. Exports
//! take no parameters: they read their input from the kernel and set their
//! output there. Host functions (`extism:host/user`) take one offset per
//! argument and return one. The bytes are JSON whose shape only the code on
//! both sides knows.
//!
//! The platform writes that shape down as WIT (`[platform] wit`), as a
//! type language only: the plugin is not a component. Each WIT import
//! function is a host function, each WIT export function an export, matched
//! by name ignoring case and `-`/`_`. Inside appfuzz values are WIT values as
//! everywhere else; `Shape` converts them to and from the JSON the plugin
//! uses, with the platform's names (`[platform.json]`). Decoding is lenient
//! like serde with `#[serde(default)]`: keys match ignoring case and
//! separators, and missing fields take their type's empty value.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use wit_parser::{Resolve, Type, TypeDefKind, WorldId, WorldItem};

use crate::manifest::fn_key;

/// How the plugin's JSON spells WIT names (`[platform.json]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonNames {
    /// Record fields: `snake` (default), `kebab`, `camel`, `pascal`,
    /// `lower`, `screaming`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<String>,
    /// Variant, enum and flag cases (default `pascal`, as serde spells Rust enums).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cases: Option<String>,
    /// The keys of a `result`: `{"ok": …}` and `{"err": …}` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    /// The field style of one record type, by WIT type name (serde's `rename_all`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename_all: BTreeMap<String, String>,
    /// One field's or case's JSON name, as `type.name` (serde's `rename`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rename: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Snake,
    Kebab,
    Camel,
    Pascal,
    Lower,
    Screaming,
}

impl Style {
    fn parse(s: &str) -> Result<Style> {
        Ok(match s {
            "snake" | "snake_case" => Style::Snake,
            "kebab" | "kebab-case" => Style::Kebab,
            "camel" | "camelCase" => Style::Camel,
            "pascal" | "PascalCase" => Style::Pascal,
            "lower" | "lowercase" => Style::Lower,
            "screaming" | "SCREAMING_SNAKE_CASE" => Style::Screaming,
            _ => bail!("unknown name style {s:?}: snake, kebab, camel, pascal, lower or screaming"),
        })
    }

    /// A WIT (kebab-case) name in this style.
    fn apply(self, wit: &str) -> String {
        let parts = wit.split('-');
        let cap = |p: &str| {
            let mut c = p.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect::<String>()).unwrap_or_default()
        };
        match self {
            Style::Snake => wit.replace('-', "_"),
            Style::Kebab => wit.to_string(),
            Style::Lower => wit.replace('-', ""),
            Style::Screaming => wit.replace('-', "_").to_uppercase(),
            Style::Pascal => parts.map(cap).collect(),
            Style::Camel => parts.enumerate().map(|(i, p)| if i == 0 { p.to_string() } else { cap(p) }).collect(),
        }
    }
}

/// A name with case and `-`/`_` removed: how decoding and function names match.
pub fn norm(s: &str) -> String {
    s.chars().filter(|c| *c != '-' && *c != '_').flat_map(char::to_lowercase).collect()
}

/// A WIT type as the plugin's JSON spells it.
#[derive(Debug, Clone)]
pub enum Shape {
    Bool,
    Num,
    Char,
    Str,
    List(Box<Shape>),
    Map(Box<Shape>, Box<Shape>),
    Option(Box<Shape>),
    Result(Option<Box<Shape>>, Option<Box<Shape>>),
    Record(Vec<Name>),
    Tuple(Vec<Shape>),
    Variant(Vec<Name>),
    Enum(Vec<Name>),
    Flags(Vec<Name>),
}

/// A field or case: its WIT name, its JSON name, and its type.
#[derive(Debug, Clone)]
pub struct Name {
    pub wit: String,
    pub json: String,
    key: String,
    pub shape: Option<Shape>,
}

/// A function's argument and result shapes.
#[derive(Debug, Clone)]
pub struct FnShape {
    pub params: Vec<(String, Shape)>,
    pub result: Option<Shape>,
}

/// What appfuzz needs to run plugins of an Extism platform.
#[derive(Debug, Clone)]
pub struct Abi {
    /// By appfuzz function key (`extism:host/user#todo-list`, `page`).
    pub funcs: BTreeMap<String, FnShape>,
    /// Host functions by normalized name: their key.
    pub imports: BTreeMap<String, String>,
    /// Exports by normalized name: their key.
    pub exports: BTreeMap<String, String>,
    pub ok: String,
    pub err: String,
}

struct Builder<'a> {
    resolve: &'a Resolve,
    fields: Style,
    cases: Style,
    rename_all: BTreeMap<String, Style>,
    rename: &'a BTreeMap<String, String>,
    ok: String,
    err: String,
}

impl Builder<'_> {
    fn shape(&self, t: &Type) -> Result<Shape> {
        Ok(match t {
            Type::Bool => Shape::Bool,
            Type::Char => Shape::Char,
            Type::String => Shape::Str,
            Type::ErrorContext => bail!("error-context cannot cross as JSON"),
            Type::Id(id) => {
                let def = &self.resolve.types[*id];
                let owner = def.name.clone().unwrap_or_default();
                let name = |wit: &str, style: Style| {
                    let json = self.rename.get(&format!("{owner}.{wit}")).cloned().unwrap_or_else(|| style.apply(wit));
                    (wit.to_string(), json)
                };
                match &def.kind {
                    TypeDefKind::Type(t) => self.shape(t)?,
                    TypeDefKind::List(t) | TypeDefKind::FixedLengthList(t, _) => Shape::List(Box::new(self.shape(t)?)),
                    TypeDefKind::Map(k, v) => Shape::Map(Box::new(self.shape(k)?), Box::new(self.shape(v)?)),
                    TypeDefKind::Option(t) => Shape::Option(Box::new(self.shape(t)?)),
                    TypeDefKind::Result(r) => Shape::Result(self.opt(&r.ok)?, self.opt(&r.err)?),
                    TypeDefKind::Tuple(t) => Shape::Tuple(t.types.iter().map(|t| self.shape(t)).collect::<Result<_>>()?),
                    TypeDefKind::Record(r) => {
                        let style = self.rename_all.get(&owner).copied().unwrap_or(self.fields);
                        Shape::Record(
                            r.fields
                                .iter()
                                .map(|f| {
                                    let (wit, json) = name(&f.name, style);
                                    Ok(Name { key: norm(&json), wit, json, shape: Some(self.shape(&f.ty)?) })
                                })
                                .collect::<Result<_>>()?,
                        )
                    }
                    TypeDefKind::Variant(v) => Shape::Variant(
                        v.cases
                            .iter()
                            .map(|c| {
                                let (wit, json) = name(&c.name, self.cases);
                                Ok(Name { key: norm(&json), wit, json, shape: self.opt(&c.ty)?.map(|b| *b) })
                            })
                            .collect::<Result<_>>()?,
                    ),
                    TypeDefKind::Enum(e) => Shape::Enum(
                        e.cases
                            .iter()
                            .map(|c| {
                                let (wit, json) = name(&c.name, self.cases);
                                Name { key: norm(&json), wit, json, shape: None }
                            })
                            .collect(),
                    ),
                    TypeDefKind::Flags(f) => Shape::Flags(
                        f.flags
                            .iter()
                            .map(|c| {
                                let (wit, json) = name(&c.name, self.cases);
                                Name { key: norm(&json), wit, json, shape: None }
                            })
                            .collect(),
                    ),
                    TypeDefKind::Resource | TypeDefKind::Handle(_) | TypeDefKind::Future(_) | TypeDefKind::Stream(_) | TypeDefKind::Unknown => {
                        bail!("{} cannot cross as JSON", if owner.is_empty() { "a resource, future or stream" } else { &owner })
                    }
                }
            }
            _ => Shape::Num,
        })
    }

    fn opt(&self, t: &Option<Type>) -> Result<Option<Box<Shape>>> {
        t.as_ref().map(|t| self.shape(t).map(Box::new)).transpose()
    }

    fn func(&self, f: &wit_parser::Function) -> Result<FnShape> {
        let params = f.params.iter().map(|p| Ok((p.name.clone(), self.shape(&p.ty)?))).collect::<Result<_>>()?;
        Ok(FnShape { params, result: self.opt(&f.result)?.map(|b| *b) })
    }
}

impl Abi {
    pub fn new(resolve: &Resolve, world: WorldId, names: &JsonNames) -> Result<Abi> {
        let style = |s: &Option<String>, d: Style| s.as_deref().map(Style::parse).transpose().map(|s| s.unwrap_or(d));
        let b = Builder {
            resolve,
            fields: style(&names.fields, Style::Snake)?,
            cases: style(&names.cases, Style::Pascal)?,
            rename_all: names.rename_all.iter().map(|(k, v)| Ok((k.clone(), Style::parse(v)?))).collect::<Result<_>>()?,
            rename: &names.rename,
            ok: names.ok.clone().unwrap_or_else(|| "ok".into()),
            err: names.err.clone().unwrap_or_else(|| "err".into()),
        };
        let mut abi = Abi { funcs: BTreeMap::new(), imports: BTreeMap::new(), exports: BTreeMap::new(), ok: b.ok.clone(), err: b.err.clone() };
        let w = &resolve.worlds[world];
        for (import, items) in [(true, &w.imports), (false, &w.exports)] {
            for (key, item) in items {
                let funcs: Vec<(String, &wit_parser::Function)> = match item {
                    WorldItem::Function(f) => vec![(String::new(), f)],
                    WorldItem::Interface { id, .. } => {
                        let iface = resolve.name_world_key(key);
                        resolve.interfaces[*id].functions.values().map(|f| (iface.clone(), f)).collect()
                    }
                    WorldItem::Type { .. } => continue,
                };
                for (iface, f) in funcs {
                    let k = fn_key(&iface, &f.name);
                    let shape = b.func(f).map_err(|e| anyhow!("{k}: {e}"))?;
                    let side = if import { &mut abi.imports } else { &mut abi.exports };
                    if let Some(other) = side.insert(norm(&f.name), k.clone()) {
                        bail!("{other} and {k} map to the same Extism name");
                    }
                    abi.funcs.insert(k, shape);
                }
            }
        }
        Ok(abi)
    }

    /// One argument or result in WIT-shaped JSON (as `val_to_json` writes
    /// it) to the bytes the plugin reads. A top-level `string` crosses as
    /// its bytes, as the PDK's `String` does; everything else as JSON.
    pub fn encode(&self, v: &Value, s: &Shape) -> Vec<u8> {
        if let (Shape::Str, Value::String(text)) = (s, v) {
            return text.as_bytes().to_vec();
        }
        serde_json::to_vec(&self.out(v, s)).expect("JSON serializes")
    }

    /// The bytes the plugin wrote to WIT-shaped JSON (as `json_to_val` reads it).
    pub fn decode(&self, bytes: &[u8], s: &Shape) -> Result<Value> {
        if let Shape::Str = s {
            return Ok(Value::String(String::from_utf8_lossy(bytes).into_owned()));
        }
        let v: Value =
            if bytes.iter().all(u8::is_ascii_whitespace) { Value::Null } else { serde_json::from_slice(bytes).map_err(|e| anyhow!("not JSON: {e}"))? };
        self.into(&v, s)
    }

    fn out(&self, v: &Value, s: &Shape) -> Value {
        match (s, v) {
            (Shape::List(t), Value::Array(a)) => Value::Array(a.iter().map(|x| self.out(x, t)).collect()),
            (Shape::Map(k, t), Value::Array(a)) => {
                let pairs = a.iter().filter_map(|p| p.as_array().filter(|p| p.len() == 2));
                let keys: Vec<Value> = pairs.clone().map(|p| self.out(&p[0], k)).collect();
                if keys.iter().all(Value::is_string) {
                    Value::Object(keys.into_iter().zip(pairs).map(|(k, p)| (k.as_str().unwrap_or_default().to_string(), self.out(&p[1], t))).collect())
                } else {
                    Value::Array(keys.into_iter().zip(pairs).map(|(k, p)| json!([k, self.out(&p[1], t)])).collect())
                }
            }
            (Shape::Option(t), Value::Object(m)) if m.len() == 1 && m.contains_key("some") => self.out(&m["some"], t),
            (Shape::Option(t), v) if !v.is_null() => self.out(v, t),
            (Shape::Result(ok, err), Value::Object(m)) if m.len() == 1 => {
                let (case, p) = m.iter().next().expect("one entry");
                let (key, t) = if case == "err" { (&self.err, err) } else { (&self.ok, ok) };
                json!({ key.clone(): t.as_ref().map_or(Value::Null, |t| self.out(p, t)) })
            }
            (Shape::Record(fields), Value::Object(m)) => {
                Value::Object(fields.iter().filter_map(|f| Some((f.json.clone(), self.out(m.get(&f.wit)?, f.shape.as_ref()?)))).collect())
            }
            (Shape::Tuple(ts), Value::Array(a)) => Value::Array(a.iter().zip(ts).map(|(x, t)| self.out(x, t)).collect()),
            (Shape::Variant(cases), Value::String(c)) | (Shape::Enum(cases), Value::String(c)) => {
                json!(cases.iter().find(|x| x.wit == *c).map_or(c.as_str(), |x| x.json.as_str()))
            }
            (Shape::Variant(cases), Value::Object(m)) if m.len() == 1 => {
                let (c, p) = m.iter().next().expect("one entry");
                match cases.iter().find(|x| x.wit == *c) {
                    Some(Name { json, shape: Some(t), .. }) => json!({ json.clone(): self.out(p, t) }),
                    Some(x) => json!(x.json),
                    None => v.clone(),
                }
            }
            (Shape::Flags(names), Value::Array(a)) => {
                Value::Array(a.iter().map(|f| json!(names.iter().find(|x| Some(x.wit.as_str()) == f.as_str()).map_or(f.clone(), |x| json!(x.json)))).collect())
            }
            (_, v) => v.clone(),
        }
    }

    fn into(&self, v: &Value, s: &Shape) -> Result<Value> {
        Ok(match (s, v) {
            (Shape::Option(_), Value::Null) => Value::Null,
            (Shape::Option(t), v) => json!({ "some": self.into(v, t)? }),
            (_, Value::Null) => empty(s),
            (Shape::List(t), Value::Array(a)) => Value::Array(a.iter().map(|x| self.into(x, t)).collect::<Result<_>>()?),
            (Shape::Map(k, t), Value::Object(m)) => {
                Value::Array(m.iter().map(|(key, x)| Ok(json!([self.into(&json!(key), k)?, self.into(x, t)?]))).collect::<Result<_>>()?)
            }
            (Shape::Map(k, t), Value::Array(a)) => Value::Array(
                a.iter()
                    .map(|p| match p.as_array().map(Vec::as_slice) {
                        Some([key, x]) => Ok(json!([self.into(key, k)?, self.into(x, t)?])),
                        _ => bail!("expected [key, value], got {p}"),
                    })
                    .collect::<Result<_>>()?,
            ),
            (Shape::Result(ok, err), Value::Object(m)) => {
                let get = |k: &str| m.get(k).or_else(|| m.iter().find(|(x, _)| norm(x) == norm(k)).map(|(_, v)| v)).filter(|v| !v.is_null());
                match (get(&self.err), err) {
                    (Some(e), Some(t)) => json!({ "err": self.into(e, t)? }),
                    (Some(_), None) => json!({ "err": null }),
                    (None, _) => match (get(&self.ok), ok) {
                        (Some(x), Some(t)) => json!({ "ok": self.into(x, t)? }),
                        (None, Some(t)) => json!({ "ok": empty(t) }),
                        (_, None) => json!({ "ok": null }),
                    },
                }
            }
            (Shape::Record(fields), Value::Object(m)) => {
                let mut out = Map::new();
                for f in fields {
                    let t = f.shape.as_ref().expect("fields have types");
                    let x = m.get(&f.json).or_else(|| m.iter().find(|(k, _)| norm(k) == f.key).map(|(_, v)| v));
                    let x = match x {
                        Some(x) => self.into(x, t).map_err(|e| anyhow!(".{}: {e}", f.json))?,
                        None => empty(t),
                    };
                    out.insert(f.wit.clone(), x);
                }
                Value::Object(out)
            }
            (Shape::Tuple(ts), Value::Array(a)) if a.len() == ts.len() => Value::Array(a.iter().zip(ts).map(|(x, t)| self.into(x, t)).collect::<Result<_>>()?),
            (Shape::Variant(cases), Value::String(c)) | (Shape::Enum(cases), Value::String(c)) => json!(case(cases, c)?.wit),
            (Shape::Variant(cases), Value::Object(m)) if m.len() == 1 => {
                let (c, p) = m.iter().next().expect("one entry");
                let x = case(cases, c)?;
                match &x.shape {
                    Some(t) => json!({ x.wit.clone(): self.into(p, t)? }),
                    None => json!(x.wit),
                }
            }
            (Shape::Flags(names), Value::Array(a)) => Value::Array(
                a.iter().map(|f| Ok(json!(case(names, f.as_str().ok_or_else(|| anyhow!("flag {f} is not a string"))?)?.wit))).collect::<Result<_>>()?,
            ),
            // A string takes any JSON as its text (an untyped `body`).
            (Shape::Str, v) if !v.is_string() => Value::String(v.to_string()),
            (Shape::Bool | Shape::Num | Shape::Str | Shape::Char, v) => v.clone(),
            (_, v) => bail!("{} does not fit {}", short(v), kind(s)),
        })
    }
}

fn case<'a>(cases: &'a [Name], c: &str) -> Result<&'a Name> {
    cases
        .iter()
        .find(|x| x.json == c)
        .or_else(|| cases.iter().find(|x| x.key == norm(c)))
        .ok_or_else(|| anyhow!("unknown case {c:?}; one of {}", cases.iter().map(|x| x.json.as_str()).collect::<Vec<_>>().join(", ")))
}

/// The empty value of a shape in WIT-shaped JSON: what `#[serde(default)]` gives.
fn empty(s: &Shape) -> Value {
    match s {
        Shape::Bool => json!(false),
        Shape::Num => json!(0),
        Shape::Char => json!("\0"),
        Shape::Str => json!(""),
        Shape::List(_) | Shape::Map(..) | Shape::Flags(_) => json!([]),
        Shape::Option(_) => Value::Null,
        Shape::Result(ok, _) => json!({ "ok": ok.as_ref().map_or(Value::Null, |t| empty(t)) }),
        Shape::Record(fields) => Value::Object(fields.iter().map(|f| (f.wit.clone(), f.shape.as_ref().map_or(Value::Null, empty))).collect()),
        Shape::Tuple(ts) => Value::Array(ts.iter().map(empty).collect()),
        Shape::Variant(cases) => match cases.first() {
            Some(Name { wit, shape: Some(t), .. }) => json!({ wit.clone(): empty(t) }),
            Some(c) => json!(c.wit),
            None => Value::Null,
        },
        Shape::Enum(cases) => cases.first().map_or(Value::Null, |c| json!(c.wit)),
    }
}

fn kind(s: &Shape) -> &'static str {
    match s {
        Shape::Bool => "a bool",
        Shape::Num => "a number",
        Shape::Char => "a char",
        Shape::Str => "a string",
        Shape::List(_) => "a list",
        Shape::Map(..) => "a map",
        Shape::Option(_) => "an option",
        Shape::Result(..) => "a result",
        Shape::Record(_) => "a record",
        Shape::Tuple(_) => "a tuple",
        Shape::Variant(_) => "a variant",
        Shape::Enum(_) => "an enum",
        Shape::Flags(_) => "flags",
    }
}

fn short(v: &Value) -> String {
    let mut s = v.to_string();
    if s.len() > 60 {
        s.truncate(s.floor_char_boundary(60));
        s.push('…');
    }
    s
}

/// Several arguments cross as one JSON object of their names; one as itself.
pub fn args_shape(params: &[(String, Shape)]) -> Option<Shape> {
    match params {
        [] => None,
        [(_, s)] => Some(s.clone()),
        many => {
            Some(Shape::Record(many.iter().map(|(n, s)| Name { wit: n.clone(), json: n.replace('-', "_"), key: norm(n), shape: Some(s.clone()) }).collect()))
        }
    }
}

/// The kernel's byte store: blocks addressed by offset, outside the plugin.
#[derive(Debug, Default)]
pub struct Kernel {
    bytes: Vec<u8>,
    /// Block start → length.
    blocks: BTreeMap<u64, u64>,
    pub input: Vec<u8>,
    input_block: Option<u64>,
    pub output: Option<Vec<u8>>,
    pub error: Option<Vec<u8>>,
    error_block: Option<u64>,
    vars: BTreeMap<Vec<u8>, Vec<u8>>,
    pub logs: Vec<(String, String)>,
    /// The most bytes the store may hold.
    pub max: usize,
    pub peak: usize,
}

/// Offsets start here: 0 means "no block".
const BASE: u64 = 8;

impl Kernel {
    pub fn new(input: Vec<u8>, max: usize) -> Kernel {
        Kernel { input, max, ..Default::default() }
    }

    pub fn alloc(&mut self, n: u64) -> Result<u64> {
        let at = (BASE + self.bytes.len() as u64 + 7) & !7;
        let end = at.checked_add(n).ok_or_else(|| anyhow!("alloc of {n} bytes"))?;
        let live: u64 = self.blocks.values().sum::<u64>() + n;
        if live as usize > self.max || (end - BASE) as usize > self.max.saturating_mul(4) {
            bail!("the Extism kernel ran out of memory ({n} bytes asked, {live} live)");
        }
        self.bytes.resize((end - BASE) as usize, 0);
        self.blocks.insert(at, n);
        self.peak = self.peak.max(live as usize);
        Ok(at)
    }

    /// A block holding these bytes.
    pub fn put(&mut self, data: &[u8]) -> Result<u64> {
        let at = self.alloc(data.len() as u64)?;
        let i = (at - BASE) as usize;
        self.bytes[i..i + data.len()].copy_from_slice(data);
        Ok(at)
    }

    pub fn free(&mut self, at: u64) {
        self.blocks.remove(&at);
    }

    pub fn length(&self, at: u64) -> u64 {
        self.blocks.get(&at).copied().unwrap_or(0)
    }

    fn range(&self, at: u64, n: u64) -> Result<std::ops::Range<usize>> {
        let s = at.checked_sub(BASE).ok_or_else(|| anyhow!("kernel offset {at} is out of bounds"))?;
        let e = s.checked_add(n).filter(|e| *e as usize <= self.bytes.len()).ok_or_else(|| anyhow!("kernel offset {at}+{n} is out of bounds"))?;
        Ok(s as usize..e as usize)
    }

    pub fn load(&self, at: u64, n: u64) -> Result<&[u8]> {
        Ok(&self.bytes[self.range(at, n)?])
    }

    pub fn store(&mut self, at: u64, data: &[u8]) -> Result<()> {
        let r = self.range(at, data.len() as u64)?;
        self.bytes[r].copy_from_slice(data);
        Ok(())
    }

    /// The bytes of the block at `at`.
    pub fn block(&self, at: u64) -> Result<Vec<u8>> {
        if at == 0 {
            return Ok(Vec::new());
        }
        let n = self.blocks.get(&at).copied().ok_or_else(|| anyhow!("kernel offset {at} is not a block"))?;
        Ok(self.load(at, n)?.to_vec())
    }

    pub fn input_offset(&mut self) -> Result<u64> {
        if let Some(b) = self.input_block {
            return Ok(b);
        }
        let input = std::mem::take(&mut self.input);
        let at = self.put(&input)?;
        self.input = input;
        self.input_block = Some(at);
        Ok(at)
    }

    pub fn input_load(&self, at: u64, n: u64) -> Result<&[u8]> {
        let s = at as usize;
        self.input.get(s..s.saturating_add(n as usize)).ok_or_else(|| anyhow!("input offset {at}+{n} is out of bounds"))
    }

    pub fn error_get(&mut self) -> Result<u64> {
        match (&self.error, self.error_block) {
            (_, Some(b)) => Ok(b),
            (Some(e), None) => {
                let e = e.clone();
                let b = self.put(&e)?;
                self.error_block = Some(b);
                Ok(b)
            }
            (None, None) => Ok(0),
        }
    }

    pub fn set_error(&mut self, e: Option<Vec<u8>>) {
        self.error = e;
        self.error_block = None;
    }

    pub fn var_get(&mut self, key: &[u8]) -> Result<u64> {
        match self.vars.get(key).cloned() {
            Some(v) => self.put(&v),
            None => Ok(0),
        }
    }

    pub fn var_set(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) {
        match value {
            Some(v) => self.vars.insert(key, v),
            None => self.vars.remove(&key),
        };
    }
}

/// Links `extism:host/env`, the kernel, to `kernel` in the store's data.
pub fn link_kernel<T: 'static>(linker: &mut wasmtime::Linker<T>, kernel: fn(&mut T) -> &mut Kernel) -> Result<()> {
    use wasmtime::Caller;
    const ENV: &str = "extism:host/env";
    let err = |e: anyhow::Error| wasmtime::Error::from_anyhow(e);
    linker.func_wrap(ENV, "alloc", move |mut c: Caller<'_, T>, n: i64| kernel(c.data_mut()).alloc(n as u64).map(|x| x as i64).map_err(err))?;
    linker.func_wrap(ENV, "free", move |mut c: Caller<'_, T>, at: i64| kernel(c.data_mut()).free(at as u64))?;
    linker.func_wrap(ENV, "length", move |mut c: Caller<'_, T>, at: i64| kernel(c.data_mut()).length(at as u64) as i64)?;
    linker.func_wrap(ENV, "length_unsafe", move |mut c: Caller<'_, T>, at: i64| kernel(c.data_mut()).length(at as u64) as i64)?;
    linker.func_wrap(ENV, "load_u8", move |mut c: Caller<'_, T>, at: i64| kernel(c.data_mut()).load(at as u64, 1).map(|b| b[0] as i32).map_err(err))?;
    linker.func_wrap(ENV, "load_u64", move |mut c: Caller<'_, T>, at: i64| {
        kernel(c.data_mut()).load(at as u64, 8).map(|b| i64::from_le_bytes(b.try_into().expect("8 bytes"))).map_err(err)
    })?;
    linker.func_wrap(ENV, "store_u8", move |mut c: Caller<'_, T>, at: i64, v: i32| kernel(c.data_mut()).store(at as u64, &[v as u8]).map_err(err))?;
    linker.func_wrap(ENV, "store_u64", move |mut c: Caller<'_, T>, at: i64, v: i64| kernel(c.data_mut()).store(at as u64, &v.to_le_bytes()).map_err(err))?;
    linker.func_wrap(ENV, "input_length", move |mut c: Caller<'_, T>| kernel(c.data_mut()).input.len() as i64)?;
    linker.func_wrap(ENV, "input_offset", move |mut c: Caller<'_, T>| kernel(c.data_mut()).input_offset().map(|x| x as i64).map_err(err))?;
    linker.func_wrap(ENV, "input_load_u8", move |mut c: Caller<'_, T>, at: i64| {
        kernel(c.data_mut()).input_load(at as u64, 1).map(|b| b[0] as i32).map_err(err)
    })?;
    linker.func_wrap(ENV, "input_load_u64", move |mut c: Caller<'_, T>, at: i64| {
        kernel(c.data_mut()).input_load(at as u64, 8).map(|b| i64::from_le_bytes(b.try_into().expect("8 bytes"))).map_err(err)
    })?;
    linker.func_wrap(ENV, "output_set", move |mut c: Caller<'_, T>, at: i64, n: i64| {
        let k = kernel(c.data_mut());
        let out = k.load(at as u64, n as u64).map_err(err)?.to_vec();
        k.output = Some(out);
        Ok(())
    })?;
    linker.func_wrap(ENV, "error_set", move |mut c: Caller<'_, T>, at: i64| {
        let k = kernel(c.data_mut());
        let e = if at == 0 { None } else { Some(k.block(at as u64).map_err(err)?) };
        k.set_error(e);
        Ok(())
    })?;
    linker.func_wrap(ENV, "error_get", move |mut c: Caller<'_, T>| kernel(c.data_mut()).error_get().map(|x| x as i64).map_err(err))?;
    linker.func_wrap(ENV, "config_get", move |_c: Caller<'_, T>, _key: i64| 0i64)?;
    linker.func_wrap(ENV, "var_get", move |mut c: Caller<'_, T>, key: i64| {
        let k = kernel(c.data_mut());
        let key = k.block(key as u64).map_err(err)?;
        k.var_get(&key).map(|x| x as i64).map_err(err)
    })?;
    linker.func_wrap(ENV, "var_set", move |mut c: Caller<'_, T>, key: i64, value: i64| {
        let k = kernel(c.data_mut());
        let key = k.block(key as u64).map_err(err)?;
        let value = if value == 0 { None } else { Some(k.block(value as u64).map_err(err)?) };
        k.var_set(key, value);
        Ok(())
    })?;
    for level in ["trace", "debug", "info", "warn", "error"] {
        linker.func_wrap(ENV, &format!("log_{level}"), move |mut c: Caller<'_, T>, at: i64| {
            let k = kernel(c.data_mut());
            let text = String::from_utf8_lossy(&k.block(at as u64).map_err(err)?).into_owned();
            k.logs.push((level.to_string(), text));
            Ok(())
        })?;
    }
    // Every level is enabled: appfuzz wants to see all logs.
    linker.func_wrap(ENV, "get_log_level", move |_c: Caller<'_, T>| 0i32)?;
    linker.func_wrap(ENV, "http_request", move |_c: Caller<'_, T>, _req: i64, _body: i64| -> wasmtime::Result<i64> {
        Err(wasmtime::Error::msg("extism:host/env#http_request is not simulated by appfuzz yet"))
    })?;
    linker.func_wrap(ENV, "http_status_code", move |_c: Caller<'_, T>| 0i32)?;
    linker.func_wrap(ENV, "http_headers", move |_c: Caller<'_, T>| 0i64)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi(wit: &str, names: JsonNames) -> Abi {
        let mut r = Resolve::new();
        let pkg = r.push_str("t.wit", wit).unwrap();
        let w = r.select_world(&[pkg], None).unwrap();
        Abi::new(&r, w, &names).unwrap()
    }

    const WIT: &str = r#"
        package extism:host;
        interface user {
            record todo { id: string, org-id: string, done: bool, tags: list<string>, owner: option<string> }
            enum state { open, in-progress }
            todo-get: func(id: string) -> result<option<todo>, string>;
            todo-state: func(s: state) -> state;
        }
        world plugin {
            import user;
            use user.{todo};
            export page: func(org-id: string, limit: u32) -> todo;
        }
    "#;

    #[test]
    fn names_and_lookup() {
        let a = abi(WIT, JsonNames::default());
        assert_eq!(a.imports["todoget"], "extism:host/user#todo-get");
        assert_eq!(a.exports["page"], "page");
        assert_eq!(Style::Pascal.apply("org-id"), "OrgId");
        assert_eq!(Style::Camel.apply("org-id"), "orgId");
    }

    #[test]
    fn round_trip() {
        let mut names = JsonNames { err: Some("error".into()), ..Default::default() };
        names.rename.insert("todo.id".into(), "Id".into());
        let a = abi(WIT, names);
        let f = &a.funcs["extism:host/user#todo-get"];
        let r = f.result.as_ref().unwrap();
        let wit = json!({"ok": {"some": {"id": "1", "org-id": "o", "done": true, "tags": ["a"], "owner": null}}});
        let bytes = a.encode(&wit, r);
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), json!({"ok": {"Id": "1", "org_id": "o", "done": true, "tags": ["a"], "owner": null}}));
        assert_eq!(a.decode(&bytes, r).unwrap(), wit);
        // Lenient: other spellings, missing fields, Go's nil slice, a missing ok.
        let got = a.decode(br#"{"ok": {"ID": "2", "OrgId": "p", "tags": null}}"#, r).unwrap();
        assert_eq!(got, json!({"ok": {"some": {"id": "2", "org-id": "p", "done": false, "tags": [], "owner": null}}}));
        assert_eq!(a.decode(br#"{"error": "gone"}"#, r).unwrap(), json!({"err": "gone"}));
        assert_eq!(a.decode(br#"{"ok": null, "error": null}"#, r).unwrap(), json!({"ok": null}));
        assert_eq!(a.encode(&json!({"err": "x"}), r), br#"{"error":"x"}"#);
        let s = a.funcs["extism:host/user#todo-state"].result.clone().unwrap();
        assert_eq!(a.encode(&json!("in-progress"), &s), br#""InProgress""#);
        assert_eq!(a.decode(br#""in_progress""#, &s).unwrap(), json!("in-progress"));
        // A top-level string is its bytes (the PDK's `String`), not JSON.
        assert_eq!(a.encode(&json!("hi"), &Shape::Str), b"hi");
        assert_eq!(a.decode(b"<p>x</p>", &Shape::Str).unwrap(), json!("<p>x</p>"));
        // Several arguments are one object.
        let p = args_shape(&a.funcs["page"].params).unwrap();
        assert_eq!(a.encode(&json!({"org-id": "o", "limit": 3}), &p), br#"{"org_id":"o","limit":3}"#);
    }

    #[test]
    fn kernel_blocks() {
        let mut k = Kernel::new(b"in".to_vec(), 1 << 20);
        let a = k.put(b"hello").unwrap();
        assert_eq!(k.length(a), 5);
        assert_eq!(k.block(a).unwrap(), b"hello");
        let b = k.alloc(3).unwrap();
        assert!(b >= a + 5 && b.is_multiple_of(8));
        k.store(b, b"abc").unwrap();
        assert_eq!(k.load(b + 1, 2).unwrap(), b"bc");
        assert!(k.load(b + 2, 8).is_err());
        assert_eq!(k.input_load(1, 1).unwrap(), b"n");
        k.free(a);
        assert_eq!(k.length(a), 0);
        assert!(Kernel::new(vec![], 4).alloc(5).is_err());
    }
}
