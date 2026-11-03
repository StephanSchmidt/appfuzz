//! Host functions described in witx, for plain (non-component) modules.
//!
//! A witx function's raw parameters are pointers, lengths and output
//! pointers. Each function gets a high-level signature: its inputs, and its
//! outputs as `result<T, status>`. The signatures are written as WIT and
//! compiled into a small component that is never run. It gives the rest of
//! appfuzz ordinary component types for plans, generation and records. At run
//! time `lift` reads the raw arguments from linear memory into values and
//! `lower` writes a result back into output pointers, buffers and the status.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use anyhow::{Context, Result, anyhow, bail};
use wasmtime::component::{Component, Val};
use wasmtime::{Engine, ValType};
use witx::{BuiltinType, Layout, RecordKind, Type, TypeRef};

use crate::wit::{FuncInfo, ImportKind, Interface};

/// A scalar as stored in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prim {
    U8,
    U16,
    U32,
    U64,
    S8,
    S16,
    S32,
    S64,
    F32,
    F64,
    Char,
}

impl Prim {
    fn size(self) -> usize {
        match self {
            Prim::U8 | Prim::S8 => 1,
            Prim::U16 | Prim::S16 => 2,
            Prim::U32 | Prim::S32 | Prim::F32 | Prim::Char => 4,
            Prim::U64 | Prim::S64 | Prim::F64 => 8,
        }
    }
    fn wit(self) -> &'static str {
        match self {
            Prim::U8 => "u8",
            Prim::U16 => "u16",
            Prim::U32 => "u32",
            Prim::U64 => "u64",
            Prim::S8 => "s8",
            Prim::S16 => "s16",
            Prim::S32 => "s32",
            Prim::S64 => "s64",
            Prim::F32 => "f32",
            Prim::F64 => "f64",
            Prim::Char => "char",
        }
    }
    fn of(b: &BuiltinType) -> Prim {
        match b {
            BuiltinType::Char => Prim::Char,
            BuiltinType::U8 { .. } => Prim::U8,
            BuiltinType::U16 => Prim::U16,
            BuiltinType::U32 { .. } => Prim::U32,
            BuiltinType::U64 => Prim::U64,
            BuiltinType::S8 => Prim::S8,
            BuiltinType::S16 => Prim::S16,
            BuiltinType::S32 => Prim::S32,
            BuiltinType::S64 => Prim::S64,
            BuiltinType::F32 => Prim::F32,
            BuiltinType::F64 => Prim::F64,
        }
    }
    fn of_repr(r: &witx::IntRepr) -> Prim {
        match r {
            witx::IntRepr::U8 => Prim::U8,
            witx::IntRepr::U16 => Prim::U16,
            witx::IntRepr::U32 => Prim::U32,
            witx::IntRepr::U64 => Prim::U64,
        }
    }
}

/// A high-level type: how a value looks in memory and in WIT.
#[derive(Clone, Debug)]
pub enum Wt {
    Prim(Prim),
    /// A handle of the named kind (`request_handle`); `u32` in WIT.
    Handle(String),
    /// An enum. `raw[i]` is the stored tag of WIT case `cases[i]`.
    Enum {
        name: String,
        repr: Prim,
        cases: Vec<String>,
        raw: Vec<u64>,
    },
    Flags {
        name: String,
        repr: Prim,
        names: Vec<String>,
    },
    Record {
        name: String,
        size: usize,
        fields: Vec<Field>,
    },
    /// A byte string: a `(list u8)` argument or a pointer and length field.
    Bytes,
    Str,
    List(Box<Wt>),
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub offset: usize,
    pub ty: Wt,
    /// For `Str`/`Bytes` fields: where the length is stored.
    pub len_offset: Option<usize>,
}

impl Wt {
    fn size(&self) -> usize {
        match self {
            Wt::Prim(p) => p.size(),
            Wt::Handle(_) => 4,
            Wt::Enum { repr, .. } | Wt::Flags { repr, .. } => repr.size(),
            Wt::Record { size, .. } => *size,
            Wt::Bytes | Wt::Str | Wt::List(_) => 8,
        }
    }
    pub fn handle(&self) -> Option<&str> {
        match self {
            Wt::Handle(k) => Some(k),
            _ => None,
        }
    }
}

/// How one or more raw parameters are used.
#[derive(Clone, Debug)]
enum Slot {
    /// One raw value: a number, handle, enum or flags.
    In { name: String, ty: Wt },
    /// Pointer and length: a string, bytes or a list.
    InList { name: String, ty: Wt },
    /// A pointer to an input record or value.
    InPtr { name: String, ty: Wt },
    /// Pointer, max length, [cursor, cursor out], length out.
    OutBuf { name: String, string: bool, cursor: bool },
    /// Pointer and length to fill; the number of bytes is the call's result.
    ReadBuf { name: String },
    /// A pointer the host writes a value to.
    OutPtr { name: String, ty: Wt },
}

impl Slot {
    fn width(&self) -> usize {
        match self {
            Slot::In { .. } | Slot::InPtr { .. } | Slot::OutPtr { .. } => 1,
            Slot::InList { .. } | Slot::ReadBuf { .. } => 2,
            Slot::OutBuf { cursor, .. } => {
                if *cursor {
                    5
                } else {
                    3
                }
            }
        }
    }
}

/// The status enum of `(expected … (error $status))`.
#[derive(Clone, Debug)]
pub struct Status {
    pub ty: Wt,
    /// Raw code of `ok`.
    pub ok: u64,
}

impl Status {
    /// The raw code of a named status, if the platform has it.
    pub fn code(&self, name: &str) -> Option<u64> {
        let Wt::Enum { cases, raw, .. } = &self.ty else { return None };
        cases.iter().position(|c| c == name).map(|i| raw[i])
    }
}

/// One witx function with its high-level signature.
#[derive(Clone, Debug)]
pub struct Sig {
    pub module: String,
    pub name: String,
    slots: Vec<Slot>,
    pub status: Option<Status>,
    /// `expected` payload members, written through trailing pointers.
    ok_outs: Vec<(String, Wt)>,
    /// The `expected` payload is the number of bytes a `ReadBuf` received.
    read_count: bool,
    /// A direct return value (no `expected`).
    ret: Option<Wt>,
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
    /// The witx `;;;` comments: the function's, then each raw parameter's.
    pub doc: String,
    pub param_docs: BTreeMap<String, String>,
}

impl Sig {
    pub fn key(&self) -> String {
        format!("{}#{}", self.module, self.name)
    }

    /// High-level inputs: (name, type).
    pub fn inputs(&self) -> Vec<(&str, &Wt)> {
        self.slots
            .iter()
            .filter_map(|s| match s {
                Slot::In { name, ty } | Slot::InList { name, ty } | Slot::InPtr { name, ty } => Some((name.as_str(), ty)),
                _ => None,
            })
            .collect()
    }

    /// High-level outputs, the parts of the success value.
    pub fn outputs(&self) -> Vec<(String, Wt)> {
        let mut out = Vec::new();
        for s in &self.slots {
            match s {
                Slot::OutBuf { name, string, cursor } => {
                    let t = if *string { Wt::Str } else { Wt::Bytes };
                    out.push((name.clone(), if *cursor { Wt::List(Box::new(t)) } else { t }));
                }
                Slot::ReadBuf { name } => out.push((name.clone(), Wt::Bytes)),
                Slot::OutPtr { name, ty } => out.push((name.clone(), ty.clone())),
                _ => {}
            }
        }
        if !self.read_count {
            out.extend(self.ok_outs.iter().cloned());
        }
        out
    }
}

/// A function the classifier could not describe; linked so that calling it
/// answers `unsupported`.
#[derive(Clone, Debug)]
pub struct Unsupported {
    pub module: String,
    pub name: String,
    pub reason: String,
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
    pub status: Option<Status>,
}

pub struct Platform {
    pub sigs: BTreeMap<String, Sig>,
    pub unsupported: BTreeMap<String, Unsupported>,
    /// The carrier's WIT, for `inspect --wit`.
    pub wit: String,
    /// High-level imports, typed by the carrier component.
    pub imports: Vec<Interface>,
    /// The entry export (`entry#handle`), when the platform declares one.
    pub exports: Vec<FuncInfo>,
}

/// Concatenates witx sources (dropping `(use …)` lines) and parses them.
pub fn parse(sources: &[(&str, &str)]) -> Result<witx::Document> {
    let mut text = String::new();
    for (name, src) in sources {
        let _ = writeln!(text, ";; {name}");
        for line in src.lines() {
            if line.trim_start().starts_with("(use ") {
                continue;
            }
            text.push_str(line);
            text.push('\n');
        }
    }
    witx::parse(&text).map_err(|e| anyhow!("witx: {}", e.report_with(&witx::MockFs::new(&[("-", &text)]))))
}

/// Loads a witx platform and builds the type carrier.
/// `entry` is the WIT of the interface apps are called through, as
/// appfuzz sees them (a request in, a response out), if the platform has one.
pub fn load(engine: &Engine, doc: &witx::Document, entry: Option<&str>) -> Result<Platform> {
    let mut sigs = BTreeMap::new();
    let mut unsupported = BTreeMap::new();
    for m in doc.modules() {
        for f in m.funcs() {
            let (params, results) = f.wasm_signature();
            let params: Vec<ValType> = params.iter().map(val_type).collect();
            let results: Vec<ValType> = results.iter().map(val_type).collect();
            let module = m.name.as_str().to_string();
            let name = f.name.as_str().to_string();
            match classify(&module, &name, &f, &params, &results) {
                Ok(sig) => {
                    sigs.insert(sig.key(), sig);
                }
                Err(reason) => {
                    let status = f.results.first().and_then(|r| expected_status(&r.tref));
                    unsupported.insert(format!("{module}#{name}"), Unsupported { module, name, reason, params, results, status });
                }
            }
        }
    }
    let wit = carrier_wit(&sigs, entry);
    let (imports, exports) = carrier_types(engine, &wit, &sigs)?;
    Ok(Platform { sigs, unsupported, wit, imports, exports })
}

fn val_type(t: &witx::WasmType) -> ValType {
    match t {
        witx::WasmType::I32 => ValType::I32,
        witx::WasmType::I64 => ValType::I64,
        witx::WasmType::F32 => ValType::F32,
        witx::WasmType::F64 => ValType::F64,
    }
}

fn expected_status(t: &TypeRef) -> Option<Status> {
    let Type::Variant(v) = &**t.type_() else { return None };
    let (_, err) = v.as_expected()?;
    status_of(err?)
}

fn status_of(t: &TypeRef) -> Option<Status> {
    let ty = wt(t).ok()?;
    let Wt::Enum { cases, raw, name, repr } = ty else { return None };
    let ok = cases.iter().position(|c| c == "ok").map(|i| raw[i])?;
    let (cases, raw): (Vec<_>, Vec<_>) = cases.into_iter().zip(raw).filter(|(c, _)| c != "ok").unzip();
    Some(Status { ty: Wt::Enum { name, repr, cases, raw }, ok })
}

fn is_byte(t: &TypeRef) -> Option<bool> {
    match &**t.type_() {
        Type::Builtin(BuiltinType::U8 { lang_c_char }) => Some(*lang_c_char),
        _ => None,
    }
}

fn is_usize(t: &TypeRef) -> bool {
    matches!(&**t.type_(), Type::Builtin(BuiltinType::U32 { .. }))
}

fn points_to(t: &TypeRef, f: impl Fn(&TypeRef) -> bool) -> bool {
    match &**t.type_() {
        Type::Pointer(p) => f(p),
        _ => false,
    }
}

fn type_name(t: &TypeRef) -> Option<String> {
    match t {
        TypeRef::Name(n) => Some(n.name.as_str().to_string()),
        TypeRef::Value(_) => None,
    }
}

/// The high-level type of a value stored in memory.
fn wt(t: &TypeRef) -> Result<Wt, String> {
    Ok(match &**t.type_() {
        Type::Builtin(b) => Wt::Prim(Prim::of(b)),
        Type::Handle(_) => Wt::Handle(type_name(t).unwrap_or_else(|| "handle".into())),
        Type::Variant(v) if v.is_enum() => {
            let name = type_name(t).ok_or("anonymous enum")?;
            Wt::Enum {
                name,
                repr: Prim::of_repr(&v.tag_repr),
                cases: v.cases.iter().map(|c| ident(c.name.as_str())).collect(),
                raw: (0..v.cases.len() as u64).collect(),
            }
        }
        Type::Variant(_) => return Err("variant with payloads".into()),
        Type::Record(r) => match &r.kind {
            RecordKind::Bitflags(repr) => Wt::Flags {
                name: type_name(t).ok_or("anonymous flags")?,
                repr: Prim::of_repr(repr),
                names: r.members.iter().map(|m| ident(m.name.as_str())).collect(),
            },
            _ => {
                let layout = r.member_layout();
                let mut fields = Vec::new();
                let mut i = 0;
                while i < layout.len() {
                    let m = &layout[i];
                    let mt = &m.member.tref;
                    let ptr_to_bytes = match &**mt.type_() {
                        Type::Pointer(p) | Type::ConstPointer(p) => is_byte(p),
                        _ => None,
                    };
                    if let (Some(chars), Some(next)) = (ptr_to_bytes, layout.get(i + 1))
                        && is_usize(&next.member.tref)
                    {
                        let ty = if chars { Wt::Str } else { Wt::Bytes };
                        fields.push(Field { name: ident(m.member.name.as_str()), offset: m.offset, ty, len_offset: Some(next.offset) });
                        i += 2;
                        continue;
                    }
                    let ty = match &**mt.type_() {
                        Type::Pointer(_) | Type::ConstPointer(_) => Wt::Prim(Prim::U32),
                        _ => wt(mt)?,
                    };
                    fields.push(Field { name: ident(m.member.name.as_str()), offset: m.offset, ty, len_offset: None });
                    i += 1;
                }
                Wt::Record { name: type_name(t).unwrap_or_else(|| "record".into()), size: r.mem_size(), fields }
            }
        },
        Type::List(_) | Type::Pointer(_) | Type::ConstPointer(_) => return Err("pointer in a value".into()),
    })
}

fn classify(module: &str, name: &str, f: &witx::InterfaceFunc, params: &[ValType], results: &[ValType]) -> Result<Sig, String> {
    let ps = &f.params;
    // A filled buffer reports its byte count as the success value.
    let returns_count = f.results.first().is_some_and(|r| match &**r.tref.type_() {
        Type::Variant(v) => v.as_expected().and_then(|(ok, _)| ok).is_some_and(|ok| matches!(&**ok.type_(), Type::Builtin(BuiltinType::U32 { .. }))),
        _ => false,
    });
    let mut slots = Vec::new();
    let mut i = 0;
    while i < ps.len() {
        let p = &ps[i];
        let pname = ident(p.name.as_str());
        let t = p.tref.type_();
        // The slot, and how many witx parameters it takes.
        let (slot, used) = match &**t {
            Type::Builtin(_) | Type::Handle(_) | Type::Variant(_) => (Slot::In { name: pname, ty: wt(&p.tref)? }, 1),
            Type::Record(r) if r.bitflags_repr().is_some() => (Slot::In { name: pname, ty: wt(&p.tref)? }, 1),
            Type::Record(_) => (Slot::InPtr { name: pname, ty: wt(&p.tref)? }, 1),
            Type::List(e) => {
                let ty = match (&**e.type_(), is_byte(e)) {
                    (_, Some(_)) => Wt::Bytes,
                    (Type::Builtin(BuiltinType::Char), _) => Wt::Str,
                    _ => Wt::List(Box::new(wt(e)?)),
                };
                (Slot::InList { name: pname, ty }, 1)
            }
            Type::ConstPointer(e) if is_byte(e).is_some() && ps.get(i + 1).is_some_and(|n| is_usize(&n.tref)) => {
                let ty = if is_byte(e) == Some(true) { Wt::Str } else { Wt::Bytes };
                (Slot::InList { name: pname, ty }, 2)
            }
            Type::Pointer(e) if is_byte(e).is_some() && ps.get(i + 1).is_some_and(|n| is_usize(&n.tref)) => {
                let string = is_byte(e) == Some(true);
                let cursor = ps.get(i + 2).is_some_and(|c| is_usize(&c.tref) && c.name.as_str().contains("cursor"))
                    && ps.get(i + 3).is_some_and(|c| points_to(&c.tref, |t| matches!(&**t.type_(), Type::Builtin(BuiltinType::S64))))
                    && ps.get(i + 4).is_some_and(|c| points_to(&c.tref, is_usize));
                if cursor {
                    (Slot::OutBuf { name: pname, string, cursor: true }, 5)
                } else if ps.get(i + 2).is_some_and(|c| points_to(&c.tref, is_usize)) {
                    (Slot::OutBuf { name: pname, string, cursor: false }, 3)
                } else if returns_count {
                    (Slot::ReadBuf { name: pname }, 2)
                } else {
                    (Slot::InList { name: pname, ty: if string { Wt::Str } else { Wt::Bytes } }, 2)
                }
            }
            Type::Pointer(e) | Type::ConstPointer(e) => {
                let ty = wt(e).map_err(|r| format!("{pname}: {r}"))?;
                // A record after flags (a mask or tag saying which fields are
                // set) is an options record the guest fills in.
                let after_flags = i > 0
                    && (ps[i - 1].name.as_str().ends_with("_mask")
                        || matches!(&**ps[i - 1].tref.type_(), Type::Record(r) if r.bitflags_repr().is_some()) && matches!(&**e.type_(), Type::Record(_)));
                let input = matches!(&**t, Type::ConstPointer(_)) || after_flags;
                if input { (Slot::InPtr { name: pname, ty }, 1) } else { (Slot::OutPtr { name: pname, ty }, 1) }
            }
        };
        i += used;
        slots.push(slot);
    }

    let mut status = None;
    let mut ok_outs = Vec::new();
    let mut ret = None;
    match f.results.as_slice() {
        [] => {}
        [r] => match &**r.tref.type_() {
            Type::Variant(v) if v.as_expected().is_some() => {
                let (ok, err) = v.as_expected().expect("checked");
                status = Some(err.and_then(status_of).ok_or("an expected without a status enum")?);
                if let Some(ok) = ok {
                    match &**ok.type_() {
                        Type::Record(rec) if rec.is_tuple() => {
                            for m in &rec.members {
                                ok_outs.push((ident(&type_name(&m.tref).unwrap_or_else(|| "value".into())), wt(&m.tref)?));
                            }
                        }
                        _ => ok_outs.push((ident(&type_name(ok).unwrap_or_else(|| "value".into())), wt(ok)?)),
                    }
                }
            }
            _ => ret = Some(wt(&r.tref)?),
        },
        _ => return Err("several results".into()),
    }
    // Unique output names (a tuple of two body handles).
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (n, _) in &mut ok_outs {
        let c = seen.entry(n.clone()).or_insert(0);
        *c += 1;
        if *c > 1 {
            *n = format!("{n}-{c}");
        }
    }
    let read = slots.iter().any(|s| matches!(s, Slot::ReadBuf { .. }));
    let read_count = read && matches!(ok_outs.as_slice(), [(_, Wt::Prim(Prim::U32))]);
    if read && !read_count {
        return Err("a buffer without a length".into());
    }
    let core: usize = slots.iter().map(Slot::width).sum::<usize>() + ok_outs.len();
    if core != params.len() {
        return Err(format!("{core} raw parameters classified, the ABI has {}", params.len()));
    }
    let doc = f.docs.trim().to_string();
    let param_docs = ps.iter().filter(|p| !p.docs.trim().is_empty()).map(|p| (ident(p.name.as_str()), p.docs.trim().to_string())).collect();
    let sig = Sig {
        module: module.into(),
        name: name.into(),
        slots,
        status,
        ok_outs,
        read_count,
        ret,
        params: params.to_vec(),
        results: results.to_vec(),
        doc,
        param_docs,
    };
    if sig.outputs().is_empty() && sig.status.is_none() && sig.ret.is_none() && !sig.results.is_empty() {
        return Err("unexpected results".into());
    }
    Ok(sig)
}

/// A witx name as a WIT identifier: `http_09` → `http09`, `send_v2` → `send-v2`.
pub fn ident(name: &str) -> String {
    let mut out = String::new();
    for seg in name.split(['_', '-']).filter(|s| !s.is_empty()) {
        let seg = seg.to_ascii_lowercase();
        if !out.is_empty() && !seg.starts_with(|c: char| c.is_ascii_digit()) {
            out.push('-');
        }
        out.push_str(&seg);
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) || out.is_empty() {
        out.insert(0, 'n');
    }
    out
}

/// The WIT type text, collecting named type definitions on the way.
fn wit_type(t: &Wt, defs: &mut BTreeMap<String, String>) -> String {
    match t {
        Wt::Prim(p) => p.wit().into(),
        Wt::Handle(_) => "u32".into(),
        Wt::Bytes => "list<u8>".into(),
        Wt::Str => "string".into(),
        Wt::List(e) => format!("list<{}>", wit_type(e, defs)),
        Wt::Enum { name, cases, .. } => {
            let n = ident(name);
            let body: Vec<String> = cases.iter().map(|c| format!("%{c}")).collect();
            defs.entry(n.clone()).or_insert_with(|| format!("enum %{n} {{ {} }}", body.join(", ")));
            format!("%{n}")
        }
        Wt::Flags { name, names, .. } => {
            let n = ident(name);
            let body: Vec<String> = names.iter().map(|c| format!("%{c}")).collect();
            defs.entry(n.clone()).or_insert_with(|| format!("flags %{n} {{ {} }}", body.join(", ")));
            format!("%{n}")
        }
        Wt::Record { name, fields, .. } => {
            let n = ident(name);
            if !defs.contains_key(&n) {
                defs.insert(n.clone(), String::new());
                let body: Vec<String> = fields.iter().map(|f| format!("%{}: {}", f.name, wit_type(&f.ty, defs))).collect();
                defs.insert(n.clone(), format!("record %{n} {{ {} }}", body.join(", ")));
            }
            format!("%{n}")
        }
    }
}

fn carrier_wit(sigs: &BTreeMap<String, Sig>, entry: Option<&str>) -> String {
    let mut by_module: BTreeMap<&str, Vec<&Sig>> = BTreeMap::new();
    for s in sigs.values() {
        by_module.entry(s.module.as_str()).or_default().push(s);
    }
    let mut out = String::from("package appfuzz:witx;\n\n");
    let mut world = String::from("world carrier {\n");
    for (module, fs) in &by_module {
        let mut defs = BTreeMap::new();
        let mut funcs = String::new();
        for s in fs {
            let params: Vec<String> = s.inputs().iter().map(|(n, t)| format!("%{n}: {}", wit_type(t, &mut defs))).collect();
            let outs = s.outputs();
            let ok = match outs.as_slice() {
                [] => None,
                [(_, t)] => Some(wit_type(t, &mut defs)),
                many => {
                    let rec = Wt::Record {
                        name: format!("{}-out", s.name),
                        size: 0,
                        fields: many.iter().map(|(n, t)| Field { name: n.clone(), offset: 0, ty: t.clone(), len_offset: None }).collect(),
                    };
                    Some(wit_type(&rec, &mut defs))
                }
            };
            let result = match (&s.status, ok, &s.ret) {
                (Some(st), ok, _) => {
                    let e = wit_type(&st.ty, &mut defs);
                    format!(" -> result<{}, {e}>", ok.unwrap_or_else(|| "_".into()))
                }
                (None, Some(ok), _) => format!(" -> {ok}"),
                (None, None, Some(r)) => format!(" -> {}", wit_type(r, &mut defs)),
                (None, None, None) => String::new(),
            };
            let _ = writeln!(funcs, "  %{}: func({}){result};", ident(&s.name), params.join(", "));
        }
        let iface = ident(module);
        let _ = writeln!(out, "interface %{iface} {{");
        for d in defs.values() {
            let _ = writeln!(out, "  {d}");
        }
        out.push_str(&funcs);
        out.push_str("}\n\n");
        let _ = writeln!(world, "  import %{iface};");
    }
    if let Some(e) = entry {
        let _ = writeln!(out, "interface entry {{\n{e}\n}}\n");
        world.push_str("  export entry;\n");
    }
    world.push_str("}\n");
    out.push_str(&world);
    out
}

/// Compiles the carrier and reads its imports, renamed to the witx names,
/// and its entry export (`entry#…`).
fn carrier_types(engine: &Engine, wit: &str, sigs: &BTreeMap<String, Sig>) -> Result<(Vec<Interface>, Vec<FuncInfo>)> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("carrier.wit", wit).context("carrier WIT")?;
    let world = resolve.select_world(&[pkg], Some("carrier"))?;
    let mut module = wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
    wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false)?;
    let bytes = wit_component::ComponentEncoder::default().module(&module)?.validate(true).encode()?;
    let component = Component::new(engine, &bytes).map_err(anyhow::Error::from).context("carrier component")?;
    let names: HashMap<(String, String), &Sig> = sigs.values().map(|s| ((ident(&s.module), ident(&s.name)), s)).collect();
    let mut out = Vec::new();
    for iface in crate::wit::imports(engine, &component) {
        let short = iface.name.rsplit('/').next().unwrap_or(&iface.name).to_string();
        let mut module = None;
        let funcs = iface
            .funcs
            .into_iter()
            .map(|f| {
                let s = names.get(&(short.clone(), f.name.clone())).ok_or_else(|| anyhow!("carrier function {} not in witx", f.name))?;
                module = Some(s.module.clone());
                Ok(FuncInfo { interface: s.module.clone(), name: s.name.clone(), key: s.key(), ty: f.ty })
            })
            .collect::<Result<Vec<_>>>()?;
        out.push(Interface { name: module.unwrap_or(short), kind: ImportKind::Platform, funcs });
    }
    let exports = crate::wit::exports(engine, &component)
        .into_iter()
        .map(|f| FuncInfo { interface: "entry".into(), key: format!("entry#{}", f.name), name: f.name, ty: f.ty })
        .collect();
    Ok((out, exports))
}

/// Why a raw argument could not be read: answered with a status.
#[derive(Debug)]
pub struct Fault(pub &'static str);

fn mem<'a>(m: &'a [u8], addr: u64, len: usize) -> Result<&'a [u8], Fault> {
    let start = usize::try_from(addr).map_err(|_| Fault("inval"))?;
    m.get(start..start.checked_add(len).ok_or(Fault("inval"))?).ok_or(Fault("inval"))
}

fn mem_mut<'a>(m: &'a mut [u8], addr: u64, len: usize) -> Result<&'a mut [u8], Fault> {
    let start = usize::try_from(addr).map_err(|_| Fault("inval"))?;
    m.get_mut(start..start.checked_add(len).ok_or(Fault("inval"))?).ok_or(Fault("inval"))
}

fn raw_u64(v: &wasmtime::Val) -> u64 {
    match v {
        wasmtime::Val::I32(x) => *x as u32 as u64,
        wasmtime::Val::I64(x) => *x as u64,
        wasmtime::Val::F32(x) => *x as u64,
        wasmtime::Val::F64(x) => *x,
        _ => 0,
    }
}

fn read_uint(m: &[u8], addr: u64, size: usize) -> Result<u64, Fault> {
    let b = mem(m, addr, size)?;
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(b);
    Ok(u64::from_le_bytes(buf))
}

fn write_uint(m: &mut [u8], addr: u64, size: usize, v: u64) -> Result<(), Fault> {
    mem_mut(m, addr, size)?.copy_from_slice(&v.to_le_bytes()[..size]);
    Ok(())
}

fn prim_val(p: Prim, bits: u64) -> Val {
    match p {
        Prim::U8 => Val::U8(bits as u8),
        Prim::U16 => Val::U16(bits as u16),
        Prim::U32 => Val::U32(bits as u32),
        Prim::U64 => Val::U64(bits),
        Prim::S8 => Val::S8(bits as i8),
        Prim::S16 => Val::S16(bits as i16),
        Prim::S32 => Val::S32(bits as i32),
        Prim::S64 => Val::S64(bits as i64),
        Prim::F32 => Val::Float32(f32::from_bits(bits as u32)),
        Prim::F64 => Val::Float64(f64::from_bits(bits)),
        Prim::Char => Val::Char(char::from_u32(bits as u32).unwrap_or('\u{fffd}')),
    }
}

fn val_bits(v: &Val) -> u64 {
    match v {
        Val::Bool(b) => *b as u64,
        Val::U8(x) => *x as u64,
        Val::U16(x) => *x as u64,
        Val::U32(x) => *x as u64,
        Val::U64(x) => *x,
        Val::S8(x) => *x as u8 as u64,
        Val::S16(x) => *x as u16 as u64,
        Val::S32(x) => *x as u32 as u64,
        Val::S64(x) => *x as u64,
        Val::Float32(x) => x.to_bits() as u64,
        Val::Float64(x) => x.to_bits(),
        Val::Char(c) => *c as u64,
        _ => 0,
    }
}

/// A value of `t` from its raw bits (one raw parameter).
fn from_bits(t: &Wt, bits: u64) -> Result<Val, Fault> {
    Ok(match t {
        Wt::Prim(p) => prim_val(*p, bits),
        Wt::Handle(_) => Val::U32(bits as u32),
        Wt::Enum { cases, raw, .. } => Val::Enum(cases[raw.iter().position(|r| *r == bits).ok_or(Fault("inval"))?].clone()),
        Wt::Flags { names, .. } => Val::Flags(names.iter().enumerate().filter(|(i, _)| bits >> i & 1 == 1).map(|(_, n)| n.clone()).collect()),
        _ => return Err(Fault("inval")),
    })
}

fn to_bits(t: &Wt, v: &Val) -> u64 {
    match (t, v) {
        (Wt::Enum { cases, raw, .. }, Val::Enum(c)) => cases.iter().position(|x| x == c).map(|i| raw[i]).unwrap_or(0),
        (Wt::Flags { names, .. }, Val::Flags(set)) => names.iter().enumerate().filter(|(_, n)| set.contains(n)).fold(0, |acc, (i, _)| acc | 1 << i),
        _ => val_bits(v),
    }
}

fn bytes_val(b: &[u8], string: bool) -> Result<Val, Fault> {
    Ok(if string { Val::String(std::str::from_utf8(b).map_err(|_| Fault("inval"))?.to_string()) } else { Val::List(b.iter().map(|x| Val::U8(*x)).collect()) })
}

fn val_bytes(v: &Val) -> Vec<u8> {
    match v {
        Val::String(s) => s.as_bytes().to_vec(),
        Val::List(items) => items.iter().map(|x| val_bits(x) as u8).collect(),
        _ => Vec::new(),
    }
}

/// Reads a value of `t` stored at `addr`.
fn read(m: &[u8], addr: u64, t: &Wt) -> Result<Val, Fault> {
    Ok(match t {
        Wt::Record { fields, .. } => {
            let mut out = Vec::new();
            for f in fields {
                let at = addr + f.offset as u64;
                let v = match (&f.ty, f.len_offset) {
                    (Wt::Str | Wt::Bytes, Some(lo)) => {
                        let ptr = read_uint(m, at, 4)?;
                        let len = read_uint(m, addr + lo as u64, 4)? as usize;
                        if ptr == 0 || len == 0 {
                            bytes_val(&[], matches!(f.ty, Wt::Str))?
                        } else {
                            let b = mem(m, ptr, len)?;
                            if matches!(f.ty, Wt::Str) { Val::String(String::from_utf8_lossy(b).into_owned()) } else { bytes_val(b, false)? }
                        }
                    }
                    _ => read(m, at, &f.ty)?,
                };
                out.push((f.name.clone(), v));
            }
            Val::Record(out)
        }
        Wt::Bytes | Wt::Str | Wt::List(_) => return Err(Fault("inval")),
        _ => from_bits(t, read_uint(m, addr, t.size())?)?,
    })
}

/// Writes a value of `t` at `addr`. Pointer fields in records are left alone.
fn write(m: &mut [u8], addr: u64, t: &Wt, v: &Val) -> Result<(), Fault> {
    match (t, v) {
        (Wt::Record { fields, .. }, Val::Record(vals)) => {
            for f in fields {
                if f.len_offset.is_some() {
                    continue;
                }
                if let Some((_, fv)) = vals.iter().find(|(n, _)| n == &f.name) {
                    write(m, addr + f.offset as u64, &f.ty, fv)?;
                }
            }
            Ok(())
        }
        (Wt::Record { .. } | Wt::Bytes | Wt::Str | Wt::List(_), _) => Err(Fault("inval")),
        _ => write_uint(m, addr, t.size(), to_bits(t, v)),
    }
}

/// The high-level arguments of a call, read from raw parameters and memory.
pub fn lift(sig: &Sig, m: &[u8], raw: &[wasmtime::Val]) -> Result<Vec<Val>, Fault> {
    let mut out = Vec::new();
    let mut i = 0;
    for s in &sig.slots {
        match s {
            Slot::In { ty, .. } => out.push(from_bits(ty, raw_u64(&raw[i]))?),
            Slot::InList { ty, .. } => {
                let (ptr, len) = (raw_u64(&raw[i]), raw_u64(&raw[i + 1]) as usize);
                out.push(match ty {
                    Wt::Str | Wt::Bytes => bytes_val(mem(m, ptr, len)?, matches!(ty, Wt::Str))?,
                    Wt::List(e) => {
                        let size = e.size();
                        let mut items = Vec::new();
                        for k in 0..len {
                            items.push(read(m, ptr + (k * size) as u64, e)?);
                        }
                        Val::List(items)
                    }
                    _ => return Err(Fault("inval")),
                });
            }
            Slot::InPtr { ty, .. } => out.push(read(m, raw_u64(&raw[i]), ty)?),
            _ => {}
        }
        i += s.width();
    }
    Ok(out)
}

/// The raw status (or direct result) for a failure before the host answered.
pub fn fault_result(status: Option<&Status>, fault: &Fault) -> Option<u64> {
    let st = status?;
    st.code(fault.0).or_else(|| st.code("error"))
}

/// Writes the call's high-level result (`results`, as the carrier types
/// them) to memory and returns the raw return value.
pub fn lower(sig: &Sig, m: &mut [u8], raw: &[wasmtime::Val], results: &[Val]) -> Result<Option<u64>, Fault> {
    let outs = sig.outputs();
    let (ok, status) = match (&sig.status, results.first()) {
        (Some(st), Some(Val::Result(r))) => match r {
            Ok(v) => (v.as_deref().cloned(), st.ok),
            Err(e) => return Ok(Some(e.as_deref().map(|e| to_bits(&st.ty, e)).unwrap_or_else(|| st.code("error").unwrap_or(1)))),
        },
        (Some(_), _) => return Err(Fault("error")),
        (None, Some(v)) if outs.is_empty() => return Ok(Some(to_bits(sig.ret.as_ref().unwrap_or(&Wt::Prim(Prim::U32)), v))),
        (None, v) => (v.cloned(), 0),
    };
    // The parts of the success value, in output order.
    let parts: Vec<Val> = match (outs.len(), ok) {
        (0, _) => vec![],
        (1, Some(v)) => vec![v],
        (_, Some(Val::Record(fields))) => fields.into_iter().map(|(_, v)| v).collect(),
        _ => return Err(Fault("error")),
    };
    let buflen = sig.status.as_ref().and_then(|s| s.code("buflen"));
    let mut part = parts.iter();
    let mut read_count = None;
    let mut i = 0;
    for s in &sig.slots {
        match s {
            Slot::OutBuf { cursor: false, .. } => {
                let bytes = val_bytes(part.next().ok_or(Fault("error"))?);
                let (ptr, max, nwritten) = (raw_u64(&raw[i]), raw_u64(&raw[i + 1]) as usize, raw_u64(&raw[i + 2]));
                write_uint(m, nwritten, 4, bytes.len() as u64)?;
                if bytes.len() > max {
                    return Ok(Some(buflen.unwrap_or(1)));
                }
                mem_mut(m, ptr, bytes.len())?.copy_from_slice(&bytes);
            }
            Slot::OutBuf { cursor: true, .. } => {
                let Val::List(items) = part.next().ok_or(Fault("error"))? else { return Err(Fault("error")) };
                let (ptr, max, cursor) = (raw_u64(&raw[i]), raw_u64(&raw[i + 1]) as usize, raw_u64(&raw[i + 2]) as usize);
                let (ending, nwritten) = (raw_u64(&raw[i + 3]), raw_u64(&raw[i + 4]));
                let mut buf = Vec::new();
                let mut next: i64 = -1;
                for (k, item) in items.iter().enumerate().skip(cursor) {
                    let b = val_bytes(item);
                    if buf.len() + b.len() + 1 > max {
                        if buf.is_empty() {
                            write_uint(m, nwritten, 4, (b.len() + 1) as u64)?;
                            return Ok(Some(buflen.unwrap_or(1)));
                        }
                        next = k as i64;
                        break;
                    }
                    buf.extend_from_slice(&b);
                    buf.push(0);
                }
                mem_mut(m, ptr, buf.len())?.copy_from_slice(&buf);
                write_uint(m, ending, 8, next as u64)?;
                write_uint(m, nwritten, 4, buf.len() as u64)?;
            }
            Slot::ReadBuf { .. } => {
                let bytes = val_bytes(part.next().ok_or(Fault("error"))?);
                let (ptr, len) = (raw_u64(&raw[i]), raw_u64(&raw[i + 1]) as usize);
                let n = bytes.len().min(len);
                mem_mut(m, ptr, n)?.copy_from_slice(&bytes[..n]);
                read_count = Some(n as u64);
            }
            Slot::OutPtr { ty, .. } => write(m, raw_u64(&raw[i]), ty, part.next().ok_or(Fault("error"))?)?,
            _ => {}
        }
        i += s.width();
    }
    if sig.read_count {
        write_uint(m, raw_u64(&raw[i]), 4, read_count.unwrap_or(0))?;
    } else {
        for (k, (_, ty)) in sig.ok_outs.iter().enumerate() {
            write(m, raw_u64(&raw[i + k]), ty, part.next().ok_or(Fault("error"))?)?;
        }
    }
    Ok(Some(status).filter(|_| sig.status.is_some()).or(None))
}

/// The most bytes a read-style call can take: the length of its buffer.
pub fn read_limit(sig: &Sig, raw: &[wasmtime::Val]) -> Option<usize> {
    let mut i = 0;
    for s in &sig.slots {
        if let Slot::ReadBuf { .. } = s {
            return raw.get(i + 1).map(|v| raw_u64(v) as usize);
        }
        i += s.width();
    }
    None
}

/// The positions of handles among a call's inputs and in its success value
/// (`None`: the success value itself; `Some(name)`: a field of it).
pub fn handle_inputs(sig: &Sig) -> Vec<(usize, String)> {
    sig.inputs().iter().enumerate().filter_map(|(i, (_, t))| t.handle().map(|k| (i, k.to_string()))).collect()
}

pub fn handle_outputs(sig: &Sig) -> Vec<(Option<String>, String)> {
    let outs = sig.outputs();
    let single = outs.len() == 1;
    outs.iter().filter_map(|(n, t)| t.handle().map(|k| (if single { None } else { Some(n.clone()) }, k.to_string()))).collect()
}

/// Checks that a module's import matches the witx signature.
pub fn check_import(sig_params: &[ValType], sig_results: &[ValType], ty: &wasmtime::FuncType) -> Result<()> {
    let same = |a: &[ValType], b: &mut dyn Iterator<Item = ValType>| {
        let b: Vec<ValType> = b.collect();
        a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| ValType::eq(x, y))
    };
    if !same(sig_params, &mut ty.params()) || !same(sig_results, &mut ty.results()) {
        bail!("signature differs from the witx");
    }
    Ok(())
}

/// The Fastly Compute ABI, vendored from Viceroy.
pub const FASTLY: &[(&str, &str)] = &[
    ("typenames.witx", include_str!("../platforms/fastly/witx/typenames.witx")),
    ("cache.witx", include_str!("../platforms/fastly/witx/cache.witx")),
    ("config-store.witx", include_str!("../platforms/fastly/witx/config-store.witx")),
    ("http-cache.witx", include_str!("../platforms/fastly/witx/http-cache.witx")),
    ("shielding.witx", include_str!("../platforms/fastly/witx/shielding.witx")),
    ("compute-at-edge.witx", include_str!("../platforms/fastly/witx/compute-at-edge.witx")),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idents() {
        assert_eq!(ident("http_09"), "http09");
        assert_eq!(ident("send_v2"), "send-v2");
        assert_eq!(ident("fastly_http_req"), "fastly-http-req");
        assert_eq!(ident("h2"), "h2");
    }

    #[test]
    fn fastly_abi_loads() {
        let doc = parse(FASTLY).unwrap();
        let engine = Engine::default();
        let p = load(&engine, &doc, Some("record request { uri: string }\nhandle: func(request: request) -> u16;")).unwrap();
        assert_eq!(p.exports.iter().map(|f| f.key.as_str()).collect::<Vec<_>>(), vec!["entry#handle"]);
        let get = &p.sigs["fastly_http_req#uri_get"];
        assert_eq!(get.inputs().len(), 1);
        assert!(matches!(get.outputs().as_slice(), [(_, Wt::Str)]));
        let send = &p.sigs["fastly_http_req#send_v2"];
        assert_eq!(send.inputs().iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec!["h", "b", "backend"]);
        assert_eq!(send.outputs().len(), 3);
        let names = &p.sigs["fastly_http_req#header_names_get"];
        assert!(matches!(names.outputs().as_slice(), [(_, Wt::List(_))]));
        assert!(p.sigs.contains_key("fastly_http_req#body_downstream_get"));
        let funcs: usize = p.imports.iter().map(|i| i.funcs.len()).sum();
        assert_eq!(funcs, p.sigs.len());
        let unsupported: Vec<String> = p.unsupported.values().map(|u| format!("{}#{}: {}", u.module, u.name, u.reason)).collect();
        assert!(unsupported.is_empty(), "{unsupported:?}");
        assert!(p.sigs["fastly_http_body#read"].read_count);
        assert!(matches!(p.sigs["fastly_secret_store#from_bytes"].inputs().as_slice(), [(_, Wt::Str)]));
        let documented = p.sigs.values().filter(|s| !s.doc.is_empty()).count();
        eprintln!("documented {documented} of {}", p.sigs.len());
        assert!(documented > 0);
    }
}
