//! What a component imports and exports, read from its own type
//! information, with WIT-like signatures for humans and agents.

use serde::Serialize;
use wasmtime::Engine;
use wasmtime::component::types::{ComponentFunc, ComponentItem};
use wasmtime::component::{Component, Type};

use crate::manifest::fn_key;

/// One function of an imported or exported interface.
#[derive(Clone)]
pub struct FuncInfo {
    /// Full interface name with version, empty for top-level functions.
    pub interface: String,
    pub name: String,
    /// `interface#function` without version.
    pub key: String,
    pub ty: ComponentFunc,
}

impl FuncInfo {
    pub fn signature(&self) -> String {
        signature(&self.name, &self.ty)
    }

    pub fn param_names(&self) -> Vec<String> {
        self.ty.params().map(|(n, _)| n.to_string()).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportKind {
    /// A platform interface: simulated host functions. Also the WASI
    /// interfaces the platform provides (`wasi:keyvalue`, `wasi:config`).
    Platform,
    /// WASI the runtime provides: clocks, streams, files, sockets, HTTP.
    Wasi,
}

/// An imported interface (component instance) and its functions.
#[derive(Clone)]
pub struct Interface {
    pub name: String,
    pub kind: ImportKind,
    pub funcs: Vec<FuncInfo>,
}

/// The standard WASI command entry, including its exact result contract.
pub fn is_cli_run(f: &FuncInfo) -> bool {
    if f.interface.split('@').next() != Some("wasi:cli/run") || f.name != "run" || f.ty.params().next().is_some() {
        return false;
    }
    let mut results = f.ty.results();
    matches!(results.next(),Some(Type::Result(r)) if r.ok().is_none()&&r.err().is_none()) && results.next().is_none()
}

pub fn is_wasi(name: &str) -> bool {
    name.starts_with("wasi:")
}

/// WASI packages the runtime provides (wasmtime-wasi, and appfuzz's
/// wasi:http). Other WASI interfaces (`wasi:keyvalue`, `wasi:config`,
/// `wasi:blobstore`) are the platform's services, simulated like its own.
const RUNTIME_WASI: [&str; 7] = ["wasi:cli", "wasi:clocks", "wasi:filesystem", "wasi:http", "wasi:io", "wasi:random", "wasi:sockets"];

/// Whether an import is WASI the runtime provides, not a platform service.
pub fn is_runtime_wasi(name: &str) -> bool {
    RUNTIME_WASI.contains(&name.split(['/', '@']).next().unwrap_or(name))
}

pub fn imports(engine: &Engine, component: &Component) -> Vec<Interface> {
    let mut out = Vec::new();
    let mut top = Vec::new();
    for (name, item) in component.component_type().imports(engine) {
        match item.ty {
            ComponentItem::ComponentInstance(inst) => {
                let funcs = inst
                    .exports(engine)
                    .filter_map(|(f, item)| match item.ty {
                        ComponentItem::ComponentFunc(ty) => Some(FuncInfo { interface: name.to_string(), name: f.to_string(), key: fn_key(name, f), ty }),
                        _ => None,
                    })
                    .collect();
                let kind = if is_runtime_wasi(name) { ImportKind::Wasi } else { ImportKind::Platform };
                out.push(Interface { name: name.to_string(), kind, funcs });
            }
            ComponentItem::ComponentFunc(ty) => {
                top.push(FuncInfo { interface: String::new(), name: name.to_string(), key: name.to_string(), ty });
            }
            _ => {}
        }
    }
    if !top.is_empty() {
        out.push(Interface { name: String::new(), kind: ImportKind::Platform, funcs: top });
    }
    out
}

/// Exported functions, flattened to `interface#function` (or the bare
/// name for top-level functions).
pub fn exports(engine: &Engine, component: &Component) -> Vec<FuncInfo> {
    let mut out = Vec::new();
    for (name, item) in component.component_type().exports(engine) {
        match item.ty {
            ComponentItem::ComponentInstance(inst) => {
                for (f, item) in inst.exports(engine) {
                    if let ComponentItem::ComponentFunc(ty) = item.ty {
                        out.push(FuncInfo { interface: name.to_string(), name: f.to_string(), key: fn_key(name, f), ty });
                    }
                }
            }
            ComponentItem::ComponentFunc(ty) => {
                out.push(FuncInfo { interface: String::new(), name: name.to_string(), key: name.to_string(), ty });
            }
            _ => {}
        }
    }
    out
}

/// `list-for-day: func(date: string) -> result<list<record {…}>, string>`
pub fn signature(name: &str, ty: &ComponentFunc) -> String {
    let params: Vec<String> = ty.params().map(|(n, t)| format!("{n}: {}", type_str(&t))).collect();
    let results: Vec<String> = ty.results().map(|t| type_str(&t)).collect();
    let ret = match results.len() {
        0 => String::new(),
        1 => format!(" -> {}", results[0]),
        _ => format!(" -> ({})", results.join(", ")),
    };
    format!("{name}: func({}){ret}", params.join(", "))
}

/// A WIT-like rendering of a type. Records and variants are anonymous here;
/// `appfuzz inspect --wit` prints the named WIT.
pub fn type_str(ty: &Type) -> String {
    match ty {
        Type::Bool => "bool".into(),
        Type::S8 => "s8".into(),
        Type::U8 => "u8".into(),
        Type::S16 => "s16".into(),
        Type::U16 => "u16".into(),
        Type::S32 => "s32".into(),
        Type::U32 => "u32".into(),
        Type::S64 => "s64".into(),
        Type::U64 => "u64".into(),
        Type::Float32 => "f32".into(),
        Type::Float64 => "f64".into(),
        Type::Char => "char".into(),
        Type::String => "string".into(),
        Type::List(l) => format!("list<{}>", type_str(&l.ty())),
        Type::Map(m) => format!("map<{}, {}>", type_str(&m.key()), type_str(&m.value())),
        Type::FixedLengthList(l) => format!("list<{}, {}>", type_str(&l.ty()), l.len()),
        Type::Record(r) => {
            let fields: Vec<String> = r.fields().map(|f| format!("{}: {}", f.name, type_str(&f.ty))).collect();
            format!("record {{ {} }}", fields.join(", "))
        }
        Type::Tuple(t) => format!("tuple<{}>", t.types().map(|t| type_str(&t)).collect::<Vec<_>>().join(", ")),
        Type::Variant(v) => {
            let cases: Vec<String> = v
                .cases()
                .map(|c| match &c.ty {
                    Some(t) => format!("{}({})", c.name, type_str(t)),
                    None => c.name.to_string(),
                })
                .collect();
            format!("variant {{ {} }}", cases.join(", "))
        }
        Type::Enum(e) => format!("enum {{ {} }}", e.names().collect::<Vec<_>>().join(", ")),
        Type::Option(o) => format!("option<{}>", type_str(&o.ty())),
        Type::Result(r) => match (r.ok(), r.err()) {
            (None, None) => "result".into(),
            (Some(ok), None) => format!("result<{}>", type_str(&ok)),
            (None, Some(err)) => format!("result<_, {}>", type_str(&err)),
            (Some(ok), Some(err)) => format!("result<{}, {}>", type_str(&ok), type_str(&err)),
        },
        Type::Flags(f) => format!("flags {{ {} }}", f.names().collect::<Vec<_>>().join(", ")),
        Type::Own(_) => "own<resource>".into(),
        Type::Borrow(_) => "borrow<resource>".into(),
        Type::Future(f) => f.ty().map_or_else(|| "future".into(), |t| format!("future<{}>", type_str(&t))),
        Type::Stream(s) => s.ty().map_or_else(|| "stream".into(), |t| format!("stream<{}>", type_str(&t))),
        Type::ErrorContext => "error-context".into(),
    }
}

/// The component's world as WIT text, with named types and docs, if it can
/// be decoded.
pub fn wit_text(bytes: &[u8]) -> Option<String> {
    let decoded = wit_component::decode(bytes).ok()?;
    let resolve = decoded.resolve();
    let mut printer = wit_component::WitPrinter::default();
    let ids: Vec<_> = resolve.packages.iter().map(|(id, _)| id).collect();
    let main = decoded.package();
    let nested: Vec<_> = ids.into_iter().filter(|id| *id != main).collect();
    printer.print(resolve, main, &nested).ok()?;
    Some(printer.output.to_string())
}
