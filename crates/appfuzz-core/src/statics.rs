//! Static analysis of the core modules inside a component: functions,
//! direct call graph, host call sites, loops that reach host calls (static
//! n+1 candidates), strings in data segments, and a plain disassembly.
//!
//! Module ids match the ids in run frames (see `record::module_id`), so an
//! agent can go from "host call 5 came from m1234:40" to the code.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use wasmparser::{
    ExternalKind, FunctionBody, KnownCustom, Name, Operator, Parser, Payload, TypeRef,
};

use crate::manifest::fn_key;
use crate::record::{Frame, module_id};
use crate::wit::is_wasi;

#[derive(Debug, Clone, Serialize)]
pub struct Statics {
    pub modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub id: String,
    /// Position among the component's core modules.
    pub index: usize,
    /// `main` (most code), `shim` (only indirect-call trampolines),
    /// `fixup` (no code), or `other`.
    pub role: String,
    /// Byte range in the component file.
    pub start: u64,
    pub end: u64,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<(String, String, u32)>,
    pub func_imports: u32,
    pub funcs: Vec<FuncInfo>,
    #[serde(skip)]
    pub strings: Vec<(u64, String)>,
    pub has_names: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportInfo {
    pub module: String,
    pub name: String,
    pub kind: String,
    /// Function index if a function import.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub func: Option<u32>,
    /// `interface#function` for a platform host function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuncInfo {
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Body byte range in the component file.
    pub start: u64,
    pub end: u64,
    /// Direct calls: (callee function index, offset in component file).
    #[serde(skip)]
    pub calls: Vec<(u32, u64)>,
    pub call_indirect: u32,
    #[serde(skip)]
    pub loops: Vec<LoopInfo>,
    pub instructions: u32,
    /// Integer constants that read as ASCII text (short string literals
    /// compiled into compares), joined when they follow each other.
    #[serde(skip)]
    pub text_consts: Vec<(u64, String)>,
    /// Integer constants the code compares against (`x == 13`).
    #[serde(skip)]
    pub cmp_consts: Vec<i64>,
    /// Constants of known hash and checksum functions (`FNV-1a`, …).
    #[serde(skip)]
    pub magic: Vec<&'static str>,
}

/// Constants that give away a hash or checksum: a trigger that compares a
/// hash of its input hides the value it waits for. SipHash (Rust's
/// HashMap) is left out on purpose.
pub const MAGIC: &[(u64, &str)] = &[
    (0xcbf29ce484222325, "FNV-1a"),
    (0x100000001b3, "FNV-1a"),
    (0x811c9dc5, "FNV-1a"),
    (0x01000193, "FNV-1a"),
    (0xcc9e2d51, "MurmurHash3"),
    (0x1b873593, "MurmurHash3"),
    (0x85ebca6b, "MurmurHash3"),
    (0xc2b2ae35, "MurmurHash3"),
    (0xff51afd7ed558ccd, "MurmurHash3"),
    (0xc4ceb9fe1a85ec53, "MurmurHash3"),
    (0x5bd1e995, "MurmurHash2"),
    (0xc6a4a7935bd1e995, "MurmurHash2"),
    (0x9e3779b1, "xxHash"),
    (0x85ebca77, "xxHash"),
    (0x9e3779b185ebca87, "xxHash"),
    (0xc2b2ae3d27d4eb4f, "xxHash"),
    (0x428a2f98, "SHA-256"),
    (0x6a09e667, "SHA-256"),
    (0xbb67ae85, "SHA-256"),
    (0x6a09e667f3bcc908, "SHA-512"),
    (0x67452301, "MD5/SHA-1"),
    (0xefcdab89, "MD5/SHA-1"),
    (0xd76aa478, "MD5"),
    (0x5a827999, "SHA-1"),
    (0xedb88320, "CRC-32"),
    (0x04c11db7, "CRC-32"),
    (0x82f63b78, "CRC-32C"),
];

fn magic_of(v: u64) -> Option<&'static str> {
    MAGIC.iter().find(|(c, _)| *c == v).map(|(_, n)| *n)
}

#[derive(Debug, Clone, Serialize)]
pub struct LoopInfo {
    pub start: u64,
    pub end: u64,
    /// Direct calls made inside the loop (callee, offset).
    pub calls: Vec<(u32, u64)>,
    pub call_indirect: u32,
    pub depth: u32,
}

impl Statics {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut modules: Vec<ModuleInfo> = Vec::new();
        // Stack of modules being parsed (core modules do not nest, but
        // components may nest components).
        let mut cur: Option<ModuleInfo> = None;
        let mut depth = 0usize;
        let mut cur_depth = usize::MAX;
        let mut func_types: Vec<u32> = Vec::new();
        let mut next_func = 0u32;
        let mut is_component = false;
        for payload in Parser::new(0).parse_all(bytes) {
            let payload = payload.context("parsing the component")?;
            match payload {
                Payload::Version { encoding, range, .. } => {
                    depth += 1;
                    if depth == 1 {
                        is_component = matches!(encoding, wasmparser::Encoding::Component);
                    }
                    if matches!(encoding, wasmparser::Encoding::Module) {
                        cur = Some(ModuleInfo {
                            id: String::new(),
                            index: modules.len(),
                            role: String::new(),
                            start: range.start,
                            end: range.end,
                            imports: vec![],
                            exports: vec![],
                            func_imports: 0,
                            funcs: vec![],
                            strings: vec![],
                            has_names: false,
                        });
                        cur_depth = depth;
                        func_types.clear();
                        next_func = 0;
                    }
                }
                Payload::End(offset) => {
                    if depth == cur_depth
                        && let Some(mut m) = cur.take()
                    {
                        m.end = offset;
                        m.id = module_id(
                            m.imports.iter().map(|i| (i.module.as_str(), i.name.as_str())),
                            m.exports.iter().map(|e| e.0.as_str()),
                        );
                        modules.push(m);
                        cur_depth = usize::MAX;
                    }
                    depth -= 1;
                }
                Payload::ImportSection(r) if cur.is_some() => {
                    let m = cur.as_mut().expect("module");
                    for imp in r.into_imports() {
                        let imp = imp?;
                        let (kind, func) = match imp.ty {
                            TypeRef::Func(_) | TypeRef::FuncExact(_) => {
                                let f = next_func;
                                next_func += 1;
                                m.func_imports += 1;
                                ("func", Some(f))
                            }
                            TypeRef::Memory(_) => ("memory", None),
                            TypeRef::Table(_) => ("table", None),
                            TypeRef::Global(_) => ("global", None),
                            TypeRef::Tag(_) => ("tag", None),
                        };
                        let host = (func.is_some() && is_platform_module(imp.module) && !imp.name.starts_with('['))
                            .then(|| fn_key(imp.module, imp.name));
                        m.imports.push(ImportInfo {
                            module: imp.module.to_string(),
                            name: imp.name.to_string(),
                            kind: kind.to_string(),
                            func,
                            host,
                        });
                    }
                }
                Payload::FunctionSection(r) if cur.is_some() => {
                    for t in r {
                        func_types.push(t?);
                    }
                }
                Payload::ExportSection(r) if cur.is_some() => {
                    let m = cur.as_mut().expect("module");
                    for e in r {
                        let e = e?;
                        let kind = match e.kind {
                            ExternalKind::Func | ExternalKind::FuncExact => "func",
                            ExternalKind::Memory => "memory",
                            ExternalKind::Table => "table",
                            ExternalKind::Global => "global",
                            ExternalKind::Tag => "tag",
                        };
                        m.exports.push((e.name.to_string(), kind.to_string(), e.index));
                    }
                }
                Payload::CodeSectionEntry(body) if cur.is_some() => {
                    let m = cur.as_mut().expect("module");
                    let index = m.func_imports + m.funcs.len() as u32;
                    m.funcs.push(scan_body(index, &body)?);
                }
                Payload::DataSection(r) if cur.is_some() => {
                    let m = cur.as_mut().expect("module");
                    for d in r {
                        let d = d?;
                        m.strings.extend(strings_in(d.data, d.range.end - d.data.len() as u64, 4));
                    }
                }
                Payload::CustomSection(c) if cur.is_some() => {
                    if let KnownCustom::Name(names) = c.as_known() {
                        let m = cur.as_mut().expect("module");
                        for n in names {
                            if let Ok(Name::Function(map)) = n {
                                m.has_names = true;
                                for naming in map.into_iter().flatten() {
                                    if let Some(f) = m.funcs.iter_mut().find(|f| f.index == naming.index) {
                                        f.name = Some(naming.name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let _ = is_component;
        let biggest = modules.iter().map(|m| m.funcs.iter().map(|f| f.end - f.start).sum::<u64>()).max().unwrap_or(0);
        for m in &mut modules {
            let code: u64 = m.funcs.iter().map(|f| f.end - f.start).sum();
            m.role = if m.funcs.is_empty() {
                "fixup"
            } else if code == biggest {
                "main"
            } else if m.funcs.iter().all(|f| f.call_indirect > 0 && f.instructions < 40) {
                "shim"
            } else {
                "other"
            }
            .to_string();
        }
        Ok(Statics { modules })
    }

    pub fn module(&self, id: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.id == id || m.index.to_string() == id)
    }

    pub fn main(&self) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.role == "main")
    }

    /// The first frame of a stack that is app code (not a shim or adapter).
    pub fn app_frame<'a>(&self, stack: &'a [Frame]) -> Option<&'a Frame> {
        stack.iter().find(|f| self.module(&f.module).is_some_and(|m| m.role == "main" || m.role == "other")).or(stack.first())
    }

    /// `name` or `module:index` of a frame's function.
    pub fn frame_name(&self, f: &Frame) -> String {
        if let Some(n) = &f.name {
            return demangle(n);
        }
        self.module(&f.module)
            .and_then(|m| m.func_name(f.func))
            .unwrap_or_else(|| format!("{}:{}", f.module, f.func))
    }
}

impl ModuleInfo {
    pub fn func(&self, index: u32) -> Option<&FuncInfo> {
        index.checked_sub(self.func_imports).and_then(|i| self.funcs.get(i as usize))
    }

    pub fn import_of(&self, index: u32) -> Option<&ImportInfo> {
        self.imports.iter().find(|i| i.func == Some(index))
    }

    /// A readable name for any function index (import or defined).
    pub fn func_name(&self, index: u32) -> Option<String> {
        if let Some(i) = self.import_of(index) {
            return Some(i.host.clone().unwrap_or_else(|| format!("{}#{}", i.module, i.name)));
        }
        let f = self.func(index)?;
        if let Some(n) = &f.name {
            return Some(demangle(n));
        }
        self.exports.iter().find(|e| e.1 == "func" && e.2 == index).map(|e| format!("export {}", e.0))
    }

    pub fn label(&self, index: u32) -> String {
        self.func_name(index).unwrap_or_else(|| format!("{}:{index}", self.id))
    }

    /// Host functions (by key) each function reaches through direct calls.
    pub fn host_reach(&self) -> BTreeMap<u32, BTreeSet<String>> {
        let mut reach: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
        for imp in &self.imports {
            if let (Some(f), Some(h)) = (imp.func, &imp.host) {
                reach.entry(f).or_default().insert(h.clone());
            }
        }
        // Fixpoint over the call graph (handles recursion).
        loop {
            let mut changed = false;
            for f in &self.funcs {
                let mut acc: BTreeSet<String> = reach.get(&f.index).cloned().unwrap_or_default();
                let before = acc.len();
                for (callee, _) in &f.calls {
                    if let Some(s) = reach.get(callee) {
                        acc.extend(s.iter().cloned());
                    }
                }
                if acc.len() != before {
                    reach.insert(f.index, acc);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        reach
    }

    /// Callers of each function index.
    pub fn callers(&self) -> BTreeMap<u32, Vec<(u32, u64)>> {
        let mut out: BTreeMap<u32, Vec<(u32, u64)>> = BTreeMap::new();
        for f in &self.funcs {
            for (callee, off) in &f.calls {
                out.entry(*callee).or_default().push((f.index, *off));
            }
        }
        out
    }

    /// The function whose body contains a component-file offset.
    pub fn func_at(&self, offset: u64) -> Option<&FuncInfo> {
        self.funcs.iter().find(|f| f.start <= offset && offset < f.end)
    }
}

fn is_platform_module(module: &str) -> bool {
    module.contains(':') && !is_wasi(module)
}

fn scan_body(index: u32, body: &FunctionBody<'_>) -> Result<FuncInfo> {
    let range = body.range();
    let mut f = FuncInfo {
        index,
        name: None,
        start: range.start,
        end: range.end,
        calls: vec![],
        call_indirect: 0,
        loops: vec![],
        instructions: 0,
        text_consts: vec![],
        cmp_consts: vec![],
        magic: vec![],
    };
    // The integer constant pushed by the previous instruction.
    let mut pending: Option<i64> = None;
    // (offset, text, instruction number) of the last text constant.
    let mut last: Option<(u64, String, u32)> = None;
    // Open blocks: Some(loop index) for loops, None for other blocks.
    let mut stack: Vec<Option<usize>> = Vec::new();
    let mut ops = body.get_operators_reader()?;
    while !ops.eof() {
        let (op, offset) = ops.read_with_offset()?;
        f.instructions += 1;
        if let Some(c) = pending.take()
            && is_compare(&op)
            && !f.cmp_consts.contains(&c)
        {
            f.cmp_consts.push(c);
        }
        let konst = match &op {
            Operator::I32Const { value } => Some((*value as i64, *value as u32 as u64)),
            Operator::I64Const { value } => Some((*value, *value as u64)),
            _ => None,
        };
        if let Some((v, bits)) = konst {
            pending = Some(v);
            if let Some(n) = magic_of(bits)
                && !f.magic.contains(&n)
            {
                f.magic.push(n);
            }
        }
        match op {
            Operator::Block { .. } | Operator::If { .. } | Operator::TryTable { .. } => stack.push(None),
            Operator::Loop { .. } => {
                let depth = stack.iter().filter(|s| s.is_some()).count() as u32;
                f.loops.push(LoopInfo { start: offset, end: offset, calls: vec![], call_indirect: 0, depth });
                stack.push(Some(f.loops.len() - 1));
            }
            Operator::End => {
                if let Some(Some(l)) = stack.pop() {
                    f.loops[l].end = offset;
                }
            }
            Operator::I32Const { value } => text_const(&(value as u32).to_le_bytes(), offset, f.instructions, &mut f.text_consts, &mut last),
            Operator::I64Const { value } => text_const(&(value as u64).to_le_bytes(), offset, f.instructions, &mut f.text_consts, &mut last),
            Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
                f.calls.push((function_index, offset));
                for l in stack.iter().flatten() {
                    f.loops[*l].calls.push((function_index, offset));
                }
            }
            Operator::CallIndirect { .. } | Operator::ReturnCallIndirect { .. } | Operator::CallRef { .. } => {
                f.call_indirect += 1;
                for l in stack.iter().flatten() {
                    f.loops[*l].call_indirect += 1;
                }
            }
            _ => {}
        }
    }
    Ok(f)
}

fn is_compare(op: &Operator<'_>) -> bool {
    use Operator::*;
    matches!(
        op,
        I32Eq | I32Ne | I32LtS | I32LtU | I32GtS | I32GtU | I32LeS | I32LeU | I32GeS | I32GeU
            | I64Eq | I64Ne | I64LtS | I64LtU | I64GtS | I64GtU | I64LeS | I64LeU | I64GeS | I64GeU
    )
}

/// Records an integer constant whose bytes are printable text (at least two
/// letters), and the joined text of constants that follow each other.
fn text_const(bytes: &[u8], offset: u64, at: u32, out: &mut Vec<(u64, String)>, last: &mut Option<(u64, String, u32)>) {
    let len = bytes.iter().rposition(|b| *b != 0).map(|i| i + 1).unwrap_or(0);
    let b = &bytes[..len];
    if len == 0 || !b.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
        return;
    }
    // Text on its own needs two letters; a shorter piece only extends the
    // text before it (`"csv"` is compared as `"cs"`, then `'v'`).
    let standalone = len >= 2 && b.iter().filter(|c| c.is_ascii_alphabetic()).count() >= 2;
    let text = String::from_utf8_lossy(b).into_owned();
    if standalone {
        out.push((offset, text.clone()));
    }
    match last.take() {
        Some((o, prev, n)) if at - n <= 8 => {
            let joined = format!("{prev}{text}");
            out.push((o, joined.clone()));
            *last = Some((o, joined, at));
        }
        _ if standalone => *last = Some((offset, text, at)),
        _ => {}
    }
}

/// Printable runs of at least `min` characters in a data segment.
pub fn strings_in(data: &[u8], base: u64, min: usize) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let start = i;
        while i < data.len() && (data[i] == b'\t' || data[i] == b'\n' || (0x20..0x7f).contains(&data[i]) || data[i] >= 0x80) {
            i += 1;
        }
        // A run may hold bytes that are not UTF-8 (lengths, pointers ≥ 0x80
        // next to the text): keep the valid pieces.
        let mut at = start;
        for piece in data[start..i].utf8_chunks() {
            let s = piece.valid();
            if s.chars().count() >= min && s.chars().filter(|c| c.is_alphanumeric()).count() * 2 >= s.chars().count() {
                out.push((base + at as u64, s.to_string()));
            }
            at += s.len() + piece.invalid().len();
        }
        i += 1;
    }
    out
}

/// A function's instructions, one per line, with calls annotated.
pub fn disasm(bytes: &[u8], statics: &Statics, module: &str, func: u32) -> Result<Vec<String>> {
    let m = statics.module(module).ok_or_else(|| anyhow!("no module {module}"))?;
    let f = m.func(func).ok_or_else(|| anyhow!("{module} has no defined function {func}"))?;
    let mut lines = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload?
            && body.range().start == f.start
        {
            let mut ops = body.get_operators_reader()?;
            let mut indent = 0usize;
            while !ops.eof() {
                let (op, offset) = ops.read_with_offset()?;
                if matches!(op, Operator::End | Operator::Else) {
                    indent = indent.saturating_sub(1);
                }
                let text = match &op {
                    Operator::Call { function_index } => format!("call {} ;; {}", function_index, m.label(*function_index)),
                    other => format!("{other:?}"),
                };
                lines.push(format!("{offset:>8x}  {}{}", "  ".repeat(indent), text));
                if matches!(op, Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } | Operator::Else | Operator::TryTable { .. }) {
                    indent += 1;
                }
            }
            return Ok(lines);
        }
    }
    Err(anyhow!("function body not found"))
}

/// Rust symbol names (legacy and v0) without hashes: `a::b::h0123…` or
/// `_RNv…3app4tree` → `app::tree`. Other names stay as they are.
pub fn demangle(name: &str) -> String {
    match rustc_demangle::try_demangle(name) {
        Ok(d) => format!("{d:#}"),
        Err(_) => match name.rsplit_once("::h") {
            Some((head, hash)) if hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit()) => head.to_string(),
            _ => name.to_string(),
        },
    }
}
