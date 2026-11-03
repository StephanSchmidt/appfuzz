//! Binary-only search instrumentation. Private memories, appended functions;
//! original indices/imports stay unchanged. Nothing here supplies finding evidence.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
};
use wasm_encoder::{
    self as enc, Instruction as I,
    reencode::{Error, Reencode, ReencodeComponent, component_utils, utils},
};
use wasmparser::{Operator as O, Parser, Payload, TypeRef};

pub const MAP: usize = 16_384;
pub const LOG: usize = 256;
const BASE: usize = 16 + MAP;
const DEDUP: usize = BASE + LOG * 32;
pub const BUFFER: usize = DEDUP + 2048;
const READ: &str = "__appfuzz_read";
const MEMORY: &str = "__appfuzz_memory";
const PREFIX: &str = "appfuzz-feedback-m";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Feedback {
    pub hits: BTreeSet<u32>,
    pub comparisons: Vec<Comparison>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub site: u32,
    pub width: u8,
    pub left: u64,
    pub right: u64,
}
impl Feedback {
    pub fn decode(&mut self, bytes: &[u8], module: u32) -> Result<()> {
        if bytes.len() != BUFFER {
            bail!("invalid feedback buffer length");
        }
        for (i, v) in bytes[16..BASE].iter().enumerate() {
            if *v != 0 {
                self.hits.insert(module * (MAP as u32) + i as u32);
            }
        }
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        if count > LOG {
            bail!("invalid feedback log count");
        }
        for entry in bytes[BASE..BASE + count * 32].as_chunks::<32>().0 {
            let u = |i| u64::from_le_bytes(entry[i..i + 8].try_into().unwrap());
            self.comparisons.push(Comparison { site: u(0) as u32, width: if u(24) == 1 { 32 } else { 64 }, left: u(8), right: u(16) });
        }
        Ok(())
    }
    pub fn progress(&self) -> Option<(String, u64)> {
        if self.comparisons.is_empty() {
            return None;
        }
        let mut sites = BTreeMap::<u32, u32>::new();
        for c in &self.comparisons {
            let bits = (c.left ^ c.right).count_ones();
            sites.entry(c.site).and_modify(|v| *v = (*v).min(bits)).or_insert(bits);
        }
        let ids: Vec<u32> = sites.keys().copied().collect();
        let key = blake3::hash(&serde_json::to_vec(&ids).unwrap()).to_hex()[..16].to_string();
        Some((key, sites.values().map(|v| *v as u64).sum()))
    }
    pub fn features(&self) -> BTreeSet<String> {
        let mut f: BTreeSet<_> = self.hits.iter().map(|x| format!("branch:{x}")).collect();
        for c in &self.comparisons {
            // Value profiles reward getting closer without pretending operands
            // are input taint. Dictionary substitutions are attempted separately.
            f.insert(format!("cmp:{}:{}:{}", c.site, (c.left ^ c.right).count_ones(), c.left.cmp(&c.right) as i8));
        }
        f
    }
}
pub struct Instrumented {
    pub bytes: Vec<u8>,
    pub readers: Vec<String>,
    pub sites: u32,
    pub skipped: Vec<String>,
}

/// Only core modules directly instantiated in this component are rewritten.
/// Nested components/imported modules remain opaque and are reported explicitly.
pub fn instrument(bytes: &[u8]) -> Result<Instrumented> {
    let types = wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all()).validate_all(bytes)?;
    let root = types.as_ref();
    let mut re = ComponentEncoder { modules: BTreeMap::new(), module_index: 0, instance_index: 0, readers: vec![], sites: 0, skipped: vec![] };
    let mut out = enc::Component::new();
    re.parse_component(&mut out, Parser::new(0), bytes).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut names = Vec::new();
    for (ordinal, instance) in re.readers.iter().enumerate() {
        let ordinal_index = ordinal as u32;
        let type_index = root.component_type_count() + ordinal_index * 2;
        let func_index = root.function_count() + ordinal_index;
        let memory_index = root.memory_count() + ordinal_index;
        let component_func = root.component_function_count() + ordinal_index;
        let name = format!("{PREFIX}{ordinal}");
        let mut aliases = enc::ComponentAliasSection::new();
        aliases.alias(enc::Alias::CoreInstanceExport { instance: *instance, kind: enc::ExportKind::Func, name: READ });
        aliases.alias(enc::Alias::CoreInstanceExport { instance: *instance, kind: enc::ExportKind::Memory, name: MEMORY });
        out.section(&aliases);
        let mut ts = enc::ComponentTypeSection::new();
        ts.defined_type().list(enc::PrimitiveValType::U8);
        ts.function().params(std::iter::empty::<(&str, enc::ComponentValType)>()).result(Some(enc::ComponentValType::Type(type_index)));
        out.section(&ts);
        let mut cs = enc::CanonicalFunctionSection::new();
        cs.lift(func_index, type_index + 1, [enc::CanonicalOption::Memory(memory_index)]);
        out.section(&cs);
        let mut exports = enc::ComponentExportSection::new();
        exports.export(name.as_str(), enc::ComponentExportKind::Func, component_func, None);
        out.section(&exports);
        names.push(name);
    }
    if names.is_empty() {
        bail!("no directly instantiated core module could be instrumented: {}", re.skipped.join("; "));
    }
    let bytes = out.finish();
    wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all()).validate_all(&bytes).context("instrumented component is invalid")?;
    Ok(Instrumented { bytes, readers: names, sites: re.sites, skipped: re.skipped })
}
struct ComponentEncoder {
    modules: BTreeMap<u32, bool>,
    module_index: u32,
    instance_index: u32,
    readers: Vec<u32>,
    sites: u32,
    skipped: Vec<String>,
}
impl Reencode for ComponentEncoder {
    type Error = Infallible;
}
impl ReencodeComponent for ComponentEncoder {
    fn parse_component_submodule(&mut self, c: &mut enc::Component, _parser: Parser, bytes: &[u8]) -> Result<(), Error<Self::Error>> {
        let idx = self.module_index;
        self.module_index += 1;
        match rewrite_module(bytes, self.sites) {
            Ok((module, sites)) => {
                self.sites = sites;
                self.modules.insert(idx, true);
                c.section(&enc::ModuleSection(&module));
            }
            Err(e) => {
                self.skipped.push(format!("module {idx}: {e:#}"));
                c.section(&enc::RawSection { id: 1, data: bytes });
            }
        }
        Ok(())
    }
    fn parse_component_subcomponent(&mut self, c: &mut enc::Component, _p: Parser, bytes: &[u8], _whole: &[u8]) -> Result<(), Error<Self::Error>> {
        self.skipped.push("nested component (opaque)".into());
        c.section(&enc::RawSection { id: 4, data: bytes });
        Ok(())
    }
    fn parse_component_import_section(
        &mut self,
        imports: &mut enc::ComponentImportSection,
        section: wasmparser::ComponentImportSectionReader<'_>,
    ) -> Result<(), Error<Self::Error>> {
        for entry in section.clone() {
            if matches!(entry?.ty, wasmparser::ComponentTypeRef::Module(_)) {
                self.module_index += 1;
            }
        }
        component_utils::parse_component_import_section(self, imports, section)
    }
    fn parse_component_alias_section(
        &mut self,
        aliases: &mut enc::ComponentAliasSection,
        section: wasmparser::ComponentAliasSectionReader<'_>,
    ) -> Result<(), Error<Self::Error>> {
        for alias in section.clone() {
            if matches!(alias?, wasmparser::ComponentAlias::Outer { kind: wasmparser::ComponentOuterAliasKind::CoreModule, .. }) {
                self.module_index += 1;
            }
        }
        component_utils::parse_component_alias_section(self, aliases, section)
    }
    fn parse_instance_section(
        &mut self,
        instances: &mut enc::InstanceSection,
        section: wasmparser::InstanceSectionReader<'_>,
    ) -> Result<(), Error<Self::Error>> {
        for instance in section.clone() {
            if let wasmparser::Instance::Instantiate { module_index, .. } = instance?
                && self.modules.contains_key(&module_index)
            {
                self.readers.push(self.instance_index);
            }
            self.instance_index += 1;
        }
        component_utils::parse_instance_section(self, instances, section)
    }
    fn parse_component_export_section(
        &mut self,
        exports: &mut enc::ComponentExportSection,
        section: wasmparser::ComponentExportSectionReader<'_>,
    ) -> Result<(), Error<Self::Error>> {
        component_utils::parse_component_export_section(self, exports, section)
    }
}

struct CoreEncoder {
    types: u32,
    functions: u32,
    memory: u32,
    params: Vec<u32>,
    body: usize,
    site: u32,
    present: BTreeSet<u8>,
}
fn rewrite_module(bytes: &[u8], site: u32) -> Result<(enc::Module, u32)> {
    let mut re = CoreEncoder { types: 0, functions: 0, memory: 0, params: vec![], body: 0, site, present: BTreeSet::new() };
    let mut types = vec![];
    let mut defs = vec![];
    for p in Parser::new(0).parse_all(bytes) {
        let p = p?;
        if let Some((id, _)) = p.as_section() {
            re.present.insert(id);
        }
        match p {
            Payload::TypeSection(s) => {
                for t in s.into_iter_err_on_gc_types() {
                    let t = t?;
                    types.push(t.params().len() as u32);
                    re.types += 1;
                }
            }
            Payload::ImportSection(s) => {
                for i in s.into_imports() {
                    match i?.ty {
                        TypeRef::Func(_) | TypeRef::FuncExact(_) => re.functions += 1,
                        TypeRef::Memory(_) => re.memory += 1,
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(s) => {
                for t in s {
                    defs.push(t?);
                    re.functions += 1;
                }
            }
            Payload::MemorySection(s) => re.memory += s.count(),
            Payload::ExportSection(s) => {
                for e in s {
                    if [READ, MEMORY].contains(&e?.name) {
                        bail!("reserved feedback export collision");
                    }
                }
            }
            _ => {}
        }
    }
    if defs.is_empty() {
        bail!("no defined functions");
    }
    re.params = defs.iter().map(|t| types[*t as usize]).collect();
    let mut module = enc::Module::new();
    re.parse_core_module(&mut module, Parser::new(0), bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((module, re.site))
}
impl CoreEncoder {
    fn next(&mut self) -> u32 {
        let n = self.site;
        self.site += 1;
        n
    }
    fn add_types(&self, t: &mut enc::TypeSection) {
        t.ty().function([enc::ValType::I32, enc::ValType::I64, enc::ValType::I64, enc::ValType::I32], []);
        t.ty().function([], [enc::ValType::I32]);
    }
    fn add_functions(&self, f: &mut enc::FunctionSection) {
        f.function(self.types);
        f.function(self.types + 1);
    }
    fn add_memory(&self, m: &mut enc::MemorySection) {
        m.memory(enc::MemoryType { minimum: 1, maximum: Some(1), memory64: false, shared: false, page_size_log2: None });
    }
    fn add_exports(&self, e: &mut enc::ExportSection) {
        e.export(READ, enc::ExportKind::Func, self.functions + 1);
        e.export(MEMORY, enc::ExportKind::Memory, self.memory);
    }
    fn edge(&mut self, f: &mut enc::Function) {
        let site = self.next();
        f.instruction(&I::I32Const(site as i32))
            .instruction(&I::I64Const(1))
            .instruction(&I::I64Const(0))
            .instruction(&I::I32Const(0))
            .instruction(&I::Call(self.functions));
    }
    fn arg(&self, offset: u64) -> enc::MemArg {
        enc::MemArg { offset, align: 0, memory_index: self.memory }
    }
    fn helper(&self) -> enc::Function {
        // (site, left, right, kind) -> (), with i32 locals address,count.
        let mut f = enc::Function::new([(2, enc::ValType::I32)]);
        macro_rules! op {
            ($i:expr) => {
                f.instruction(&$i);
            };
        }
        // Approximate control-flow bitmap. The predicate's zero/nonzero side is retained.
        op!(I::I32Const(16));
        op!(I::LocalGet(0));
        op!(I::I32Const(2));
        op!(I::I32Mul);
        op!(I::LocalGet(1));
        op!(I::I64Eqz);
        op!(I::I32Add);
        op!(I::I32Const((MAP - 1) as i32));
        op!(I::I32And);
        op!(I::I32Add);
        op!(I::I32Const(1));
        op!(I::I32Store8(self.arg(0)));
        op!(I::LocalGet(3));
        op!(I::I32Eqz);
        op!(I::If(enc::BlockType::Empty));
        op!(I::Return);
        op!(I::End);
        // Bound and deduplicate comparison samples; bitmap recording continues when full.
        op!(I::I32Const(8));
        op!(I::I32Load(self.arg(0)));
        op!(I::LocalTee(5));
        op!(I::I32Const(LOG as i32));
        op!(I::I32GeU);
        op!(I::If(enc::BlockType::Empty));
        op!(I::Return);
        op!(I::End);
        op!(I::LocalGet(0));
        op!(I::I32Const(16777619));
        op!(I::I32Mul);
        op!(I::LocalGet(1));
        op!(I::I32WrapI64);
        op!(I::I32Const(31));
        op!(I::I32Mul);
        op!(I::I32Xor);
        op!(I::LocalGet(2));
        op!(I::I32WrapI64);
        op!(I::I32Const(131));
        op!(I::I32Mul);
        op!(I::I32Xor);
        op!(I::I32Const(2047));
        op!(I::I32And);
        op!(I::I32Const(DEDUP as i32));
        op!(I::I32Add);
        op!(I::LocalTee(4));
        op!(I::I32Load8U(self.arg(0)));
        op!(I::If(enc::BlockType::Empty));
        op!(I::Return);
        op!(I::End);
        op!(I::LocalGet(4));
        op!(I::I32Const(1));
        op!(I::I32Store8(self.arg(0)));
        op!(I::LocalGet(5));
        op!(I::I32Const(32));
        op!(I::I32Mul);
        op!(I::I32Const(BASE as i32));
        op!(I::I32Add);
        op!(I::LocalSet(4));
        for (source, offset, extend) in [(0, 0, true), (1, 8, false), (2, 16, false), (3, 24, true)] {
            op!(I::LocalGet(4));
            op!(I::LocalGet(source));
            if extend {
                op!(I::I64ExtendI32U);
            }
            op!(I::I64Store(self.arg(offset)));
        }
        op!(I::I32Const(8));
        op!(I::LocalGet(5));
        op!(I::I32Const(1));
        op!(I::I32Add);
        op!(I::I32Store(self.arg(0)));
        op!(I::End);
        f
    }
    fn reader(&self) -> enc::Function {
        let mut f = enc::Function::new([]);
        f.instruction(&I::I32Const(0))
            .instruction(&I::I32Const(0))
            .instruction(&I::I32Store(self.arg(0)))
            .instruction(&I::I32Const(4))
            .instruction(&I::I32Const(BUFFER as i32))
            .instruction(&I::I32Store(self.arg(0)))
            .instruction(&I::I32Const(0))
            .instruction(&I::End);
        f
    }
}
impl Reencode for CoreEncoder {
    type Error = Infallible;
    fn parse_type_section(&mut self, t: &mut enc::TypeSection, s: wasmparser::TypeSectionReader<'_>) -> Result<(), Error<Self::Error>> {
        utils::parse_type_section(self, t, s)?;
        self.add_types(t);
        Ok(())
    }
    fn parse_function_section(&mut self, f: &mut enc::FunctionSection, s: wasmparser::FunctionSectionReader<'_>) -> Result<(), Error<Self::Error>> {
        utils::parse_function_section(self, f, s)?;
        self.add_functions(f);
        Ok(())
    }
    fn parse_memory_section(&mut self, m: &mut enc::MemorySection, s: wasmparser::MemorySectionReader<'_>) -> Result<(), Error<Self::Error>> {
        utils::parse_memory_section(self, m, s)?;
        self.add_memory(m);
        Ok(())
    }
    fn parse_export_section(&mut self, e: &mut enc::ExportSection, s: wasmparser::ExportSectionReader<'_>) -> Result<(), Error<Self::Error>> {
        utils::parse_export_section(self, e, s)?;
        self.add_exports(e);
        Ok(())
    }
    fn intersperse_section_hook(
        &mut self,
        module: &mut enc::Module,
        _after: Option<enc::SectionId>,
        before: Option<enc::SectionId>,
    ) -> Result<(), Error<Self::Error>> {
        let before = before.map(|s| s as u8).unwrap_or(255);
        for id in [1, 3, 5, 7] {
            if before > id && !self.present.contains(&id) {
                match id {
                    1 => {
                        let mut s = enc::TypeSection::new();
                        self.add_types(&mut s);
                        module.section(&s);
                    }
                    3 => {
                        let mut s = enc::FunctionSection::new();
                        self.add_functions(&mut s);
                        module.section(&s);
                    }
                    5 => {
                        let mut s = enc::MemorySection::new();
                        self.add_memory(&mut s);
                        module.section(&s);
                    }
                    7 => {
                        let mut s = enc::ExportSection::new();
                        self.add_exports(&mut s);
                        module.section(&s);
                    }
                    _ => {}
                }
                self.present.insert(id);
            }
        }
        Ok(())
    }
    fn parse_code_section(&mut self, c: &mut enc::CodeSection, s: wasmparser::CodeSectionReader<'_>) -> Result<(), Error<Self::Error>> {
        utils::parse_code_section(self, c, s)?;
        c.function(&self.helper());
        c.function(&self.reader());
        Ok(())
    }
    fn parse_function_body(&mut self, c: &mut enc::CodeSection, body: wasmparser::FunctionBody<'_>) -> Result<(), Error<Self::Error>> {
        let mut locals = Vec::new();
        let mut count = self.params[self.body];
        self.body += 1;
        for local in body.get_locals_reader()? {
            let (n, t) = local?;
            count += n;
            locals.push((n, self.val_type(t)?));
        }
        let t0 = count;
        let t1 = count + 1;
        let u0 = count + 2;
        let u1 = count + 3;
        locals.extend([(2, enc::ValType::I32), (2, enc::ValType::I64)]);
        let mut f = enc::Function::new(locals);
        self.edge(&mut f);
        let mut ops = body.get_operators_reader()?;
        while !ops.eof() {
            let op = ops.read()?;
            let width = match op {
                O::I32Eq | O::I32Ne | O::I32LtS | O::I32LtU | O::I32GtS | O::I32GtU | O::I32LeS | O::I32LeU | O::I32GeS | O::I32GeU => 32,
                O::I64Eq | O::I64Ne | O::I64LtS | O::I64LtU | O::I64GtS | O::I64GtU | O::I64LeS | O::I64LeU | O::I64GeS | O::I64GeU => 64,
                _ => 0,
            };
            if width != 0 {
                let (a, b) = if width == 32 { (t0, t1) } else { (u0, u1) };
                let site = self.next();
                f.instruction(&I::LocalSet(b)).instruction(&I::LocalTee(a)).instruction(&I::I32Const(site as i32)).instruction(&I::LocalGet(a));
                if width == 32 {
                    f.instruction(&I::I64ExtendI32U);
                }
                f.instruction(&I::LocalGet(b));
                if width == 32 {
                    f.instruction(&I::I64ExtendI32U);
                }
                f.instruction(&I::I32Const(if width == 32 { 1 } else { 2 })).instruction(&I::Call(self.functions)).instruction(&I::LocalGet(b));
            } else if matches!(op, O::If { .. } | O::BrIf { .. } | O::BrTable { .. }) {
                let site = self.next();
                f.instruction(&I::LocalTee(t0))
                    .instruction(&I::I32Const(site as i32))
                    .instruction(&I::LocalGet(t0))
                    .instruction(&I::I64ExtendI32U)
                    .instruction(&I::I64Const(0))
                    .instruction(&I::I32Const(0))
                    .instruction(&I::Call(self.functions));
            }
            let edge = matches!(op, O::Loop { .. } | O::Else);
            f.instruction(&self.instruction(op)?);
            if edge {
                self.edge(&mut f);
            }
        }
        c.function(&f);
        Ok(())
    }
}

pub struct Guide {
    app: crate::harness::App,
    pub sites: u32,
    pub modules: usize,
    pub skipped: Vec<String>,
}
impl Guide {
    pub fn new(app: &crate::harness::App) -> Result<Self> {
        let result = instrument(&app.bytes)?;
        let modules = result.readers.len();
        let shadow = crate::harness::App::from_feedback(app.manifest.clone(), result.bytes, result.readers)?;
        Ok(Self { app: shadow, sites: result.sites, modules, skipped: result.skipped })
    }
    pub fn collect(&self, spec: &crate::record::RunSpec) -> Result<Feedback> {
        let mut s = spec.clone();
        s.component = self.app.hash.clone();
        s.contract = self.app.contract.clone();
        s.fuel = s.fuel.saturating_mul(64);
        s.memory = s.memory.saturating_add(self.modules as u64 * 65536);
        self.app.feedback(&s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub mode: String,
    pub setup_ms: u64,
    pub sites: u32,
    pub modules: usize,
    pub skipped: Vec<String>,
    pub unavailable: Option<String>,
    pub runs: u64,
    pub discarded_runs: u64,
    pub last_error: Option<String>,
}
pub struct Probe {
    guide: Option<Guide>,
    status: Status,
    runs: std::sync::atomic::AtomicU64,
    discarded: std::sync::atomic::AtomicU64,
    error: std::sync::Mutex<Option<String>>,
}
impl Probe {
    pub fn new(app: &crate::harness::App, enabled: bool) -> Self {
        let start = std::time::Instant::now();
        let result = if enabled { Some(Guide::new(app)) } else { None };
        let (guide, unavailable) = match result {
            Some(Ok(g)) => (Some(g), None),
            Some(Err(e)) => (None, Some(format!("{e:#}"))),
            None => (None, None),
        };
        let status = Status {
            mode: if guide.is_some() { "internal" } else { "boundary" }.into(),
            setup_ms: start.elapsed().as_millis() as u64,
            sites: guide.as_ref().map_or(0, |g| g.sites),
            modules: guide.as_ref().map_or(0, |g| g.modules),
            skipped: guide.as_ref().map_or_else(Vec::new, |g| g.skipped.clone()),
            unavailable,
            runs: 0,
            discarded_runs: 0,
            last_error: None,
        };
        Self { guide, status, runs: Default::default(), discarded: Default::default(), error: Default::default() }
    }
    pub fn collect(&self, spec: &crate::record::RunSpec) -> Feedback {
        let Some(guide) = &self.guide else { return Feedback::default() };
        use std::sync::atomic::Ordering::Relaxed;
        self.runs.fetch_add(1, Relaxed);
        match guide.collect(spec) {
            Ok(f) => f,
            Err(e) => {
                self.discarded.fetch_add(1, Relaxed);
                *self.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("{e:#}"));
                Feedback::default()
            }
        }
    }
    pub fn finish(mut self) -> Status {
        use std::sync::atomic::Ordering::Relaxed;
        self.status.runs = self.runs.load(Relaxed);
        self.status.discarded_runs = self.discarded.load(Relaxed);
        self.status.last_error = self.error.into_inner().unwrap_or_else(|e| e.into_inner());
        self.status
    }
}

/// Compact edits: never clone entire requests for each proposed mutation.
#[derive(Debug, Clone, Serialize)]
pub struct Substitution {
    argument: usize,
    path: String,
    replacement: Replacement,
}
#[derive(Debug, Clone, Serialize)]
enum Replacement {
    Value(serde_json::Value),
    Text { position: usize, width: usize, text: String },
}
impl Substitution {
    pub fn apply(&self, args: &mut [serde_json::Value]) -> bool {
        let Some(v) = args.get_mut(self.argument).and_then(|v| v.pointer_mut(&self.path)) else {
            return false;
        };
        match &self.replacement {
            Replacement::Value(value) => {
                if v == value {
                    return false;
                }
                *v = value.clone();
                true
            }
            Replacement::Text { position, width, text } => {
                let Some(s) = v.as_str() else {
                    return false;
                };
                let end = position + width;
                if end > s.len() || !s.is_char_boundary(*position) || !s.is_char_boundary(end) {
                    return false;
                }
                let serde_json::Value::String(mut owned) = v.take() else { unreachable!("checked string") };
                owned.replace_range(*position..end, text);
                *v = serde_json::Value::String(owned);
                true
            }
        }
    }
}
/// Candidate substitutions from observed operands. Work and storage are bounded;
/// operand matching is a heuristic, not taint tracking or constraint solving.
pub fn substitutions(args: &[serde_json::Value], comparisons: &[Comparison]) -> Vec<Substitution> {
    use serde_json::{Value, json};
    const SCAN_BUDGET: usize = 262_144;
    fn paths(v: &Value, p: String, arg: usize, out: &mut Vec<(usize, String)>) {
        if out.len() >= 128 {
            return;
        }
        match v {
            Value::Object(o) => {
                for (k, v) in o.iter().take(128) {
                    paths(v, format!("{p}/{}", k.replace('~', "~0").replace('/', "~1")), arg, out)
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().take(128).enumerate() {
                    paths(v, format!("{p}/{i}"), arg, out)
                }
            }
            Value::Number(_) | Value::String(_) => out.push((arg, p)),
            _ => {}
        }
    }
    let mut leaves = vec![];
    for (i, arg) in args.iter().take(128).enumerate() {
        paths(arg, String::new(), i, &mut leaves);
    }
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    let mut remaining = SCAN_BUDGET;
    for c in comparisons.iter().take(LOG) {
        for (from, to) in [(c.left, c.right), (c.right, c.left)] {
            if from == to {
                continue;
            }
            for (argument, path) in &leaves {
                let value = args[*argument].pointer(path).unwrap();
                let mut edits = Vec::new();
                if value.as_u64() == Some(from) {
                    edits.push(Replacement::Value(json!(to)));
                }
                if value.as_i64().is_some_and(|n| n == if c.width == 32 { from as u32 as i32 as i64 } else { from as i64 }) {
                    edits.push(Replacement::Value(json!(if c.width == 32 { to as u32 as i32 as i64 } else { to as i64 })));
                }
                if let Some(s) = value.as_str() {
                    if s.len() <= 20 && s.parse::<u64>().ok() == Some(from) {
                        edits.push(Replacement::Value(json!(to.to_string())));
                    }
                    for width in [1usize, 2, 4, 8] {
                        if remaining == 0 || width > c.width as usize / 8 || (width < 8 && (from >> (width * 8) != 0 || to >> (width * 8) != 0)) {
                            continue;
                        }
                        let source = from.to_le_bytes();
                        let target = to.to_le_bytes();
                        let Ok(text) = std::str::from_utf8(&target[..width]) else {
                            continue;
                        };
                        let length = s.len().min(16384).min(remaining);
                        remaining -= length;
                        for (position, _) in s.as_bytes()[..length].windows(width).enumerate().filter(|(_, b)| *b == &source[..width]).take(8) {
                            if s.is_char_boundary(position) && s.is_char_boundary(position + width) {
                                edits.push(Replacement::Text { position, width, text: text.into() });
                            }
                        }
                    }
                }
                for replacement in edits {
                    let patch = Substitution { argument: *argument, path: path.clone(), replacement };
                    if seen.insert(serde_json::to_string(&patch).unwrap()) {
                        out.push(patch);
                        if out.len() >= 256 {
                            return out;
                        }
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comparison_mutations_store_small_edits_for_large_strings() {
        let mut args = vec![serde_json::json!("a".repeat(1_000_000))];
        let patches = substitutions(&args, &[Comparison { site: 1, width: 32, left: 97, right: 98 }]);
        assert!(!patches.is_empty());
        assert!(serde_json::to_vec(&patches).unwrap().len() < 4096);
        assert!(patches[0].apply(&mut args));
        assert_eq!(args[0].as_str().unwrap().len(), 1_000_000);
        assert!(args[0].as_str().unwrap().contains('b'));
    }
}

#[cfg(test)]
mod semantics_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn appended_instrumentation_preserves_calls_tables_memory_and_i64_results() {
        let wit = "package test:feedback; interface db { get: func(id:u32) -> u32; } world app { import db; export run: func(x:u64,y:u64) -> u64; }";
        let wat = r#"(module
          (type $unary (func (param i64) (result i64)))
          (import "test:feedback/db" "get" (func $get (param i32) (result i32)))
          (memory (export "memory") 1)
          (table 1 funcref)
          (func $helper (type $unary) (local.get 0) (i64.const 3) i64.mul)
          (elem (i32.const 0) $helper)
          (func (export "run") (param i64 i64) (result i64) (local i64)
            (i64.store (i32.const 0) (local.get 0))
            (if (i64.lt_u (local.get 0) (local.get 1))
              (then (local.set 2 (call_indirect (type $unary) (i64.load (i32.const 0)) (i32.const 0))))
              (else (local.set 2 (call $helper (local.get 1)))))
            (i64.add (local.get 2) (i64.extend_i32_u (call $get (i32.const 7))))))"#;
        let mut resolve = wit_parser::Resolve::new();
        let pkg = resolve.push_str("test.wit", wit).unwrap();
        let world = resolve.select_world(&[pkg], Some("app")).unwrap();
        let mut bytes = wat::parse_str(wat).unwrap();
        wit_component::embed_component_metadata(&mut bytes, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
        let bytes = wit_component::ComponentEncoder::default().module(&bytes).unwrap().validate(true).encode().unwrap();
        let original = crate::harness::App::from_bytes(crate::manifest::Manifest::for_wasm(std::path::Path::new("test.wasm")), bytes).unwrap();
        let guide = Guide::new(&original).unwrap();
        for (x, y) in [(0, 1), (5, 2), (u64::MAX, 9), (20, 20)] {
            let spec = original.spec(original.export("run").unwrap(), vec![json!(x), json!(y)], crate::plan::Plan::default(), 1);
            let before = original.run(&spec);
            let mut probe = spec.clone();
            probe.component = guide.app.hash.clone();
            probe.contract = guide.app.contract.clone();
            probe.memory += 65536;
            let after = guide.app.run(&probe);
            assert_eq!(before.outcome.kind, after.outcome.kind, "{:?}", after.outcome);
            assert_eq!(before.result, after.result);
            assert_eq!(before.events.len(), after.events.len());
            assert_eq!(before.events[0].args, after.events[0].args);
            assert_eq!(before.events[0].result, after.events[0].result);
            assert!(after.totals.fuel > before.totals.fuel); // Only the original's measurement is evidence.
        }
    }
}
