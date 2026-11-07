//! Shopify Functions (`[shopify]`, or a `shopify.extension.toml`).
//!
//! A function makes no host calls. Its input is the request, encoded the
//! way Shopify sends it (JSON, or MessagePack for newer provider modules),
//! on stdin or in the provider's memory; its output comes back the same
//! way. A provider is Shopify's own module the function links with (Javy's
//! QuickJS, the Rust crate's I/O helpers): it is instantiated for every run
//! and its setup and teardown are not counted, as on Shopify.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use wasmtime::{Engine, Module, Store};

use super::Host;
use crate::manifest::Manifest;
use crate::shopify::providers::Provider;
use crate::shopify::{Function, RunInfo};
use crate::wit::{FuncInfo, ImportKind, Interface};

const WASI_P1: &str = "wasi_snapshot_preview1";

/// Fuel for the provider's setup and teardown, which Shopify does not count.
const UNCOUNTED: u64 = u64::MAX / 4;

pub(super) struct ShopifyApp {
    pub(super) function: Arc<Function>,
    module: Module,
    provider: Option<(&'static Provider, Module)>,
    /// The module export of each WIT export, by key.
    names: BTreeMap<String, String>,
    module_bytes: u64,
    wasi: bool,
    pub(super) imports: Vec<Interface>,
    pub(super) exports: Vec<FuncInfo>,
}

/// What a run needs: shared by every run of the app.
pub(super) struct Runtime {
    linker: wasmtime::Linker<Host>,
    function: Arc<Function>,
    module: Module,
    provider: Option<(&'static Provider, Module)>,
    names: BTreeMap<String, String>,
    module_bytes: u64,
}

/// One run's input, before the module runs.
pub(super) struct Input {
    pub(super) bytes: Vec<u8>,
    pub(super) info: RunInfo,
}

/// What a run wrote: through stdout and stderr, or the provider's memory.
pub(super) struct Written {
    pub(super) output: Option<Vec<u8>>,
    pub(super) logs: Option<Vec<u8>>,
}

impl super::App {
    /// A Shopify run's input, on stdin unless the function reads it from
    /// the provider's memory. None for other apps.
    pub(super) fn shopify_start(&self, export: &FuncInfo, args: &[Value], builder: &mut wasmtime_wasi::WasiCtxBuilder) -> Result<Option<Input>> {
        let super::Pre::Shopify(rt) = &self.pre else { return Ok(None) };
        let input = rt.input(export, args)?;
        if !rt.memory_io() {
            builder.stdin(wasmtime_wasi::p2::pipe::MemoryInputPipe::new(input.bytes.clone()));
        }
        Ok(Some(input))
    }

    /// Fills in what a Shopify run wrote, checked as Shopify checks it.
    pub(super) fn shopify_finish(
        &self,
        export: &FuncInfo,
        input: Option<Input>,
        written: Option<Written>,
        stdout: &super::MemoryOutputPipe,
        record: &mut crate::record::RunRecord,
    ) {
        let (super::Pre::Shopify(rt), Some(input)) = (&self.pre, input) else { return };
        let written = written.unwrap_or(Written { output: None, logs: None });
        if let Some(logs) = written.logs {
            record.stderr = String::from_utf8_lossy(&logs).into_owned();
        }
        let output = written.output.unwrap_or_else(|| stdout.contents().to_vec());
        rt.finish(export, input.info, &output, record);
    }
}

impl ShopifyApp {
    pub(super) fn new(engine: &Engine, manifest: &Manifest, bytes: &[u8]) -> Result<Self> {
        let function = manifest.shopify.as_ref().and_then(|s| s.function.clone()).ok_or_else(|| anyhow!("[shopify] was not loaded"))?;
        let module = Module::new(engine, bytes).map_err(anyhow::Error::from).context("compiling the function")?;
        let mut provider = None;
        let mut wasi = false;
        for imp in module.imports() {
            match imp.module() {
                WASI_P1 => wasi = true,
                name => match Provider::named(name) {
                    Some(p) if provider.is_none_or(|q: &Provider| q.name == p.name) => provider = Some(p),
                    Some(p) => bail!("the function imports two provider modules ({} and {}); Shopify links one", provider.map_or("", |q| q.name), p.name),
                    None => bail!("the function imports {}#{}, which Shopify does not provide", name, imp.name()),
                },
            }
        }
        if let Some(p) = provider
            && p.memory_io()
            && wasi
        {
            bail!("the function imports {} and WASI, which Shopify refuses; a Rust function using it builds for wasm32-unknown-unknown", p.name);
        }
        let provider = match provider {
            Some(p) => {
                let bytes = p.bytes()?;
                Some((p, Module::new(engine, &bytes).map_err(anyhow::Error::from).with_context(|| format!("compiling Shopify's {}", p.name))?))
            }
            None => None,
        };
        if let Some((p, pm)) = &provider {
            let missing: Vec<&str> = module.imports().filter(|i| i.module() == p.name && pm.get_export(i.name()).is_none()).map(|i| i.name()).collect();
            if let Some(first) = missing.first() {
                // `cargo build` output: Shopify's CLI rewrites the module
                // (its "trampoline") before it uploads it.
                if missing.iter().any(|n| pm.get_export(&format!("_{n}")).is_some()) {
                    bail!(
                        "the function imports {}#{first} as `cargo build` writes it, before Shopify's CLI prepares it for upload; run `shopify app function build` and review the module it writes",
                        p.name
                    );
                }
                bail!("the function imports {}#{first}, which Shopify's {} module does not have", p.name, p.name);
            }
        }
        let wasi_anywhere = wasi || provider.as_ref().is_some_and(|(_, m)| m.imports().any(|i| i.module() == WASI_P1));

        let all = wit_exports(engine, &function.wit)?;
        let mut names = BTreeMap::new();
        let mut missing = Vec::new();
        for t in &function.model.targets {
            match module.get_export(&t.export) {
                Some(wasmtime::ExternType::Func(ft)) if ft.params().len() == 0 && ft.results().len() == 0 => {
                    names.insert(t.wit.clone(), t.export.clone());
                }
                Some(_) => bail!("the function's export {} takes or returns values; Shopify calls it with none", t.export),
                None => missing.push(format!("{} ({})", t.export, t.target)),
            }
        }
        if !missing.is_empty() {
            let have: Vec<&str> = module.exports().filter(|e| matches!(e.ty(), wasmtime::ExternType::Func(_))).map(|e| e.name()).collect();
            bail!("the module does not export {}; it exports {}", missing.join(", "), have.join(", "));
        }
        let exports: Vec<FuncInfo> = all.into_iter().filter(|f| names.contains_key(&f.key)).collect();
        let mut imports = Vec::new();
        if wasi_anywhere {
            imports.push(Interface { name: WASI_P1.to_string(), kind: ImportKind::Wasi, funcs: Vec::new() });
        }
        if let Some((p, _)) = &provider {
            imports.push(Interface { name: p.name.to_string(), kind: ImportKind::Wasi, funcs: Vec::new() });
        }
        Ok(ShopifyApp { function, module, provider, names, module_bytes: bytes.len() as u64, wasi: wasi_anywhere, imports, exports })
    }

    pub(super) fn link(self, engine: &Engine) -> Result<Runtime> {
        let mut linker: wasmtime::Linker<Host> = wasmtime::Linker::new(engine);
        if self.wasi {
            super::p1::link(&mut linker)?;
        }
        Ok(Runtime { linker, function: self.function, module: self.module, provider: self.provider, names: self.names, module_bytes: self.module_bytes })
    }
}

/// The WIT exports of the function's types.
fn wit_exports(engine: &Engine, wit: &str) -> Result<Vec<FuncInfo>> {
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve.push_str("shopify.wit", wit).context("the function's types as WIT")?;
    let w = resolve.select_world(&[pkg], None)?;
    let mut module = wit_component::dummy_module(&resolve, w, wit_parser::ManglingAndAbi::Standard32);
    wit_component::embed_component_metadata(&mut module, &resolve, w, wit_component::StringEncoding::UTF8, false)?;
    let bytes = wit_component::ComponentEncoder::default().module(&module)?.validate(true).encode()?;
    let component = wasmtime::component::Component::new(engine, &bytes).map_err(anyhow::Error::from).context("compiling the function's types")?;
    Ok(crate::wit::exports(engine, &component))
}

impl Runtime {
    fn msgpack(&self) -> bool {
        self.provider.as_ref().is_some_and(|(p, _)| p.msgpack())
    }

    pub(super) fn memory_io(&self) -> bool {
        self.provider.as_ref().is_some_and(|(p, _)| p.memory_io())
    }

    /// The request as the bytes the function reads, and the limits it sets.
    pub(super) fn input(&self, export: &FuncInfo, args: &[Value]) -> Result<Input> {
        let target = self.function.target(&export.key).ok_or_else(|| anyhow!("{} is not a target of the function", export.key))?;
        let arg = args.first().ok_or_else(|| anyhow!("{} takes the input", export.key))?;
        let shopify = self.function.model.encode(arg, &target.input);
        let bytes = crate::shopify::encode_bytes(&shopify, self.msgpack())?;
        let sizes = self.function.model.sizes(arg, &target.input);
        let scale = sizes.values().map(|(_, s)| *s).fold(1.0, f64::max).clamp(1.0, crate::shopify::MAX_SCALE);
        let mut info = RunInfo::new(&target.target, scale);
        info.sizes = sizes.into_iter().map(|(path, (n, _))| (path, n)).collect();
        info.input_bytes = bytes.len() as u64;
        info.module_bytes = self.module_bytes;
        info.provider = self.provider.as_ref().map(|(p, _)| p.name.to_string());
        Ok(Input { bytes, info })
    }

    /// Instantiates the provider and the function and calls the export.
    pub(super) fn call(&self, store: &mut Store<Host>, export: &FuncInfo, input: &[u8], initializing: &mut bool) -> wasmtime::Result<Written> {
        let name = self.names.get(&export.key).ok_or_else(|| wasmtime::Error::msg(format!("the function does not export {}", export.key)))?;
        let mut linker = self.linker.clone();
        let mut provider = None;
        if let Some((p, module)) = &self.provider {
            let fuel = store.get_fuel()?;
            store.set_fuel(UNCOUNTED)?;
            let instance = linker.instantiate(&mut *store, module).map_err(|e| e.context(format!("instantiating Shopify's {}", p.name)))?;
            if p.memory_io() {
                let at = instance.get_typed_func::<i32, i32>(&mut *store, "initialize")?.call(&mut *store, input.len() as i32)?;
                let memory = instance.get_memory(&mut *store, "memory").ok_or_else(|| wasmtime::Error::msg(format!("{} exports no memory", p.name)))?;
                memory.write(&mut *store, at as u32 as usize, input)?;
            }
            linker.instance(&mut *store, p.name, instance)?;
            store.set_fuel(fuel)?;
            provider = Some((p, instance));
        }
        let instance = linker.instantiate(&mut *store, &self.module).map_err(|e| e.context("instantiating the function"))?;
        *initializing = false;
        let func = instance.get_typed_func::<(), ()>(&mut *store, name)?;
        match func.call(&mut *store, ()) {
            Ok(()) => {}
            Err(e) if e.downcast_ref::<wasmtime_wasi::I32Exit>().is_some_and(|x| x.0 == 0) => {}
            Err(e) => {
                let code = e.downcast_ref::<wasmtime_wasi::I32Exit>().map(|x| x.0);
                return Err(match code {
                    Some(code) => e.context(format!("the function exited with code {code}")),
                    None => e,
                });
            }
        }
        let Some((p, instance)) = provider.filter(|(p, _)| p.memory_io()) else { return Ok(Written { output: None, logs: None }) };
        // Teardown is not counted: put the fuel back after it.
        let fuel = store.get_fuel()?;
        store.set_fuel(UNCOUNTED)?;
        let at = instance.get_typed_func::<(), i32>(&mut *store, "finalize")?.call(&mut *store, ())? as u32 as usize;
        store.set_fuel(fuel)?;
        let memory = instance.get_memory(&mut *store, "memory").ok_or_else(|| wasmtime::Error::msg(format!("{} exports no memory", p.name)))?;
        let mut header = [0u8; 24];
        memory.read(&*store, at, &mut header)?;
        let word = |i: usize| u32::from_le_bytes(header[i * 4..i * 4 + 4].try_into().expect("4 bytes")) as usize;
        let read = |store: &Store<Host>, at: usize, len: usize| -> wasmtime::Result<Vec<u8>> {
            let mut buf = vec![0; len];
            memory.read(store, at, &mut buf)?;
            Ok(buf)
        };
        let output = read(store, word(0), word(1))?;
        let mut logs = read(store, word(2), word(3))?;
        logs.extend(read(store, word(4), word(5))?);
        Ok(Written { output: Some(output), logs: Some(logs) })
    }

    /// Checks what the function wrote the way Shopify does and fills in
    /// the record: its result as a WIT value, its output and logs as text.
    pub(super) fn finish(&self, export: &FuncInfo, mut info: RunInfo, output: &[u8], record: &mut crate::record::RunRecord) {
        info.output_bytes = output.len() as u64;
        info.log_bytes = record.stderr.len() as u64;
        let ok = record.outcome.kind == crate::record::OutcomeKind::Ok;
        if ok && let Some(target) = self.function.target(&export.key) {
            match crate::shopify::decode_bytes(output, self.msgpack()) {
                Err(problem) => {
                    info.invalid_output.push(problem);
                    if self.msgpack() {
                        record.stdout.clear();
                    }
                }
                Ok(json) => {
                    if self.msgpack() {
                        record.stdout = serde_json::to_string(&json).unwrap_or_default();
                    }
                    match self.function.model.decode(&json, &target.output) {
                        Ok(v) => record.result = Some(v),
                        Err(problems) => info.invalid_output = problems,
                    }
                }
            }
            if !info.invalid_output.is_empty() && !output.is_empty() {
                record.rejected_output = Some(output.to_vec());
            }
        }
        record.shopify = Some(info);
    }
}
