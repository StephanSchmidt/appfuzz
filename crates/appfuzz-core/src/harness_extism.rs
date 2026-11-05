//! Extism plugins on a platform whose `wit` types the JSON (`abi = "extism"`).
//!
//! The kernel (`extism:host/env`) is `extism::Kernel`, one per run. Every
//! host function (`extism:host/user`) goes to one trampoline: it reads each
//! argument's block, decodes the JSON into WIT values, asks the interceptor
//! components use, and writes the answer back as a new block. A run puts the
//! request into the kernel's input, calls the export and reads its output
//! (or its error).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};
use wasmtime::component::Val;
use wasmtime::{AsContextMut, Caller, Engine, ExternType, Module, ValType};

use super::{Host, intercept};
use crate::extism::{Abi, FnShape, Shape, args_shape, norm};
use crate::manifest::Manifest;
use crate::value::{json_to_val, val_to_json};
use crate::wit::{FuncInfo, ImportKind, Interface};

const USER: &str = "extism:host/user";
const ENV: &str = crate::extism::KERNEL_MODULE;
const WASI_P1: &str = "wasi_snapshot_preview1";

pub(super) struct ExtismApp {
    module: Module,
    pub(super) kernel: Module,
    pub(super) abi: Arc<Abi>,
    /// The module export of each WIT export, by key.
    pub(super) names: Arc<BTreeMap<String, String>>,
    pub(super) imports: Vec<Interface>,
    pub(super) exports: Vec<FuncInfo>,
}

impl ExtismApp {
    pub(super) fn new(engine: &Engine, manifest: &Manifest, bytes: &[u8]) -> Result<Self> {
        let host = manifest.host.as_ref().expect("checked by the caller");
        let name = &host.platform.name;
        let types = host.types(engine)?;
        let abi = types.extism.clone().ok_or_else(|| anyhow!("platform {name} has abi = \"extism\" but no wit"))?;
        let module = Module::new(engine, bytes).map_err(anyhow::Error::from).context("compiling the plugin")?;

        // Host functions: each import of extism:host/user must be in the WIT.
        let mut used = BTreeSet::new();
        for imp in module.imports().filter(|i| i.module() == USER) {
            let key = abi
                .imports
                .get(&norm(imp.name()))
                .ok_or_else(|| anyhow!("the plugin imports host function {:?}, which platform {name}'s WIT does not describe", imp.name()))?;
            let ExternType::Func(ft) = imp.ty() else { bail!("{USER}#{} is not a function", imp.name()) };
            check(&ft, &abi.funcs[key], false).with_context(|| format!("host function {}", imp.name()))?;
            used.insert(key.clone());
        }
        for imp in module.imports() {
            if ![USER, ENV, WASI_P1].contains(&imp.module()) {
                bail!("the plugin imports {}#{}, which is neither Extism nor WASI preview 1", imp.module(), imp.name());
            }
        }
        let mut imports: Vec<Interface> = types
            .imports
            .into_iter()
            .filter_map(|mut iface| {
                iface.funcs.retain(|f| used.contains(&f.key));
                (!iface.funcs.is_empty()).then_some(iface)
            })
            .collect();
        if module.imports().any(|i| i.module() == WASI_P1) {
            imports.push(Interface { name: WASI_P1.to_string(), kind: ImportKind::Wasi, funcs: Vec::new() });
        }

        // Exports: the WIT exports the module has.
        let mut names = BTreeMap::new();
        for e in module.exports() {
            let ExternType::Func(ft) = e.ty() else { continue };
            let Some(key) = abi.exports.get(&norm(e.name())) else { continue };
            check(&ft, &abi.funcs[key], true).with_context(|| format!("export {}", e.name()))?;
            names.insert(key.clone(), e.name().to_string());
        }
        let exports: Vec<FuncInfo> = types.exports.into_iter().filter(|f| names.contains_key(&f.key)).collect();
        if exports.is_empty() {
            let have: Vec<&str> = module.exports().filter(|e| matches!(e.ty(), ExternType::Func(_))).map(|e| e.name()).collect();
            bail!("the plugin exports none of platform {name}'s WIT exports; it exports {}", have.join(", "));
        }
        Ok(ExtismApp { module, kernel: crate::extism::Kernel::module(engine).map_err(anyhow::Error::from)?, abi, names: Arc::new(names), imports, exports })
    }

    pub(super) fn link(&self, engine: &Engine) -> Result<wasmtime::InstancePre<Host>> {
        let mut linker: wasmtime::Linker<Host> = wasmtime::Linker::new(engine);
        super::p1::link(&mut linker)?;
        crate::extism::link_kernel(&mut linker, &self.kernel, |h: &mut Host| h.kernel.as_mut().expect("plugin runs have a kernel"))?;
        for imp in self.module.imports().filter(|i| i.module() == USER) {
            let ExternType::Func(ft) = imp.ty() else { continue };
            let key = self.abi.imports[&norm(imp.name())].clone();
            let abi = self.abi.clone();
            linker.func_new(USER, imp.name(), ft.clone(), move |mut caller, params, results| {
                call(&mut caller, &key, &abi, params, results).map_err(wasmtime::Error::from_anyhow)
            })?;
        }
        linker.define_unknown_imports_as_traps(&self.module)?;
        linker.instantiate_pre(&self.module).map_err(anyhow::Error::from).context("linking the plugin")
    }
}

/// Host functions take one i64 offset per WIT parameter and return one for
/// the result; exports take nothing and return a status.
fn check(ft: &wasmtime::FuncType, f: &FnShape, export: bool) -> Result<()> {
    let params: Vec<ValType> = ft.params().collect();
    let results: Vec<ValType> = ft.results().collect();
    if export {
        if !params.is_empty() || !(results.is_empty() || matches!(results.as_slice(), [ValType::I32])) {
            bail!("an Extism export takes nothing and returns no value or an i32; this one is {ft}");
        }
        return Ok(());
    }
    if params.len() != f.params.len() || params.iter().any(|t| !matches!(t, ValType::I64)) {
        bail!("takes {} i64 offsets in the WIT, the plugin imports it as {ft}", f.params.len());
    }
    let want = usize::from(f.result.is_some());
    if results.len() != want || results.iter().any(|t| !matches!(t, ValType::I64)) {
        bail!("returns {want} i64 offset(s) in the WIT, the plugin imports it as {ft}");
    }
    Ok(())
}

/// Extism initializes a reactor or language runtime before preparing the input.
/// Haskell's reactor runs before hs_init; other plugins prefer constructors.
pub(super) fn initialize(store: &mut wasmtime::Store<Host>, instance: &wasmtime::Instance) -> wasmtime::Result<()> {
    if let Some(haskell) = instance.get_func(&mut *store, "hs_init") {
        if let Ok(reactor) = instance.get_typed_func::<(), ()>(&mut *store, "_initialize") {
            reactor.call(&mut *store, ())?;
        }
        let mut results = vec![wasmtime::Val::I32(0); haskell.ty(&*store).results().len()];
        return haskell.call(&mut *store, &[wasmtime::Val::I32(0), wasmtime::Val::I32(0)], &mut results);
    }
    let init = instance.get_func(&mut *store, "__wasm_call_ctors").or_else(|| instance.get_func(&mut *store, "_initialize"));
    if let Some(init) = init
        && let Ok(init) = init.typed::<(), ()>(&*store)
    {
        init.call(&mut *store, ())?;
    }
    Ok(())
}

/// Identifies guest-provided context without mistaking arbitrary diagnostic text
/// (which can contain host-plan values) for app output.
#[derive(Debug)]
pub(super) struct GuestError(pub(super) String);

impl std::fmt::Display for GuestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuestError {}

pub(super) fn invoke(store: &mut wasmtime::Store<Host>, instance: &wasmtime::Instance, name: &str) -> wasmtime::Result<i32> {
    let func = instance.get_func(&mut *store, name).ok_or_else(|| wasmtime::Error::msg(format!("the plugin does not export {name}")))?;
    let mut results = vec![wasmtime::Val::I32(0); func.ty(&*store).results().len()];
    let mut called = func.call(&mut *store, &[], &mut results);
    if store.get_fuel()? == 0 {
        return Err(called.err().map_or_else(|| wasmtime::Trap::OutOfFuel.into(), |error| error.context(wasmtime::Trap::OutOfFuel)));
    }
    let rt = store.data().kernel.as_ref().expect("plugin runs have a kernel").runtime.expect("kernel was installed");
    match rt.capture(&mut *store) {
        Ok((output, error)) => {
            let kernel = store.data_mut().kernel.as_mut().unwrap();
            kernel.output = Some(output);
            kernel.error = error;
        }
        Err(error) if called.is_ok() => called = Err(wasmtime::Error::from_anyhow(error)),
        Err(_) => {}
    }
    let kernel = store.data().kernel.as_ref().expect("plugin runs have a kernel");
    let error_bytes = kernel.error_bytes().map_err(wasmtime::Error::from_anyhow)?;
    match called {
        Ok(()) => Ok(results.first().map_or(0, |value| value.unwrap_i32())),
        Err(error) if error.downcast_ref::<wasmtime_wasi::I32Exit>().is_some_and(|exit| exit.0 == 0) && error_bytes.is_none_or(<[u8]>::is_empty) => Ok(0),
        Err(error) => {
            if let Some(bytes) = error_bytes.filter(|bytes| !bytes.is_empty()) {
                Err(error.context(GuestError(String::from_utf8_lossy(bytes).into_owned())))
            } else {
                Err(error)
            }
        }
    }
}

/// One host call: decode the argument blocks, intercept, encode the answer.
fn call(caller: &mut Caller<'_, Host>, key: &str, abi: &Abi, params: &[wasmtime::Val], results: &mut [wasmtime::Val]) -> Result<()> {
    let shape = &abi.funcs[key];
    let platform = caller.data().platform.clone();
    let info = platform.funcs.get(key).ok_or_else(|| anyhow!("{key} is not a platform function"))?;
    let mut args = Vec::with_capacity(params.len());
    for ((name, s), (p, (_, ty))) in shape.params.iter().zip(params.iter().zip(info.ty.params())) {
        let at = p.unwrap_i64() as u64;
        let rt = caller.data().kernel.as_ref().expect("plugin runs have a kernel").runtime.expect("kernel was installed");
        let bytes = rt.block(&mut *caller, at).with_context(|| format!("{key} argument {name}"))?;
        let wit = abi.decode(&bytes, s).with_context(|| format!("{key}: the plugin sent {name} as JSON that does not fit the WIT"))?;
        args.push(json_to_val(&wit, &ty).with_context(|| format!("{key} argument {name}"))?);
    }
    let mut values = vec![Val::Bool(false); info.ty.results().len()];
    intercept(caller.as_context_mut(), key, &args, &mut values)?;
    if let (Some(s), Some(v), Some(slot)) = (&shape.result, values.first(), results.first_mut()) {
        let bytes = abi.encode(&val_to_json(v), s);
        let rt = caller.data().kernel.as_ref().expect("plugin runs have a kernel").runtime.expect("kernel was installed");
        *slot = wasmtime::Val::I64(rt.put(&mut *caller, &bytes)? as i64);
    }
    Ok(())
}

/// The kernel input for an export's arguments.
pub(super) fn input(abi: &Abi, export: &FuncInfo, args: &[Val]) -> Vec<u8> {
    let shape = &abi.funcs[&export.key];
    match (args_shape(&shape.params), args) {
        (None, _) => Vec::new(),
        (Some(s), [one]) => abi.encode(&val_to_json(one), &s),
        (Some(s), many) => {
            let obj: Map<String, Value> = shape.params.iter().zip(many).map(|((n, _), v)| (n.clone(), val_to_json(v))).collect();
            abi.encode(&Value::Object(obj), &s)
        }
    }
}

/// What an export answered: its output, or for a non-zero status its
/// error as the `err` of a WIT `result`. `Err` is a message for an outcome.
pub(super) fn answer(abi: &Abi, export: &FuncInfo, status: i32, kernel: &crate::extism::Kernel) -> std::result::Result<Value, String> {
    let output = kernel.output_bytes().map_err(|error| error.to_string())?;
    let error = kernel.error_bytes().map_err(|error| error.to_string())?;
    if status == 0
        && let Some(error) = error.filter(|error| !error.is_empty())
    {
        return Err(format!("the plugin reported an error: {}", String::from_utf8_lossy(error)));
    }
    let shape = &abi.funcs[&export.key];
    let ty = export.ty.results().next();
    let fit = |wit: Value| -> std::result::Result<Value, String> {
        match &ty {
            Some(t) => json_to_val(&wit, t).map(|v| val_to_json(&v)).map_err(|e| format!("the plugin's answer does not fit the platform WIT: {e:#}")),
            None => Ok(Value::Null),
        }
    };
    if status == 0 {
        let bad = |e: anyhow::Error| format!("the plugin's output does not fit the platform WIT: {e:#}");
        let out = output.unwrap_or_default();
        // A `result` export writes its ok value; the status says which case.
        return match &shape.result {
            None => Ok(Value::Null),
            Some(Shape::Result(ok, _)) => {
                let v = ok.as_deref().map(|s| abi.decode(out, s)).transpose().map_err(bad)?;
                fit(serde_json::json!({ "ok": v }))
            }
            Some(s) => fit(abi.decode(out, s).map_err(bad)?),
        };
    }
    let text = String::from_utf8_lossy(error.unwrap_or_default()).into_owned();
    match &shape.result {
        Some(Shape::Result(_, err)) => {
            let e = match err.as_deref() {
                None => Value::Null,
                Some(Shape::Str) => Value::String(text),
                Some(s) => abi.decode(text.as_bytes(), s).unwrap_or(Value::String(text)),
            };
            fit(serde_json::json!({ "err": e }))
        }
        _ => Err(format!("the plugin returned error {status}: {text}")),
    }
}
