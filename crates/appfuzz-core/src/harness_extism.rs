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
const ENV: &str = "extism:host/env";
const WASI_P1: &str = "wasi_snapshot_preview1";

pub(super) struct ExtismApp {
    module: Module,
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
        Ok(ExtismApp { module, abi, names: Arc::new(names), imports, exports })
    }

    pub(super) fn link(&self, engine: &Engine) -> Result<wasmtime::InstancePre<Host>> {
        let mut linker: wasmtime::Linker<Host> = wasmtime::Linker::new(engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |h: &mut Host| h.p1.as_mut().expect("plugin runs have a WASI p1 context"))?;
        crate::extism::link_kernel(&mut linker, |h: &mut Host| h.kernel.as_mut().expect("plugin runs have a kernel"))?;
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
        if !params.is_empty() || !matches!(results.as_slice(), [ValType::I32]) {
            bail!("an Extism export takes nothing and returns an i32; this one is {ft}");
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

/// One host call: decode the argument blocks, intercept, encode the answer.
fn call(caller: &mut Caller<'_, Host>, key: &str, abi: &Abi, params: &[wasmtime::Val], results: &mut [wasmtime::Val]) -> Result<()> {
    let shape = &abi.funcs[key];
    let platform = caller.data().platform.clone();
    let info = platform.funcs.get(key).ok_or_else(|| anyhow!("{key} is not a platform function"))?;
    let mut args = Vec::with_capacity(params.len());
    for ((name, s), (p, (_, ty))) in shape.params.iter().zip(params.iter().zip(info.ty.params())) {
        let at = p.unwrap_i64() as u64;
        let kernel = caller.data().kernel.as_ref().expect("plugin runs have a kernel");
        let bytes = kernel.block(at).with_context(|| format!("{key} argument {name}"))?;
        let wit = abi.decode(&bytes, s).with_context(|| format!("{key}: the plugin sent {name} as JSON that does not fit the WIT"))?;
        args.push(json_to_val(&wit, &ty).with_context(|| format!("{key} argument {name}"))?);
    }
    let mut values = vec![Val::Bool(false); info.ty.results().len()];
    intercept(caller.as_context_mut(), key, &args, &mut values)?;
    if let (Some(s), Some(v), Some(slot)) = (&shape.result, values.first(), results.first_mut()) {
        let bytes = abi.encode(&val_to_json(v), s);
        let kernel = caller.data_mut().kernel.as_mut().expect("plugin runs have a kernel");
        *slot = wasmtime::Val::I64(kernel.put(&bytes)? as i64);
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
pub(super) fn answer(abi: &Abi, export: &FuncInfo, status: i32, output: Option<&[u8]>, error: Option<&[u8]>) -> std::result::Result<Value, String> {
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
