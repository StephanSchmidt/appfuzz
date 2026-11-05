//! Plain WebAssembly modules on a witx platform (Fastly Compute).
//!
//! Every witx import goes to one trampoline. It reads the raw arguments from
//! the guest's memory into WIT values (`witx_abi::lift`), asks the same
//! interceptor components use, and writes the answer back into the guest's
//! buffers and output pointers (`witx_abi::lower`). WASI preview 1 is
//! wasmtime-wasi on the virtual clock. A run calls the module's `start`
//! export (`_start`); `proc_exit(0)` is a normal end.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use wasmtime::component::Val;
use wasmtime::component::types::Type;
use wasmtime::{AsContextMut, Caller, Engine, ExternType, Module, ValType};

use super::{Host, intercept};
use crate::handles::{Binding, Kind};
use crate::manifest::Manifest;
use crate::wit::{FuncInfo, ImportKind, Interface};
use crate::witx_abi::{self, Sig, Unsupported};

/// The WASI module plain modules import.
const WASI_P1: &str = "wasi_snapshot_preview1";

pub(super) struct CoreApp {
    module: Module,
    sigs: Arc<BTreeMap<String, Sig>>,
    unsupported: Arc<BTreeMap<String, Unsupported>>,
    pub(super) start: String,
    /// The platform functions the module imports, typed by the carrier.
    pub(super) imports: Vec<Interface>,
    pub(super) exports: Vec<FuncInfo>,
}

impl CoreApp {
    pub(super) fn new(engine: &Engine, manifest: &Manifest, bytes: &[u8]) -> Result<Self> {
        let host = manifest.host.as_ref().ok_or_else(|| {
            anyhow!("this is a plain WebAssembly module, not a component: name its platform in appfuzz.toml, e.g. [app] platform = \"fastly\"")
        })?;
        let name = &host.platform.name;
        let types = host.types(engine)?;
        let sigs = types.witx.clone().ok_or_else(|| anyhow!("platform {name} describes components (wit), but this is a plain module"))?;
        let start = host.platform.start.clone().ok_or_else(|| anyhow!("platform {name} names no start export ([platform] start = \"_start\")"))?;
        if types.exports.is_empty() {
            bail!("platform {name} has no entry_wit: appfuzz needs the request and response types of a run");
        }
        let module = Module::new(engine, bytes).map_err(anyhow::Error::from).context("compiling the module")?;
        if !module.exports().any(|e| e.name() == start) {
            bail!("the module does not export {start:?}, the start function of platform {name}");
        }
        let used: BTreeSet<(String, String)> = module.imports().map(|i| (i.module().to_string(), i.name().to_string())).collect();
        let mut imports: Vec<Interface> = types
            .imports
            .into_iter()
            .filter_map(|mut iface| {
                iface.funcs.retain(|f| used.contains(&(f.interface.clone(), f.name.clone())));
                (!iface.funcs.is_empty()).then_some(iface)
            })
            .collect();
        let wasi: BTreeSet<&str> = used.iter().map(|(m, _)| m.as_str()).filter(|m| *m == WASI_P1).collect();
        imports.extend(wasi.into_iter().map(|m| Interface { name: m.to_string(), kind: ImportKind::Wasi, funcs: Vec::new() }));
        Ok(CoreApp { module, sigs, unsupported: types.unsupported_sigs.clone(), start, imports, exports: types.exports })
    }

    /// The handle parameters and results of each imported function, and the
    /// platform's bindings for them.
    pub(super) fn handle_spec(&self, manifest: &Manifest, funcs: &BTreeMap<String, FuncInfo>) -> Result<HandleSpec> {
        let host = manifest.host.as_ref().expect("checked in new");
        let mut spec = HandleSpec {
            bindings: BTreeMap::new(),
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            outs: BTreeMap::new(),
            kinds: host.handles.clone(),
            bad: host.platform.bad_handle.clone().unwrap_or_else(|| "badf".into()),
            absent: host.platform.absent.clone().unwrap_or_else(|| "none".into()),
        };
        for (key, info) in funcs {
            let Some(sig) = self.sigs.get(key) else { continue };
            let inputs: Vec<usize> = witx_abi::handle_inputs(sig).into_iter().map(|(i, _)| i).collect();
            if !inputs.is_empty() {
                spec.inputs.insert(key.clone(), inputs);
            }
            let n = sig.outputs().len();
            spec.outs.insert(key.clone(), n);
            // Output names as the carrier's ok record spells them.
            let fields = ok_fields(info);
            let outputs: Vec<(Option<String>, String)> = witx_abi::handle_outputs(sig)
                .into_iter()
                .map(|(name, kind)| {
                    let field = name.and_then(|name| sig.outputs().iter().position(|(n, _)| *n == name)).and_then(|i| fields.get(i).cloned());
                    (field, kind)
                })
                .collect();
            if !outputs.is_empty() {
                spec.outputs.insert(key.clone(), outputs);
            }
            if let Some(b) = manifest.function(key).and_then(|f| f.handle.clone()) {
                let names = info.param_names();
                for p in [&b.handle, &b.key, &b.value, &b.body].into_iter().flatten() {
                    if !names.contains(p) {
                        bail!("{key}: handle binding names parameter {p:?}; it has {}", names.join(", "));
                    }
                }
                spec.bindings.insert(key.clone(), b);
            }
        }
        for key in manifest.host.iter().flat_map(|h| h.functions.iter()).filter(|(_, f)| f.handle.is_some()).map(|(k, _)| k) {
            if !self.sigs.contains_key(key) {
                bail!("platform binds {key}, which its witx lacks");
            }
        }
        Ok(spec)
    }

    pub(super) fn link(&self, engine: &Engine) -> Result<wasmtime::InstancePre<Host>> {
        let mut linker: wasmtime::Linker<Host> = wasmtime::Linker::new(engine);
        super::p1::link(&mut linker)?;
        for imp in self.module.imports() {
            let ExternType::Func(ft) = imp.ty() else { continue };
            let (m, n) = (imp.module(), imp.name());
            let key = format!("{m}#{n}");
            if let Some(sig) = self.sigs.get(&key) {
                witx_abi::check_import(&sig.params, &sig.results, &ft).with_context(|| format!("import {key}"))?;
                let sig = sig.clone();
                linker.func_new(m, n, ft.clone(), move |mut caller, params, results| {
                    call(&mut caller, &key, &sig, params, results).map_err(wasmtime::Error::from_anyhow)
                })?;
            } else if let Some(u) = self.unsupported.get(&key) {
                // The real host has it; appfuzz cannot describe it. Answer
                // `unsupported` where the ABI has a status, else trap.
                let code = u.status.as_ref().and_then(|s| s.code("unsupported"));
                let ty = u.results.first().cloned();
                let reason = u.reason.clone();
                linker.func_new(m, n, ft.clone(), move |_caller, _params, results| match (code, &ty) {
                    (Some(c), Some(t)) => {
                        results[0] = raw(t, c);
                        Ok(())
                    }
                    _ => Err(wasmtime::Error::msg(format!("{key} is not supported by appfuzz ({reason})"))),
                })?;
            }
        }
        // Imports in no witx file trap when called.
        linker.define_unknown_imports_as_traps(&self.module)?;
        linker.instantiate_pre(&self.module).map_err(anyhow::Error::from).context("linking the module")
    }
}

fn raw(t: &ValType, v: u64) -> wasmtime::Val {
    match t {
        ValType::I64 => wasmtime::Val::I64(v as i64),
        _ => wasmtime::Val::I32(v as u32 as i32),
    }
}

/// One host call from the module: lift, intercept, lower.
fn call(caller: &mut Caller<'_, Host>, key: &str, sig: &Sig, params: &[wasmtime::Val], results: &mut [wasmtime::Val]) -> Result<()> {
    let memory = caller.get_export("memory").and_then(|e| e.into_memory()).ok_or_else(|| anyhow!("the module exports no memory"))?;
    let status = sig.status.as_ref();
    let ret = sig.results.first().cloned();
    let answer = |results: &mut [wasmtime::Val], fault: witx_abi::Fault| -> Result<()> {
        match (witx_abi::fault_result(status, &fault), &ret) {
            (Some(code), Some(t)) => {
                results[0] = raw(t, code);
                Ok(())
            }
            _ => bail!("{key}: bad arguments ({})", fault.0),
        }
    };
    let args = match witx_abi::lift(sig, memory.data(&*caller), params) {
        Ok(a) => a,
        Err(f) => return answer(results, f),
    };
    caller.data_mut().read_limit = witx_abi::read_limit(sig, params);
    let n = caller.data().platform.funcs.get(key).map_or(0, |f| f.ty.results().len());
    let mut values = vec![Val::Bool(false); n];
    intercept(caller.as_context_mut(), key, &args, &mut values)?;
    match witx_abi::lower(sig, memory.data_mut(&mut *caller), params, &values) {
        Ok(Some(code)) => {
            if let Some(t) = &ret {
                results[0] = raw(t, code);
            }
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(f) => answer(results, f),
    }
}

/// What the interceptor needs to keep handles.
pub(super) struct HandleSpec {
    pub(super) bindings: BTreeMap<String, Binding>,
    /// Positions of handle parameters.
    pub(super) inputs: BTreeMap<String, Vec<usize>>,
    /// Handles in the success value: (ok record field or the value; kind).
    pub(super) outputs: BTreeMap<String, Vec<(Option<String>, String)>>,
    /// The number of parts of the success value.
    pub(super) outs: BTreeMap<String, usize>,
    pub(super) kinds: BTreeMap<String, Kind>,
    pub(super) bad: String,
    pub(super) absent: String,
}

fn ok_fields(info: &FuncInfo) -> Vec<String> {
    match info.ty.results().next() {
        Some(Type::Result(r)) => match r.ok() {
            Some(Type::Record(rec)) => rec.fields().map(|f| f.name.to_string()).collect(),
            _ => vec![],
        },
        _ => vec![],
    }
}

/// A binding's parts as the success value of the carrier result type:
/// strings and bytes converted where the type wants the other.
pub(super) fn shape(parts: Vec<Value>, ty: Option<&Type>, outs: usize) -> Value {
    let Some(Type::Result(r)) = ty else { return parts.into_iter().next().unwrap_or(Value::Null) };
    let ok = match r.ok() {
        None => Value::Null,
        Some(Type::Record(rec)) if outs > 1 => Value::Object(rec.fields().zip(parts).map(|(f, v)| (f.name.to_string(), fit(v, &f.ty))).collect()),
        Some(t) => parts.into_iter().next().map_or(Value::Null, |v| fit(v, &t)),
    };
    json!({ "ok": ok })
}

fn fit(v: Value, ty: &Type) -> Value {
    match (ty, v) {
        (Type::List(l), Value::String(s)) if matches!(l.ty(), Type::U8) => json!(s.into_bytes()),
        (Type::String, v @ Value::Array(_)) => json!(crate::handles::text(&v)),
        (Type::List(l), Value::Array(a)) => Value::Array(a.into_iter().map(|x| fit(x, &l.ty())).collect()),
        (_, v) => v,
    }
}
