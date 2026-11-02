//! Runs one export of a component against simulated host functions and records
//! everything it does.
//!
//! Every platform import is replaced by an interceptor that asks the host
//! plan what to return (or generates a value from the WIT type), charges
//! virtual latency and cost, and records the call with its arguments and
//! the guest stack that made it. WASI is real wasmtime-wasi, made
//! deterministic: virtual clocks, seeded randomness, captured output, no
//! files, no network, sleeps that only advance virtual time.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};
use wasmtime::component::types::ComponentFunc;
use wasmtime::component::{Component, InstancePre, Linker, Resource, ResourceTable, Val};
use wasmtime::{Config, Engine, Store, StoreContextMut, Trap, WasmBacktrace};
use wasmtime_wasi::p2::DynPollable;
use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::manifest::{Manifest, fn_key};
use crate::plan::{Decision, Plan};
use crate::record::{Frame, HostCall, Outcome, OutcomeKind, RunRecord, RunSpec, Totals, module_id};
use crate::value::{Generator, json_to_val, val_to_json};
use crate::wasi::{CountingRng, MonotonicClock, Ready, VirtualClock, WallClock, format_datetime, parse_datetime};
use crate::wit::{self, FuncInfo, ImportKind, Interface};

const EPOCH_TICK: Duration = Duration::from_millis(10);
const MAX_FRAMES: usize = 32;
const OUTPUT_CAPACITY: usize = 1 << 20;

/// What the interceptors need to know about the platform.
struct Platform {
    funcs: BTreeMap<String, FuncInfo>,
    granted: BTreeMap<String, bool>,
    cost: BTreeMap<String, u64>,
    latency_ms: BTreeMap<String, f64>,
    /// `pii` and `secret` result paths, whose generated strings are marked.
    marks: BTreeMap<String, Vec<(String, crate::labels::Label)>>,
    /// Value constraints of host results.
    constraints: BTreeMap<String, Vec<(String, crate::constraints::Constraint)>>,
}

pub struct App {
    pub engine: Engine,
    pub component: Component,
    pub bytes: Vec<u8>,
    pub hash: String,
    pub manifest: Manifest,
    pub imports: Vec<Interface>,
    pub exports: Vec<FuncInfo>,
    pre: InstancePre<Host>,
    platform: Arc<Platform>,
    ticker_stop: Arc<AtomicBool>,
}

// Runs share an `App` across threads; each run has its own store.
const _: fn() = || {
    fn sync<T: Send + Sync>() {}
    sync::<App>();
};

impl Drop for App {
    fn drop(&mut self) {
        self.ticker_stop.store(true, Ordering::Relaxed);
    }
}

struct Host {
    ctx: WasiCtx,
    table: ResourceTable,
    platform: Arc<Platform>,
    /// Module ids already computed in this run (hashing a module's
    /// imports and exports on every frame of every call is slow).
    modules: Vec<(wasmtime::Module, String)>,
    plan: Arc<Plan>,
    seed: u64,
    /// The caller's id for generated `identity` and `owner` values.
    identity: String,
    clock: VirtualClock,
    fuel_start: u64,
    ns_per_fuel: f64,
    events: Vec<HostCall>,
    calls: BTreeMap<String, u32>,
    plan_error: Option<String>,
    host_trap: Option<String>,
    limiter: Limiter,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.ctx, table: &mut self.table }
    }
}

struct Limiter {
    max: u64,
    peak: u64,
    hit: bool,
}

impl wasmtime::ResourceLimiter for Limiter {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        if desired as u64 > self.max {
            self.hit = true;
            return Ok(false);
        }
        self.peak = self.peak.max(desired as u64);
        Ok(true)
    }
    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(desired <= 1_000_000)
    }
}

impl Host {
    /// Brings the guest part of virtual time up to date from fuel spent.
    fn sync_guest_time(store: &mut StoreContextMut<'_, Host>) -> u64 {
        let left = store.get_fuel().unwrap_or(0);
        let data = store.data();
        let used = data.fuel_start.saturating_sub(left);
        let ns = (used as f64 * data.ns_per_fuel) as u64;
        data.clock.with(|c| c.guest_ns = ns);
        used
    }
}

pub fn engine() -> Result<Engine> {
    Ok(Engine::new(&base_config())?)
}

fn base_config() -> Config {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
    // Deep enough to see recursion (the default is 20 frames).
    config.wasm_backtrace_max_frames(std::num::NonZeroUsize::new(BACKTRACE_FRAMES));
    config
}

const BACKTRACE_FRAMES: usize = 1000;

/// An error message with its backtrace cut to the innermost frames and
/// the trap reason (the last line).
fn short_message(err: &wasmtime::Error) -> String {
    let full = format!("{err:#}");
    let lines: Vec<&str> = full.lines().collect();
    if lines.len() <= 24 {
        return full;
    }
    let mut out = lines[..20].join("\n");
    out.push_str(&format!("\n    … {} more frames\n{}", lines.len() - 21, lines[lines.len() - 1]));
    out
}

/// An engine that reuses instance memory across runs. Mapping fresh
/// memory per run and unmapping it after makes the kernel flush the TLB
/// of every thread: with many runs at once that costs more than the runs.
/// Falls back to a plain engine if the pool cannot be reserved.
fn pooled_engine(max_memory: u64) -> Result<Engine> {
    let slots = (rayon::current_num_threads() as u32).saturating_mul(2).max(4) + 4;
    let mut pool = wasmtime::PoolingAllocationConfig::new();
    pool.total_component_instances(slots)
        .total_core_instances(slots * 16)
        .total_memories(slots * 4)
        .total_tables(slots * 8)
        .total_stacks(slots)
        .max_core_instances_per_component(16)
        .max_memories_per_component(4)
        .max_tables_per_component(8)
        .max_memory_size(max_memory as usize)
        // A small app's memory is cleared in place, not unmapped.
        .linear_memory_keep_resident(4 << 20)
        .table_keep_resident(64 << 10);
    let mut config = base_config();
    config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(pool));
    Engine::new(&config).or_else(|_| engine())
}

impl App {
    pub fn load(manifest: Manifest) -> Result<Self> {
        let path = manifest.wasm_path();
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_bytes(manifest, bytes)
    }

    pub fn from_path(wasm: &Path) -> Result<Self> {
        Self::load(Manifest::for_wasm(wasm))
    }

    pub fn from_bytes(manifest: Manifest, bytes: Vec<u8>) -> Result<Self> {
        let engine = pooled_engine(manifest.limits.memory.saturating_mul(4))?;
        let component = Component::new(&engine, &bytes).map_err(anyhow::Error::from).context("not a WebAssembly component (appfuzz runs components only)")?;
        let hash = component_hash(&bytes);
        let imports = wit::imports(&engine, &component);
        let exports = wit::exports(&engine, &component);

        let mut platform = Platform {
            funcs: BTreeMap::new(),
            granted: BTreeMap::new(),
            cost: BTreeMap::new(),
            latency_ms: BTreeMap::new(),
            marks: BTreeMap::new(),
            constraints: BTreeMap::new(),
        };
        crate::labels::check_wit(&manifest, &imports)?;
        for iface in imports.iter().filter(|i| i.kind == ImportKind::Platform) {
            for f in &iface.funcs {
                platform.granted.insert(f.key.clone(), iface.name.is_empty() || manifest.grants_import(&iface.name));
                platform.cost.insert(f.key.clone(), manifest.cost_of(&f.key));
                platform.latency_ms.insert(f.key.clone(), manifest.latency_ms_of(&f.key));
                platform.funcs.insert(f.key.clone(), f.clone());
                let marks: Vec<_> = manifest
                    .result_labels(&f.key)
                    .into_iter()
                    .filter(|(_, l)| matches!(l, crate::labels::Label::Pii | crate::labels::Label::Secret) || l.is_id())
                    .collect();
                if !marks.is_empty() {
                    platform.marks.insert(f.key.clone(), marks);
                }
                if let Some(spec) = manifest.function(&f.key).filter(|s| !s.values.is_empty()) {
                    platform.constraints.insert(f.key.clone(), spec.values.iter().map(|(p, c)| (p.clone(), c.clone())).collect());
                }
            }
        }

        let mut linker: Linker<Host> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
        linker.allow_shadowing(true);
        // Sleeps return at once and advance virtual time. Defined under the
        // version wasmtime-wasi provides, so semver matching routes older
        // 0.2.x imports (componentize-py uses 0.2.9) here too; a definition
        // under the import's own older name would not share the host's
        // `pollable` resource type and fail to link.
        if imports.iter().any(|i| i.name.starts_with("wasi:clocks/monotonic-clock@")) {
            let mut inst = linker.instance(WASI_MONOTONIC_CLOCK)?;
            inst.func_wrap("subscribe-duration", |mut store: StoreContextMut<'_, Host>, (d,): (u64,)| {
                store.data().clock.with(|c| {
                    c.sleep_ns += d;
                    c.sleeps += 1;
                });
                Ok((ready(&mut store)?,))
            })?;
            inst.func_wrap("subscribe-instant", |mut store: StoreContextMut<'_, Host>, (when,): (u64,)| {
                let now = store.data().clock.monotonic_now();
                store.data().clock.with(|c| {
                    c.sleep_ns += when.saturating_sub(now);
                    c.sleeps += 1;
                });
                Ok((ready(&mut store)?,))
            })?;
        }
        for iface in imports.iter().filter(|i| i.kind == ImportKind::Platform) {
            if iface.name.is_empty() {
                for f in &iface.funcs {
                    let key = f.key.clone();
                    linker.root().func_new(&f.name, move |store, _ty, params, results| intercept(store, &key, params, results).map_err(wasmtime::Error::from_anyhow))?;
                }
                continue;
            }
            let mut inst = linker.instance(&iface.name)?;
            for f in &iface.funcs {
                let key = f.key.clone();
                inst.func_new(&f.name, move |store, _ty, params, results| intercept(store, &key, params, results).map_err(wasmtime::Error::from_anyhow))?;
            }
        }
        // Link as is first. `define_unknown_imports_as_traps` matches names
        // exactly, so for an older WASI import (`wasi:cli/environment@0.2.9`)
        // it adds an `@0.2.9` instance of traps that shadows wasmtime-wasi's
        // semver-compatible 0.2.12 definition. Only stub when something is
        // really missing (an import nobody provides, like wasi:http).
        let pre = match linker.instantiate_pre(&component) {
            Ok(pre) => pre,
            Err(_) => {
                linker.define_unknown_imports_as_traps(&component)?;
                linker.instantiate_pre(&component).map_err(anyhow::Error::from).context("linking the component")?
            }
        };

        let ticker_stop = Arc::new(AtomicBool::new(false));
        {
            let engine = engine.clone();
            let stop = ticker_stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    engine.increment_epoch();
                }
            });
        }

        Ok(App { engine, component, bytes, hash, manifest, imports, exports, pre, platform: Arc::new(platform), ticker_stop })
    }

    pub fn export(&self, name: &str) -> Result<&FuncInfo> {
        if let Some(f) = self.exports.iter().find(|f| f.key == name || f.name == name) {
            return Ok(f);
        }
        let (i, f) = name.split_once('#').unwrap_or(("", name));
        let key = fn_key(i, f);
        self.exports.iter().find(|e| e.key == key).ok_or_else(|| {
            let names: Vec<_> = self.exports.iter().map(|e| e.key.as_str()).collect();
            anyhow!("no export {name:?}; exports: {}", names.join(", "))
        })
    }

    /// The entry export from the manifest, or the only exported function.
    pub fn default_export(&self) -> Result<&FuncInfo> {
        if let Some(e) = &self.manifest.entry {
            return self.export(&e.export);
        }
        match self.exports.as_slice() {
            [one] => Ok(one),
            [] => bail!("the component exports no functions"),
            _ => bail!("several exports; name one (or set [entry] export in the manifest)"),
        }
    }

    /// A spec with the manifest's defaults.
    pub fn spec(&self, export: &FuncInfo, args: Vec<Value>, plan: Plan, seed: u64) -> RunSpec {
        RunSpec {
            component: self.hash.clone(),
            export: export.key.clone(),
            args,
            plan,
            now: self.manifest.start_time(),
            seed,
            fuel: self.manifest.limits.fuel.saturating_mul(5),
            memory: self.manifest.limits.memory.saturating_mul(4),
            ns_per_fuel: self.manifest.limits.ns_per_fuel,
        }
    }

    /// Arguments from the manifest's `[entry] request`, with clock fields
    /// set to `now`.
    pub fn default_args(&self, export: &FuncInfo, now: &str) -> Result<Vec<Value>> {
        let n = export.ty.params().len();
        let entry = self.manifest.entry.as_ref().filter(|e| fn_key_eq(&e.export, &export.key));
        let mut args = match entry.and_then(|e| e.request.clone()) {
            Some(Value::Array(a)) if n != 1 => a,
            Some(v) => vec![v],
            None => {
                let mut g = Generator::new(0, Default::default());
                export.ty.params().map(|(_, t)| g.gen_json(&t)).collect()
            }
        };
        if let (Some(e), Some(first)) = (entry, args.first_mut()) {
            set_clock_fields(first, &e.fields, now);
        }
        Ok(args)
    }

    pub fn run(&self, spec: &RunSpec) -> RunRecord {
        let started = Instant::now();
        let id = spec.id();
        let mut record = RunRecord {
            id,
            spec: spec.clone(),
            outcome: Outcome { kind: OutcomeKind::Ok, message: None, stack: vec![] },
            result: None,
            totals: Totals::default(),
            events: vec![],
            stdout: String::new(),
            stderr: String::new(),
        };
        if let Err(e) = self.run_inner(spec, &mut record) {
            record.outcome = Outcome { kind: OutcomeKind::Error, message: Some(format!("{e:#}")), stack: vec![] };
        }
        record.totals.wall_us = started.elapsed().as_micros() as u64;
        record
    }

    fn run_inner(&self, spec: &RunSpec, record: &mut RunRecord) -> Result<()> {
        if spec.component != self.hash {
            bail!("spec is for component {}, this is {}", spec.component, self.hash);
        }
        let export = self.export(&spec.export)?.clone();
        let params: Vec<_> = export.ty.params().collect();
        if params.len() != spec.args.len() {
            bail!("{} takes {} arguments, got {}", export.key, params.len(), spec.args.len());
        }
        let args = params
            .iter()
            .zip(&spec.args)
            .map(|((name, ty), v)| json_to_val(v, ty).with_context(|| format!("argument {name}")))
            .collect::<Result<Vec<_>>>()?;

        let start = parse_datetime(&spec.now).ok_or_else(|| anyhow!("bad time {:?}", spec.now))?;
        let start_ns = (start.max(0) as u64).checked_mul(1_000_000_000).ok_or_else(|| anyhow!("time {:?} is past the year 2554", spec.now))?;
        let clock = VirtualClock::new(start_ns);
        let drawn = Arc::new(Mutex::new(0u64));
        let stdout = MemoryOutputPipe::new(OUTPUT_CAPACITY);
        let stderr = MemoryOutputPipe::new(OUTPUT_CAPACITY);
        let ctx = WasiCtx::builder()
            .wall_clock(WallClock(clock.clone()))
            .monotonic_clock(MonotonicClock(clock.clone()))
            .secure_random(CountingRng::new(spec.seed, drawn.clone()))
            .insecure_random(CountingRng::new(spec.seed ^ 0x5eed, drawn.clone()))
            .insecure_random_seed(spec.seed as u128)
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .build();
        let host = Host {
            ctx,
            table: ResourceTable::new(),
            platform: self.platform.clone(),
            modules: Vec::new(),
            plan: Arc::new(spec.plan.clone()),
            seed: spec.seed,
            identity: crate::identity::caller(spec, &self.manifest),
            clock: clock.clone(),
            fuel_start: spec.fuel,
            ns_per_fuel: spec.ns_per_fuel,
            events: vec![],
            calls: BTreeMap::new(),
            plan_error: None,
            host_trap: None,
            limiter: Limiter { max: spec.memory, peak: 0, hit: false },
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|h| &mut h.limiter);
        store.set_fuel(spec.fuel)?;
        let ticks = (self.manifest.limits.wall_timeout_ms / EPOCH_TICK.as_millis() as u64).max(1);
        store.set_epoch_deadline(ticks);
        store.epoch_deadline_trap();

        let instance = self.pre.instantiate(&mut store).map_err(anyhow::Error::from).context("instantiating the component")?;
        // Instantiation may run start code; measure from here.
        let fuel_start = store.get_fuel()?;
        store.data_mut().fuel_start = fuel_start;
        let func = lookup_export(&instance, &mut store, &export)?;
        let mut results = vec![Val::Bool(false); export.ty.results().len()];
        let call = func.call(&mut store, &args, &mut results);

        let fuel_left = store.get_fuel().unwrap_or(0);
        let used = fuel_start.saturating_sub(fuel_left);
        let guest_ns = (used as f64 * spec.ns_per_fuel) as u64;
        clock.with(|c| c.guest_ns = guest_ns);

        match call {
            Ok(()) => {
                record.result = Some(match results.as_slice() {
                    [] => Value::Null,
                    [one] => val_to_json(one),
                    many => Value::Array(many.iter().map(val_to_json).collect()),
                });
            }
            Err(err) => record.outcome = classify(&err, store.data()),
        }

        let data = store.data_mut();
        let c = clock.with(|c| c.clone());
        record.totals = Totals {
            fuel: used,
            peak_memory: data.limiter.peak,
            virtual_ns: c.elapsed_ns(),
            guest_ns: c.guest_ns,
            host_ns: c.host_ns,
            sleep_ns: c.sleep_ns,
            host_calls: data.events.len() as u32,
            cost: data.events.iter().map(|e| e.cost).sum(),
            clock_reads: c.wall_reads + c.monotonic_reads,
            random_bytes: *drawn.lock().unwrap_or_else(|e| e.into_inner()),
            wall_us: 0,
        };
        record.events = std::mem::take(&mut data.events);
        drop(store);
        record.stdout = String::from_utf8_lossy(&stdout.contents()).into_owned();
        record.stderr = String::from_utf8_lossy(&stderr.contents()).into_owned();
        Ok(())
    }
}

pub fn component_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..16].to_string()
}

pub fn fn_key_eq(a: &str, b: &str) -> bool {
    let (i, f) = a.split_once('#').unwrap_or(("", a));
    a == b || fn_key(i, f) == b
}

fn lookup_export(
    instance: &wasmtime::component::Instance,
    store: &mut Store<Host>,
    export: &FuncInfo,
) -> Result<wasmtime::component::Func> {
    let idx = if export.interface.is_empty() {
        instance.get_export_index(&mut *store, None, &export.name)
    } else {
        let iface = instance
            .get_export_index(&mut *store, None, &export.interface)
            .ok_or_else(|| anyhow!("no exported interface {}", export.interface))?;
        instance.get_export_index(&mut *store, Some(&iface), &export.name)
    }
    .ok_or_else(|| anyhow!("no export {}", export.key))?;
    instance.get_func(&mut *store, idx).ok_or_else(|| anyhow!("{} is not a function", export.key))
}

/// The monotonic-clock interface as wasmtime-wasi 50 provides it.
const WASI_MONOTONIC_CLOCK: &str = "wasi:clocks/monotonic-clock@0.2.12";

fn ready(store: &mut StoreContextMut<'_, Host>) -> wasmtime::Result<Resource<DynPollable>> {
    let table = &mut store.data_mut().table;
    let r = table.push(Ready)?;
    wasmtime_wasi::p2::subscribe(table, r)
}

fn intercept(mut store: StoreContextMut<'_, Host>, key: &str, params: &[Val], results: &mut [Val]) -> Result<()> {
    let fuel_before = Host::sync_guest_time(&mut store);
    let stack = frames(&mut store);
    let data = store.data_mut();
    let platform = data.platform.clone();
    let info = platform.funcs.get(key).ok_or_else(|| anyhow!("unknown host function {key}"))?;
    let ty: &ComponentFunc = &info.ty;

    let call = {
        let n = data.calls.entry(key.to_string()).or_insert(0);
        *n += 1;
        *n
    };
    let names = info.param_names();
    let args: Vec<(String, Value)> = names.iter().cloned().zip(params.iter().map(val_to_json)).collect();
    let resolved = data.plan.resolve(key, call, &args);
    let latency_ms = resolved.latency_ms.unwrap_or_else(|| platform.latency_ms.get(key).copied().unwrap_or(1.0));
    let latency_ns = (latency_ms * 1_000_000.0) as u64;
    let cost = resolved.cost.unwrap_or_else(|| platform.cost.get(key).copied().unwrap_or(1));
    let t_ns = data.clock.with(|c| {
        let t = c.elapsed_ns();
        c.host_ns += latency_ns;
        t
    });

    let mut event = HostCall {
        n: data.events.len() as u32 + 1,
        func: key.to_string(),
        call,
        args: args.into_iter().map(|(k, v)| (k, compact(v))).collect::<Map<_, _>>(),
        result: None,
        trap: None,
        source: resolved.source.clone(),
        granted: platform.granted.get(key).copied().unwrap_or(true),
        latency_ns,
        cost,
        fuel_before,
        t_ns,
        stack,
    };

    let result_types: Vec<_> = ty.results().collect();
    let outcome: Result<()> = match resolved.decision {
        Decision::Trap(msg) => {
            event.trap = Some(msg.clone());
            data.host_trap = Some(msg.clone());
            Err(anyhow!("host trap from plan: {msg}"))
        }
        Decision::Return(mut v) => {
            // The host keeps its promises, whatever the plan says.
            if let (Some(c), 1) = (platform.constraints.get(key), result_types.len()) {
                crate::constraints::conform_at(&mut v, c, data.seed);
            }
            let vals: Result<Vec<Val>> = match result_types.len() {
                0 => Ok(vec![]),
                1 => json_to_val(&v, &result_types[0]).map(|x| vec![x]),
                n => match &v {
                    Value::Array(a) if a.len() == n => {
                        a.iter().zip(&result_types).map(|(v, t)| json_to_val(v, t)).collect()
                    }
                    _ => Err(anyhow!("expected an array of {n} results")),
                },
            };
            match vals {
                Ok(vals) => {
                    event.result = Some(compact(v));
                    results.clone_from_slice(&vals);
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("plan for {key} (call {call}, {}): {e:#}", resolved.source);
                    event.trap = Some(format!("plan error: {msg}"));
                    data.plan_error = Some(msg.clone());
                    Err(anyhow!("plan error: {msg}"))
                }
            }
        }
        Decision::Generate(opts) => {
            let seed = data.seed ^ blake3::hash(key.as_bytes()).as_bytes()[0] as u64 ^ ((call as u64) << 20);
            let mut g = Generator::new(seed, opts);
            let mut vals: Vec<Val> = result_types.iter().map(|t| g.gen_val(t)).collect();
            if let (Some(marks), [v], [t]) = (platform.marks.get(key), vals.as_mut_slice(), result_types.as_slice()) {
                let mut j = val_to_json(v);
                crate::labels::mark(&mut j, marks, seed, &data.identity);
                if let Ok(x) = json_to_val(&j, t) {
                    *v = x;
                }
            }
            if let (Some(c), [v], [t]) = (platform.constraints.get(key), vals.as_mut_slice(), result_types.as_slice()) {
                let mut j = val_to_json(v);
                crate::constraints::conform_at(&mut j, c, seed);
                if let Ok(x) = json_to_val(&j, t) {
                    *v = x;
                }
            }
            event.result = Some(compact(match vals.as_slice() {
                [] => Value::Null,
                [one] => val_to_json(one),
                many => Value::Array(many.iter().map(val_to_json).collect()),
            }));
            results.clone_from_slice(&vals);
            Ok(())
        }
    };
    data.events.push(event);
    outcome
}

/// Strings longer than this are cut in recorded host calls.
const MAX_RECORDED_STRING: usize = 1024;

/// A host-call value as recorded: long strings keep their first 256
/// characters and a `…[N bytes]` marker. The app gets the full value; the
/// record stays small (32 results × 10 kB strings × 200 calls is 200 MB).
fn compact(mut v: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::String(s) if s.len() > MAX_RECORDED_STRING => {
                // The hash keeps strings that differ after the cut apart.
                let n = s.len();
                let h = s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
                *s = format!("{}…[{n} bytes #{:08x}]", s.chars().take(256).collect::<String>(), h as u32);
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            Value::Object(o) => o.values_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    v
}

fn frames(store: &mut StoreContextMut<'_, Host>) -> Vec<Frame> {
    let bt = WasmBacktrace::capture(&*store);
    let cache = &mut store.data_mut().modules;
    bt.frames()
        .iter()
        .take(MAX_FRAMES)
        .map(|f| {
            let m = f.module();
            let id = match cache.iter().find(|(c, _)| wasmtime::Module::same(c, m)) {
                Some((_, id)) => id.clone(),
                None => {
                    let id = module_id_of(m);
                    cache.push((m.clone(), id.clone()));
                    id
                }
            };
            Frame { module: id, func: f.func_index(), name: f.func_name().map(str::to_string), offset: f.module_offset() }
        })
        .collect()
}

fn module_id_of(m: &wasmtime::Module) -> String {
    module_id(m.imports().map(|i| (i.module(), i.name())), m.exports().map(|e| e.name()))
}

fn frame(f: &wasmtime::FrameInfo) -> Frame {
    Frame { module: module_id_of(f.module()), func: f.func_index(), name: f.func_name().map(str::to_string), offset: f.module_offset() }
}

/// Frames before a bad memory access counts as a shadow stack overflow.
const SHADOW_STACK_DEPTH: usize = 100;

/// One function (or a pair calling each other) makes up at least half of
/// the innermost frames.
fn recursive(stack: &[Frame]) -> bool {
    stack.iter().any(|f| stack.iter().filter(|g| g.func == f.func && g.module == f.module).count() * 2 >= stack.len())
}

fn classify(err: &wasmtime::Error, host: &Host) -> Outcome {
    let bt = err.downcast_ref::<WasmBacktrace>();
    let stack: Vec<Frame> = bt.map(|bt| bt.frames().iter().take(MAX_FRAMES).map(frame).collect()).unwrap_or_default();
    let depth = bt.map(|bt| bt.frames().len()).unwrap_or(0);
    let mut message = Some(short_message(err));
    if let Some(msg) = &host.plan_error {
        return Outcome { kind: OutcomeKind::PlanError, message: Some(msg.clone()), stack };
    }
    if let Some(msg) = &host.host_trap {
        return Outcome { kind: OutcomeKind::HostTrap, message: Some(msg.clone()), stack };
    }
    let kind = match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => OutcomeKind::OutOfFuel,
        Some(Trap::Interrupt) => OutcomeKind::Timeout,
        Some(Trap::StackOverflow) => OutcomeKind::StackOverflow,
        Some(Trap::UnreachableCodeReached) if host.limiter.hit => OutcomeKind::OutOfMemory,
        Some(Trap::UnreachableCodeReached) => OutcomeKind::Unreachable,
        Some(Trap::MemoryOutOfBounds) => OutcomeKind::MemoryOutOfBounds,
        Some(_) => OutcomeKind::Trap,
        None if host.limiter.hit => OutcomeKind::OutOfMemory,
        None => OutcomeKind::Trap,
    };
    // A shadow stack in linear memory (Rust, C) runs out before the
    // engine's: a bad access deep in one recursive function.
    let kind = if kind == OutcomeKind::MemoryOutOfBounds && depth >= SHADOW_STACK_DEPTH && recursive(&stack) {
        let more = if depth >= BACKTRACE_FRAMES { "+" } else { "" };
        message = Some(format!("shadow stack overflow ({depth}{more} frames deep): {}", message.unwrap_or_default()));
        OutcomeKind::StackOverflow
    } else {
        kind
    };
    Outcome { kind, message, stack }
}

/// Sets request fields with a clock role (`clock.date`, `clock.time`,
/// `clock.datetime`) to the run's start time. Paths are dot-separated;
/// a segment also matches the key of a `[key, value]` pair in a list.
pub fn set_clock_fields(request: &mut Value, fields: &BTreeMap<String, String>, now: &str) {
    let Some(secs) = parse_datetime(now) else { return };
    let (date, time, full_time) = format_datetime(secs);
    for (path, role) in fields {
        let value = match role.as_str() {
            "clock.date" => date.clone(),
            "clock.time" => time.clone(),
            "clock.datetime" => format!("{date}T{full_time}"),
            _ => continue,
        };
        if let Some(slot) = field_mut(request, path) {
            *slot = Value::String(value);
        }
    }
}

pub fn field_mut<'a>(v: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get_mut(seg).or(None)?,
            Value::Array(a) => {
                let i = a.iter().position(|p| p.as_array().and_then(|p| p.first()).and_then(Value::as_str) == Some(seg))?;
                a[i].as_array_mut()?.get_mut(1)?
            }
            _ => return None,
        };
    }
    Some(cur)
}

pub fn field<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for seg in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get(seg)?,
            Value::Array(a) => a
                .iter()
                .find(|p| p.as_array().and_then(|p| p.first()).and_then(Value::as_str) == Some(seg))?
                .as_array()?
                .get(1)?,
            _ => return None,
        };
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn clock_fields() {
        let mut req = json!({"path": "/", "query": [["date", "x"], ["q", "y"]]});
        let fields = BTreeMap::from([("query.date".to_string(), "clock.date".to_string())]);
        set_clock_fields(&mut req, &fields, "2026-03-04T05:06:07");
        assert_eq!(req["query"][0][1], json!("2026-03-04"));
        assert_eq!(field(&req, "query.q"), Some(&json!("y")));
    }
}
