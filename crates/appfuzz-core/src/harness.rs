//! Runs one export of a component against simulated host functions and records
//! everything it does.
//!
//! Every platform import is replaced by an interceptor that asks the host
//! plan what to return (or generates a value from the WIT type), charges
//! virtual latency and cost, and records the call with its arguments and
//! the guest stack that made it. WASI is real wasmtime-wasi, made
//! deterministic: virtual clocks, seeded randomness, captured output, no
//! files, no network, sleeps that only advance virtual time.

use std::collections::{BTreeMap, BTreeSet};
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
use crate::value::{Generator, json_to_val, val_to_json, val_to_json_with};
use crate::wasi::{CountingRng, MonotonicClock, Ready, VirtualClock, WallClock, format_datetime, parse_datetime};
use crate::wit::{self, FuncInfo, ImportKind, Interface};

#[path = "harness_core.rs"]
mod core;
use core::CoreApp;
#[path = "harness_extism.rs"]
mod extism;
#[path = "harness_http.rs"]
mod http;
use extism::ExtismApp;

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
    /// Functions whose manifest rules label results by argument: their own
    /// labels and the rules.
    label_rules: BTreeMap<String, (Option<crate::labels::ResultLabels>, Vec<crate::plan::Rule>)>,
    /// Value constraints of host results.
    constraints: BTreeMap<String, Vec<(String, crate::constraints::Constraint)>>,
    argument_checks: BTreeMap<String, crate::value_contract::HostChecks>,
    /// The manifest's rules: what the host always answers for some arguments.
    rules: BTreeMap<String, Vec<crate::plan::CompiledRule>>,
    queries: BTreeMap<String, crate::dataset::Query>,
    mutations: BTreeMap<String, crate::dataset::Mutation>,
    datasets: BTreeMap<String, crate::dataset::Dataset>,
    /// Plain modules on a witx platform: handles and their bindings.
    handles: Option<core::HandleSpec>,
    /// Functions the platform says never fail: injected failures are not delivered.
    infallible: BTreeSet<String>,
}

/// How a run instantiates the app.
enum Pre {
    Component(InstancePre<Host>),
    /// A plain module on a witx platform; a run calls `start`.
    Core {
        pre: wasmtime::InstancePre<Host>,
        start: String,
    },
    /// An Extism plugin; a run calls the export's function of the module.
    Extism {
        pre: wasmtime::InstancePre<Host>,
        abi: Arc<crate::extism::Abi>,
        names: Arc<BTreeMap<String, String>>,
    },
}

impl Pre {
    /// A plain module with WASI preview 1.
    fn plain(&self) -> bool {
        !matches!(self, Pre::Component(_))
    }
}

pub struct App {
    pub engine: Engine,
    pub bytes: Vec<u8>,
    pub hash: String,
    pub contract: String,
    pub state_key: String,
    pub manifest: Manifest,
    pub imports: Vec<Interface>,
    pub exports: Vec<FuncInfo>,
    pre: Pre,
    platform: Arc<Platform>,
    ticker_stop: Arc<AtomicBool>,
    feedback_readers: Vec<String>,
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
    /// WASI preview 1, for plain modules.
    p1: Option<wasmtime_wasi::p1::WasiP1Ctx>,
    table: ResourceTable,
    platform: Arc<Platform>,
    /// Module ids already computed in this run (hashing a module's
    /// imports and exports on every frame of every call is slow).
    modules: Vec<(wasmtime::Module, String)>,
    plan: Arc<Plan>,
    world: Arc<Mutex<crate::dataset::State>>,
    seed: u64,
    /// The caller's id for generated `identity` and `owner` values.
    identity: String,
    clock: VirtualClock,
    fuel_start: u64,
    ns_per_fuel: f64,
    events: Vec<HostCall>,
    calls: BTreeMap<String, u32>,
    /// When the next host call started, if before it was answered: an
    /// outgoing HTTP request is in flight from `handle` until the guest
    /// waits for it, alongside the guest's work and other requests.
    call_started_ns: Option<u64>,
    /// How long the next host call may take before it times out (an
    /// outgoing request's `first-byte-timeout`).
    call_deadline_ns: Option<u64>,
    plan_error: Option<String>,
    host_trap: Option<String>,
    limiter: Limiter,
    /// The handles the host gave out in this run (plain modules).
    handles: crate::handles::Handles,
    /// The request argument, which the client-request handles hold.
    request: Option<Value>,
    /// The buffer length of the current read-style call.
    read_limit: Option<usize>,
    /// Extism plugins: the kernel's byte store.
    kernel: Option<crate::extism::Kernel>,
    /// The last handle given out for a platform resource (`connection.open`).
    resource_rep: u32,
    /// wasi:http resources and requests in flight.
    http: http::Http,
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

/// An error message: the cause on the first line, which titles and
/// `explain` show, then the backtrace cut to its innermost frames.
fn short_message(err: &wasmtime::Error) -> String {
    let Some(bt) = err.downcast_ref::<WasmBacktrace>() else { return format!("{err:#}") };
    let frames = bt.to_string();
    let header = frames.lines().next().unwrap_or_default();
    let cause: Vec<String> = err.chain().map(|e| e.to_string()).filter(|e| !e.starts_with(header)).collect();
    let lines: Vec<&str> = frames.lines().collect();
    let frames = if lines.len() <= 21 { frames.clone() } else { format!("{}\n    … {} more frames", lines[..21].join("\n"), lines.len() - 21) };
    if cause.is_empty() { frames } else { format!("{}\n{frames}", cause.join(": ")) }
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
        Self::from_bytes_engine(manifest, bytes, engine)
    }

    pub(crate) fn from_feedback(manifest: Manifest, bytes: Vec<u8>, readers: Vec<String>) -> Result<Self> {
        let mut app = Self::from_bytes_engine(manifest, bytes, engine()?)?;
        app.feedback_readers = readers;
        Ok(app)
    }

    fn from_bytes_engine(mut manifest: Manifest, bytes: Vec<u8>, engine: Engine) -> Result<Self> {
        manifest.binary = crate::manifest::Binary::of(&bytes);
        let hash = component_hash(&bytes);
        // The manifest as written identifies the contract. Built-in labels
        // added below follow from the component and appfuzz's version, both
        // already in the key, and commands that only read stored runs and
        // findings never load the component to add them.
        let contract = manifest.fingerprint();
        let state_key = manifest.state_key(&hash);
        let extism_abi = manifest.host.as_ref().is_some_and(|h| h.platform.abi.as_deref() == Some("extism"));
        let mut plugin = None;
        let (component, core, imports, exports) = if wasmparser::Parser::is_core_wasm(&bytes) && extism_abi {
            let p = ExtismApp::new(&engine, &manifest, &bytes)?;
            let (imports, exports) = (p.imports.clone(), p.exports.clone());
            plugin = Some(p);
            (None, None, imports, exports)
        } else if wasmparser::Parser::is_core_wasm(&bytes) {
            let core = CoreApp::new(&engine, &manifest, &bytes)?;
            let (imports, exports) = (core.imports.clone(), core.exports.clone());
            (None, Some(core), imports, exports)
        } else {
            let component = Component::new(&engine, &bytes).map_err(anyhow::Error::from).context("not a WebAssembly component or module")?;
            let mut imports = wit::imports(&engine, &component);
            let mut exports = wit::exports(&engine, &component);
            crate::wasi_http::adapt(&engine, &mut imports, &mut exports)?;
            crate::wasi_http::default_manifest(&mut manifest, &imports, &exports)?;
            crate::known::defaults(&mut manifest, &imports)?;
            (Some(component), None, imports, exports)
        };

        let mut platform = Platform {
            funcs: BTreeMap::new(),
            granted: BTreeMap::new(),
            cost: BTreeMap::new(),
            latency_ms: BTreeMap::new(),
            marks: BTreeMap::new(),
            label_rules: BTreeMap::new(),
            constraints: BTreeMap::new(),
            argument_checks: BTreeMap::new(),
            rules: BTreeMap::new(),
            queries: BTreeMap::new(),
            mutations: BTreeMap::new(),
            datasets: manifest.datasets.clone(),
            handles: None,
            infallible: BTreeSet::new(),
        };
        crate::labels::check_wit(&manifest, &imports)?;
        if let Some(entry) = &mut manifest.entry
            && !entry.input_values.is_empty()
        {
            let export = exports.iter().find(|e| fn_key_eq(&e.key, &entry.export)).context("input_values export not found")?;
            let (_, ty) = export.ty.params().next().context("input_values needs a request argument")?;
            for (path, domain) in &mut entry.input_values {
                domain.validate_input_type(&ty, path).with_context(|| format!("input_values {path}"))?;
            }
        }
        crate::dataset::validate(&manifest.datasets)?;
        if let Some(suite) = &manifest.acceptance {
            suite.validate(&manifest)?;
            suite.validate_wit(&manifest, &imports, &exports)?;
        }
        for spec in manifest.functions.values() {
            if spec.query.is_some() && spec.mutation.is_some() {
                bail!("a host function cannot have both query and mutation bindings");
            }
            if let Some(m) = &spec.mutation {
                m.validate(&manifest.datasets)?;
                let expected = match m.operation {
                    crate::dataset::Operation::Delete => crate::manifest::Effect::Delete,
                    _ => crate::manifest::Effect::Write,
                };
                if spec.effect != Some(expected) {
                    bail!("mutation binding requires effect = {}", expected.name());
                }
            }
            if let Some(q) = &spec.query {
                q.validate(&manifest.datasets)?;
            }
        }
        for iface in imports.iter().filter(|i| i.kind == ImportKind::Platform) {
            for f in &iface.funcs {
                platform.granted.insert(f.key.clone(), iface.name.is_empty() || manifest.grants_interface(&iface.name));
                platform.cost.insert(f.key.clone(), manifest.cost_of(&f.key));
                platform.latency_ms.insert(f.key.clone(), manifest.latency_ms_of(&f.key));
                platform.funcs.insert(f.key.clone(), f.clone());
                if manifest.function(&f.key).and_then(|s| s.fails) == Some(false) {
                    platform.infallible.insert(f.key.clone());
                }
                if let Some(spec) = manifest.function(&f.key).filter(|s| !s.param_values.is_empty()) {
                    let params = f.ty.params().map(|(n, t)| (n.to_string(), t)).collect::<Vec<_>>();
                    let checks = crate::value_contract::HostChecks::compile(&params, &spec.param_values).with_context(|| format!("{} param_values", f.key))?;
                    platform.argument_checks.insert(f.key.clone(), checks);
                }
                if let Some(m) = manifest.function(&f.key).and_then(|s| s.mutation.as_ref()) {
                    let names = f.param_names();
                    if m.fields.values().chain(m.filter.values()).any(|p| !names.iter().any(|n| n == p.split('.').next().unwrap_or(""))) {
                        bail!("{}: mutation names an unknown parameter", f.key);
                    }
                    let results: Vec<_> = f.ty.results().collect();
                    if results.len() != 1 {
                        bail!("{}: mutation requires one WIT result", f.key);
                    }
                    json_to_val(&m.response, &results[0]).context("mutation success response does not match WIT")?;
                    json_to_val(&m.reject, &results[0]).context("mutation rejection response does not match WIT")?;
                    platform.mutations.insert(f.key.clone(), m.clone());
                }
                if let Some(q) = manifest.function(&f.key).and_then(|s| s.query.as_ref()) {
                    let names = f.param_names();
                    if q.filter.values().any(|p| !names.contains(p)) {
                        bail!("{}: dataset filter names an unknown parameter", f.key);
                    }
                    let types: Vec<_> = f.ty.results().collect();
                    if types.len() != 1 {
                        bail!("{}: dataset query requires one WIT result", f.key);
                    }
                    let sizes = manifest.datasets.keys().map(|k| (k.clone(), 1)).collect();
                    let world = crate::dataset::build(&manifest.datasets, &sizes, 0)?;
                    let mut sample_query = q.clone();
                    sample_query.filter.clear();
                    let check = |w: &crate::dataset::World| -> Result<()> {
                        let value = sample_query.resolve(w, &[])?;
                        json_to_val(&value, &types[0]).with_context(|| format!("{}: dataset response does not match WIT", f.key))?;
                        Ok(())
                    };
                    check(&world)?;
                    for (field, values) in &manifest.datasets[&q.dataset].choices {
                        for value in values {
                            let mut variant = world.clone();
                            variant.get_mut(&q.dataset).expect("validated")[0][field] = value.clone();
                            check(&variant)?;
                        }
                    }
                    let mut empty = world;
                    empty.get_mut(&q.dataset).expect("validated").clear();
                    check(&empty)?;
                    platform.queries.insert(f.key.clone(), q.clone());
                }
                let marks: Vec<_> = manifest
                    .result_labels(&f.key)
                    .into_iter()
                    .filter(|(_, l)| matches!(l, crate::labels::Label::Pii | crate::labels::Label::Secret) || l.is_id())
                    .collect();
                if !marks.is_empty() {
                    platform.marks.insert(f.key.clone(), marks);
                }
                if let Some(spec) = manifest.function(&f.key).filter(|s| s.rules.iter().any(|r| r.result.is_some())) {
                    platform.label_rules.insert(f.key.clone(), (spec.result.clone(), spec.rules.clone()));
                }
                if let Some(spec) = manifest.function(&f.key).filter(|s| !s.rules.is_empty()) {
                    platform.rules.insert(f.key.clone(), crate::plan::compile_rules(&spec.rules));
                }
                if let Some(spec) = manifest.function(&f.key).filter(|s| !s.values.is_empty()) {
                    platform.constraints.insert(f.key.clone(), spec.values.iter().map(|(p, c)| (p.clone(), c.clone())).collect());
                }
            }
        }

        if let Some(core) = &core {
            let spec = core.handle_spec(&manifest, &platform.funcs)?;
            // Handle bookkeeping is free unless the manifest prices it.
            for key in spec.bindings.keys() {
                let f = manifest.function(key);
                if f.and_then(|f| f.cost).is_none() {
                    platform.cost.insert(key.clone(), 0);
                }
                if f.and_then(|f| f.latency_ms).is_none() {
                    platform.latency_ms.insert(key.clone(), 0.0);
                }
            }
            platform.handles = Some(spec);
        }
        let pre = match (component, core, plugin) {
            (_, _, Some(p)) => Pre::Extism { pre: p.link(&engine)?, abi: p.abi.clone(), names: p.names.clone() },
            (_, Some(core), _) => Pre::Core { pre: core.link(&engine)?, start: core.start },
            (Some(component), None, None) => Pre::Component(link_component(&engine, &component, &imports, crate::wasi_http::uses_http(&imports, &exports))?),
            (None, None, None) => unreachable!("one of them"),
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

        Ok(App {
            contract,
            state_key,
            engine,
            bytes,
            hash,
            manifest,
            imports,
            exports,
            pre,
            platform: Arc::new(platform),
            ticker_stop,
            feedback_readers: vec![],
        })
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
            contract: self.contract.clone(),
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
        // Clock fields are paths of the platform's request: every export
        // that has them gets them.
        if let (Some(e), Some(first)) = (self.manifest.entry.as_ref(), args.first_mut()) {
            set_clock_fields(first, &e.fields, now);
        }
        Ok(args)
    }

    pub fn initial_state(&self, plan: &Plan, seed: u64) -> Result<crate::dataset::State> {
        let defaults = plan.0.get("_defaults");
        Ok(crate::dataset::State::new(crate::dataset::build(
            &self.manifest.datasets,
            &defaults.map(|p| p.dataset_rows.clone()).unwrap_or_default(),
            defaults.and_then(|p| p.dataset_seed).unwrap_or(seed),
        )?))
    }

    pub fn run(&self, spec: &RunSpec) -> RunRecord {
        self.run_shared(spec, None)
    }

    /// Sequence records include the starting state in their identity. They are
    /// replayed as a sequence, never through the stateless run cache.
    pub fn run_in_state(&self, spec: &RunSpec, state: Arc<Mutex<crate::dataset::State>>) -> RunRecord {
        self.run_shared(spec, Some(state))
    }

    fn run_shared(&self, spec: &RunSpec, state: Option<Arc<Mutex<crate::dataset::State>>>) -> RunRecord {
        self.run_captured(spec, state).0
    }

    pub(crate) fn feedback(&self, spec: &RunSpec) -> Result<crate::feedback::Feedback> {
        let (record, feedback) = self.run_captured(spec, None);
        if matches!(record.outcome.kind, OutcomeKind::Error | OutcomeKind::PlanError) {
            bail!("{}", record.outcome.message.unwrap_or_else(|| "feedback run could not execute".into()));
        }
        Ok(feedback)
    }

    fn run_captured(&self, spec: &RunSpec, state: Option<Arc<Mutex<crate::dataset::State>>>) -> (RunRecord, crate::feedback::Feedback) {
        let started = Instant::now();
        let id = if let Some(s) = &state {
            let mut bytes = serde_json::to_vec(&*s.lock().unwrap_or_else(|e| e.into_inner())).expect("state serializes");
            bytes.extend_from_slice(spec.id().as_bytes());
            format!("s{}", &blake3::hash(&bytes).to_hex()[..16])
        } else {
            spec.id()
        };
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
        let mut feedback = crate::feedback::Feedback::default();
        if let Err(e) = self.run_inner(spec, &mut record, state, &mut feedback) {
            record.outcome = Outcome { kind: OutcomeKind::Error, message: Some(format!("{e:#}")), stack: vec![] };
        }
        record.totals.wall_us = started.elapsed().as_micros() as u64;
        (record, feedback)
    }

    fn run_inner(
        &self,
        spec: &RunSpec,
        record: &mut RunRecord,
        state: Option<Arc<Mutex<crate::dataset::State>>>,
        feedback: &mut crate::feedback::Feedback,
    ) -> Result<()> {
        if spec.component != self.hash {
            bail!("spec is for component {}, this is {}", spec.component, self.hash);
        }
        if spec.contract != self.contract {
            bail!("saved run uses a different platform contract or engine; use replay --against-current for a regression check");
        }
        let export = self.export(&spec.export)?.clone();
        let params: Vec<_> = export.ty.params().collect();
        if params.len() != spec.args.len() {
            bail!("{} takes {} arguments, got {}", export.key, params.len(), spec.args.len());
        }
        let args =
            params.iter().zip(&spec.args).map(|((name, ty), v)| json_to_val(v, ty).with_context(|| format!("argument {name}"))).collect::<Result<Vec<_>>>()?;

        let start = parse_datetime(&spec.now).ok_or_else(|| anyhow!("bad time {:?}", spec.now))?;
        let start_ns = (start.max(0) as u64).checked_mul(1_000_000_000).ok_or_else(|| anyhow!("time {:?} is past the year 2554", spec.now))?;
        let clock = VirtualClock::new(start_ns);
        let drawn = Arc::new(Mutex::new(0u64));
        let stdout = MemoryOutputPipe::new(OUTPUT_CAPACITY);
        let stderr = MemoryOutputPipe::new(OUTPUT_CAPACITY);
        let mut builder = WasiCtx::builder();
        builder
            .wall_clock(WallClock(clock.clone()))
            .monotonic_clock(MonotonicClock(clock.clone()))
            .secure_random(CountingRng::new(spec.seed, drawn.clone()))
            .insecure_random(CountingRng::new(spec.seed ^ 0x5eed, drawn.clone()))
            .insecure_random_seed(spec.seed as u128)
            .stdout(stdout.clone())
            .stderr(stderr.clone());
        // Plain modules use WASI preview 1, made the same way.
        let (ctx, p1) = if self.pre.plain() { (WasiCtx::builder().build(), Some(builder.build_p1())) } else { (builder.build(), None) };
        let kernel = match &self.pre {
            Pre::Extism { abi, .. } => Some(crate::extism::Kernel::new(extism::input(abi, &export, &args), spec.memory as usize)),
            _ => None,
        };
        let host = Host {
            ctx,
            p1,
            table: ResourceTable::new(),
            platform: self.platform.clone(),
            modules: Vec::new(),
            plan: Arc::new(spec.plan.clone()),
            world: match state {
                Some(s) => s,
                None => Arc::new(Mutex::new(self.initial_state(&spec.plan, spec.seed)?)),
            },
            seed: spec.seed,
            identity: crate::identity::caller(spec, &self.manifest),
            clock: clock.clone(),
            fuel_start: spec.fuel,
            ns_per_fuel: spec.ns_per_fuel,
            events: vec![],
            calls: BTreeMap::new(),
            call_started_ns: None,
            call_deadline_ns: None,
            plan_error: None,
            host_trap: None,
            limiter: Limiter { max: spec.memory, peak: 0, hit: false },
            handles: Default::default(),
            request: matches!(self.pre, Pre::Core { .. }).then(|| spec.args.first().cloned()).flatten(),
            read_limit: None,
            kernel,
            http: Default::default(),
            resource_rep: 0,
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|h| &mut h.limiter);
        store.set_fuel(spec.fuel)?;
        let ticks = (self.manifest.limits.wall_timeout_ms / EPOCH_TICK.as_millis() as u64).max(1);
        store.set_epoch_deadline(ticks);
        store.epoch_deadline_trap();

        let mut instance = None;
        let call = match &self.pre {
            Pre::Component(pre) => {
                let inst = pre.instantiate(&mut store).map_err(anyhow::Error::from).context("instantiating the component")?;
                // Instantiation may run start code; measure from here.
                let fuel_start = store.get_fuel()?;
                store.data_mut().fuel_start = fuel_start;
                let func = lookup_export(&inst, &mut store, &export)?;
                let call = if crate::wasi_http::is_handler(&export) {
                    // The request record becomes an incoming request; the
                    // response set on the outparam becomes the result.
                    let request = spec.args.first().cloned().unwrap_or(Value::Null);
                    // The response JSON is the result as it is: the carrier
                    // type has no place for binary bodies or trailers.
                    http::call_handler(&mut store, func, &request)?.map(|response| {
                        store.data_mut().http.result = Some(response);
                        vec![]
                    })
                } else {
                    let mut results = vec![Val::Bool(false); export.ty.results().len()];
                    func.call(&mut store, &args, &mut results).and_then(|()| http::flush(&mut store)).map(|()| results)
                };
                instance = Some(inst);
                call
            }
            Pre::Core { pre, start } => {
                let inst = pre.instantiate(&mut store).map_err(anyhow::Error::from).context("instantiating the module")?;
                let fuel_start = store.get_fuel()?;
                store.data_mut().fuel_start = fuel_start;
                let func = inst.get_typed_func::<(), ()>(&mut store, start).map_err(anyhow::Error::from)?;
                match func.call(&mut store, ()) {
                    Ok(()) => Ok(vec![]),
                    // `proc_exit(0)` ends a run normally.
                    Err(e) if e.downcast_ref::<wasmtime_wasi::I32Exit>().is_some_and(|x| x.0 == 0) => Ok(vec![]),
                    Err(e) => Err(e),
                }
            }
            Pre::Extism { pre, names, .. } => {
                let inst = pre.instantiate(&mut store).map_err(anyhow::Error::from).context("instantiating the plugin")?;
                let fuel_start = store.get_fuel()?;
                store.data_mut().fuel_start = fuel_start;
                let name = names.get(&export.key).ok_or_else(|| anyhow!("the plugin does not export {}", export.key))?;
                let func = inst.get_typed_func::<(), i32>(&mut store, name).map_err(anyhow::Error::from)?;
                func.call(&mut store, ()).map(|status| vec![Val::S32(status)])
            }
        };
        let fuel_start = store.data().fuel_start;

        let fuel_left = store.get_fuel().unwrap_or(0);
        let used = fuel_start.saturating_sub(fuel_left);
        let guest_ns = (used as f64 * spec.ns_per_fuel) as u64;
        clock.with(|c| c.guest_ns = guest_ns);

        match call {
            // A plain module's result is the response it sent, if any.
            Ok(_) if matches!(self.pre, Pre::Core { .. }) => record.result = store.data_mut().handles.response.take(),
            Ok(_) if crate::wasi_http::is_handler(&export) => record.result = store.data_mut().http.result.take(),
            Ok(status) if let Pre::Extism { abi, .. } = &self.pre => {
                let status = match status.first() {
                    Some(Val::S32(s)) => *s,
                    _ => 0,
                };
                let k = store.data().kernel.as_ref().expect("plugin runs have a kernel");
                match extism::answer(abi, &export, status, k.output.as_deref(), k.error.as_deref()) {
                    Ok(v) => record.result = Some(v),
                    Err(message) => record.outcome = Outcome { kind: OutcomeKind::Trap, message: Some(message), stack: vec![] },
                }
            }
            Ok(results) => {
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
            peak_memory: data.limiter.peak + data.kernel.as_ref().map_or(0, |k| k.peak as u64),
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
        let kernel_logs = data.kernel.as_mut().map(|k| std::mem::take(&mut k.logs)).unwrap_or_default();
        if let Some(instance) = instance.filter(|_| !self.feedback_readers.is_empty()) {
            store.set_fuel(10_000_000)?;
            store.set_epoch_deadline(100);
            for (module, name) in self.feedback_readers.iter().enumerate() {
                let read = instance.get_typed_func::<(), (Vec<u8>,)>(&mut store, name)?;
                let (bytes,) = read.call(&mut store, ())?;
                feedback.decode(&bytes, module as u32)?;
            }
        }
        drop(store);
        record.stdout = String::from_utf8_lossy(&stdout.contents()).into_owned();
        record.stderr = String::from_utf8_lossy(&stderr.contents()).into_owned();
        // Extism logs go to the host, which shows them like stderr.
        for (level, text) in kernel_logs {
            record.stderr.push_str(&format!("[{level}] {text}\n"));
        }
        Ok(())
    }
}

/// Links a component: wasmtime-wasi made deterministic, and every
/// platform import routed to the interceptor.
fn link_component(engine: &Engine, component: &Component, imports: &[Interface], uses_http: bool) -> Result<InstancePre<Host>> {
    let mut linker: Linker<Host> = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_sync(&mut linker)?;
    linker.allow_shadowing(true);
    if uses_http {
        http::link(&mut linker)?;
    }
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
    let resources: BTreeMap<String, Vec<String>> = component
        .component_type()
        .imports(engine)
        .filter_map(|(name, item)| match item.ty {
            wasmtime::component::types::ComponentItem::ComponentInstance(ci) => Some((
                name.to_string(),
                ci.exports(engine)
                    .filter(|(_, e)| matches!(e.ty, wasmtime::component::types::ComponentItem::Resource(_)))
                    .map(|(n, _)| n.to_string())
                    .collect(),
            )),
            _ => None,
        })
        .collect();
    let mut next_resource = 0u32;
    // The outgoing handler is linked by `http::link`.
    for iface in imports.iter().filter(|i| i.kind == ImportKind::Platform && !crate::wasi_http::is_client(&i.name)) {
        if iface.name.is_empty() {
            for f in &iface.funcs {
                let key = f.key.clone();
                linker.root().func_new(&f.name, move |store, ty, params, results| {
                    intercept_component(store, &ty, &key, params, results).map_err(wasmtime::Error::from_anyhow)
                })?;
            }
            continue;
        }
        let mut inst = linker.instance(&iface.name)?;
        // Its resources (a database connection, a key-value store): the
        // host hands out handles and gets them back in method calls.
        for name in resources.get(iface.name.as_str()).into_iter().flatten() {
            inst.resource(name, wasmtime::component::ResourceType::host_dynamic(RESOURCE_BASE + next_resource), |_, _| Ok(()))?;
            next_resource += 1;
        }
        for f in &iface.funcs {
            let key = f.key.clone();
            inst.func_new(&f.name, move |store, ty, params, results| {
                intercept_component(store, &ty, &key, params, results).map_err(wasmtime::Error::from_anyhow)
            })?;
        }
    }
    // Link as is first. `define_unknown_imports_as_traps` matches names
    // exactly, so for an older WASI import (`wasi:cli/environment@0.2.9`)
    // it adds an `@0.2.9` instance of traps that shadows wasmtime-wasi's
    // semver-compatible 0.2.12 definition. Only stub when something is
    // really missing (an import nobody provides, like wasi:http).
    Ok(match linker.instantiate_pre(component) {
        Ok(pre) => pre,
        Err(_) => {
            linker.define_unknown_imports_as_traps(component)?;
            linker.instantiate_pre(component).map_err(anyhow::Error::from).context("linking the component")?
        }
    })
}

pub fn component_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..16].to_string()
}

pub fn fn_key_eq(a: &str, b: &str) -> bool {
    let (i, f) = a.split_once('#').unwrap_or(("", a));
    a == b || fn_key(i, f) == b
}

fn lookup_export(instance: &wasmtime::component::Instance, store: &mut Store<Host>, export: &FuncInfo) -> Result<wasmtime::component::Func> {
    let idx = if export.interface.is_empty() {
        instance.get_export_index(&mut *store, None, &export.name)
    } else {
        let iface = instance.get_export_index(&mut *store, None, &export.interface).ok_or_else(|| anyhow!("no exported interface {}", export.interface))?;
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
    // Labels that depend on the arguments (a secret variable, a public one).
    let by_args: Option<Vec<_>> = platform.label_rules.get(key).map(|(own, rules)| {
        crate::plan::result_labels_for(own.as_ref(), rules, &args)
            .into_iter()
            .filter(|(_, l)| matches!(l, crate::labels::Label::Pii | crate::labels::Label::Secret) || l.is_id())
            .collect()
    });
    let value_checks = platform.argument_checks.get(key).map(|checks| checks.check(&args));
    // The platform's rules come first: the host keeps its promises, whatever
    // the plan or the fuzzer says.
    let mut resolved = match platform.rules.get(key) {
        Some(rules) => crate::plan::resolve_compiled_rules(rules, &args, None).unwrap_or_else(|| data.plan.resolve(key, call, &args)),
        None => data.plan.resolve(key, call, &args),
    };
    let commit_trap = match &resolved.decision {
        Decision::CommitThenTrap(msg) => Some(msg.clone()),
        _ => None,
    };
    if commit_trap.is_some() && (!platform.mutations.contains_key(key) || resolved.source.starts_with("manifest rule")) {
        data.plan_error = Some("commit_then_trap requires a modeled mutation in a host plan".into());
        bail!("commit_then_trap requires a modeled mutation in a host plan");
    }
    // Dataset bindings are platform guarantees. Raw success mutations cannot
    // contradict the shared world. Explicit service failures remain injectable.
    // A call the platform says never fails answers normally, whatever a
    // plan or the fuzzer injected.
    if platform.infallible.contains(key) && !resolved.source.starts_with("manifest rule") {
        let injected = match &resolved.decision {
            Decision::Trap(_) | Decision::CommitThenTrap(_) => true,
            Decision::Return(v) => v.get("err").is_some(),
            Decision::Generate(o) => o.results.as_deref() == Some("err"),
        };
        if injected {
            resolved.decision = Decision::Generate(Default::default());
            resolved.source = "platform: never fails".into();
        }
    }
    let failure = match &resolved.decision {
        Decision::CommitThenTrap(_) => false,
        Decision::Trap(_) => true,
        Decision::Return(v) => v.get("err").is_some() || v.is_null(),
        Decision::Generate(o) => o.results.as_deref() == Some("err") || o.options.as_deref() == Some("none"),
    };
    if !resolved.source.starts_with("manifest rule")
        && !failure
        && let Some(query) = platform.queries.get(key)
    {
        resolved.decision = Decision::Return(query.resolve(&data.world.lock().unwrap_or_else(|e| e.into_inner()).tables, &args)?);
        resolved.source = format!("dataset {}", query.dataset);
    }
    let mut pending_state = None;
    if !resolved.source.starts_with("manifest rule")
        && !failure
        && let Some(mutation) = platform.mutations.get(key)
    {
        let current = data.world.lock().unwrap_or_else(|e| e.into_inner());
        let (next, response) = mutation.prepare(&platform.datasets, &current, &args)?;
        pending_state = Some(next);
        resolved.decision = Decision::Return(response);
        resolved.source = format!("dataset mutation {}", mutation.dataset);
    }
    let result_types: Vec<_> = ty.results().collect();
    // Handles: an unknown one gets the platform's error; bound calls act on
    // handle state. Manifest rules and plan failures still come first.
    let mut bound = false;
    if let Some(h) = &platform.handles
        && !resolved.source.starts_with("manifest rule")
        && !failure
    {
        let inputs = h.inputs.get(key).map(Vec::as_slice).unwrap_or_default();
        let unknown = inputs.iter().any(|&i| args.get(i).and_then(|(_, v)| v.as_u64()).is_some_and(|id| !data.handles.valid(id as u32)));
        let answer = if unknown {
            Some(serde_json::json!({ "err": h.bad }))
        } else if let Some(b) = h.bindings.get(key) {
            let ctx = crate::handles::Ctx { kinds: &h.kinds, request: data.request.as_ref(), read_limit: data.read_limit, bad: &h.bad, absent: &h.absent };
            Some(match data.handles.apply(b, &args, inputs, &ctx) {
                Ok(parts) => core::shape(parts, result_types.first(), h.outs.get(key).copied().unwrap_or(0)),
                Err(e) => serde_json::json!({ "err": e }),
            })
        } else {
            None
        };
        if let Some(v) = answer {
            resolved.decision = Decision::Return(v);
            resolved.source = "handle".into();
            bound = true;
        }
    }
    let generated = matches!(resolved.decision, Decision::Generate(_));
    let latency_ms = resolved.latency_ms.unwrap_or_else(|| platform.latency_ms.get(key).copied().unwrap_or(1.0));
    let mut latency_ns = (latency_ms * 1_000_000.0) as u64;
    // A request the guest gave a timeout fails when the timeout runs out.
    if let Some(d) = data.call_deadline_ns.take()
        && latency_ns > d
    {
        latency_ns = d;
        resolved.decision = Decision::Return(serde_json::json!({ "err": "connection-read-timeout" }));
        resolved.source = "timeout".into();
    }
    let cost = resolved.cost.unwrap_or_else(|| platform.cost.get(key).copied().unwrap_or(1));
    // A call in flight since `started` is ready at `started + latency`; the
    // guest waits only for what is left (requests sent together overlap).
    let started = data.call_started_ns.take();
    let t_ns = data.clock.with(|c| {
        let now = c.elapsed_ns();
        let t = started.map_or(now, |s| s.min(now));
        c.host_ns += (t + latency_ns).saturating_sub(now);
        t
    });

    let mut event = HostCall {
        n: data.events.len() as u32 + 1,
        func: key.to_string(),
        call,
        args: args.into_iter().map(|(k, v)| (k, compact(v))).collect::<Map<_, _>>(),
        value_checks,
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

    let outcome: Result<()> = match resolved.decision {
        Decision::CommitThenTrap(_) => unreachable!("resolved modeled mutation"),
        Decision::Trap(msg) => {
            event.trap = Some(msg.clone());
            data.host_trap = Some(msg.clone());
            Err(anyhow!("host trap from plan: {msg}"))
        }
        Decision::Return(mut v) => {
            // The host keeps its promises, whatever the plan says.
            if let (Some(c), 1) = (platform.constraints.get(key), result_types.len()) {
                if resolved.source.starts_with("dataset ") {
                    let mut conformed = v.clone();
                    crate::constraints::conform_at(&mut conformed, c, data.seed);
                    if conformed != v {
                        data.plan_error = Some(format!("dataset response for {key} contradicts value constraints"));
                        bail!("dataset response contradicts value constraints");
                    }
                } else {
                    crate::constraints::conform_at(&mut v, c, data.seed);
                }
            }
            let vals: Result<Vec<Val>> = match result_types.len() {
                0 => Ok(vec![]),
                1 => json_to_val(&v, &result_types[0]).map(|x| vec![x]),
                n => match &v {
                    Value::Array(a) if a.len() == n => a.iter().zip(&result_types).map(|(v, t)| json_to_val(v, t)).collect(),
                    _ => Err(anyhow!("expected an array of {n} results")),
                },
            };
            match vals {
                Ok(vals) => {
                    if let Some(next) = pending_state {
                        *data.world.lock().unwrap_or_else(|e| e.into_inner()) = next;
                    }
                    if let Some(msg) = commit_trap {
                        event.trap = Some(msg.clone());
                        data.host_trap = Some(msg.clone());
                        data.events.push(event);
                        bail!("host response lost after commit: {msg}");
                    }
                    event.result = Some(compact(v));
                    for (r, v) in results.iter_mut().zip(vals) {
                        *r = v;
                    }
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
            if let (Some(marks), [v], [t]) = (by_args.as_ref().or(platform.marks.get(key)), vals.as_mut_slice(), result_types.as_slice()) {
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
            event.result = Some(match vals.as_slice() {
                [] => Value::Null,
                [one] => val_to_json_with(one, &recorded),
                many => Value::Array(many.iter().map(|v| val_to_json_with(v, &recorded)).collect()),
            });
            for (r, v) in results.iter_mut().zip(vals) {
                *r = v;
            }
            Ok(())
        }
    };
    // Handles in an answer that no binding made: generated ones get fresh
    // ids, ones a plan returned join the table.
    if outcome.is_ok()
        && !bound
        && let Some(h) = &platform.handles
        && let Some(outs) = h.outputs.get(key)
        && let ([r], [t]) = (&mut *results, result_types.as_slice())
    {
        let mut j = val_to_json(r);
        data.handles.adopt(&mut j, outs, generated, &h.kinds);
        if let Ok(v) = json_to_val(&j, t) {
            *r = v;
            event.result = Some(compact(j));
        }
    }
    data.events.push(event);
    outcome
}

/// A component's platform import: as `intercept`, then owned resources in
/// the answer become handles. Their types come from the linked function
/// type, where imported resources are the host's.
fn intercept_component(mut store: StoreContextMut<'_, Host>, ty: &ComponentFunc, key: &str, params: &[Val], results: &mut [Val]) -> Result<()> {
    let answer = intercept(wasmtime::AsContextMut::as_context_mut(&mut store), key, params, results);
    // Handles the guest passed in (a borrowed `self`) are released by the
    // host, or the call fails with borrows outstanding.
    let mut passed = Vec::new();
    for p in params {
        resources_in(p, &mut passed);
    }
    for r in passed {
        r.resource_drop(&mut store)?;
    }
    answer?;
    let types: Vec<_> = ty.results().collect();
    if let ([t], Some(e)) = (types.as_slice(), store.data_mut().events.last_mut())
        && let Some(r) = e.result.as_mut()
    {
        show_resources(r, t);
    }
    for (r, t) in results.iter_mut().zip(&types) {
        give_resources(r, t, &mut store)?;
    }
    Ok(())
}

/// Recorded answers show a handle as `"<resource>"`.
fn show_resources(v: &mut Value, ty: &wasmtime::component::Type) {
    use wasmtime::component::Type as T;
    match (ty, v) {
        (T::Own(_), v) => *v = Value::String("<resource>".into()),
        (T::List(l), Value::Array(xs)) => xs.iter_mut().for_each(|x| show_resources(x, &l.ty())),
        (T::Record(r), Value::Object(m)) => {
            for f in r.fields() {
                if let Some(x) = m.get_mut(f.name) {
                    show_resources(x, &f.ty);
                }
            }
        }
        (T::Tuple(t), Value::Array(xs)) => t.types().zip(xs.iter_mut()).for_each(|(t, x)| show_resources(x, &t)),
        (T::Option(o), v) if !v.is_null() => match v.get_mut("some") {
            Some(x) => show_resources(x, &o.ty()),
            None => show_resources(v, &o.ty()),
        },
        (T::Result(r), Value::Object(m)) => {
            if let (Some(x), Some(t)) = (m.get_mut("ok"), r.ok()) {
                show_resources(x, &t);
            }
            if let (Some(x), Some(t)) = (m.get_mut("err"), r.err()) {
                show_resources(x, &t);
            }
        }
        _ => {}
    }
}

fn resources_in(v: &Val, out: &mut Vec<wasmtime::component::ResourceAny>) {
    match v {
        Val::Resource(r) => out.push(*r),
        Val::List(xs) | Val::Tuple(xs) | Val::FixedLengthList(xs) => xs.iter().for_each(|x| resources_in(x, out)),
        Val::Record(fs) => fs.iter().for_each(|(_, x)| resources_in(x, out)),
        Val::Option(Some(x)) | Val::Variant(_, Some(x)) | Val::Result(Ok(Some(x)) | Err(Some(x))) => resources_in(x, out),
        _ => {}
    }
}

/// Payloads of the host resource types appfuzz defines for platform imports.
const RESOURCE_BASE: u32 = 0x4146_0000;
const MAX_RESOURCES: u32 = 4096;

/// Replaces the placeholders `json_to_val` and the generator leave for an
/// owned resource with a fresh handle of the right type.
fn give_resources(v: &mut Val, ty: &wasmtime::component::Type, store: &mut StoreContextMut<'_, Host>) -> Result<()> {
    use wasmtime::component::Type as T;
    match (ty, v) {
        (T::Own(rt), v) => {
            let payload = (RESOURCE_BASE..RESOURCE_BASE + MAX_RESOURCES)
                .find(|&p| wasmtime::component::ResourceType::host_dynamic(p) == *rt)
                .ok_or_else(|| anyhow!("appfuzz can't create this resource (it is not a resource of a platform import)"))?;
            store.data_mut().resource_rep += 1;
            let rep = store.data().resource_rep;
            *v = Val::Resource(wasmtime::component::ResourceDynamic::new_own(rep, payload).try_into_resource_any(&mut *store)?);
        }
        (T::List(l), Val::List(items)) => {
            let t = l.ty();
            for x in items {
                give_resources(x, &t, store)?;
            }
        }
        (T::Record(r), Val::Record(fields)) => {
            for (f, (_, x)) in r.fields().zip(fields.iter_mut()) {
                give_resources(x, &f.ty, store)?;
            }
        }
        (T::Tuple(t), Val::Tuple(items)) => {
            for (t, x) in t.types().zip(items.iter_mut()) {
                give_resources(x, &t, store)?;
            }
        }
        (T::Option(o), Val::Option(Some(x))) => give_resources(x, &o.ty(), store)?,
        (T::Result(r), Val::Result(res)) => match res {
            Ok(Some(x)) => {
                if let Some(t) = r.ok() {
                    give_resources(x, &t, store)?;
                }
            }
            Err(Some(x)) => {
                if let Some(t) = r.err() {
                    give_resources(x, &t, store)?;
                }
            }
            _ => {}
        },
        (T::Variant(var), Val::Variant(case, Some(x))) => {
            if let Some(t) = var.cases().find(|c| c.name == case.as_str()).and_then(|c| c.ty) {
                give_resources(x, &t, store)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Strings longer than this are cut in recorded host calls.
const MAX_RECORDED_STRING: usize = 1024;

/// A host-call value as recorded: long strings keep their first 256
/// characters and a `…[N bytes]` marker. The app gets the full value; the
/// record stays small (32 results × 10 kB strings × 200 calls is 200 MB).
/// A quick hash of a long string, eight bytes at a time.
fn hash32(b: &[u8]) -> u32 {
    const K: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut h = b.len() as u64;
    let (chunks, rest) = b.as_chunks::<8>();
    for c in chunks {
        h = (h ^ u64::from_le_bytes(*c)).wrapping_mul(K).rotate_left(29);
    }
    for &x in rest {
        h = (h ^ x as u64).wrapping_mul(K).rotate_left(29);
    }
    h ^= h >> 32;
    h = h.wrapping_mul(K);
    (h >> 32) as u32
}

/// A long string as recorded. The hash keeps strings that differ after the
/// cut apart.
fn cut(s: &str) -> String {
    let n = s.len();
    let end = s.char_indices().nth(256).map_or(n, |(i, _)| i);
    format!("{}…[{n} bytes #{:08x}]", &s[..end], hash32(s.as_bytes()))
}

/// A string of a host-call value as recorded.
fn recorded(s: &str) -> Value {
    Value::String(if s.len() > MAX_RECORDED_STRING { cut(s) } else { s.to_string() })
}

fn compact(mut v: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::String(s) if s.len() > MAX_RECORDED_STRING => *s = cut(s),
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
    if path.is_empty() {
        return Some(v);
    }
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
    if path.is_empty() {
        return Some(v);
    }
    let mut cur = v;
    for seg in path.split('.') {
        cur = match cur {
            Value::Object(o) => o.get(seg)?,
            Value::Array(a) => a.iter().find(|p| p.as_array().and_then(|p| p.first()).and_then(Value::as_str) == Some(seg))?.as_array()?.get(1)?,
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
