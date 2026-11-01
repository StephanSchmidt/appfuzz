//! What a run is (its spec) and what happened (its record).
//!
//! A run is pure: the same spec on the same component gives the same
//! record (apart from `wall_us`). The run id is a hash of the spec, so
//! asking twice for the same thing finds the stored answer.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::plan::Plan;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunSpec {
    /// blake3 of the component bytes.
    pub component: String,
    /// `interface#function` or a top-level function.
    pub export: String,
    /// Arguments as WIT-shaped JSON, one per parameter.
    pub args: Vec<Value>,
    #[serde(default)]
    pub plan: Plan,
    /// Virtual wall clock at the start, `YYYY-MM-DDTHH:MM:SS`.
    pub now: String,
    /// Seed for WASI randomness and generated host responses.
    pub seed: u64,
    /// Fuel the run may spend (can be above the production limit, so the
    /// overrun can be measured).
    pub fuel: u64,
    /// Memory the run may grow to, in bytes.
    pub memory: u64,
    /// Virtual ns per instruction.
    pub ns_per_fuel: f64,
}

impl RunSpec {
    pub fn id(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("spec serializes");
        let h = blake3::hash(&bytes).to_hex();
        format!("r{}", &h[..10])
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    Ok,
    OutOfFuel,
    Timeout,
    StackOverflow,
    Unreachable,
    OutOfMemory,
    MemoryOutOfBounds,
    /// A host function trapped because the plan said so.
    HostTrap,
    /// The plan gave a value that does not fit the function's type.
    PlanError,
    /// Another trap (division by zero, bad cast, …).
    Trap,
    /// appfuzz could not run the call (bad arguments, instantiation).
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub kind: OutcomeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Guest frames at the trap, innermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack: Vec<Frame>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Frame {
    /// Short id of the core module (see `appfuzz wasm info`).
    pub module: String,
    /// Function index in the module's function index space.
    pub func: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Byte offset of the instruction within the core module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCall {
    /// 1-based position among all host calls of the run.
    pub n: u32,
    /// `interface#function`.
    pub func: String,
    /// 1-based number of calls to this function so far.
    pub call: u32,
    /// Arguments by parameter name.
    pub args: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// Which part of the plan decided (`rule 0`, `generated`, …).
    pub source: String,
    /// False if the manifest does not grant the interface.
    pub granted: bool,
    pub latency_ns: u64,
    pub cost: u64,
    /// Guest instructions spent before this call.
    pub fuel_before: u64,
    /// Virtual time at the call, ns since the start.
    pub t_ns: u64,
    /// Guest frames that made the call, innermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack: Vec<Frame>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Totals {
    /// Instructions (fuel) spent.
    pub fuel: u64,
    pub peak_memory: u64,
    /// Virtual time of the whole call.
    pub virtual_ns: u64,
    pub guest_ns: u64,
    pub host_ns: u64,
    pub sleep_ns: u64,
    pub host_calls: u32,
    pub cost: u64,
    pub clock_reads: u64,
    pub random_bytes: u64,
    /// Real time the run took, µs (not deterministic).
    pub wall_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    pub spec: RunSpec,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub totals: Totals,
    pub events: Vec<HostCall>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
}

impl RunRecord {
    /// Calls per host function, in first-call order.
    pub fn call_counts(&self) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = Vec::new();
        for e in &self.events {
            match out.iter_mut().find(|(k, _)| *k == e.func) {
                Some((_, n)) => *n += 1,
                None => out.push((e.func.clone(), 1)),
            }
        }
        out
    }
}

/// Short id of a core module from its import and export names, so frames
/// seen at run time map to modules found by static analysis.
pub fn module_id<'a>(imports: impl Iterator<Item = (&'a str, &'a str)>, exports: impl Iterator<Item = &'a str>) -> String {
    let mut h = blake3::Hasher::new();
    for (m, n) in imports {
        h.update(b"i:");
        h.update(m.as_bytes());
        h.update(b"/");
        h.update(n.as_bytes());
        h.update(b";");
    }
    for e in exports {
        h.update(b"e:");
        h.update(e.as_bytes());
        h.update(b";");
    }
    format!("m{}", &h.finalize().to_hex()[..6])
}
