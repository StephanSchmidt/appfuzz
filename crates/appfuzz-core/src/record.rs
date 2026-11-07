//! What a run is (its spec) and what happened (its record).
//!
//! A run is pure: the same spec on the same component gives the same
//! record (apart from `wall_us`). The run id is a hash of the spec, so
//! asking twice for the same thing finds the stored answer.

use crate::natural::Natural;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::plan::Plan;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunSpec {
    /// blake3 of the component bytes.
    pub component: String,
    /// Effective platform contract and engine identity. Empty for legacy records.
    #[serde(default)]
    pub contract: String,
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
        hashed_id('r', &bytes)
    }

    /// Compare the exact serialized inputs used by the run identity. Unlike
    /// `PartialEq`, this preserves distinctions such as positive and negative zero.
    pub fn same_inputs(&self, other: &Self) -> bool {
        serde_json::to_vec(self).expect("spec serializes") == serde_json::to_vec(other).expect("spec serializes")
    }
}

/// Keep 128 bits for persisted identities; callers may still use unique prefixes.
pub(crate) fn hashed_id(prefix: char, bytes: &[u8]) -> String {
    format!("{prefix}{}", &blake3::hash(bytes).to_hex()[..32])
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
    /// Execution stopped with a measured production-budget violation.
    BudgetExceeded,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostCall {
    /// 1-based position among all host calls of the run.
    pub n: u32,
    /// `interface#function`.
    pub func: String,
    /// 1-based number of calls to this function so far.
    pub call: u32,
    /// Arguments by parameter name.
    pub args: Map<String, Value>,
    /// Validation of complete arguments before trace compaction. Absent on legacy
    /// calls or functions without explicit parameter value declarations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_checks: Option<crate::value_contract::Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::value::present_json_value")]
    pub result: Option<Value>,
    /// Items in the returned list (or the list inside `ok`/`some`), counted
    /// on the complete answer before the trace shortens it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_items: Option<u32>,
    /// Size of the complete answer as compact JSON, before long strings are cut.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub result_bytes: u64,
    /// Set when a call with a changing effect (write, delete, external)
    /// took effect: the rows a modeled mutation changed, none for others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<Commit>,
    /// Marked records (`records::Counter`) in the arguments of a call that
    /// sends them out, per collection, counted before long strings are cut.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub records: std::collections::BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// Which part of the plan decided (`rule 0`, `generated`, …).
    pub source: String,
    /// False if the manifest does not grant the interface.
    pub granted: bool,
    pub latency_ns: Natural,
    pub cost: u64,
    /// Guest instructions spent before this call.
    pub fuel_before: u64,
    /// Virtual time at the call, ns since the start.
    pub t_ns: Natural,
    /// Guest frames that made the call, innermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack: Vec<Frame>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What a modeled mutation did to the shared world.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Commit {
    pub rows: Vec<RowChange>,
    /// The change stayed, but the guest never got the success response.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lost: bool,
}

/// One record a mutation created (`before` absent), changed or deleted (`after` absent).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RowChange {
    pub dataset: String,
    pub key: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
}

impl HostCall {
    /// Textual inspection of native HTTP body bytes. Rules, equality, storage
    /// and value-domain checks use `args`; this view is only for text detectors.
    pub(crate) fn text_args(&self) -> std::borrow::Cow<'_, Map<String, Value>> {
        let is_http = self.func.split_once('#').is_some_and(|(interface, name)| crate::wasi_http::is_client(interface) && name == "handle");
        let Some(array) = self.args.get("body").filter(|_| is_http).and_then(Value::as_array) else {
            return std::borrow::Cow::Borrowed(&self.args);
        };
        let Some(bytes) = array.iter().map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok())).collect::<Option<Vec<_>>>() else {
            return std::borrow::Cow::Borrowed(&self.args);
        };
        let mut text = Some(Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        std::borrow::Cow::Owned(
            self.args.iter().map(|(key, value)| (key.clone(), if key == "body" { text.take().expect("one body key") } else { value.clone() })).collect(),
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Totals {
    /// Instructions (fuel) spent.
    pub fuel: u64,
    pub peak_memory: u64,
    /// Virtual time of the whole call.
    pub virtual_ns: Natural,
    pub guest_ns: Natural,
    pub host_ns: Natural,
    pub sleep_ns: Natural,
    pub host_calls: u32,
    /// Exact sum of u64 host charges; unusually large totals use decimal JSON strings.
    #[serde(with = "crate::wide")]
    pub cost: u128,
    pub clock_reads: u64,
    pub random_bytes: u64,
    /// List items all host calls returned.
    #[serde(default)]
    pub host_result_items: u64,
    /// Bytes all host calls returned, as compact JSON.
    #[serde(default)]
    pub host_result_bytes: u64,
    /// Real time the run took, µs (not deterministic).
    pub wall_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: String,
    pub spec: RunSpec,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "crate::value::present_json_value")]
    pub result: Option<Value>,
    /// Terminal status of a selected standard wasi:cli/run command. A normal
    /// result maps to 0/1; an explicit exit preserves its original status code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_exit_code: Option<i32>,
    pub totals: Totals,
    pub events: Vec<HostCall>,
    /// A reviewer resource guard stopped evidence capture.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub capture_limited: bool,
    /// Error text explicitly reported by the guest, separate from engine and
    /// host-plan diagnostics in outcome.message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_error: Option<String>,
    /// Bytes returned by the guest but rejected by its declared output type.
    /// Keep these separate from engine and host-plan diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_output: Option<Vec<u8>>,
    /// At least one allocation was denied by the run's memory cap. The guest
    /// may handle a denial; this alone does not identify a later trap's cause.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub memory_limit_hit: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    /// A Shopify Function's run measured against Shopify's limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shopify: Option<crate::shopify::RunInfo>,
}

impl RunRecord {
    /// A text view for detectors; the original bytes remain lossless in the record.
    pub(crate) fn rejected_output_text(&self) -> Option<std::borrow::Cow<'_, str>> {
        let bytes = self.rejected_output.as_deref()?;
        let text = String::from_utf8_lossy(bytes);
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else { return Some(text) };
        // A rejected typed value may still be valid JSON. Its decoded keys and
        // string values can appear in diagnostics; wire escapes must not hide
        // those values from leak, encoded-flow or reviewer-text checks.
        let mut text = text.into_owned();
        append_json_text(&value, &mut text);
        Some(std::borrow::Cow::Owned(text))
    }

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

fn append_json_text(value: &Value, text: &mut String) {
    match value {
        Value::String(s) => {
            text.push('\n');
            text.push_str(s);
        }
        Value::Array(values) => values.iter().for_each(|v| append_json_text(v, text)),
        Value::Object(values) => {
            for (key, value) in values {
                text.push('\n');
                text.push_str(key);
                append_json_text(value, text);
            }
        }
        _ => {}
    }
}

/// Base id of a core module from its import and export names. Static analysis
/// adds an occurrence suffix when needed; runtime byte offsets identify that occurrence.
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
