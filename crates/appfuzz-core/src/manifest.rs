//! `appfuzz.toml`: what appfuzz knows about an app and its platform.
//!
//! Phase 1 needs only `[app]`, `[entry]`, `[grants]` and `[limits]`.
//! `[functions]` adds per host function cost and latency; `[web]` is
//! reserved for phase 2 labels and kept as raw data.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::labels::{Label, ResultLabels};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub app: AppSection,
    #[serde(default)]
    pub entry: Option<Entry>,
    #[serde(default)]
    pub grants: Grants,
    #[serde(default)]
    pub limits: Limits,
    /// Per host function settings, keyed by `interface#function` (with or
    /// without the interface version).
    #[serde(default)]
    pub functions: BTreeMap<String, FunctionSpec>,
    /// Reserved for phase 2 (labels for how the platform treats output).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<Value>,
    /// Where the manifest was loaded from; relative paths resolve against it.
    #[serde(skip)]
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSection {
    pub wasm: PathBuf,
    #[serde(default)]
    pub name: Option<String>,
    /// Untrusted text from the app author.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The export appfuzz calls: `interface#function` or a top-level function.
    pub export: String,
    /// The default argument (for a one-parameter export) as WIT-shaped JSON,
    /// or an array of arguments.
    #[serde(default)]
    pub request: Option<Value>,
    /// Roles of request fields (`clock.date`, `clock.time`, `http.query`, …).
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub output: Output,
    /// Virtual wall clock at the start of a run, `YYYY-MM-DDTHH:MM:SS`.
    #[serde(default)]
    pub now: Option<String>,
}

/// Where to find things in the export's result. Paths are dot-separated
/// field names, e.g. `body` or `response.body`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub status: Option<String>,
    pub body: Option<String>,
    pub headers: Option<String>,
    pub body_format: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    /// Interfaces the app may import (without version). `None`: no grant
    /// list, every import is linked and nothing is reported.
    #[serde(default)]
    pub imports: Option<Vec<String>>,
    /// WASI interface prefixes the app may import, e.g. `wasi:clocks`.
    #[serde(default)]
    pub wasi: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Production fuel (instructions) per call.
    #[serde(default = "default_fuel")]
    pub fuel: u64,
    /// Production memory limit in bytes (`"64MiB"` or a number).
    #[serde(default = "default_memory", deserialize_with = "de_bytes")]
    pub memory: u64,
    /// Cost units one call may spend on host calls.
    #[serde(default)]
    pub cost_per_request: Option<u64>,
    /// Cost of a host call without its own entry in `[functions]`.
    #[serde(default = "default_cost")]
    pub default_cost: u64,
    /// A call taking longer than this (virtual time) is slow.
    #[serde(default)]
    pub max_latency_ms: Option<f64>,
    /// Virtual latency of a host call without its own setting.
    #[serde(default = "default_host_latency")]
    pub default_host_latency_ms: f64,
    /// Virtual nanoseconds per unit of fuel (instruction).
    #[serde(default = "default_ns_per_fuel")]
    pub ns_per_fuel: f64,
    /// Real time after which a run is stopped, whatever the fuel says.
    #[serde(default = "default_wall_timeout")]
    pub wall_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel: default_fuel(),
            memory: default_memory(),
            cost_per_request: None,
            default_cost: default_cost(),
            max_latency_ms: None,
            default_host_latency_ms: default_host_latency(),
            ns_per_fuel: default_ns_per_fuel(),
            wall_timeout_ms: default_wall_timeout(),
        }
    }
}

fn default_fuel() -> u64 {
    2_000_000_000
}
fn default_memory() -> u64 {
    64 * 1024 * 1024
}
fn default_cost() -> u64 {
    1
}
fn default_host_latency() -> f64 {
    1.0
}
fn default_ns_per_fuel() -> f64 {
    0.5
}
fn default_wall_timeout() -> u64 {
    10_000
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionSpec {
    #[serde(default)]
    pub cost: Option<u64>,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    /// Reserved for phase 2 labels (`read`, `write`, `identity`, …).
    #[serde(default)]
    pub effect: Option<String>,
    /// Labels of parameters: a sink (`sql`, `path`, `shell`, `url`, `html`,
    /// `regex`) or what they may receive (`pii`, `secret`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, Label>,
    /// Labels of the result: `untrusted`, `html`, `pii`, `secret`, for the
    /// whole result or by field path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultLabels>,
}

fn de_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        N(u64),
        S(String),
    }
    match Raw::deserialize(d)? {
        Raw::N(n) => Ok(n),
        Raw::S(s) => parse_bytes(&s).map_err(serde::de::Error::custom),
    }
}

/// Parses `64MiB`, `64MB`, `64M`, `65536`.
pub fn parse_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().with_context(|| format!("not a size: {s:?}"))?;
    let mult = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        other => bail!("unknown size unit {other:?}"),
    };
    Ok(n * mult)
}

/// `bench:web/items@0.1.0` → `bench:web/items`.
pub fn strip_version(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// The key appfuzz uses for a host function: `interface#function`, without
/// the interface version.
pub fn fn_key(interface: &str, func: &str) -> String {
    if interface.is_empty() { func.to_string() } else { format!("{}#{func}", strip_version(interface)) }
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut m: Manifest = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        m.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        crate::labels::check_positions(&m).with_context(|| format!("in {}", path.display()))?;
        Ok(m)
    }

    /// A manifest for a bare `.wasm` without `appfuzz.toml`.
    pub fn for_wasm(wasm: &Path) -> Self {
        Manifest {
            app: AppSection { wasm: wasm.to_path_buf(), name: None, description: None },
            entry: None,
            grants: Grants::default(),
            limits: Limits::default(),
            functions: BTreeMap::new(),
            web: None,
            dir: PathBuf::new(),
        }
    }

    pub fn wasm_path(&self) -> PathBuf {
        if self.app.wasm.is_absolute() { self.app.wasm.clone() } else { self.dir.join(&self.app.wasm) }
    }

    pub fn function(&self, key: &str) -> Option<&FunctionSpec> {
        self.functions.get(key).or_else(|| {
            // Also accept keys written with a version.
            self.functions.iter().find(|(k, _)| {
                let (i, f) = k.split_once('#').unwrap_or(("", k));
                fn_key(i, f) == key
            }).map(|(_, v)| v)
        })
    }

    /// The label of a host function parameter.
    pub fn param_label(&self, key: &str, param: &str) -> Option<Label> {
        self.function(key).and_then(|f| f.params.get(param).copied())
    }

    /// The labelled result paths of a host function.
    pub fn result_labels(&self, key: &str) -> Vec<(String, Label)> {
        self.function(key).and_then(|f| f.result.as_ref()).map(ResultLabels::paths).unwrap_or_default()
    }

    /// Whether any parameter is labelled as a sink.
    pub fn has_sinks(&self) -> bool {
        self.functions.values().any(|f| f.params.values().any(|l| l.is_sink()))
    }

    pub fn cost_of(&self, key: &str) -> u64 {
        self.function(key).and_then(|f| f.cost).unwrap_or(self.limits.default_cost)
    }

    pub fn latency_ms_of(&self, key: &str) -> f64 {
        self.function(key).and_then(|f| f.latency_ms).unwrap_or(self.limits.default_host_latency_ms)
    }

    /// Whether an imported platform interface is granted (version ignored).
    pub fn grants_import(&self, interface: &str) -> bool {
        match &self.grants.imports {
            None => true,
            Some(list) => list.iter().any(|g| strip_version(g) == strip_version(interface)),
        }
    }

    /// Whether a WASI interface is granted by prefix (`wasi:clocks` grants
    /// `wasi:clocks/monotonic-clock@0.2.12`).
    pub fn grants_wasi(&self, interface: &str) -> bool {
        match &self.grants.wasi {
            None => true,
            Some(list) => list.iter().any(|g| interface.starts_with(g.as_str())),
        }
    }

    pub fn start_time(&self) -> String {
        self.entry.as_ref().and_then(|e| e.now.clone()).unwrap_or_else(|| "2026-01-15T10:00:00".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_bytes("64MiB").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_bytes("100").unwrap(), 100);
        assert!(parse_bytes("3 parsecs").is_err());
    }

    #[test]
    fn keys() {
        assert_eq!(fn_key("bench:web/items@0.1.0", "all"), "bench:web/items#all");
        assert_eq!(fn_key("", "run"), "run");
    }

    #[test]
    fn parses_manifest() {
        let m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "x:y/handler#handle"
            request = { method = "GET", query = [] }
            fields = { today = "clock.date" }
            [grants]
            imports = ["x:y/items-read"]
            [limits]
            memory = "64MiB"
            cost_per_request = 100
            [functions."x:y/items-write#create"]
            cost = 5
            "#,
        )
        .unwrap();
        assert_eq!(m.limits.memory, 64 * 1024 * 1024);
        assert_eq!(m.cost_of("x:y/items-write#create"), 5);
        assert_eq!(m.cost_of("x:y/items-read#all"), 1);
        assert!(m.grants_import("x:y/items-read@0.1.0"));
        assert!(!m.grants_import("x:y/items-write@0.1.0"));
    }

    #[test]
    fn parses_labels() {
        let m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [functions."x:y/db#query"]
            params = { sql = "sql" }
            [functions."x:y/users#current"]
            result = { email = "pii", "bio-html" = "html" }
            [functions."x:y/config#secret"]
            result = "secret"
            "#,
        )
        .unwrap();
        crate::labels::check_positions(&m).unwrap();
        assert_eq!(m.param_label("x:y/db#query", "sql"), Some(Label::Sql));
        assert!(m.has_sinks());
        assert_eq!(m.result_labels("x:y/config#secret"), vec![(String::new(), Label::Secret)]);
        assert_eq!(m.result_labels("x:y/users#current").len(), 2);
        let bad: Manifest = toml::from_str("[app]\nwasm = \"a\"\n[functions.\"x#f\"]\nresult = \"sql\"\n").unwrap();
        assert!(crate::labels::check_positions(&bad).is_err());
        assert!(toml::from_str::<Manifest>("[app]\nwasm = \"a\"\n[functions.\"x#f\"]\nparams = { a = \"nosql\" }\n").is_err());
    }
}
