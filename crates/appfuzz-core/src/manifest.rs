//! `appfuzz.toml`: what appfuzz knows about an app and its platform.
//!
//! The platform supplies grants, limits, labels, constraints and host rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::labels::{Label, ResultLabels};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Required, unless `[shopify]` names the function.
    #[serde(default)]
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub datasets: BTreeMap<String, crate::dataset::Dataset>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sequences: BTreeMap<String, crate::sequence::Scenario>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<crate::acceptance::Suite>,
    /// A Shopify Function: its extension types the input and output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shopify: Option<crate::shopify::Section>,
    /// Where the manifest was loaded from; relative paths resolve against it.
    #[serde(skip)]
    pub dir: PathBuf,
    /// Printable strings of the component, set when the app is loaded.
    #[serde(skip)]
    pub binary: Binary,
    /// The platform named in `[app] platform`, already merged in; kept for
    /// its types (plain modules run against its witx).
    #[serde(skip)]
    pub host: Option<std::sync::Arc<crate::host_manifest::HostManifest>>,
}

/// The component's printable strings, joined with NUL: what the app could
/// have written into its output without being given it.
#[derive(Clone, Default)]
pub struct Binary(pub std::sync::Arc<String>);

impl Binary {
    pub fn of(bytes: &[u8]) -> Self {
        let mut s = String::new();
        for (_, t) in crate::statics::strings_in(bytes, 0, 8) {
            s.push_str(&t);
            s.push('\0');
        }
        Binary(std::sync::Arc::new(s))
    }

    pub fn contains(&self, t: &str) -> bool {
        self.0.contains(t)
    }
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Binary({} bytes)", self.0.len())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSection {
    /// Required, but `[shopify]` can give it.
    #[serde(default)]
    pub wasm: PathBuf,
    #[serde(default)]
    pub name: Option<String>,
    /// Untrusted text from the app author.
    #[serde(default)]
    pub description: Option<String>,
    /// The label vocabulary the manifest is written in (`LABELS.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<String>,
    /// The path the platform serves the app under (`/apps/roomer`). A path
    /// on the same host outside it belongs to another app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// The platform the app runs on: a bundled name (`fastly`) or a path to
    /// its `platform.toml`. Its contract is merged in; the app may only tighten it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// The world of the platform's WIT this app targets, when it has several
    /// (one per app on a platform whose apps export different functions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    /// Environment variables the platform gives the app (Spin's
    /// `environment`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// What a host function does to the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Read,
    Write,
    Delete,
    External,
}

impl Effect {
    pub fn name(self) -> &'static str {
        match self {
            Effect::Read => "read",
            Effect::Write => "write",
            Effect::Delete => "delete",
            Effect::External => "external",
        }
    }

    /// Changes something: a write, a delete, or an act outside the platform.
    pub fn changes(self) -> bool {
        self != Effect::Read
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The export appfuzz calls: `interface#function` or a top-level function.
    /// Required, but may come from the platform.
    #[serde(default)]
    pub export: String,
    /// The default argument (for a one-parameter export) as WIT-shaped JSON,
    /// or an array of arguments.
    #[serde(default)]
    pub request: Option<Value>,
    /// More example requests, shaped like `request`: the fuzzer starts from
    /// each of them too (one per route, form or mode the app has).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub examples: Vec<Value>,
    /// The export's parameter names, when it has more than one: a request
    /// path may start with one (`req.now`) to be in that argument. Set when
    /// the app is loaded.
    #[serde(skip)]
    pub params: Vec<String>,
    /// Roles of request fields (`clock.date`, `clock.time`, `http.query`, …).
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    #[serde(default)]
    pub output: Output,
    /// Virtual wall clock at the start of a run, `YYYY-MM-DDTHH:MM:SS`.
    #[serde(default)]
    pub now: Option<String>,
    /// Labels of the export's result by field path: what the platform
    /// allows there (`html:no-scripts`, `html:safe`, `html:scripts`,
    /// `url:local`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub result: BTreeMap<String, crate::markup::OutputLabel>,
    /// Routes no `html:safe` markup may send a request to (`/admin`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_paths: Vec<String>,
    /// The Content-Security-Policy the platform sends with the export's
    /// HTML, on top of the app's own: under `html:scripts` both apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csp: Option<String>,
    /// The export's output never contains personal data: a value a host
    /// function returned at a `pii` path anywhere in the result is a
    /// `pii_leak` fail. Reading personal data stays allowed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_pii: bool,
    /// What the platform lets through in request fields, by path
    /// (`range:1..31`, `len:..100`, `enum:a,b`, `format:date`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub values: BTreeMap<String, crate::constraints::Constraint>,
    /// Accepted guest input domains; unlike `values`, invalid values can arrive.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub input_values: BTreeMap<String, crate::value_contract::Domain>,
    /// The combinations of request fields the platform sends (a route and
    /// its methods), one row each: a request matches a row or never comes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_of: Vec<BTreeMap<String, Pick>>,
    /// What the platform lets through for some requests only: request
    /// fields that go together (a route and its method).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<EntryRule>,
    /// The response the platform sends, made from host calls: for an app
    /// that answers with `page#set-html` and returns nothing. Keys are
    /// `status`, `body` and `headers.<name>`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub response: BTreeMap<String, crate::response::Sources>,
}

/// `[[entry.rules]]`: a request whose fields match `when` keeps to
/// `values`, on top of `[entry] values`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryRule {
    /// Request path → matcher (a value, or `{regex|range|contains|not|any}`). All must match.
    pub when: BTreeMap<String, Value>,
    pub values: BTreeMap<String, crate::constraints::Constraint>,
}

/// A field of an `[entry] one_of` row: a value the field equals (`"POST"`,
/// `3`, `true`), or a constraint it keeps to (`"enum:GET,HEAD"`).
#[derive(Debug, Clone, PartialEq)]
pub enum Pick {
    Is(Value),
    Keeps(crate::constraints::Constraint),
}

impl Pick {
    pub fn holds(&self, v: &Value) -> bool {
        match self {
            Pick::Is(x) => crate::plan::matches(x, v),
            Pick::Keeps(c) => c.holds(v),
        }
    }
}

impl Serialize for Pick {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Pick::Is(v) => v.serialize(s),
            Pick::Keeps(c) => c.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Pick {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut v = Value::deserialize(d)?;
        // Text that starts like a constraint is one, as in `values`.
        if let Some(s) = v.as_str()
            && s.split_once(':').is_some_and(|(kind, _)| matches!(kind, "range" | "len" | "enum" | "format" | "unique"))
        {
            return crate::constraints::Constraint::parse(s).map(Pick::Keeps).map_err(serde::de::Error::custom);
        }
        crate::value::toml_none(&mut v);
        Ok(Pick::Is(v))
    }
}

impl Entry {
    /// Whether the parameter `param` of host function `func` (which takes
    /// `n_params`) is a field of `[entry.response]`.
    pub fn response_param(&self, func: &str, param: &str, n_params: usize) -> bool {
        self.response.values().flat_map(|s| s.all()).any(|s| {
            s.value.is_none()
                && s.call.as_deref().is_some_and(|c| crate::harness::fn_key_eq(c, func))
                && s.arg.as_deref().map_or(n_params == 1, |a| a == param || a.replace('-', "_") == param.replace('-', "_"))
        })
    }

    /// Whether the platform limits request fields, always or by row or rule.
    pub fn constrains(&self) -> bool {
        !self.values.is_empty() || !self.one_of.is_empty() || !self.rules.is_empty()
    }

    /// Whether the request is one of the `one_of` rows: every field of the
    /// row is there and keeps to it.
    pub fn is_row(&self, args: &[Value], row: &BTreeMap<String, Pick>) -> bool {
        row.iter().all(|(p, pick)| self.field(args, p).is_some_and(|v| pick.holds(v)))
    }

    /// For a request no `one_of` row allows: the fields the rows name, and
    /// the request's values there.
    pub fn outside_one_of(&self, args: &[Value]) -> Option<(String, Value)> {
        if self.one_of.is_empty() || self.one_of.iter().any(|row| self.is_row(args, row)) {
            return None;
        }
        let paths: std::collections::BTreeSet<&String> = self.one_of.iter().flat_map(BTreeMap::keys).collect();
        let values = paths.iter().map(|p| ((*p).clone(), self.field(args, p).cloned().unwrap_or(Value::Null))).collect();
        Some((paths.into_iter().map(String::as_str).collect::<Vec<_>>().join(", "), Value::Object(values)))
    }

    /// The row a request is made to keep to: none when it is one already,
    /// else the one `seed` picks.
    pub fn row_for(&self, args: &[Value], seed: u64) -> Option<&BTreeMap<String, Pick>> {
        if self.one_of.iter().any(|row| self.is_row(args, row)) {
            return None;
        }
        self.one_of.get(usize::try_from(seed % self.one_of.len().max(1) as u64).unwrap_or(0))
    }

    /// The `values` of the rules whose `when` the request matches.
    pub fn rule_values(&self, args: &[Value]) -> Vec<(String, crate::constraints::Constraint)> {
        self.rules
            .iter()
            .filter(|r| r.when.iter().all(|(p, m)| self.field(args, p).is_some_and(|v| crate::plan::matches(m, v))))
            .flat_map(|r| r.values.iter().map(|(p, c)| (p.clone(), c.clone())))
            .collect()
    }

    /// Every constraint on this request: `values`, then the matching rules'.
    pub fn values_for(&self, args: &[Value]) -> Vec<(String, crate::constraints::Constraint)> {
        self.values.iter().map(|(p, c)| (p.clone(), c.clone())).chain(self.rule_values(args)).collect()
    }

    /// The argument a request path is in, and the path inside it. For an
    /// export with several parameters, a path that starts with a
    /// parameter's name (`req.now`, or `handler` alone) is in that
    /// argument; any other path is in the first, as for one parameter.
    pub fn locate<'p>(&self, path: &'p str) -> (usize, &'p str) {
        // `@1.now`, as `sweep` and `scale` write it.
        if path.starts_with('@') {
            return crate::scale::split_arg(path);
        }
        if self.params.len() > 1 {
            let (head, rest) = path.split_once('.').unwrap_or((path, ""));
            if let Some(i) = self.params.iter().position(|p| p == head || p.replace('-', "_") == head) {
                return (i, rest);
            }
        }
        (0, path)
    }

    /// The value at a request path ([`Entry::locate`]).
    pub fn field<'a>(&self, args: &'a [Value], path: &str) -> Option<&'a Value> {
        let (i, p) = self.locate(path);
        crate::harness::field(args.get(i)?, p)
    }

    pub fn field_mut<'a>(&self, args: &'a mut [Value], path: &str) -> Option<&'a mut Value> {
        let (i, p) = self.locate(path);
        crate::harness::field_mut(args.get_mut(i)?, p)
    }

    /// A request path as `sweep` and `scale` write it: `@1.now` for a path
    /// in the second argument, unchanged in the first.
    pub fn arg_path(&self, path: &str) -> String {
        match self.locate(path) {
            (0, rest) => rest.to_string(),
            (i, "") => format!("@{i}"),
            (i, rest) => format!("@{i}.{rest}"),
        }
    }

    /// The roles of `fields` in argument `i`, by path inside it.
    pub fn fields_in(&self, i: usize) -> BTreeMap<String, String> {
        self.fields
            .iter()
            .filter_map(|(p, r)| {
                let (j, rest) = self.locate(p);
                (j == i).then(|| (rest.to_string(), r.clone()))
            })
            .collect()
    }

    /// The argument that holds the request (`http.path`, `http.query`, …):
    /// the one the `http.` roles name, else the first.
    pub fn request_arg(&self) -> usize {
        self.fields.iter().find(|(_, r)| r.starts_with("http.")).map_or(0, |(p, _)| self.locate(p).0)
    }

    /// Sets the fields with a clock role to `now`, in every argument.
    pub fn set_clock(&self, args: &mut [Value], now: &str) {
        for (i, a) in args.iter_mut().enumerate() {
            crate::harness::set_clock_fields(a, &self.fields_in(i), now);
        }
    }

    /// The arguments of one example (`request` or one of `examples`): an
    /// array of them for an export with several parameters.
    pub fn args_of(example: &Value, params: usize) -> Vec<Value> {
        match example {
            Value::Array(a) if params != 1 => a.clone(),
            v => vec![v.clone()],
        }
    }
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
    /// Hosts the app may name as destinations: `api.example.com`, or
    /// `example.com` for it and its subdomains (see `lists_hosts`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    /// Capabilities of the platform the app asks for, by name; each grants
    /// the interfaces `platform.toml` lists for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

impl Grants {
    /// Whether the platform says which hosts the app may call: in `hosts`,
    /// or by listing other grants and no hosts (it grants none). Without
    /// any grants a host written into the app is a hint.
    pub fn lists_hosts(&self) -> bool {
        self.hosts.is_some() || self.imports.is_some() || self.wasi.is_some() || self.capabilities.is_some()
    }
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
    /// The most records of one host collection a response, the logs or
    /// the calls that send data out may carry (`mass_disclosure`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub records_per_response: Option<u64>,
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
            records_per_response: None,
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
    /// What the function does, for the agents writing apps (platform only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What each parameter means, by name (platform only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub param_docs: BTreeMap<String, String>,
    /// What the result means (platform only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_doc: Option<String>,
    /// The errors it returns and when (platform only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub errors: BTreeMap<String, String>,
    /// The SDK call that reaches this function (platform only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<String>,
    /// What the call does to handle state (platform only; witx platforms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<crate::handles::Binding>,
    /// `false`: the real host does not fail this call (the SDK treats a
    /// failure as impossible), so no failure is injected (platform only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fails: Option<bool>,
    /// Its error texts are written for the people using the app: an app
    /// that shows them leaks nothing (no `leaky_error` for them).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub user_errors: bool,
    /// Platform-declared requirements on actual guest-to-host arguments.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub param_values: BTreeMap<String, crate::value_contract::Domain>,
    /// Source of the platform's semantic parameter contract (data, not instructions).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_source: Option<String>,
    #[serde(default)]
    pub cost: Option<u64>,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    /// What a call does: `read`, `write`, `delete` or `external` (acts
    /// outside the platform: sends mail, charges a card).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,
    /// The same call twice is harmless (a write that sets, not adds).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub idempotent: bool,
    /// The change is everyone's (a shared counter, a team-wide log): its
    /// arguments may depend on other users' records.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: bool,
    /// This function does at once what `<fn>` does for one: calling `<fn>`
    /// in a loop is then an n+1 fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<crate::dataset::Query>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation: Option<crate::dataset::Mutation>,
    /// What the host promises about its result, by path (`range:0..100`,
    /// `len:..50`, `enum:a,b`, `format:date`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub values: BTreeMap<String, crate::constraints::Constraint>,
    /// What the host always answers for some arguments, whatever a plan or
    /// the fuzzer says: the platform's own rules (`create` fails for an
    /// hour outside 8..16). Same shape as plan rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<crate::plan::Rule>,
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
/// Where runs, corpora and findings of one build under one contract live.
pub fn state_key(component: &str, contract: &str) -> String {
    blake3::hash(format!("{component}:{contract}").as_bytes()).to_hex().to_string()
}

pub fn fn_key(interface: &str, func: &str) -> String {
    if interface.is_empty() { func.to_string() } else { format!("{}#{func}", strip_version(interface)) }
}

pub(crate) fn validate_timing_value(name: &str, value: f64) -> Result<()> {
    if !value.is_finite() || value < 0.0 {
        bail!("{name} must be finite and non-negative");
    }
    Ok(())
}

impl Manifest {
    pub(crate) fn validate_timing(&self) -> Result<()> {
        for (name, value) in [
            ("limits.max_latency_ms", self.limits.max_latency_ms),
            ("limits.default_host_latency_ms", Some(self.limits.default_host_latency_ms)),
            ("limits.ns_per_fuel", Some(self.limits.ns_per_fuel)),
        ] {
            if let Some(value) = value {
                validate_timing_value(name, value)?;
            }
        }
        for (name, function) in &self.functions {
            if let Some(value) = function.latency_ms {
                validate_timing_value(&format!("{name}.latency_ms"), value)?;
            }
            for (i, rule) in function.rules.iter().enumerate() {
                rule.response.validate().with_context(|| format!("{name}: rule {i}"))?;
            }
        }
        Ok(())
    }

    /// Identity of the effective platform contract, independent of its location.
    /// Bump the execution schema when simulation/detector semantics change.
    /// Acceptance checks are requirements, not contract: editing one keeps runs and corpora.
    pub fn fingerprint(&self) -> String {
        self.fingerprint_with_browser(crate::browser::GUEST)
    }

    fn fingerprint_with_browser(&self, browser: &[u8]) -> String {
        let mut v = serde_json::to_value(self).expect("manifest serializes");
        v["app"]["wasm"] = Value::Null;
        v["acceptance"] = Value::Null;
        // A Shopify function's contract is its schema, queries and targets, wherever they are.
        if let Some(s) = &self.shopify {
            v["shopify"] = s.function.as_ref().map_or(Value::Null, |f| Value::String(f.digest.clone()));
        }
        // Descriptions don't change what a run does.
        for f in v["functions"].as_object_mut().into_iter().flat_map(|m| m.values_mut()) {
            if let Some(f) = f.as_object_mut() {
                for k in ["description", "param_docs", "result_doc", "errors", "sdk"] {
                    f.remove(k);
                }
            }
        }
        let mut h = blake3::Hasher::new();
        h.update(b"appfuzz-execution-v114");
        h.update(crate::extism::KERNEL_BYTES);
        h.update(browser);
        h.update(env!("CARGO_PKG_VERSION").as_bytes());
        h.update(include_bytes!("../../../Cargo.lock"));
        h.update(&serde_json::to_vec(&v).expect("manifest serializes"));
        h.finalize().to_hex().to_string()
    }

    /// Identity of the `[acceptance]` suite; reviews and envelopes are bound to it.
    pub fn requirements_fingerprint(&self) -> String {
        let v = serde_json::to_vec(&self.acceptance).expect("acceptance serializes");
        blake3::hash(&[b"appfuzz-requirements-v1".as_slice(), &v].concat()).to_hex().to_string()
    }

    pub fn state_key(&self, component: &str) -> String {
        state_key(component, &self.fingerprint())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut m: Manifest = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        m.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if let Some(p) = m.app.platform.clone() {
            let mut host = crate::host_manifest::HostManifest::resolve(&p, &m.dir)?;
            if let Some(w) = &m.app.world {
                host.platform.world = Some(w.clone());
            }
            let table: toml::Table = toml::from_str(&text)?;
            let dir = m.dir.clone();
            m = crate::host_manifest::merge(&host, m, &table).with_context(|| format!("in {}", path.display()))?;
            m.dir = dir;
            m.host = Some(std::sync::Arc::new(host));
        }
        if m.shopify.is_some() {
            if m.host.is_some() {
                bail!("{}: [shopify] and [app] platform exclude each other", path.display());
            }
            let table: toml::Table = toml::from_str(&text)?;
            crate::shopify::attach(&mut m, &table).with_context(|| format!("in {}", path.display()))?;
        }
        if m.app.wasm.as_os_str().is_empty() {
            bail!("{}: [app] needs wasm = \"path/to/app.wasm\"", path.display());
        }
        if m.entry.as_ref().is_some_and(|e| e.export.is_empty()) {
            bail!("{}: [entry] needs export = \"interface#function\"", path.display());
        }
        crate::labels::check_positions(&m).with_context(|| format!("in {}", path.display()))?;
        m.validate_timing().with_context(|| format!("in {}", path.display()))?;
        m.toml_none();
        Ok(m)
    }

    /// TOML has no null: `{ none = true }` stands for it in every
    /// WIT-shaped value of the manifest (requests, rules, sequences, checks).
    pub fn toml_none(&mut self) {
        use crate::value::toml_none as none;
        if let Some(e) = &mut self.entry {
            e.request.iter_mut().for_each(none);
            e.examples.iter_mut().for_each(none);
        }
        for f in self.functions.values_mut() {
            f.rules.iter_mut().for_each(crate::plan::Rule::toml_none);
        }
        for s in self.sequences.values_mut() {
            s.plan.toml_none();
            for step in &mut s.steps {
                step.request.iter_mut().for_each(none);
                step.args.iter_mut().flatten().for_each(none);
                step.plan.toml_none();
            }
        }
        for c in self.acceptance.iter_mut().flat_map(|a| a.checks.values_mut()) {
            c.request.iter_mut().for_each(none);
            c.args.iter_mut().flatten().for_each(none);
            c.plan.toml_none();
            c.when.values_mut().for_each(none);
            if let Some(x) = &mut c.expect {
                none(&mut x.equals);
            }
            if let Some(r) = &mut c.relation {
                r.set.values_mut().for_each(none);
            }
        }
    }

    /// A manifest for a bare `.wasm` without `appfuzz.toml`.
    pub fn for_wasm(wasm: &Path) -> Self {
        Manifest {
            app: AppSection {
                wasm: wasm.to_path_buf(),
                name: None,
                description: None,
                labels: None,
                base: None,
                platform: None,
                world: None,
                env: BTreeMap::new(),
            },
            entry: None,
            grants: Grants::default(),
            limits: Limits::default(),
            functions: BTreeMap::new(),
            datasets: BTreeMap::new(),
            sequences: BTreeMap::new(),
            acceptance: None,
            shopify: None,
            dir: PathBuf::new(),
            binary: Binary::default(),
            host: None,
        }
    }

    pub fn wasm_path(&self) -> PathBuf {
        if self.app.wasm.is_absolute() { self.app.wasm.clone() } else { self.dir.join(&self.app.wasm) }
    }

    pub fn function(&self, key: &str) -> Option<&FunctionSpec> {
        self.functions.get(key).or_else(|| {
            // Also accept keys written with a version.
            self.functions
                .iter()
                .find(|(k, _)| {
                    let (i, f) = k.split_once('#').unwrap_or(("", k));
                    fn_key(i, f) == key
                })
                .map(|(_, v)| v)
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

    /// The result labels of one recorded call: a manifest rule can label the
    /// results for some arguments differently.
    pub fn call_result_labels(&self, key: &str, args: &serde_json::Map<String, serde_json::Value>) -> Vec<(String, Label)> {
        match self.function(key) {
            Some(f) if f.rules.iter().any(|r| r.result.is_some()) => {
                let args: Vec<(String, serde_json::Value)> = args.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                crate::plan::result_labels_for(f.result.as_ref(), &f.rules, &args)
            }
            _ => self.result_labels(key),
        }
    }

    /// Whether the export's result has labels.
    pub fn has_output_labels(&self) -> bool {
        self.entry.as_ref().is_some_and(|e| !e.result.is_empty())
    }

    /// Whether any parameter is labelled as a sink.
    pub fn has_sinks(&self) -> bool {
        self.functions.values().any(|f| f.params.values().any(|l| l.is_sink()))
    }

    pub fn effect_of(&self, key: &str) -> Option<Effect> {
        self.function(key).and_then(|f| f.effect)
    }

    /// A call that changes something and may not be repeated.
    pub fn unrepeatable(&self, key: &str) -> bool {
        self.function(key).is_some_and(|f| f.effect.is_some_and(Effect::changes) && !f.idempotent)
    }

    /// A function the manifest names as the batch version of `key`.
    pub fn batch_for(&self, key: &str) -> Option<String> {
        self.functions
            .iter()
            .find(|(_, f)| {
                f.batch_of.as_deref().is_some_and(|b| {
                    let (i, n) = b.split_once('#').unwrap_or(("", b));
                    fn_key(i, n) == key
                })
            })
            .map(|(k, _)| {
                let (i, n) = k.split_once('#').unwrap_or(("", k));
                fn_key(i, n)
            })
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

    /// Whether an imported interface is granted: WASI by prefix, others
    /// by name.
    pub fn grants_interface(&self, interface: &str) -> bool {
        if crate::wit::is_wasi(interface) { self.grants_wasi(interface) } else { self.grants_import(interface) }
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
    use serde_json::json;

    #[test]
    fn entry_paths_name_the_parameter_and_toml_writes_none() {
        let mut m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "acme:web/handler#handle"
            request = ["GET /", { path = "/", now = "", query = [["day", ""]] }]
            examples = [["POST /signup", { path = "/signup", now = "", query = [] }]]
            fields = { "req.now" = "clock.rfc3339", "@1.query.day" = "clock.date" }
            [functions."acme:web/store#get"]
            rules = [{ when = { key = "gone" }, return = { none = true } }, { when = { key = "kept" }, return = { none = false } }]
            "#,
        )
        .unwrap();
        m.toml_none();
        let rules = &m.functions["acme:web/store#get"].rules;
        assert_eq!(rules[0].response.ret, Some(Value::Null));
        assert_eq!(rules[1].response.ret, Some(json!({"none": false})), "only none = true is null");
        let e = m.entry.as_mut().unwrap();
        // One parameter: paths start inside it, whatever their first word.
        assert_eq!(e.locate("req.now"), (0, "req.now"));
        e.params = vec!["route".into(), "req".into()];
        assert_eq!(e.locate("req.now"), (1, "now"));
        assert_eq!(e.locate("@1.now"), (1, "now"));
        assert_eq!(e.locate("route"), (0, ""));
        assert_eq!(e.locate("path"), (0, "path"));
        assert_eq!(e.arg_path("req.now"), "@1.now");
        assert_eq!(e.arg_path("route"), "");
        assert_eq!(e.fields_in(0), BTreeMap::new());
        let mut args = Entry::args_of(e.request.as_ref().unwrap(), 2);
        e.set_clock(&mut args, "2026-11-02T10:00:00");
        assert_eq!(args[1]["now"], "2026-11-02T10:00:00Z");
        assert_eq!(args[1]["query"][0][1], "2026-11-02");
        assert_eq!(args[0], "GET /", "the clock leaves other arguments alone");
        assert_eq!(e.field(&args, "req.path"), Some(&json!("/")));
        assert_eq!(Entry::args_of(&e.examples[0], 2).len(), 2);
        // A one-parameter export takes an array as its single argument.
        assert_eq!(Entry::args_of(&json!(["a", "b"]), 1), vec![json!(["a", "b"])]);
    }

    #[test]
    fn entry_rules_tie_request_fields_together() {
        let mut m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "acme:web/handler#start"
            values = { handler = "enum:list,save,delete" }
            [[entry.rules]]
            when = { handler = "save" }
            values = { "req.method" = "enum:POST" }
            [[entry.rules]]
            when = { handler = { regex = "^(list|show)$" } }
            values = { "req.method" = "enum:GET,HEAD" }
            "#,
        )
        .unwrap();
        m.entry.as_mut().unwrap().params = vec!["handler".into(), "req".into()];
        let e = m.entry.as_ref().unwrap();
        let req = |h: &str, method: &str| vec![json!(h), json!({"method": method, "path": "/"})];
        // The rule that matches adds its values; `values` always apply.
        assert_eq!(e.values_for(&req("save", "GET")).len(), 2);
        assert_eq!(e.values_for(&req("delete", "GET")).len(), 1);
        assert!(crate::constraints::broken_request(&req("save", "POST"), &m).is_empty());
        assert!(crate::constraints::broken_request(&req("delete", "PUT"), &m).is_empty(), "no rule for delete");
        let broken = crate::constraints::broken_request(&req("save", "GET"), &m);
        assert_eq!(broken.iter().map(|(p, _, _)| p.as_str()).collect::<Vec<_>>(), ["req.method"]);
        // Conforming keeps generated requests to the rules, after `values`.
        for seed in 0..32 {
            let mut args = req("x", "GET");
            crate::constraints::conform_request(&mut args, &m, seed);
            assert!(crate::constraints::broken_request(&args, &m).is_empty(), "{args:?}");
        }
        let mut args = req("save", "GET");
        crate::constraints::conform_request(&mut args, &m, 1);
        assert_eq!(args[1]["method"], "POST");
    }

    #[test]
    fn one_of_lists_the_requests_the_platform_sends() {
        let mut m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            [entry]
            export = "acme:web/handler#start"
            one_of = [
              { handler = "list", "req.method" = "enum:GET,HEAD" },
              { handler = "save", "req.method" = "POST" },
              { handler = "delete", "req.method" = "POST", "req.admin" = true },
            ]
            "#,
        )
        .unwrap();
        m.entry.as_mut().unwrap().params = vec!["handler".into(), "req".into()];
        let e = m.entry.as_ref().unwrap();
        assert_eq!(e.one_of[0]["req.method"], Pick::Keeps(crate::constraints::Constraint::parse("enum:GET,HEAD").unwrap()));
        assert_eq!(e.one_of[1]["req.method"], Pick::Is(json!("POST")), "plain text is the value itself");
        let req = |h: &str, method: &str, admin: bool| vec![json!(h), json!({"method": method, "admin": admin})];
        let broken = |args: &[Value]| crate::constraints::broken_request(args, &m);
        assert!(broken(&req("list", "HEAD", false)).is_empty());
        assert!(broken(&req("save", "POST", true)).is_empty(), "a field the row leaves out is free");
        // Closed: a combination no row lists, or a handler none names.
        for args in [req("save", "GET", false), req("delete", "POST", false), req("show", "GET", false)] {
            let b = broken(&args);
            assert_eq!(b.len(), 1, "{args:?}");
            assert_eq!(b[0].0, "handler, req.admin, req.method");
            assert_eq!(b[0].2, json!({"handler": args[0], "req.admin": args[1]["admin"], "req.method": args[1]["method"]}));
        }
        // Conforming keeps a request that is a row, else makes it one, and
        // reaches every row.
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..32 {
            let mut args = req("x", "PATCH", false);
            crate::constraints::conform_request(&mut args, &m, seed);
            assert!(broken(&args).is_empty(), "{args:?}");
            seen.insert(args[0].as_str().unwrap().to_string());
        }
        assert_eq!(seen.len(), 3, "{seen:?}");
        let mut args = req("list", "HEAD", false);
        crate::constraints::conform_request(&mut args, &m, 1);
        assert_eq!(args, req("list", "HEAD", false));
        // A malformed constraint is an error, not a value.
        let bad = toml::from_str::<Manifest>("[app]\nwasm = \"a.wasm\"\n[entry]\nexport = \"x\"\none_of = [{ n = \"range:9..1\" }]\n");
        assert!(bad.unwrap_err().to_string().contains("lower bound exceeds upper bound"));
    }

    #[test]
    fn contract_identity_tracks_the_embedded_browser_build() {
        let manifest = Manifest::for_wasm(std::path::Path::new("app.wasm"));
        let original = manifest.fingerprint();
        assert_eq!(original, manifest.fingerprint_with_browser(crate::browser::GUEST));
        assert_ne!(original, manifest.fingerprint_with_browser(b"a different browser build"));
    }

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

    #[test]
    fn parses_phase2_labels() {
        let m: Manifest = toml::from_str(
            r#"
            [app]
            wasm = "a.wasm"
            labels = "1"
            [entry]
            export = "h"
            result = { body = "html:safe", "headers.location" = "url:local" }
            sensitive_paths = ["/admin"]
            values = { "query.days" = "range:1..31" }
            fields = { user = "identity" }
            [functions."x:y/store#save"]
            effect = "write"
            idempotent = true
            [functions."x:y/orders#for-user"]
            params = { user-id = "user-id" }
            result = { owner = "owner" }
            values = { total = "range:0.." }
            "#,
        )
        .unwrap();
        crate::labels::check_positions(&m).unwrap();
        assert_eq!(m.effect_of("x:y/store#save"), Some(Effect::Write));
        assert!(!m.unrepeatable("x:y/store#save"));
        assert!(m.has_output_labels());
        assert_eq!(m.param_label("x:y/orders#for-user", "user-id"), Some(Label::UserId));
        let mut v2 = m.clone();
        v2.app.labels = Some("2".into());
        assert!(crate::labels::check_positions(&v2).is_err());
        let bad = "[app]\nwasm = \"a\"\n[functions.\"x#f\"]\nidempotent = true\n";
        assert!(crate::labels::check_positions(&toml::from_str(bad).unwrap()).is_err());
        let bad = "[app]\nwasm = \"a\"\n[functions.\"x#f\"]\nshared = true\n";
        assert!(crate::labels::check_positions(&toml::from_str(bad).unwrap()).is_err());
        let good = "[app]\nwasm = \"a\"\n[functions.\"x#f\"]\neffect = \"write\"\nshared = true\n";
        crate::labels::check_positions(&toml::from_str(good).unwrap()).unwrap();
        assert!(toml::from_str::<Manifest>("[app]\nwasm = \"a\"\n[entry]\nexport = \"h\"\nvalues = { a = \"range:x..\" }\n").is_err());
    }
}
