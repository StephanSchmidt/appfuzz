//! Shopify Functions: core Wasm modules that read a cart (or checkout,
//! order, …) as JSON shaped by a GraphQL input query and write operations
//! as JSON shaped by the schema's mutation input.
//!
//! A function is described by its extension's `shopify.extension.toml`:
//! its targets, each with an export and an input query, and the schema
//! (`schema.graphql`) next to it. appfuzz turns each target into a WIT
//! export (`graphql`), so the input is generated, fuzzed and shrunk like
//! any request, and runs it the way Shopify does: no host calls, the
//! input on stdin (or through Shopify's provider module), the output on
//! stdout, instructions counted the way Shopify counts them, and limits
//! that grow with the cart.

pub mod graphql;
pub mod providers;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::manifest::{Entry, Manifest};
use graphql::{Model, TargetSource};

/// Instructions a run may execute before scaling.
pub const INSTRUCTIONS: u64 = 11_000_000;
/// Input bytes before scaling.
pub const INPUT_BYTES: u64 = 128_000;
/// Output bytes before scaling.
pub const OUTPUT_BYTES: u64 = 20_000;
/// Log bytes kept; Shopify truncates the rest.
pub const LOG_BYTES: u64 = 1_000;
/// The largest module Shopify accepts.
pub const MODULE_BYTES: u64 = 256 * 1024;
/// Linear memory.
pub const MEMORY_BYTES: u64 = 10 * 1024 * 1024;
/// Limits grow with the input up to this factor.
pub const MAX_SCALE: f64 = 10.0;

/// `[shopify]` in `appfuzz.toml`: the function's extension, whose schema,
/// queries and targets type the input and output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    /// The extension's `shopify.extension.toml`, relative to the manifest.
    pub extension: PathBuf,
    /// Loaded from the extension.
    #[serde(skip)]
    pub function: Option<Arc<Function>>,
}

/// One function: its types and where they came from.
#[derive(Debug)]
pub struct Function {
    pub handle: String,
    pub api_version: Option<String>,
    pub model: Model,
    /// The model as WIT.
    pub wit: String,
    /// Identity of the schema, queries and targets: part of the contract.
    pub digest: String,
}

impl Function {
    /// The target behind a WIT export name.
    pub fn target(&self, export: &str) -> Option<&graphql::Target> {
        self.model.target(export).or_else(|| self.model.targets.iter().find(|t| t.export == export || t.target == export))
    }

    /// A request as appfuzz works with it (WIT-shaped), from one that is
    /// either that already or the input as Shopify sends it (the input
    /// query's JSON: `discountNode`, `"12.0"`, `__typename`), such as
    /// an `input.json` of Shopify's CLI. A value that is neither stays.
    pub fn request(&self, export: &str, v: Value) -> Value {
        let Some(t) = self.target(export) else { return v };
        // WIT already: Shopify's JSON of it reads back as it.
        if self.model.decode(&self.model.encode(&v, &t.input), &t.input).is_ok_and(|w| w == v) {
            return v;
        }
        self.model.decode(&v, &t.input).unwrap_or(v)
    }

    /// The values of a request Shopify never sends: (path, what Shopify
    /// sends there, the value). A negative price, a quantity of 0, an id
    /// that is not a `gid://shopify/…`.
    pub fn unsendable(&self, export: &str, args: &[Value]) -> Vec<(String, String, Value)> {
        match (self.target(export), args.first()) {
            (Some(t), Some(v)) => self.model.unsendable(v, &t.input),
            _ => Vec::new(),
        }
    }

    /// A run's output as Shopify reads it, with decimals as numbers: what
    /// `out.json` gives a rule. None when Shopify would reject the output.
    pub fn output(&self, r: &crate::record::RunRecord) -> Option<Value> {
        r.shopify.as_ref()?;
        let t = self.target(&r.spec.export)?;
        Some(self.model.readable(r.result.as_ref()?, &t.output))
    }

    /// Makes every value of a request one Shopify could send.
    pub fn conform(&self, export: &str, args: &mut [Value]) {
        if let (Some(t), Some(v)) = (self.target(export), args.first_mut()) {
            self.model.conform(v, &t.input);
        }
    }
}

/// What one run measured against Shopify's limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunInfo {
    pub target: String,
    /// How much this input raises the limits (1 to 10).
    pub scale: f64,
    /// What raises them: items (or characters) per `@scaleLimits` field,
    /// `cart.lines` → 37.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub sizes: std::collections::BTreeMap<String, u64>,
    pub instructions_limit: u64,
    pub input_bytes: u64,
    pub input_limit: u64,
    pub output_bytes: u64,
    pub output_limit: u64,
    pub log_bytes: u64,
    pub module_bytes: u64,
    /// The provider module Shopify links the function with, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Why Shopify would reject the output (empty: it accepts it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalid_output: Vec<String>,
}

impl RunInfo {
    pub fn new(target: &str, scale: f64) -> Self {
        let scaled = |base: u64| (base as f64 * scale) as u64;
        RunInfo {
            target: target.to_string(),
            scale,
            sizes: Default::default(),
            instructions_limit: scaled(INSTRUCTIONS),
            input_bytes: 0,
            input_limit: scaled(INPUT_BYTES),
            output_bytes: 0,
            output_limit: scaled(OUTPUT_BYTES),
            log_bytes: 0,
            module_bytes: 0,
            provider: None,
            invalid_output: Vec::new(),
        }
    }

    /// Shopify does not run the function on this input: it is too big.
    pub fn input_refused(&self) -> bool {
        self.input_bytes > self.input_limit
    }

    /// The input's size as a reader names it: "37 cart.lines".
    pub fn size_text(&self) -> Option<String> {
        (!self.sizes.is_empty()).then(|| self.sizes.iter().map(|(path, n)| format!("{n} {path}")).collect::<Vec<_>>().join(", "))
    }
}

#[derive(Deserialize)]
struct ExtensionToml {
    api_version: Option<String>,
    #[serde(default)]
    extensions: Vec<Extension>,
    // The format before `[[extensions]]` (API versions up to 2023-07).
    #[serde(rename = "type")]
    kind: Option<String>,
    name: Option<String>,
    build: Option<Build>,
}

#[derive(Deserialize)]
struct Extension {
    #[serde(rename = "type")]
    kind: Option<String>,
    handle: Option<String>,
    name: Option<String>,
    #[serde(default)]
    targeting: Vec<Targeting>,
    build: Option<Build>,
}

#[derive(Deserialize)]
struct Targeting {
    target: String,
    input_query: Option<String>,
    export: Option<String>,
}

#[derive(Deserialize)]
struct Build {
    path: Option<String>,
}

/// Whether a manifest path is a Shopify extension's.
pub fn is_extension(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "shopify.extension.toml")
}

/// What a function's extension says: its types and where its module is.
struct Loaded {
    function: Function,
    wasm: PathBuf,
    name: String,
}

fn load_extension(path: &Path) -> Result<Loaded> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let ext: ExtensionToml = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let (handle, name, build, targets) = if ext.extensions.is_empty() {
        // Before targets: one function, `input.graphql`, the result through `handleResult`.
        let kind = ext.kind.clone().ok_or_else(|| anyhow!("{}: no [[extensions]] and no type", path.display()))?;
        let handle = ext.name.clone().unwrap_or_else(|| kind.clone());
        let t = Targeting { target: kind, input_query: Some("input.graphql".into()), export: Some("_start".into()) };
        (handle.clone(), handle, ext.build, vec![t])
    } else {
        let e = ext
            .extensions
            .into_iter()
            .find(|e| e.kind.as_deref().is_none_or(|k| k == "function"))
            .ok_or_else(|| anyhow!("{}: no extension of type \"function\"", path.display()))?;
        let handle = e.handle.clone().or(e.name.clone()).unwrap_or_else(|| "function".into());
        if e.targeting.is_empty() {
            bail!("{}: the function has no [[extensions.targeting]]", path.display());
        }
        (handle.clone(), e.name.filter(|n| !n.starts_with("t:")).unwrap_or(handle), e.build, e.targeting)
    };
    let schema_path = dir.join("schema.graphql");
    let schema =
        std::fs::read_to_string(&schema_path).with_context(|| format!("reading {} (`shopify app function schema` writes it)", schema_path.display()))?;
    let mut queries = Vec::new();
    for t in &targets {
        let q = t.input_query.clone().ok_or_else(|| anyhow!("target {}: no input_query", t.target))?;
        let p = dir.join(&q);
        queries.push((q, std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?));
    }
    let sources: Vec<TargetSource> = targets
        .iter()
        .zip(&queries)
        .map(|(t, (name, query))| TargetSource { target: &t.target, export: t.export.as_deref().unwrap_or("run"), query, query_name: name })
        .collect();
    let model = Model::new(&schema, &sources).with_context(|| format!("typing {}", path.display()))?;
    let wit = model.wit();
    let mut h = blake3::Hasher::new();
    h.update(b"appfuzz-shopify-v1\0");
    h.update(schema.as_bytes());
    for (t, (_, q)) in targets.iter().zip(&queries) {
        for part in [t.target.as_str(), t.export.as_deref().unwrap_or("run"), q.as_str()] {
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
    }
    let wasm = build.and_then(|b| b.path).unwrap_or_else(|| "dist/function.wasm".into());
    Ok(Loaded {
        function: Function { handle, api_version: ext.api_version, model, wit, digest: h.finalize().to_hex().to_string() },
        wasm: dir.join(wasm),
        name,
    })
}

/// The appfuzz manifest for a function's `shopify.extension.toml`.
pub fn load(path: &Path) -> Result<Manifest> {
    let mut m = Manifest::for_wasm(Path::new(""));
    m.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    m.shopify = Some(Section { extension: PathBuf::from(path.file_name().unwrap_or_default()), function: None });
    attach(&mut m, &toml::Table::new()).with_context(|| format!("in {}", path.display()))?;
    Ok(m)
}

/// Loads `[shopify]`'s extension into the manifest: the module, the
/// export to call, Shopify's limits. The app may tighten the limits.
pub(crate) fn attach(m: &mut Manifest, app_toml: &toml::Table) -> Result<()> {
    let Some(section) = &m.shopify else { return Ok(()) };
    let path = m.dir.join(&section.extension);
    let loaded = load_extension(&path)?;
    if m.app.wasm.as_os_str().is_empty() {
        m.app.wasm = loaded.wasm.strip_prefix(&m.dir).map(Path::to_path_buf).unwrap_or(loaded.wasm.clone());
    }
    if m.app.name.is_none() {
        m.app.name = Some(loaded.name.clone());
    }
    let set = |key: &str| app_toml.get("limits").and_then(|l| l.get(key)).is_some();
    let most_fuel = (INSTRUCTIONS as f64 * MAX_SCALE) as u64;
    if !set("fuel") || m.limits.fuel > most_fuel {
        m.limits.fuel = most_fuel;
    }
    if !set("memory") || m.limits.memory > MEMORY_BYTES {
        m.limits.memory = MEMORY_BYTES;
    }
    let first = loaded.function.model.targets.first().map(|t| t.wit.clone()).unwrap_or_default();
    match &mut m.entry {
        Some(e) if e.export.is_empty() => e.export = first,
        Some(e) if loaded.function.target(&e.export).is_none() => {
            let names: Vec<&str> = loaded.function.model.targets.iter().map(|t| t.wit.as_str()).collect();
            bail!("[entry] export {:?} is none of the function's targets ({})", e.export, names.join(", "));
        }
        Some(e) => {
            let wit = loaded.function.target(&e.export).map(|t| t.wit.clone()).unwrap_or_default();
            e.export = wit;
        }
        None => m.entry = Some(entry(first)),
    }
    if let Some(s) = &mut m.shopify {
        s.function = Some(Arc::new(loaded.function));
    }
    Ok(())
}

fn entry(export: String) -> Entry {
    Entry {
        export,
        request: None,
        fields: Default::default(),
        output: Default::default(),
        now: None,
        result: Default::default(),
        sensitive_paths: vec![],
        csp: None,
        no_pii: false,
        values: Default::default(),
        input_values: Default::default(),
    }
}

/// Shopify's JSON of a value in the codec the module reads: JSON text, or
/// MessagePack for the provider modules that use it.
pub fn encode_bytes(v: &Value, msgpack: bool) -> Result<Vec<u8>> {
    if msgpack { rmp_serde::to_vec_named(v).map_err(|e| anyhow!("encoding the input as MessagePack: {e}")) } else { serde_json::to_vec(v).map_err(Into::into) }
}

/// The output bytes as JSON, or why they are not.
pub fn decode_bytes(bytes: &[u8], msgpack: bool) -> std::result::Result<Value, String> {
    if msgpack {
        rmp_serde::from_slice::<Value>(bytes).map_err(|e| format!("the output is not MessagePack: {e}"))
    } else {
        let text = std::str::from_utf8(bytes).map_err(|_| "the output is not UTF-8 text".to_string())?;
        if text.trim().is_empty() {
            return Err("the function wrote no output".into());
        }
        serde_json::from_str(text).map_err(|e| format!("the output is not JSON: {e}"))
    }
}
