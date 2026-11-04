//! `platform.toml`: what a platform promises and requires, written once by
//! the platform and shared by every app on it.
//!
//! It holds the host functions' types (WIT or witx), their descriptions for
//! the agents that write apps, how apps are called, limits, capabilities, and
//! per function the semantics appfuzz checks against: cost, latency, effects,
//! value domains, rules and labels. An app manifest names its platform with
//! `[app] platform = "…"` and adds its own semantics. It may tighten what the
//! platform says, never weaken it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasmtime::Engine;

use crate::labels::{Label, ResultLabels};
use crate::manifest::{Entry, FunctionSpec, Grants, Limits, Manifest, fn_key, strip_version};
use crate::wit::{FuncInfo, Interface};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostManifest {
    pub platform: PlatformInfo,
    /// How apps are called and what their output may do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<Entry>,
    /// The most an app can be granted: WASI interfaces and hosts.
    #[serde(default)]
    pub grants: Grants,
    #[serde(default)]
    pub limits: Limits,
    /// Named groups of interfaces apps ask for (`grants.capabilities`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, Capability>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub functions: BTreeMap<String, FunctionSpec>,
    /// Handle kinds and their initial state (`[handles.KIND] init = {...}`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub handles: BTreeMap<String, crate::handles::Kind>,
    /// Where the file was loaded from; `wit`/`witx` paths resolve against it.
    #[serde(skip)]
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The SDK apps are written with (`fastly crate 0.13`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<String>,
    /// The WIT package (a file or directory) with the world apps target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wit: Option<PathBuf>,
    /// The world in `wit`, when the package has several.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    /// witx files for plain-module apps (`builtin:fastly` for the bundled ABI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witx: Option<Vec<String>>,
    /// witx platforms: the WIT of the interface `entry` apps are called
    /// through as appfuzz sees them (its functions become `entry#NAME`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_wit: Option<String>,
    /// witx platforms: the module export a run calls (`_start`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// The status a call with an unknown or closed handle gets (`badf`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad_handle: Option<String>,
    /// The status of an absent value (`none`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absent: Option<String>,
    /// How plain-module apps talk to the host when it is not witx:
    /// `extism` (JSON through the Extism kernel, typed by `wit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
    /// `abi = "extism"`: how the JSON spells WIT names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<crate::extism::JsonNames>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Interfaces (WIT) or modules (witx) the capability grants.
    pub interfaces: Vec<String>,
}

/// Platforms bundled with appfuzz, by name.
const BUILTIN: &[(&str, &str)] = &[("fastly", include_str!("../platforms/fastly/platform.toml"))];

/// Whether `name` is a platform bundled with appfuzz (`fastly`).
pub fn is_bundled(name: &str) -> bool {
    BUILTIN.iter().any(|(n, _)| *n == name)
}

impl HostManifest {
    pub fn parse(text: &str, dir: &Path) -> Result<Self> {
        let mut h: HostManifest = toml::from_str(text)?;
        h.dir = dir.to_path_buf();
        Ok(h)
    }

    /// A platform by bundled name (`fastly`), or a `platform.toml` path or
    /// the directory holding one, relative to `base`.
    pub fn resolve(spec: &str, base: &Path) -> Result<Self> {
        if let Some((_, text)) = BUILTIN.iter().find(|(n, _)| *n == spec) {
            return Self::parse(text, Path::new("")).with_context(|| format!("bundled platform {spec}"));
        }
        let mut path = if Path::new(spec).is_absolute() { PathBuf::from(spec) } else { base.join(spec) };
        if path.is_dir() {
            path = path.join("platform.toml");
        }
        if !path.exists() {
            let names: Vec<&str> = BUILTIN.iter().map(|(n, _)| *n).collect();
            bail!("platform {spec:?}: no such file, and not a bundled platform ({})", names.join(", "));
        }
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text, path.parent().unwrap_or(Path::new(""))).with_context(|| format!("parsing {}", path.display()))
    }

    /// The platform an app manifest names in `[app] platform`.
    pub fn of_app(manifest: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(manifest).with_context(|| format!("reading {}", manifest.display()))?;
        let table: toml::Table = toml::from_str(&text).with_context(|| format!("parsing {}", manifest.display()))?;
        let Some(p) = table.get("app").and_then(|a| a.get("platform")).and_then(|p| p.as_str()) else {
            bail!("{} has no [app] platform", manifest.display());
        };
        Self::resolve(p, manifest.parent().unwrap_or(Path::new("")))
    }
    pub fn function(&self, key: &str) -> Option<&FunctionSpec> {
        lookup(&self.functions, key)
    }

    /// Every interface some capability grants.
    fn grantable(&self) -> BTreeSet<String> {
        self.capabilities.values().flat_map(|c| c.interfaces.iter().map(|i| strip_version(i).to_string())).collect()
    }

    /// The platform's host functions, typed, with the descriptions their
    /// type files carry (`///` in WIT, `;;;` in witx).
    pub fn types(&self, engine: &Engine) -> Result<Types> {
        match (&self.platform.wit, &self.platform.witx) {
            (Some(_), Some(_)) => bail!("[platform] has both wit and witx; name one"),
            (None, None) => bail!("[platform] names no types: set wit = \"<dir or file>\" or witx = [...]"),
            (Some(wit), None) => {
                let extism = match self.platform.abi.as_deref() {
                    None => None,
                    Some("extism") => Some(self.platform.json.clone().unwrap_or_default()),
                    Some(other) => bail!("unknown [platform] abi {other:?}; appfuzz knows extism (or witx = [...])"),
                };
                wit_types(engine, &self.dir.join(wit), self.platform.world.as_deref(), extism.as_ref())
            }
            (None, Some(files)) => {
                let mut sources = Vec::new();
                for f in files {
                    if let Some(name) = f.strip_prefix("builtin:") {
                        match name {
                            "fastly" => sources.extend(crate::witx_abi::FASTLY.iter().map(|(n, s)| (n.to_string(), s.to_string()))),
                            _ => bail!("unknown bundled witx {name:?}"),
                        }
                    } else {
                        let p = self.dir.join(f);
                        sources.push((f.clone(), std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?));
                    }
                }
                let refs: Vec<(&str, &str)> = sources.iter().map(|(n, s)| (n.as_str(), s.as_str())).collect();
                let doc = crate::witx_abi::parse(&refs)?;
                let p = crate::witx_abi::load(engine, &doc, self.platform.entry_wit.as_deref())?;
                let docs = p.sigs.values().map(|s| (s.key(), FnDocs { description: s.doc.clone(), params: s.param_docs.clone() })).collect();
                let unsupported = p.unsupported.values().map(|u| (format!("{}#{}", u.module, u.name), u.reason.clone())).collect();
                Ok(Types {
                    imports: p.imports,
                    exports: p.exports,
                    docs,
                    unsupported,
                    witx: Some(Arc::new(p.sigs)),
                    unsupported_sigs: Arc::new(p.unsupported),
                    extism: None,
                })
            }
        }
    }
}

fn lookup<'a>(map: &'a BTreeMap<String, FunctionSpec>, key: &str) -> Option<&'a FunctionSpec> {
    map.get(key).or_else(|| map.iter().find(|(k, _)| norm(k) == norm(key)).map(|(_, v)| v))
}

fn norm(key: &str) -> String {
    let (i, f) = key.split_once('#').unwrap_or(("", key));
    fn_key(i, f)
}

/// A platform's host functions with their types and type-file docs.
pub struct Types {
    pub imports: Vec<Interface>,
    pub exports: Vec<FuncInfo>,
    pub docs: BTreeMap<String, FnDocs>,
    /// Functions the types could not describe, with the reason.
    pub unsupported: BTreeMap<String, String>,
    /// witx platforms: each function's raw ABI, for running plain modules.
    pub witx: Option<Arc<BTreeMap<String, crate::witx_abi::Sig>>>,
    pub unsupported_sigs: Arc<BTreeMap<String, crate::witx_abi::Unsupported>>,
    /// Extism platforms: how each function's JSON looks.
    pub extism: Option<Arc<crate::extism::Abi>>,
}

#[derive(Debug, Clone, Default)]
pub struct FnDocs {
    pub description: String,
    pub params: BTreeMap<String, String>,
}

impl Types {
    pub fn func(&self, key: &str) -> Option<&FuncInfo> {
        self.imports.iter().flat_map(|i| &i.funcs).find(|f| norm(&f.key) == norm(key))
    }
}

fn wit_types(engine: &Engine, path: &Path, world: Option<&str>, extism: Option<&crate::extism::JsonNames>) -> Result<Types> {
    let mut resolve = wit_parser::Resolve::new();
    let (pkg, _) = resolve.push_path(path).with_context(|| format!("reading WIT {}", path.display()))?;
    let w = resolve.select_world(&[pkg], world)?;
    let mut docs = BTreeMap::new();
    for item in resolve.worlds[w].imports.values().chain(resolve.worlds[w].exports.values()) {
        if let wit_parser::WorldItem::Interface { id, .. } = item {
            let name = resolve.id_of(*id).unwrap_or_default();
            for (fname, f) in &resolve.interfaces[*id].functions {
                let d = f.docs.contents.clone().unwrap_or_default();
                docs.insert(fn_key(&name, fname), FnDocs { description: d.trim().to_string(), params: BTreeMap::new() });
            }
        }
    }
    let mut module = wit_component::dummy_module(&resolve, w, wit_parser::ManglingAndAbi::Standard32);
    wit_component::embed_component_metadata(&mut module, &resolve, w, wit_component::StringEncoding::UTF8, false)?;
    let bytes = wit_component::ComponentEncoder::default().module(&module)?.validate(true).encode()?;
    let component = wasmtime::component::Component::new(engine, &bytes).map_err(anyhow::Error::from).context("compiling the platform WIT")?;
    Ok(Types {
        imports: crate::wit::imports(engine, &component),
        exports: crate::wit::exports(engine, &component),
        docs,
        unsupported: BTreeMap::new(),
        witx: None,
        unsupported_sigs: Default::default(),
        extism: extism.map(|names| crate::extism::Abi::new(&resolve, w, names).map(Arc::new)).transpose().context("the platform WIT as Extism JSON")?,
    })
}

/// The app manifest with its platform merged in: the platform's contract,
/// tightened by the app. `app_toml` is the app manifest's text, to tell
/// what the app set from what it left at the default.
pub fn merge(host: &HostManifest, mut app: Manifest, app_toml: &toml::Table) -> Result<Manifest> {
    let name = host.platform.name.clone();
    let weaker = |what: String, a: String, h: String| anyhow!("{what} = {a} is weaker than platform {name}'s {h}; an app may only tighten its platform");
    let owned = |what: String| anyhow!("{what} belongs to platform {name}; remove it from the app manifest");

    // Limits: only lower.
    let set = |section: &str, key: &str| app_toml.get(section).and_then(|s| s.get(key)).is_some();
    let (a, h) = (&app.limits, &host.limits);
    let mut limits = h.clone();
    if set("limits", "fuel") {
        if a.fuel > h.fuel {
            return Err(weaker("limits.fuel".into(), a.fuel.to_string(), h.fuel.to_string()));
        }
        limits.fuel = a.fuel;
    }
    if set("limits", "memory") {
        if a.memory > h.memory {
            return Err(weaker("limits.memory".into(), a.memory.to_string(), h.memory.to_string()));
        }
        limits.memory = a.memory;
    }
    if set("limits", "wall_timeout_ms") {
        if a.wall_timeout_ms > h.wall_timeout_ms {
            return Err(weaker("limits.wall_timeout_ms".into(), a.wall_timeout_ms.to_string(), h.wall_timeout_ms.to_string()));
        }
        limits.wall_timeout_ms = a.wall_timeout_ms;
    }
    if let Some(v) = a.cost_per_request {
        if h.cost_per_request.is_some_and(|h| v > h) {
            return Err(weaker("limits.cost_per_request".into(), v.to_string(), h.cost_per_request.unwrap_or(0).to_string()));
        }
        limits.cost_per_request = Some(v);
    }
    if let Some(v) = a.max_latency_ms {
        if h.max_latency_ms.is_some_and(|h| v > h) {
            return Err(weaker("limits.max_latency_ms".into(), v.to_string(), h.max_latency_ms.unwrap_or(0.0).to_string()));
        }
        limits.max_latency_ms = Some(v);
    }
    for k in ["default_cost", "default_host_latency_ms", "ns_per_fuel"] {
        if set("limits", k) {
            return Err(owned(format!("limits.{k}")));
        }
    }
    app.limits = limits;

    // Entry: the platform's, with the app's example request and own domains.
    if let Some(he) = &host.entry {
        let mut e = he.clone();
        if let Some(ae) = app.entry.take() {
            let entry_set = |k: &str| set("entry", k);
            if entry_set("export") && ae.export != he.export {
                return Err(owned("entry.export".into()));
            }
            // Output fields the platform leaves open (`body_format`) are the app's.
            let o = &mut e.output;
            for (field, h, a) in [
                ("status", &mut o.status, ae.output.status),
                ("body", &mut o.body, ae.output.body),
                ("headers", &mut o.headers, ae.output.headers),
                ("body_format", &mut o.body_format, ae.output.body_format),
            ] {
                match (h.as_ref(), a) {
                    (Some(hv), Some(av)) if *hv != av => return Err(owned(format!("entry.output.{field}"))),
                    (None, Some(av)) => *h = Some(av),
                    _ => {}
                }
            }
            if !ae.values.is_empty() && !same(&ae.values, &he.values) {
                return Err(owned("entry.values (what the platform lets through)".into()));
            }
            if ae.request.is_some() {
                e.request = ae.request;
            }
            if ae.now.is_some() {
                e.now = ae.now;
            }
            add_map(&mut e.fields, ae.fields, "entry.fields")?;
            add_map(&mut e.input_values, ae.input_values, "entry.input_values")?;
            for (path, l) in ae.result {
                match e.result.get(&path) {
                    Some(hl) if *hl == l => {}
                    Some(crate::markup::OutputLabel::HtmlNoScripts) if l == crate::markup::OutputLabel::HtmlSafe => {
                        e.result.insert(path, l);
                    }
                    Some(hl) => return Err(weaker(format!("entry.result.{path:?}"), l.name().into(), hl.name().into())),
                    None => {
                        e.result.insert(path, l);
                    }
                }
            }
            for p in ae.sensitive_paths {
                if !e.sensitive_paths.contains(&p) {
                    e.sensitive_paths.push(p);
                }
            }
            // Either side can forbid personal data in the output; neither can allow it back.
            e.no_pii |= ae.no_pii;
        }
        app.entry = Some(e);
    }

    // Grants: capabilities by name, never past the platform's maximum.
    let caps = app.grants.capabilities.clone();
    if let Some(caps) = &caps {
        let mut imports = app.grants.imports.clone().unwrap_or_default();
        for c in caps {
            let cap = host.capabilities.get(c).ok_or_else(|| {
                let known: Vec<&str> = host.capabilities.keys().map(String::as_str).collect();
                anyhow!("grants.capabilities: platform {name} has no capability {c:?} ({})", known.join(", "))
            })?;
            imports.extend(cap.interfaces.iter().cloned());
        }
        app.grants.imports = Some(imports);
    } else if !host.capabilities.is_empty() && app.grants.imports.is_none() {
        // A platform with capabilities grants nothing unasked.
        app.grants.imports = Some(Vec::new());
    }
    if let Some(imports) = &app.grants.imports
        && !host.capabilities.is_empty()
    {
        let grantable = host.grantable();
        if let Some(i) = imports.iter().find(|i| !grantable.contains(strip_version(i))) {
            return Err(anyhow!("grants.imports: {i} is in no capability of platform {name}"));
        }
    }
    match (&host.grants.wasi, &app.grants.wasi) {
        (Some(hw), Some(aw)) => {
            if let Some(w) = aw.iter().find(|w| !hw.iter().any(|h| w.starts_with(h.as_str()))) {
                return Err(weaker("grants.wasi".into(), format!("{w:?}"), format!("{hw:?}")));
            }
        }
        (Some(hw), None) => app.grants.wasi = Some(hw.clone()),
        _ => {}
    }
    if !host.grants.hosts.is_empty() {
        if let Some(x) = app.grants.hosts.iter().find(|x| !host.grants.hosts.iter().any(|h| *x == h || x.ends_with(&format!(".{h}")))) {
            return Err(weaker("grants.hosts".into(), format!("{x:?}"), format!("{:?}", host.grants.hosts)));
        }
        if app.grants.hosts.is_empty() {
            app.grants.hosts = host.grants.hosts.clone();
        }
    }

    // Functions: the platform's, with the app's additions.
    let mut functions = host.functions.clone();
    for (k, af) in std::mem::take(&mut app.functions) {
        let at = format!("functions.{k:?}");
        if af.description.is_some() || !af.param_docs.is_empty() || af.result_doc.is_some() || !af.errors.is_empty() || af.sdk.is_some() {
            return Err(owned(format!("{at}: descriptions")));
        }
        let hk = functions.keys().find(|hk| norm(hk) == norm(&k)).cloned();
        match hk {
            None => {
                reject_trust(&at, &af)?;
                functions.insert(k, af);
            }
            Some(hk) => {
                let hf = functions.get_mut(&hk).expect("found");
                merge_fn(&at, hf, af).map_err(|e| anyhow!("{e} (platform {name})"))?;
            }
        }
    }
    app.functions = functions;
    crate::labels::check_positions(&app)?;
    Ok(app)
}

/// Only the platform can say host text is trusted markup.
fn reject_trust(at: &str, af: &FunctionSpec) -> Result<()> {
    if let Some((p, _)) = af.result.iter().flat_map(ResultLabels::paths).find(|(_, l)| *l == Label::Html) {
        let at = if p.is_empty() { format!("{at}.result") } else { format!("{at}.result.{p}") };
        bail!("{at} = \"html\" trusts host text as markup; only the platform may say that");
    }
    Ok(())
}

fn merge_fn(at: &str, hf: &mut FunctionSpec, af: FunctionSpec) -> Result<()> {
    reject_trust(at, &af)?;
    if af.value_source.is_some() {
        bail!("{at}.value_source belongs to the platform");
    }
    if af.handle.is_some() {
        bail!("{at}.handle belongs to the platform");
    }
    if af.fails.is_some() {
        bail!("{at}.fails belongs to the platform");
    }
    if let Some(c) = af.cost {
        if hf.cost.is_some_and(|h| c < h) {
            bail!("{at}.cost = {c} is lower than the platform's {}", hf.cost.unwrap_or(0));
        }
        hf.cost = Some(c);
    }
    if let Some(l) = af.latency_ms {
        if hf.latency_ms.is_some_and(|h| l < h) {
            bail!("{at}.latency_ms = {l} is lower than the platform's {}", hf.latency_ms.unwrap_or(0.0));
        }
        hf.latency_ms = Some(l);
    }
    match (hf.effect, af.effect) {
        (Some(h), Some(a)) if h != a => bail!("{at}.effect = {:?}: the platform says {:?}", a.name(), h.name()),
        (None, Some(a)) => hf.effect = Some(a),
        _ => {}
    }
    if af.idempotent && !hf.idempotent {
        bail!("{at}.idempotent = true: the platform does not say the call may be repeated");
    }
    match (&hf.batch_of, af.batch_of) {
        (Some(h), Some(a)) if norm(h) != norm(&a) => bail!("{at}.batch_of = {a:?}: the platform says {h:?}"),
        (None, Some(a)) => hf.batch_of = Some(a),
        _ => {}
    }
    if af.query.is_some() {
        if hf.query.is_some() {
            bail!("{at}.query is set by the platform");
        }
        hf.query = af.query;
    }
    if af.mutation.is_some() {
        if hf.mutation.is_some() {
            bail!("{at}.mutation is set by the platform");
        }
        hf.mutation = af.mutation;
    }
    add_map(&mut hf.values, af.values, &format!("{at}.values"))?;
    add_map(&mut hf.param_values, af.param_values, &format!("{at}.param_values"))?;
    add_map(&mut hf.params, af.params, &format!("{at}.params"))?;
    hf.rules.extend(af.rules);
    match (hf.result.take(), af.result) {
        (h, None) => hf.result = h,
        (None, a) => hf.result = a,
        (Some(ResultLabels::Fields(mut h)), Some(ResultLabels::Fields(a))) => {
            add_map(&mut h, a, &format!("{at}.result"))?;
            hf.result = Some(ResultLabels::Fields(h));
        }
        (Some(h), Some(a)) if same(&h, &a) => hf.result = Some(h),
        (Some(_), Some(_)) => bail!("{at}.result differs from the platform's labels"),
    }
    Ok(())
}

/// Adds the app's entries; a key the platform has must keep its value.
fn add_map<V: Serialize>(into: &mut BTreeMap<String, V>, from: BTreeMap<String, V>, at: &str) -> Result<()> {
    for (k, v) in from {
        match into.get(&k) {
            Some(h) if !same(h, &v) => bail!("{at}.{k:?} differs from the platform's {}", serde_json::to_string(h).unwrap_or_default()),
            Some(_) => {}
            None => {
                into.insert(k, v);
            }
        }
    }
    Ok(())
}

fn same<T: Serialize>(a: &T, b: &T) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

/// The coding reference for app authors: every function with its
/// signature, description and declared semantics.
pub fn docs(host: &HostManifest, types: &Types, only: Option<&str>, capability: Option<&str>) -> Result<Value> {
    let mut by_iface: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (cname, c) in &host.capabilities {
        for i in &c.interfaces {
            by_iface.entry(strip_version(i).to_string()).or_default().push(cname.clone());
        }
    }
    if let Some(c) = capability
        && !host.capabilities.contains_key(c)
    {
        bail!("platform {} has no capability {c:?}", host.platform.name);
    }
    let mut funcs = Vec::new();
    for iface in &types.imports {
        let caps = by_iface.get(strip_version(&iface.name)).cloned().unwrap_or_default();
        if capability.is_some_and(|c| !caps.iter().any(|x| x == c)) {
            continue;
        }
        for f in &iface.funcs {
            if only.is_some_and(|o| norm(o) != norm(&f.key) && o != f.name) {
                continue;
            }
            funcs.push(func_doc(host, types, f, &caps));
        }
    }
    if let Some(o) = only
        && funcs.is_empty()
    {
        bail!("platform {} has no function {o:?}", host.platform.name);
    }
    let caps: Vec<Value> = host
        .capabilities
        .iter()
        .filter(|(n, _)| capability.is_none_or(|c| c == n.as_str()))
        .map(|(n, c)| json!({"name": n, "description": c.description, "interfaces": c.interfaces}))
        .collect();
    let undocumented = funcs.iter().filter(|f| f["description"].is_null()).count();
    Ok(json!({
        "platform": host.platform,
        "entry": host.entry,
        "limits": host.limits,
        "grants": host.grants,
        "capabilities": caps,
        "functions": funcs,
        "undocumented": undocumented,
        "unsupported": types.unsupported,
    }))
}

fn func_doc(host: &HostManifest, types: &Types, f: &FuncInfo, caps: &[String]) -> Value {
    let spec = host.function(&f.key).cloned().unwrap_or_default();
    let typed = types.docs.get(&f.key).cloned().unwrap_or_default();
    let description = spec.description.clone().or_else(|| Some(typed.description.clone()).filter(|d| !d.is_empty()));
    let mut params = serde_json::Map::new();
    for p in f.param_names() {
        let doc = spec.param_docs.get(&p).or_else(|| typed.params.get(&p)).cloned();
        let mut v = json!({});
        if let Some(d) = doc {
            v["description"] = json!(d);
        }
        if let Some(l) = spec.params.get(&p) {
            v["label"] = json!(l.name());
        }
        if let Some(d) = spec.param_values.get(&p) {
            v["values"] = serde_json::to_value(d).unwrap_or(Value::Null);
        }
        params.insert(p, v);
    }
    let mut out = json!({
        "key": f.key,
        "signature": f.signature(),
        "description": description,
        "params": params,
    });
    let o = out.as_object_mut().expect("object");
    let mut put = |k: &str, v: Value| {
        if !v.is_null() && v != json!({}) && v != json!([]) {
            o.insert(k.to_string(), v);
        }
    };
    put("capabilities", json!(caps));
    put("result", json!(spec.result_doc));
    put("errors", json!(spec.errors));
    put("sdk", json!(spec.sdk));
    put("effect", json!(spec.effect.map(|e| e.name())));
    put("idempotent", json!(spec.idempotent.then_some(true)));
    put("cost", json!(spec.cost));
    put("latency_ms", json!(spec.latency_ms));
    put("values", serde_json::to_value(&spec.values).unwrap_or(Value::Null));
    put("result_labels", json!(spec.result.as_ref().map(|r| r.paths().into_iter().map(|(p, l)| (p, l.name())).collect::<BTreeMap<_, _>>())));
    put("rules", serde_json::to_value(&spec.rules).unwrap_or(Value::Null));
    put("batch_of", json!(spec.batch_of));
    out
}

/// The reference as Markdown, for a kit (`HOST-API.md`).
pub fn docs_markdown(d: &Value) -> String {
    use std::fmt::Write as _;
    let mut t = String::new();
    let p = &d["platform"];
    let _ = writeln!(t, "# {} host API\n", p["name"].as_str().unwrap_or("platform"));
    if let Some(s) = p["description"].as_str() {
        let _ = writeln!(t, "{s}\n");
    }
    if let Some(s) = p["sdk"].as_str() {
        let _ = writeln!(t, "SDK: {s}\n");
    }
    if let Some(caps) = d["capabilities"].as_array().filter(|c| !c.is_empty()) {
        let _ = writeln!(t, "## Capabilities\n\nAn app asks for these in its manifest (`grants.capabilities`).\n");
        for c in caps {
            let _ = writeln!(t, "- `{}`: {}", c["name"].as_str().unwrap_or(""), c["description"].as_str().unwrap_or(""));
        }
        t.push('\n');
    }
    let _ = writeln!(t, "## Functions\n");
    for f in d["functions"].as_array().into_iter().flatten() {
        let _ = writeln!(t, "### `{}`\n\n```wit\n{}\n```\n", f["key"].as_str().unwrap_or(""), f["signature"].as_str().unwrap_or(""));
        if let Some(s) = f["description"].as_str() {
            let _ = writeln!(t, "{s}\n");
        }
        if let Some(s) = f["sdk"].as_str() {
            let _ = writeln!(t, "SDK: `{s}`\n");
        }
        let params = f["params"].as_object().into_iter().flatten().filter(|(_, v)| v.as_object().is_some_and(|o| !o.is_empty())).collect::<Vec<_>>();
        if !params.is_empty() {
            let _ = writeln!(t, "| Parameter | Meaning |\n|---|---|");
            for (n, v) in params {
                let mut parts = Vec::new();
                if let Some(s) = v["description"].as_str() {
                    parts.push(s.replace('\n', " "));
                }
                if let Some(s) = v["label"].as_str() {
                    parts.push(format!("label `{s}`"));
                }
                if !v["values"].is_null() {
                    parts.push(format!("values `{}`", v["values"]));
                }
                let _ = writeln!(t, "| `{n}` | {} |", parts.join("; "));
            }
            t.push('\n');
        }
        if let Some(s) = f["result"].as_str() {
            let _ = writeln!(t, "Returns: {s}\n");
        }
        if let Some(e) = f["errors"].as_object() {
            for (k, v) in e {
                let _ = writeln!(t, "- error `{k}`: {}", v.as_str().unwrap_or(""));
            }
            t.push('\n');
        }
        let facts: Vec<String> = ["effect", "cost", "latency_ms", "values", "result_labels", "batch_of"]
            .iter()
            .filter(|k| !f[**k].is_null())
            .map(|k| format!("{k} `{}`", f[*k]))
            .collect();
        if !facts.is_empty() {
            let _ = writeln!(t, "{}\n", facts.join(", "));
        }
        if let Some(rules) = f["rules"].as_array() {
            let _ = writeln!(t, "Rules:");
            for r in rules {
                let _ = writeln!(t, "- `{r}`");
            }
            t.push('\n');
        }
    }
    t
}

/// Checks a platform file against its types: every named function,
/// interface, parameter and doc exists.
pub fn check(host: &HostManifest, types: &Types) -> Value {
    let mut errors = Vec::new();
    let ifaces: BTreeSet<String> = types.imports.iter().map(|i| strip_version(&i.name).to_string()).collect();
    for (c, cap) in &host.capabilities {
        for i in &cap.interfaces {
            if !ifaces.contains(strip_version(i)) {
                errors.push(format!("capabilities.{c}: no interface {i} in the platform types"));
            }
        }
    }
    for (k, f) in &host.functions {
        let Some(func) = types.func(k) else {
            errors.push(format!("functions.{k:?}: no such function in the platform types"));
            continue;
        };
        let names = func.param_names();
        for p in f.param_docs.keys().chain(f.params.keys()).chain(f.param_values.keys()) {
            let root = p.split(['.', '[']).next().unwrap_or(p);
            if !names.iter().any(|n| n == root) {
                errors.push(format!("functions.{k:?}: no parameter {root:?} (has {})", names.join(", ")));
            }
        }
    }
    let mut undocumented = Vec::new();
    for f in types.imports.iter().flat_map(|i| &i.funcs) {
        let described = host.function(&f.key).is_some_and(|s| s.description.is_some()) || types.docs.get(&f.key).is_some_and(|d| !d.description.is_empty());
        if !described {
            undocumented.push(f.key.clone());
        }
    }
    let total = types.imports.iter().map(|i| i.funcs.len()).sum::<usize>();
    json!({
        "platform": host.platform.name,
        "ok": errors.is_empty(),
        "errors": errors,
        "functions": total,
        "described": total - undocumented.len(),
        "undocumented": undocumented,
        "unsupported": types.unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = r#"
[platform]
name = "shop"
wit = "unused"

[entry]
export = "shop:web/handler#handle"
request = { path = "/" }
result = { body = "html:no-scripts" }
values = { today = "format:date" }

[grants]
wasi = ["wasi:clocks", "wasi:io"]

[limits]
fuel = 1000
memory = "8MiB"
cost_per_request = 50

[capabilities.items]
description = "Read the catalogue."
interfaces = ["shop:web/items"]

[capabilities.store]
interfaces = ["shop:web/store"]

[functions."shop:web/items#get"]
description = "One item by id."
param_docs = { id = "The item id." }
cost = 2
latency_ms = 4.0
effect = "read"
result = { owner = "owner" }
values = { score = "range:0..100" }
"#;

    fn app(text: &str) -> Result<Manifest> {
        let host = HostManifest::parse(HOST, Path::new("")).unwrap();
        let table: toml::Table = toml::from_str(text).unwrap();
        let m: Manifest = toml::from_str(text).unwrap();
        merge(&host, m, &table)
    }

    #[test]
    fn app_inherits_and_tightens() {
        let m = app(r#"
[app]
wasm = "a.wasm"
platform = "shop"
[grants]
capabilities = ["items"]
[limits]
fuel = 500
[entry]
request = { path = "/list" }
result = { body = "html:safe", "headers.location" = "url:local" }
input_values = { "query.id" = "format:uuid" }
[functions."shop:web/items#get"]
latency_ms = 10.0
params = { id = "sql" }
result = { name = "pii" }
"#)
        .unwrap();
        assert_eq!(m.limits.fuel, 500);
        assert_eq!(m.limits.memory, 8 * 1024 * 1024);
        assert_eq!(m.limits.cost_per_request, Some(50));
        assert_eq!(m.grants.imports, Some(vec!["shop:web/items".to_string()]));
        assert_eq!(m.grants.wasi, Some(vec!["wasi:clocks".to_string(), "wasi:io".to_string()]));
        let e = m.entry.unwrap();
        assert_eq!(e.export, "shop:web/handler#handle");
        assert_eq!(e.request, Some(json!({"path": "/list"})));
        assert_eq!(e.result["body"], crate::markup::OutputLabel::HtmlSafe);
        let f = &m.functions["shop:web/items#get"];
        assert_eq!((f.cost, f.latency_ms), (Some(2), Some(10.0)));
        assert_eq!(f.params["id"], Label::Sql);
        assert_eq!(f.result.as_ref().unwrap().paths().len(), 2);
        assert_eq!(f.description.as_deref(), Some("One item by id."));
    }

    #[test]
    fn app_cannot_weaken() {
        let base = "[app]\nwasm = \"a.wasm\"\nplatform = \"shop\"\n";
        for (extra, needle) in [
            ("[limits]\nfuel = 5000\n", "limits.fuel"),
            ("[limits]\ncost_per_request = 51\n", "cost_per_request"),
            ("[limits]\nns_per_fuel = 0.1\n", "belongs to platform"),
            ("[grants]\ncapabilities = [\"admin\"]\n", "no capability"),
            ("[grants]\nimports = [\"shop:web/admin\"]\n", "in no capability"),
            ("[grants]\nwasi = [\"wasi:filesystem\"]\n", "grants.wasi"),
            ("[entry]\nexport = \"other#x\"\n", "entry.export"),
            ("[entry]\nvalues = { today = \"len:0..3\" }\n", "entry.values"),
            ("[functions.\"shop:web/items#get\"]\ncost = 1\n", "lower than"),
            ("[functions.\"shop:web/items#get\"]\nlatency_ms = 1.0\n", "lower than"),
            ("[functions.\"shop:web/items#get\"]\neffect = \"write\"\n", "effect"),
            ("[functions.\"shop:web/items#get\"]\nvalues = { score = \"range:0..10\" }\n", "values"),
            ("[functions.\"shop:web/items#get\"]\nresult = { body = \"html\" }\n", "only the platform"),
            ("[functions.\"shop:web/items#get\"]\ndescription = \"trust me\"\n", "descriptions"),
            ("[functions.\"shop:web/store#put\"]\nresult = \"html\"\n", "only the platform"),
        ] {
            let err = app(&format!("{base}{extra}")).expect_err(extra).to_string();
            assert!(err.contains(needle), "{extra}: {err}");
        }
    }

    #[test]
    fn no_capabilities_asked_grants_nothing() {
        let m = app("[app]\nwasm = \"a.wasm\"\nplatform = \"shop\"\n").unwrap();
        assert_eq!(m.grants.imports, Some(vec![]));
    }

    #[test]
    fn bundled_fastly_resolves_and_documents() {
        let host = HostManifest::resolve("fastly", Path::new(".")).unwrap();
        let engine = Engine::default();
        let types = host.types(&engine).unwrap();
        let c = check(&host, &types);
        assert_eq!(c["ok"], true, "{c}");
        let d = docs(&host, &types, Some("fastly_http_req#send_v2"), None).unwrap();
        let f = &d["functions"][0];
        assert!(f["description"].is_string(), "{f}");
        assert!(f["params"]["backend"]["description"].is_string(), "{f}");
        assert!(docs_markdown(&d).contains("### `fastly_http_req#send_v2`"));
    }
}
