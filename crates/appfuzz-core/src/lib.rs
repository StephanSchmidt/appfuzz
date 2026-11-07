//! appfuzz-core: runs WebAssembly components against scripted, simulated host
//! functions and measures what they do.

mod adapt;
pub mod agents;
pub mod auth;
pub mod browser;
pub mod check;
pub mod constraints;
mod csp;
pub mod dest;
pub mod detect;
pub mod dormant;
pub mod effects;
pub mod envelope;
pub mod extism;
pub mod fuzz;
pub mod growth;
pub mod handles;
pub mod harness;
pub mod host_manifest;
mod html;
pub mod hygiene;
pub mod identity;
mod js;
pub mod known;
pub mod labels;
pub mod manifest;
pub mod markup;
pub mod metamorphic;
pub mod natural;
pub mod output;
pub mod pages;
pub mod par;
pub mod payload;
pub mod plan;
pub mod probe;
pub mod record;
pub mod records;
pub mod scale;
pub mod shopify;
pub mod shrink;
pub mod spin;
pub mod standards;
pub mod statics;
pub mod store;
mod streams;
pub mod tenants;
pub mod urls;
pub mod value;
pub mod value_contract;
pub mod wasi;
pub mod wasi_http;
pub mod web;
pub mod wide;
pub mod wit;
pub mod witx_abi;

pub mod dataset;

pub mod sequence;

pub mod acceptance;
pub mod assertion;

pub mod faults;
pub mod feedback;

mod structured;

mod memory;

/// Where downloads and their runs go: `$APPFUZZ_CACHE`, else the platform's
/// cache folder.
pub fn cache_dir() -> anyhow::Result<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Some(d) = std::env::var_os("APPFUZZ_CACHE").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_CACHE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d).join("appfuzz"));
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or_else(|| anyhow::anyhow!("no cache folder: set APPFUZZ_CACHE or HOME"))?;
    let home = PathBuf::from(home);
    Ok(if cfg!(target_os = "macos") { home.join("Library/Caches/appfuzz") } else { home.join(".cache/appfuzz") })
}
