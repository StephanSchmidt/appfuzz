//! Shopify's provider modules: the standard library a function links with
//! (Javy's QuickJS for JavaScript, the I/O helpers of the Rust crate).
//!
//! appfuzz does not ship them. A function that imports one gets it from
//! Shopify's function-runner repository on first use, checked against the
//! hash pinned here and kept in appfuzz's cache folder.

use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};

/// Where the pinned providers are downloaded from.
pub const SOURCE: &str = "https://raw.githubusercontent.com/Shopify/function-runner/v9.2.3/providers";

/// A provider module: the import module name a function uses for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    pub name: &'static str,
    pub blake3: &'static str,
    pub size: u64,
}

/// The providers of function-runner v9.2.3.
pub const PROVIDERS: &[Provider] = &[
    Provider { name: "javy_quickjs_provider_v1", blake3: "f161cc3ee4179bf8ee53ca15ed9ecaf704691d95db15edc859d023be61d35995", size: 1_787_528 },
    Provider { name: "javy_quickjs_provider_v2", blake3: "7ef6dc7c5a837ff1d4eebd3e9811e9ff1481809df009526014cdd3abde6ce8fe", size: 1_438_465 },
    Provider { name: "javy_quickjs_provider_v3", blake3: "2fc5e7b65990a8a7e3b5e103125c226a7ff67bc961608dc7a744b23c426df69c", size: 1_459_593 },
    Provider { name: "shopify_functions_javy_v1", blake3: "013c90cd5ec02bea2e374c3ac8ae8241ec1a19d4c09f8b6af2b67e9a245a8d46", size: 1_260_732 },
    Provider { name: "shopify_functions_javy_v2", blake3: "e3ceb1376171d3485a31b95f5ec4322c21552eb6cd609557b30d7e15d7fc1a62", size: 1_176_141 },
    Provider { name: "shopify_functions_javy_v3", blake3: "bdc0f72d55e5e760647ed1d3867390751a60cee0b3aeb2e42887987ab0145cd4", size: 1_160_993 },
    Provider { name: "shopify_functions_javy_v4", blake3: "4f218ad6fb2996fd1f4e973ac632a6054ac738fc575edc5605a006a1104237f3", size: 1_233_749 },
    Provider { name: "shopify_function_v1", blake3: "b37e2a1fd94125d25399089f61074bd514c013a27944b812c4509788ac69904c", size: 117_461 },
    Provider { name: "shopify_function_v2", blake3: "4b4cc85af19eb4adda7b74dc1c9cd226a38ddffb37e2ef87a6f8160b3af335f6", size: 75_185 },
];

fn version(name: &str, prefix: &str) -> Option<usize> {
    name.strip_prefix(prefix).and_then(|v| v.parse().ok())
}

impl Provider {
    /// The provider a function's import module names, if it is one.
    pub fn named(module: &str) -> Option<&'static Provider> {
        PROVIDERS.iter().find(|p| p.name == module)
    }

    /// The input and output go through the provider's memory, not stdin and stdout.
    pub fn memory_io(&self) -> bool {
        version(self.name, "shopify_functions_javy_v").is_some_and(|v| v >= 3) || version(self.name, "shopify_function_v").is_some_and(|v| v >= 2)
    }

    /// The input and output are MessagePack, not JSON.
    pub fn msgpack(&self) -> bool {
        version(self.name, "shopify_functions_javy_v").is_some_and(|v| v >= 2) || version(self.name, "shopify_function_v").is_some()
    }

    pub fn url(&self) -> String {
        format!("{SOURCE}/{}.wasm", self.name)
    }

    fn cached(&self) -> Result<PathBuf> {
        Ok(crate::cache_dir()?.join("shopify").join(format!("{}-{}.wasm", self.name, &self.blake3[..16])))
    }

    /// The provider's bytes: from the cache, else downloaded. Either way
    /// they must have the pinned hash.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let path = self.cached()?;
        if let Ok(bytes) = std::fs::read(&path) {
            if self.check(&bytes).is_ok() {
                return Ok(bytes);
            }
            let _ = std::fs::remove_file(&path);
        }
        let fetch = FETCH.get().ok_or_else(|| {
            anyhow!("this function needs Shopify's {} module and appfuzz cannot download it here; put {} at {}", self.name, self.url(), path.display())
        })?;
        let bytes = fetch(&self.url(), self.size + 1).with_context(|| format!("downloading Shopify's {} module", self.name))?;
        self.check(&bytes)?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
        Ok(bytes)
    }

    fn check(&self, bytes: &[u8]) -> Result<()> {
        let hash = blake3::hash(bytes).to_hex();
        if hash.as_str() != self.blake3 {
            bail!("{} from {} is not the pinned file (blake3 {hash}, expected {})", self.name, self.url(), self.blake3);
        }
        Ok(())
    }
}

/// Downloads `url` (at most `limit` bytes). The CLI sets it; without it
/// a provider must already be in the cache.
pub type Fetch = fn(url: &str, limit: u64) -> Result<Vec<u8>>;

static FETCH: OnceLock<Fetch> = OnceLock::new();

/// How providers are downloaded.
pub fn set_fetch(fetch: Fetch) {
    let _ = FETCH.set(fetch);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_styles_follow_the_provider_version() {
        let p = |n| Provider::named(n).unwrap();
        assert!(!p("javy_quickjs_provider_v3").msgpack() && !p("javy_quickjs_provider_v3").memory_io());
        assert!(!p("shopify_functions_javy_v1").msgpack());
        assert!(p("shopify_functions_javy_v2").msgpack() && !p("shopify_functions_javy_v2").memory_io());
        assert!(p("shopify_functions_javy_v3").memory_io());
        assert!(p("shopify_function_v1").msgpack() && !p("shopify_function_v1").memory_io());
        assert!(p("shopify_function_v2").msgpack() && p("shopify_function_v2").memory_io());
        assert!(Provider::named("wasi_snapshot_preview1").is_none());
    }

    #[test]
    fn a_file_without_the_pinned_hash_is_refused() {
        let p = Provider::named("shopify_function_v2").unwrap();
        let err = p.check(b"\0asm not the provider").unwrap_err().to_string();
        assert!(err.contains("is not the pinned file"), "{err}");
    }
}
