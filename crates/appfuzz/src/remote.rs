//! `appfuzz https://…/app.wasm`: review a Wasm file someone hosts.
//!
//! The file is downloaded (HTTPS only, size-capped, at most 5 redirects),
//! checked for the Wasm magic bytes and stored under its content hash. The
//! manifest is the same URL with `.wasm` replaced by `.toml`; a 404 means
//! there is none. The download runs in the same sandbox as a local file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

/// The largest `.wasm` that is downloaded.
pub(crate) const MAX_WASM: u64 = 50 << 20;
/// The largest manifest that is downloaded.
pub(crate) const MAX_TOML: u64 = 1 << 20;

/// Options that take a value, so a URL right after one of them is that
/// option's value and not the app to review.
const VALUE_OPTIONS: &[&str] = &["-m", "--manifest", "--wasm", "--state", "-j", "--jobs"];

pub(crate) fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("https://") || l.starts_with("http://")
}

/// `appfuzz [options] URL [args]` becomes `appfuzz [options] --wasm URL
/// review [args]`: a URL in place of a command reviews it. Someone trying a
/// URL wants an answer soon, so the fuzzing time is 10s unless `--time`
/// says otherwise.
/// The fuzzing time of `appfuzz URL`.
const URL_REVIEW_TIME: &str = "10s";

pub(crate) fn rewrite_args(args: Vec<String>) -> Vec<String> {
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if VALUE_OPTIONS.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        if !is_url(a) {
            return args;
        }
        let mut out = args[..i].to_vec();
        out.extend(["--wasm".to_string(), a.clone(), "review".to_string()]);
        out.extend(args[i + 1..].iter().cloned());
        if !args.iter().any(|a| a == "--time" || a.starts_with("--time=")) {
            out.extend(["--time".to_string(), URL_REVIEW_TIME.to_string()]);
        }
        return out;
    }
    args
}

/// A downloaded app.
pub(crate) struct Fetched {
    pub(crate) wasm: PathBuf,
    pub(crate) manifest: Option<PathBuf>,
    /// Where its runs are kept unless `--state` says otherwise: one folder
    /// per URL, so the commands in `next` find them again.
    pub(crate) state: PathBuf,
}

/// Where downloads and their runs go: `$APPFUZZ_CACHE`, else the platform's
/// cache folder.
fn cache_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("APPFUZZ_CACHE").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_CACHE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d).join("appfuzz"));
    }
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty()).ok_or_else(|| anyhow!("no cache folder: set APPFUZZ_CACHE or HOME"))?;
    let home = PathBuf::from(home);
    Ok(if cfg!(target_os = "macos") { home.join("Library/Caches/appfuzz") } else { home.join(".cache/appfuzz") })
}

fn agent(allow_http: bool) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(!allow_http)
        .max_redirects(5)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        .user_agent(concat!("appfuzz/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// The body of `url`, at most `limit` bytes; `None` on 404 or 410.
fn get(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    let mut resp = agent.get(url).call().map_err(|e| anyhow!("downloading {url}: {e}"))?;
    let status = resp.status().as_u16();
    if status == 404 || status == 410 {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        bail!("downloading {url}: the server answered {status}");
    }
    let body = resp.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| match e {
        ureq::Error::BodyExceedsLimit(_) => anyhow!("downloading {url}: larger than {} MB", limit >> 20),
        e => anyhow!("downloading {url}: {e}"),
    })?;
    Ok(Some(body))
}

/// The manifest's URL: the same URL with `.wasm` replaced by `.toml`, or
/// none when the path doesn't end in `.wasm`.
pub(crate) fn manifest_url(url: &str) -> Option<String> {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    let (path, rest) = url.split_at(end);
    path.strip_suffix(".wasm").map(|p| format!("{p}.toml{rest}"))
}

/// The file name the URL's path ends in, safe as a file name.
fn file_stem(url: &str) -> String {
    let end = url.find(['?', '#']).unwrap_or(url.len());
    let last = url[..end].rsplit('/').next().unwrap_or("");
    let stem = last.strip_suffix(".wasm").unwrap_or(last);
    let clean: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect();
    let clean = clean.trim_matches('.').to_string();
    if clean.is_empty() { "app".into() } else { clean }
}

/// A downloaded manifest may not reach into the user's files: its wasm is
/// always the download, and its platform must be a bundled one.
fn check_manifest(url: &str, text: &str) -> Result<()> {
    let table: toml::Table = toml::from_str(text).with_context(|| format!("{url} is not a valid appfuzz manifest"))?;
    if let Some(p) = table.get("app").and_then(|a| a.get("platform")).and_then(|p| p.as_str())
        && !appfuzz_core::host_manifest::is_bundled(p)
    {
        bail!("{url}: a downloaded manifest can only name a bundled platform (like \"fastly\"), not {p:?}");
    }
    Ok(())
}

fn short_hash(bytes: &[u8]) -> String {
    crate::blake3_hex(bytes).chars().take(16).collect()
}

/// Downloads `url` and its manifest into the cache.
pub(crate) fn fetch(url: &str, allow_http: bool, human: bool) -> Result<Fetched> {
    if !allow_http && !url.to_ascii_lowercase().starts_with("https://") {
        bail!("{url}: only https:// URLs are downloaded; pass --allow-http for plain http");
    }
    let agent = agent(allow_http);
    let wasm = get(&agent, url, MAX_WASM)?.ok_or_else(|| anyhow!("{url}: not found (404)"))?;
    if !wasm.starts_with(b"\0asm") {
        bail!("{url} is not a WebAssembly file");
    }
    let manifest = match manifest_url(url) {
        Some(m) => match get(&agent, &m, MAX_TOML)? {
            Some(body) => {
                let text = String::from_utf8(body).map_err(|_| anyhow!("{m} is not UTF-8 text"))?;
                check_manifest(&m, &text)?;
                Some((m, text))
            }
            None => None,
        },
        None => None,
    };
    let cache = cache_dir()?;
    let stem = file_stem(url);
    let dir = cache.join("remote").join(short_hash(&wasm));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let wasm_path = dir.join(format!("{stem}.wasm"));
    std::fs::write(&wasm_path, &wasm).with_context(|| format!("writing {}", wasm_path.display()))?;
    let manifest_path = dir.join(format!("{stem}.toml"));
    let _ = std::fs::remove_file(&manifest_path);
    if let Some((_, text)) = &manifest {
        std::fs::write(&manifest_path, text).with_context(|| format!("writing {}", manifest_path.display()))?;
    }
    if human {
        crate::human::downloaded(&format!("{stem}.wasm"), wasm.len() as u64, manifest.is_some().then(|| format!("{stem}.toml")).as_deref());
    } else {
        eprintln!(
            "appfuzz: downloaded {url} ({} bytes, {}), manifest: {}",
            wasm.len(),
            short_hash(&wasm),
            manifest.as_ref().map_or("none".to_string(), |(m, _)| m.clone())
        );
    }
    Ok(Fetched { wasm: wasm_path, manifest: manifest.map(|_| manifest_path), state: cache.join("state").join(short_hash(url.as_bytes())) })
}

/// Whether `p` is the default `--state`.
pub(crate) fn is_default_state(p: &Path) -> bool {
    p == Path::new(".appfuzz")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn a_url_in_place_of_a_command_reviews_it() {
        assert_eq!(rewrite_args(args("appfuzz https://x/a.wasm")), args("appfuzz --wasm https://x/a.wasm review --time 10s"));
        assert_eq!(rewrite_args(args("appfuzz -j 2 https://x/a.wasm --time 5s")), args("appfuzz -j 2 --wasm https://x/a.wasm review --time 5s"));
        assert_eq!(rewrite_args(args("appfuzz --wasm https://x/a.wasm run")), args("appfuzz --wasm https://x/a.wasm run"));
        assert_eq!(rewrite_args(args("appfuzz run https://x")), args("appfuzz run https://x"));
        assert_eq!(rewrite_args(args("appfuzz")), args("appfuzz"));
    }

    #[test]
    fn the_manifest_is_the_wasm_url_with_toml() {
        assert_eq!(manifest_url("https://a.dev/demo/app.wasm").as_deref(), Some("https://a.dev/demo/app.toml"));
        assert_eq!(manifest_url("https://a.dev/app.wasm?v=2").as_deref(), Some("https://a.dev/app.toml?v=2"));
        assert_eq!(manifest_url("https://a.dev/download?id=7"), None);
    }

    #[test]
    fn file_names_come_from_the_url_and_stay_inside_the_folder() {
        assert_eq!(file_stem("https://a.dev/demo/chatty.wasm"), "chatty");
        assert_eq!(file_stem("https://a.dev/x/..%2F..%2Fetc.wasm?q"), "_2F.._2Fetc");
        assert_eq!(file_stem("https://a.dev/"), "app");
    }

    #[test]
    fn downloaded_manifests_name_only_bundled_platforms() {
        assert!(check_manifest("u", "[app]\nwasm = \"x.wasm\"\nplatform = \"fastly\"\n").is_ok());
        assert!(check_manifest("u", "[app]\nwasm = \"x.wasm\"\nplatform = \"/etc/platform.toml\"\n").is_err());
        assert!(check_manifest("u", "<html>not found</html>").is_err());
    }
}
