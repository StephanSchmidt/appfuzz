//! Stored runs under `.appfuzz/runs/<id>.json`, so an agent can come back
//! to any run by id (or a prefix of it, or `last`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::record::RunRecord;

pub struct RunStore {
    dir: PathBuf,
}

impl RunStore {
    pub fn new(state: &Path) -> Self {
        RunStore { dir: state.join("runs") }
    }

    pub fn save(&self, r: &RunRecord) -> Result<()> {
        std::fs::create_dir_all(&self.dir).with_context(|| format!("creating {}", self.dir.display()))?;
        write_atomic(&self.dir.join(format!("{}.json", r.id)), &serde_json::to_vec(r)?)?;
        write_atomic(&self.dir.join("last"), r.id.as_bytes())?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<RunRecord>> {
        let path = self.dir.join(format!("{id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&std::fs::read(&path)?).with_context(|| format!("reading {}", path.display()))?))
    }

    /// A run by id, unique id prefix, or `last`.
    pub fn load(&self, id: &str) -> Result<RunRecord> {
        let id = if id == "last" {
            std::fs::read_to_string(self.dir.join("last")).context("no runs yet")?.trim().to_string()
        } else {
            id.to_string()
        };
        if let Some(r) = self.get(&id)? {
            return Ok(r);
        }
        let matches: Vec<String> = self.ids()?.into_iter().filter(|i| i.starts_with(&id)).collect();
        match matches.as_slice() {
            [one] => Ok(self.get(one)?.expect("listed")),
            [] => bail!("no run {id:?}"),
            many => bail!("{id:?} matches {} runs", many.len()),
        }
    }

    pub fn ids(&self) -> Result<Vec<String>> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return Ok(vec![]) };
        let mut out = Vec::new();
        for e in rd {
            let name = e?.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json") {
                out.push(id.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn all(&self) -> Result<Vec<RunRecord>> {
        self.ids()?.iter().filter_map(|id| self.get(id).transpose()).collect()
    }
}

/// Writes through a temporary file and a rename, so parallel runs never
/// leave a half-written file for a reader.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp{}.{n}", std::process::id()));
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
