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
        self.set_last(&r.id)
    }

    /// Makes `id` the run `last` stands for: the one a command just ran,
    /// or found already stored.
    pub fn set_last(&self, id: &str) -> Result<()> {
        write_atomic(&self.dir.join("last"), id.as_bytes())
    }

    pub fn get(&self, id: &str) -> Result<Option<RunRecord>> {
        let path = self.dir.join(format!("{id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(
            serde_json::from_slice(&std::fs::read(&path)?)
                .with_context(|| format!("{} is not a run this appfuzz can read (another version wrote it, or it is damaged)", path.display()))?,
        ))
    }

    /// A run by id, unique id prefix, or `last`.
    pub fn load(&self, id: &str) -> Result<RunRecord> {
        let id = if id == "last" {
            std::fs::read_to_string(self.dir.join("last"))
                .map_err(|_| anyhow::anyhow!("no runs yet: run `appfuzz run` or `appfuzz review` first"))?
                .trim()
                .to_string()
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
        let rd = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.dir.display())),
        };
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

    /// Every stored run. A file that doesn't read as a run (another
    /// appfuzz version wrote it, or it is damaged) is left out and noted
    /// for [`skipped`], so one bad file doesn't stop every command.
    pub fn all(&self) -> Result<Vec<RunRecord>> {
        let mut out = Vec::new();
        for id in self.ids()? {
            match self.get(&id) {
                Ok(Some(r)) => out.push(r),
                Ok(None) => {}
                Err(_) => {
                    SKIPPED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(self.dir.join(format!("{id}.json")));
                }
            }
        }
        Ok(out)
    }
}

static SKIPPED: std::sync::Mutex<std::collections::BTreeSet<PathBuf>> = std::sync::Mutex::new(std::collections::BTreeSet::new());

/// The run files [`RunStore::all`] left out in this process.
pub fn skipped() -> Vec<PathBuf> {
    SKIPPED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter().cloned().collect()
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
