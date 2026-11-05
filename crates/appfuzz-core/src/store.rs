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
        // The check and replacement must be one operation across threads and
        // processes. The OS releases this lock even if a writer crashes.
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(self.dir.join(".save.lock"))?;
        lock.lock().context("locking run storage")?;
        if let Some(old) = self.get(&r.id)?
            && !old.spec.same_inputs(&r.spec)
        {
            bail!("run ID {} is already bound to another specification", r.id);
        }
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
            [one] => self.get(one)?.with_context(|| format!("run {one:?} disappeared while loading")),
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
    write_atomic_with_id(path, bytes, || N.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

fn write_atomic_with_id(path: &Path, bytes: &[u8], mut next_id: impl FnMut() -> u64) -> Result<()> {
    use std::io::Write as _;

    let (tmp, mut file) = loop {
        let n = next_id();
        let tmp = path.with_extension(format!("tmp{}.{n}", std::process::id()));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => break (tmp, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).with_context(|| format!("writing {}", tmp.display())),
        }
    };
    let written = file.write_all(bytes);
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("writing {}", tmp.display()));
    }
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(seed: u64) -> RunRecord {
        let mut record = crate::envelope::Trace::default().to_record();
        record.spec.component = "collision-component".into();
        record.spec.contract = "collision-contract".into();
        record.spec.export = "run".into();
        record.spec.now = "2026-11-05T00:00:00".into();
        record.spec.fuel = 1000;
        record.spec.memory = 65536;
        record.spec.ns_per_fuel = 0.5;
        record.spec.seed = seed;
        record.id = record.spec.id();
        record.result = Some(json!(seed));
        record
    }

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            loop {
                let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!("appfuzz-store-{}-{n}", std::process::id()));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("creating test storage: {error}"),
                }
            }
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn prefix_lookup_handles_a_run_disappearing_during_the_lookup() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        let run = record(1);
        store.save(&run).unwrap();
        let path = store.dir.join(format!("{}.json", run.id));
        let away = path.with_extension("away");
        let stopped = AtomicBool::new(false);
        let panicked = std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                while !stopped.load(Ordering::Acquire) {
                    std::fs::rename(&path, &away).unwrap();
                    std::thread::yield_now();
                    std::fs::rename(&away, &path).unwrap();
                    std::thread::yield_now();
                }
            });
            let mut panicked = false;
            for _ in 0..50_000 {
                if std::panic::catch_unwind(|| store.load(&run.id[..9])).is_err() {
                    panicked = true;
                    break;
                }
            }
            stopped.store(true, Ordering::Release);
            writer.join().unwrap();
            panicked
        });
        assert!(!panicked, "concurrent removal must produce a normal lookup error");
    }

    #[test]
    fn distinct_specs_with_a_known_short_hash_collision_keep_distinct_ids() {
        let (a, b) = (record(12157), record(498193));
        assert_ne!(a.spec, b.spec);
        assert!(a.id.starts_with("r103ebc9618"));
        assert!(b.id.starts_with("r103ebc9618"));
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn stored_runs_with_a_known_short_hash_collision_remain_individually_loadable() {
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        let (a, b) = (record(12157), record(498193));
        store.save(&a).unwrap();
        store.save(&b).unwrap();
        assert_eq!(store.load(&a.id).unwrap().spec, a.spec);
        assert_eq!(store.load(&b.id).unwrap().spec, b.spec);
        assert_eq!(store.ids().unwrap().len(), 2);
        assert!(store.load("r103ebc9618").is_err());
    }

    #[test]
    fn saving_different_specs_under_one_id_cannot_replace_evidence() {
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        let a = record(1);
        let mut b = record(2);
        b.id = a.id.clone();
        store.save(&a).unwrap();
        assert!(store.save(&b).is_err());
        assert_eq!(store.load(&a.id).unwrap().spec, a.spec);
        assert_eq!(store.load("last").unwrap().spec, a.spec);
    }

    #[test]
    fn identity_checks_preserve_signed_zero_in_run_arguments() {
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        let mut a = record(1);
        a.spec.args = vec![json!(0.0)];
        a.id = a.spec.id();
        let mut b = a.clone();
        b.spec.args = vec![json!(-0.0)];
        assert_ne!(serde_json::to_vec(&a.spec).unwrap(), serde_json::to_vec(&b.spec).unwrap());
        store.save(&a).unwrap();
        assert!(store.save(&b).is_err());
        assert_eq!(store.load(&a.id).unwrap().spec.args[0].as_f64().unwrap().to_bits(), 0.0f64.to_bits());
    }

    #[test]
    fn identical_inputs_keep_their_identity_after_storage() {
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        for number in
            [0.0, -0.0, f64::MIN_POSITIVE, f64::MAX, 1.2345678901234567, 1.0000000000000002, 9.007199254740994e15, f64::from_bits(1727240679746839071)]
        {
            let mut value = record(1);
            value.spec.args = vec![json!(number)];
            value.id = value.spec.id();
            store.save(&value).unwrap();
            let loaded = store.load(&value.id).unwrap();
            assert!(loaded.spec.same_inputs(&value.spec), "{number}");
            store.save(&value).unwrap();
        }
    }

    #[test]
    fn finite_float_inputs_round_trip_exactly() {
        let mut bits = 0x718aba94923964u64;
        for _ in 0..10000 {
            bits ^= bits << 13;
            bits ^= bits >> 7;
            bits ^= bits << 17;
            let number = f64::from_bits(bits);
            if !number.is_finite() {
                continue;
            }
            let encoded = serde_json::to_vec(&json!(number)).unwrap();
            let decoded: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded.as_f64().unwrap().to_bits(), bits, "{}", String::from_utf8(encoded).unwrap());
        }
    }

    #[test]
    fn legacy_short_ids_still_load_directly_and_by_unique_prefix() {
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        let mut old = record(1);
        old.id.truncate(11);
        store.save(&old).unwrap();
        assert_eq!(store.load(&old.id).unwrap().spec, old.spec);
        assert_eq!(store.load(&old.id[..6]).unwrap().spec, old.spec);
        assert_eq!(store.load("last").unwrap().id, old.id);
    }

    #[test]
    fn concurrent_writers_cannot_replace_evidence_for_another_specification() {
        let directory = Directory::new();
        let store = RunStore::new(&directory.0);
        let id = record(1).id;
        let barrier = std::sync::Barrier::new(8);
        let winners = std::thread::scope(|scope| {
            let writers: Vec<_> = (0..8)
                .map(|seed| {
                    let (store, id, barrier) = (&store, &id, &barrier);
                    scope.spawn(move || {
                        let mut value = record(seed);
                        value.id = id.clone();
                        barrier.wait();
                        store.save(&value).is_ok().then_some(seed)
                    })
                })
                .collect();
            writers.into_iter().filter_map(|writer| writer.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(winners.len(), 1);
        assert_eq!(store.load(&id).unwrap().spec.seed, winners[0]);
    }
    #[cfg(unix)]
    #[test]
    fn atomic_writes_skip_existing_temporary_symlinks() {
        let directory = Directory::new();
        let target = directory.0.join("record.json");
        let victim = directory.0.join("unrelated.txt");
        std::fs::write(&target, b"old record").unwrap();
        std::fs::write(&victim, b"preserved").unwrap();
        let occupied = target.with_extension(format!("tmp{}.0", std::process::id()));
        std::os::unix::fs::symlink(&victim, &occupied).unwrap();
        let mut next = 0;
        write_atomic_with_id(&target, b"new record", || {
            let id = next;
            next += 1;
            id
        })
        .unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserved");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new record");
        assert!(!std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        assert!(std::fs::symlink_metadata(&occupied).unwrap().file_type().is_symlink());
    }
}
