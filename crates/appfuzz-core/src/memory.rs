//! One allocation budget shared by Wasm memories, including the Extism kernel.

use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, Clone)]
pub(crate) struct Budget(Arc<Mutex<Usage>>);

#[derive(Debug)]
struct Usage {
    max: u64,
    used: u64,
    peak: u64,
    hit: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Checkpoint {
    used: u64,
    peak: u64,
}

impl Budget {
    pub(crate) fn new(max: u64) -> Self {
        Self(Arc::new(Mutex::new(Usage { max, used: 0, peak: 0, hit: false })))
    }

    fn usage(&self) -> MutexGuard<'_, Usage> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn reserve(&self, bytes: u64) -> Option<Checkpoint> {
        let mut usage = self.usage();
        let Some(used) = usage.used.checked_add(bytes).filter(|used| *used <= usage.max) else {
            usage.hit = true;
            return None;
        };
        let before = Checkpoint { used: usage.used, peak: usage.peak };
        usage.used = used;
        usage.peak = usage.peak.max(used);
        Some(before)
    }

    /// A permitted allocation failed before it could be used. Call immediately,
    /// before any other allocation, to undo its attempted contribution to peak.
    pub(crate) fn rollback(&self, before: Checkpoint) {
        let mut usage = self.usage();
        usage.used = before.used;
        usage.peak = before.peak;
    }

    pub(crate) fn hit(&self) -> bool {
        self.usage().hit
    }

    pub(crate) fn peak(&self) -> u64 {
        self.usage().peak
    }
}
