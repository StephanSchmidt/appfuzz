//! Running many specs at once. Runs share the `App` and nothing else, so
//! every list of independent runs goes through `map` on the rayon pool
//! (sized by `--jobs`). Results come back in input order: the analyses
//! that read them stay deterministic.

use rayon::prelude::*;

use crate::record::{RunRecord, RunSpec};

/// Executes (and may store) one spec; shared by all worker threads.
pub type Runner<'a> = &'a (dyn Fn(&RunSpec) -> RunRecord + Sync);

/// `f` over `items` in parallel, results in input order.
pub fn map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    items.par_iter().map(f).collect()
}

/// Worker threads in the pool.
pub fn jobs() -> usize {
    rayon::current_num_threads()
}
