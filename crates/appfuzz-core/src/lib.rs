//! appfuzz-core: runs WebAssembly components against scripted, simulated host
//! functions and measures what they do.

pub mod manifest;
pub mod markup;
pub mod check;
pub mod constraints;
pub mod metamorphic;
pub mod output;
pub mod detect;
pub mod effects;
pub mod fuzz;
pub mod par;
pub mod growth;
pub mod harness;
pub mod identity;
pub mod labels;
pub mod plan;
pub mod probe;
pub mod record;
pub mod scale;
pub mod shrink;
pub mod statics;
pub mod urls;
pub mod store;
pub mod value;
pub mod wasi;
pub mod wit;
