//! appfuzz-core: runs WebAssembly components against scripted, simulated host
//! functions and measures what they do.

pub mod agents;
pub mod manifest;
pub mod markup;
pub mod check;
pub mod constraints;
pub mod value_contract;
pub mod metamorphic;
pub mod output;
pub mod detect;
pub mod dormant;
pub mod dest;
pub mod effects;
pub mod envelope;
pub mod fuzz;
pub mod par;
pub mod payload;
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

pub mod dataset;

pub mod sequence;

pub mod acceptance;
pub mod assertion;

pub mod feedback;
pub mod faults;

mod structured;
