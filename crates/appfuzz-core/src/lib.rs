//! appfuzz-core: runs WebAssembly components against scripted, simulated host
//! functions and measures what they do.

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
pub mod scale;
pub mod shrink;
pub mod spin;
pub mod statics;
pub mod store;
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
