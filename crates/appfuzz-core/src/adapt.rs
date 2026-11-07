//! Components built as `wasm32-wasip1` modules.
//!
//! wit-bindgen also works for `wasm32-wasip1`: the module then carries its
//! WIT world in a `component-type` custom section and imports WASI preview 1.
//! Spin's `http-rust-p2` template builds this way, and Spin (like
//! `wasm-tools component new`) makes it a component with the WASI preview 1
//! adapter when it loads it. appfuzz does the same, so `spin.toml`'s
//! `source` is reviewed as Spin runs it.

use anyhow::{Context, Result};
use wasi_preview1_component_adapter_provider::{
    WASI_SNAPSHOT_PREVIEW1_ADAPTER_NAME, WASI_SNAPSHOT_PREVIEW1_COMMAND_ADAPTER, WASI_SNAPSHOT_PREVIEW1_REACTOR_ADAPTER,
};
use wasmparser::{Parser, Payload};

/// The component a `wasm32-wasip1` module with WIT metadata stands for, or
/// `None` for anything else (a component, a plain module for a witx
/// platform).
pub fn componentize(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if !Parser::is_core_wasm(bytes) {
        return Ok(None);
    }
    let mut metadata = false;
    let mut command = false;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::CustomSection(c) if c.name().starts_with("component-type") => metadata = true,
            Payload::ExportSection(exports) => {
                for e in exports {
                    command |= e?.name == "_start";
                }
            }
            _ => {}
        }
    }
    if !metadata {
        return Ok(None);
    }
    // A module with `_start` is a command (`wasi:cli/run`); the rest are
    // libraries whose exports the host calls.
    let adapter = if command { WASI_SNAPSHOT_PREVIEW1_COMMAND_ADAPTER } else { WASI_SNAPSHOT_PREVIEW1_REACTOR_ADAPTER };
    let component = wit_component::ComponentEncoder::default()
        .module(bytes)
        .context("reading the module's WIT metadata")?
        .adapter(WASI_SNAPSHOT_PREVIEW1_ADAPTER_NAME, adapter)
        .context("the WASI preview 1 adapter")?
        .validate(true)
        .encode()
        .context("making the wasm32-wasip1 module a component")?;
    Ok(Some(component))
}

#[cfg(test)]
mod tests {
    use super::componentize;

    #[test]
    fn a_module_without_wit_metadata_stays_a_module() {
        let module = wat::parse_str(r#"(module (func (export "_start")))"#).unwrap();
        assert!(componentize(&module).unwrap().is_none());
    }

    #[test]
    fn a_component_is_left_alone() {
        let component = wat::parse_str("(component)").unwrap();
        assert!(componentize(&component).unwrap().is_none());
    }

    #[test]
    fn a_module_with_wit_metadata_becomes_a_component() {
        let mut resolve = wit_parser::Resolve::new();
        let pkg = resolve.push_str("t.wit", "package t:t;\ninterface entry { greet: func(name: string) -> string; }\nworld app { export entry; }").unwrap();
        let world = resolve.select_world(&[pkg], Some("app")).unwrap();
        let mut module = wit_component::dummy_module(&resolve, world, wit_parser::ManglingAndAbi::Standard32);
        wit_component::embed_component_metadata(&mut module, &resolve, world, wit_component::StringEncoding::UTF8, false).unwrap();
        let component = componentize(&module).unwrap().expect("a component");
        assert!(wasmparser::Parser::is_component(&component));
    }
}
