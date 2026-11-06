//! Snapshots the browser guest once it has created its QuickJS runtime and
//! evaluated the shim, so a session starts there instead of parsing 200 KB
//! of JavaScript: `appfuzz-browser-wizen in.wasm out.wasm [scripts.json]`.
//!
//! With `scripts.json` (`{"modules": {url: code}, "classic": {url: code}}`,
//! an app's static scripts) the snapshot also holds them compiled: a
//! session then runs them without parsing.

use wasmtime::component::{Linker, ResourceTable};
use wasmtime::{Engine, Result, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView, p2};
use wasmtime_wizer::Wizer;

struct Ctx {
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(input), Some(output)) = (args.next(), args.next()) else {
        eprintln!("usage: appfuzz-browser-wizen in.wasm out.wasm");
        std::process::exit(2);
    };
    let wasm = std::fs::read(&input)?;
    let mut wasi = WasiCtxBuilder::new();
    if let Some(scripts) = args.next() {
        wasi.stdin(p2::pipe::MemoryInputPipe::new(std::fs::read(scripts)?));
    }
    let engine = Engine::default();
    let mut store = Store::new(&engine, Ctx { wasi: wasi.build(), table: ResourceTable::new() });
    // The init export stays: wizer's component rewrite needs it kept
    // (wasmtime issue 13186); appfuzz calls only page#session.
    let (snapshot, _) = Wizer::new()
        .keep_init_func(true)
        .run_component(&mut store, &wasm, async |store, component| {
            let mut linker = Linker::new(store.engine());
            p2::add_to_linker_async(&mut linker)?;
            // The page's way out (net, nav, sink) is never called while
            // booting.
            linker.define_unknown_imports_as_traps(component)?;
            linker.instantiate_async(store, component).await
        })
        .await?;
    std::fs::write(&output, &snapshot)?;
    eprintln!("{input} ({} bytes) -> {output} ({} bytes)", wasm.len(), snapshot.len());
    Ok(())
}
