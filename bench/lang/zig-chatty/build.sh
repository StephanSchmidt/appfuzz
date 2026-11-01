#!/bin/sh
# Builds app.wasm: C bindings from wit-bindgen, Zig for the app, then a
# component with the WASI preview1 adapter (Zig targets wasm32-wasi, not
# wasip2). Needs zig (0.17), wit-bindgen (0.63) and wasm-tools.
#
#   ADAPTER=path/to/wasi_snapshot_preview1.reactor.wasm ./build.sh
#
# The adapter comes with wasmtime releases and with jco (../ts-chatty).
set -eu
cd "$(dirname "$0")"
adapter="${ADAPTER:-../ts-chatty/node_modules/@bytecodealliance/jco/lib/wasi_snapshot_preview1.reactor.wasm}"
wit-bindgen c ../../wit/web.wit --world items-app --out-dir gen
# Zig's default WebAssembly stack is 16 MB; 1 MB (as Rust) makes each fresh
# instance cheaper and runs 2.3 times faster.
zig build-exe app.zig gen/items_app.c gen/items_app_component_type.o -Igen \
    -target wasm32-wasi -O ReleaseSmall -fno-entry -mexec-model=reactor -lc \
    --stack 1048576 -femit-bin=core.wasm
wasm-tools component new core.wasm --adapt wasi_snapshot_preview1="$adapter" -o app.wasm
rm -f core.wasm
