#!/bin/sh
# Builds the demo apps served at appfuzz.dev/demo/ into OUT: each bench app
# as NAME.wasm with its manifest as NAME.toml, so that
#   appfuzz https://appfuzz.dev/demo/NAME.wasm
# reviews it. With CHECK=1 each one is reviewed and must show its expected
# findings (APPFUZZ: the binary to use).
set -eu
cd "$(dirname "$0")"
out=${1:?usage: bench/demo.sh OUT_DIR}
apps="chatty reflect-query empty-panic utf8-slice clean"
mkdir -p "$out"
pkgs=""
for a in $apps; do pkgs="$pkgs -p $(echo "$a" | tr - _)"; done
# shellcheck disable=SC2086
cargo build --quiet --release --target wasm32-wasip2 $pkgs
for a in $apps; do
    cp "target/wasm32-wasip2/release/$(echo "$a" | tr - _).wasm" "$out/$a.wasm"
    sed "s|^wasm = .*|wasm = \"$a.wasm\"|" "apps/$a/appfuzz.toml" > "$out/$a.toml"
done
if [ "${CHECK:-0}" = 1 ]; then
    bin=${APPFUZZ:-appfuzz}
    for a in $apps; do
        kinds=$("$bin" -j 1 -m "$out/$a.toml" --state "$out/.appfuzz" review --time 2s |
            python3 -c 'import json,sys; print(" ".join(sorted({f["kind"] for f in json.load(sys.stdin)["findings"] if f["severity"] != "info"})))')
        echo "$a: ${kinds:-pass}"
    done
    rm -rf "$out/.appfuzz"
fi
