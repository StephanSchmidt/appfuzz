#!/bin/sh
# Build go-chatty with TinyGo (wasip2) and wit-bindgen-go.
# TinyGo's runtime imports wasi:cli, so the world adds wasi:cli/imports to
# the bench's items-app world. Needs tinygo, go and wasm-tools on PATH.
set -eu
cd "$(dirname "$0")"
root=$(tinygo env TINYGOROOT)
rm -rf gen wit
mkdir -p wit/deps/web wit/deps/cli
cp ../../wit/web.wit wit/deps/web/
cp "$root"/lib/wasi-cli/wit/*.wit wit/deps/cli/
cp -r "$root"/lib/wasi-cli/wit/deps/* wit/deps/
cat > wit/world.wit <<'EOF'
package bench:go-chatty;

world go-app {
    include bench:web/items-app@0.1.0;
    include wasi:cli/imports@0.2.0;
}
EOF
wasm-tools component wit wit --wasm -o gen.wasm
go run go.bytecodealliance.org/cmd/wit-bindgen-go@v0.7.0 generate --world go-app --out gen --package-root go-chatty/gen gen.wasm
rm gen.wasm
tinygo build -target=wasip2 -opt=2 --wit-package wit --wit-world go-app -o app.wasm .
