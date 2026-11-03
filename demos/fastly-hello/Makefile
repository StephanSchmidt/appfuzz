# Fastly Compute demo, step by step through the .wasm file:
#   make wasm     cargo builds the WASI preview 1 module
#   make serve    runs that .wasm locally in Viceroy (http://127.0.0.1:7676)
#   make pack     wraps that .wasm into pkg/fastly-hello.tar.gz
#   make deploy   deploys the package to the service in fastly.toml
#   make check    requests the live URL
#   make imports  lists the host calls the .wasm imports

WASM := target/wasm32-wasip1/release/fastly-hello.wasm
PKG  := pkg/fastly-hello.tar.gz
URL  := https://multiply-clean-ghost.edgecompute.app

.PHONY: wasm serve pack deploy check imports clean

wasm: $(WASM)

$(WASM): Cargo.toml Cargo.lock $(wildcard src/*)
	cargo build --release

serve: $(WASM)
	fastly compute serve --skip-build --file $(WASM)

pack: $(PKG)

$(PKG): $(WASM) fastly.toml
	fastly compute pack --wasm-binary $(WASM) --non-interactive

deploy: $(PKG)
	fastly compute deploy --package $(PKG) --non-interactive

check:
	@curl -s -o /dev/null -w "GET /      %{http_code}\n" $(URL)/
	@curl -s -o /dev/null -w "POST /     %{http_code}\n" -X POST $(URL)/
	@curl -s -o /dev/null -w "GET /nope  %{http_code}\n" $(URL)/nope

imports: $(WASM)
	wasm-tools print $(WASM) | grep -o '(import "[^"]*"' | sort | uniq -c

clean:
	cargo clean
	rm -rf pkg
