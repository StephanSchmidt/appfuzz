# Test coverage with cargo-llvm-cov (cargo install cargo-llvm-cov;
# rustup component add llvm-tools-preview). The full bench is left out:
# it takes about 20 minutes and is run before a release.

COV = cargo llvm-cov --workspace
SKIP_BENCH = -- --exact --skip bench

.PHONY: coverage coverage-html coverage-lcov speed browser

coverage:
	$(COV) --summary-only $(SKIP_BENCH)

coverage-html:
	$(COV) --html --open $(SKIP_BENCH)

coverage-lcov:
	$(COV) --lcov --output-path lcov.info $(SKIP_BENCH)

# Engine speed in Go's benchmark format, mostly on one thread. Compare two
# builds with benchstat (go install golang.org/x/perf/cmd/benchstat@latest):
#   make speed > old.txt; change something; make speed > new.txt
#   benchstat old.txt new.txt
SPEED_ARGS ?= -count 6

speed:
	@cargo bench -p appfuzz --bench speed -- $(SPEED_ARGS)

# The browser guest that runs pages' scripts (probe scripts): the DOM shim
# (npm), then QuickJS and the driver for wasm32-wasip2, into the core's
# assets with a note of what went in.
BROWSER_ASSETS = crates/appfuzz-core/assets/browser
BROWSER_WASM = browser/target/wasm32-wasip2/release/appfuzz_browser.wasm

browser:
	cd browser/js && npm ci --silent && npm run --silent build
	cargo build --release --manifest-path browser/Cargo.toml --target wasm32-wasip2 -p appfuzz-browser
	cp $(BROWSER_WASM) $(BROWSER_ASSETS)/browser.wasm
	{ echo "The browser guest: QuickJS (quickjs-ng, MIT, via rquickjs, MIT), a DOM"; \
	  echo "shim on linkedom (ISC), cookies with tldts (MIT, Public Suffix List),"; \
	  echo "and the page driver, built by make browser."; \
	  echo "Source: browser/ (guest/, js/, wit/)."; \
	  echo "rquickjs: $$(grep -A1 '^name = "rquickjs-core"' browser/Cargo.lock | sed -n 's/version = //p' | tr -d '"')"; \
	  echo "linkedom: $$(node -p 'require("./browser/js/node_modules/linkedom/package.json").version')"; \
	  echo "tldts: $$(node -p 'require("./browser/js/node_modules/tldts/package.json").version')"; \
	  echo "tldts-core: $$(node -p 'require("./browser/js/node_modules/tldts-core/package.json").version')"; \
	  echo "rustc: $$(rustc --version)"; \
	  echo "SHA-256: $$(sha256sum $(BROWSER_ASSETS)/browser.wasm | cut -d' ' -f1)"; \
	} > $(BROWSER_ASSETS)/PROVENANCE.txt
	{ echo "tldts"; cat browser/js/node_modules/tldts/LICENSE; \
	  echo; echo "tldts-core"; cat browser/js/node_modules/tldts-core/LICENSE; \
	} > $(BROWSER_ASSETS)/LICENSES.tldts.txt
