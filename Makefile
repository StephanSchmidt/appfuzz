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
# (npm), then QuickJS and the driver for wasm32-wasip2, snapshotted once the
# shim is loaded (wizen: a page visit starts there), into the core's assets
# with a note of what went in.
BROWSER_ASSETS = crates/appfuzz-core/assets/browser
BROWSER_WASM = browser/target/wasm32-wasip2/release/appfuzz_browser.wasm
BROWSER_LOCK = grep -A1 '^name = "$(1)"$$' browser/Cargo.lock | sed -n 's/version = //p' | tr -d '"'

browser:
	cd browser/js && npm ci --silent && node --test private-dom-slots.test.mjs && npm run --silent build
	cargo build --release --manifest-path browser/Cargo.toml --target wasm32-wasip2 -p appfuzz-browser
	cargo run --release --manifest-path browser/Cargo.toml -p appfuzz-browser-wizen -- $(BROWSER_WASM) $(BROWSER_ASSETS)/browser.wasm
	{ echo "The browser guest: QuickJS (quickjs-ng, MIT, via rquickjs, MIT), a DOM"; \
	  echo "shim on linkedom (ISC), HTML tree building with parse5 (MIT),"; \
	  echo "cookies with psl (MIT, Public Suffix List), URLs with url"; \
	  echo "(MIT/Apache-2.0) and the page driver, snapshotted after boot,"; \
	  echo "built by make browser."; \
	  echo "Source: browser/ (guest/, js/, wit/, wizen/)."; \
	  echo "rquickjs: $$($(call BROWSER_LOCK,rquickjs-core))"; \
	  echo "QuickJS patch: browser/vendor/rquickjs-sys/json-private-lists.patch"; \
	  echo "QuickJS source SHA-256: $$(sha256sum browser/vendor/rquickjs-sys/quickjs/quickjs.c | cut -d' ' -f1)"; \
	  echo "url: $$($(call BROWSER_LOCK,url))"; \
	  echo "linkedom: $$(node -p 'require("./browser/js/node_modules/linkedom/package.json").version')"; \
	  echo "parse5: $$(node -p 'require("./browser/js/node_modules/parse5/package.json").version')"; \
	  echo "parse5 entities: $$(node -p 'require("./browser/js/node_modules/parse5/node_modules/entities/package.json").version')"; \
	  echo "psl: $$($(call BROWSER_LOCK,psl))"; \
	  echo "encoding_rs: $$($(call BROWSER_LOCK,encoding_rs))"; \
	  echo "roxmltree: $$($(call BROWSER_LOCK,roxmltree))"; \
	  echo "xml: $$($(call BROWSER_LOCK,xml))"; \
	  echo "unicode-bidi: $$($(call BROWSER_LOCK,unicode-bidi))"; \
	  echo "color: $$($(call BROWSER_LOCK,color))"; \
	  echo "cssparser: $$($(call BROWSER_LOCK,cssparser))"; \
	  echo "cssparser-color: $$($(call BROWSER_LOCK,cssparser-color))"; \
	  echo "rustc: $$(rustc --version)"; \
	  echo "SHA-256: $$(sha256sum $(BROWSER_ASSETS)/browser.wasm | cut -d' ' -f1)"; \
	} > $(BROWSER_ASSETS)/PROVENANCE.txt
	{ echo "parse5"; cat browser/js/node_modules/parse5/LICENSE; \
	  echo; echo "parse5 entities"; cat browser/js/node_modules/parse5/node_modules/entities/LICENSE; \
	} > $(BROWSER_ASSETS)/LICENSES.parse5.txt
