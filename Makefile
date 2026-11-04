# Test coverage with cargo-llvm-cov (cargo install cargo-llvm-cov;
# rustup component add llvm-tools-preview). The full bench is left out:
# it takes about 20 minutes and is run before a release.

COV = cargo llvm-cov --workspace
SKIP_BENCH = -- --exact --skip bench

.PHONY: coverage coverage-html coverage-lcov

coverage:
	$(COV) --summary-only $(SKIP_BENCH)

coverage-html:
	$(COV) --html --open $(SKIP_BENCH)

coverage-lcov:
	$(COV) --lcov --output-path lcov.info $(SKIP_BENCH)
