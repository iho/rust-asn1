install:
	rustup component add llvm-tools
	cargo install cargo-llvm-cov

test_coverage:
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	cargo llvm-cov report --html --output-dir coverage
	@echo "Coverage report generated in coverage/index.html"
