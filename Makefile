install:
	rustup component add llvm-tools
	cargo install cargo-llvm-cov

test_coverage:
	cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
	cargo llvm-cov report --html --output-dir coverage
	@echo "Coverage report generated in coverage/index.html"

report:
	cargo llvm-cov report


# Mutation testing

install_mutant:
	cargo install --locked cargo-mutants

mutant:
	cargo mutants --timeout 20 --jobs 10
