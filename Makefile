# siros-wallet-core Makefile
#
# Targets:
#   make check   — fmt --check, clippy -D warnings, tests, panic-site check
#   make audit   — cargo audit + cargo deny (needs cargo-audit / cargo-deny)
#   make clean   — remove build artifacts

.PHONY: all check fmt clippy test panic-sites audit clean

all: check

check: fmt clippy test panic-sites

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --locked --workspace --all-features

panic-sites:
	python3 scripts/check_panic_sites.py Cargo.toml

audit:
	cargo audit
	cargo deny check

clean:
	cargo clean
