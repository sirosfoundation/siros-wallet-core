# siros-wallet-core Makefile

SHELL := /bin/bash
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

# ── engine-adapter-sdk bindings ──────────────────────────────────────────
# The UniFFI bindings of the engine core, generated from the cdylib exactly
# as siros-wscd-manager does. Committed bindings must match a fresh
# generation; the CI job checks they are not empty.

.PHONY: bindings bindings-kotlin bindings-swift check-bindings

SDK_CRATE := engine-adapter-sdk
SDK_LIB := libengine_adapter_sdk.so

bindings: bindings-kotlin bindings-swift

bindings-kotlin: target/debug/$(SDK_LIB)
	@mkdir -p bindings/kotlin
	cargo run -p $(SDK_CRATE) --features bindgen --bin uniffi-bindgen -- \
		generate --library target/debug/$(SDK_LIB) \
		--language kotlin --out-dir bindings/kotlin

bindings-swift: target/debug/$(SDK_LIB)
	@mkdir -p bindings/swift
	cargo run -p $(SDK_CRATE) --features bindgen --bin uniffi-bindgen -- \
		generate --library target/debug/$(SDK_LIB) \
		--language swift --out-dir bindings/swift

target/debug/$(SDK_LIB):
	cargo build -p $(SDK_CRATE)

check-bindings: bindings
	@found=0; \
	while IFS= read -r -d '' f; do \
		test -s "$$f" || { echo "::error::$$f is empty"; exit 1; }; \
		grep -q "requestTxCode\|request_tx_code" "$$f" || { echo "::error::$$f has no Host surface"; exit 1; }; \
		echo "$$f: $$(wc -l < "$$f") lines"; \
		found=$$((found + 1)); \
	done < <(find bindings \( -name '*.kt' -o -name '*.swift' \) -print0); \
	test "$$found" -ge 2 || { echo "::error::expected Kotlin and Swift bindings, found $$found"; exit 1; }

# ── the mobile packaging (AAR / XCFramework) ──────────────────────────────
# Cross-compiles the engine-adapter-sdk for Android arm64 and iOS, and
# packages the bindings. Mirrors siros-wscd-manager's Makefile.

ANDROID_TARGETS := aarch64-linux-android
IOS_TARGETS := aarch64-apple-ios
IOS_SIM_TARGETS := aarch64-apple-ios-sim

.PHONY: android ios xcframework

android: $(ANDROID_TARGETS)

$(ANDROID_TARGETS):
	rustup target add $@
	cargo build -p engine-adapter-sdk --target $@ --release

ios: $(IOS_TARGETS) $(IOS_SIM_TARGETS)

$(IOS_TARGETS) $(IOS_SIM_TARGETS):
	rustup target add $@
	cargo build -p engine-adapter-sdk --target $@ --release

xcframework: ios
	@mkdir -p target/xcframework
	xcodebuild -create-xcframework \
		-library target/$(IOS_TARGETS)/release/libengine_adapter_sdk.a \
		-library target/$(IOS_SIM_TARGETS)/release/libengine_adapter_sdk.a \
		-output target/xcframework/engine_adapter_sdk.xcframework

# ── the JVM async smoke ──────────────────────────────────────────────────
# Compiles the generated Kotlin bindings plus the smoke against the built
# cdylib and runs it: the JVM implements the engine's async ports, drives
# an exported async flow, and the Rust side awaits the foreign callbacks.
# Toolchain overridable for CI (KOTLINC, COROUTINES_JAR, JNA_JAR,
# STDLIB_JAR).

KOTLINC ?= /tmp/opencode/kotlinc/bin/kotlinc
COROUTINES_JAR ?= /tmp/opencode/coroutines.jar
JNA_JAR ?= /tmp/opencode/jna.jar
STDLIB_JAR ?= /tmp/opencode/stdlib.jar

.PHONY: kotlin-smoke

kotlin-smoke: bindings check-bindings
	mkdir -p target/kotlin-smoke
	$(KOTLINC) -classpath "$(COROUTINES_JAR):$(JNA_JAR)" -d target/kotlin-smoke \
		bindings/kotlin/uniffi/engine_adapter_sdk/engine_adapter_sdk.kt \
		crates/engine-adapter-sdk/bindings-test/src/main/kotlin/Main.kt
	java -classpath "target/kotlin-smoke:$(COROUTINES_JAR):$(JNA_JAR):$(STDLIB_JAR)" \
		-Djna.library.path=target/debug MainKt
