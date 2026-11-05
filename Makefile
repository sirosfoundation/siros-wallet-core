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

# The cdylib's extension follows the host: .so on Linux and Android,
# .dylib on macOS (the bindings and the xcframework recipes build the
# host cdylib to generate from).
HOST_LIB_EXT := $(shell uname -s | grep -q Darwin && echo dylib || echo so)
SDK_LIB := libengine_adapter_sdk.$(HOST_LIB_EXT)

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

# ── the mini-wallet page (the OIDF conformance harness) ──────────────────
# wasm-pack builds the browser module; the page directory assembles the
# harness (index.html, wallet.js, wallet_glue.js) and the built pkg into
# target/wasm-page — serve it as the wallet under test for the
# conformance suites (docs/oidf-conformance.md).
.PHONY: wasm-page

wasm-page:
	wasm-pack build --target web crates/engine-adapter-wasm --out-dir $(CURDIR)/target/wasm-pkg
	@mkdir -p target/wasm-page
	cp crates/engine-adapter-wasm/page/index.html crates/engine-adapter-wasm/page/wallet.js crates/engine-adapter-wasm/page/mini-wallet.json crates/engine-adapter-wasm/page/mini-test.crl target/wasm-page/
	@mkdir -p target/wasm-page/pkg
	cp -r target/wasm-pkg/* target/wasm-page/pkg/
	sed 's|../pkg/engine_adapter_wasm.js|./pkg/engine_adapter_wasm.js|' \
		crates/engine-adapter-wasm/page/wallet_glue.js > target/wasm-page/wallet_glue.js

# ── the mobile packaging (AAR / XCFramework) ──────────────────────────────
# Cross-compiles the engine-adapter-sdk for Android arm64 and iOS, and
# packages the bindings. Mirrors siros-wscd-manager's Makefile.

# ── the mobile packaging (AAR / XCFramework) ──────────────────────────────
# Cross-compiles the engine-adapter-sdk for Android arm64 and iOS, and
# packages the bindings. Mirrors siros-wscd-manager's Makefile, whose
# recipes are proven on real xcodebuild and gradle consumers.

# The version of the SDK crate, for the artifact names. The release
# workflow passes VERSION explicitly from the tag.
VERSION := $(shell cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; [print(p['version']) for p in json.load(sys.stdin)['packages'] if p['name']=='engine-adapter-sdk']")

# Maven coordinates: consumers resolve org.siros:siros-wallet-core.
MAVEN_GROUP    := org.siros
MAVEN_ARTIFACT := siros-wallet-core

ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
IOS_TARGETS := aarch64-apple-ios
# The Intel simulator target (x86_64-apple-ios-sim) is gone: Apple
# removed the Intel iOS-simulator SDK in Xcode 26 and Rust 1.99 dropped
# the target with it. Apple Silicon simulators take the aarch64 slice.
IOS_SIM_TARGETS := aarch64-apple-ios-sim

.PHONY: android ios xcframework aar pom

# Android cross-compilation (requires cargo-ndk — the release runner
# installs it; the plain cargo target cannot name the NDK linker).
android: $(foreach t,$(ANDROID_TARGETS),android-$(t))

android-%:
	rustup target add $*
	cargo ndk --target $* --platform 28 -- build -p engine-adapter-sdk --release

ios: $(IOS_TARGETS) $(IOS_SIM_TARGETS)

$(IOS_TARGETS) $(IOS_SIM_TARGETS):
	rustup target add $@
	cargo build -p engine-adapter-sdk --target $@ --release

xcframework: ios bindings-swift
	@rm -rf target/xcframework
	# The modulemap: plain "module", not "framework module" — this
	# XCFramework is built from static libraries (-library/-headers), so
	# the framework form fails at import time. The headers nest under
	# engine_adapter_sdkFFI/ so two static-archive XCFrameworks linked
	# into one product do not collide in Xcode's shared include/
	# directory (the wscd-manager finding, confirmed on a real
	# xcodebuild).
	@mkdir -p target/Headers/engine_adapter_sdkFFI
	@cp bindings/swift/engine_adapter_sdkFFI.h target/Headers/engine_adapter_sdkFFI/
	@echo 'module engine_adapter_sdkFFI { header "engine_adapter_sdkFFI.h" export * }' \
		> target/Headers/engine_adapter_sdkFFI/module.modulemap
	xcodebuild -create-xcframework \
		-library target/$(IOS_TARGETS)/release/libengine_adapter_sdk.a \
		-headers target/Headers \
		-library target/$(IOS_SIM_TARGETS)/release/libengine_adapter_sdk.a \
		-headers target/Headers \
		-output target/xcframework/engine_adapter_sdk.xcframework
	@echo "XCFramework created at target/xcframework/engine_adapter_sdk.xcframework"

# ── AAR packaging (mirrors siros-wscd-manager) ────────────────────────────
# The AAR ships the native .so libraries; the UniFFI Kotlin bindings are
# consumed as vendored source by the SDK, so an empty classes.jar
# satisfies the AAR layout. JNA is provided transitively via the POM.

aar: android
	@rm -rf target/aar target/aar-classes
	@mkdir -p target/aar/jni/arm64-v8a target/aar/jni/armeabi-v7a target/aar/jni/x86_64
	cp target/aarch64-linux-android/release/libengine_adapter_sdk.so target/aar/jni/arm64-v8a/
	cp target/armv7-linux-androideabi/release/libengine_adapter_sdk.so target/aar/jni/armeabi-v7a/
	cp target/x86_64-linux-android/release/libengine_adapter_sdk.so target/aar/jni/x86_64/
	@echo '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.engine"/>' \
		> target/aar/AndroidManifest.xml
	@mkdir -p target/aar-classes/META-INF
	@printf 'Manifest-Version: 1.0\n' > target/aar-classes/META-INF/MANIFEST.MF
	cd target/aar-classes && zip -qr ../aar/classes.jar .
	cd target/aar && zip -r ../siros-wallet-core-$(VERSION).aar .
	@echo "AAR created at target/siros-wallet-core-$(VERSION).aar"

# ── Maven POM (for publishing the AAR by coordinates) ─────────────────────

pom:
	@mkdir -p target
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<project xmlns="http://maven.apache.org/POM/4.0.0"' \
	  '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	  '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
	  '  <modelVersion>4.0.0</modelVersion>' \
	  '  <groupId>$(MAVEN_GROUP)</groupId>' \
	  '  <artifactId>$(MAVEN_ARTIFACT)</artifactId>' \
	  '  <version>$(VERSION)</version>' \
	  '  <packaging>aar</packaging>' \
	  '  <name>siros-wallet-core</name>' \
	  '  <description>The SIROS wallet engine core: the native engine behind the Android SDK.</description>' \
	  '  <url>https://github.com/sirosfoundation/siros-wallet-core</url>' \
	  '  <licenses>' \
	  '    <license><name>BSD 2-Clause License</name><url>https://opensource.org/license/bsd-2-clause</url></license>' \
	  '  </licenses>' \
	  '  <dependencies>' \
	  '    <dependency>' \
	  '      <groupId>net.java.dev.jna</groupId>' \
	  '      <artifactId>jna</artifactId>' \
	  '      <version>5.17.0</version>' \
	  '      <scope>compile</scope>' \
	  '    </dependency>' \
	  '  </dependencies>' \
	  '</project>' \
	  > target/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "POM created at target/$(MAVEN_ARTIFACT)-$(VERSION).pom"

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
		crates/engine-adapter-sdk/bindings-test/src/main/kotlin/Main.kt \
		crates/engine-adapter-sdk/bindings-test/src/main/kotlin/EngineSmoke.kt
	java -classpath "target/kotlin-smoke:$(COROUTINES_JAR):$(JNA_JAR):$(STDLIB_JAR)" \
		-Djna.library.path=target/debug MainKt
