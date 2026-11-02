# The UniFFI smoke: the engine's async ports across the FFI

The verdict of the plan's P0.4 — the head-to-head the engine specification
demanded before the async-ports design is confirmed, executed 2026-11-02.

## The question

The engine core's whole design rests on **async port traits**: the core
`await`s an `HttpClient` the host performs, and sub-flow requests — sign,
consent, tx_code — it `await`s from a `Host` the *foreign* side implements
in Kotlin or Swift. go-wmp and the engine spec both flagged this as the
risk: "async trait objects over UniFFI are awkward or immature." The two
recorded fallbacks: a synchronous foreign callback with an async bridge in
Rust (what `siros-wscd-manager` ships), or a sans-I/O effect-list core.

## The answer

**Async-ports work on the pinned toolchain.** uniffi 0.28.3 supports
foreign-implemented async trait methods for both Kotlin and Swift, given
this exact incantation — recorded here because the macros reject anything
less:

```toml
uniffi = { version = "0.28", features = ["tokio"] }
async-trait = "0.1"
```

```rust
#[uniffi::export(callback_interface)]
#[async_trait::async_trait]
pub trait Host: Send + Sync {
    async fn request_tx_code(&self, flow_id: String) -> Result<String, SdkError>;
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn run_pre_authorized_flow(...) -> Result<String, SdkError { ... }
```

The trait **must** carry `#[async_trait]` (the plain `async fn` form fails
inside `callback_interface`), and exported async functions **must** name the
runtime. The generated shapes are the native ones:

- Kotlin: `interface Host { suspend fun requestTxCode(flowId: String): String }`
- Swift: `protocol Host { func requestTxCode(flowId: String) async throws -> String }`

## The evidence

1. **Generation**: `make bindings` produces 1,758 lines of Kotlin and 1,417
   of Swift from the engine-adapter-sdk's cdylib, with the full async
   surface (`suspend fun send`, `suspend fun requestTxCode`, `suspend fun
   runPreAuthorizedFlow`, `ping`; the `async throws` equivalents). `make
   check-bindings` fails the build if the bindings are empty or the Host
   surface is missing.
2. **Execution**: `make kotlin-smoke` compiles the generated bindings plus
   the smoke (`crates/engine-adapter-sdk/bindings-test/`) against the real
   cdylib and runs it on the JVM: the JVM implements both async ports with
   `suspend fun`, drives `runPreAuthorizedFlow` end to end — the Rust side
   `await`s the foreign HTTP port, then the foreign tx_code sub-flow, then
   the token POST carries the answered code — and the `Declined` error
   surfaces as the SDK error the host catches. Executed locally on
   2026-11-02: `uniffi-async-smoke: ok — async ports across UniFFI work on
   the JVM`. CI runs the same smoke on every push, plus a macOS job that
   type-checks the generated Swift and asserts its async surface.
3. **The counter-precedent, weighed**: `siros-wscd-manager` ships
   *synchronous* foreign callbacks (`FfiHttpTransport`, `FfiAuthCallback`)
   and adapts them to its internal `#[async_trait]` traits with a Rust
   bridge. That design is now a choice, not a constraint — its shape
   (plugins calling back into long-running native code) fits it, and it
   avoids the coroutine dependency on the host side. The engine's shape
   (the host is a *person's* answer; the SDK already speaks coroutines)
   fits the async ports, and the smoke proves the machinery.

## What the smoke does not cover

- **iOS/Android execution**: the smoke runs on the JVM; the macOS CI job
  type-checks the Swift. An on-device run arrives with the SDK integration
  proper (the plan's stub-then-ship order).
- **Cancellation**: a sub-flow the host cancels (the coroutine dropped
  mid-await) is the remaining sharp edge of the async design — uniffi's
  foreign-callback cancellation surfaces as a dropped future. The engine
  spec's cancellation port requirement (D4) is the hedge either way, and
  the spike report must test it when the flow runtime lands.
- **The sans-I/O core** stays the recorded fallback: the wallet-core
  presentation crates prove it daily, and nothing here forecloses it. The
  head-to-head's conclusion is that the async-ports design is *viable*, not
  that the alternative is dead — but the primary stands.

## Verdict

Proceed with the async-ports design as specified. The smoke crate
(`engine-adapter-sdk`), its committed bindings, `make bindings`,
`make check-bindings` and `make kotlin-smoke` are the mechanical gate the
spike report cites; the acceptance criterion of the plan — "a minimal
Kotlin (JVM) and Swift smoke test of an async HttpClient and Host callback
over UniFFI" — is met, with the Swift side type-checked and the JVM side
executed.
