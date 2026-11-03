# Architecture review: three deployment targets, one core

Nov 3, 2026. A step back from the implementation, reviewing what we have
against what the three targets need:

1. **A drop-in replacement** for `go-wallet-backend --mode=engine` (the
   in-cloud engine, container-deployed)
2. **Native SDK integration** (Kotlin and Swift, in-process, UniFFI)
3. **A WASM module** for the wallet-frontend (browser)

## What we have

| Crate | State | Serves |
| --- | --- | --- |
| `wmp-core` | Complete: peer, registry, profiles, session, flows, sub-flows, transports | All three |
| `engine-adapter-server` | Working: HTTP+SSE, WebSocket, token validation, session management, health probes | Target 1 |
| `engine-adapter-sdk` | Smoke-tested: async HttpClient and Host over UniFFI on the JVM | Target 2 |
| `engine-ports` | **Stub — no traits defined** | None yet |
| `engine-core` | **Stub — no flow runtime** | None yet |
| `engine-conformance` | **Stub — no vector runner** | Testing |
| Presentation core (13 crates) | Complete, green, proven | All three (payload handling) |

## The five findings

### 1. `engine-ports` is empty, and everything bypasses it

The port traits are the engine core's only interface with the world — the
spec's central architectural rule ("The core has no knowledge of tenants,
HTTP routers, Mongo, Redis or WebSockets; everything environmental is a
port"). But the crate is still a stub, and every adapter bypasses it:

- The server adapter talks to `ureq` directly (the JWKS fetch) and to the
  `SessionService` directly, with no port trait in between.
- The SDK adapter defines its *own* `HttpClient` and `Host` traits as UniFFI
  callback interfaces — not the engine's port traits.
- The session service takes entropy and clock as raw closures, not as
  port-trait objects.

This is the most consequential gap. When the engine core lands (S0–S3), it
needs the port traits to be its only dependency boundary. Right now, there is
no contract between the core and the adapters, and the adapters are each
building their own.

**What to do**: define `engine-ports` before S0, with exactly the traits the
spec names (`HttpClient` with declared purpose and limits, `Pdp`, `Clock`,
`Rng`, `Host` with the sub-flow methods, `KeyValue` for the session store,
`Telemetry`). The adapters then implement those traits; the core depends on
nothing else.

### 2. The SDK's traits are not the engine's traits

The `engine-adapter-sdk` defines `HttpClient` and `Host` as UniFFI callback
interfaces with their own types (`HttpRequest`, `FetchPurpose`, `SdkError`).
When the engine core lands, it needs the *same* traits — the `HttpClient`
the core `await`s must be the `HttpClient` the SDK exposes over UniFFI, not
a second one. Otherwise there are two trait hierarchies to keep in sync, and
the "one core, two adapters" claim breaks.

**What to do**: `engine-adapter-sdk` re-exports the `engine-ports` traits
with the UniFFI derives added; it does not define its own. The P0.4 smoke
proved the async-callback-over-UniFFI shape works — the port traits adopt
that shape.

### 3. `wmp-core`'s flow driver uses `std::thread`, which does not exist on wasm32

The async flow driver (`flowcontext.rs` line 517, `subflow.rs` lines 365,
425) spawns `std::thread` for flow workers and sub-flow senders. This works
on the server and on mobile (both have threads), but **wasm32 has no
threads** (without wasm-bindgen-rayon, which is a build-time-only solution).
The wallet-frontend's WASM build cannot use the flow driver as written.

This is the most important finding for the WASM target. The P0.4 smoke
proved async-over-UniFFI works on the JVM, where threads exist; the wasm32
case needs either:

- **(a)** An async-runtime abstraction: tokio on native, wasm-bindgen-futures
  on wasm — the flow driver takes a `Spawner` port that spawns differently
  per target. This keeps the async-ports design.
- **(b)** The sans-I/O core (effects in, actions out) — the spec's fallback,
  which the wallet-core presentation crates already use. The host drives the
  effect loop; no threading is needed.

**What to do**: this is a design decision, not an implementation detail. The
spike report must answer it. My recommendation: **(b) for WASM only** — the
sans-I/O core as a feature-gated variant of the flow driver, or as a second
driver beside the async one. The async driver stays for server and mobile;
the sans-I/O driver serves the browser. Both share the same flow logic; only
the execution model differs.

### 4. The server adapter's token validator is synchronous (`ureq`), not a port

The `TokenValidator` in `token.rs` fetches the JWKS through `ureq` — a
direct dependency, not through the `HttpClient` port. This works today (the
JWKS fetch happens at most every five minutes), but it means:

- The TEE build carries `ureq`'s TLS stack alongside `rustls` — exactly
  what the spec's "prefer rustls; avoid OpenSSL" supply-chain rule tries to
  prevent.
- The token validator's HTTP is not testable through the port fakes; it needs
  a real JWKS endpoint or a mock server.
- When the engine core's `Pdp` port lands, the trust path and the token path
  should go through the same `HttpClient` port, not two different stacks.

**What to do**: when `engine-ports::HttpClient` is defined, the token
validator takes it and the `ureq` dependency moves to the adapter (or is
replaced by the adapter's HTTP client entirely). This is a refactoring, not
a redesign — the `ureq` call is already isolated in `JwksCache::keys()`.

### 5. The session store is in-memory; the drop-in replacement needs Mongo

The Go engine uses Redis or Mongo for its session store
(`--mode=engine` with the shared Mongo revocation store). Our server uses
`MemorySessionStore` — fine for the spike and the test environments, but a
drop-in replacement in production needs the same store. The `SessionStore`
trait is already pluggable, but there is no Mongo adapter, and the Go
engine's session document schema is not documented in the spec.

**What to do**: the Mongo adapter is a server-adapter concern, not
engine-core. It arrives when the overlap starts (when the Rust engine runs
beside the Go engine against the same backend). The trait is ready; the
adapter is a follow-up task with a clear owner.

## The three targets, mapped

### Target 1: the drop-in `--mode=engine` replacement

**What works today**: the WMP transport (both bindings), token validation,
session management (create, resume, close), health probes, Docker packaging.

**What's missing**: the flow families (engine-core, gated on S0–S3), the
PDP port (engine-ports), the Mongo session store adapter, the resolve
endpoint (`/v1/resolve`, the authzen proxy the Go backend serves), and the
legacy WebSocket protocol (the spec says it stays on the Go engine during
the overlap — but a true drop-in replacement eventually needs it, or the
clients must all migrate to WMP first).

**Gates**: S0–S3 (the spike), PR 163 landing, the engine-ports traits.

### Target 2: the native SDK

**What works today**: the UniFFI async port shapes (tested on the JVM), the
wmp-core peer and session service, the Profile trait as the extension seam.

**What's missing**: the engine-core flow runtime (gated), the
engine-ports traits (the SDK's traits need to be those traits), the
platform-specific `Host` implementations (Kotlin UI, Swift UI), and the
build packaging (AAR, XCFramework — the Makefile targets exist but the
Android NDK and iOS SDK targets are not wired in CI yet).

**Gates**: S0–S3, the engine-ports traits, the SDK's UI-layer integration.

### Target 3: the WASM module for the wallet-frontend

**What works today**: the wallet-core presentation crates (all 13 build for
wasm32 in the proving workspace's `siros-zkp-req-wasm` crate), the wmp-core
types and session model (no threads needed for the data structures).

**What's missing**: the flow driver (std::thread doesn't work on wasm32 —
finding 3), the engine-ports traits (the browser's `fetch` is the HttpClient
port), the wasm-bindgen bindings, and the decision about which parts of the
engine the frontend actually runs in WASM.

**The architectural question**: the spec says "a WASM build of the engine" is
a non-goal because browsers cannot fetch issuers and verifiers directly
(CORS). But the wallet-frontend already runs the presentation-side work
(matching, consent building, response assembly) in WASM, and the backend
proxies the fetches that CORS blocks. The question is: does the frontend need
the *flow driver* in WASM (the browser drives the flows locally, with the
backend only proxying HTTP), or does the frontend only need the
*presentation-side* work (which it already has)?

**My reading**: the frontend needs the WMP *client* in WASM — the
`wmp-core` peer, the session management, the message types — so the browser
speaks WMP to the engine (the remote or TEE one) instead of the legacy
WebSocket protocol. The *flow driver* stays on the engine; the frontend's
role is the Host (the consent UI, the key operations). The sans-I/O flow
driver (finding 3's option b) would let the frontend drive the presentation
flows locally if that's what's wanted; the async driver stays for the
server and the SDKs.

## The recommended order

1. **Define `engine-ports`** — the traits the core depends on and the
   adapters implement. This is the prerequisite for everything else. The
   SDK's P0.4 traits become these traits; the server's `ureq` fetch becomes
   a port call.

2. **Build `engine-core`'s flow runtime** — S0, on the engine-ports traits,
   with the `AsyncFlowProfile` as the flow-family registration seam. The
   server's handler delegates to this.

3. **Build the flow families** — S1–S3 (OID4VCI issuance, trust through the
   `Pdp` port, the live gdc run). The server and the SDK both get these
   through the same core.

4. **Add the WASM driver** — the sans-I/O variant of the flow driver, for
   the browser, sharing the same flow logic. This is a design task with the
   spike report, not a last-minute port.

5. **Wire the `engine-conformance` runner** — the vector runner that both
   the Go and Rust engines run against, loading the `engine-vectors`
   repository's scenarios.

## What this review changes in the existing code

- `engine-adapter-sdk`: its `HttpClient` and `Host` traits move to
  `engine-ports`; the SDK re-exports them with UniFFI derives added.
- `engine-adapter-server`: its token validator's `ureq` fetch becomes an
  `HttpClient` port call; its handler delegates to `engine-core`'s runtime
  when the flow families land.
- `wmp-core`: unchanged — it is the shared WMP library, not the engine. The
  flow driver's threading is a wmp-core concern that the WASM variant
  resolves inside wmp-core (or in a feature-gated module), not in the
  adapters.

None of these are rewrites; they are the wiring that the spike's gated work
was always going to need. The review's purpose is to record them now, so
S0 starts with the seams in the right place.
