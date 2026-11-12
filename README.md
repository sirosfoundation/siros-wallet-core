# siros-wallet-core

[![CI](https://github.com/sirosfoundation/siros-wallet-core/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-wallet-core/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-wallet-core/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-wallet-core)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)
[![rustc](https://img.shields.io/badge/rustc-1.99.1-9c6144.svg)](rust-toolchain.toml)

The Rust wallet core of SIROS: one workspace for what a wallet computes, on
both sides of the WMP engine seam.

**The presentation core** answers OpenID4VP 1.0 presentation requests and the
W3C Digital Credentials API, from request intake to the response: DCQL, SD-JWT
VC and ISO mdoc, issuer trust, display, transaction data on the PaSO model,
`zkp_req` — extensions to DCQL that let a verifier state a zero-knowledge
request and a wallet answer it; the first capability defined on it is
nym_auth, a normal credential that happens to carry the capability of doing
pseudonyms — and the presentation component that plans a consent view and
turns the user's selection into the response.

**The WMP engine core** implements OpenID4VCI issuance and OpenID4VP
presentation behind the Wallet Messaging Protocol, in one core with three
adapters: in-process in the native SDKs (UniFFI), standalone as a server
container (HTTP+SSE and WebSocket transports), and in the browser (WASM over
the page's callbacks). Every environmental effect — the network, the clock,
the entropy, the persistence, the trust decisions, the user's consent — flows
through the port traits, so the same core runs on all three without touching
a socket, a clock, or a keystore.

## Crates

### The WMP engine core

| Crate | Role |
| --- | --- |
| `wmp-core` | The Wallet Messaging Protocol itself: the peer, the session service, both transports' message shapes — the complete mirror of go-wmp v0.13.0 |
| `engine-ports` | The port traits the core runs on: `HttpClient`, `Host`, `Pdp`, `Clock`, `Rng`, `KeyValue`, `Telemetry` — plus the wire contracts that cross the host boundary (the verifier info, the match and presentation asks, the DPoP and attestation asks) |
| `engine-core` | The flow runtime and the flow families. **OpenID4VCI**: the offer (by value, by reference, by URI scheme), the issuer and AS metadata resolvers, the pre-authorized-code and authorization-code grants (PKCE, PAR, the two-call resume), the renewal grant with the refresh-token and DPoP-key relay, the token exchange with DPoP (RFC 9449, nonce retry, client-held or engine-held keys) and OAuth-Client-Attestation (WIA from the wallet provider, challenge retry), the credential request (the `invalid_nonce` retry, the response-encryption offer and decrypt, the identifier substitution), deferred polling, the notification, and trust evaluation through the PDP — fail closed. **OpenID4VP**: request parsing (by value, request object, `request_uri`), the client_id schemes, the §5 validations, verifier trust through the PDP, transaction data, DCQL (the §8.1 vp_token assembly), the JARM response (`direct_post.jwt` encrypted via jose-rs), the decline, and the response modes |
| `engine-adapter-sdk` | The UniFFI bindings for the native SDKs: the ports as Kotlin/Swift interfaces, the in-process engine handle, the async callbacks |
| `engine-adapter-server` | The standalone container: both WMP transports (HTTP+SSE and WebSocket), the token validation, the health probes |
| `engine-adapter-wasm` | The browser engine: the WMP JSON-RPC surface over JS Promises, the page's fetch behind `HttpClient`, the wallet's UI callbacks behind `Host`, the JS event loop bridged to the Send-bounded port traits |
| `engine-conformance` | The vector runner: loads the [engine-vectors](https://github.com/sirosfoundation/engine-vectors) scenarios, validates every one against the repository's schema, and runs them against the real engine — the scripted world asserts every fetch, every host ask, and every outgoing message |

### The presentation core

| Crate | Role |
| --- | --- |
| `siros-codec` | Strict CBOR and JSON, base64url, the padded base64 of `x5c`, CBOR dates and shared types |
| `siros-dcql` | The DCQL query model (OpenID4VP §6, construction by parsing only) and the shared request vocabulary |
| `siros-sdjwt` | The stored SD-JWT VC (RFC 9901), disclosure selection, the KB-JWT signing input |
| `siros-mdoc` | The stored mdoc, its MSO, disclosure, DeviceResponse and the DeviceAuthentication signing input |
| `siros-oid4vp` | Request intake, client identifier prefixes, handovers, `vp_token`, response encryption and submissions |
| `siros-trust` | The trust store, issuer chains, path validation, issuer admission |
| `siros-wallet-state` | The decrypted wallet state of the private data container |
| `siros-credential` | The format-independent credential with typed claims and validity |
| `siros-display` | Display metadata, locale resolution, cards, claim rows, purpose lines |
| `siros-transaction-data` | `transaction_data` on the PaSO model, definitions, projection, rendering, bindings |
| `siros-zkp-req` | The `zkp_req` protocol layer: extensions to DCQL (`_req`, `_req_sets`, `vp_formats_supported.zkp_req`, the presentation) that carry ZKP requests and responses. Holds no prover and no system; format-neutral by design |
| `siros-zkp-catalogues` | The catalogue crate: every `zkp_req` rulebook lands here as modules and features — capability growth never adds a crate. Today it holds nym_auth, a normal credential (an mdoc, stored in the wallet state and consented like any other) that happens to carry the capability of doing pseudonyms: its rulebook defines the functions (`pseudonym`, `age_check`) and the Longfellow and Vega systems that prove them |
| `siros-presentation` | The plan of a request over the wallet's credentials, the consent view, the selection, the response |
| `siros-explain` | The error contract: a stable id and named arguments, each a typed value with its `Display` |
| `siros-explain-derive` | `#[derive(Explain)]` beside `thiserror` |
| `siros-derive-internals` | The field rules the two derives share: arguments, `Option`, `Arg` bounds, the id marker, the `check` row |
| `siros-syntax` | Checked texts, keyed and non-empty lists, and values in their literal forms: numbers, amounts in the currencies of ISO 4217 List One (SIX, 2026-09-17), dates and times |
| `siros-i18n` | The wallet's texts: a `Context` of MessageFormat 2 sources resolves an error or a statement (`Message`) to `Text` |
| `siros-i18n-derive` | `#[derive(Message)]` for statements |
| `siros-cldr` | Writes a language's CLDR format options as MF2 source |

siros-i18n's format functions are features, which an app turns on as its
wording calls them: `number` (`:number`, `:integer`), `currency` (`:currency`,
`:percent`), `offset` (`:offset`) and `date` (`:siros:date`, `:siros:time`,
`:siros:datetime`). `derive` gives `#[derive(Message)]`. `nfc` holds
MessageFormat 2's names, variant keys and selector literals in Unicode
Normalization Form C, as MF2 compares them, and adds `Context::module_in_nfc`,
which refuses a source normalization would change. A build without `nfc` links
no unicode-normalization and holds them as written, and resolves a source that
`module_in_nfc` loads to the same texts. The wallet turns `nfc` on; the
Credential Manager matcher leaves it off. All six are defaults. `check` adds
`Context::check`, the wallet's completeness test, and `conformance` MF2's test
functions for siros-i18n's conformance tests.

Rust 1.89 is the floor of every crate (`rust-version` in `Cargo.toml`).

`proving/` is a second workspace — the `zkp_req` proof backends
(`siros-zkp-backend-longfellow`, `siros-zkp-backend-vega`) and the browser
presenter (`siros-zkp-req-wasm`) — with its own 1.95 floor; see
[CONTRIBUTING.md](CONTRIBUTING.md#development).

The Android credential picker (`matcher.wasm`, `siros-registration`,
`android-credman`) and the Kotlin/Swift bindings of the matcher stay in
[siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher); they
consume the presentation core from there.

## Build and test

Rust, pinned exactly in `rust-toolchain.toml` (rustup installs it on first
use). The gates CI holds:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/check_panic_sites.py Cargo.toml
```

On a push to `main`, CI's per-merge tier also runs siros-i18n's ignored tests, its
differentials against ICU4X 2.4: dates, times and years, plural categories, numbers and
amounts in every currency.

```sh
cargo test --locked -p siros-i18n --all-features -- --ignored
```

Nothing panics outside the tests: a type makes the impossible state
unrepresentable, or the caller receives an error. CI holds each crate to it
with clippy and `scripts/check_panic_sites.py`.

### The adapters

```sh
make bindings          # the UniFFI Kotlin and Swift bindings
make kotlin-smoke      # the JVM smoke: the port traits over UniFFI
wasm-pack test --node crates/engine-adapter-wasm   # the browser smoke
```

The Kotlin smoke needs `kotlinc` and the JNA/coroutines jars on the path the
Makefile documents; everything else is plain cargo.

### The release artifacts

Built by the standard GitHub builders on a `v*` tag
([release.yml](.github/workflows/release.yml)):

- **Android**: `make aar` — the three ABIs cross-compiled through cargo-ndk,
  packaged as the AAR, published to GitHub Packages as
  `org.siros:siros-wallet-core`
- **iOS**: `make xcframework` — the aarch64 device and simulator slices, the
  FFI header and modulemap, packaged as the XCFramework
- Both consume the UniFFI bindings the release generates alongside

## Conformance

The engine's behaviours are gated by the scenarios in
[engine-vectors](https://github.com/sirosfoundation/engine-vectors) — the
runner executes them against the real engine in CI, and the recorded
decisions (the places where the spec allowed a choice, or the two engines
disagree and the disagreement is decided) live in that repository's
`docs/decisions.md`, cited by the vectors that test them.

## Provenance

The presentation crates are an independent implementation, ported from the
dc-matcher workspace (closed for placement, not content). The
[OpenWallet Foundation's Multipaz](https://github.com/openwallet-foundation/multipaz)
project is a **conformance oracle only** — see
[CONTRIBUTING.md](CONTRIBUTING.md#provenance) for the rule in full.

`siros-dcql` is on [crates.io](https://crates.io/crates/siros-dcql); the other
crates are `publish = false` until their first release.
