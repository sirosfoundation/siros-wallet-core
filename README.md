# siros-wallet-core

[![CI](https://github.com/sirosfoundation/siros-wallet-core/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-wallet-core/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-wallet-core/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-wallet-core)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)
[![rustc](https://img.shields.io/badge/rustc-1.99.1-9c6144.svg)](rust-toolchain.toml)

The Rust wallet core of SIROS: one workspace for what a wallet computes, on
both sides of the WMP engine seam.

**The presentation core** answers an OpenID4VP 1.0 request, received by the W3C
Digital Credentials API or by a URI: DCQL, SD-JWT VC and ISO mdoc, issuer
trust, transaction data on the PaSO model and CSC's QES, consent, and the
response; the caller performs every network call and key operation. `zkp_req`
extends DCQL so a verifier states a zero-knowledge request and a wallet
answers it; nym_auth is its first capability.

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

A wallet receives an OpenID4VP 1.0 request, by the W3C Digital Credentials API
or by a URI, and answers it; the caller performs every network call and key
operation. `docs/wallet-core-design.md` is the contract of these crates.

| Crate | The problem it solves |
| --- | --- |
| `siros-openid4vp` | The core: a request in, a response built. Arrival, the envelope, routing, Verifier authentication, DCQL, matching and consent, phase 2, and every extension point's trait |
| `siros-x509` | The `x509_hash` and `x509_san_dns` Client Identifier Prefixes |
| `siros-mdoc` | `mso_mdoc`: B.2.6's handover, the `DeviceMac` module, the stored mdoc's reading (`stored`), and its registration: the view with `validityInfo` (`registration`) |
| `siros-sdjwt` | `dc+sd-jwt`: the issued SD-JWT read into its document and view with validity (`Registered`), its presentation with a compact Key Binding JWT, and a type metadata document's `display` as a defined module |
| `siros-paso` | PaSO's transaction data, with the `Paso`, `RandomIds`, `IssuerTrust` and `CoseEncrypt` modules; `sealed-signals` seals an mdoc's risk signals with the last |
| `siros-qes` | CSC's QES transaction data; its SHA-3 approval hashes under `sha3` |
| `siros-ts12` | TS12's payments and logins under `urn:eudi:sca:`: the registration document, typed payloads, the translation into PaSO's model, the request rules T1 to T6 and the Key Binding JWT's claims, rendered through siros-paso's engine |
| `siros-webuild` | WE BUILD's CS-02 rules: the Request Object claims CS-02 §8.2 requires (`Cs02Claims`) and the Verifier's error answer of CS-02 §8.3 (`Cs02ErrorAnswer`) |
| `siros-credman` | Android Credential Manager's Standard and Payment entries of the core's consent entries, and each set's delegation (A9, K4), for the matcher; the matcher's entry emission through the registration's package, and under `register` the registration's package |
| `siros-trust` | Issuer trust at registration: the trust store, issuer chains, the `Facts` the core matches a query's `trusted_authorities` against |
| `siros-wallet-state` | The decrypted wallet state of the private data container, and the instance of a batch a presentation uses |
| `siros-i18n` | The i18n engine: MessageFormat 2 modules loaded whole, rendered through format modules |
| `siros-explain` | Errors as messages: a stable identifier and typed, named arguments |
| `siros-explain-derive` | `#[derive(Explain)]` beside `thiserror` |
| `siros-cldr` | Writes a language's CLDR format options for siros-i18n modules |
| `siros-testkit` | The core's test doubles |
| `siros-integration` | The HAIP and WE BUILD builds end to end: every flow of the design, F1 to F13 |
| `siros-zkp-req` | The `zkp_req` protocol layer: extensions to DCQL (`_req`, `_req_sets`, `vp_formats_supported.zkp_req`, the presentation) that carry ZKP requests and responses. Holds no prover and no system; format-neutral by design |
| `siros-zkp-catalogues` | The catalogue crate: every `zkp_req` rulebook lands here as modules and features — capability growth never adds a crate. Today it holds nym_auth, a normal credential (an mdoc, stored in the wallet state and consented like any other) that happens to carry the capability of doing pseudonyms: its rulebook defines the functions (`pseudonym`, `age_check`) and the Longfellow and Vega systems that prove them |

Each mechanism of the core is a feature, which the crates that use it turn on;
a build compiles what it registers. The right column names the core's features
each crate turns on: those it always turns on, then `feature: core features`
for each of its own features that turns more on. The core turns on siros-i18n's
`render`, `number` and `list`, siros-paso its `number`, `currency` and `date`,
siros-credman its `render`, and siros-credman's `register` its `load`; the app
turns on `load`.

```text
siros-openid4vp       the core: a request in, a response built   match | resolve | dc-api | uri | signed | request-decryption | cbor | transaction-data | sha3 | blake2 | k12 | sri | claims
├── siros-x509        x509_hash, x509_san_dns                     signed
├── siros-mdoc        mso_mdoc; B.2.6's handover; module DeviceMac; the stored mdoc's reading and registration   claims; resolve: resolve, cbor
├── siros-sdjwt       dc+sd-jwt; the issued SD-JWT's registration and presentation; siros-i18n: render   claims; resolve: resolve
├── siros-paso        PaSO's transaction data; modules Paso, RandomIds, IssuerTrust, CoseEncrypt; resolve: siros-x509's x5c   transaction-data, sri; resolve: resolve; sealed-signals: cbor
├── siros-qes         CSC's QES transaction data                  sri; resolve: resolve; sha3: its SHA-3 approval hashes
├── siros-credman     Credential Manager's entries for the matcher; the entry emission; register: the registration's package   match
├── siros-ts12        TS12 on PaSO's engine                                 transaction-data; resolve: resolve
├── siros-webuild     WE BUILD's CS-02 rules: Cs02Claims, Cs02ErrorAnswer   signed, uri
├── siros-trust       issuer trust at registration                match, resolve
├── siros-zkp-req     zkp_req's protocol layer                    resolve, cbor
├── siros-zkp-catalogues   the zkp_req rulebooks: nym_auth         resolve, cbor, dc-api, uri
├── siros-testkit     the core's test doubles                     resolve, dc-api, request-decryption, cbor, sha3, blake2, k12, sri, claims
└── siros-integration the HAIP and WE BUILD builds end to end     resolve
siros-i18n            the i18n engine                             load | render | number | currency | offset | date | list
siros-cldr            CLDR format options for siros-i18n modules
siros-explain         the message contract
siros-explain-derive  #[derive(Explain)]
siros-wallet-state    the decrypted wallet state
xtask                 the repository's build gates: cargo xtask builds, cargo xtask alone
```

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
cargo xtask layout   # no test code under src/, no message source outside the test app and tests/, no display literal
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/check_panic_sites.py Cargo.toml proving/Cargo.toml
cargo xtask builds   # each build of xtask/builds.json against the crates it excludes and its count
cargo xtask alone    # each crate alone, with and without its default features
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

The presentation crates are an independent implementation. The
[OpenWallet Foundation's Multipaz](https://github.com/openwallet-foundation/multipaz)
project is a **conformance oracle only** — see
[CONTRIBUTING.md](CONTRIBUTING.md#provenance) for the rule in full.

Every crate is `publish = false` until its first release.
