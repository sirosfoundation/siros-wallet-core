# siros-wallet-core

The Rust wallet core of SIROS: one workspace for what a wallet computes, on
both sides of the WMP engine seam.

**The presentation core** — ported here from
[siros-dc-matcher #54](https://github.com/sirosfoundation/siros-dc-matcher/pull/54) and
[#55](https://github.com/sirosfoundation/siros-dc-matcher/pull/55), where it was
built in the wrong repository and closed unmerged — answers OpenID4VP 1.0
presentation requests and the W3C Digital Credentials API, from request intake
to the response: DCQL, SD-JWT VC and ISO mdoc, issuer trust, display,
transaction data on the PaSO model, `zkp_req` — extensions to DCQL that let a
verifier state a zero-knowledge request and a wallet answer it; the first
capability defined on it is nym_auth, a normal credential that happens to
carry the capability of doing pseudonyms — and the presentation component
that plans a consent view and turns the user's selection into the response.
Its contract is
[`docs/wallet-core-architecture.md`](docs/wallet-core-architecture.md).

**The WMP engine core** — planned, stubs only for now — implements OpenID4VCI
issuance and OpenID4VP presentation behind the Wallet Messaging Protocol, in one
core with two adapters: in-process in the native SDKs (UniFFI) and as a
standalone container suitable for a TEE. Its specification is
[`docs/engine-spec.md`](docs/engine-spec.md), with the phase and spike plan in
[`docs/implementation-plan.md`](docs/implementation-plan.md); the spike (S0)
starts when the PR 163 rework lands on go-wallet-backend `main`.

The Android credential picker (`matcher.wasm`, `siros-registration`,
`android-credman`) and the Kotlin/Swift bindings of the matcher stay in
[siros-dc-matcher](https://github.com/sirosfoundation/siros-dc-matcher); they
consume this core from there.

## Crates

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
| `siros-zkp-req-nym-auth` | The nym_auth capability: a normal credential (an mdoc, stored in the wallet state and consented like any other) that happens to carry the capability of doing pseudonyms. Its rulebook defines the functions (`pseudonym`, `age_check`) and the Longfellow and Vega systems that prove them — session binding, credential tests, the prover interface, the verifier. Further capabilities arrive as new crates, not as protocol changes |
| `siros-presentation` | The plan of a request over the wallet's credentials, the consent view, the selection, the response |
| `wmp-core`, `engine-ports`, `engine-core`, `engine-adapter-sdk`, `engine-adapter-server`, `engine-conformance` | The WMP engine core (stubs; see the specification) |

`proving/` is a second workspace — the `zkp_req` proof backends
(`siros-zkp-backend-longfellow`, `siros-zkp-backend-vega`) and the browser
presenter (`siros-zkp-req-wasm`) — with its own 1.95 floor; see
[CONTRIBUTING.md](CONTRIBUTING.md#development).

`siros-dcql` is on [crates.io](https://crates.io/crates/siros-dcql); the other
crates are `publish = false` until their first release.

## Build and test

Rust, pinned exactly in `rust-toolchain.toml` (rustup installs it on first use):

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/check_panic_sites.py Cargo.toml
```

Nothing panics outside the tests: a type makes the impossible state
unrepresentable, or the caller receives an error. CI holds each crate to it
with clippy and `scripts/check_panic_sites.py`.

## Provenance

The presentation crates are an independent implementation. The
[OpenWallet Foundation's Multipaz](https://github.com/openwallet-foundation/multipaz)
project is a **conformance oracle only** — see
[CONTRIBUTING.md](CONTRIBUTING.md#provenance) for the rule in full.

The port's history: the crates were written and reviewed as part of the
dc-matcher workspace (PRs #54/#55, closed for placement, not content) and move
here unchanged; the picker crates that remain in dc-matcher consume them.
