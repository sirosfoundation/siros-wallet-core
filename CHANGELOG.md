# Changelog

All notable changes to this workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Changed

- Rust 1.89 is the floor of every crate. The msrv job checks the workspace on
  1.89, then each crate with and without its default features. The workspace
  resolves with resolver 3. The test image builds on Rust 1.99.1, the pinned
  toolchain.
- `engine-adapter-sdk` links UniFFI and tokio in every build; the
  `tokio-runtime` feature and the default features leave.

## [0.1.2] — 2026-11-06

The first release whose run completed: the 0.1.0 and 0.1.1 tags' runs
failed at their packaging jobs (the AAR action's v4 line, then the
image job's action pins - both fixed on main by then) and produced no
GitHub releases. This cut carries the fixes and the complete artifact
set: the
AAR, the XCFramework, the bindings, and the engine server's container
image (ghcr.io/sirosfoundation/engine-server, this release's new
publish).

### Added (since the 0.1.0 cut)

- The engine server's container image: built by the release workflow
  on tags (ghcr, the version tag + latest) and verified on every push
  by CI - a static musl binary on distroless, built with the pinned
  toolchain (rust-toolchain.toml, the single source of truth).
- The engine server's environment configuration
  (`Config::from_env`): the `ENGINE_*` variables over the defaults -
  the container platform's deployment shape (the compose file, the
  chart), beside the `ENGINE_CONFIG`-named JSON file. Includes the AS
  trust knobs the dev stacks need: `ENGINE_AS_JWKS_URL` (the Go
  backend's own AS publishes under `/auth/.well-known/`),
  `ENGINE_AS_ISSUER` (its configured issuer) and
  `ENGINE_AS_AUDIENCES` (set-but-empty accepts every audience).
- CI: the AAR/XCFramework recipes verified on every push (was:
  release-time only), the engine image build with its health probe
  asserted.

## [0.1.0] — 2026-11-05

The first release: the wallet core (presentation side, imported
unchanged) and the WMP engine — `siros-wallet-core` as the primary WMP
engine across the deployment models (wasm, cloud, native), the
drop-in replacement of `go-wallet-backend --mode=engine` and the
legacy WebSocket protocol (the plan and its record:
`docs/engine-parity.md`).

### Added

- Initial import of the wallet core, presentation side, ported unchanged from
  the siros-dc-matcher workspace (pull requests
  [#54](https://github.com/sirosfoundation/siros-dc-matcher/pull/54) and
  [#55](https://github.com/sirosfoundation/siros-dc-matcher/pull/55), closed
  2026-11-01 for placement, not content): `siros-codec`, `siros-credential`,
  `siros-dcql`, `siros-display`, `siros-mdoc`, `siros-oid4vp`,
  `siros-presentation`, `siros-sdjwt`, `siros-transaction-data`, `siros-trust`,
  `siros-wallet-state`, `siros-zkp-req`, `siros-zkp-catalogues`, with the
  architecture contract and the `zkp_req` specifications under `docs/`.
- The WMP engine core, on the go-wmp v0.13.0 mechanics:
  - `wmp-core`: the peer (dispatch, sessions, sub-flow routing), the session
    service (single-use rotating tokens, owner binding, capability
    negotiation), the typed JSON-RPC error codes, `wmp.resolve` (the vctm
    lookup), typed protocol version negotiation.
  - `engine-ports`: the port traits — the engine core's only interface with
    the world (`Host`, `HttpClient`, `Clock`, `Rng`, `Pdp`, `KeyValue`,
    `Telemetry`) — including the verifier attestation, client-held DPoP and
    credential-selection asks, the DID resolution and the eval context of
    the trust port, and the issuer entitlement (ARF 6.6.2.3) with its
    bounded wire shapes.
  - `engine-core`: the flow runtime (the capability gate) and the OpenID4
    flow family — OpenID4VCI (both grants, PKCE, PAR + the RFC 7523
    assertion, tx_code, deferred, §10/§11 notifications, DPoP, response
    encryption, the credential selection, the issuer entitlement check)
    and OpenID4VP (request parsing with the per-scheme rules — the signed
    + x5c form of `x509_san_dns`, the constant-time `x509_hash` binding,
    the `verifier_attestation` extraction and `cnf.jwk` verification —
    the four response modes, JARM, the DCQL assembly, the consent vetting
    with its modes, the sign-stage refusals) — plus the
    `credential_notification` flow over its single-use, TTL-bounded
    notification context store (WMP OpenID4x 3.4).
  - The adapters: `engine-adapter-server` (the drop-in engine server: the
    HTTP+SSE WMP binding with the outbox and `Last-Event-ID` replay, the
    host bridge — the engine's asks as child flows — the TAC principal and
    the lifecycle gate, the backend proxy PDP), `engine-adapter-wasm` (the
    in-page dispatcher for the browser wallet), `engine-adapter-sdk` (the
    UniFFI bindings for Kotlin and Swift: `createEngine` over the full
    ports, the `WmpEngine` transport handle), and `engine-conformance`
    (the OIDF-suite runner).
  - The mobile packaging: the AAR (the native `.so` per ABI, the empty
    classes.jar — the Kotlin bindings are vendored source) and the
    XCFramework (the iOS device + simulator static slices), published per
    tag as the Maven coordinate `org.siros:siros-wallet-core` (GitHub
    Packages) and as release assets; the packaging recipes verified on
    every push by CI.

### Changed

- `siros-zkp-req-nym-auth` is renamed to `siros-zkp-catalogues` on import. The
  ZK stack is two crates permanently: `siros-zkp-req` (protocol) and
  `siros-zkp-catalogues` (every rulebook as modules and features). nym_auth is
  the first rulebook in the catalogue crate; further rulebooks, credential
  forms and systems land in it rather than in new crates.

### Not ported

The Android credential picker and its registration (`siros-picker`,
  `siros-registration`, `siros-picker-testhost`, `android-credman`,
  `siros-dc-matcher-ffi`) remain in siros-dc-matcher, which consumes this core.
