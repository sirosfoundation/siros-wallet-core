# Changelog

All notable changes to this workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the workspace has no
released version yet.

## [0.1.0] — unreleased

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
- Stub crates for the planned WMP engine core (`wmp-core`, `engine-ports`,
  `engine-core`, `engine-adapter-sdk`, `engine-adapter-server`,
  `engine-conformance`) and the engine specification under
  `docs/engine-spec.md`. The spike is gated on the PR 163 rework landing on
  go-wallet-backend `main`.

### Changed

- Rust 1.89 is the floor of every crate. The msrv job checks the workspace on
  1.89, then each crate with and without its default features. The workspace
  resolves with resolver 3. Both container images build on Rust 1.99.1, the
  pinned toolchain. The production image runs on
  `gcr.io/distroless/static-debian12`.
- `engine-adapter-sdk` links UniFFI and tokio in every build; the
  `tokio-runtime` feature and the default features leave.
- `siros-zkp-req-nym-auth` is renamed to `siros-zkp-catalogues` on import. The
  ZK stack is two crates permanently: `siros-zkp-req` (protocol) and
  `siros-zkp-catalogues` (every rulebook as modules and features). nym_auth is
  the first rulebook in the catalogue crate; further rulebooks, credential
  forms and systems land in it rather than in new crates.

### Not ported

The Android credential picker and its registration (`siros-picker`,
  `siros-registration`, `siros-picker-testhost`, `android-credman`,
  `siros-dc-matcher-ffi`) remain in siros-dc-matcher, which consumes this core.
