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

- `siros-zkp-req-nym-auth` is renamed to `siros-zkp-catalogues` on import. The
  ZK stack is two crates permanently: `siros-zkp-req` (protocol) and
  `siros-zkp-catalogues` (every rulebook as modules and features). nym_auth is
  the first rulebook in the catalogue crate; further rulebooks, credential
  forms and systems land in it rather than in new crates.
- `engine-adapter-wasm`'s mini host builds its presentations itself and
  depends on none of `siros-codec`, `siros-dcql`, `siros-sdjwt` and
  `siros-mdoc`. The PID's holds the disclosures of the claims paths the
  match named (OpenID4VP §7, resolved as §7.2 processes them) and the KB-JWT
  over `iat`, `aud`, `nonce` and `sd_hash` (RFC 9901 §4.3), with `base64` for
  the segments. The mDL's is the DeviceResponse of the selected items with
  the device signature over the OpenID4VPHandover's session transcript
  (OpenID4VP B.2.6.1); `ciborium` writes its CBOR in the core deterministic
  encoding (RFC 8949 §4.2.1). A PID signing key without an x5c chain leaves
  the host without an mDL. `MiniHost::new` fails when the mDL's issuance
  fails, an x5c that is no array of standard-base64 strings included, and
  when a public key does not serialize.

### Not ported

The Android credential picker and its registration (`siros-picker`,
  `siros-registration`, `siros-picker-testhost`, `android-credman`,
  `siros-dc-matcher-ffi`) remain in siros-dc-matcher, which consumes this core.
