# Changelog

All notable changes to this workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.7.1] — 2026-11-28

### Added

- **The §14.2 Response Code relay (#138, issue #136)**: the verifier's v0.3.0 answers a done `direct_post` with `{"redirect_uri": "<verifier>/vp/complete?response_code=<one-time code>"}` — the flow's completion notification (`wmp.flow.complete`, the outgoing wire the wallet consumes) now carries **`redirect_uri`** and **`response_code`** beside `presented`/`credential_ids`: the cross-device material the wallet UX surfaces when it cannot reach the starting browser (the code shown to the user, the completion URL rendered as a QR). The same-device relay keeps riding the `open_authorization` ask. Both members additive — old wallets parse unchanged, bound flows stay fail-closed. The SDK-side relay (custom tab / QR) rides the SDK version line that pins verifier-core v0.3.0.

## [0.7.0] — 2026-11-27

### Changed

- **The jose-rs re-pin to upstream 0.13.1 — the fork ride retired (#130)**: kushaldas/jose-rs#33 (merged as `cf9e7e81`) raised `MAX_TOKEN_BYTES` 1 MiB → 4 MiB and **v0.13.1 is published on crates.io**; the workspace pins move `0.10` → `0.13.1` across every crate and the `[patch.crates-io]` section is removed — the removal condition 0.6.2's entry named, met the same day. One test-only API change rides along: `Claims.extra` moved `HashMap` → `BTreeMap`.

### Added

- **The signed well-known + the `participant_id` (#132, #100 gaps 1–2)**: `Accept: application/jwt` answers the WMP well-known as a compact JWS — the same document, the participant chain in the `x5c` header (RFC 7515 §4.1.6: standard-alphabet base64 DER, not base64url), the signature under the chain's leaf, self-verified before serving (CS-15 §7.2: the configuration as **attestation**, the eDelivery profile's trust model — verifiable without the TLS session). Unconfigured answers `406`; a broken pair answers `500`. `participant_id` joins the document (CS-15 §7.2's MUST, the `x509:san:dns:…` form), from `ENGINE_PARTICIPANT_ID`.
- **The participant credential port — the PKCS#11 home (#133)**: the certs&keys behind `ParticipantCredential` (chain + JOSE alg + `sign_compact`) — two homes shipped: the config's PEM pair, and a PKCS#11 token (the off-by-default `pkcs11` feature: kryptering's `Pkcs11Signer` through jose-rs's own `&dyn Signer` seam — the key never leaves the token, CS-15 §8.4's WSCA/QSCD). Both probe at construction (the key signs, the leaf must verify — a broken pair fails at the start line); `EngineServer::with_participant_credential` is the injection point for other homes. Knobs: `ENGINE_PKCS11_MODULE` (set = the token wins), `ENGINE_PKCS11_SLOT`, `ENGINE_PKCS11_PIN`, `ENGINE_PKCS11_KEY_LABEL`, `ENGINE_PKCS11_ALG`.

### Fixed

- **The x509 SAN binding (#129)**: the `x509_san_dns`/`x509_san_uri` arms verified the request object's signature under the `x5c` leaf's key but never compared the client_id's **value** against the certificate's own SAN entries — any signed request could claim a SAN name the certificate never carried. The arms now parse the leaf (x509-cert) and refuse with `ClientIdSanDnsMismatch`/`ClientIdSanUriMismatch` on a mismatch; an absent SAN extension binds none.
- **The wmp-mls Welcome hardening (#134, issue #127)**: `process_welcome_for_group` refuses — committing **nothing**, both ids named — when the Welcome's MLS GroupId is not the declared one (the GroupInfo is encrypted, so the check belongs inside the provider); `stage_welcome`/`commit_staged` hold the join between the caller's checks and the commit. `generate_key_package` carries the **configured signer** and the `credential()` path (the X.509 chain when configured, basic otherwise) — RFC 9420 §5.3.1 end to end — and a suite whose signature algorithm the signer does not serve refuses loudly, never a fresh per-suite key beside the identity.
- **The jose fork pin's reachability (#126)**: 0.6.2's fork pin (rev `5e8ada5`) was orphaned when the test-fix amend moved the `cap-4m-0.10` tip to `a21303e`; the pin named the reachable tip from here on. *(0.6.2's tagged tree predates this fix — see the note under [0.6.2].)*
- **The zkp-req formats reader (96d441f)**: accepts the deployed chain's `proof_system_values` beside the rulebook's `proof_backend_values` — the draft-era spelling the deployed verifier's config schema names.

> **The [0.6.2] correction**: the 0.6.2 release was cut 19 minutes before the fork pin's reachability fix (#126) and one day before the upstream re-pin (#130) — its tagged tree and its release artifacts bundle the orphaned fork-pin state the workspace no longer carries. Superseded by 0.7.0; the tag and its artifacts are left as cut (nothing reached Maven Central from it). Its behavioural claims stand: tokens under 1 MiB behave byte-identically, and the 4 MiB cap holds in both the fork and the upstream pin.

## [0.6.2] — 2026-11-26

### Changed

- **The workspace rides our jose-rs fork — the 1 MiB emit cap lifted to 4 MiB (#125)**: jose-rs 0.10's `MAX_TOKEN_BYTES` refused the ~1.1 MiB JARM JWE the wasm engine emits for zkp presentations (the Longfellow proof alone is ~620 KiB) — at the last inch, after the proof builds and the token assembles. The `[patch.crates-io]` section points at `sirosfoundation/jose-rs` (the `cap-4m-0.10` line): the one-constant raise, the same patch the realeyes demo proved live. The raise rides upstream as kushaldas/jose-rs#33 (the fork's `raise-max-token-bytes` branch); the section is removed when upstream ships it and the workspace re-pins. Tokens under 1 MiB behave byte-identically.

> **Corrected in 0.7.0**: this release was cut 19 minutes before the fork pin's reachability fix (#126) and one day before the upstream re-pin retired the fork (#130) — the tagged tree and its release artifacts bundle the orphaned pin state the workspace no longer carries. Superseded by 0.7.0; the tag and its artifacts are left as cut (nothing reached Maven Central from it).

## [0.6.1] — 2026-11-26

### Fixed

- **The wasm peer's message cap fits the JARM (#122)**: the Longfellow zkp proofs are ~620KB, the JWE-wrapped presentation ~1.1MB — the wmp-core default 1MB peer cap refused the JARM at the last inch (the flow reached `submitting_response` and the peer dropped it). The wasm engine's peer is an in-process boundary; the dispatcher raises the cap to 4MB.
- **The wasm presenter's assemble writes the rulebook's `ZkpPresentation` (#122)**: the nym_auth rulebook v0.4's shape (flat — `system_id`, the raw `proof` bytes, `issuer_key_set`, `? proof_time`, `results`; no `proof_backend`, no envelope) is what the deployed verifier's parser and the native SDK presenters speak. The draft-0.1 envelope the assemble used to emit carried `proof_backend` — the unknown member the verifier refused (the demo's `presentation_unknown_member`). The prover still produces the envelope internally; the boundary promotes its `inputs` to the rulebook's top level. Live-proven: the verifier accepted the assembled presentation.

## [0.6.0] — 2026-11-26

### Added

- **`export_group_info` on the `WmpMls` FFI surface (#118, issue #108)**: the wallet-driven group create can now mint spec §3.1's `group_info` param — the pass-through follows the surface's own pattern, and the regenerated Kotlin/Swift bindings carry `exportGroupInfo`.
- **The Valkey-backed session and invitation stores (#113, issue #109)**: `ValkeySessionStore` (JSON values, the session's own expiry as the TTL, `SCAN` not `KEYS`) and `ValkeyInvitationStore` (single-use via `GETDEL`), behind the `valkey` feature, wired by `EngineServer::with_stores()`.

### Fixed

- **The wasm host asks cross as plain objects (#121)**: every JS crossing in `engine-adapter-wasm` serializes maps as plain objects (`serialize_maps_as_objects`), never `Map` — a JS host reading `params.dcql_query.credentials` saw `undefined` and `JSON.stringify(Map)` answered `{}` (found live in the realeyes demo: every raw-JSON member of the match ask read as empty).
- **The engine advertises and accepts the security modes it serves (#116, issue #110)**: `tls` always, `mls` iff the build carries the MLS handler — one list (`handler::security_modes`), the well-known and the session create both reading it, so a wallet that offers an advertised mode never meets a `-31002`.
- **The tools gate answers the session's own semantics (#117, issue #104)**: a `tools/*` call naming a lost session answers `-31000` (not the misleading `-31005` that bricked wallets until a hard restart), an expired record answers `-31001`.
- **The mini-wallet host-UX contract (#120)**: the library ships no renderer — `modal.ts` moved to the example, `AdoptModal` is the contract in `types.ts`; the store put is awaited, the flow-start answer is bounded, the fresh-key ask is get-or-create per flow, `dispose()` exists.
- **The zkp presenter seam (#119)**: `mini-wallet` answers the engine's `vp` ask over the browser proving wasm — the Handover CBOR pinned against the catalogues' vectors, the verifier id strictly the engine-verified `client_id`.

## [0.5.0] — 2026-11-26

### Changed

- **openmls 0.10 (issue #115)**: wmp-mls upgrades openmls 0.8.3 → 0.10.0-rc.1, openmls_rust_crypto 0.5.1 → 0.7.0-rc.1 (hpke 0.8, hpke-rs-libcrux 0.8.1, libcrux ≥0.0.10), openmls_basic_credential and openmls_traits → 0.7.0-rc.1. **All eight RUSTSEC advisories lifted** (2026-0124/0330/0331/0207/0208/0209/0211/0212); cargo audit: 11 → 3 vulnerabilities (the 3 remaining are pre-existing and unrelated).

### Fixed

- **`create_group` never passed the caller's `cipher_suite` to the builder** (`let _ = suite;`) — every group was silently minted on the default 0x0001, and a 0x0002 member's add failed valn0201. The spec's `cipher_suite` param now governs the group (a pre-existing latent bug surfaced by the 0.10 upgrade's Capabilities Reject policy).
- **`Capabilities::new` Reject policy** (the 0.10 semantic break): an unset ciphersuite list is now *empty* and every group create refused its own group. Fixed by advertising both wire suites (0x0001, 0x0002) explicitly, and the KeyPackage leaf also advertises both credential types (a package must be addable to a group holding an X.509 member).

### Added

- **The signer-accepting constructor** (`for_identity_with_certificate_and_key`): reads the leaf's PKCS#8 key, derives the signer type from the key's own OID (Ed25519 RFC 8410 / P-256 RFC 5915), falls back to the fresh-Ed25519 behaviour on `None`, and fails closed (-31004) on any other algorithm. The X.509 credential's signature key now matches the certificate's key (RFC 9420 §5.3.1's key binding) — the coherence the siros-verifier-core WMP surface was waiting on.

### MSRV

- **The workspace floor raised 1.89 → 1.94** — the openmls 0.10 line declares 1.94. The `msrv` CI job installs 1.94 with this release.

## [0.4.2] — 2026-11-25

### Fixed
- **The certificate length in the X.509 credential uses the MLS varint encoding** ([Jochen's analysis from the interop]):
  the certificate data used a uint16 length prefix (`03 36` for 822 bytes) where RFC 9420 §5.3 expects the MLS varint
  (`43 36`). Echo's ts-mls stopped with "Data length exceeds buffer" on the uint16 form — the basic-credential runs
  joined fine, so it was specific to the X.509 path.

## [0.4.3] — 2026-11-25

### Added
- **The DPoP per-request proof** (wmp-core §4.4.8): the DPoP model (RFC 9449) for HTTPS sessions that cannot carry
  the client's credential at TLS. The proof is a compact JWS with `x5c`/`kid` in the header, payload
  `{htm, htu, iat, jti, sid}` (the session binding), sent as `Authorization: DPoP <proof-jws>`. The transport
  verifies the proof and stamps the principal from the certificate's subject. Deployments terminating TLS without
  forwarding the client certificate accept DPoP-authenticated requests.

## [0.4.4] — 2026-11-25

### Fixed
- **DPoP `sid` on session.create** (wmp PR #46): the proof payload omits `sid` for `session.create` messages and
  requires an exact session-id match on every other request. `for_session_create` builds the omitted-sid payload;
  the transport enforces the same rule and identifies `wmp.session.create` from the JSON-RPC body.

## [Unreleased]

## [0.4.1] — 2026-11-25

### Added
- **The invitation bootstrap auth** (wmp-invitation §5.2, #112): when a `wmp.session.create` carries a valid
  `invitation_nonce` and the caller is unauthenticated, the engine stamps a synthetic principal — the invitation IS
  the identity for the join. The engine stays in strict mode; the bootstrap is the only relaxation.
- **The file-backed session and invitation stores** (#109, #112): `ENGINE_PERSISTENCE_PATH` wires `FileSessionStore`
  and `FileInvitationStore` — sessions and invitations survive restarts. Empty path = the memory stores (the default).
- **`EngineServer::with_stores()`** (#112): the pluggable injection point — deployments bring their own
  `SessionStore` + `InvitationStore` (the Android SDK's Room, the iOS SDK's Core Data, a Go backend's database).
- **The X.509 MLS credential** (#112): `OpenMlsProvider::for_identity_with_certificate()` carries the subscriber
  certificate chain — the MLS credential is X.509 for certificate-backed schemes (wmp-mls §2.3), the BasicCredential
  otherwise. Found live at the Cleverbase interop: Echo's MLS refused to decrypt our first message because our
  member carried a BasicCredential while the scheme called for X.509.

## [0.4.0] — 2026-11-24

### Fixed
- **The group's advertised credentials + the GroupInfo export** ([#107](https://github.com/sirosfoundation/siros-wallet-core/pull/107), found live at the Cleverbase interop):
  the provider's `create_group` never advertised the accepted credential types (wmp-mls spec §2.3's MUST; RFC 9420 valn0104) — adding a peer whose KeyPackage carries an X.509 credential refused with "Credentials are not acceptable". The builder now advertises both `x509` and `basic`. `MlsProvider` gained `export_group_info` (spec §3.1's create param — the peer's validator demanded it live).

## Unreleased

### Added

- `siros-explain` is the error contract: `Explain` gives an error's stable id,
  `err.<scope>.<id>`, and each named argument by its key: the field, which a
  reader takes by its type or by its `Display`.
  `#[derive(Explain)]` (`siros-explain-derive`) sits beside thiserror's derive:
  each struct or variant carries `#[explain(id = "…")]` or
  `#[error(transparent)]`, a named field is an argument, a cause is `#[source]`
  or `#[explain(skip)]`, a tuple argument and a field spelled `r#source` are
  refused, and an id given twice in a crate fails the build. `scope!` names a
  crate's scope once, at its root. Under `check`, each derived id registers a
  row that `check::rows` reads.
- `siros-derive-internals`: the field rules `#[derive(Explain)]` and
  `#[derive(Message)]` share, which siros-explain-derive and siros-i18n-derive
  call through its `Derive` trait.
- `siros-syntax` holds the checked texts and values: `checked!`, `Keyed` with
  `Entry` and `Repeated`, the non-empty `AllOf`, and `Count`, `Decimal`,
  `Amount`, `Currency` with ISO 4217 List One (SIX's `list-one.xml`, published
  2026-09-17, vendored and read by the build script), `Date`, `Time`,
  `OffsetTime`, `Offset` and `DateTime`. Each value type writes its literal form
  as `Display` and parses exactly that form, refusing any other text with
  `Malformed`. `Digits`, one or more ASCII digits as written, give their count
  through `Count::from`. Its errors derive `Explain`.
- `siros-i18n` resolves the wallet's texts. A `Context` holds the
  MessageFormat 2 sources of one locale, each loaded whole and checked
  (`LoadError`); `Context::resolve` makes a `Text`, styled spans, from an error
  or a statement (`ResolveError`), and no other code makes one. A statement
  derives `Message` (`siros-i18n-derive`). Every argument is typed: the
  context's `Formatters` give each type the functions a call may name on it and
  at most one default, which a placeholder, a declaration and a selector that
  name no function take (`ResolveError::Unformatted`, `ResolveError::Selector`,
  `RegisterError`). Every type takes `:string`, which writes its `Display` as
  given, by default where it registers no other. The functions read the
  argument's text: `:number` and `:integer` parse an MF2 number literal and
  show its fraction digits as written; `:currency` (its `currency` option
  literal or variable), `:siros:date`, `:siros:time` and `:siros:datetime`
  parse their operand. An option's value is a literal or a variable's value: an
  argument's text, a literal, or the value of a declared call. The load refuses
  an option of the `u:` namespace. Names, variant keys and selector literals
  compare as written. A load takes memory in proportion to its source, and time
  in proportion to its source and, for each use of a call, to the calls its
  operand's value applies. Each function sits behind its feature: `number`,
  `currency` and `date`, the defaults with `derive`. `check` holds
  `Context::check`. `escape` writes a resource value that resolves to a given
  text, and `Context::bidi` takes the app's bidi strategy. ICU4X 2.4 over CLDR
  49.0.0 is its oracle.
- siros-i18n's `check` feature is the wallet's one completeness test: each
  derive registers its id and argument names, and `Context::check` refuses an
  id two crates share, an id no source words, a message that names an
  argument its row lacks, and a formatter whose options no module defines.
- `siros-i18n-derive`: `#[derive(Message)]` on a statement, its id under the
  crate's scope and its named fields as arguments. A repeated id fails the
  build; under `check` each id registers a row for `Context::check`.
- `siros-cldr` writes a language's format options from CLDR's JSON release
  49.0.0 as MF2 source: a resource head and `[formats.<format>]` sections.
- Each is edition 2024 and unpublished.
- CI's per-merge job runs siros-i18n's ignored tests on a push to `main`.
- The architecture contract's messages component (§4.19, layer L0): an error
  is a stable id and named arguments, a statement a `Message` of the same
  shape, and the wallet words both in MessageFormat 2 sources that a `Context`
  loads and resolves into `Text`; the UI lays out the result (D4, §4.17).

### Changed

- Rust 1.89 is the floor of every crate. The msrv job checks the workspace on
  1.89, then each crate with and without its default features. The workspace
  resolves with resolver 3. The test image builds on Rust 1.99.1, the pinned
  toolchain.
- `engine-adapter-sdk` links UniFFI and tokio in every build; the
  `tokio-runtime` feature and the default features leave.

## [0.3.9] — 2026-11-24

### Fixed
- **An authorization answer routes to the flow its state names** ([#106](https://github.com/sirosfoundation/siros-wallet-core/pull/106), closes
  [#105](https://github.com/sirosfoundation/siros-wallet-core/issues/105)): the EBW-OID issuance with PID authentication died at the credential
  step (`flow.action failed: Method not found`) — the apigw's openid4vp login is its own flow here, and the oid4vp family refuses every action
  with -32601, while the Go engine ran the login and the issuance as one flow so its `resumeWithAuthCode` always landed on the stash's owner.
  The handoff now writes a `state → flow` index beside the stash (same 600s TTL), and the runtime routes an `authorization_complete` whose
  state names a live owner to that owner — the CSRF check, the token exchange and the whole issuance tail run where the stash lives, the Go
  topology restored for the resume. Found live at the Cleverbase interop (the Pixel, twice reproduced); an answer whose state names no stash
  keeps its own family's answer, the oid4vp -32601 included.

## [0.3.8] — 2026-11-24

### Added
- **The invitation signing key publishes** ([#101](https://github.com/sirosfoundation/siros-wallet-core/pull/101)):
  `GET /wmp/jwks` serves the JWKS (RFC 7517 — each JWK carrying its `kid`, the thumbprint the invitation
  JWS's `kid` names), and the well-known document embeds the same set as `invitation_jwks` and names the
  `jwks` endpoint. The kid-resolution path wmp-core §12.2 REQUIRES — an external verifier resolving a minted
  invitation's JWS `kid` had no path before (found live at the Cleverbase interop: the key signed, nothing
  published it). The key stays ephemeral per-boot, self-signed (the operational trust plane; the test CA is
  the mTLS/SMP layer).
- **Multi-tenant well-known discovery** ([#99](https://github.com/sirosfoundation/siros-wallet-core/pull/99)):
  the `DiscoveryBase` (host + tenant path), the `discovery_base` document field and its validation, the
  `BaseMismatch` refusal — wmp PR #41's client half.

### Fixed
- **The bindgen's LIBRARY builds with mls** ([#98](https://github.com/sirosfoundation/siros-wallet-core/pull/98)):
  the `--features mls` rode the bindgen binary's cargo run, not the library file it reads — the released
  bindings.zip shipped without the MLS surface (and the v0.3.7 XCFramework's **headers** came from the same
  MLS-less bindgen: binary with the symbols, headers without the declarations — the Swift iOS compile
  error's true cause). One release, one surface: **AAR ✓ binary ✓ XCFramework binary ✓ XCFramework headers ✓
  bindings ✓**.

## [0.3.7] — 2026-11-24

### Fixed
- **The artifacts are feature-symmetric** ([#96](https://github.com/sirosfoundation/siros-wallet-core/pull/96)): the
  `android-%` recipe built with `--features mls` while the iOS targets and both bindgen recipes built without — the
  v0.3.6 release shipped an AAR with 24 `wmpmls` symbols and an XCFramework with **zero** (measured), and its
  `bindings.zip` carried no MLS surface. The iOS targets and both bindgens now carry `mls`: one release, one surface
  across AAR / XCFramework / bindings. This is the release the Swift SDK's MLS line needs (the vendored MLS bindings
  link against the XCFramework's iOS slices at last).

## [0.3.6] — 2026-11-24

### Added
- **The group's name rides the signed invitation** ([#94](https://github.com/sirosfoundation/siros-wallet-core/pull/94)):
  `POST /wmp/invitation` accepts `group_name` (the front's label — wmp-mcp's two-random-words
  name or the operator's rename) and embeds it into the invitation's `label`, **inside the ES256
  signing payload** (set before `key.sign()`), so consumers render the name without trusting an
  unsigned field. 40-char cap; absent/empty leaves it unset and consumers fall back to the group's
  session id. The e2e (`group_e2e`) asserts the label on the minted join invitation.

*The engine image (`ghcr.io/sirosfoundation/engine-server:v0.3.6`) carries this + the full MLS
feature line since v0.3.5 (the FFI surface, the GroupId contract, the commit merge).*

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
