# Changelog

All notable changes to this workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the workspace has no
released version yet.

## [Unreleased]

### Added

- The presentation core: `siros-openid4vp`, `siros-x509`, `siros-mdoc`,
  `siros-sdjwt`, `siros-paso`, `siros-qes`, `siros-testkit`, `siros-explain`,
  `siros-explain-derive`, `siros-i18n`, `siros-cldr` and `siros-integration`,
  from the design's reference implementation. Each is edition 2024 and
  unpublished. `siros-mdoc` and `siros-sdjwt` replace the earlier crates of
  those names.
- `siros-mdoc::stored` reads a stored mdoc: its items against the MSO's
  digests, the MSO, `issuerAuth`, and the data the device key signs.
  ISO/IEC 18013-5 Annex D's DeviceResponse is its known answer, and each
  construction rule refuses its fixture.
- `siros-credman` lays out the core's consent entries as Android Credential
  Manager's Standard and Payment entries, and decides each set's delegation:
  `Full` when the set needs no wallet display (A9, K4). `siros-openid4vp`
  composes the consent entry as platform-neutral data (`consent`), its
  transaction header filled by the profile.
- `siros-webuild` holds WE BUILD's CS-02 rules: `Cs02Claims` requires a
  Request Object's `exp` and `aud` (CS-02 §8.2), `Cs02ErrorAnswer` reads the
  Verifier's error answer from the Response URI (CS-02 §8.3).
- `siros-openid4vp`'s extension points, each implemented by the core's own
  cases as peers: response types and response modes (`ResponseType`, `Mode`,
  `ModeHost`; `vp_token` and the modes `dc_api`, `dc_api.jwt`,
  `direct_post.jwt`, `direct_post`), transaction data hash algorithms
  (`HashAlgorithm`; `Sha2`, `Sha3`, `Blake2`, `K12`), scope
  queries (`ScopeQuery`, §5.5), rules on a Request Object's claims
  (`ObjectRule`, A14), the `request_uri` POST and encrypted Request Objects
  (`RequestPost`, `EncryptedRequests`). The registry refuses each conflict:
  a name twice, an error mode over the DC API, a DC API mode declaring
  `wallet_metadata` members, a transaction data profile without `sha-256`, a
  scope query the DCQL reader refuses or whose ids another shares.
- `siros-openid4vp`'s features put each mechanism behind the feature its users
  turn on: `match`, `resolve`, `dc-api`, `uri`, `signed`,
  `request-decryption`, `cbor`, `transaction-data`, `sha3`, `blake2`, `k12`,
  `sri`, `claims` and `test-util`. A build compiles what it registers: an
  SD-JWT DC API build links no CBOR, COSE, form encoding, curve arithmetic or
  hash beyond SHA-2. `siros-paso`'s `sealed-signals` holds its `COSE_Encrypt`
  sealing, `siros-qes`'s `sha3` its SHA-3 approval hashes. A feature changes
  no signature: a crate compiles the same when another turns it on. The
  registry's host fixes what it takes of each plug-in (`Build`): `NoHost` takes
  phase 1's `Format`, `Profile` and `Mode` in every build, and under `resolve`
  a host holding a `Platform` takes plug-ins with their phase 2 over it.
- `cargo xtask builds` checks that each build of the design's section 4.11
  compiles none of the crates its row excludes, and that the SD-JWT and the
  mdoc DC API builds each compile fewer than 96 crates, two different sets; `cargo xtask alone` checks
  each crate alone, with and without its default features, and the workspace
  crates it names. CI runs both.
- `siros-testkit`'s doubles of the extension points: `TestMode`,
  `TestResponseType`, `TestHash`, `TestScope`, `TestObjectRule`,
  `TestPostContribution` and `TestAnswerReader`.
- `siros-paso` classifies the inherence facts the platform reports as Risk
  Signal Registry §2.8's `bio_strong` and `bio_weak` (`BiometricClass`).

### Changed

- `siros-zkp-req`, `siros-zkp-catalogues`, `siros-trust` and `proving/` read
  DCQL, CBOR, JSON, identifiers, sessions and authenticated requests through
  `siros-openid4vp`. `siros-zkp-req` holds its member faults and value macros,
  and refuses an indefinite length through the core's definite reading.
- `siros-zkp-catalogues` reads the semantics identifier from the trust
  service's facts and its stored mdocs through `siros-mdoc::stored`, and holds
  its calendar dates and ES256 signatures. Its session binds the key that
  `siros-openid4vp`'s key rule chooses for the response.
- `siros-trust` takes the core's `Timestamp` and identifiers. Its chain
  reader is part of the crate, without a feature, on the workspace's
  `x509-cert`, `der`, `p256` and `p384`.
- `siros-wallet-state` holds its own errors and timestamp.
- `siros-openid4vp`'s `Presentation` is made by `Presentation::text` or
  `Presentation::object` alone (§8.1). A format states a credential's types
  (`ViewAdditions`), which a profile reads in its `Binding`; `siros-sdjwt`'s
  `vct_values` matches a type the credential's `extends` chain names (B.3.5).
- `siros-openid4vp` composes `wallet_metadata` from what each registered part
  contributes: the formats, the prefixes (`client_id_prefixes_supported`), the
  prefix's verifying module, the URI modes, encrypted Request Objects and each
  `PostContribution`, whose parameters the POST carries beside it. The
  Response URI's answer reads through registered `AnswerReader`s. The registry
  refuses a name two parts declare and one the core writes. `RequestClaims`
  leaves `TrustConfig`: a deployment requiring claims registers an
  `ObjectRule`.
- `ErrorCode` is open: a code in RFC 6749 Appendix A.7's syntax, checked by
  `ErrorCode::new` or `checked!`; a plug-in's rule returns its
  specification's code.
- The host's modules state the algorithms they implement (`Haip::verifies`,
  `Haip::agreements`, `RequestDecryption::decrypts`), and the core accepts
  exactly those: A7 refuses an `alg` the module does not state before the
  caller is asked. `VerificationKey` and `EphemeralKey` are public JWKs, the
  secret behind a `KeyHandle`; the core links no curve arithmetic.
- `CoreHost` is `Platform` alone; each registration that makes the core call
  another module bounds it (`client_prefix` and `jwe_mode`: `Haip`;
  `request_encryption`: `RequestDecryption`). `RandomIds` and `CoseEncrypt`
  are `siros-paso`'s modules.
- The session holds the facts a presentation binds; `siros-mdoc` builds
  B.2.6's handover, the RFC 7638 thumbprint and ISO/IEC 18013-5's
  `SessionTranscript` from them, and decodes a transcript a Verifier holds.
- A format states how its proof carries a profile's members
  (`Format::placement`), and a profile places its members by it
  (`Profile::members(placement)`), naming no format.
- `Profile`'s phase-2 methods (`wanted`, `informed`, `authentication`) are
  `ProfileHost`'s; each plug-in gates its phase 2 on its own `resolve`.
- The core refuses a mode's JWE choice whose key the request does not name
  (`RouteBreach::Foreign`), whose key or `enc` the sealing module does not
  state, or whose `enc` the Verifier does not list (§5.1). `siros-testkit`'s
  `TestChoice::Foreign` chooses a key of other metadata.
- Phase 2 answers with `Built`: the Authorization Response
  (`AuthorizationResponse`, §8.1's object, its parameters beside `vp_token`
  and `state` each a `ResponseMember`) and its `Delivery`, the
  DigitalCredential's `data` (`DcApiData`, a JSON object the core reads back)
  or a `PostBody` POSTed to the `response_uri`. `FormBody::of` writes any flat
  members, each name once (`NotForm`); `PostBody::of` refuses the form media
  type (`FormMedia`), which `MediaType::form` names and `MediaType::is_form`
  finds. An error response (`ErrorResponse`) carries its code,
  its description and `state` as received; `ErrorDescription::sanitized`
  writes a refusal's text with `?` for each character outside RFC 6749
  Appendix A.8.
- A response mode writes the body around an answer (`ModeHost::answer`): the
  core seals the Authorization Response to the route's key through
  `Haip::encrypt_jwe` and hands the mode the `SealedJwe` alone
  (`AnswerContent`, `ModeRoute`), and refuses a body of another channel than
  the request's (`RouteBreach::BodyChannel`). `dc_api` writes the response,
  `dc_api.jwt` `{"response": JWE}`, `direct_post.jwt` `response=<JWE>`
  (`ResponseForm::of`). `siros-testkit`'s `TestMode` writes a body of either
  channel (`TestBody`), and `JweHaip` seals with ECDH-ES.
- A URI response mode writes the form around an error (`ErrorModeHost::error`,
  `ErrorContent`), which `error_mode` registers through `HostedErrorMode`:
  `direct_post` and `direct_post.jwt` write §8.2's plain form (`ErrorForm::of`),
  `direct_post.jwt` `response=<JWE>` for an error the core sealed. A
  rejection's error goes in the clear on its route (`Rejected::reply`): A.4's
  `{"error": code}` over the DC API, or a cancelled flow (`DcApiErrors`,
  `Reply`), and §8.2's plain form by URI.
- Phase 2 answers an authenticated request through its route.
  `Prepared::prepare` takes the `Authenticated` and the ids the End-User
  chose, none when every credential set is optional (§6.4.2), and reads the
  request from the authenticated envelope. `Route::new` binds the authenticated endpoint, the
  registered modes the request names and the key the answering mode chose,
  checked; `Route::answering` gives the `AnswerRoute`, whose `answer` seals,
  has the mode wrap the content and delivers to the bound endpoint, and whose
  `session` holds the binding facts and the `RouteKey`. By URI a request whose
  mode names no registered error mode is `Unroutable`
  (`Outcome::Unroutable`). `Route::refusal`, `Route::unmet` and
  `Route::unavailable` send a refusal, an unmet request under its `UnmetCode`
  and `wallet_unavailable` on the route: A.4's error over the DC API, the
  error mode's body by URI, sealed by the core when the route bound a key.
  `Match::unmet` derives the code from the exclusions' plug-in
  (`ExcludedBy`). The envelope holds `client_metadata` as read
  (`Envelope::client_metadata`), and `Authenticated` the Verifier's keys.
- An extension adds Authorization Response parameters (`ResponseParameters`,
  `ResponseParametersHost`, `HostedResponseParameters`,
  `RegistryBuilder::response_parameters`) under names the registry checks
  (`NamePlace::ResponseParameter`, `CORE_RESPONSE`); phase 2 writes them
  after `vp_token` and `state`. `siros-testkit`'s `TestResponseParameters` is
  the double; its `fixtures::authenticate` and `fixtures::trust_config` give
  a test an authenticated request.
- The consent entry's icon is of any image media type; `siros-credman` draws
  PNG and JPEG and the card's icon otherwise.
- `siros-openid4vp` encodes CBOR deterministically (RFC 8949 §4.2.1), reads
  CBOR with definite lengths alone under a nesting bound, and reads a
  `dcql_query`'s Credential Queries alone (`Query::read_all`).
- `clippy.toml` disallows `BTreeMap` and `BTreeSet`, and `split_off` and
  `split_at` on vectors, strings, slices and `str`. `wmp-core` and
  `engine-conformance` keep their ordered maps under `#[expect]`.
- `scripts/check_panic_sites.py` reads a `const` item's initialiser and an
  inline `const` block as build-time code.
- `engine-adapter-wasm`'s mini host builds its PID's presentation itself: the
  disclosures the match named and the KB-JWT over `iat`, `aud`, `nonce` and
  `sd_hash` (RFC 9901 §4.3), with `base64` for the segments.
- Rust 1.89 is the floor of every crate. The msrv job checks the workspace on
  1.89, then each crate with and without its default features. The workspace
  resolves with resolver 3. Both container images build on Rust 1.99.1, the
  pinned toolchain.

### Removed

- `ResponseData` and `Response`, which `Delivery` and `Built` replace;
  `FormMembers`.
- The `direct_post.cwt` routing and `Modes`; `ResponseMode`, `DcApiMode`,
  `ModeChoice`, `Protection`, `Encryption::choose`, `ResponseKey` and
  `ResponseEnc`, which the registered modes and HAIP's key rule replace;
  `Strength`, which the inherence facts replace; `with_resolve!` and
  `without_resolve!`.
- `siros-codec`, `siros-dcql` and `siros-oid4vp`: `siros-openid4vp` reads
  DCQL, CBOR, JSON and requests, and the crates that read them name it.
  crates.io's `siros-dcql` stays as siros-dc-matcher published it.
- `siros-credential`, `siros-display`, `siros-transaction-data` and
  `siros-presentation`. `docs/wallet-core-design.md`, section 10.3, names the
  crate and milestone that takes each of their capabilities; `zkp_req`
  matching and its phase 2 wait for the `zkp_req` plug-in (Appendix A). The
  generated Unicode tables and `scripts/gen_unicode_tables.py` leave with them.
- `docs/wallet-core-architecture.md`: `docs/wallet-core-design.md` is the
  contract of the presentation core.

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

### Not ported

The Android credential picker and its registration (`siros-picker`,
  `siros-registration`, `siros-picker-testhost`, `android-credman`,
  `siros-dc-matcher-ffi`) remain in siros-dc-matcher, which consumes this core.
