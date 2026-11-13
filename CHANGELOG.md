# Changelog

All notable changes to this workspace. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
  show its fraction digits as written; `:offset`, `:currency` (its `currency`
  option literal or variable), `:percent`, `:siros:date`, `:siros:time` and
  `:siros:datetime` parse their operand. An option's value is a literal or a
  variable's value: an argument's text, a literal, or the value of a declared
  call. `u:dir` takes `ltr`, `rtl`, `auto` or `inherit`; another value from a
  variable refuses the resolution (`ResolveError::Option`). A load takes
  memory in proportion to its source, and time in proportion to its source and,
  for each use of a call, to the calls its operand's value applies. Each
  function sits behind its feature: `number`, `currency`, `offset` and `date`,
  the defaults with `derive` and `nfc`. `nfc` holds names,
  variant keys and selector literals in NFC, as MF2 compares them, and adds
  `Context::module_in_nfc`, which refuses a source NFC would change
  (`LoadError::Unnormalized`); without it they stay as written. `check` holds
  `Context::check`, and `conformance` MF2's test functions for siros-i18n's
  conformance tests. `escape` writes a resource value that resolves to a given
  text, and `Context::bidi` takes the app's bidi strategy. The
  message-format-wg test suite and ICU4X 2.4 over CLDR 49.0.0 are its oracles.
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
