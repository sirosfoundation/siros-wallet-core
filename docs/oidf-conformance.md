# The OIDF conformance plan: the raw engine against the certification suite

**Status: Phase 2 green (2026-11-04).** Both halves pass through the
mini-wallet:

**Phase 1 — the OID4VCI wallet plan** (both variants: `sd_jwt_vc /
pre_authorization_code`, immediate and deferred; DPoP sender-constrain;
private_key_jwt client auth):

- `oid4vci-1_0-wallet-test-credential-issuance` — PASSED
- `oid4vci-1_0-wallet-test-credential-issuance-notification` — PASSED
- `oid4vci-1_0-wallet-happy-path-with-scopes-without-authorization-details-in-token-response` — PASSED
- `oid4vci-1_0-wallet-test-batch-credential-issuance` — SKIPPED by the
  suite (not exercised by the agreed variant)

**Phase 2 — the OID4VP wallet plan** (`sd_jwt_vc / x509_san_dns /
request_uri_signed / plain_vp`, both `direct_post` and
`direct_post.jwt`): every applicable module PASSED, the eight negative
modules REVIEW (the wallet refuses each invalid request for the right
reason; the suite's placeholder evidence uploads through its API), the
`request_uri` POST method SKIPPED by the suite.

`make test-mini-wallet` and `make test-mini-wallet-vp` in
siros-conformance run them end to end. The 1.0 wire shapes the suites
demanded are pinned by tests and vectors: the
`proofs: {"jwt": [...]}` credential request, the proof header's public
JWK with the RFC 7638 thumbprint kid (exactly one of jwk/kid/x5c),
the DPoP nonce retries on the token, credential, nonce, deferred and
notification endpoints (RFC 9449 §8.1), the RFC 7523 assertion
(single-use jti, one per request — on the pre-authorized and the
authorization-code exchanges alike), the RFC 8414 well-known path
without the trailing slash, and the `notification_id` echo (OID4VCI
1.0 §11); on the presentation side the DCQL required/credential_set
rule (§6.4.2) and the JARM response body (§8.3, no iss/exp/aud; cty
json).

**Remaining:** the haip profile (the x509_hash client_id scheme, the
dc_api browser variants) and the iso_mdl format (the mdoc presentation
path in the mini host). Both runs are published on the Pages site under
`runs/mini-wallet-phase1-2026-11-04` and
`runs/mini-wallet-vp-phase2-2026-11-04`.

## The goal

The [OpenID Foundation certification suites](https://www.certification.openid.net/)
are the objective evidence that the new engine is good — the same plans
that gate the deployed wallet stack, green against the raw Rust core.
That is the Phase B milestone the engine-vectors repository pegs its
go-observed hard sunset to ("the agreed OIDF plans green against the
Rust core"), and the run's results become the `oidf`-provenance vectors
the schema was designed for.

## The harness that already exists

`siros-conformance` runs the suites today against
`wallet-frontend + go-wallet-backend` with Playwright driving the wallet
**by URLs** — navigate the wallet to an offer URL, answer its UI, and the
suite judges the wallet by its HTTP traffic. The mini-wallet-adapter
swaps the wallet side for the raw engine; nothing else changes.

## The mini-wallet-adapter

Three pieces; the ports were built for exactly this:

1. **The wallet under test = `engine-adapter-wasm` + a ~100-line harness
   page.** `?offer=<url>` maps to `wmp.flow.start(oid4vci)`,
   `?request=<url>` to `wmp.flow.start(oid4vp)`; consent and tx_code
   become `confirm()`/`prompt()` dialogs Playwright already answers;
   credentials persist through the adapter's existing JS `kv` callbacks
   (localStorage).
2. **A built-in "mini host" in the wasm adapter** (a Host implementation
   the config selects): auto-consent, a WebCrypto P-256 key behind
   `request_sign` — the proof JWTs the OID4VCI plans verify — and the
   compose stack's `go-trust-allow` behind `pdp.evaluate`. No engine
   changes; the sub-flows are answered, the protocol is the engine's.
3. **The one real gap: `request_vp`.** The OID4VP wallet plans need a
   real VP the suite can verify, and VP construction is host-side by
   design. The presentation crates (`siros-sdjwt`, `siros-mdoc`,
   `siros-openid4vp` — pure Rust, already in the workspace) build
   those; they are not yet exposed through the wasm adapter. Wiring them
   is the only substantive new work, and it is work the real SDK needs
   anyway.

## The phases

- **Phase 1 — the OID4VCI wallet plans green.** Offer intake, metadata,
  both grants, proofs, deferred, notification — all engine-side already;
  the mini host only signs. Objective evidence for the entire issuance
  half, fast.
- **Phase 2 — the OID4VP wallet plans.** The presentation crates land in
  the wasm adapter as the VP builder; the suite issues test credentials
  to the mini-wallet through Phase 1's path, then verifies what it
  presents.
- **Phase 3 — the Phase B milestone.** Both agreed plans green; the
  go-observed hard sunset can fire; the runs (plan links, suite
  versions) are recorded as `oidf`-provenance vectors, promoting the
  hand-authored `spec` ones.

## The conformance profile

A `mini-wallet` variant in `siros-conformance`: a compose profile with
the suite, the vc-issuer stack and `go-trust-allow`, the wallet-frontend
and `go-wallet-backend` replaced by a static page serving the wasm
harness; a Playwright spec that navigates, answers the dialogs, and
asserts through the suite's results API (`conformance-api.ts` already
does that part). The existing wallet specs stay — the mini-wallet
profile runs beside them, not instead.
