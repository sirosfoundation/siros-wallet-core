# The OIDF conformance plan: the raw engine against the certification suite

**Status: the OID4VCI wallet plan green on both grants (2026-11-05).** Both
halves pass through the mini-wallet:

**Phase 1 — the pre-authorized code grant** (both variants: `sd_jwt_vc /
pre_authorized_code`, immediate and deferred; DPoP sender-constrain;
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

**The authorization-code grant (2026-11-05)** — both issuance modes green
through the two-call resume: the start pushes PAR (the RFC 7523 assertion
riding the pushed form, RFC 9126 §2.1) and hands the authorization URL
over; the redirect returns with `?code&state`, and the reloaded page
answers the open flow through the KV-persisted stash (the stateless
resume — the wasm adapter's `kv` callbacks carry the stash and the flow
registry through localStorage, the fix that let the reload resolve the
family). The code-for-token exchange carries the same assertion
(`vci.oidf.authcode-private-key-jwt.001` pins the wire; provenance `oidf`,
plans `qxakXX5iipJh4` and `hBdQN9b9fHxXP`).

**The HAIP profile (2026-11-05)** — the OID4VP HAIP wallet plan
(`oid4vp-1final-wallet-haip-test-plan`, `sd_jwt_vc` / `eudi_pid` /
`direct_post.jwt`) green against the raw engine: 11 modules PASSED
(both happy flows, the unusable-encryption-key, all-mandatory-claims,
fewer-claims, optional-credential-set, no-claims, the three DCQL path
forms — array index, array all-elements, object member — and the
required-non-matching negative), `request-uri-method-post` SKIPPED by
the suite, the other eight negative modules REVIEW (each refusal
verified; the placeholder upload completes them). The profile's three
new rules all engine-side: the `x509_hash` client_id scheme (§5.2.3 —
the base64url SHA-256 over the request object's `x5c` leaf, checked in
constant time; an unsigned or chainless request under the scheme
refuses), the HAIP credential form (the PID's JWS header carries its
X.509 chain, HAIP-6.1.1, validating to the configured trust anchor),
and the DCQL §7 path forms over the typed fixture claims. The wire is
pinned by `vp.oidf.x509-hash.basic.001` and
`vp.oidf.x509-hash.mismatch.001` (provenance `oidf`, plan
`x03k3BO5eKEsQ`, suite 5.3.4).

**The iso_mdl format (2026-11-05)** — the OID4VP wallet plan's mdoc variant
(`x509_san_dns` / `direct_post` / `request_uri_signed` / `plain_vp`)
green against the raw engine: the mso_mdoc DCQL query's
`[namespace, claim name]` paths select the mDL's `IssuerSignedItem`s, and
the presentation answer is the base64url `DeviceResponse`
(ISO/IEC 18013-5, 8.3.2.1.2.2) — the selected items as issued, the
`issuerAuth` COSE_Sign1 as issued (ES256: the protected header
`{alg: -7}`, major type 1 encoding `-1-n`), and the device key's
signature over the session transcript of the request's
`OpenID4VPHandover` (OpenID4VP 1.0, B.2.6.1). 6 PASSED,
`request-uri-method-post` SKIPPED by the suite, the eight negative
modules REVIEW. The fixtures carry the ISO 18013-5 document-signer
profile (B.1–B.3): the DS certificate (ECDSA-SHA256, critical
`1.0.18013.5.1.2` mdlDS EKU, IAN, CRL DP) and a real CRL (AKI, CRL
number, ≤90-day nextUpdate) served by the harness nginx with the
RFC 2585 §4.2 content type. The wire is pinned by
`vp.oidf.mdoc.basic.001` (provenance `oidf`, plan `OzBNWDaDeiAn7`).

**The Digital Credentials API channel (complete 2026-11-10)** — the W3C
DC API response modes (OpenID4VP 1.0 §8.4), ALL THREE module groups of
the haip plan's `dc_api.jwt` variant (53 modules, eudi_pid on the HAIP
profile): the signed compact form (`x509_hash` / `request_uri_signed`,
19 — 11 PASSED, 8 REVIEW), the unsigned web-origin form
(`web-origin` / `request_uri_unsigned`, 14 — 10 PASSED, 4 REVIEW), and
the multi-signed general JWS (`x509_hash` / `request_uri_multisigned`,
20 — 12 PASSED including multisigned-one-invalid-signature, 8 REVIEW).
The negatives: the wallet refuses each for the right reason; the
browser API's promise rejection posts to the module's submit URL, then
the tester's error-screen placeholder. The channel's engine side:
the response never POSTs back — the flow completes with the
DigitalCredential's data (the plain response object for `dc_api`, the
JWE for `dc_api.jwt`), the error answers ride the same completion, and
the caller's actual origin (the transport's input, validated against
the request's `expected_origins`) binds the KB-JWT's `aud`
(`origin:` + the URL, HAIP-7.3.2) and the mdoc
OpenID4VPDCAPIHandover (B.2.6.2). The wasm adapter forwards the
engine's `wmp.flow.complete` notifications to the page's
`onNotification` callback — the flow results the resolved start answer
alone never carried. The harness plays the browser: the response data
hands to the module's browser API submit URL exactly as the suite's
own page does.

The 2026-11-10 completion added three wire rules:

- **The multi-signed request object** (RFC 7515 §7.2, the JWS JSON
  Serialization): every signature verifies through its
  compact-equivalent against the `x5c` in its own protected header;
  AT LEAST ONE valid signature authenticates the verifier (the
  one-invalid-signature module leaves the second valid on purpose — a
  failing signature is skipped, none verifying refuses). The
  multisigned form carries the client_id in the signatures' protected
  headers, not the payload: the first VERIFIED signature's client_id
  is the binding the wallet's scheme rules run against — the
  invalidated signature's claim never authenticates anything.
- **§5.9.2's bounds on the pre-registered fallback**: an unknown-prefixed
  client_id names a pre-registered client ONLY on an UNSIGNED request
  (the alternate happy flow's `invalid_scheme:example` with wrong
  origins — advisory); a SIGNED request's unknown prefix refuses (the
  invalid-prefix negative), and a value embedding a recognized prefix
  can never be pre-registered and refuses too. The web-origin form (no
  client_id): the caller's origin IS the client.
- **The origin binding is enforced for an authenticated verifier** — a
  recognized Client Identifier Prefix OR a signed request object (the
  multisigned form carries no client_id but its valid signature
  authenticates); the unsigned pre-registered fallback's
  `expected_origins` is advisory.

Every module group of every agreed plan now passes through the
mini-wallet: OID4VCI (both grants, both issuance modes) and OID4VP
(both redirect response modes, the HAIP profile, the iso_mdl format,
and the complete Digital Credentials API channel). The runs are published on
the Pages site under `runs/mini-wallet-phase1-2026-11-04`,
`runs/mini-wallet-vp-phase2-2026-11-04`,
`runs/mini-wallet-authcode-2026-11-05`,
`runs/mini-wallet-vp-haip-2026-11-05`,
`runs/mini-wallet-vp-mdoc-2026-11-05` and
`runs/mini-wallet-vp-dcapi-2026-11-09` and
`runs/mini-wallet-vp-dcapi-2026-11-10` (the complete channel, all three
groups).

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
