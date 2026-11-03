# The OIDF conformance plan: the raw engine against the certification suite

**Status: designed, deferred** — start when the remaining engine work is
finished. This document is the plan agreed on 2026-11-04.

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
   `siros-presentation` — pure Rust, already in the workspace) build
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
