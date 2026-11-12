# The cross-repo backlog

**Scope:** engine-core, the Kotlin and Swift SDKs, go-wallet-backend, go-trust.
**Dated:** 2026-11-12 — the step-back review after the v0.2.2 / v0.23.0 / v0.17.0 release train.

This is the working backlog across the platform, not any one repo's issue list —
the tiers are ranked by blast radius, every item links to its issue, and the
handful that have no issue yet are marked for filing on approval. Review and
re-rank freely; the tiers are proposals.

---

## Where we stand (2026-11-12)

| Piece | State |
|---|---|
| wallet-core **v0.2.2** | Released: AAR on Central + GH Packages, XCFramework + bindings on the release, engine image on ghcr, conformance green |
| Kotlin SDK **v0.23.0** | Released: Maven Central, GH Packages, Play internal track — the consent round and the credential deck shipped |
| Swift SDK **v0.17.0** | Released: tarballs + TestFlight — the consent bridge and the listener-contract repairs shipped |
| GDC | Backend 0.25.2 (deployed), engine re-pinned to the **released** `engine-server:v0.2.2` (verified live) |
| Native AARs | **8/8 on Maven Central** (wallet-core 0.2.2 and verifier-core-ffi 0.1.2 added 2026-11-12; the token-free resolution is proven) |
| Multi-credential issuance (Platform-Epics#63) | Analyzed, decided (no mid-flow selection; subset-at-flow-start; `IssuanceSelectionPolicy` knob), tracked in five repos — **not started** |

---

## P0 — this week

1. **Swift #276 — WMP batch completions are metadata-checked then discarded.**
   Nothing stored while the UI reports success; silent data loss the moment the
   engine emits batches (i.e. the moment multi-credential issuance lands).
   The Kotlin twin is fixed in code (`SirosWallet.kt`'s entry-by-entry batch
   store) — the fix is a mirror. **[2026-11-12] DONE: Kotlin #398 closed as
   fixed-in-code; the Swift mirror merged as siros-sdk-swift#282 (both batch
   tests green, 1766-test suite green) and #276 closed with it.**
   https://github.com/sirosfoundation/siros-sdk-swift/issues/276
2. **The GDC remote validation round.** The re-pinned released engine + the
   0.25.2 backend have not been exercised from a device since the re-pin, and
   0.25.2 just unblocked the tenant-mint/remote-failover flow that 401'd
   before it. One hour with a device closes the release train with evidence:
   tenant mint, a consent ask (expect `client_name` — see go-trust#249), a
   no-match presentation (the redirect), cross-device.
3. **go-trust#249 — the registry `display_name` is never emitted.** The
   verifier-label chain shipped in the consent surfaces consumes it as its
   first link; until it exists, every consent ask shows the client_name.
   The wire plumbing (wallet-core's `EvaluationResponse.context` → both SDKs)
   is done; the source is a small go-trust change. **[2026-11-12] In flight.**
   https://github.com/sirosfoundation/go-trust/issues/249
4. **The #549 protocol decision — the one gate on the multi-credential epic.**
   **[2026-11-12] DECIDED and recorded on #549:** the flow-start subset
   (`credential_configuration_ids`, absent = all) + the `credentials[]`
   completion are the WMP wire mechanism; select-vs-issue-all is an
   engine/SDK-level configuration defaulting to issue-all; and the
   go-wallet-backend engine module (the legacy WebSocket protocol) is
   **explicitly out of scope** — #549 is the decision record, the
   implementation is wallet-core#28 (WMP), with the SDK legs unblocked.
   https://github.com/sirosfoundation/go-wallet-backend/issues/549

## P1 — next two weeks

5. **The parity sweep** — one cross-SDK push through the 2026-11-11 audit's
   remaining set: zkp_req match planning, the WMP REAUTH surface, Swift's
   local disconnect + attestation ask, Kotlin's WMP match UX.
   Kotlin https://github.com/sirosfoundation/siros-sdk-kotlin/issues/399 ·
   Swift https://github.com/sirosfoundation/siros-sdk-swift/issues/277
6. **Consent-set hardening** — the shared-query-in-unselected-option and the
   multi-element-option misattribution edges, against the consent UX that
   just shipped.
   https://github.com/sirosfoundation/siros-sdk-kotlin/issues/363 ·
   https://github.com/sirosfoundation/siros-sdk-kotlin/issues/356
7. **The EUCC pair** — `UniFFISigner` hardcodes "EUCC" as the certifying
   scheme with no evaluation behind it, in both SDKs, identically.
   Kotlin https://github.com/sirosfoundation/siros-sdk-kotlin/issues/375 ·
   Swift https://github.com/sirosfoundation/siros-sdk-swift/issues/260
8. **Backend #511** — the credential offer's `authorization_server` hint is
   ignored (MUST NOT proceed on mismatch). Security-adjacent, small.
   https://github.com/sirosfoundation/go-wallet-backend/issues/511
9. **Kotlin #364** — the credential-kid retention check misses DIIP
   (did:jwk) bound credentials; the shadow/renew state is wrong for them.
   https://github.com/sirosfoundation/siros-sdk-kotlin/issues/364
10. **Backend #530** — a failed DPoP signing burns the single-use
    notification context; WMP cannot sign after the flow ended.
    https://github.com/sirosfoundation/go-wallet-backend/issues/530
11. **Release-pipeline hardening.** The drift class (env mappings, stale pins,
    skipped publishes) has now struck three releases (v0.17.0, v0.18.0,
    v0.23.0). Two moves: make the publishes idempotent (tolerate an
    already-published version instead of dying at the 409), and add a
    post-tag "release doctor" dry-run that fails loudly on the missing
    mappings/stale pins before anything ships.

## P2 — the queue

12. **Backend #502 — the credential-data-free consent shape** (WMP spec #27).
    Quietly the biggest item on the board: it changes the wire the consent
    surfaces we just shipped consume. Promote to its own epic when scheduled.
    https://github.com/sirosfoundation/go-wallet-backend/issues/502
13. **The Swift sample's deck parity** — the Android-first UX round
    (lift/swipe deck, edge-to-edge, pull-down-to-close) has no Swift mirror.
    A product decision, then a port or a divergence.
14. **Swift #255, #253, #254** — the link-ledger attempt-identity races, the
    path-carrying identifier URL construction, `auxiliary_data` not refused in
    relayed completions.
    https://github.com/sirosfoundation/siros-sdk-swift/issues/255 ·
    https://github.com/sirosfoundation/siros-sdk-swift/issues/253 ·
    https://github.com/sirosfoundation/siros-sdk-swift/issues/254
15. **Backend #512, #521, #478, #534** — the AuthZEN proxy's issuer
    resolution; "last connection wins" not superseding across replicas;
    flow_start rejecting client-generated flow ids; the anonymous-token
    `/issuer/all` rejection.
16. **Swift #274** — mirror the WMP OID4VP findings (partially overtaken by
    the engine v0.2.2 and #276; the blocking-send and consent-default
    mirrors need verification).
    https://github.com/sirosfoundation/siros-sdk-swift/issues/274
17. **Swift #252, #270; Kotlin #365, #361** — the SVG logo fidelity gaps; the
    light-appearance status bar over the brand-blue header; the BBS git
    dependency re-pin; the TransactionSchemas pool flakiness.
18. **Repo hygiene** — OpenSSF Scorecard fails on every wallet-core commit
    (chronic, policy-side); backend release-notes PRs #547/#542 open;
    Kotlin's `.claude/` still un-gitignored (the near-miss happened there
    twice; Swift's is ignored).

## Items with no issue yet — file on approval

A. **The detail screen's "Expires" row shows the JWT `exp`** while the status
   evaluator judges the VCDM `validUntil` — the two can disagree (short-lived
   envelope, long-lived credential), which read on-device as "shows as expired
   but needs-attention says fine". Both SDKs' detail screens should show the
   credential's own validity, the same field the evaluator reads.
B. **The credential deck's accessibility semantics** — the hand-written gesture
   detectors replaced `combinedClickable`, so the cards lost their clickable/
   click-label semantics: a TalkBack user gets no click or lift actions on
   deck cards. Needs semantics annotations on the cards (click = detail;
   custom action = lift/put back).
C. **The release doctor** (see P1 item 11) — listed there; file as its own
   issue on whichever repo owns the workflow templates.
D. **Kotlin's `.claude/` ignore** — a one-line PR.

## Proposed next steps

1. **#276 + close #398** — in flight (the mirror fix).
2. **The GDC remote round** — needs a device and the verifier side; an hour.
3. **go-trust#249** — assign or pick up; small, high consent-UX value.
4. **The #549 spec edit** — the backend owner; unblocks four repos.
5. The P1 sweep as capacity allows, starting with the parity set (#399/#277).
