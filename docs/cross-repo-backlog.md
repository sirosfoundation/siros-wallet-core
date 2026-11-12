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
| wallet-core **v0.2.2–v0.2.4** | Released: AARs on Central + GH Packages, XCFramework + bindings per tag, engine image on ghcr, conformance green. **v0.2.4** (2026-11-13): `VpParams` carries `verified_request` + `response_encryption` — the zkp_req policy inputs (#33) |
| Kotlin SDK **v0.23.0** | Released: Maven Central, GH Packages, Play internal track — the consent round and the credential deck shipped. **Predates #404** (the zkp_req match + sign pipeline, the session recovery, the diagnostics, the dialog buttons) |
| Swift SDK **v0.17.0** | Released: tarballs + TestFlight — the consent bridge and the listener-contract repairs shipped. **Predates #283** (the session recovery twin) |
| GDC | Backend 0.25.2 (deployed), engine re-pin v0.2.3 → **v0.2.4** auto-deploying (2026-11-13 overnight) |
| Native AARs | **8/8 on Maven Central** (wallet-core 0.2.2 and verifier-core-ffi 0.1.2 added 2026-11-12; the token-free resolution is proven) |
| Multi-credential issuance (Platform-Epics#63) | Analyzed, decided (no mid-flow selection; subset-at-flow-start; `IssuanceSelectionPolicy` knob), tracked in five repos — **not started** |
| **SDK patch releases (v0.23.1 / v0.17.1)** | **Queued behind the morning nym_auth validation.** Carry #404/#283 from merged main + embed engine **v0.2.4** — both SDKs currently pin **v0.2.2** (Kotlin: the `walletCoreVersion` gradle property in `sdk/transport/build.gradle.kts`; Swift: the `Package.swift` xcframework zip URL). The embedded engine only serves local-first mode (a local-first zkp_req needs v0.2.4's `VpParams` or it dies at the same policy gate); the remote path deserializes the params from the wire, so the morning test does not wait on this. The #33 change touched no FFI records (`VpParams` is an engine-internal port), so the vendored UniFFI bindings are unchanged — the bump is the AAR pin + the zip URL, re-vendored from v0.2.4 anyway for the same-release rule |

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
2. **The GDC remote validation round.** **[2026-11-12] DONE — and it found
   four real bugs that only a live device round could surface:**
   - The SDK's remote engine bearer took the legacy HMAC app token instead
     of the AS's pseudonymous tenant token (the engine's asymmetric-only
     gate refused it before even fetching the JWKS — fixed: a tenant-mode
     engine always mints the tenant kind, siros-sdk-kotlin `fix/wmp-session-recovery`)
   - The engine's principal read the AS's `tenant` claim, but the AS stamps
     `tenant_id` — every real AS token produced an empty tenant, and a
     tenant-mode principal with no tenant has an empty ownership key
     (fixed: wallet-core#32, released as v0.2.3, re-pinned)
   - The wallet's resume loop exhausted on "Session not found" (the TTL
     lapsed) and left the wallet stranded on a dead session — every later
     flow start landed on it and the engine answered "Capability not
     supported" (fixed: the resume exhaustion falls back to a fresh
     session create, siros-sdk-kotlin `fix/wmp-session-recovery`)
   - The wallet-proxy's nginx spoke HTTP/1.0 to the engine's SSE — the
     first event arrived, every subsequent one was lost in the encoding
     mismatch (fixed: `proxy_http_version 1.1` + `Connection ''`, sirosid-dev)
   After all four: the tenant mint works (0.25.2 proven), the session
   connects (v0.2.3 proven), the cross-device presentation works for both
   the matching case (consent popup → noun-phrase claims → signed share →
   completion clears the UI) and the no-match case (decline reaches the
   verifier, the wallet shows the denial, the UI clears). The consent
   surfaces show `client_name` (go-trust#249's `display_name` is still
   in flight).
3. **go-trust#249 — the registry `display_name` is never emitted.** The
   verifier-label chain shipped in the consent surfaces consumes it as its
   first link; until it exists, every consent ask shows the client_name.
   The wire plumbing (wallet-core's `EvaluationResponse.context` → both SDKs)
   is done; the source is a small go-trust change. **[2026-11-12] In flight.**
   https://github.com/sirosfoundation/go-trust/issues/249
   **[2026-11-12, late] The implementation (go-trust#255, closing #249) will
   ALSO add `display_name_l10n` — a map of language-tag → string — alongside
   `display_name`. The consumption plan, mapped to the code:**
   - **The arrival needs no engine change**: the PDP client relays go-trust's
     `context` verbatim (`engine-adapter-server/src/ports.rs:513`), so the map
     rides `EvaluationResponse.context` automatically once go-trust sends it.
   - **But the pick point drops it today**:
     `engine-core/src/oid4vp/trust.rs:275` collapses `context.display_name`
     into the single-string `verifier.name` (`VerifierInfo.name`, the match
     ask's label) — the map is lost right there, and the engine cannot pick a
     locale entry anyway because it never learns the wallet's device locale.
   - **Engine change (wallet-core, next release)**: `VerifierInfo` gains an
     optional `display_name_l10n` map member, populated in `trust.rs` from
     `context.display_name_l10n` verbatim; `display_name` → `name` stays the
     default so old wallets see today's behaviour unchanged.
   - **Kotlin SDK**: the match-ask verifier parsing (`handleWmpMatchRequest`
     → the `TrustResult(entityName = label)` construction) prefers the
     locale-matching entry: exact `Locale.getDefault().toLanguageTag()` →
     language-only → case-insensitive tag → `display_name` → today's label
     chain.
   - **Swift SDK**: the twin, `Locale.current.identifier`, in the match
     handler's TrustResult construction.
   - Not in scope: the legacy wallet-backend PDP's own context (`entity_name`
     keys — `TrustResolution`/`MdocTrust`/`DCAPI` read those) is a different
     wire shape from a different source.
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

   **[2026-11-12, evening] P0-2 follow-up — the zkp_req match gap is now
   root-caused on-device** (the GDC round's nym_auth test): the WMP
   `handleWmpMatchRequest` path calls `CredentialMatcher.match` WITHOUT
   the `circuitZk` support, so every `zkp_req` query falls through to
   `matchSingleQuery`, whose format filter (`format == "mso_mdoc"`) rejects
   the nym_auth credential before the doctype check runs — `format=zkp_req
   vct=null doctype=eu.europa.ec.eudi.nym_auth.1 → 0 matches`. The legacy
   engine path works because its own matcher passes the `CircuitZkSupport`.
   **[2026-11-12, night] The match half is FIXED and on-device** (`fix/wmp-session-recovery`
   @ 44ba225f): `handleWmpMatchRequest` now passes the `circuitZk` support and the
   payload's `client_metadata` to `matchDcql` (the same wiring every other call
   site had). On-device verified: the nym_auth presentation now matches, the
   consent ask appears, and the flow reaches the sign step.

   **The remaining two halves, with a precise on-device signature:**
   the flow now fails at sign with `vp ask: disclosedClaims=[] → vp sign:
   consentedClaims=null → DisclosureRefusedException` —
   1. The consent ask carries `claims=[]` (a zkp_req match result has
      `requestedClaims = emptyList()`), so the UI words nothing — it needs
      the circuit's proof description (what the verifier learns), which the
      DC API path renders through `answerCircuitZkQueries`'
      `PresentationConsentHandler`.
   2. The sign step's `consentedClaims=null` means "disclose everything",
      which the ZK wrapper refuses — a zkp_req presentation must disclose
      exactly the circuit's declared inputs. The sign step needs the
      ZK-wrapped presentation (`zkPresentation.present`, the DC API path's
      shape), not the plain DeviceResponse.
   **[2026-11-12, night] The WMP zkp sign pipeline is IMPLEMENTED and on-device**
   (`fix/wmp-session-recovery`): the WMP `sign_presentation` arm routes
   `zkp_req` queries through `answerWmpCircuitZkPresentation` — a port of the
   legacy transport's `handleCircuitZkEngineSignPresentation` that runs the
   shared `answerCircuitZkQueries` pipeline (the plan's consent wording,
   verifier-id resolution, the CircuitZkPresenter). The on-device trace:
   match succeeds ✓ → consent ask fires ✓ → the ZK sign pipeline runs ✓ →
   **refuses at `ZkpReqPolicy.refusalStep` with `step=unsigned-request`**.

   **The remaining gap is ENGINE-SIDE**: `VpParams` (the Rust engine's
   `request_vp` host port) doesn't carry `verified_request` (the engine's
   verified, signed request object) or `response_encryption` (the verifier's
   response encryption key) — both of which the wallet's ZK policy gate
   requires ("the engine verified the request's signature AND the response
   channel is encrypted"). The legacy Go engine relays both on its
   sign_presentation; the Rust engine's `VpParams` struct
   (engine-ports/src/lib.rs:413) has neither. The fix: add both to
   `VpParams`, populate them from the OID4VP request parsing in the engine's
   oid4vp flow, thread them through the host bridge — then a wallet-core
   release → engine re-deploy → the SDK picks them up from the WMP sign
   sub-flow's params. The Swift twin follows.

   **[2026-11-12, midnight] ALL THREE LAYERS MERGED AND BUILDING.**
   - Engine: wallet-core **#33** merged, tagged **v0.2.4**, release running.
   - Kotlin SDK: **#404** merged (all five fixes). The device runs the merged build.
   - Swift SDK: **#283** merged (the session recovery). The Swift zkp match
     and sign pipeline are the remaining #277 work.
   After the v0.2.4 engine deploy: the nym_auth test should run end-to-end.
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
