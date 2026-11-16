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
| wallet-core **v0.2.2–v0.2.9** | Released: AARs on Central + GH Packages, XCFramework + bindings per tag, engine image on ghcr, conformance green. **v0.2.4–v0.2.8** (#33–#37): the nym_auth zkp chain's five wire members. **v0.2.9** (#40, 2026-11-14): the RFC 9207 `iss` gate (the #551 twin) + the mini-wallet page's client rollout (the conformance suite caught it — the `authorization_code` variant) |
| Kotlin SDK **v0.23.1** | **Released 2026-11-14** (Maven Central + GH Packages + Play internal track, from the v0.23.1 tag): carries #404/#405 (the WMP zkp chain), #406/#407 (the message journal, the Show me action, the completion-race fix), the engine AAR pin **v0.2.9** (bindings byte-identical v0.2.2→v0.2.9 — the whole engine train rode JSON through the Host port) |
| Swift SDK **v0.17.1** | **Released 2026-11-14** (tarballs + TestFlight, from the v0.17.1 tag): carries #283 (the session recovery twin), the xcframework pin **v0.2.9** (FFI surface byte-identical). The zkp parity (#277) stays open |
| GDC | Backend 0.25.2 (deployed), engine **v0.2.8 verified live**; Spherity's OID4VCI issuer whitelisted (2026-11-13, the sd-jwt offer test) |
| Native AARs | **8/8 on Maven Central** (wallet-core 0.2.2 and verifier-core-ffi 0.1.2 added 2026-11-12; the token-free resolution is proven) |
| Multi-credential issuance (Platform-Epics#63) | Analyzed, decided (no mid-flow selection; subset-at-flow-start; `IssuanceSelectionPolicy` knob), tracked in five repos — **not started** |
| **SDK patch releases (v0.23.1 / v0.17.1)** | **[2026-11-14] UNBLOCKED — the nym_auth chain is device-validated end-to-end.** Carry #404/#405/#406/#407 from merged main + embed engine **v0.2.8** — both SDKs currently pin **v0.2.2** (Kotlin: the `walletCoreVersion` gradle property in `sdk/transport/build.gradle.kts`; Swift: the `Package.swift` xcframework zip URL). The embedded engine only serves local-first mode (a local-first zkp_req needs v0.2.4+'s `VpParams` members or it dies at the same policy gate); the remote path deserializes the params from the wire. The #33–#37 changes touched no FFI records (`VpParams`/`MatchParams`/`VerifierInfo` — hmm, `VerifierInfo` IS a uniffi Record: re-vendor the bindings from v0.2.8 for the `trust_context` member), so the bump is the AAR pin + the zip URL + the re-vendored bindings, all from v0.2.8 per the same-release rule |

**[2026-11-14] THE NYM_AUTH ZKP_REQ CHAIN IS DONE — device-validated end-to-end**
(match → consent → the ZK proof → the engine's JARM submission →
`onFlowComplete` → the spinner clears). Seven gates found and fixed, each one
found on-device and root-caused:
1. v0.2.5 (#34): `signature_verification` rides the ask — the gate's missing member.
2. #404 (merged): the WMP synthesis dropped `verified_request`/`response_encryption`.
3. v0.2.6 (#35): the encryption key from `client_metadata.jwks`, not the top-level `jwk`.
4. v0.2.7 (#36): `VerifierInfo.trust_context` — the PDP's `verifier_ids` relay.
5. v0.2.8 (#37): the match ask carries `client_metadata` — the planner's circuit lists.
6. #405 (merged): the SSE data-line log leak + the apiCheck dump.
7. #407 (the "stuck at contacting verifier" fix, in flight): **`WmpPeer.startFlow` tracked
   a wallet-initiated flow's type AFTER the start RPC** — the engine answers that RPC
   only after the flow completes, so the completion always won the race, found
   `type=unknown`, and was silently dropped. Track BEFORE the call; forget on the
   start's own failure paths. Plus the completion-drop recovery (a spinner can
   never hang again).
The full hunt is on #407 and in the Kotlin commit history; the Swift twins of
the engine-side members ride the #277 parity sweep (the `trust_context`/
`client_metadata` mirrors + the `iss` items below).

---

## The step-back review (2026-11-14, post-v0.2.9 / v0.23.1 / v0.17.1)

After the release train: a full-platform gap analysis. Sources:
`engine-parity.md` (the wave history — W1–W8 complete, W9 in progress),
the SDK checkouts, the CI surfaces, and this week's on-device findings.
Ranked by risk × likelihood, not by effort.

### A. The structural risks (the ones that bite in production)

1. **The server adapter's state is all in-process — multi-replica is broken
   today** (parity #432, known and recorded): `MemorySessionStore` (the WMP
   sessions — this week's on-device "Session not found" was the single-replica
   TTL lapse; a replica bounce is the multi-replica version), `InMemoryKv`
   (the `AuthorizationStash`, 600s TTL), the outbox (the SSE replay log),
   the flow-type registry. The Rust engine answers correctly for ONE pod;
   a Fly deploy with `min_machines>1` or a restart mid-flow silently loses
   every in-flight session/stash/replay. **The TEE stateless-resume design
   (below) is ALSO the fix here** — the client-held sealed stash moves the
   resumable state off the server entirely; the session store becomes a
   cache. Until then: `min_machines=1`, sticky sessions, and the stash TTL
   kept short.

2. **The conformance suite's 45-minute runner cap is a recurring flake**
   (two cancelled runs this week, both the `authorization_code` variant
   burning 10m × 4 modules × 2 retries on a real failure, the third a
   genuine timeout). The suite serialises 4 VCI variants + 4 VP variants
   on ONE job. Split the matrix (VCI/VP as parallel jobs) or raise the cap
   — the job is the only CI gate that has blocked merges twice this week
   for infra reasons.

3. **`wallet-frontend` (the wasm consumer) is the least-tested surface.**
   The mini-wallet page (`engine-adapter-wasm/page/wallet.js`) is the
   reference consumer and its `kv` is localStorage, its resume is
   sessionStorage, its engine is a fresh WASM instance per page load — and
   this week's `iss` catch showed exactly how its gaps surface (through the
   conformance suite, not its own tests). The page has NO test coverage of
   its own; every wallet-side fix lands there last. **Priority: the
   duplicate-`iss` guard and the forwarded-`iss` we just shipped exist only
   there and in the conformance evidence — port them as first-class tests
   or move the page's logic into the wasm crate's testable surface.**

### B. The SDK parity gaps (ranked)

4. **Swift `CredentialMatcher.matchDcql` has NO `circuitZk`/`zkSystemIds`
   parameters at all** (#277, the known biggest lift): the Swift WMP match
   path offers every eligible credential regardless of the query's zkp_req
   format filter, and there is no Swift ZK sign pipeline. This is the ONLY
   remaining blocker for zkp_req parity — a Swift user presenting to a
   zkp_req verifier gets a refusal (or worse, a wrong-credential match).
   The engine-side members (`trust_context`, `client_metadata`,
   `verified_request`, `response_encryption`) are all wire-shape-stable
   now, so the port can be built against them without churn.

5. **The Kotlin embedded-engine path (`WmpEngineAskHandler`) forwards nulls
   for the new wire members** — `verified_request`/`response_encryption`
   are in the uniffi `VpParams` Record but the handler passes null (the
   vendored bindings predate them); local-first mode would refuse at the
   same policy gates the remote path just cleared. Same for the Swift
   `WmpEngineAskHandler` twins. **The bindings are byte-identical because
   the members ride JSON — but the EMBEDDED adapters still need their
   bridges updated** (engine-adapter-sdk's `From` impls) to populate them.
   Verify with one local-first device test.

6. **Swift #283's session-recovery fix landed, but the bearer-precedence
   parity and the SSE-logging diagnostics did not** (the Kotlin #404 set
   is only partially twinned): no Swift `SSE line`-equivalent trace, no
   dispatch logging. The Kotlin round proved those diagnostics are what
   makes on-device debugging tractable at all — port them BEFORE the next
   Swift on-device debugging session, not during it.

### C. The engine (the Rust core)

7. **`select_as_url` first-entry on multi-AS issuers** (#511, W1-remainder,
   recorded): a grant-level `authorization_server` hint MUST match; absent
   + several advertised takes `first()`. Fail-closed on mismatch landed;
   the absent-then-first case is a documented choice but a real interop
   hazard for multi-AS production issuers.

8. **The decline/no-match OAuth description divergence** (#D2, trivial):
   Go sends the same description for decline and no-match (the verifier
   cannot probe which); Rust sends distinct strings. One-line align.

9. **The response-endpoint sanitisation** (#D1): Go sanitises the
   response endpoint scheme (http/https); Rust posts to whatever the
   request names. An SSRF-adjacent gap on the submission path — worth
   closing with the same rule as Go.

### D. The process gaps (this week's meta-findings)

10. **The admin-merge-before-CI lesson, twice-learned**: #404 (the SSE log
    leak reached main) and #407 (the translations lint) both merged on
    partial CI. The auto-merge watchers now gate on `fail==0 AND
    pending==0`, but the discipline is: no admin merge before the FULL
    suite, ever — the watchers suffice.

11. **The engine releases are tag-per-PR** (v0.2.4–v0.2.9 in two days): the
    release train is cheap and correct, but GDC re-pins are manual
    per-release. A rolling `engine-server:latest-sha` tag + an auto-pin
    pipeline would retire the per-release ceremony; until then the
    per-release pin stays deliberate.

### E. The Swift↔Kotlin parity sweep (2026-11-14, the second pass)

The listener-surface and feature-set diff, beyond the known #277. Ranked
by user-visible blast radius:

12. **The Credential Auxiliary Data surface is ABSENT in Swift** (the
    #480 wave's wallet half): Kotlin's `AuxiliaryDataV01` /
    `AuxiliaryDataShape` / `AuxiliarySelection` (46 call sites in
    SirosWallet — the advertised-selection bookkeeping, the
    `auxiliary_data_to_issuer`/`_to_wallet` answer slots) has NO Swift
    counterpart. The `secretSeedAdvertised` per-issuer bookkeeping, the
    seed-delivery answer, the conflict/refusal listeners
    (`onAuxiliaryDataConflict`/`onAuxiliaryDataRefused`) — none exist.
    A Swift wallet presenting to a nym_auth verifier that advertises
    auxiliary data cannot deliver the seed commitment: the issuance and
    the presentation both miss. **This is the largest single gap; it
    blocks the nym_auth issuance path on Swift entirely.**

13. **`onTransactionDataRefused` has no Swift twin**: Kotlin reports the
    TS12 refusal's reason class (`TransactionDataReason`, the typed
    decline the UI words locally); Swift's `TransactionDataError.Reason`
    exists but no listener callback surfaces it. The Swift wallet cannot
    tell a user-decline from an unsupported-transaction-type refusal in
    its UI — the exact conflation the Kotlin side words apart.

14. **`onCredentialSelectionRequired` is async-with-answer in Swift but
    the Swift ENGINE path appears to drive selection differently**:
    Kotlin's WMP `consent`/`presentation` asks thread the engine's own
    selection (`credentials_to_include`, the `EngineVpParams.selections`
    relay); Swift's `handleWmpVpRequest` synthesizes from
    `EngineVpParams.selections` but its `onCredentialSelectionRequired`
    returns the DC-API presentation's answer. Verify the two SDKs agree
    on WHO picks (the engine's relay vs the wallet's ask) for the same
    request — a mismatch here is a silent wrong-credential presentation.

15. **The verifier module**: Kotlin's `verifier` (mdoc reader) and
    `passkey-provider` modules have Swift counterparts
    (`SirosVerifier`, `Sources/SirosWallet/SirosWallet+Passkey.swift`)
    but the SirosVerifier module list looks thinner (Mdoc/, trust/) —
    verify the reader trust roots and the NFC engagement parity.
    Lower priority (the verifier is the other side's problem).

16. **The SSE-logging + dispatch diagnostics** (already in the review's
    B.6): reconfirmed — no Swift `SSE line`-equivalent, no dispatch trace.
    The completion-race fix (#407) landed Kotlin-side only; the Swift
    `WmpSession.startFlow` tracking has the same latent race if its
    transport awaits the start RPC (verify: `WmpSession.swift`'s
    `sendRequest` path).

17. **The Kotlin side's gaps (the reverse sweep)**: `onNoMatchingCredential`
    (with `requestedTypes`) and `onTransactionLogFailure` exist ONLY in
    Swift — Kotlin reports the no-match via `onFlowComplete(matchedNothing)`
    and the transaction-log failure not at all. Port both to Kotlin for
    the parity-check CI to hold.

### F. The plugin-selection test program (2026-11-15, from the key-loss hunt)

18. **Test the plugin-selection policy engine end-to-end: set tier requirements
    on the credential catalogue that force nym_auth onto a hardware-bound
    plugin.** The 2026-11-15 key-loss hunt found the selection machinery
    exercised only incidentally: the sample app offers every plugin
    (`softkey`, `fido2`, `r2ps`) to `WscdSelectionPolicy`, which picks per
    required tier — but nothing in the current catalogue *demands* a
    hardware tier, so softkey wins every pick and the policy's
    hw-requirement branch has never fired on-device. A deliberate test:
    annotate the credential catalogue (the zk-circuits manifest / the
    issuer metadata the sample consumes) with a tier requirement that
    nym_auth cannot satisfy in software, forcing the fido2/r2ps path —
    then issue and present nym_auth against it. This validates:
    - the policy's requirement parsing (the catalogue annotation →
      the effective tier),
    - the fail-closed behaviour when the demanded plugin is absent
      (a wallet with no fido2 hardware),
    - the fallback/ordering semantics between the offered keystores,
    - and, with the softkey write-through (v0.14.2) landed, it
      cross-checks that hw-bound keys were never affected by the
      volatility bug — the mdoc deviceKey path on this device was
      softkey-resident all along, so "nym_auth worked" was survivorship
      (its issuance-to-presentation window never crossed a restart), not
      a different key path.
    **[2026-11-15] The test's supporting config surface (the reporter's
    addition): build settings in BOTH SDKs and expose them in the sample
    apps to allow mapping credential-catalog labels to a WSCD plugin** —
    the sample app already sketches this shape
    (`WalletViewModel.defaultWscdMappingText`, the
    `"issuer|credentialType=pluginId"` parsed form feeding
    `WalletConfig.defaultWscdMapping`), but it is a UI-side
    pre-population for the *policy's* own selection, not a first-class
    SDK setting: promote the mapping to a real
    `WalletConfig`/`SirosWallet` surface (the label → pluginId map the
    `WscdSelectionPolicy` consults beside the tier requirements), expose
    it in both sample apps' settings, and use it as the F.18 test's
    actuator — flipping a nym_auth catalogue label onto `fido2`/`r2ps`
    at runtime is the test itself.
    owner: the credential-catalogue annotation is
    siros-zk-catalogues/issuer-metadata work; the policy itself is
    `WscdSelectionPolicy` (both SDKs) + the catalogue's schema; the
    mapping setting is SDK-side (`WalletConfig.defaultWscdMapping`
    already exists as the parsed form — promote it) + both sample apps.

### The ranked order (next two weeks)

1. **#277** — the Swift zkp parity (the only feature-parity blocker left)
2. **The TEE stateless-resume design doc + the `AuthorizationStash`
   sealed-blob shape** (fixes A.1 in passing, the backlog's standing item)
3. **A.2** — the conformance matrix split (infra, one workflow edit)
4. **A.5** — the embedded-adapter bridges + one local-first device test
5. **C.8 + C.9** — the two small engine alignments (#D2, #D1)
6. **A.3** — the wasm page's tests (or its logic into the crate)
7. Then the P1 sweep as it stands (consent-set hardening, EUCC, #511's
   full multi-AS treatment)

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

4. **The FAPI `iss` (RFC 9207) validation — the new engine's twin of
   go-wallet-backend#551.** The OpenID Foundation's
   `fapi2-security-profile-final-client-test-remove-authorization-response-iss`
   (run against the legacy WS engine) strips `iss` from the authorization
   response and expects the wallet to refuse BEFORE the token exchange; #551
   fixes the legacy path (its bulk is the stateless-resumption machinery —
   a signed HMAC `authorization_context` — the Go engine needs because it
   has no per-transaction server-side storage).
   **The new Rust engine has the same gap** (traced 2026-11-13, the
   morning's four-gate nym_auth debugging, `resume_authorization_code` in
   `crates/engine-core/src/oid4vci/mod.rs`): the resume reads only `code` +
   `state` from the action params — the CSRF state match, then straight to
   `exchange_authorization_code`. No `iss` is read, required, or compared;
   `AsMetadata` (`oid4vci/types.rs`) does not even model
   `authorization_response_iss_parameter_supported`, so the engine CANNOT
   enforce it when an AS advertises it; there is no
   `require_authorization_response_issuer` knob.
   **Why it has not come up:** the wallet-core conformance runs cover
   OID4VCI/OID4VP core, not the FAPI2 security-profile suite that does the
   `iss`-removal test — the gap is real but unexercised, not absent. **Do
   not run the FAPI2 suite against the new engine until this is fixed** or
   it will produce the identical finding.
   **The Rust fix is much smaller than #551** (the engine already stashes
   per-flow state server-side — `AuthorizationStash`, the KV store, 600s
   TTL — so the stateless-resumption machinery is already built):
   1. model `authorization_response_iss_parameter_supported` in `AsMetadata`;
   2. read `iss` in the resume (typed — reject null/non-string);
   3. require it when advertised; compare exactly against the stashed AS
      (the stash gains `as_url`/`as_issuer`); refuse BEFORE the exchange;
   4. a `require_authorization_response_issuer` knob for FAPI deployments.
   The #551 client-rollout caveats (duplicate-`iss` URL parameters before
   reducing to the JSON message; preserving the decoded callback `iss`)
   do NOT apply to the engine path — the resume arrives as typed JSON, and
   the duplicate-parameter guard belongs in the wallet-frontend/SDK callback
   parser (the legacy path's concern).
   https://github.com/sirosfoundation/go-wallet-backend/pull/551

   **[2026-11-13, midday] Investigation follow-up — the TEE direction, an
   architectural constraint on this fix and the engine's state design
   generally.** Server-side state makes TEE deployment hard (encrypted
   pages, small RAM budgets, attestation-unfriendly state sprawl), so the
   goal is mechanisms that keep the engine stateless — the state rides
   the wire, sealed to the client, and the engine holds nothing across
   requests. **The state the engine keeps today (the inventory):**
   - `MemorySessionStore` (engine-adapter-server/handler.rs) — the WMP
     sessions (that is what `Session not found` was: the TTL lapsed).
   - `InMemoryKv` (engine-adapter-server/ports.rs:602) — the KV port's
     default implementation; `AuthorizationStash` (oid4vci/mod.rs, 600s
     TTL) rides it, 8 put/get sites total (6 oid4vci, 2 runtime).
   - The resumption token already carries state forward (transport.rs:279)
     — the sessions are half-stateless already.
   **The mechanisms to investigate (in rough order of effort):**
   1. **The client-held sealed stash (the #551 pattern, adapted):** replace
      `AuthorizationStash`-in-KV with a signed (HMAC or the host key) and
      optionally encrypted blob returned to the wallet with the redirect
      hand-off, presented back on the resume — the engine verifies,
      never stores. #551 built exactly this for the Go engine
      (the 5-minute signed `authorization_context`); the Rust engine can
      adopt the same shape at the `wmp.flow.action` boundary.
   2. **The KV port to an attested host:** the `KeyValue` port
      (engine-ports) is already an interface — a TEE deployment can back
      it with the host's encrypted storage (or a sealed sidecar) without
      engine changes, IF the host is trusted for that state. This is the
      low-effort TEE story: the engine's logic is unchanged, only the
      adapter. Cost: the TEE boundary then excludes the state (a
      session/stash read is a host roundtrip) — fine for correctness,
      weaker for the confidentiality story.
   3. **The full stateless resume (the biggest lift):** the flow start
      returns everything the resume needs (the offer params already ride
      the stash today — the resume re-parses them); extend that so
      NOTHING needs the KV: the resume carries the verifier, state,
      redirect, PKCE, and configuration, sealed. Sessions go the same way
      — the resumption token IS the session, the store becomes a cache,
      not a source of truth.
   Design rule going forward (the actionable part): every new engine flow
   must state its resume story up front — what rides the wire, what the
   engine must hold, what the TTL is — and the default is the
   stateless option. #551's `iss` fix (item 4 above) should land in
   shape 1 (the sealed stash), not by deepening the KV dependency.

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

   **[2026-11-13, morning] THE v0.2.4 TEST REFUSED AT
   step=unsigned-request, reason=NOT_TRUSTED — a fourth layer found.**
   Match, trust and consent all ran; the sign ask died at the wallet's
   ZK policy gate (`ZkpReqPolicy.refusalStep`). Root cause: the gate
   reads `signed` AND `signature_verification == "verified"`
   (go-wallet-backend#471's `VerifiedRequest` shape, which the legacy
   backend sends); #33's `VpVerifiedRequest` carried `signed` but not
   `signature_verification` — the SDK read the absent member as null ≠
   "verified" and refused, whatever `signed` said. Engine wire drift,
   fixed by wallet-core **#34** (v0.2.5, deployed): the member rides
   the ask ("verified" — the engine verifies synchronously at parse and
   never defers; "none" without a signed request object), `signed`
   simplifies to `request_jwt.is_some()` (the parser's refusal is the
   truth source; the DID schemes verify against resolved keys, not an
   x5c chain), and a wire test now asserts the exact member set the
   wallets' `VerifiedRequest`/`ResponseEncryptionRequest` readers
   expect — this class of drift fails in CI now, not on a device.
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
E. **Merge-swept regression guards — a recurring failure class (2026-11-16,
   twice found).** The tests-out-of-src / move-the-tests merges resolved their
   file conflicts against branches cut BEFORE the fixes whose tests they moved:
   #11 swept `1b78321`'s client_id form assertions off `auth_code.rs` entirely
   (found via wallet-frontend wasm: apigw refuses the authorization_code grant
   without client_id — green release, real regression, `9596d5c` restores it);
   #16 swept `1cfebe1` the same way (restored manually at the time). Review
   rule: EVERY test-relocating merge is diffed assertion-by-assertion against
   MAIN's current tests — compile-green is not enough, the moved set must be
   main's set, and every drive-validated fix's assertions must survive the
   move. Conformance suites do not backstop this: the OIDF mini-wallet tests
   against a permissive AS and does not require client_id, so the swept guard
   was the only one. When filing: the rule belongs in the merge checklist of
   whichever repo owns the tests.

## Proposed next steps

1. **#276 + close #398** — in flight (the mirror fix).
2. **The GDC remote round** — needs a device and the verifier side; an hour.
3. **go-trust#249** — assign or pick up; small, high consent-UX value.
4. **The #549 spec edit** — the backend owner; unblocks four repos.
5. The P1 sweep as capacity allows, starting with the parity set (#399/#277).
