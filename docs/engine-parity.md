# The engine parity matrix: go-wallet-backend (engine mode) → siros-wallet-core

**Status: triaged 2026-11-05.** The full-behavior comparison between the Go
engine (`go-wallet-backend --mode=engine`, `internal/engine/`) and the Rust
engine core (`engine-core`), against what the three consumers — the Kotlin
and Swift SDKs and the wallet-frontend — expect. The goal: **full alignment
and a drop-in replacement**, then real testing.

Sources: the Go engine (`internal/engine/{oid4vp,oid4vci,session,messages}.go`),
the SDKs (`siros-sdk-kotlin` `sdk/transport/engine/EngineTypes.kt`,
`sdk/flow/FlowStepCatalog.kt`, `sdk/wallet/ClientIdScheme.kt`,
`.../wmp/OpenID4xProfile.kt`), the wallet-frontend
(`src/lib/openid-flow/transports/OIDFlowWebSocketTransport.ts`,
`types/ProtocolSteps.ts`), and this workspace's
(`docs/engine-switching.md`, `docs/sdk-integration.md`, the port traits).
Line references are to the surveyed checkouts.

## The deployment model (why the boundary is where it is)

`docs/engine-switching.md`: the engine core is one implementation behind
three adapters — UniFFI (the native SDKs), wasm (the browser), tokio+rustls
(the server container). The consumers **do not speak UniFFI types**: the
SDKs' `WmpUniFFITransport` wraps the exported `WmpEngine` handle behind the
SDKs' existing `Transport` interface, and the frontend's wasm transport would
wrap the JS `engine.request()` JSON-RPC surface. The **legacy WebSocket v2
protocol stays on the Go engine** until retirement
(`docs/engine-spec.md`: "the in-SDK engine speaks WMP, not the legacy
WebSocket protocol") — the drop-in surface is:

1. the **engine core's observable behaviors** — flow steps, refusal codes,
   wire shapes, scheme handling — consumed through the ports;
2. the **adapters' completeness** — the server adapter's `Host` bridge, the
   SDK adapter's port wiring.

This matrix triages (1) exhaustively and (2) as the gaps the surveys found.

## 1. Client ID schemes (OID4VP §5)

The Go engine (`oid4vp.go:56-72, 507-851, 1832-1859`) vs the Rust
(`engine-ports/src/lib.rs:236-292`, `engine-core/src/oid4vp/request.rs`,
`trust.rs`). The SDK's `ClientIdScheme.kt` mirrors the same prefixes.

| Scheme | Go engine | Rust engine | Verdict |
|---|---|---|---|
| `redirect_uri` | default; no signature requirement; best-effort key material from `client_metadata` (x5c > jwks > jwks_uri), else unverified JWT header extraction | recognized; JWS verified under `x5c` when present; the best-effort key material (x5c > the metadata's jwks > the request JWT header's jwk) | **aligned (W8)** — the key-material enrichment landed |
| `did:` | `did:` and `decentralized_identifier:` both infer; server-side DID resolution (`TrustSvc.ResolveDID`); JWT must verify against ≥1 resolved key | both prefixes infer (W1); the resolution behind the Pdp `resolve` port (`did_document`), the request JWT verified engine-side against the resolved `publicKeyJwk`s, the **matched key** the PDP evaluates; a PDP without DID resolution = best-effort, a failed one fails closed | **landed (W8)** — gap A2 closed per the recorded architecture |
| `x509_san_dns:` | JWT-required; JWS verified pre-cache (`:1986-1994`); key material must be `x5c`; SAN↔DNS binding delegated to the PDP | signed+x5c enforced (W1); the `x5c` chain is the key material the PDP evaluates (W8) | **landed (W8)** |
| `x509_san_uri:` | falls into the default best-effort path (no dedicated handling) | same (recognized, no dedicated path) | **aligned** (both best-effort) |
| `x509_hash:` | JWT-required; JWS verified; the hash↔leaf binding **left to the PDP** | JWS verified; **hash↔leaf binding checked in-engine** (constant time; unsigned/chainless refused) | **aligned** (Rust stricter; the PDP check is redundant but compatible) |
| `verifier_attestation:` | attestation extracted from the request JWT's `jwt` header param (`pkg/trust/jwtutil.go:93-168`): `iss`/`sub`/`cnf.jwk` required, request JWT signature verified against `cnf.jwk`, `sub` must equal `client_id` minus the prefix; attestation key material → PDP | the extraction + checks (W1); the `cnf.jwk` is the key material and the whole attestation JWT rides the eval context (W8) — the PDP verifies it | **landed (W8)** |

**A2 (DID resolution) — landed (W8), as the decision recorded.** The DID
document resolution moves behind the Pdp port (`resolve` with a
`did_document` resource type), the port returning the **raw document** (the
preferred form), and the engine verifying the request JWT against the
resolved `publicKeyJwk`s itself — the matched key is the key material the
PDP evaluates, exactly the Go engine's split between resolution
(`TrustSvc.ResolveDID`) and trust (`evaluate`). The transition state, as
recorded: a PDP that does not implement `did_document` resolutions answers
the did-schemed verifier **best-effort** (the metadata's jwks, the request
JWT unverified); a configured resolution that fails **fails closed**, as
the evaluate step does.

## 2. Flow progress steps

The consumers key on the **Go engine's emitted vocabulary**:

- the SDK's legacy path: `FlowStepCatalog.kt:22-60` —
  `parsing_offer, offer_parsed, fetching_metadata, metadata_fetched,
  evaluating_trust, trust_evaluated, awaiting_selection,
  authorization_required, exchanging_token, token_obtained,
  requesting_credential, deferred` (VCI) and `parsing_request,
  request_parsed, evaluating_verifier_trust, match_credentials,
  awaiting_consent, credential_selection, submitting_response` (VP);
- the wallet-frontend's UI state machine (`types/ProtocolSteps.ts`) is fed
  the raw server step token as `stage` and maps the known ones;
- the SDK's WMP path (`OpenID4xProfile.kt`) has its own openid4x vocabulary
  (`resolving_metadata, awaiting_offer_acceptance, awaiting_tx_code,
  authorization_pending, generating_proof, credential_received,
  matching_credentials, generating_presentation`) — the profile's own
  concern, mapped SDK-side.

The Rust engine's emissions today vs the Go target (extra steps are
harmless — consumers ignore unknown tokens; **missing** steps break progress
UI):

| Go emits (drop-in target) | Rust today | Action |
|---|---|---|
| `parsing_offer` (message) | — | **add** |
| `offer_parsed` `{credential_issuer, credential_configuration_ids, grants}` | `offer_parsed` `{credential_issuer, credential_configuration_ids}` | add `grants` |
| `fetching_metadata` (message) | — | **add** |
| `metadata_fetched` `{credential_issuer, credential_endpoint, display, validated}` | `metadata_resolved` `{credential_issuer, is_signed}` | **rename** + enrich |
| — (AS discovery folded into metadata) | `as_discovered` | keep (extra) |
| `evaluating_trust` (message) | — | **add** |
| `trust_evaluated` `{issuer_trust_evaluated, issuer, trusted, framework, reason, certificates}` | `trust_evaluated` `{issuer, trusted, framework, reason}` | add `issuer_trust_evaluated` |
| `awaiting_selection` `{available_credentials[]}` (auto-selects when exactly one) | — (blinded `first()`) | **gap B1**: emit + auto-select single; multi-config needs the ask |
| `authorization_required` `{authorization_url, expected_redirect_uri, state, …}` / `{type:"tx_code", …}` | `authorization_url` `{…}` | **rename** |
| `exchanging_token` (message) | — | **add** |
| `token_obtained` (message) | `token_received` `{token_type}` | **rename** |
| `requesting_credential` (message) | — | **add** |
| `deferred` `{transaction_id, interval, attempt, max_attempts}` | — (poll loop, no progress) | **add** |
| `parsing_request` (message) | — | **add** |
| `request_parsed` | `request_parsed` | keep |
| `evaluating_verifier_trust` (message) | — | **add** |
| `trust_evaluated` `{verifier_trust_evaluated, verifier, trusted, framework, reason}` | `trust_evaluated` `{verifier, verifier_name, trusted, framework, reason}` | add `verifier_trust_evaluated` |
| — | `transaction_data_validated` | keep (extra) |
| `credential_selection` | `credential_selected` | **rename** |
| `submitting_response` (message) | — | **add** |
| — | `redirect_opened`, `no_matching_credential` | keep (extra) |

## 3. Trust evaluation

Go (`oid4vp.go:507-851`): per-scheme key material → PDP
(`EvaluateVerifierWithContext`, tenant-aware) with an eval-context map
(`client_id_scheme`, response/redirect URIs, trust chain from the JAR
header §5.9.3.6, attestation context) — **PDP error fails closed**; verdict
cached by `verifiedIdentity + ctx hash` (per-scheme identity, §1 above);
when **no PDP is configured** → frontend path: progress
`evaluating_verifier_trust` + `trust_evaluation_required` payload, waits
the `trust_result` action (2 min). OID4VCI likewise
(`oid4vci.go:1313-1460`).

Rust: `Pdp` port `evaluate` only (`EvaluationRequest{subject,
key_material, resource_type}`), fail-closed, **no eval-context**, **no
verdict cache**, **no frontend/trust-result path** (the architecture moves
that behind the port — the adapter's `Pdp` implementation may bridge to
whatever answers, including the user).

| Gap | Action |
|---|---|
| eval-context (scheme, URIs, trust chain, attestation) | **landed (W8)**: `EvaluationRequest.context` — the `client_id_scheme` claim name, `response_uri`/`redirect_uri`, the `trust_chain` from the JAR header (OID4VP §5.9.3.6), the attestation's `attestation_issuer`/`attestation_subject`/`attestation_jwt` (§5.9.3.4) |
| verdict cache | **gap C2**: adapter-side (the core is stateless; the server adapter caches) |
| no-PDP frontend path | **by design** — the port's implementation bridges (documented); the SDK's `Pdp` callback answers |

## 4. Response modes, parsing, OID4VCI, the wire

Aligned after the conformance milestones unless noted:

- Response modes: all four (`direct_post`, `direct_post.jwt`, `query`,
  `fragment`) implemented; JARM negotiation incl. `*_values_supported`
  inference and usable-key selection (§8.3) — suite-validated. **Gap D1**:
  Go sanitizes the response endpoint (http/https only, SSRF break,
  `oid4vp.go:1679-1695`) — Rust posts to whatever the request names.
- Request parsing: URL schemes (`openid4vp:`, `haip:`, `haip-vp:`,
  `mdoc-openid4vp:`, raw query, bare reference), by-value/by-reference,
  request-object `typ` + JWS + `x5c`, `x509_hash` binding — suite-validated.
  Rust is **stricter** (typ-checked; Go never typ-checks) — compatible.
- OID4VCI: offers (by value/URI), both grants, PKCE, PAR + the RFC 7523
  assertion at both PAR and token, tx_code, deferred (5s×60), §11
  notification, DPoP, response encryption — suite-validated on both
  grants. **Gap B1** (selection, landed W6), **gap E1**: the §10
  client-initiated notification **landed (W7)** — the
  `credential_notification` flow over the TTL'd, single-use context
  store; the legacy `wmp.credential.notification` method is WS-era and
  does not carry over.
- Decline/no-match OAuth descriptions: Go sends the **same** description
  (`"The wallet did not fulfil the request"`) for decline and no-match so
  the verifier cannot probe which; Rust sends distinct strings —
  **gap D2**, trivially aligned.
- VCTM protocol: Go registers it; Rust has no family — **gap E2** (out of
  scope until the SDKs' VCTM flows are triaged).

## 5. The adapters (the drop-in boundary)

| Gap | Where | What |
|---|---|---|
| **F1** | `engine-adapter-server/src/ports.rs:151-184` | The server's `Host` is a stub — every ask refuses. The remote mode's Host must bridge the asks to the wallet over WMP (`request_sign`, `request_tx_code`, `request_consent`, `request_match`, `request_vp`, `open_authorization`, `progress` → WMP messages to the client), exactly the seam `engine-switching.md` names ("the server's Host is the remote WMP peer"). **The single largest drop-in gap.** |
| **F2** | `engine-adapter-sdk` | `create_engine` wires **no ports** (no Host, no HttpClient; `take_notifications` returns empty) and exports no `Pdp`/`Clock`/`Rng`/`KeyValue`/`Telemetry` callbacks. The SDK's local mode cannot run a single flow. |
| **F3** | `engine-adapter-sdk` | The UniFFI `Host` lacks `request_signing_key` and `request_attestation` (`engine-ports` has both) — the attestation/DPoP asks can't reach the SDK. |
| **F4** | both SDKs | `WmpUniFFITransport` does not exist in either checkout (the core docs claim "written"); no `org.siros:siros-wallet-core` coordinate; AAR/XCFramework packaging has no CI. |
| **F5** | wallet-frontend | No WMP transport, no wasm module consumption, and the flow result shapes (`issuer_metadata`, `authorization_url`, … in `mapOID4VCIResponse`) would need synthesizing from `wmp.flow.complete` results — a frontend transport to write. |

## 6. The open go-wallet-backend engine PRs (the 2026-11-05 triage)

The scope has moved: **siros-wallet-core is the primary target for WMP
deployment** (wasm, cloud, native); `go-wallet-backend --mode=engine` and
the legacy WS protocol retire together. The open engine PRs on
go-wallet-backend are therefore triaged against the Rust core, their
issues tracked here, and the PRs closed with a reference to the move.
Backend-only PRs (#319 lifecycle — one engine seam, see §6.10; #450, #453,
#479, #533, #536) stay open: they touch `internal/{service,api,storage}`,
not the engine.

| PR | What it adds | Rust core today | Wave |
|---|---|---|---|
| **#163** the WMP bridge | go-wmp v0.13.0 thin bridge: `SessionService` (single-use rotating tokens, owner binding), HTTP+SSE with `id:`/`Last-Event-ID` replay + `410 Gone` + **redaction** (withholds `refresh_token`/`dpop_jwk`), per-request TAC (`Principal{user,tenant,jti,TAC}`; −31002), the OpenID4x profile + step/action translation (3.1.2/3.2.2), sub-flow routing, `wmp.resolve` vctm (six members), typed −31006 data (`{reason, retryable}`), transaction_data −31005, deliver-on-orchestrator −31008 | **Partial**: wmp-core mirrors the go-wmp mechanics (sessionservice, peer, subflow, resolve, −31020); adapter-server has the routes (POST /wmp, WS, SSE). **Missing: the bridge** — the SSE event pump is an empty stub (no `id:`/replay/`410`/redaction), no OpenID4x profile/translation, `Principal` carries no jti/TAC, no Host↔WMP sub-flow bridge (F1), no typed −31006 wire mapping, `wmp.resolve`/`wmp.credential.notification` unserved, no capability advert | **W2 (the keystone)** |
| **#472** sign-stage refusal | `sign_response` `error_code:"SIGN_REFUSED"` ends `RequestSign` immediately: verifier gets `access_denied` (no description, +state), client `flow_error` `PRESENTATION_ERROR` + `details.redirect_uri`; WMP-rejected sub-flow → same answer; nothing of the wallet's text relayed | **Gap**: `request_vp` decline maps to −31006 `{"reason":"engine: declined by the user"}` — **the verifier is never told**; `SubFlowError::rejected()` (wmp-core) exists unused | W3 |
| **#480** auxiliary data v0.1 | `auxiliary_data_supported.{to_wallet,to_issuer}` advert, `AUXILIARY_DATA_UNSUPPORTED` selection refusal, `auxiliary_data_to_issuer`/`_to_wallet` in the proof ask, required `credential_response_encryption` with a `to_wallet` commitment, strict offer decode, HTTP 400 `auxiliary_data_conflict` → `AUXILIARY_DATA_CONFLICT` (never retried) | **Split**: the wallet-side secret rules live in siros-presentation/siros-display (hash_commitment/ssc); response encryption exists. **The engine-side negotiation is absent** — no advert parsing, no selection refusal, no request members, no conflict relay | W4 |
| **#522** issuer entitlement (ARF 6.6.2.3) | After the trust decision: WRPAC/WRPRC registration check per offered configuration (`pkg/issuertrust`), modes `fail`/`warn`/`off`, findings (≤16, truncated) as progress or `ISSUER_NOT_ENTITLED` refusal | **Absent** — only the `-31020` constant exists (`ERR_ISSUER_NOT_ENTITLED`, wmp-core); no rulebook parsing, no engine call site, no findings | W5 |
| **#525** consent component | One transport-independent OID4VP consent component (DCQL vetting `dcql_consent_check`, selection handle, observer) | **Different architecture**: consent is the Host-port ask; decline→`access_denied` exists; DCQL vetting/selection-handle absent | W6 (SDK-side) |
| **#526** entitlement→WMP mapping | `ISSUER_NOT_ENTITLED` → −31020 + `{issuer, issuer_entitlement}` data; `UNTRUSTED_ISSUER` → −31006 `{reason:"untrusted_issuer", retryable:false}`; bounding/filtering of findings | **Absent** (only the code constant) — folds into W5 | W5 |
| **#527** credential_notification flow (OpenID4x 3.4) | The client-initiated notification as a **flow**: context store (bound to the issuance session+principal, single use per `notification_id`, ≤256 ids, TTL 5 min), capability advert, DPoP `sign_client_auth` sub-flow for client-held keys (htu = endpoint without query/fragment), failure reasons, completion gains `notification_endpoint` + `credentials[].notification_id`; legacy method kept | **Landed (W7)**: `oid4vci/notification.rs` — the `credential_notification` flow, the TTL'd single-use context store (`Ports.notifications`), the capability advert (server + wasm), the `-32602` member validation, the `-31006 {reason, retryable}` reasons, the issuance completion's `notification_endpoint` + `notification_id`, the DPoP proof over the stripped htu (the client-held key via `request_dpop_proof`, the engine-held key the fallback). The legacy WS method does not carry over | W7 ✅ |
| **#528** DPoP notification after flow end | The context is spent only after the issuer was actually contacted; a refused/timed-out `sign_client_auth` **restores** it (original expiry); retry until TTL | **Landed (W7)**: the claim/unspend pair — `ForwardOutcome::NotSent` unspends with the original expiry, the seq check never revives a superseded registration, and the retry forwards the same id (tested through the flow) | W7 ✅ |
| **#529** entitlement wiring into the bridge | `errorWire` → #526's mapping; one terminal error per flow (never −31020 and −31006 together); malformed findings dropped, never relayed as a trust result | Nothing to wire until W2/W5 — the rules fold into both | W2+W5 |

### §6.10 The #319 engine seam (the decision: the Rust adapter replicates it)

#319 (wallet-instance revocation) is backend lifecycle work, but its engine
seam — the token cut-off consulted at **every flow start**
(`User.AuthInvalidBefore`), the anonymous-token refusal on oid4vci/oid4vp
flow starts, and the engine session store erased by the cascade — is now
**decided: the Rust adapter replicates it** (the scope moved —
siros-wallet-core is the primary engine, so the guarantee cannot live in a
Go middleware in front of it). Concretely: `bearer_principal` gains the
token's `AuthInvalidBefore` (and the wallet-revocation tombstone), and
`FlowRuntime::start_flow` refuses a flow start whose principal's token
was cut off — the W2 auth wave, alongside the TAC principal (§6.1). Until
that lands, the standalone engine trusts the token's signature only.

### §6.11 The open-issue triage (2026-11-05)

The open go-wallet-backend issues that touch the engine, triaged against
this plan; the issues close and/or refocus to non-engine as the switch
proceeds.

| Issue | What it is | The plan's coverage |
|---|---|---|
| **#432** | WMP routing and replay state shared across engine replicas (follow-up to #163) | **Deployment concern for the Rust server adapter** — the outbox (`outbox.rs`) is per-process in-memory today; a multi-replica deployment needs shared state for the event log (replay) and the flow registry (routing), or sticky sessions. Recorded here; the backend adapter's shared store (Redis, the Go backend's own plan) is the seam — the `Outbox` and `Registry` are the traits to back. |
| **#441** | OID4VP error responses aren't JARM-encoded for `direct_post.jwt` | **A real gap, W3.** The Rust `submit_error_response` (`response.rs:67-84`) posts plain form for every mode — the P0.6 note characterized the Go bug, not the spec. OpenID4VP 1.0 + JARM: in `direct_post.jwt` mode the error response (decline, no-match, transaction-data) is a JWT encrypted to the verifier's key, in the `response` parameter — the same key selection `submit_jarm_response` already uses for the success path. |
| **#478** | `flow_start` accepts a client-generated flow id | Legacy WS protocol — retires with the engine. (The WMP `flow_id` is client-supplied by design; the flow-route claim and the registry's generation counter are the WMP-native collision guards.) |
| **#502** | Credential-data-free consent shape (WMP spec #27) | Covered: **W6** (the consent component). |
| **#511** | The offer's `authorization_server` hint is ignored (MUST NOT proceed on mismatch) | **A real gap, W1-remainder.** OpenID4VCI 1.0/1.1: when the offer's grant carries `authorization_server`, it MUST equal one of the metadata's `authorization_servers` (exact string) — select that AS; a mismatch fails closed. Absent + several advertised: today's first-entry choice, documented. The Rust `oid4vci/mod.rs:153` takes `first()`, ignoring the hint. |
| **#521** | "Last connection wins" is per replica | WS-session-specific — stays backend/legacy. |
| **#530** | Failed DPoP signing burns the notification context | Covered: **W7** (#527/#528 — the spend-after-contact semantics land with the flow). |
| **#415** | The process-local TokenBlacklist | **Mixed.** The engine-handshake piece retires with the engine (the Rust `RevocationChecker` trait in `token.rs` is the seam — the backend adapter implements it against the shared store); the registry piece and the shared store stay backend. |
| **#342** | Carrying wallet-instance identity past login | Engine seam covered: **§6.10** (the token cut-off gate, landed with W2-complete — `Principal.iat`/`auth_invalid_before` + the `TokenGate` trait). |
| **#333** | The lifecycle gate's tokens | Mostly backend; the engine mention is the same **§6.10** seam (covered). |
| **#218** | Lifecycle push notifications | **Needs rescoping for WMP** — the design assumes WebSocket-first; with WMP the push shape needs defining (the SSE stream is the natural carrier, the outbox the natural log). An open design item for the lifecycle wave; not blocking the engine switch. |
| **#444** | `admin_host` and `engine_host` never applied | `engine_host` retires with the engine (no Rust counterpart); `admin_host` stays backend. |
| **#512** | The AuthZEN proxy resolving the wrong authorization server | Backend (the `/v1/evaluate` proxy route); the engine's `Pdp` port is unaffected. |
| **#445** | Trust doc comments | Backend. |

### §6.12 W4's design survey — Credential Auxiliary Data v0.1 (#480, surveyed 2026-11-05)

The Go implementation (`feat/aux-data-secret-members`,
`internal/engine/auxiliary_data.go`, 583 lines + a 1084-line test)
surveyed against this core. Spec: nym_auth_rulebook PR #12 (Credential
Auxiliary Data v0.1) §§3–7. **The engine never handles a secret value**:
an issuer delivers it in an encrypted response the client decrypts;
`auxiliary_data` is the one credential_metadata member that carries
Secret Values (§8.4) — the engine decides from the advertisement alone
whether the response MUST be encrypted.

**The pieces to port (the W4 wave):**

1. **`auxiliary_data_supported` parsing (§5, `parseAuxiliaryDataSupported`)**:
   an object with at least one of `to_wallet`/`to_issuer`, each a
   non-empty array of entries; an entry is an object with a string
   `type`; at most one entry per (type, path); `to_issuer` entries may
   carry a boolean `required` (a `required` in `to_wallet` is
   malformed); a `hash_commitment` entry needs a string `alg` and a
   valid claims path (OpenID4VCI App. C: a non-empty array of strings,
   nulls, non-negative integers), and MUST NOT carry `opening` or
   `commitment` at any depth (values, never metadata). An unrecognised
   type is ignored (§3) — only its `required` is read, and only in
   `to_issuer` (a required entry the wallet cannot send makes the
   configuration unusable).

2. **`secretDelivery` — what the engine takes from one configuration**
   (`secretDeliveryOf`): `requireEncryption` (any `to_wallet`
   `hash_commitment`: §7.1, a Secret Value MUST NOT travel unencrypted
   — the credential response encryption becomes required);
   `to_issuer` (the verbatim entries the wallet can send — a
   `hash_commitment` entry with unsupported `alg` or `encoding` is
   dropped, or the whole config refused when it is `required`);
   `toWallet` (verbatim, for the client's own response checking, §7.2);
   `unusable` (why not); `requiredToIssuer` (a proof that can carry
   auxiliary_data is needed: the config must declare a `jwt` or
   `attestation` proof type, `carriesAuxiliaryData`).

3. **The selection refusal (`configRefusal` → `usable` → the flow)**: a
   `to_wallet` `hash_commitment` with an unsupported `alg`/`encoding`,
   or a required `to_issuer` entry the wallet cannot send (§§4.1, 5)
   → the flow fails `AUXILIARY_DATA_UNSUPPORTED` (the
   `ErrCodeAuxiliaryDataUnsupported` equivalent: a refusal BEFORE any
   authorization or request — at the selection point). A required
   `to_issuer` with no carrying proof type → the same refusal.

4. **The `auxiliary_data` MUST-NOT rule (§7)**:
   `auxiliary_data` MUST NOT appear in issuer metadata
   (`credential_metadata`) — `checkIssuerCredentialMetadata` →
   `errMalformedAdvertisement` (fail closed). A PLAIN response
   carrying it → the flow refuses (the client's secret travelled
   unencrypted, §7.1) — `refusePlainSecretMembers`.

5. **The proof ask carries the aux data**: `auxiliary_data_to_issuer`
   (the verbatim sendable entries) and `auxiliary_data_to_wallet` (the
   advertised entries) ride `generate_proof` — the host places them
   in its key proofs. The engine's one check before forwarding
   (`checkProofsForwardNoOpening`): no `hash_commitment` entry carries
   an `opening` — an opening IS the secret; the engine never relays a
   secret, its own safety property. When `to_issuer` is advertised the
   engine has promised to inspect: a proof it cannot inspect (a
   non-jwt/attestation type, an unreadable JWT, a non-array
   auxiliary_data) is refused, not forwarded unexamined. Whether the
   entries are ACCEPTABLE (§6.4: the same entries in every proof, the
   path/alg match, the commitment length, every required entry sent)
   is the issuer's — deliberately not re-implemented, so the two
   cannot drift.

6. **The conflict relay**: an issuer HTTP 400 whose body carries
   `auxiliary_data_conflict` → the flow error
   `AUXILIARY_DATA_CONFLICT` (a fixed message, the issuer's own
   operator-reset text never retried) — the client is told what to do,
   not retried.

7. **Strict offer decode (`pkg/strictjson`)**: the credential offer
   decodes with unknown-member rejection (the superseded SIROS secret
   shapes — `secret_seed`, `holder_commitments`, `psc` — are ordinary
   unknown members now).

**The Rust shape (the plan):** a new
`engine-core/src/oid4vci/auxiliary.rs` — `SecretDelivery::of(config)`
(the parsed advertisement + the usability verdict), the selection
refusal threaded into the flow after `trust_evaluated` (before the
grant dispatch), the `auxiliary_data_to_*` members on the proof ask
(the `request_sign` path carries them), the `opening`-check on the
proofs before forwarding, the `refuse_plain` check on the response,
and the conflict relay on the 400. The `VpResult`-style ports follow:
whatever the host needs to carry aux entries into its proofs rides the
existing sign ask. The suite evidence: the mini-wallet's host places
the entries in its proofs; the vectors pin the advert parse and the
three refusals (unusable, required-without-proof-type, plain-secret).

## 7. The fix waves (revised after the PR and issue triages)

1. **W1 — engine-core parity: COMPLETE.** The step vocabulary, scheme
   enforcement, description/sanitization alignment — landed with vectors +
   wasm self-test. **#511 — the offer's `authorization_server` hint**
   (`select_as_url`, both grant paths + the resume): a grant-level hint
   MUST match a metadata entry exactly (else fail closed); absent + several
   advertised: the documented first-entry choice. **The `awaiting_selection` step + the
   multi-config `select_credential` action path** — landed with W6
   (the consent/selection wave).
2. **W2 — the bridge (#163): COMPLETE.** ✅ the SSE event pump (`id:`
   lines, `Last-Event-ID` replay, `410 Gone`, the
   `refresh_token`/`dpop_jwk`/`dpop_key_id` redaction, and the replayer
   — `wmp.session.resume`'s `missed_messages` counts from the same
   log); ✅ `wmp.resolve` vctm serving (the six-member projection,
   `-32603` with `metadata_fetch_error`, `-32602`); ✅ **the Host↔WMP
   sub-flow bridge (F1)** — every engine ask (sign, signing_key, match,
   consent, tx_code, presentation, dpop_proof, attestation,
   authorization) rides a child flow (`<parent>::<type>::<n>`), its
   completion routed back through the peer's registry, with the Go
   per-ask timeouts and the cancel-on-timeout; ✅ the typed −31006 wire
   data on the trust refusals; ✅ the flows capability advert on the
   server's session create (§10.3); ✅ **the OpenID4x action translation
   (3.1.2/3.2.2)** at the adapter — `authorize`→`authorization_complete`,
   `select_credentials`→`select_credential`, `provide_tx_code`→
   `provide_pin`, `accept_offer`→`consent`, unknown actions pass
   through; ✅ **the TAC principal** — `Principal` carries `jti`/`tac`
   (+ the lifecycle claims), the flow-start gate enforces the Go
   `requiredTACForProtocol` map (`oid4vp`→`r`, `oid4vci`→`i`), only
   when the principal carries a TAC (the legacy-auth empty-TAC shape
   does not enforce); ✅ **the #319 seam, the flow-start half**
   (§6.10): the anonymous principal refuses engine flow starts with
   `-31002`, and the token cut-off gate — `Principal.iat`/`auth_invalid_before`
   (stamped by `bearer_principal` from the token) + the `TokenGate`
   trait (stateless claim check + the store-backed half, default
   `NoTokenGate` for the standalone deployment, the backend adapter
   implements it) — refuses a principal whose token was cut off.
3. **W3 — COMPLETE (#472 + #441)**: the sign-stage refusal — `request_vp`
   decline/refusal answers the verifier `access_denied` at once
   (`invalid_transaction_data` for the transaction-type refusal), the
   client's completion carrying `declined:true` + the verifier's
   redirect; and the JARM error responses — `submit_error_response`
   dispatches on the mode exactly as the success path does
   (`direct_post.jwt`: the error claims `iss`/`aud`/`exp`/`error`/
   `error_description`/`state` encrypted with the success path's key
   selection, in `response=<jwe>`; `query`/`fragment`: the error
   redirect; `direct_post`: the plain form). `VpResult` carries the
   optional `SignRefusal` across the ports, the wasm mini host, the
   SDK mirror, and the conformance world.
4. **W4 — COMPLETE (#480, engine half)**: the advert parse (§5) and the
   usability verdict (§§4.1, 5) in `oid4vci/auxiliary.rs`; the selection
   gate before any authorization or request (start + resume); the proof
   ask carrying `auxiliary_data_to_issuer`/`_to_wallet` (§6 — the engine
   builds the proof TBS, so no opening can enter structurally); the
   §7 metadata rule and the plain-secret check (§7.1); the conflict
   relay (§8). The engine never handles a secret value. Design survey
   §6.12. **The strict offer decode landed (W9)**: the third-party
   offer documents (the `credential_offer` URI parameter, the fetched
   offer, the inline form) refuse unknown members
   (`OfferError::UnknownMember`); the by-value params form — the
   wallet's own merge — stays lenient, exactly as the Go engine's
   always-own-document differs.
5. **W5 — COMPLETE (#522/#526/#529, the core's half)**: the
   entitlement wire shapes on the `Pdp` port (`engine-ports`: the
   warn/fail/off mode parsed with warn as the default, the twelve
   finding codes, the decision with its bounded relay form, the
   not-evaluated answer, `Pdp::evaluate_entitlement` with a
   `NotImplemented` default); the call site in `oid4vci/entitlement.rs`
   (the request: the raw document — `issuer_info` rides it unmodelled,
   ETSI TS 119 472-3 — the signing key material as the trust decision
   received it, the offers with the type each format counts, the Go
   `OfferFor`); the flow wiring (start + resume, after the trust
   decision, before the grant dispatch; the trust refusal answers
   first, so never both refusals for one flow); the additive
   `trust_evaluated` progress (`issuer_entitlement_evaluated`, never
   `issuer_trust_evaluated`, no `trust_info`); the −31020 refusal with
   the bounded decision. `IssuerMetadata` carries the raw document as
   resolved. The evaluation itself stays behind the port (the backend
   adapter implements it on `go-trust`'s rpcert); the mode lives there
   too. **Remaining: the backend adapter's `evaluate_entitlement`**
   (the WRPAC/WRPRC rulebook evaluation on `go-trust`'s rpcert,
   mirroring `pkg/issuertrust`) — lands with the adapter work in W9.
6. **W6 — COMPLETE (the consent component #525 + the selection)**:
   `oid4vp/consent.rs` — the DCQL vetting of the host's match answer
   (the Go `checkConsentAgainstDCQL`, its fixture table ported case
   for case): the four reason classes, `always_disclosed`, the bounds
   (a 32-element path, a 512-byte entry, a 64-character logged id),
   the bare and `.`-joined entry spellings, the memoised wildcard
   matcher, the `credential_sets` options constraint. The mode
   (`presentation.dcql_consent_check`: off/warn/enforce, the default
   warn) rides `Ports` — `engine_ports::ConsentCheckMode`. Warn
   records the violation (telemetry: the reason class and the query id
   alone, never a claim name) and proceeds; enforce answers the
   verifier `access_denied` before the consent UI is asked — the
   two-ask split vets at the match answer, where the Go single ask
   vets after. The transport's selection handle (OpenID4x 3.2.3.1)
   rides `MatchResult.handle` into `VpParams.selection_handle`,
   unchanged. `oid4vci/selection.rs` — the `awaiting_selection` step
   and the host ask (`Host::request_credential_selection`, default
   refusal): exactly one resolvable configuration auto-selects (no
   progress, no ask); more emits the progress with the
   `available_credentials` (the Go wire names) and asks. The answer is
   constrained to the offer — stronger than the Go engine's
   metadata-wide check — because the entitlement check evaluated the
   offered configurations: a selection outside the offer refuses. The
   auth-code stash carries the selection; the resume requests the
   stashed configuration, no second ask. The selected configuration
   threads the auxiliary gate, the authorization request (the scope)
   and the credential request — the blinded `first()` is gone.
7. **W7 — COMPLETE (the notification flow #527/#528)**: the
   `credential_notification` flow (`oid4vci/notification.rs`,
   registered on the server, the wasm dispatcher and the conformance
   runner); the context store (`Ports.notifications`, in-process,
   never persisted — the access token rides it): the 5-minute TTL,
   the single-use claim per `notification_id` bound to the issuance
   session, the ≤256 blind ids, the spend-after-contact rule (#528:
   `NotSent` unspends with the original expiry, the seq check never
   revives a superseded registration), the 32-forward backpressure
   (busy, retryable, the context kept); the start's validation
   (OpenID4x 3.4.1's bounds, the `-32602 {member}` refusals); the
   forward (the §10 body to the full endpoint, the DPoP proof over the
   endpoint without query/fragment — the client-held key via
   `request_dpop_proof`, the engine-held key the fallback — the nonce
   retry, 204/200); the reasons (context_unavailable, busy,
   signing_failed, forward_failed, timeout) on `-31006
   {reason, retryable}`; the issuance completion registers and gains
   `notification_endpoint` + `notification_id`; the capability advert
   (`credential_notification: {events, context_ttl_seconds}` on the
   server and the wasm dispatcher — the runtime gate answers `-31005`
   without it). The server's runtime now registers its families
   (oid4vci, oid4vp, credential_notification — it answered `-31005`
   for everything before).
8. **W8 — COMPLETE (trust plumbing, §1 + §3)**: the eval-context map on
   `EvaluationRequest.context` (gap C1 — the Go
   `buildVerifierEvalContext`: the scheme's claim name, the
   response/redirect URIs, the JAR header's `trust_chain`
   (OpenID4VP §5.9.3.6), the whole verifier attestation JWT
   (§5.9.3.4, which the PDP verifies itself), forwarded by the
   server's proxy); the DID resolution (gap A2, the recorded
   architecture): the did-schemed request resolves the DID document
   behind the Pdp `resolve` port (`did_document`), the engine verifies
   the request JWT against the resolved `publicKeyJwk`s, and the
   matched key — not the DID in the abstract — is the key material
   the PDP evaluates; a PDP without DID resolution answers best-effort
   (the documented transition), a failed one fails closed; the
   per-scheme key material (the x.509 schemes' `x5c` chain as the
   header carried it, the attestation's `cnf.jwk`, the best-effort
   chain x5c > the metadata's jwks > the request JWT header's jwk).
   The parser retains the raw request JWT, the chain and the
   attestation on `AuthorizationRequest` for the evaluation.
9. **W9 — IN PROGRESS (the Rust half landed)**: **the strict offer
   decode** (the folded W4 remainder — see W4's entry); **the
   peer↔runtime cycle fixed at the root** — `FlowRuntime::set_peer`:
   the server's placeholder dance left its handler dispatching to a
   runtime over a dead placeholder peer with no families (every flow
   start answered -31005, and even registered families would have
   sent their notifications nowhere) — one runtime now, the real peer
   swapped in before any flow can start; **the F2/F3 wiring** —
   `create_engine` over the full ports (the SDK's Host/HttpClient/Pdp
   callbacks bridged to `engine-ports`, the built-ins, the three flow
   families, the capability advert, the tokio runtime, the
   notification channel with `take_notifications` and the blocking
   `read_notification`); **the real e2e at the adapter**
   (`engine-adapter-sdk/tests/engine_e2e.rs`): the session create with
   the capability negotiation, an issuance flow through the bridges,
   the completion — with W7's notification members — read from the
   channel the transport polls, and the no-PDP fail-closed.
   **The rest landed**: the **packaging CI** (ci.yml's
   `xcframework`/`aar` jobs — the recipes verified on every push;
   the first runs found and fixed the v4 input change of
   setup-android and the BSD `wc` padding); the **real e2e**
   (`engine-adapter-server/tests/e2e.rs` — a wallet client driving a
   complete pre-authorized issuance and its credential_notification
   flow through the HTTP+SSE binding, the child asks answered from
   the stream while the parent POST is in flight, the PDP proxy, the
   issuer fetches through ServerHttpClient — the drive found and
   fixed the credential asks' constant flow id);
   the **SDK transports** opened as PRs:
   [siros-sdk-kotlin#383](https://github.com/sirosfoundation/siros-sdk-kotlin/pull/383)
   (the bindings vendored source + `WmpUniFFITransport` + the tests,
   which run where the native library loads and skip on a plain JVM)
   and
   [siros-sdk-swift#264](https://github.com/sirosfoundation/siros-sdk-swift/pull/264)
   (the same, `#if canImport`-gated so the package builds everywhere
   today). **Remaining: the first `siros-wallet-core` release tag**
   (the owner's call) — the release workflow builds the
   XCFramework/AAR artifacts; the Swift PR's `binaryTarget` line +
   checksum lands with it.

**The deployment notes (§6.11):** #432 — a multi-replica deployment needs
shared WMP routing/replay state (the outbox and the flow registry are the
seams; Redis behind both, or sticky sessions until then). #218 — the
lifecycle push design needs its WMP rescoping (the SSE stream is the
natural carrier). Neither blocks the switch; both land with the backend
adapter's shared store.

The suite evidence stands: everything in §4 marked suite-validated is green
against the OIDF plans (four OID4VCI + OID4VP variants incl. HAIP and
iso_mdl) with `oidf`-provenance vectors pinning each wire.
---

## 8. The tenant-bound remote principal (W10 — proposed 2026-11-06)

**The proposal:** the REMOTE engine (the HTTP+SSE binding; the container
deployment) consumes **tenant-bound** tokens instead of user-bound ones.
Privacy is the driver: the engine is infrastructure — it relays offers,
proofs and credentials between wallets and issuers/verifiers, and every
user-bound token it validates today attributes that traffic to a person in
its logs, its KV flow registry and its session store. A tenant-bound token
removes the person from the engine entirely.

**The analysis — where the engine actually depends on the user.** The
complete `Principal.subject` dependency surface (audited 2026-11-06):

| Use | Where | Tenant-bound status |
| --- | --- | --- |
| Authentication gate | `is_authenticated()` = non-empty `subject` (session create + every flow start) | Needs a non-user `sub` (G3) |
| Session ownership | `principal.key()` = `tenant/subject`; resume/close/extend check it (`sessionservice`) | Must become tenant-keyed (G1) |
| The #319 token cut-off | `TokenGate.auth_invalid_before(subject, tenant)` (the engine's §6.10 seam) | Per-user keying dissolves (G2) |
| The PDP contract | — | **No user anywhere**: subjects are the issuer/verifier (`ports.rs` binds `{type:"key", id: <issuer|verifier>}`) |
| The flows, the asks, the completions | — | **No user anywhere**: the asks go to the wallet's Host/callbacks over the session's own channel; the flow state is per-flow; the redaction withholds the renewal material from replay |

The proposal's premise holds: **nothing in the engine's flow execution
attributability needs the user.** The user-bound tasks (consent UI,
matching, signing, storage) are the frontend/SDK's; the engine only needs
to know "an authenticated principal of tenant T may run flows, and this
session belongs to that principal".

### The gaps and issues

- **G1 — session ownership and resume.** Sessions are owned by
  `tenant/subject`; a token whose `sub` is a pseudonym minted per token
  (or the tenant itself) breaks `session_resume`'s ownership check (a
  fresh pseudonym ≠ the one that created the session). **Fix:** in tenant
  mode the session's owner key is the **tenant**; the per-session security
  is the **resumption token** (single-use, rotated on every resume —
  already enforced), not the subject. Cross-user hijack within a tenant
  reduces to stealing the resumption token — the same attack as today
  with a user token.
- **G2 — the #319 cut-off loses its key.** The per-user
  `auth_invalid_before` is the engine's only per-user dependency beyond
  G1. In tenant mode the gate keys the **tenant** (a tenant-wide cut-off)
  or falls back to per-token **`jti` blacklisting**
  (`with_revocation` exists, unwired). **The accepted risk** (owner's
  words): a non-revocable short-lived tenant-scoped token may lie around
  for its TTL. Mitigation: short TTLs (the GDC AS already mints ~120 s
  tokens) + the jti blacklist as the cheap per-token revocation.
- **G3 — the AS token shape.** `is_authenticated` requires a non-empty
  `sub`; the AS's anonymous kind mints none. **Fix:** a new token kind
  (beside `TOKEN_BACKEND`/`TOKEN_ANONYMOUS`): `sub` = a **random
  pseudonym** (per mint — rotating with the TTL, so it identifies nothing
  and cannot be correlated across mints), `tac ⊇ "ri"` (both flow types
  gate on it), tenant claimed as today. The engine's wire handling is
  then **unchanged** — only G1's owner keying and G2's gate keying move.
- **G4 — audit.** Engine-side per-user attribution disappears (the
  privacy win); per-user audit stays where the user actually is — the
  backend/AS. Acceptable by design.
- **G5 — the #319 interplay.** #319's **backend** halves (the login
  gate, the erasure cascade, the instance model) are orthogonal and
  unaffected. Its **engine seam** (§6.10) collapses: the Rust engine in
  tenant mode needs no per-user cut-off propagation at all — hold #319's
  engine-propagation stack until W10 decides the mode per deployment
  (`ENGINE_PRINCIPAL_MODE=user|tenant`, default `user` for
  backwards-compatible deployments, `tenant` for the privacy-preserving
  remote one).
- **G6 — the SDK side.** `WmpHttpSseTransport.tokenProvider` mints per
  request (the freshened bearer); switching the WMP modes to the tenant
  kind is a one-line `ensureTenantToken()` beside `ensureBackendToken()`
  (the LEGACY_WS Go path keeps user tokens — go-wallet-backend is not
  changing here).

### The shape of W10

**Landed 2026-11-08** — every step, in this order: engine
`3345cf3`→`b52b9f7`→`3a78934` (`PrincipalMode` on the Principal, the
transport stamps it from `ENGINE_PRINCIPAL_MODE`, the #319 gate's
store-backed half keys the tenant via
`TokenGate::tenant_auth_invalid_before`, `JtiBlacklist` wired into the
validator with `EngineServer::revoke_jti`); AS `go-wallet-backend
4b811641` (the `pseudonymous` token kind — `issueToken` splits the
policy subject from the minted subject, the minted `sub` is a fresh
`p-<uuid>` per mint, `tac` capped to `ri`); Kotlin
`siros-sdk-kotlin#385` (`TokenKind.pseudonymous`, `TOKEN_WMP_ENGINE`,
`ensureTenantToken()`, `AuthServerClient.requestPseudonymousToken`,
`WalletConfig.wmpTenantTokens` — the `HTTP_SSE` provider mints per the
flag); Swift `siros-sdk-swift#266` (the same mirror); deployment
`sirosid-dev` `deploy.py` (the GDC/Fly engine overlay sets
`ENGINE_PRINCIPAL_MODE=tenant` — read by the next engine image; the
local compose keeps the default user mode). The SDK flag
(`wmpTenantTokens`) must match the deployment's engine: a tenant-mode
engine with user tokens keeps its sessions but loses the privacy
point; a user-mode engine with pseudonym tokens strands every session
at the token's mint.

1. `wmp-core`: `Principal` gains a mode flag (or the owner key becomes
   tenant-or-subject per configuration) — the sessionservice's ownership
   checks follow it. Tests: a tenant principal resumes a session a
   different pseudonym created; a cross-TENANT resume still refuses.
2. `engine-adapter-server`: `ENGINE_PRINCIPAL_MODE` (default `user`);
   `tenant` mode keys the gate tenant-wide and wires the jti blacklist.
   Tests: both modes' flow-start gates.
3. `sirosid-dev`: the AS token kind (`sub` = pseudonym, `tac` = "ri").
4. `siros-sdk-kotlin`/`-swift`: `ensureTenantToken()` for the WMP
   remote modes.
5. Deployment: the GDC/Fly overlay sets `ENGINE_PRINCIPAL_MODE=tenant`.

**Priority:** after the current SDK wave lands (the Kotlin drive is
mid-flight; the Swift mirror and the merges follow). W10 then gates the
**#319 merge decision** — the owner's call at merge time: merge #319's
backend halves on their own merits, hold its engine seam for W10.

**Not in scope:** the local (in-process) mode — the AAR/XCFramework runs
in the wallet's own process; there is no third party to hide the user
from, and the Host callbacks already carry the wallet's own context.
