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
| `redirect_uri` | default; no signature requirement; best-effort key material from `client_metadata` (x5c > jwks > jwks_uri), else unverified JWT header extraction | recognized; JWS verified under `x5c` when present; no key-material extraction | **aligned on acceptance**; key-material enrichment → §3 trust |
| `did:` | `did:` and `decentralized_identifier:` both infer; server-side DID resolution (`TrustSvc.ResolveDID`); JWT must verify against ≥1 resolved key | `did:` infers; **no `decentralized_identifier:` prefix**; no resolution — trust goes straight to the PDP | **gap A1** (prefix); **gap A2** (resolution — architectural, see below) |
| `x509_san_dns:` | JWT-required; JWS verified pre-cache (`:1986-1994`); key material must be `x5c`; SAN↔DNS binding delegated to the PDP | JWS verified under `x5c` when present; **unsigned/chainless accepted** | **gap A3**: enforce the signed+x5c requirement |
| `x509_san_uri:` | falls into the default best-effort path (no dedicated handling) | same (recognized, no dedicated path) | **aligned** (both best-effort) |
| `x509_hash:` | JWT-required; JWS verified; the hash↔leaf binding **left to the PDP** | JWS verified; **hash↔leaf binding checked in-engine** (constant time; unsigned/chainless refused) | **aligned** (Rust stricter; the PDP check is redundant but compatible) |
| `verifier_attestation:` | attestation extracted from the request JWT's `jwt` header param (`pkg/trust/jwtutil.go:93-168`): `iss`/`sub`/`cnf.jwk` required, request JWT signature verified against `cnf.jwk`, `sub` must equal `client_id` minus the prefix; attestation key material → PDP | recognized; **no handling** | **gap A4**: extraction + `sub` check + signature verification |

**A2 (DID resolution) — the architectural decision.** The Go engine resolves
the DID document server-side and verifies the request JWT against the
resolved keys before the PDP decides trust. The Rust core's `Pdp` port
already carries the `/v1/resolve` shape (`ResolveRequest{uri,
resource_type}`), and the wasm/mini host answers it always-trusted. The
alignment decision, recorded here: **the DID document resolution moves
behind the Pdp port** (`resolve` with a `did_document` resource type), with
the **engine verifying the request JWT against the resolved keys** once the
port returns them — the same split the Go engine makes between resolution
(`TrustSvc`) and trust (`evaluate`). Until a `Pdp` implementation answers
`did_document` resolutions, the engine treats a `did:`-schemed verifier as
best-effort (the current behavior), the same way an unconfigured PDP fails
closed. *(Open: extend `ResolveResponse` with the DID verification methods,
or return the raw document and verify engine-side — preferred, the latter.)*

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
| eval-context (scheme, URIs, trust chain, attestation) | **gap C1**: extend `EvaluationRequest` with a context map |
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
  grants. **Gap B1** (selection), **gap E1**: §10 client-initiated
  notification (Go registers a TTL'd notification context and forwards the
  client's later `credential_notification`; the SDK's WMP layer has
  `wmp.credential.notification`).
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

## 6. The fix waves

1. **Engine-core parity (this wave)**: the step vocabulary (§2 renames +
   additions incl. `awaiting_selection` + auto-select), scheme enforcement
   (`decentralized_identifier:` prefix, x509_san_dns JWT+x5c requirement,
   verifier_attestation extraction/check), decline/no-match description
   alignment, response-endpoint sanitization. Vectors updated.
2. **Trust plumbing**: the eval-context map on `EvaluationRequest`; DID
   resolution behind `resolve` + engine-side JWT verification (§1 A2).
3. **Server adapter**: the WMP Host bridge (F1) — the remote drop-in.
4. **SDK adapter**: port wiring + the missing Host callbacks (F2, F3).
5. **SDK/frontend integration** (F4, F5) + real testing: the SDK transports,
   the frontend wasm transport, then end-to-end against the deployed stack.

The suite evidence stands: everything in §4 marked suite-validated is green
against the OIDF plans (four OID4VCI + OID4VP variants incl. HAIP and
iso_mdl) with `oidf`-provenance vectors pinning each wire.