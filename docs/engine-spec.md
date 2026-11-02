# Rust WMP Engine: Specification and Spike Plan

Oct 28, 2026 · @Leif Johansson

Draft for review. This document specifies a Rust implementation of the SIROS wallet engine, starting with a spike that proves one slice end to end. It is written so that an agent with no other context can pick it up.

## Status and decisions

Status: draft for review. No Rust code exists yet. The intent is a Rust engine core that replaces the Go engine, built once and used in two places: inside the native SDKs and as a standalone container (possibly inside a TEE). The backend replacement is gated on the spike; the SDK side is the committed target. The core is also built to extend beyond OpenID4: other WMP flows, such as QERDS (registered delivery) or agentic and MCP flows, must be addable without changing the runtime. OpenID4 is where the work starts, not where it ends.

| Decision | State | Source |
| --- | --- | --- |
| One Rust core replaces the Go engine, in the SDKs and in the backend, with no Go involved | Intended end state; backend replacement is gated on the spike result | Owner, 2026-10-28 |
| The engine runs in separate containers, possibly in a TEE, to reduce privacy-leak risk | Target ops model | Owner, 2026-10-28 |
| WMP only: the in-SDK engine speaks WMP, not the legacy WebSocket protocol | Decided | Owner, 2026-10-27 |
| Trust evaluation stays remote (AuthZEN PDP); the core may call the PDP directly instead of the backend proxy | Intended; PDP authentication will use our usual JWT tokens (go-tokenauth; go-trust needs a small addition), and the proxy's policy gate is open (see Resolvers) | Owner, 2026-10-28 |
| Resolvers (the calls behind the engine's /resolve endpoint) are implemented in the core | Intended | Owner, 2026-10-28 |
| First test vectors are generated from go-wallet-backend, with an explicit sunset | Decided; see Phase A | Owner, 2026-10-28 |
| After the spike, real integration tests run against the OpenID conformance suite in Docker | Decided; see Phase B | Owner, 2026-10-28 |
| Splitting the Go engine into its own process or image first | Dropped: --mode=engine already exists and the split gains nothing for this effort | Owner, 2026-10-28 |
| gomobile embedding spike (E1) | On hold since 2026-10-27; superseded if this proceeds | Owner |
| Never switch between engines mid-flow; switch only after explicit user confirmation | Decided | Owner, 2026-10-21 |

**Review answers on the risk table (2026-10-29), now part of the plan:**

- **Start condition.** The spike starts only when the WMP work has landed in the current Go engine (go-wmp v0.12.0 and the rework of go-wallet-backend PR 163). The reference must be still before vectors are generated from it.
- **Container host in parallel.** The in-backend host, the Rust engine running in a container, is developed in parallel with the in-SDK host, so test environments can run the Rust engine as a container. The conformance runs use that host.
- **Existing Rust libraries first.** Evaluate the libraries behind Kushal Das's projects (`tunnelbana`, `bergshamra`, `gamlastan` and what they build on) before writing any JOSE, OAuth or DPoP code. See the library notes under Architecture.
- **TEE hosting needs its own analysis,** as a separate task outside the spike.
- **Pace.** There is plenty of Rust skill in the organisation, but the spike and the initial phases will be pushed fast with AI-controlled coding. Security-relevant code still gets human review.
- **The seam's proof flow** is an MCP integration flow (the answer given was "MCP integration"); see step S0.

Open decisions that block or shape the spike are collected under Risks and open questions. The ones to settle first: where the code lives, the details of PDP tokens (authentication will use our usual JWT tokens validated with go-tokenauth; go-trust does not support this yet), and which OIDF test plans are the gate.

## Context

### What the engine is today

- **Where it lives.** The engine is part of [go-wallet-backend](https://github.com/sirosfoundation/go-wallet-backend), a Go service. One binary, and `--mode` selects the roles it runs: `backend`, `registry`, `engine`, `admin`, `auth`, `wallet-provider` (comma-separated, or `all`). `--mode=engine` already runs the engine as its own process; it fetches the authorization server's signing keys from `as.external_url` and, with the shared Mongo revocation store, rejects tokens the backend revoked.
- **Size.** `internal/engine` is about 12.7k lines of non-test Go (origin/main `373e7959`, 2026-10-30): `oid4vci.go` 3.5k, `oid4vp.go` 3.2k, `session.go` 1.8k, `messages.go` 1.0k, plus `oid4vci_blind_response.go`, `oid4vci_request_encryption.go`, `oid4vp_consent.go` and `verified_request.go`. The resolver and trust side adds about 3.9k more across `internal/api/authzen_proxy.go` (1.4k), `pkg/issuermetadata/resolver.go` (1.1k), `pkg/oidc` (1.1k) and `pkg/trust/authzen` (340). An earlier revision of this document said 8.7k engine and 6.3k resolver lines; the engine number was stale and the resolver number was never reproducible by any non-test accounting.
- **What it does.** The engine runs OpenID4VCI issuance and OpenID4VP presentation on behalf of a wallet client that holds the keys. It parses offers and requests, fetches issuer, authorization-server and verifier metadata, evaluates trust, talks to the issuer or verifier endpoints, and asks the client to sign (key proofs, the VP token) and to consent. The legacy WebSocket protocol carries `handshake`, `flow_start`, `flow_action`, `sign_response`, `match_response` and `credential_notification` from the client, and `handshake_complete`, `flow_progress`, `flow_complete`, `flow_error`, `sign_request`, `match_request`, `push`, `error` and `notification_ack` from the engine.
- **Blind encryption.** Since go-wallet-backend PRs 469 and 471 (see `docs/engine-blind-encryption.md`), in the encrypted modes the client decrypts issuance responses and builds the encrypted presentation response. The engine still sees metadata (which issuer or verifier, timing, IP) but not credential contents. A remote engine is therefore honest-but-curious; it is not a defence against an actively malicious engine that substitutes keys.
- **Trust.** The engine's preferred path is a direct server-side PDP call (`TrustSvc.EvaluateIssuer` / `EvaluateVerifierWithContext`); the backend-proxy round-trip (`POST /v1/evaluate` and `POST /v1/resolve`, which validates the wallet's session token, authorizes the query against SPOCP policies, looks up the tenant's PDP URL, and forwards) is the legacy fallback, reached only when no issuer PDP URL is configured. The proxy's own `/v1/evaluate` and `/v1/resolve` are what the SDK's `BackendProxy` Pdp port will speak, because they are what a remote caller can reach.
- **WMP.** The Wallet Messaging Protocol is the successor to the legacy WebSocket protocol. The spec is [wmp](https://github.com/sirosfoundation/wmp) with test vectors in `vectors/*.json`. The Go library is [go-wmp](https://github.com/sirosfoundation/go-wmp) (v0.11.0 released, v0.12.0 in progress). The client-side JS library is [wmp-js](https://github.com/sirosfoundation/wmp-js). The backend's WMP adapter is go-wallet-backend PR 163, which is being reworked on go-wmp's seams. One requirement from that rework (E0): the engine-to-WMP bridge must be callable without an HTTP request, with the principal passed in, so an in-process caller can drive it.

### Why a Rust core

- **One implementation, two deployments.** In-process in the Kotlin and Swift SDKs (the answer to an active relay on native, since the operator is then out of the path), and as a container on the server side.
- **TEE and TCB.** A static binary with no garbage collector and few dependencies is a smaller trusted computing base than a Go runtime plus the current engine dependencies, and a pinned toolchain gives reproducible builds that an attestation measurement needs.
- **Web.** A browser cannot embed an engine, because CORS stops it from fetching issuers, verifiers and DID hosts. An attested TEE engine is the only route to a meaningful guarantee for web.
- **Rust is already here.** `siros-wscd-manager` (UniFFI, including the CTAP2 logic), the longfellow ZK crates and the DC API matcher are Rust. With a Rust engine, sign requests to the wallet become in-process calls instead of Go to host to Rust.
- **Fewer WMP clients.** The WMP client logic exists three times (Kotlin, Swift, wmp-js). A shared Rust WMP crate, which this work needs anyway, can replace the native duplicates. That crate is also useful on its own.

### Why not gomobile

Gomobile gives one engine with no port, and it stays the fallback. Its costs: a second runtime and FFI toolchain beside UniFFI, a Go runtime and heap in every app, DNS and CA behaviour on Android that was never verified, and Go-to-host-to-Rust crossings for signing and ZK. The gomobile spike (E1) has been on hold since 2026-10-27.

### Decisions carried over from the embedded-engine work

- WMP only for the in-SDK engine; the legacy WebSocket path stays on the remote Go engine.
- Trust stays remote. In v1 the embedded engine uses the backend's AuthZEN proxy with the wallet's session token, supplied at runtime by the SDK. Local trust evaluation with prefetched registries is a later consideration, not ruled out; keep the guarantee-level enum extensible.
- A flow lost when the app is killed is accepted in v1. System trust roots only, no user-installed CAs.
- Never switch engines mid-flow. A switch between remote and embedded happens only after explicit user confirmation, never silently.
- Pairing with blind encryption: the TEE protects the metadata the engine still sees; blind encryption protects contents. Neither replaces the other.

## Goals and non-goals

### Goals

1. A Rust engine core that implements OpenID4VCI issuance and OpenID4VP presentation behind WMP, with behaviour verified against the OpenID conformance suite and not only against the Go engine.
2. One core, two adapters: in-process in the native SDKs (UniFFI for Kotlin and Swift), and a standalone server binary suitable for a minimal container image and for a TEE.
3. Clean interfaces. The core has no knowledge of tenants, HTTP routers, Mongo, Redis or WebSockets; everything environmental is a port (see Ports). Protocol logic is also separated from the flow runtime, so a new WMP flow type can be added without touching the runtime (see Beyond OpenID4).
4. Resolvers (issuer metadata, authorization-server metadata, offer-by-reference, key material) implemented in the core, so an in-SDK engine needs no resolve call to the backend.
5. A PDP client in the core, so the engine can evaluate trust directly when the deployment allows it.
6. A spike that measures real effort and surfaces interop drift between serde-based Rust and the Go engine early, before the full port is committed.

### Non-goals

- Reimplementing the rest of go-wallet-backend (authorization server, wallet provider, admin API, tenant management, storage). The Rust engine is the engine only; it talks to those through ports.
- The legacy WebSocket protocol. It stays on the Go engine until that engine is retired.
- A WASM build of the engine. Browsers cannot fetch issuers and verifiers directly (CORS), so the engine in WASM does not help; the web path is the remote or TEE engine. A WASM build of the WMP client crate is separate and welcome.
- Local trust evaluation and bulk registry prefetch in v1.
- Mid-flow state portability between engines.
- Replacing wallet-side key custody. Signing and consent stay with the client; the core asks for them through a port.
- Bug-for-bug compatibility with the Go engine. The Go engine is a reference for behaviour, not a specification (see Phase A).

## Architecture

The core is a runtime-agnostic library. It never opens a socket, reads a clock or touches a database itself; every environmental effect goes through a port trait. Two adapters supply the ports: one for the native SDKs and one for a standalone server or TEE container.

```
  Wallet host (Kotlin / Swift)                      Server / TEE container
  +------------------------------+                  +--------------------------------+
  | SDK: keys, consent UI, WSCD  |                  | engine-server (tokio, rustls)  |
  +--------------+---------------+                  |  WMP over HTTP+SSE / WS        |
                 | UniFFI                           +----------------+---------------+
  +--------------v---------------+                                   |
  | engine-adapter-sdk           |                  +----------------v---------------+
  |  HttpClient = platform stack |                  | engine-adapter-server          |
  |  Host = sign / consent / ... |                  |  HttpClient = rustls (in TEE)  |
  +--------------+---------------+                  |  Pdp = AuthZEN over HTTPS      |
                 |                                  +----------------+---------------+
                 +-------------------+------------------------------+
                                     |
                        +------------v-------------+
                        | engine-core              |   flows: oid4vci, oid4vp
                        |  resolvers, trust client |   resolvers, validators
                        |  jose / dpop / jwe       |   no tenants, no HTTP router
                        +------------+-------------+
                                     |
                        +------------v-------------+
                        | wmp-core (shared crate)  |   messages, sessions, peer,
                        +--------------------------+   flows, validators, error codes
```

### Crates

| Crate | Role | In the spike |
| --- | --- | --- |
| `wmp-core` | WMP messages, session state, peer, flow contexts, completion and consent validators, error codes. Sans-network. Also the future base of the native WMP clients. | Minimal subset (session, flow start, sub-flow request and answer, progress, complete, error) |
| `engine-core` | A flow runtime (flow registry, sessions, sub-flow routing) plus the OpenID4 flow family on top of it (OID4VCI, OID4VP, resolvers, PDP client, JOSE, DPoP, response encryption). Depends only on the port traits. Flows depend on the runtime, never the reverse, so a family can move to its own crate. | Yes |
| `engine-ports` | The trait definitions and their message types. Kept tiny and stable. | Yes |
| `engine-adapter-sdk` | UniFFI bindings and the host callback interfaces for Kotlin and Swift. | Stub only |
| `engine-adapter-server` | Tokio, rustls HTTP client, AuthZEN client, WMP transport endpoints. | Built in parallel with the SDK adapter; the container host for test environments (the TEE image itself is out of scope) |
| `engine-conformance` | Vector runner, fake issuer and verifier, OIDF harness driver. | Yes |

### Design decisions

- **Async ports, not hand-written state machines.** The flows are long sequences with waits for client answers, which maps naturally to `async fn` over port traits. The core depends on `futures` only, never on Tokio. Fakes for every port give deterministic tests. Recommended; the spike validates it. The alternative, an explicit sans-IO state machine (events in, actions out), is more code for the same testability and is kept as a fallback if async proves awkward over UniFFI.
- **The HTTP port is at the HTTP level in both adapters.** In the SDK the host performs the request with the platform stack, so system roots, proxies and VPNs behave natively. In the TEE the adapter performs it with rustls inside the trusted binary, so the untrusted host never sees plaintext. The core cannot tell which.
- **Time and randomness are ports.** No `SystemTime::now` or ambient RNG in the core, so vectors are reproducible.
- **No Go in the build.** Pure Rust and pinned crate versions; reproducible build with a vendored dependency set; static musl binary for the container.
- **Strict decoding is a policy, not a default.** An earlier revision said the Go engine settles on strict decoding for the credential offer only; the verification found the offer is decoded with plain `json.Unmarshal` on every Go ref, while strict decoding (PR 480's `decodeStrict`) applies to auxiliary-data documents, deferred and error bodies, and proof payloads. The Rust core decides per document type which gets strict handling, records it in the vectors, and never copies Go's inconsistency. Serde is case-exact and last-wins by default, which differs from Go's case-insensitive decoding; the spike decides explicitly, per document.

### Beyond OpenID4: the flow seam

The goal starts with OpenID4VCI and OpenID4VP but does not end there. WMP is profile-neutral by design: the core spec defines sessions, flows, sub-flows and messages, and OpenID4 is one profile on top of it (go-wmp has the same split, with a neutral core and an `openid4x` package). The Rust runtime keeps that split.

- **A flow family is a handler plus a spec.** The runtime exposes a `FlowHandler` trait, roughly: a flow type name, an optional required capability, and `async fn run(ctx, params) -> Result<Completion, FlowError>`. The runtime registers handlers by flow type, gates them on negotiated capabilities (an unsupported type is refused with the WMP error, not a crash), routes sub-flow requests to the host through the flow context, and supplies the ports. A family never reaches into the runtime's internals.
- **What adding a family takes.** Its parameter and result schemas in the WMP spec with vectors, a handler module, and new ports only if the family needs effects the existing ports do not cover. No change to the runtime crate.
- **QERDS and agentic or MCP flows** are the examples named by the owner. They are not specified here. They suggest things to keep in mind, not requirements: delivery and evidence flows can be long-lived and asynchronous, so flow state and resume must not assume a flow finishes in one sitting (the `KeyValue` port and WMP session resume are the hooks); an agent-driven host may answer sign, consent and selection by policy rather than through a person, so `Host` stays an interface and never a UI; and a family may use transports other than HTTP, which means new ports, not changes to the existing ones.
- **How the seam is kept honest.** Step S0 of the spike registers a second, trivial flow type unrelated to OpenID4 through the same trait. If that needs any change to the runtime, the seam is wrong. Nothing more speculative than that is built.

### Rust libraries already in the organisation

Before writing JOSE, OAuth or DPoP code, evaluate what Kushal Das's projects already use. What follows is from their READMEs, Cargo manifests and the crates.io pages on 2026-10-29; nothing was run or tested.

| Project | What it is | Relevance to the engine |
| --- | --- | --- |
| [SUNET/tunnelbana](https://github.com/SUNET/tunnelbana) (BSD-2-Clause) | A fast identity proxy in Rust: actix-web, tokio, `rustls` 0.23 with `ring`, `reqwest` 0.13 on rustls, RustCrypto (`p256`, `p384`, `ed25519-dalek`, `rsa`, `sha2`, `hkdf`), `tracing`. Built on the libraries below. | A worked example of the stack, TLS choice and dependency hygiene we would adopt, in production-style use |
| [jose-rs](https://github.com/kushaldas/jose-rs) | Pure-Rust JWS, JWE, JWK and JWT, with software and HSM key support. JWE key management includes ECDH-ES and ECDH-ES with AES key wrap on P-256, P-384, P-521 and X25519, with AES-GCM and AES-CBC-HMAC content encryption; JWK thumbprints per RFC 7638; a post-quantum feature flag. | The likely JOSE layer: encrypted credential responses, `direct_post.jwt`, DPoP proofs, signed metadata |
| [kryptering](https://crates.io/crates/kryptering) | Crypto operations over RustCrypto (software) and PKCS#11 (HSM) backends; the base of `jose-rs`. | Key custody abstraction; relevant to hardware-backed keys on the server |
| [grindvakt](https://github.com/kushaldas/grindvakt) | A runtime-agnostic OAuth 2.0, OpenID Connect and OpenID Federation library on `jose-rs`; DPoP (RFC 9449) with a pluggable store; OpenID Federation 1.1. | May cover parts of the OAuth client side and trust-chain handling; need to check how much is provider-side only |
| [bergshamra](https://github.com/kushaldas/bergshamra) and [gamlastan](https://github.com/kushaldas/gamlastan) | XML security and SAML in Rust. | Not needed by the engine; useful as evidence of the team's practices and release cadence |

**Questions the evaluation must answer:**

- Does `jose-rs` cover what the engine needs as a recipient and a sender (ECDH-ES JWE to a verifier key, decryption with a client key, ES256 and ES384 and EdDSA signing, `x5c` header handling) and does it behave correctly on the edge cases the Go engine already handles?
- Does `grindvakt` offer a client-side DPoP proof builder and a PAR client, or only provider-side pieces? Is its runtime-agnostic claim compatible with our async ports?
- Can these crates build for Android arm64 and iOS, and for a static musl target, within our size and reproducibility goals?
- Maintenance and risk: the versions are 0.x, the number of maintainers, review and audit status, API stability, and how quickly security fixes ship. All are BSD-2-Clause, which fits our licensing, to be confirmed against our policy.
- What the engine would still need to write itself: X.509 path validation for signed metadata (`rustls-webpki` is the likely base), and the OpenID4-specific logic.

The default is to reuse these crates instead of rewriting them, and to cross-check their behaviour against the Go engine with the vectors.

## Ports

The ports are the only way the core touches the world. They live in `engine-ports`, with plain data types so they cross UniFFI cleanly. The sketches below are shapes, not final signatures.

```rust
// Perform one HTTP request. The adapter owns TLS, roots, proxies, redirects and
// the address policy. The core states WHY it is fetching and what limits apply.
#[async_trait]
pub trait HttpClient {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, HttpError>;
}
pub struct HttpRequest {
    pub method: Method, pub url: String,
    pub headers: Vec<(String, String)>, pub body: Vec<u8>,
    pub purpose: FetchPurpose,        // IssuerMetadata, AsMetadata, Offer, Nonce, Token,
                                      // Credential, Deferred, Notification, RequestObject,
                                      // ClientMetadata, DirectPost, Jwks, Logo, Pdp
    pub max_response_bytes: usize,    // 1 MiB for metadata-like fetches
    pub redirects: RedirectPolicy,    // max hops, http(s) only, no userinfo
    pub allow_plaintext: bool,        // from config; off in production
    pub timeout: Duration,
}

pub trait Clock  { fn now_unix(&self) -> i64; async fn sleep(&self, d: Duration); }
pub trait Rng    { fn fill(&self, buf: &mut [u8]); }

// The wallet client, seen from the core. This IS a WMP peer: sign, consent,
// selection, match and user-agent steps are sub-flow requests (wmp-core FlowContext).
pub trait Host {
    async fn request_sign(&self, flow: FlowId, p: SignParams)    -> Result<SignResult, SubFlowError>;
    async fn request_match(&self, flow: FlowId, p: MatchParams)  -> Result<MatchResult, SubFlowError>;
    async fn request_consent(&self, flow: FlowId, p: ConsentParams) -> Result<ConsentResult, SubFlowError>;
    async fn request_tx_code(&self, flow: FlowId, p: TxCodeParams) -> Result<String, SubFlowError>;
    async fn open_authorization(&self, flow: FlowId, url: String)  -> Result<AuthRedirect, SubFlowError>;
    fn progress(&self, flow: FlowId, step: FlowStep, detail: Option<Detail>);
}

// Trust. Two implementations: AuthzenDirect (talks to the PDP) and BackendProxy
// (today's /v1/evaluate and /v1/resolve, with a token from TokenProvider).
pub trait Pdp {
    async fn evaluate(&self, req: EvaluationRequest) -> Result<EvaluationResponse, PdpError>;
    async fn resolve(&self, req: ResolveRequest)     -> Result<ResolveResponse, PdpError>;
}
pub trait TokenProvider { async fn bearer(&self) -> Result<String, AuthError>; }

// Optional persistence and caches (default in-memory): metadata, DPoP nonces,
// attestation challenges, flow state for resume. Values carry a TTL.
pub trait KeyValue { /* get / put / delete with ttl */ }

// Logs and metrics. The core passes only redacted, allow-listed fields.
pub trait Telemetry { fn event(&self, e: Event); }
```

### Rules for the ports

- **The adapter enforces network policy; the core declares it.** The address policy (refuse private, loopback, link-local and cloud-metadata addresses at dial time, on every redirect hop) lives in the adapter. The core must set `purpose`, size and redirect limits on every request, and the vectors assert that it does. In the SDK the host's platform stack must apply an equivalent policy; the adapter-sdk documents the minimum.
- **Keys.** The engine may hold ephemeral keys (for example a DPoP key it generates), and the client may hold others (client-held DPoP and client-authentication signing, see `sign_client_auth` in the Go engine). The core supports both: where the client holds the key, the core builds the to-be-signed input and asks the host to sign it through `request_sign`. Long-term keys never live in the engine.
- **Host is WMP.** In the server adapter `Host` is a remote WMP peer over a transport; in the SDK adapter it is an in-process peer implemented by the native SDK. The core does not know which. This is the "padding" that lets the same core replace the engine in both places.
- **No ambient state.** No global caches, no environment variables, no files. Configuration is a struct passed to the engine constructor, mirroring the Go engine's `http_client.*` and trust settings where they apply (for example `metadata_type`: prefer-signed, require-signed, prefer-unsigned, require-unsigned, any).

## Behavioural reference

This section inventories what the Go engine does, so the Rust core knows what to reproduce and which behaviours are the risky ones to copy. Source of truth for each row is the cited Go function in `internal/engine` (names, not line numbers, since those drift) or the cited issue or PR.

Every behaviour carries a **provenance tag**. The tag decides how much weight its vector has:

- **spec**: required by a published specification clause. Normative.
- **oidf**: confirmed by a conformance-suite run. Normative.
- **policy**: a SIROS decision recorded in a review or issue. Normative until the decision is revisited.
- **observed**: the Go engine does it, and nothing independent says it is right. A characterization only; a Rust mismatch triggers a review, not an automatic fix.

### OpenID4VCI issuance

| Area | Behaviour the core must reproduce | Go reference | Tag |
| --- | --- | --- | --- |
| Offer parsing | By value, by `credential_offer_uri`, and the `openid-credential-offer:` URI scheme (both the `//`-prefixed and the bare form; the past bug was requiring the `//` prefix, so the bare form fell through to plain `json.Unmarshal` — PR 345, not a URL parser dropping an empty authority). The offer is decoded with plain `json.Unmarshal` on every Go ref; the strict decoder (`decodeStrict`) applies to auxiliary-data documents, deferred and error bodies, and proof payloads — never the offer. Whether the Rust core makes the offer strict is a decision to record in the vectors, not a Go behaviour to copy. | `parseOffer`, `fetchOfferFromURI`, PR 480 `strictjson.go` | spec + policy |
| Issuer metadata URL | Insert `/.well-known/openid-credential-issuer` between host and path, path as given with a trailing slash kept (1.0 literal form, what the OIDF suite expects, issue 505). Fall back to the 1.1-draft form (one terminating slash removed) only on HTTP 404. Identity is exact: `credential_issuer` must equal the identifier as received. Cache keyed on the identifier as received. | `pkg/issuermetadata/resolver.go`, `pkg/oidc/wellknown.go` | oidf + policy |
| Metadata type | `Accept` negotiation per config: prefer-signed (default), require-signed, prefer-unsigned, require-unsigned, any. Fall back to the other form only after HTTP 406. A signed document that fails verification is an error, never a fallback. The issuer-metadata response limit is 10 MB (`maxResponseBodyBytes`); 1 MiB is the AS-metadata and offer-by-reference limit. | resolver, `http_client.metadata_type` | spec + policy |
| Authorization-server metadata | Candidates in order: RFC 8414 section 3.1 insertion, then OIDC discovery appended; one terminating slash removed in each. Fall back only on 404. The document's `issuer` must equal the AS identifier exactly. Endpoint guesses (`<issuer>/token`, `<AS>/authorize`) only when every candidate answered 404. A served document without a needed endpoint is an error, not a guess. | `oidc.FetchAuthorizationServerMetadata`, `fetchOAuthMetadata` | spec + policy |
| Credential selection | Client picks among offered configuration ids; auto-select when exactly one is usable. On origin/main an offer with zero usable configurations sends a selection request with an empty list and waits; on PR 480 configurations refused for a named reason fail at once with the refusal (`failConfigRefusal`), while an offer whose ids are merely absent from metadata still waits. The spec's earlier "fails at once" grafted the oid4vp presentation fix onto the issuance row. | `awaitCredentialSelection` (main), PR 480 | spec + policy |
| Grants | Pre-authorized code with optional `tx_code` (asked of the client); authorization code with PAR, PKCE S256 and authorization details, the browser step delegated to the host, resume with the returned code; refresh token. | `handlePreAuthorized`, `startAuthorizationFlow`, `exchangeAuthCode`, `exchangeRefreshToken` | spec |
| Client authentication | Client attestation (WIA plus proof of possession), attestation challenge fetch and retry, client assertion, DPoP with nonce retry on a DPoP nonce error. | `requestClientAttestation`, `createClientAssertion`, `createDPoPProof` | spec + observed |
| Nonce and retry | Nonce endpoint when advertised. On `invalid_nonce`: fetch a fresh nonce (nonce endpoint first, then a legacy `c_nonce` in the body) and retry once; terminal after a second `invalid_nonce`. The retry re-sends the same auxiliary data and encryption offer. Nonce text never reaches logs. | `freshNonceForRetry`, `CNonceRequiredError` | spec + policy |
| Key proofs | Proofs are built by the engine and signed by the client through a sign sub-flow; batch size from issuer metadata; re-issuance proves with the existing key id. | `requestProofs`, `credentialBatchSize` | observed |
| Credential request and response | Response encryption offered when the issuer supports it (ECDH-ES family, JWE; the client JWK is rebuilt from the parsed P-256 key — there is no thumbprint in the VCI path; the thumbprint is an oid4vp behaviour). On origin/main a plain 200 is **accepted** even when response encryption was negotiated and the issuer said `encryption_required`; the refusal happens only for secret-seed and auxiliary-data delivery. This contradicts the Security-requirements bullet below — a decision for the Rust core and the vectors, not a Go behaviour to copy blindly. Also: credential **request** encryption (PR 520, OID4VCI §8.2/§10) is a whole feature this row missed. Deferred issuance via `transaction_id` with the issuer's interval (default 5 s, max 60 attempts); notification afterwards. | `requestCredential`, `pollDeferredCredential`, `registerNotificationContext`, `oid4vci_request_encryption.go` | spec + policy |
| Credential Auxiliary Data v0.1 (PR 480, unmerged) | Advertisement parsing and the checks before the request (`usable`); `to_wallet` entries handed to the client; a plain response that carries `auxiliary_data` is refused; an issuer conflict is relayed as `AUXILIARY_DATA_CONFLICT`; an unsupported advertisement yields `AUXILIARY_DATA_UNSUPPORTED`. Entries of an unrecognized type are **forwarded verbatim to the client** (not dropped), checked for duplicate type+path, and searched for `opening`/`commitment` members at any depth; `required` on a `to_issuer` entry must be a boolean. Legacy seed and commitment member names (`org.siros.secret_seed`, `org.siros.holder_commitments`, `org.siros.psc`, `holder_commitments`, `secret_members`) are **refused** with `LEGACY_SECRET_MEMBER`, not ordinary unknown members — ignoring an advertisement of one would let a seed travel in clear. Also: `AUXILIARY_DATA_PROOF_INVALID` refuses proofs carrying an `opening`; `auxiliary_data` must not appear in issuer metadata; `CredentialConfig` requires unambiguous top-level member names. **Meanwhile at origin/main there is no auxiliary data at all** — the current mechanism is the holder-commitments/PSC extension (`PSC_CONFLICT`, `checkPSCNeedsProof`, `verifyProofCarriesPSC`), which PR 480 removes. | `auxiliary_data.go`, `oid4vci.go:3343-3540` (main PSC path), PR 480 | spec + policy |
| Errors and logs | The credential endpoint logs only the status and a safe error code (`safeErrorCode`: allow-list `[A-Za-z0-9_.-]`, ≤64). The token endpoint, the PAR endpoint and the oid4vp submission paths log raw remote bodies at Debug — bodies that carry `c_nonce` — so "no raw bodies" is not fully true (a Go bug worth fixing, not a policy to copy). Issuer error text: on main only the PSC-conflict `error_description` is relayed (capped 512, control characters stripped); on PR 480 even that reduces to the code. Openings are never relayed. | `safeErrorCode`, `pscConflictMessage`, PR 480 `oid4vci.go:3273-3295` | policy |
| Trust | The issuer is evaluated by the PDP using key material from signed metadata (x5c, jwk, inline jwks, jwks_uri, or mdoc IACA certificates — the last three missing from the earlier revision). Issuance fails closed when untrusted. The VP trust cache does store untrusted verdicts (`TrustStatusUntrusted`); VCI has no issuer-trust storage at all, making the earlier "nothing stored with trusted=false" vacuous there and contradicted here. The primary path is the direct server-side PDP call; the frontend-mediated round-trip is the fallback. | `evaluateTrust`, `extractIssuerKeyMaterial`, `oid4vp.go:1564-1580` | policy |

### OpenID4VP presentation

| Area | Behaviour the core must reproduce | Go reference | Tag |
| --- | --- | --- | --- |
| Request parsing | By value, by `request_uri` (a signed **or plain** request object), and the URL forms (`openid4vp://`, `haip://`, `haip-vp://`, `mdoc-openid4vp://`, raw query string, direct https URL, bare reference URL). The client id scheme is inferred and must match the prefix; the client id must match the request; the response URI origin is validated — but only for `x509_san_dns` (and skipped for raw query strings). | `parseRequest`, `validateClientIDMatch`, `validateResponseURIOrigin` | spec |
| Verifier trust | Evaluated by the PDP; a DID-based request is verified first. Trust results may be cached. | `evaluateVerifierTrust`, `verifyDIDRequest` | policy + observed |
| Client metadata | Fetched with bounded size; raw objects preserved. | `fetchClientMetadata` | spec |
| DCQL and selection | The requested credential types come from the DCQL query; selection and consent are asked of the client; no match produces a clean failure. The match step carries no credential data (WMP spec PR 24). | `requestCredentialSelection`, `failNoMatchingCredential` | spec + policy |
| Transaction data | Decoded and validated against the DCQL ids; an unsupported entry is refused with the allow-listed `UNSUPPORTED_TRANSACTION_DATA` code and no client text. | `validateTransactionData`, `failTransactionData` | spec + policy |
| VP signing | The VP token is signed by the client; the DCQL-shaped token is assembled and the verifier JWK thumbprint bound. | `requestVPSignature`, `buildDCQLVPToken` | spec |
| Response modes | `direct_post`, `direct_post.jwt` (encrypted to the verifier's key; algorithm and encryption mapping; the JWE is validated), fragment and query redirects. | `submitResponse`, `submitDirectPostJWT`, `resolveResponseEncryption` | spec |
| Decline | No client encrypts a decline; the engine posts a plain form (`application/x-www-form-urlencoded`) to the response URI — query and fragment modes get an error redirect. Under `direct_post.jwt` most refusals (transaction-data failures, encryption-contract failures) are **not sent at all**: the verifier times out. Only declines, no-match and consent vetoes post the plain form in jwt mode. No JARM error response is built anywhere. The earlier "stay plain (a known limitation, deferred)" understated this: it is not that they stay plain, it is that the verifier is not contacted. | `submitErrorResponse`, `failTransactionData`, `refuseVerifierOnEncryptionError` | policy |

### Cross-cutting

- **Fetch hygiene.** Address-policed on every redirect hop (`guardedDial` + `ssrfGuard`; private, loopback, link-local and cloud metadata refused; plain http refused unless configured). Redirect-bounded only by Go's client default (10 hops). **The offer-by-reference fetch has no size limit on any Go ref** (`fetchOfferFromURI`) — a Go bug, not a policy. Purpose-reporting is a Rust-port design, not a Go behaviour. No endpoint is guessed after a served-but-unusable document.
- **Fail closed.** If two things cannot be compared, the check refuses. JSON null is a type error where a value is required.
- **Security-relevant derived values** are computed after decoding, never taken from a decoded field.
- **The WMP surface** (session, flow start, sub-flows, completion, consent) follows the WMP spec and its vectors, not the legacy WebSocket messages.

## Resolvers and direct PDP

### What the engine's resolve endpoint does today

`POST /v1/resolve` (go-wallet-backend `internal/api/authzen_proxy.go`) is more than a relay. Depending on the request it:

- resolves a URL subject as a credential issuer (the default) or as an OAuth authorization server (`resource_type: oauth-authorization-server`), using the shared issuer-metadata resolver and the AS discovery rules above;
- resolves a credential offer by reference (`credential_offer_uri`);
- extracts key material from the resolved metadata (x5c or jwk) and asks the PDP to evaluate trust for it;
- applies the ARF 6.6.2.3 entitlement checks to a resolved provider: is the signing certificate a WRPAC, does the registration certificate describe this provider, is it registered for what it offers;
- inlines logos as data URIs, so a browser does not fetch them from the issuer;
- rejects unsupported resource types, maps a document mismatch to 502 without leaking the document, and applies the SSRF-guarded client throughout.

`POST /v1/evaluate` authorizes the query against SPOCP policies, looks up the tenant's PDP URL (`tenant.TrustConfig.PDPURL`, with a global fallback), and forwards to the PDP.

### What moves into the core

| Piece | Moves to the core | Notes |
| --- | --- | --- |
| Issuer metadata and AS metadata resolution | Yes | Exactly the behaviours in the reference tables, including the signed-metadata verification and `metadata_type` policy. |
| Offer by reference | Yes |  |
| Key material extraction and the trust call | Yes | The call goes through the `Pdp` port. |
| Entitlement checks (ARF 6.6.2.3) | Later | Needs WRPAC and registration-certificate parsing; excluded from the spike. |
| Logo inlining | No | A host or adapter concern. The data-URI inlining existed to protect a browser; in an in-SDK engine the device already talks to the issuer. Decide per adapter. |
| SPOCP query authorization | Open | A policy gate in the backend proxy today. See below. |

The core exposes the resolver as a plain library API as well (`resolve_issuer`, `resolve_authorization_server`, `resolve_offer`), so a non-engine caller such as a verifier-side tool or a test can use it.

### The PDP client

The `Pdp` port has two implementations:

1. **`BackendProxy`**: talks to the existing `/v1/evaluate` and `/v1/resolve` with a bearer token from `TokenProvider`. This works today and is what the spike uses.
2. **`AuthzenDirect`**: talks to the tenant's PDP (go-trust) over AuthZEN directly. This removes the backend proxy from the trust path; the request carries a JWT (see below).

Open questions before `AuthzenDirect` can ship, found by reading the proxy:

- **PDP authentication.** Direction decided: the PDP accepts our usual JWT access tokens, validated server-side with go-tokenauth, as the backend's other services do. This does not exist in go-trust today and is expected to be an easy addition; it is a change in go-trust, outside the spike, to be requested from that project. Until it exists, the proxy's PDP client sends no credentials (the PDP URL is operator-controlled and not SSRF-restricted), so a directly reachable PDP would be unauthenticated. Still open: which token the SDK presents (the wallet session token, or one minted for the PDP), its audience and scopes, tenant binding, and rate limiting.
- **The policy gate.** Direct calls skip the SPOCP authorization of queries. Either the PDP takes over that role, or it is accepted as a loss.
- **Discovering the PDP URL.** It comes from the tenant record. The SDK needs a configuration endpoint or a compiled-in value, and the engine needs the same value in server mode.
- **Privacy.** The PDP sees the same queries the backend sees today; direct calls change who else can observe them, not what is observed.
- **Availability.** With no backend in the path there is no fallback if the PDP is down; the failure mode must stay fail closed.

## Phase A: vectors generated from go-wallet-backend

### Purpose and its limit

The spike needs a test oracle before the conformance-suite integration exists. The only complete oracle today is the Go engine, so Phase A generates test vectors from it. The limit is built in: **these vectors can only say what the Go engine does, not what is right.** The Go engine has been wrong before. The credential-issuer metadata URL builder stripped a trailing slash, and only the OpenID Foundation conformance run found it (go-wallet-backend issue 505). Vectors that freeze Go behaviour would turn bugs like that into requirements for the Rust core. So Phase A vectors are temporary scaffolding with an enforced sunset.

### Rules that keep the vectors from ossifying our bugs

1. **Provenance is on every vector.** Generated vectors carry `provenance: go-observed`, the Go repo and commit they were generated from, and the generation date. A vector's provenance is changed only by evidence: a spec clause (`spec`), a conformance-suite result (`oidf`), or a recorded decision (`policy`).
2. **A go-observed vector never overrules a spec clause or a conformance result.** If the Rust core disagrees with one, the disagreement is reviewed. The outcomes are: fix Rust to match, fix Go and regenerate, or record a `known-divergence` with a link to the issue and the intended behaviour. It is never silently resolved by copying Go.
3. **Every go-observed vector has a `review_by` date**, at most 60 days after generation, and the vector runner fails once that date passes. Extending it requires a written reason in the vector.
4. **Hard sunset.** When Phase B reaches its first milestone (the chosen OIDF plans green against the Rust core), every remaining go-observed vector must have been promoted (backed by spec, oidf or policy), replaced, or deleted. No go-observed vector is allowed to remain as a gate after that point.
5. **Prefer negative vectors.** Most of the value is in what the engine must refuse (duplicate keys in an offer, issuer mismatch, fallback on a 5xx, plain response with auxiliary data, unsupported transaction data). Refusals are where a copied bug does the most damage, so each refusal vector must cite the spec clause or the policy that demands it, and a refusal with no citation is flagged `observed`.

### Generation harness

- **Where.** A test-only package in go-wallet-backend (not production code), for example under `test/vectorgen`. It drives the engine through its Go interface with `httptest` fake issuers, authorization servers, verifiers and PDPs, and a recording `RoundTripper`. The existing engine tests already use this style.
- **Determinism.** The Go engine uses `crypto/rand` and the wall clock. Do not add injection points to production code just for this. Instead assert **relations, not bytes**: PKCE challenge equals S256 of the verifier; the DPoP proof verifies under the presented JWK and carries the right `htm`, `htu`, `ath` and nonce; the JWE decrypts under the test key; random values are matched by pattern and then bound by name for later steps. Where a vector needs exact bytes (a signature input), the test supplies the key and the vector records the to-be-signed input.
- **Pinned.** Generation runs against a named go-wallet-backend commit. The commit goes into each file, and regeneration is a deliberate, reviewed act.
- **Go runner stays.** The same vectors run against the Go engine during the overlap, so a Go regression is visible while both engines exist.

### Vector format

One JSON file per scenario. A script is an ordered list of steps; each step names an actor and what must be seen or done.

```json
{
  "id": "vci.preauth.tx_code.001",
  "provenance": "go-observed",
  "generator": {"repo": "go-wallet-backend", "commit": "<sha>", "date": "2026-11-xx"},
  "review_by": "2026-12-31",
  "spec_refs": ["OpenID4VCI 1.0 section 6"],
  "config": {"metadata_type": "prefer-signed", "allow_plaintext": false},
  "setup": {"issuer": "https://issuer.example/path/", "keys": {"...": "..."}},
  "script": [
    {"wmp_in":   {"method": "wmp.flow.start", "params": {"type": "oid4vci", "offer": "..."}}},
    {"http_out": {"expect": {"method": "GET", "url": "https://issuer.example/.well-known/openid-credential-issuer/path/", "purpose": "issuer_metadata"}, "reply": {"status": 200, "body": "..."}}},
    {"host_ask": {"expect": {"kind": "tx_code"}, "answer": {"value": "1234"}}},
    {"http_out": {"expect": {"method": "POST", "url": ".../token", "form": {"tx_code": "1234"}}, "reply": {"status": 200, "body": "..."}}},
    {"wmp_out":  {"expect": {"method": "wmp.flow.complete", "result": {"...": "..."}}}}
  ]
}
```

`http_out` steps assert the engine's outgoing request (method, URL, selected headers, form or JSON members, and the `purpose` and limits the core declared) and supply the world's reply. `host_ask` steps assert what the engine asks the wallet (sign inputs, consent, selection) and supply the answer. `wmp_in` and `wmp_out` follow the WMP spec and vectors. A step may carry `must_refuse: true` with the error code expected.

### Where the vectors live

A new repository, language-neutral and owned by neither engine, for example `sirosfoundation/engine-vectors` (open decision: name and location). It follows the pattern of the WMP vectors: the Go and Rust runners both load a sibling checkout, with a CI fallback checkout. WMP-level wire vectors stay in the `wmp` repository; engine-level HTTP transcripts are a different thing and go here.

### Scenarios to cover before the spike ends

| Group | Scenarios |
| --- | --- |
| Offer | by value; by reference; URI scheme form; duplicate and case-variant members refused; nothing usable fails at once |
| Issuer metadata | plain path; path with trailing slash (literal form first, fallback on 404); 5xx no fallback; `credential_issuer` mismatch; signed vs unsigned per `metadata_type`; 406 fallback; oversize body refused |
| AS metadata | RFC 8414 insertion; OIDC discovery only; 404 then 200; 5xx and 401 no fallback; `issuer` mismatch; all-404 then endpoint guess; served document without a token endpoint is an error |
| Pre-authorized issuance | plain response; with `tx_code`; encrypted response; deferred then ready; notification |
| Nonce | nonce endpoint; `invalid_nonce` then retry; two in a row ends the flow; legacy `c_nonce` body |
| Client auth | DPoP with server nonce retry; client attestation and attestation challenge |
| Auxiliary data | usable; conflict relayed; plain response with `auxiliary_data` refused; unrecognized entry type ignored |
| Trust and failure | untrusted issuer fails closed; PDP unreachable fails closed; SSRF refusals reported by the adapter surface as flow errors |
| Logging | no token, nonce text, opening or raw body in emitted telemetry events |

## Phase B: OpenID conformance suite integration

After the spike, the referee changes from the Go engine to the OpenID Foundation conformance suite, run from its Docker containers so it works in CI. The team has already run the hosted suite against the Go wallet once; that run is what exposed the issuer-metadata slash bug (go-wallet-backend issue 505). Phase B makes that routine and applies it to the Rust core and, for a baseline, to the Go engine.

### Set-up

- **Suite.** The open-source conformance suite (OpenID Foundation, GitLab project `openid/conformance-suite`), run with its Docker Compose set-up: the suite server, its HTTP front end and MongoDB. Pin the suite release and record it in every result. The suite needs HTTPS with certificates and hostnames it can reach; use the arrangement in its own documentation. (Exact commands, hostnames and ports to be taken from the suite release in use; not verified here.)
- **The engine plays the wallet.** The suite plays the issuer, authorization server or verifier. For each test the suite exposes an offer URL or authorization request URL and the endpoints behind it.
- **A headless wallet driver** (in `engine-conformance`) connects the pieces:
  1. create a test plan through the suite's REST API and start a test run;
  2. read the test's published URLs (offer, request, endpoints);
  3. start the flow on the Rust engine over WMP (`flow_start` with that offer or request);
  4. act as the `Host`: hold software test keys, answer sign requests, tx\_code, selection and consent from a script per test;
  5. wait for the engine's flow result, then fetch the suite's result and log and assert the verdict.
- **Trust.** The engine uses a test `Pdp` that trusts the suite's certificates and keys, so the suite can run without the production trust infrastructure. A second, shorter run keeps the real PDP path honest.
- **Artifacts.** Keep the suite's HTML log and JSON result per test, plus the engine's telemetry, as CI artifacts.

### Which plans (to confirm against the suite release)

The suite ships wallet test plans for OpenID4VCI and OpenID4VP. The exact plan names and variant matrix must be read from the release in use; the engine should be run against at least these dimensions:

| Protocol | Dimensions to cover |
| --- | --- |
| OpenID4VCI (wallet) | pre-authorized code with and without `tx_code`; authorization code with PAR, PKCE and DPoP; issuer identifiers with and without a path and trailing slash; signed and unsigned issuer metadata; `invalid_nonce` handling; encrypted credential responses; deferred issuance; SD-JWT VC and mdoc credential formats |
| OpenID4VP (wallet) | client id schemes the engine supports (x509 SAN DNS, x509 hash, DID, redirect URI, verifier attestation); request by value and by reference; `direct_post` and `direct_post.jwt`; DCQL queries; transaction data; negative request-object cases |

The first Phase B task is to enumerate the plans actually available, map each to a row above, and write the mapping into this document.

### Order of work

1. **Go baseline.** Run the chosen plans against the Go engine first. Every failure is a Go bug or a driver bug. Failures become issues and, where they are intended to stay, `known-divergence` entries. This is the step that protects the Rust core from inheriting Go's mistakes.
2. **Rust against the same plans.** Run, fix, repeat. The target is a documented set of plans passing, with every warning reviewed.
3. **Promote vectors.** For each passing test, record the HTTP interaction into an engine vector tagged `oidf` with the suite version, plan and test id. These replace the go-observed vectors in the same scenario. Remaining go-observed vectors are retired under the sunset rule.
4. **CI.** A nightly job plus an on-demand job for pull requests that touch protocol code. Flakes are triaged, never retried into green.

### What the suite does not cover

The suite cannot judge the WMP layer, Credential Auxiliary Data, the consent and lifecycle rules, ZK proofs, or the PDP integration. Those stay under `spec` and `policy` vectors, reviewed by hand, and under live interop runs against real issuers and verifiers (the gdc issuer, and the EUDI interop events). Passing the suite is evidence, not proof: it covers only what its plans exercise.

### Phase B milestone

B1 is reached when the agreed plans pass against the Rust core in CI, every go-observed vector has been promoted, replaced or deleted, and the known-divergence list is written and linked from the vector repository.

## Spike scope, milestones and acceptance criteria

The spike's real product is **information**: how big the port is, whether the async-ports design holds up, and where Rust and the Go engine disagree. A working slice is the means. The spike ends with a written report and a go or no-go recommendation for the full port.

### Slice

| Step | Content | Proves |
| --- | --- | --- |
| S0 | Cargo workspace; the port traits; in-memory fake adapters; the vector runner; the smallest `wmp-core` (session, flow start, sub-flow request and answer, progress, complete, error). A minimal second flow type, unrelated to OpenID4, registered through the same flow seam. The review answer names MCP integration for this role; confirm which minimal MCP flow is meant. | The seam works and is not OpenID-shaped; vectors run end to end |
| S1 | Offer parsing; issuer metadata resolution (the 1.0 literal form with 404 fallback, exact identity, `metadata_type`); AS metadata discovery. | The resolver behaviours and the serde-versus-Go decoding decisions |
| S2 | Pre-authorized-code issuance: token (with `tx_code` asked of the host), nonce, `invalid_nonce` retry, key proofs signed through the host, credential request with plain and encrypted (JWE, ECDH-ES) responses, deferred polling, notification. DPoP and client attestation if the gdc issuer requires them. | The JOSE, DPoP and response-encryption stack in Rust |
| S3 | Trust through `BackendProxy` (`Pdp` port), fail closed. A live run: the Rust engine issues a credential from the gdc issuer through the real backend proxy, with a test wallet host. | Real interop and the PDP seam |
| S4 (stretch) | Authorization code with PAR and PKCE, or a basic OpenID4VP `direct_post` presentation. | The second flow family on the same runtime |

The container host (the server adapter) is built alongside the SDK adapter from S0, not after it. Spike test environments, the live runs in S3 and the Phase B conformance runs use the Rust engine in a container; the SDK adapter is proven with the UniFFI smoke test.

Out of scope for the spike: the UniFFI adapters beyond a build-and-call smoke test, the TEE image, `AuthzenDirect`, the entitlement checks, full OpenID4VP, the legacy WebSocket protocol, and any change to the Go engine beyond the Phase A generator.

### Measurements the report must contain

- Lines of Rust per area against the Go lines in the reference, and the time each step took, so the full-port estimate rests on data.
- A table of every behavioural difference found between serde-based decoding and the Go engine, with the decision taken for each.
- A minimal Kotlin (JVM or Android) and Swift smoke test of an async `HttpClient` and `Host` callback over UniFFI. This is the main technical risk of the async-ports design; if it fails, the fallback is the explicit state-machine design.
- The static musl binary size and the Android arm64 library size, `cargo tree` dependency counts, and whether two clean builds produce identical bytes. These test the TCB and reproducibility claims.
- The list of crypto crates used and the reasons, with notes on anything that needs an audit before production.

### Acceptance criteria for the spike

1. S0 to S3 pass their vectors, and S3 has been run live against gdc with the result recorded.
2. Every go-observed vector used carries provenance and a `review_by` date, and the runner enforces both.
3. The second, non-OpenID4 flow runs on the same runtime without any change to the runtime crate.
4. Fail-closed behaviour is tested: untrusted issuer, PDP unreachable, issuer mismatch, ambiguous offer.
5. No secrets, tokens or nonce text appear in emitted telemetry in any vector run.
6. The measurements above are written up, with an estimate for the full port and a recommendation.

### Gate after the spike

Proceed to the full port only if: the async-over-UniFFI test works (or the state-machine fallback is judged acceptable); the Rust slice is within a reasonable multiple of the Go size; the divergences found are manageable; and the owner agrees the estimate is worth it. The backend replacement is decided separately, after the SDK side has shipped and the Go engine has stopped changing.

## Security requirements

These apply to the spike and to everything after it.

- **Fail closed.** If a check cannot be performed or two values cannot be compared, the flow refuses. JSON null where a value is required is a type error, not an absent value. A trust decision that cannot be obtained is a refusal.
- **Derived security values** (thumbprints, hashes, expected audiences) are computed after decoding from the decoded data, never read from a field the sender controls.
- **Decoding policy is explicit.** Serde is case-exact and last-wins on duplicate keys. For each document type the code states whether duplicates are refused. The Go engine's current position is strict for the credential offer only, because a third party writes it and two parties read it; for documents whose author is the only party that could exploit an ambiguity, ordinary decoding is enough. The Rust core records the choice per document type in the vectors.
- **Fetch policy.** Every request declares its purpose and limits. The adapter refuses private, loopback, link-local and cloud-metadata addresses at dial time and on every redirect hop, bounds redirects, refuses userinfo in URLs, and applies the response size limit. Plain http is refused unless the operator allows it. In the SDK adapter the host stack must apply an equivalent policy; if it cannot, that is documented.
- **No identifier or value in errors or logs that the issuer or verifier chose,** except where a protocol requires returning issuer text to the client. Telemetry passes only allow-listed, redacted fields: no tokens, nonces, openings, request bodies or credential data.
- **Secrets.** Key material and secret values are held in zeroizing types and not cloned into logs, errors or serialized state. Long-term keys never live in the engine; where the client holds a key, the core asks it to sign.
- **Time and randomness through ports.** No ambient clock or RNG. Production adapters use the operating system's secure RNG.
- **Response encryption.** When an encrypted response was offered: the verification found that origin/main **accepts** a plain 200 even after negotiating encryption with `encryption_required` — the refusal happens only for secret-seed and auxiliary-data delivery. The Rust core must decide whether to match this or to refuse (the Security-requirements intent), record the decision in the vectors, and not silently copy the Go behaviour. There is no thumbprint in the VCI response-encryption path (the client JWK is rebuilt from the parsed key); the thumbprint is an oid4vp behaviour.
- **No endpoint guessing after a served document.** A document that was served but unusable ends the flow; it never triggers a guessed endpoint.
- **Supply chain.** Pinned versions, a vendored dependency set, `cargo deny` and `cargo audit` in CI, no build scripts that fetch from the network, and a published list of direct dependencies with the reason for each. Prefer RustCrypto crates and `rustls` with a small set of providers; avoid OpenSSL.
- **Memory safety.** `#![forbid(unsafe_code)]` in the core and runtime crates. Any `unsafe` in adapters is isolated, justified and reviewed.
- **TEE readiness (design, not spike).** Nothing in the core may assume a particular host. The server adapter keeps TLS inside the binary, reads no ambient configuration beyond a struct, and exposes a measurement-friendly build: static, reproducible, one binary. Attestation handling belongs to the adapter and the deployment, not to the core.

## Risks and open questions

### Risks

| Risk | Why it matters | Mitigation | Leifs answers |
| --- | --- | --- | --- |
| Async trait objects over UniFFI are awkward or immature | The whole port design assumes the host can implement async callbacks | Smoke test in the spike; fallback is an explicit state-machine core (events in, actions out) | agree |
| Serde decodes differently from Go (case-exact, last-wins duplicates, null handling) | Silent interop drift in both directions | Decision per document type, recorded in vectors; difference table in the spike report | agree |
| The Go engine, the WMP spec and go-wmp are still changing (v0.12.0, the rework of PR 163, auxiliary data) | A port of a moving target goes stale | Pin the Go commit for generation; follow WMP through its vectors, not through Go code; regenerate deliberately | we'll start this only when the wmp work has landed in the current engine |
| Second-system effect: a rewrite of interop-heavy code loses accumulated fixes | Regressions that were already fixed once | The reference tables, the vectors, and the conformance suite are the memory; port the tests before the code | agree |
| Overlap period with two engines | Double maintenance | Shared vectors; the Go engine is frozen to fixes while the Rust core is in its spike | agree |
| Rust crate maturity for JOSE and X.509 | JWE with ECDH-ES and key wrap, signed-metadata x5c chains and path validation are easy to get subtly wrong | Use RustCrypto and `rustls-webpki`; record gaps in the report; cross-check against Go with vectors | Investigate the libraries used by Kushals "tunnelbana", "bergshamra", "gamlastan" etc |
| The conformance suite needs a browser-like wallet for some plans | The headless driver grows | Start with plans that need no user agent; emulate the user agent only for authorization-code plans | we can setup test environments with the rust-based engine running in a container (in-backend version). The in-backend host should be developed in parallell with the in-SDK host for this reason. |
| TEE hosting unknown | Image and attestation design depend on it | Keep it out of the spike; decide the platform before the container work starts | agree - this needs analysis |
| Rust skills and review capacity | A single-owner core is a bus-factor risk | Small crates, strict lints, review by a second person on security-relevant code | we have plenty of rust skills in the org but for the spike and initial phases we will push fast with ai-controlled coding |
| Over-engineering the extension seam | A speculative framework costs more than it returns | Prove the seam with one concrete non-OpenID4 flow in S0 and stop there | MCP integration. |

### Open questions for the owner

1. **Where does the code live?** Recommended: a new repository for the Cargo workspace, and a language-neutral `engine-vectors` repository (or a directory with its own CI) for vectors. Names and licence to be decided.
2. **PDP access.** Authentication will use our usual JWT access tokens, validated with go-tokenauth on the PDP side (not yet supported by go-trust). Which token does the SDK present, with what audience and scopes, and does the SPOCP query gate move into the PDP?
3. **TEE.** Which platform, and who verifies the attestation: the SDK, a gateway, or the relying wallet?
4. **Which OIDF plans form the gate** for B1, once the available plans are enumerated.
5. **Is the async-ports design acceptable,** subject to the UniFFI smoke test?
6. **Decoding policy.** Confirm strict decoding for the credential offer only, and ordinary decoding for the author-only documents, as the Go engine now does.
7. **Rust WMP client crate.** Is it a separate work stream with its own owner, shared with the native SDKs and possibly wmp-js? The engine spike needs only a minimal subset.
8. **Extension flows.** Which non-OpenID4 flow is next after the spike (QERDS, an agentic or MCP flow), and where are those flows specified? This document does not specify them; it only requires that adding one needs no change to the runtime.
9. **Go engine policy during the spike.** Recommended: fixes only, no new features, so the reference stays still.

## Hand-off notes for the implementing agent

### Start condition

Do not start the spike until the WMP work has landed in the current Go engine (go-wmp v0.12.0, and the rework of go-wallet-backend PR 163 on it). Until then the reference is still moving and vectors generated from it would go stale. The library evaluation and the review of this document can happen earlier, since they need no Go change.

### First, a caveat about this document

The reference tables were written from the structure of the Go engine and from the review and issue history, not from an exhaustive line-by-line audit. **Your first task is to verify them against the code and correct this document**, adding anything missing. Treat any row you cannot confirm in the code as unverified. The OIDF plan names are also unverified.

### Read first

- go-wallet-backend: `internal/engine/` (`oid4vci.go`, `oid4vp.go`, `session.go`, `messages.go`, `auxiliary_data.go`), `pkg/issuermetadata/`, `pkg/oidc/`, `internal/api/authzen_proxy.go`, `pkg/trust/authzen/`, and the docs `ARCHITECTURE.md`, `DEPLOYMENT.md`, `CONFIGURATION.md`, `engine-blind-encryption.md`, `client-id-strategy.md`, `adr/012-trust-evaluation-architecture.md`.
- WMP: the `wmp` spec repository and its `vectors/*.json`; `go-wmp` for the reference behaviour of sessions, flows and validators; `wmp-js` for the client-side shape.
- Rust and UniFFI practice already in the organisation: `siros-wscd-manager` (UniFFI bindings, Makefile targets for Kotlin and Swift, the CTAP2 raw-bytes transport pattern).
- Issue 505 in go-wallet-backend (the slash bug) and the issue-metadata and AS-discovery pull requests that followed it.

### Order of work

1. Verify and correct the reference tables; enumerate the OIDF wallet plans and write the mapping.
2. Build the Phase A generator in go-wallet-backend (test-only) and produce the first vector groups: offer, issuer metadata, AS metadata.
3. Stand up the Cargo workspace and S0 (ports, fakes, runner, minimal `wmp-core`, the second non-OpenID4 flow).
4. S1, then S2, then S3, running vectors at each step; S4 only if time allows.
5. Write the spike report with the measurements listed in the spike section, and stop for review before any Phase B work.

### Working rules

Follow the conventions of each repository you touch. In addition, these are the owner's standing rules for this work:

- Git over SSH only, never HTTPS. Commits are signed. Do not force-push. Do not merge pull requests and do not tag or publish anything; merging needs an approved human review, and releases need the owner's explicit go.
- Fix every review finding and every instance of the same class of bug. Reply to review threads with the full commit URL and resolve them. Check the actual commit state (signed, pushed) before reporting anything as done.
- Every test must be shown to fail when its fix is reverted. A passing test that never failed proves nothing.
- Do not change production code in go-wallet-backend for this effort; the generator is test-only. If the Go engine needs a fix because a vector or the suite found a bug, open an issue and raise it with the owner.
- Report in full URLs for every pull request and issue.
- Do not decide the open questions above. Record what you would recommend and ask.

### What to hand back

A pull request per step, the vector repository with provenance and `review_by` fields, the measurement report, the list of divergences and bugs found (in Go and in this document), and a recommendation on the gate.

## References

**Repositories**

- [go-wallet-backend](https://github.com/sirosfoundation/go-wallet-backend): the Go engine and backend.
- [wmp](https://github.com/sirosfoundation/wmp): the Wallet Messaging Protocol spec and vectors.
- [go-wmp](https://github.com/sirosfoundation/go-wmp): the Go WMP library.
- [wmp-js](https://github.com/sirosfoundation/wmp-js): the TypeScript WMP library.
- [siros-wscd-manager](https://github.com/sirosfoundation/siros-wscd-manager): Rust with UniFFI bindings, the pattern to follow.

**Issues and pull requests that shaped the reference behaviour**

- [Issue 505: trailing slash removed from the issuer metadata URL](https://github.com/sirosfoundation/go-wallet-backend/issues/505) (found by the OIDF conformance run).
- [PR 518: AS metadata discovery with ordered candidates and an exact issuer check](https://github.com/sirosfoundation/go-wallet-backend/pull/518).
- [PR 480: Credential Auxiliary Data v0.1 handling](https://github.com/sirosfoundation/go-wallet-backend/pull/480).
- [PR 163: the WMP adapter in the backend](https://github.com/sirosfoundation/go-wallet-backend/pull/163), being reworked on go-wmp.
- [Issue 521: last connection wins is per replica](https://github.com/sirosfoundation/go-wallet-backend/issues/521) (context for the session model the engine sits in).
- WMP spec PRs: [24 (match sub-flow)](https://github.com/sirosfoundation/wmp/pull/24), [27 (closed consent action)](https://github.com/sirosfoundation/wmp/pull/27).

**Specifications**

- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), including section 12.2.2 on issuer metadata.
- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414).
- [RFC 9449: DPoP](https://www.rfc-editor.org/rfc/rfc9449), [RFC 9126: PAR](https://www.rfc-editor.org/rfc/rfc9126), [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636).

**Conformance**

- [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) (open source, Docker Compose set-up; confirm the wallet plan names against the release in use).

Where this document says a fact is unverified, it is: check the cited source before relying on it.

## Verification addendum (P0.6, 2026-11-02)

The behavioural reference tables were verified against origin/main `373e7959` (2026-10-30) and `remotes/pr/480` (`149f69b7`, 2026-10-27, unmerged). The corrections above are applied; this section records the remaining findings and the Go bugs the verification surfaced, as issues for the owner.

### Go bugs to file

1. **`fetchOfferFromURI` reads the offer body with no size limit** — `main:internal/engine/oid4vci.go:1382-1404` uses `json.NewDecoder(resp.Body).Decode` with no `LimitReader`; also on PR 480. Violates the codebase's own fetch-hygiene standard.
2. **Raw remote error bodies logged at Debug** — the token endpoint (`oid4vci.go:1998`), the PAR endpoint (`2472`), `submitErrorResponse` (`oid4vp.go:2664`), `submitDirectPostJWT` (`3078`), and PR 480's credential path (`2851`) log `string(body)` — bodies that carry `c_nonce`. "Nonce text never reaches logs" is therefore not fully true.
3. **`credential_response_encryption` omits the `alg` member** — `oid4vci_blind_response.go:57-59` sends only `enc` + `jwk`; the `alg` rides in `jwk.alg`. OID4VCI §7.3 requires the `alg` member.
4. **A plain 200 is accepted after negotiated encryption with `encryption_required`** — `requestCredential` `2979-3012`; see the row and the Security-requirements correction above.
5. **PR 480's invalid-nonce retry can proceed with an empty nonce** — when both the nonce endpoint and the body `c_nonce` fail, `pr/480:oid4vci.go:1156-1171` `continue`s with an empty nonce; main's `freshNonceForRetry` (`2574-2586`) terminates cleanly. The branches have diverged.
6. **`pkg/trust/service.go:236` stale comment** — says "If no PDP URL is resolved, returns 'allow all' (trusted=true)" while the code fails closed at `531-539`. The newer comment at `302-303` is correct; the old one is dangerous.
7. **`evaluateTrustViaFrontend` delegates trust to the client** in no-PDP mode — only safe because `evaluate` fails closed when no PDP URL exists; the layering deserves a vector of its own.

### Major behaviours the tables missed (added to the rows or noted for the vectors)

- Credential **request** encryption (PR 520): a whole feature.
- RFC 8707 `resource` indicators on token and PAR; `issuer_state`; `authorization_details` projection and the granted `credential_identifier` substitution.
- Holder commitments/PSC (the current main-branch secret-binding mechanism, which PR 480 removes).
- `AUXILIARY_DATA_PROOF_INVALID` (openings never relayed); `auxiliary_data`-must-not-appear-in-issuer-metadata; strict `CredentialConfig` top-level decoding (all PR 480).
- Registered-issuer enrichment (per-tenant `client_id`, private_key_jwt from a stored client JWK); mdoc IACA key material; DID server-side resolution; duplicate `client_metadata` refusal; 64 KiB client-metadata cap; deferred-poll caps (60 attempts / 5 min); `maxEncryptedCredentialCount` 256; consent vetting against the query (`vetConsent`); the identical decline/no-match description to the verifier (anti-probing); the trust cache storing untrusted records; the `/v1/resolve` allowlist and `did:web` handling; logo-inlining preconditions (unsigned or trusted).

### The PR 480 divergence

The auxiliary-data row describes an **unmerged** PR. At origin/main the current secret-bearing mechanism is the holder-commitments/PSC extension (`PSC_CONFLICT`); PR 480 removes it and replaces it with Credential Auxiliary Data. A Rust implementer must know which vintage is the reference — the vectors pin it.
