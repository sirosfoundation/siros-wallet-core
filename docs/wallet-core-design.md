# OpenID4VP flows for the wallet core: design proposal

**Base.** wallet-rs master `f718dc3`. Width: the presentation flows of OpenID4VC HAIP 1.0 (final,
24 December 2025), as the owner ruled on 2026-11-02, and the WE BUILD profile on top of them
(decision 12): WE BUILD's conformance specifications CS-02, CS-07, CS-12 and CS-13 at `b63c25a`,
and TS12 v1.0.1 as CS-12 profiles it (section 4.10). Specification: OpenID for Verifiable
Presentations 1.0 (final, 9 July 2025; the HTML downloaded 2026-03-11). The related standards are
in Appendix C. Oracle: wallet-ref, frozen; it has no URI flow, so its differential covers the DC
API path alone.

**Status.** This plan is the SIROS wallet core's design; the owner: "the design we did is the new
source of truth for the siros wallet core". sirosfoundation/siros-wallet-core adopts it on branch
`flows` (section 10). The owner greenlit building this plan; wallet-rs branch `flows` holds its
first milestones, and section 6 lists the refactor they take. The core is modular (decision 20): every
mechanism a specification leaves open is an extension point, and a build compiles what it
registers. zkp_req is out of this plan's scope; Appendix A lists what is deferred with it. The
full-width design is archived in `proposals/flows-full-width/`; the response types this width
leaves out can come back from there. Evidence sits beside this file: `ka/` (known answers), `trace/` (the
requirement trace, its source accounts and its scripts), `coverage/` (the flow table and its
check), `inventory/` (call-site counts), `sigs/` (a scratch crate that typechecks section 4's
signatures against the picked crates), `g1/` (the litmus G1 scan), `g2/` (the litmus G2
baseline), `crates/` (the crate survey and its probes), `checks/` (the number, crate-table
and type-audit checks).

## 1. Summary

The core answers one entry point today: a DC API request whose caller has already verified a
signed request and hands the core its parameters. This proposal makes the core answer HAIP 1.0's
presentation flows, and keeps it pure and offline.

- **Width.** The response type is `vp_token`, the core's registered type. Signed requests use `x509_hash`, which HAIP
  requires, or `x509_san_dns` (§5.9.3), by URI and over the DC API; an unsigned DC API request
  stands under its Origin. A link or a QR code holds `client_id` and `request_uri`; the caller
  fetches the Request Object by GET, or by POST when `request_uri_method` is `post` and the build
  registers the POST; the answer goes in `direct_post.jwt`, and the wallet follows the
  `redirect_uri` the Response URI returns. DC API requests come unsigned, signed or multisigned
  and are answered in `dc_api.jwt` or `dc_api`. DCQL; HAIP's algorithms, as the host's modules
  state them: ECDH-ES on P-256 with A256GCM or A128GCM, ES256; SHA-256. A response type, Client
  Identifier Prefix or response mode the build does not register is refused with its error code,
  and so is a request form outside the width: a request by URI is a Request Object by reference
  (section 4.5).
- **The WE BUILD profile** (section 4.10). A Request Object fetched by POST with `wallet_metadata`,
  signed, or signed and encrypted to a fresh wallet key (CS-12 §7.3 item 9). `verifier_info`
  handed with the DCQL query to the trust service, which requires it and checks the registration
  certificate and the intermediary rules (CS-02 §7.1, CS-13 §7.2).
  The signed DC API protocols alone (CS-07 WU-DC-01). `vct_values` matched through the
  credential type's `extends` chain (CS-12 §8.1). The profiles state the End-User authentication
  they need, and TS12's needs two factor categories. siros-ts12 answers
  `urn:eudi:sca:payment:1` and `urn:eudi:sca:login_risk_transaction:1` over siros-paso's engine:
  TS12's wire in and out, PaSO's rule where TS12 is loose, no support where TS12 defines nothing.
  It implements neither JSON Schema nor TS12's bracket-path integrity claims.
- **Host modules** (decision 13). `Runtime` gives way to modules, one per family a specification
  mandates together: the core's `Platform`, which the core calls itself (`CoreHost`); the core's
  `Haip` and `RequestDecryption`, which the registrations that make the core call them bound
  (a prefix and a JWE mode `Haip`, encrypted Request Objects `RequestDecryption`); siros-paso's
  `Paso`, `RandomIds` and `CoseEncrypt`; siros-mdoc's `DeviceMac`. Each plug-in bounds the modules
  it requires (`Has`) and those it uses when the build holds them (`MayHave`), and a build's
  registry takes a plug-in only when its host meets them: the compiler checks it, and presence is
  a property of the host's type. Every module takes `&self`; one without state is a zero-sized
  type the host gives as `&'static`. A module states the algorithms it implements, and the core
  accepts exactly those.
- **Intake as sans-I/O.** The caller hands the core DC API `data` with its protocol and Origin
  (`Received::dc_api`), or a URI (`Fetch::of`), whose one effect is the GET of its
  `request_uri`. `Fetch::resume` turns the body into `Received`, which the caller owns and can
  replay.
- **Typestate from arrival to answer.** `Received` → `Envelope` (parameters and signatures as
  read, before any check that needs a key or a clock) → `Pending` (the trust questions, as data)
  → `Authenticated` (only `Pending::authenticate` makes one) → `Route` (only an `Authenticated`
  yields one) → `AnswerRoute` (only a `Route` whose request names a registered answering mode,
  whose choice of encryption holds, and a `nonce` N1 accepts yields one; its `session` is the one
  the presentations bind). Every Authorization Response goes to an endpoint the wallet
  authenticated.
- **No invalid state.** A constrained value is a type whose field is private and whose
  constructor checks it. A fixed identifier is checked when the crate builds (`checked!`), and
  entries under distinct keys are a `Keyed`. A value bound to the request, such as the
  `Verifier` a `Route` comes from, comes only from the step that holds the request, and the
  envelope holds the routing every later step reads. A step's answers fill the slots it made,
  one per question. Section 4.15 audits every type.
- **Extension points** (decision 20, section 4.12). Each mechanism a specification leaves open
  is a trait with a stated contract: credential formats, transaction data profiles, Client
  Identifier Prefixes (§5.9.3), response types (RFC 6749 §8.4), response modes (OAuth 2.0
  Multiple Response Type Encoding Practices §2.1), Authorization Response parameters (§8.1),
  `wallet_metadata` members and POST parameters (§10.1, §5.10), the Response URI's answer members
  (§8.2), rules on a Request Object's claims, transaction data hash algorithms (B.3.3.1's IANA
  registry), scope queries (§5.5), and the host's modules. Its inputs are core-made types, the core checks what it
  returns, its host bounds are the modules it calls, and the registry takes it and refuses a
  conflict. The core's own cases implement the same traits as peers: OpenID4VP's modes, the SHA-2
  algorithms. siros-x509 implements `x509_hash` and `x509_san_dns`; the core names no prefix,
  format, profile or platform.
- **Effects in the AuthZEN shape.** A trust question is an AuthZEN Authorization API 1.0
  evaluation (subject, action, resource, context → decision); phase 2's resources are fetches.
  `Runtime::fetch` gives way to effects, so every network call runs outside the core's call
  stack.
- **Answers as data.** A `Delivery` says what the caller does: POST a form to the
  `response_uri`, or return DC API `data`. Errors travel the same `Route`. A request refused
  before authentication answers the platform over the DC API. By URI it answers the
  `response_uri` its trust decision listed when its signature, validity or audience fails.
  Otherwise the End-User hears of it and can choose to send the error to the `response_uri` the
  request names, so the Verifier learns the flow failed and its answer's `redirect_uri` returns
  the End-User to its site.
- **Response modes are plug-ins.** A mode states its name, its channel, its request rules and the
  names of its `wallet_metadata` members, chooses its route's encryption once and writes a body
  around what the core hands it; the core writes every delivery's endpoint from the authenticated
  route, seals every encrypted answer itself, and writes OpenID4VP A.4's DC API error form on every
  DC API route. The core ships OpenID4VP's `dc_api` and `dc_api.jwt` (feature `dc-api`), and
  `direct_post.jwt` with plain `direct_post`, which carries errors alone (§8.3.1; feature `uri`).
- **Established crates.** x509-cert parses certificates, fluent-uri parses URIs, serde_urlencoded
  reads the URI's query and writes form bodies; base64 and sha2 stay. JSON stays in the core's
  `json` module, which refuses a repeated member name at every level. Each of the 15 JOSE crates
  tested accepts a repeated member at some level, so the core splits and checks a JWS itself, over
  its `json` module and base64. Four in-house implementations give way to crates first, in their own
  commits: RustCrypto's k12, uuid, fluent-uri under `HttpsUrl`, and ciborium with coset for
  siros-mdoc's ISO/IEC 18013-5 encoding, read through a core `cbor` module that refuses a repeated
  key at every depth (section 4.9).
- **Records keep working.** A record commits to the digest of the request as received, a fetched
  Request Object included. DC API digests are unchanged.
- **Crates stand alone** (decision 16, decision 20, section 4.11). A crate names another SIROS crate
  only for the types it implements or calls, and the core puts each optional mechanism behind a
  feature that the crates using it turn on: OpenID4VP with siros-sdjwt alone compiles no CBOR or
  COSE, the DC API alone no URI flow, unsigned requests alone no signature step, no build any
  curve arithmetic in the core, and a build without transaction data no hash algorithm beyond
  SHA-256. A module's test double ships with
  the plug-in crate that defines the module, behind that crate's `test-util` feature; the core's
  doubles sit in siros-testkit.
- **Documentation** (decision 17, section 4.12). Each crate's README is its crate documentation:
  the problem the crate solves and how to use it, with an example that compiles. Each extension
  point documents how to implement it, with an example that compiles.
- **Errors are messages** (decision 18, decision 21, section 4.13). Every error carries a stable
  id and named arguments: siros-explain's `Explain`, derived beside thiserror's derive. An argument
  is a named field, and its value is its `Display`. `Display` of the error keeps the English text
  for logs and the Verifier. A statement derives siros-i18n's `Message` the same way. Crates ship
  no wording.
- **The wallet's context resolves every text** (decision 19, decision 21, section 4.14). A `Context`
  holds the wallet's MessageFormat 2 sources for one locale, and `Context::resolve` alone makes a
  `Text`. Every output holds resolved `Text`, and every extension point that writes a text receives
  the wallet's `Context`. A credential's display metadata shows as written. Converters write PaSO's
  and TS12's Views as MF2 source for that context. A record commits to the SHA-256 of its entry's
  shown texts (`shown`); phase 2 resolves again and refuses a pick whose digest differs. The DC API
  matcher builds its context from the registration's sources and resolves through the wallet's code
  path.

The design was gated against itself. The requirement trace covers its 20 traced sources: 1,511
rows, of which 569 bind the Wallet, all 569 with an owner; 101 more stand under the umbrella row
of the caller's trust evaluator; 408 sections hold a key-word sentence, each accounted for
(section 8.5). Of 94 sources in all, 20 traced row by row, 2 under a caller umbrella and 72 at
source level, each with its reason; the 109 references of OpenID4VP's and HAIP's normative lists
and of the five WE BUILD sources' lists map to them. The coverage table maps 13 flows by 12 steps, 156 cells, none empty (section 5.4). 10 known
answers derived from the specifications' examples hold, in 12 of 12 checks (section 8.1). The
crate survey fed 15 JOSE crates and 5 CBOR crates repeated member names (section 4.7). The litmus
G1 scan finds no plug-in concept in the proposed core signatures.

## 2. What the core lacks today

Each row is a clause the design must meet: what the core at wallet-rs `f718dc3` does today, and
what the clause requires.

| Clause | Today | Required |
| :-- | :-- | :-- |
| A.1, A.3: DC API protocols | The caller passes `Received::Signed { request_object, parameters }`; the parameters come from the caller beside the JWS and can differ from the signed ones. Unsigned and signed alone. | The core decodes `data` per protocol: the parameters object, a compact JWS in `request`, a JWS JSON Serialization. The parameters come from the payload. |
| §5: `typ` | Unread. | A Request Object processed only with `typ` `oauth-authz-req+jwt`. |
| §5.1, §5.10, RFC 9101 §5, HAIP §5.1: requests by URI | DC API alone. | `client_id` and `request_uri`; the Request Object fetched by GET, or for `request_uri_method` `post` by a POST of `wallet_metadata`, plain or encrypted to the posted key (§5.1, §5.10, CS-12 §7.3 item 9); parameters in the URI and `request` by value refused. |
| §5.2, §5.3: `nonce`, `state` | `nonce` non-empty; `state` unread. | Both URL-safe ASCII; `state` echoed, and required when a query waives holder binding. |
| §5.5: `scope` | Unread. | By URI, a value the build's registered scope queries name reads as their DCQL queries; any other value `invalid_scope` (§8.5: "unknown"). |
| §5.8, RFC 7519 §4.1.3: `aud` | Unread. | Absent, or `https://self-issued.me/v2`. |
| §5.9, HAIP §5: Client Identifier Prefixes | `client_id` unread (the zkp_req proposal's M8 reads it). No Verifier authentication. | `x509_hash` and `x509_san_dns`; `origin` refused; every other prefix, and none, refused. |
| §5.11: `verifier_info` | Unread. | Handed as received, with the DCQL query, to the trust service, which requires and checks it under the WE BUILD build (reading 22, CS-02 §7.1). |
| A.1, CS-07 WU-DC-01: DC API protocols | All three. | The configured set; the WE BUILD build takes the signed two. |
| B.3.5, CS-12 §8.1: `vct_values` | The credential's own type alone. | Any type in the credential type's `extends` chain too (reading 26). |
| TS12, CS-12: `urn:eudi:sca:` | No profile. | siros-ts12 (section 4.10.2). |
| TS12 §3.6, CS-12 §5 item 4: the End-User's authentication | `Runtime::authenticate()` takes no requirement. | The profiles state the strength they need; the core refuses a weaker authentication. |
| §5.6, RFC 6749 §8.4, HAIP §5: the response type | `response_type` unread. | Response types as plug-ins the registry takes (`ResponseType`); the core's `vp_token`; a value no registered type names `unsupported_response_type`. |
| §8.1: response parameters | `vp_token` and `state` alone. | Registered `ResponseParameters` add members beside them (§8.1: "Additional response parameters MAY be defined"). |
| OAuth 2.0 Multiple Response Type Encoding Practices §2.1; §8.2, §8.3.1, A.2, HAIP §5.1, §5.2: response modes | C5 accepts `dc_api` and `dc_api.jwt` alone, matched by name in the core. | Modes as plug-ins the registry takes (`Mode`, `ModeHost`); the core's `dc_api`, `dc_api.jwt`, `direct_post.jwt`, and plain `direct_post` for errors. |
| §8.2, HAIP §5.1: the Response URI's answer | Absent. | Read the JSON object; follow `redirect_uri`; registered `AnswerReader`s read the members they declare (§8.2: "Additional parameters MAY be defined"). |
| §5.10, §10.1: `wallet_metadata` and the POST | Absent. | Composed from contributions, each name from one contributor: formats, prefixes (`client_id_prefixes_supported`, `request_object_signing_alg_values_supported`), modes, `EncryptedRequests`'s `jwks`, and registered `PostContribution`s; a POST without encryption as well. |
| RFC 7519 §4.1.3, §4.1.4, CS-02 §8.2: a Request Object's `exp` and `aud` | Unread. | Checked when present; a deployment requires them through a registered `ObjectRule` (A14). |
| §8.3, HAIP §5: response encryption | The first key on any of five curves; ECDH-ES when `alg` is absent; the key wraps; the first `enc` implemented. | A P-256 key with `alg` `ECDH-ES` present and 32-octet coordinates; A256GCM when listed, else A128GCM. |
| RFC 7515 §7.2.1, RFC 8725 §3.1, HAIP §7: JWS | Absent. | The algorithms the verifying module states (`Haip::verifies`; HAIP's: ES256); protected and unprotected header names disjoint; `Haip::verify` verifies. |
| §8.5, RFC 9101 §6, §7, RFC 6749 §4.1.2.1, §8.5, RFC 9700 §4.11.2: errors | Most codes exist, as a closed enum; error responses and their targets are absent. | Error responses in the request's mode to the platform, to the authenticated endpoint, or to an endpoint the trust decision listed; else the End-User, who can choose to send the error to the endpoint the request names; descriptions holding the Verifier's own values alone. |
| B.2.6.1: the redirect handover | `Handover::Redirect` exists and siros-mdoc reads it; phase 2 builds `Handover::DcApi` alone; B.2.6.1's bytes are unchecked. | Built from the route; B.2.6.1's example as a known answer (KA2 to KA4). |
| RFC 9700 §2.6: endpoint schemes | DC API alone. | An absolute `https` `response_uri` with a host (A13). |
| Owner ruling: the core holds no networking notion | `Runtime::fetch(&HttpsUrl)` runs inside phase 2 (siros-paso, siros-qes). | Resources as effects. |
| Owner ruling (decision 13): modular host state | One `Runtime` trait; every host implements each method, used or not; PaSO's risk-signal types in the core. | Modules by family; each plug-in bounds the modules it requires and those it uses; a plug-in's module in its crate. |
| A.4: DC API errors | Absent. | `{"error": code}`, which the core writes on every DC API route, or a cancelled flow by policy. |
| RFC 6749 §8.5: error codes | A closed `ErrorCode` enum: a plug-in's rule cannot return its specification's code. | An open `ErrorCode`, a checked `&'static str` in Appendix A.7's syntax, with constants for RFC 6749's, RFC 9101's and §8.5's codes. |
| §8.1: `Presentation` | A public `Box<RawValue>`: any JSON. | Private; `text` and `object` make §8.1's two forms. |
| Decision 20: the consent entry | `boxes.rs` holds Android Credential Manager's Standard and Payment entries. | A platform-neutral entry with a transaction header; siros-credman maps it to Credential Manager. |
| Owner ruling: no type holds an invalid state; `OptionIndex` | A public `usize`: any position. | Private; only the query's `options` and the core's slots make one (`sigs/src/kept.rs`). |
| RFC 7638: `Thumbprint` | A public array in the core: any 32 bytes. | siros-mdoc's, private; only `Thumbprint::of(key)` makes one, from the key the session holds. |
| PSD2 Art. 4(30), TS12 §3.6: `Authentication` | `factors` a public `Vec`, which may be empty. | Private fields; one factor or more (`AllOf<Factor>`). |
| RFC 7518 §6.2.1, RFC 8037 §2: `AgreeableKey` | Public fields; `x` and `y` base64url texts of any length. | Private fields; `of` decodes the point per curve and refuses a coordinate of another length; the agreeing module checks the curve (section 4.15). |
| B.2.6: `Session` | Public fields: any handover beside any keys; the core builds B.2.6's CBOR handover. | Private; the binding facts (the channel with its Origin, or the Client Identifier and the `response_uri`; the nonce; the key the core sealed to), from which siros-mdoc builds B.2.6's handover; only `AnswerRoute::session` makes one. |
| Owner ruling: `Answered` | Public fields: a profile's record anyone can build. | Private fields, with the route's mode name and the profile's fetched resources; only the core's phase 2 makes one. |
| zkp_req §2.1, §4: `ProofRequest` | Public fields: the query, the credential, the option as a `usize`, the session. | Moves to siros-zkp-req with private fields; siros-zkp-req's `Prover` module makes the presentation. |

## 3. Prior art

### 3.1 Sans-I/O protocol libraries

The pattern is "sans-I/O", the functional core and imperative shell: the protocol code turns
input data into output data and effects, and the caller performs every effect.

- **h11** (Python HTTP/1.1) separates `LocalProtocolError` (the caller broke the protocol) from
  `RemoteProtocolError` (the peer did). A caller that stops draining events stalls.
- **quinn-proto** (QUIC) takes every `Instant` as an argument: "events or timeouts with
  different instants must not be interleaved".
- **rustls unbuffered.** `process_tls_records` returns a state whose variant carries the handle
  for the next action; the caller owns every buffer, and records "MUST not be sent to the peer
  more than once".

The design answers these pitfalls by construction:

- Each step hands over its effects in one batch: `Fetch::request`, `Pending::questions`,
  `Prepared::questions`.
- The continuation is a `#[must_use]` value the effect consumes (`Fetch::resume(self, ..)`,
  `Pending::authenticate(self, ..)`, `Prepared::respond(self, ..)`). Skipping or repeating an
  effect is a compile error or a lint.
- A step holds one slot per question, typed by the question's kind, and its continuation fills
  every slot through the caller's function: an `Evaluation` takes a `Decision`, a `Resource` a
  `Fetch`. A missing, extra or mistyped answer cannot be written, so the caller's errors are
  compile errors; the Verifier's stay values (`Unreadable`, `Unauthenticated`, `Refused`), h11's
  remote errors.
- The fetched body is the caller's buffer, borrowed by `Received<'a>`, as rustls borrows the
  caller's buffers.
- Time is read once per step from the host's `Platform` and passed to the plug-in as an argument.
- Crypto stays a callback (`Haip::verify`, `Haip::encrypt_jwe`), as rustls's `CryptoProvider` keeps
  it. Network effects are data.

### 3.2 OpenID4VP wallets

| | Intake | Client Identifier Prefixes | Errors |
| :-- | :-- | :-- | :-- |
| oid4vc-ts 0.4.3 (Animo, local) | Callbacks: `fetch`, `verifyJwt`, `decryptJwe`. | Code per prefix in one module. | Thrown `Oauth2ServerErrorResponseError`; dispatch is the caller's. |
| spruceid openid4vp (`935ed0c`, Rust) | An `AsyncHttpClient` trait inside the library; GET only. | A `RequestVerifier` trait with one method per prefix. | `anyhow`. |
| EUDI Kotlin (`d4599b3`) | A Ktor client inside; GET and POST. | Sealed `SupportedClientIdPrefix`. | `Resolution.Invalid(error, dispatchDetails?)`: an error is dispatchable or not. |
| EUDI Swift (`0c6acb9`) | Mirrors the Kotlin model. | Same. | Same split. |
| walt.id (`waltid-openid4vp-wallet`, `-clientidprefix`) | Kotlin multiplatform. | A sealed class per prefix. | An error response only after "destination binding". |

Their issue trackers document the failure modes the design must exclude:

- **A boolean verdict discarded.** EUDI #490: a `JWSObject.verify` result was ignored. Here every
  check is a constructor of the next type (`Authenticated`, `Route`).
- **Errors sent to endpoints the request named.** EUDI #492: error dispatch re-derived the
  endpoint from the unvalidated request. Here an error goes to an authenticated endpoint, to the
  platform, or to an endpoint the trust decision listed apart from the request
  (`EndpointBasis::Framework`). The endpoint an unauthenticated request names has its own type,
  `ErrorTarget::Unverified`, which the caller sends to on the End-User's choice alone. EUDI's
  `ErrorDispatchPolicy.AllClients` dispatches to such endpoints without asking.
- **Fail-open defaults.** spruceid skips chain validation when `trusted_roots` is `None`; EUDI
  #494 dropped unparsable `x5c` entries silently. Here an absent trust answer is
  `Unauthenticated`, and an unparsable `x5c` item is A5.
- **Unbounded skew.** EUDI #493: `clockSkew` unbounded. Here `Skew` is at most 300 s.
- **Encoding.** oid4vc-ts fixed its form encoding per platform, and #185 found a fractional
  NumericDate. Here the core writes every form body, and `NumericDate` keeps the fraction.
- **The Response URI's answer.** EUDI #504: `redirect_uri` comes with error responses too. Here
  `ResponseUriAnswer` reads it after any POST.
- **HAIP's width.** EUDI #484 to #486 propose the same cut for EUDI's libraries: `x509_hash`,
  `direct_post.jwt` and `dc_api` alone. This design adds `x509_san_dns` (§5.9.3), and takes every
  further prefix and mode as a plug-in.

### 3.3 Patterns named

Sans-I/O (functional core, imperative shell); typestate; parse, don't validate; plug-in registry
(strategy), with the core's own cases as registered peers (rustls's `CryptoProvider`, whose
default provider implements the same traits as any other); typed host state with projection to
modules (axum's `State` and `FromRef`); policy enforcement point and policy decision point
(AuthZEN); algorithm allow-listing and explicit typing (RFC 8725 §3.1, §3.11), the allow-list the
implementing module's statement; additive Cargo features (the Cargo Book's "Features" chapter:
"features should be additive"), so a variant or a method a feature adds never breaks a crate that
does not turn it on; domain separation of hash inputs (the digest); check at use (phase 2
revalidation, existing).

### 3.4 Typed host state

axum 0.8 hands each handler the state it extracts: `State<T>` compiles only when `T: FromRef<S>`
for the router's state `S`. Its note for library authors: "keep `S` generic but require that it
can produce a `MyLibraryState`" (`axum::extract::State`). The run-time alternative,
`Extension<T>`, rejects a missing value "with a `500 Internal Server Error` response", and axum
advises: "You should prefer using `State` if possible since it's more type safe". The host
modules follow `State`: a plug-in is the library, the build's host is the state, and `Has<M>`
plays `FromRef`.

## 4. Design

### 4.1 Who owns what

| Owner | Owns |
| :-- | :-- |
| siros-openid4vp (core) | What OpenID4VP fixes, and the invariants no extension can break: every answer reaches the authenticated endpoint; a signature verifies under the key the prefix bound; phase 2 answers only records phase 1 derived; a record commits to the request as received. The host's access traits (`Has`, `MayHave`), the module it calls with no extension registered (`Platform`), and the modules its registrations bound (`Haip`, `RequestDecryption`). Arrival: DC API `data`, the Authorization Request URI, the Request Object's fetch step; `Received` and its digest; JOSE structure (compact and JSON JWS, JWT times, the JWE Request Object); the `Envelope`; routing over the registered response types and modes; request content (DCQL, `nonce`, `scope` through the registered scope queries); the Client Identifier's classification and dispatch to the registered prefix; the signature check under the bound key, by the module's stated algorithms; the effect types; the route, which binds the endpoint and the mode's encryption, the sealing of every encrypted answer, A.4's DC API error, and the session's binding facts; error responses, their `Route` and `ErrorRoute`; `Delivery`; the Response URI's `redirect_uri`; `wallet_metadata`'s and the POST's composition; phase 2 over an authenticated request. Every extension point's trait, its registration and the conflicts it refuses (section 4.12). As peers behind features: `vp_token`, OpenID4VP's modes, the SHA-2 hash algorithms, the POST of `wallet_metadata` (`RequestPost`), encrypted Request Objects (`EncryptedRequests`) with `RequestDecryption`, the `cbor` module, W3C SRI and the claims kit. |
| siros-x509 (new) | `x509_hash` and `x509_san_dns`: the `x5c` chain, the leaf's hash, dNSName entries and key as a public JWK, the trust question with `verifier_info` and the DCQL query in its context, the endpoints the decision lists, the facts it states, `x509_san_dns`'s host rule. |
| siros-mdoc, siros-sdjwt | Read the session's binding facts; their `vp_formats_supported` members and their placement of a profile's members (`Format::placement`). siros-mdoc owns B.2.6's handover, the RFC 7638 thumbprint, ISO/IEC 18013-5's `SessionTranscript` and the `DeviceMac` module, with the core's `cbor`. siros-sdjwt matches `vct_values` against the credential type's `extends` chain. |
| siros-paso, siros-qes | Revalidate from resources the caller fetched; place their response members by the format's placement. siros-paso defines the `Paso`, `RandomIds`, `IssuerTrust` and `CoseEncrypt` modules, verifies an ad-hoc metadata JWT (Proof Metadata §5.3) with siros-x509's `x5c` chain behind its `resolve` feature, classifies an inherence factor as `bio_strong` or `bio_weak` (Risk Signal Registry §2.8), seals signals with `CoseEncrypt` and the core's `cbor` behind its `sealed-signals` feature, and opens its engine to siros-ts12 (section 4.10.3). |
| siros-ts12 (new) | TS12's `payment` and `login_risk_transaction` under `urn:eudi:sca:`: the registration document, typed payloads, the translation into PaSO's model, the request rules T1 to T6, TS12's Key Binding JWT claims (section 4.10.2). |
| siros-credman (new) | Android Credential Manager's Standard and Payment entries (`AddEntryToSet`, `AddPaymentEntryToSetV2`), mapped from the core's consent entry, for the matcher. |
| siros-webuild (new) | WE BUILD's deployment rules beside its profile: CS-02 §8.2's Request Object claims (`Cs02Claims`, an `ObjectRule`) and CS-02 §8.3's error answer from the Response URI (`Cs02ErrorAnswer`, an `AnswerReader`). |
| siros-testkit | The core's test doubles: a test prefix, a test response type, test response parameters, a test mode, a test hash algorithm, a test scope query, a test POST contribution, a test answer reader, a test Request Object rule, a test trust service, the core's modules, and `test_host!`, which assembles a host from module doubles. |
| siros-integration | The HAIP and WE BUILD builds end to end, each over a host of its modules' doubles (I19). |
| The caller | The host: a struct per build holding the modules its plug-ins need. The registry: the formats, profiles, prefixes, response types, modes, response parameters, POST contributions, answer readers, Request Object rules, hash algorithms and scope queries its build registers. Every effect (section 4.3): HTTP, trust evaluation (under the WE BUILD build, `verifier_info`: its presence, the registration certificate, the intermediary rules, over-asking); crypto, time, End-User authentication; the consent UI; the platform and its URI schemes. Beside the flows: credential registration (a type's metadata chain, the TS12 documents it names) and the OpenID4VCI client. |

Features: `match` (phase 1, the matcher's build: JOSE parsing, the envelope, routing, the request
rules, matching) and `resolve` (authentication, the answer, phase 2), and one feature per
optional mechanism, which the crates using it turn on (section 4.11): `dc-api`, `uri`, `signed`,
`request-decryption`, `cbor`, `transaction-data` with `sha3`, `blake2` and `k12`, `sri` and
`claims`. The matcher builds `match`, `dc-api` and what its plug-ins' phase 1 turns on.
fluent-uri enters it through `HttpsUrl` (section 4.9.3); every other crate a mechanism links
stays behind that mechanism's feature, and no feature of the core links curve arithmetic. The core's module doubles sit in
siros-testkit (section 4.11).

### 4.2 Core signatures (siros-openid4vp)

The signatures below typecheck in `sigs/`, where an `*Api` trait stands for each type's inherent
methods. Doc comments are the contracts; `sigs/` holds them in full. No type holds an invalid
state. A value with a rule of its own has a private field and a constructor that checks the rule
(`parse`, `new`); a fixed identifier takes a `const fn new` that `checked!` runs when the crate
builds. Entries under distinct keys are a `Keyed`. A value bound to the request, the metadata or
another value has private fields and comes only from the step that holds them; an enum view
carries field types that hold their own rules.

#### Arrival (`arrival.rs`, `match`; `Received::dc_api` under `dc-api`, the URI form's constructor, `Fetch::resume`, under `uri`)

```rust
pub enum DcApiProtocol { Unsigned, Signed, Multisigned }           // A.1 (U1)

/// The protocols the wallet registers with the platform, among A.1's three, as the app's
/// configuration picks them: `ALL`, `SIGNED` (signed and multisigned), or `UNSIGNED` for a build
/// without `signed`. HAIP's width takes `ALL`, the WE BUILD build `SIGNED` (CS-07 WU-DC-01).
pub struct DcApiProtocols(&'static [DcApiProtocol]);

/// The request as received. The caller keeps it: phase 2 and a replay parse it again.
pub struct Received<'a> { form: ReceivedForm<'a>, digest: RequestDigest }

pub enum ReceivedForm<'a> {
    DcApi { origin: Origin<'a>, request: DcApiRequest<'a> },
    Uri { uri: AuthorizationUri<'a>, object: CompactJws<'a> },   // fetched from `uri.request_uri()`
}

/// `data`, its parameters parsed; `data.request`, a compact JWS; `data.request` or `data`, a JWS
/// JSON Serialization (A.3; reading 5).
pub enum DcApiRequest<'a> { Unsigned(Parameters<'a>), Signed(CompactJws<'a>),
                            Multisigned(JsonJws<'a>) }

impl<'a> Received<'a> {
    /// U1 (a protocol outside A.1's or outside `protocols`), U2, U3 for unsigned `data`, U10,
    /// U16 (feature `dc-api`).
    pub fn dc_api(protocol: &str, data: &'a str, origin: Origin<'a>, protocols: &DcApiProtocols)
        -> Result<Self, Unreadable>;
    pub fn form(&self) -> &ReceivedForm<'a>;
    /// The digest records commit to.
    pub fn digest(&self) -> &RequestDigest;
}
```

`Unreadable` carries each U rule's cause (section 4.5; `sigs/src/arrival.rs` lists the
variants).

**The digest.** SHA-256 over length-prefixed parts (8 bytes, big-endian), base64url without
padding:

| Form | Parts |
| :-- | :-- |
| DC API unsigned | Origin; `00`; the parameters text |
| DC API signed | Origin; `01`; the JWS text; the payload text |
| DC API multisigned | Origin; `02`; the JWS JSON text; the payload text |
| By URI | the URI; `10`; the Request Object: the body, or a JWE body's plaintext |

The first two rows are today's digest: record ids of DC API requests stay as they are, and the
oracle's `wire_digest` keeps its formula. The flag byte separates the domains.

#### URIs (`uri.rs`, `uri`)

The types the core's always-present enums carry (`AuthorizationUri`, `RequestUri`, `ResponseUri`,
`RedirectTarget`, `RequestUriMethod`, `FormBody`) compile in every build over fluent-uri's base,
which `match` links for `HttpsUrl`. `ResponseUri::parse`, `NotHttps` and `NotUri` compile in every
build too: every build holds `ReceivedForm::Uri`'s case, and the authentication and recourse arms
over it parse the `response_uri`. The other parsers, `Fetch`, `FormBody::of`, the POST and
`ResponseUriAnswer` are `uri`'s, which links serde_urlencoded and fluent-uri's `net` (section
4.11).

```rust
/// A URI whose query holds the request (§9), parsed by fluent-uri (RFC 3986 §3), and the
/// parameters the core reads from it, each parsed by its type: `client_id` (U3: RFC 6749
/// Appendix A.1), `request_uri` (U7), `request_uri_method` (U8; absent reads `get`).
pub struct AuthorizationUri<'a> { uri: fluent_uri::Uri<&'a str>, client_id: ClientId<'a>,
                                  request_uri: RequestUri, method: RequestUriMethod }
pub struct RequestUri(fluent_uri::Uri<String>);      // absolute `https`, a host (U7)
pub struct ResponseUri(fluent_uri::Uri<String>);     // absolute `https`, a host (A13)
pub struct RedirectTarget(fluent_uri::Uri<String>);  // a URI with a scheme (reading 23)

pub enum RequestUriMethod { Get, Post }                    // §5.1; absent reads `get` (U8)

/// What the caller fetches, with `Accept: application/oauth-authz-req+jwt` (RFC 9101 §5.2.3,
/// §5.10): a GET of the `request_uri`, or a POST of this form body to it.
pub enum RequestObjectFetch<'f> { Get(&'f RequestUri),
                                  Post { uri: &'f RequestUri, body: &'f FormBody } }

#[must_use]
pub struct Fetch<'a> { uri: AuthorizationUri<'a>, method: FetchMethod }
/// A POST keeps the key its form posts, which a JWE Request Object is encrypted to; `None`
/// without `EncryptedRequests`.
enum FetchMethod { Get, Post { body: FormBody, key: Option<EphemeralKey> } }
/// The POST of `wallet_metadata` (§5.10; feature `uri`): a core component the registry takes
/// (`RegistryBuilder::request_post`).
pub struct RequestPost;
/// Encrypted Request Objects (§5.10; feature `request-decryption`): a core component the
/// registry takes beside `RequestPost` when the build's host holds `RequestDecryption`
/// (`RegistryBuilder::request_encryption`).
pub struct EncryptedRequests;
pub enum FetchAnswer<'b> { Body(&'b str), Failed(FetchFailure) }
pub enum FetchFailure { Status(FailedStatus), MediaType, Transport }
pub struct FailedStatus(u16);    // 100 to 599, other than 200 (RFC 9110 §15); `FailedStatus::new`
/// Why a URI gives no fetch: a U rule, a `wallet_metadata` contributor that broke its
/// declaration, a module that broke its contract.
pub enum NoFetch { Unreadable(Unreadable), Metadata(MetadataRefused), Fault(Fault) }

impl<'a> Fetch<'a> {
    /// `AuthorizationUri::parse` (U3 to U8, U18, U19). `get` gives a GET. `post` gives a POST of
    /// `wallet_metadata` through the registry's `RequestPost`, its `jwks` holding a fresh key
    /// from the registry's `EncryptedRequests` when it holds one (§5.1, §5.10; reading 21);
    /// without `RequestPost`, a GET (§5.1: "Wallets not supporting the post method will send a
    /// GET request").
    pub fn of<H: CoreHost>(uri: &'a str, registry: &Registry<H>, host: &H)
        -> Result<Self, NoFetch>;
    /// What the caller GETs or POSTs.
    pub fn request(&self) -> RequestObjectFetch<'_>;
    /// U9 on a failed fetch. A compact JWE after a POST that posted a key is decrypted with it
    /// through the registry's `EncryptedRequests`, any other JWE refused (U11); the Request
    /// Object is a compact JWS (U10).
    pub fn resume<H: CoreHost>(self, answer: FetchAnswer<'a>, registry: &Registry<H>, host: &H)
        -> Result<Received<'a>, Box<Rejected<'a>>>;
}

/// `application/x-www-form-urlencoded`, UTF-8 (§5.10, §8.2), which serde_urlencoded's
/// serializer writes from text members: `RequestUriPost`, and each mode's form. A member that is
/// `None` is left out; a nested value and a name written twice are `NotForm`.
pub struct FormBody(String);
impl FormBody { pub fn of(members: &impl Serialize) -> Result<Self, NotForm>; }
pub enum NotForm { Serializer(String), Repeated(String) }

/// The Response URI's answer (§8.2): a JSON object with unique member names at every level;
/// `redirect_uri` a `RedirectTarget` when present; the outcomes the registered `AnswerReader`s
/// read from the members they declare. §8.2 leaves every other member open ("Additional
/// parameters MAY be defined"); a member no reader declares is ignored.
pub struct ResponseUriAnswer { redirect: Option<RedirectTarget>, outcomes: Vec<Box<dyn Explain>> }
pub enum AnswerError { NotObject, RedirectUri, Reader(Box<dyn Explain>) }

/// Members of the Response URI's answer a profile or a deployment defines, and the outcome the
/// wallet shows the End-User. `names` is a constant the registry checks; `read` receives the
/// declared members alone (`AnswerMembers`, core-made).
pub trait AnswerReader: DynClone + Send + Sync {
    fn names(&self) -> &'static [ParameterName];
    fn read(&self, members: &AnswerMembers<'_>)
        -> Result<Option<Box<dyn Explain>>, Box<dyn Explain>>;
}
pub struct AnswerMembers<'a> { object: &'a Object<'a>, names: &'static [ParameterName] }

impl ResponseUriAnswer {
    /// Parses the body and runs each registered reader over its members.
    pub fn parse<H: Build>(body: &str, registry: &Registry<H>) -> Result<Self, AnswerError>;
    /// Where the wallet sends the user agent (HAIP §5.1).
    pub fn redirect(&self) -> Option<&RedirectTarget>;
    /// The outcomes the readers read, which the wallet shows the End-User.
    pub fn outcomes(&self) -> &[Box<dyn Explain>];
}

impl<H: Build> RegistryBuilder<H> {
    /// `build` refuses a name another reader declares (`NameTwice`) and `redirect_uri`
    /// (`NameReserved`).
    pub fn answer_reader<R: AnswerReader + 'static>(&mut self, reader: R);
}
```

**The query.** `AuthorizationUri::parse` reads the query with serde_urlencoded (section 4.7)
into `QueryRead`, whose `Deserialize` visits the pairs. A name given twice, known or unknown,
stops the read (U4). A parameter without a value counts as omitted (RFC 6749 §3.1).
`client_id`, `request_uri`, `request_uri_method` and `request` are kept, and every other name is
ignored (§5). serde_urlencoded's error holds a message alone, so the repetition travels as the
read's value. The rules then run in this order: U5, U3 (`client_id`), U6, U19, U18, U7, U8.
serde_urlencoded decodes an escape whose octets are no UTF-8 as U+FFFD, and each parameter the
core reads refuses a value holding it (`crates/form-probe.out`): `client_id` by RFC 6749
Appendix A.1's `*VSCHAR` (U3), `request_uri` by fluent-uri (U7), `request_uri_method` by its
two values (U8); `request` is refused whatever it holds (U6, U19). `RequestUri` and
`ResponseUri` refuse an empty host, which fluent-uri accepts (`https:///r`, section 4.7).

**Forms.** A mode writes its form through `FormBody::of` over text members, and the core keeps
the encoding: serde_urlencoded's serializer escapes as RFC 6749 Appendix B says and refuses a
map, a sequence or a struct as a member's value (`NotForm::Serializer`); the body read back
refuses a name written twice (`NotForm::Repeated`), which a sequence of pairs could write.
`PostBody::of` refuses `application/x-www-form-urlencoded`, so every form body comes from
`FormBody::of`.

**The Response URI's answer.** §8.2 defines `redirect_uri` alone, which the core reads. A
deployment's members come through a registered `AnswerReader`: siros-webuild's `Cs02ErrorAnswer`
reads CS-02 §8.3's `error` and `error_description`, as RFC 6749 §5.2 writes them, into the outcome
the wallet shows (CS-02 §6.1.7), and refuses an `error_description` without an `error`.

#### JOSE (`jose.rs`; parsing under `match`, keys under `resolve`, the JWE under `request-decryption`; `JweError` and `JweAlgorithms` in every build)

```rust
/// A JWS `alg` (IANA "JSON Web Signature and Encryption Algorithms"): one or more printable
/// ASCII characters other than space and `"`; a module names its own with `checked!`.
pub struct JwsAlgorithm(&'static str);
impl JwsAlgorithm { pub const ES256: Self; pub const fn new(name: &'static str) -> Option<Self>; }
/// What a verifying module states (`Haip::verifies`); `NONE`, an empty list, is a module that
/// verifies nothing, under which A7 refuses every signature.
pub struct JwsAlgorithms(&'static [JwsAlgorithm]);
impl JwsAlgorithms { pub const NONE: Self; pub const fn new(algorithms: &'static [JwsAlgorithm]) -> Self; }
/// What a decrypting module states (`RequestDecryption::decrypts`): the curves of the keys it
/// draws, the `alg` and `enc` values it decrypts, each list one or more.
pub struct JweAlgorithms { curves: &'static [Curve], agreements: &'static [KeyAgreement],
                           encryptions: &'static [ContentEncryption] }

/// A signature's octets; their length is the `alg`'s, which the verifying module checks.
pub struct JwsSignature(Vec<u8>);

/// A protected header: `alg`, `typ`, `kid` and `crit` read; every member kept for the prefix
/// plug-in.
pub struct ProtectedHeader { alg: HeaderAlgorithm, typ: Option<HeaderType>, kid: Option<KeyId<'static>>,
                             members: Object<'static> }

pub struct CompactJws<'t> { text: Cow<'t, str>, header: ProtectedHeader, payload: String,
                            signing_input: Range<usize>, signature: JwsSignature }
pub struct JsonJws<'t> { text: &'t str, payload: String, first: JsonSignature,
                         rest: Vec<JsonSignature> }
pub struct JsonSignature { header: ProtectedHeader, unprotected: Option<Object<'static>>,
                           signing_input: String, signature: JwsSignature }

/// One signature to verify, as its JWS holds it: its protected and unprotected headers, its
/// signing input (RFC 7515 §5.1), its bytes. Only the JWS makes one, so the signing input is
/// that header's and that payload's.
pub struct Signed<'s> { header: &'s ProtectedHeader, unprotected: Option<&'s Object<'static>>,
                        signing_input: &'s [u8], signature: &'s JwsSignature }

pub enum JwsError { Structure, Base64, Json(JsonError), Algorithm(Option<String>),
                    Critical(String), HeaderTwice(String) }

/// A compact JWE Request Object (RFC 7516 §7.1): five parts; a protected header whose `alg` and
/// `enc` are ones the decrypting module states (RFC 8725 §3.1); `crit` read as for a JWS.
/// `RequestDecryption::decrypt` decrypts it.
pub struct CompactJwe<'t> { text: &'t str, header: Object<'static> }
impl<'t> CompactJwe<'t> {
    pub fn parse(text: &'t str, accepted: &JweAlgorithms) -> Result<Self, JweError>;
}
/// In every build: `Unreadable::Jwe` carries it.
pub enum JweError { Structure, Base64, Json(JsonError), Algorithm(Option<String>),
                    Encryption(Option<String>), Critical(String) }

pub struct NumericDate { seconds: i64, nanos: u32 }      // a fraction allowed (RFC 7519 §2)
pub struct Skew(Seconds);                                // at most 300 s (RFC 7519 §4.1.4)
pub struct Validity { exp: Option<NumericDate>, nbf: Option<NumericDate> }

/// A public key as RFC 7517 writes it: a JSON object with unique names, `kty` a string, no
/// private member (RFC 7518 §6.2.2, §6.3.2, §6.4); `parse` refuses another (`NotPublicJwk`).
pub struct PublicJwk(Object<'static>);
/// The key a prefix binds and a signature verifies under (`resolve`, beside `Haip`, which takes
/// it). The verifying module checks that it fits the signature's `alg`, a point off its curve
/// included.
pub struct VerificationKey(PublicJwk);
```

`CompactJws::parse` splits the text on `.` into exactly three parts, decodes each with base64's
URL-safe alphabet without padding, and parses the header with the core's `json` module. It
refuses per `JwsError`: an `alg` absent, no string, or `none` (RFC 8725 §3.2); a `crit` that is
empty, sits outside the protected header, or names a header the wallet does not process (RFC
7515 §4.1.11). `JsonJws::parse` reads the general and the flattened serialization the same way,
refuses an empty `signatures` array, and refuses a name in both a signature's protected and
unprotected header (RFC 7515 §7.2.1). `ProtectedHeader::typ` compares as RFC 7515 §4.1.9 says:
`application/` prefixed when it holds no `/`, case-insensitively.

**Algorithms are the modules' capabilities.** The parse reads `alg` as a name, so the matcher,
which holds no verifying module, parses every JWS a request carries. `Envelope::questions`
refuses an `alg` the `Haip` that the prefix's registration reached does not state
(`Haip::verifies`, A7) before it asks the caller; `Pending::authenticate` then has `Haip::verify`
check the signature and the key's fit to its `alg` (A8). `CompactJwe::parse` accepts exactly the
`alg` and `enc` values `RequestDecryption::decrypts` states (U11). Each list has one owner:
`request_object_signing_alg_values_supported` is `Haip::verifies`; the JWE modes'
`authorization_encryption_*` members are their key rule intersected with `Haip::agreements`, in
the module's order; the JWE Request Object's algorithms are `RequestDecryption::decrypts`. An
empty statement (`JwsAlgorithms::NONE`, `Agreements::NONE`) is a module that lacks the
capability, and the core never calls the method it would serve. The core's vocabulary names no
profile's values: HAIP's ES256, and its ECDH-ES on P-256 with A256GCM and A128GCM, are the
statements a HAIP host's modules make and the key rule the core's JWE modes hold.
`Pending::authenticate` holds A9 inside its step: the Request Object is processed before `exp`
and at or after `nbf`, each within the skew. siros-x509 writes the leaf's EC or EdDSA key as a public
JWK; the verifying module holds the curve arithmetic.

#### The envelope (`envelope.rs`, `match`)

```rust
pub enum Channel<'r> { DcApi(&'r Origin<'r>), Uri }

/// DC API `data` or the Request Object's payload: a JSON object with unique member names at
/// every level, which `Parameters::parse` refuses otherwise (U3).
pub struct Parameters<'r>(RawObject<'r>);

/// Each the JWS the request arrived in, whose parse holds one signature or more. `One` carries
/// its payload's `client_id`, refused when absent by A3 over the DC API and by U14 by URI.
pub enum Signatures<'r> { Unsigned,
                          One { jws: &'r CompactJws<'r>, client_id: Option<ClientId<'r>> },
                          Many(&'r JsonJws<'r>) }

/// The request as read, with the hash algorithms and scope queries of the registry it was read
/// with. The routing holds the registered mode the request names, as phase 1 reads it
/// (`dyn Mode`). `client_metadata` is read once, kept as read or as C6's refusal; the `nonce`
/// once, kept as N1 accepts it or as why it holds none (`NonceError { Absent, Unsafe }`,
/// crate-private), which `Request::parse` maps to S3 and N1 and the route reads. The `hashes`
/// field, `hashes()` and `Hashes` compile under `transaction-data`, `scopes` in every build.
pub struct Envelope<'r> { hashes: Hashes<'r>, scopes: Scopes<'r>, received: &'r Received<'r>,
                          parameters: Parameters<'r>, signatures: Signatures<'r>,
                          routing: Routing<'r>,
                          client_metadata: Result<ClientMetadata<'r>, MetadataError>,
                          nonce: Result<Nonce<'r>, NonceError> }

impl<'r> Envelope<'r> {
    /// U3, U10, U12, U13, U14, U16, U17; the routing read over the registry's response types and
    /// modes. The envelope keeps the registry's hashes and scope queries.
    pub fn parse<H: Build>(received: &'r Received<'r>, registry: &'r Registry<H>)
        -> Result<Self, Unreadable>;
    /// The registry's hash algorithms (B.3.3.1; `transaction-data`) and scope queries (§5.5).
    pub fn hashes(&self) -> Hashes<'r>;
    pub fn scopes(&self) -> Scopes<'r>;
    /// What the request asks of its answer: every later step reads it here.
    pub fn routing(&self) -> &Routing<'r>;
    /// `client_metadata` as read, or C6's refusal of it: `Accepted` borrows it, and
    /// `Pending::authenticate` reads the Verifier's `VerifierMetadata` from it.
    pub fn client_metadata(&self) -> Result<&ClientMetadata<'r>, &MetadataError>;
    /// The received form's channel.
    pub fn channel(&self) -> Channel<'r>;
    /// The Request Object's parameters alone when there is one (§5.10.1, RFC 9101 §6.3).
    pub fn parameters(&self) -> &Parameters<'r>;
    pub fn signatures(&self) -> &Signatures<'r>;
    /// `Signatures::One`'s `client_id`; `None` for an unsigned DC API request (ignored, A.2) and
    /// a multisigned one (each protected header names its own, A.3.2.2).
    pub fn client_id(&self) -> Option<&ClientId<'r>>;
    /// `verifier_info` as received, for the trust service (reading 22).
    pub fn verifier_info(&self) -> Option<&'r RawValue>;
}
```

`Request::parse(origin, received)` becomes `Request::parse(envelope)`, which reads the routing,
the hash algorithms and the scope queries the envelope holds and keeps the envelope
(`Request::envelope`). Phase 2 reads the routed mode's
registration from its own registry by the routing's `ModeHandle`, the name checked: a handle the
registry holds under another name is a `Fault`. The envelope holds `Scopes` in every build and
`Hashes` in a `transaction-data` build. Its rules keep
their order and texts (C0, the DCQL structure, `nonce`), require `dcql_query` or a `scope` naming
a registered query (§5.1), and gain S3 and S4 (`scope` by URI, through the registered scope
queries, feature `uri`), N1 (`nonce` URL-safe) and P7. `Request::request_object()` returns the JWS
text of a signed request, compact or JSON, so siros-paso's integrity member reads it as today.
`Request::client_id()` (the zkp_req proposal's M8) reads the envelope's.
`Request::response_mode()` gives way to `Routing::mode` in the core, and to `Answered::mode` in
the profiles.

#### Routing (`routing.rs`, `match`)

A response type and a response mode are extension points. RFC 6749 §8.4: "New response types
... are defined and registered in the Authorization Endpoint Response Types registry"; OAuth 2.0
Multiple Response Type Encoding Practices §2.1: "it is expected that additional Response Modes may
be defined by other specifications in the future". Phase 1 reads a mode as `Mode`: its name, its
channel, its request rules and the names of its `wallet_metadata` members. Phase 2 reads it as
`ModeHost<H>` for answers and `ErrorModeHost<H>` for a URI route's errors (the answer, below).
What a mode carries is its registration's.

```rust
/// A `response_mode` value: one or more of ASCII letters, digits, `_`, `.` and `-`, the
/// characters of the registered names; a mode makes its own with `checked!`.
pub struct ModeName(&'static str);
impl ModeName { pub const fn new(name: &'static str) -> Option<Self>; }

/// The channel a request arrives on, which its answer leaves by.
pub enum ChannelKind { DcApi, Uri }

/// What a registered mode carries, by its registration: `mode` and `jwe_mode` register answers,
/// `error_mode` a URI mode's errors. `Errors`: a mode registered with `error_mode` alone; C5
/// refuses a request naming it, and its error goes in the mode's form (reading 24's plain
/// `direct_post`).
pub enum Carries { Answers, Errors }

/// A response mode as phase 1 reads it. The core's modes implement it as peers of any
/// extension's.
pub trait Mode: DynClone + Send + Sync {
    /// The `response_mode` value it answers.
    fn name(&self) -> ModeName;
    /// The channel it answers on.
    fn channel(&self) -> ChannelKind;
    /// The mode's request rules (a JWE mode: C7); the core lists their refusals after C6.
    fn rules(&self, request: &Request<'_>, metadata: &VerifierMetadata<'_>) -> Vec<Refusal>;
    /// The names of the `wallet_metadata` members it writes (§5.10, §10.1), a constant the
    /// registry checks when it builds; a DC API mode declares none.
    fn metadata_names(&self) -> &'static [ParameterName];
}

/// A `response_type` value (RFC 6749 §3.1.1): response names of ASCII letters, digits and `_`,
/// separated by single spaces; a plug-in makes its own with `checked!`.
pub struct ResponseTypeName(&'static str);
impl ResponseTypeName { pub const fn new(name: &'static str) -> Option<Self>; }

/// A response type whose Authorization Response carries the VP Token (§8). P1 refuses a request
/// whose `response_type` names no registered type. The parameters a type adds beside `vp_token`
/// come from a registered `ResponseParameters`.
pub trait ResponseType: DynClone + Send + Sync {
    fn name(&self) -> ResponseTypeName;
}
/// `vp_token` (§5.6, HAIP §5), the core's peer, which adds no parameter.
pub struct VpToken;

/// Parameters an extension adds to the Authorization Response beside `vp_token` and `state`
/// (§8.1: "Additional response parameters MAY be defined"; RFC 9207's `iss`, `id_token` for a
/// `vp_token id_token` type): their names, a constant the registry checks and keeps. In every
/// build, as `NoHost`'s registry stores it.
pub trait ResponseParameters: DynClone + Send + Sync {
    fn names(&self) -> &'static [ParameterName];
}
/// The phase-2 half (`resolve`): members of the names the registry kept for the part, each once,
/// for the response type the request names, from the session the presentations bind.
pub trait ResponseParametersHost<H>: ResponseParameters {
    fn members(&self, response_type: ResponseTypeName, session: &Session<'_>, host: &H)
        -> Result<Vec<ResponseMember>, Fault>;
}

/// The Verifier's `client_metadata` as a mode reads it, and its `jwks` keys the wallet can agree
/// a key with; only the core makes one, from the request it parsed.
pub struct VerifierMetadata<'k> { object: Option<Node<'k>>, keys: VerifierKeys<'k> }
impl<'k> VerifierMetadata<'k> {
    /// `encrypted_response_enc_values_supported` lists `enc`, or, absent, `enc` is A128GCM (§5.1's
    /// default): the key rule and phase 2's check of a `Jwe` choice read it.
    pub fn lists(&self, enc: ContentEncryption) -> bool;
}
pub struct VerifierKeys<'k> { keys: Vec<AgreeableKey<'k>> }
/// One of the Verifier's keys by its place; only `VerifierKeys::iter` yields one, so a mode
/// chooses among the request's keys alone.
pub struct VerifierKey<'k> { place: KeyPlace, key: &'k AgreeableKey<'k> }

pub struct ModeHandle(usize);                  // a place in the registry; only the registry makes one
/// The registered mode a request names on its channel; only `Envelope::parse` makes one, from the
/// registry it reads. Phase 2 reads the mode's registration from its own registry by `handle`,
/// the name checked, a mismatch a `Fault`.
pub struct RoutedMode { handle: ModeHandle, name: ModeName, carries: Carries }

/// HAIP §5's key rule's choice under its own statement (`modes::KEY_RULE`), as phase 1 reads it:
/// the key's place among the request's agreeable keys, its `kid`, and the `enc`; `modes`
/// re-exports it. A reader that binds the key before phase 2 reads it; phase 2 chooses under the
/// sealing module's statement, which can narrow it.
pub struct KeyChoice { place: KeyPlace, kid: KeyId<'static>, enc: ContentEncryption }
impl KeyChoice {
    pub fn of(mode: ModeName, metadata: &ClientMetadata<'_>) -> Result<Self, KeyRule>;   // C7
}

pub struct State<'r>(Cow<'r, str>);     // P6; `State::parse` refuses another value
pub struct Echo<'r>(Cow<'r, str>);      // `state` as received (RFC 6749 §4.1.2.1)

/// A mode that carries answers is held with its registration as phase 1 reads it, so its rules
/// run without the host's type.
pub struct Routing<'r> { response_type: Option<ResponseTypeName>,
                         mode: Option<(RoutedMode, &'r dyn Mode)>,
                         response_uri: Option<Cow<'r, str>>, state: Option<Echo<'r>>,
                         refusals: Vec<Refusal> }

/// Only `Envelope::parse` makes one, from the registry's response types and modes, and the
/// envelope holds it. P1, C5, P5, P6, in that order. Over the DC API `state` and `redirect_uri`
/// are unrecognized parameters (A.2).
impl<'r> Routing<'r> {
    /// The registered response type the request names; `None` when P1 refuses it.
    pub fn response_type(&self) -> Option<ResponseTypeName>;
    /// The registered mode the request names on its channel; `None` when it names none.
    pub fn mode(&self) -> Option<&RoutedMode>;
    pub fn response_uri(&self) -> Option<&NamedResponseUri<'r>>;
    pub fn echo(&self) -> Option<&Echo<'r>>;
    pub fn state(&self) -> Option<State<'_>>;
    pub fn refusals(&self) -> &[Refusal];
}

/// What a format's request rules read. Only `Accepted::new` makes one, from the request's
/// routing.
pub struct QueryContext<'q> { request: &'q Request<'q>, mode: Option<ModeName>,
                              naming: EntryNaming, supported: Option<Node<'q>> }
impl<'q> QueryContext<'q> {
    pub fn request(&self) -> &'q Request<'q>;
    /// The mode's name; `None` when rule C5 refuses the request's mode.
    pub fn mode(&self) -> Option<ModeName>;
    /// Whether a `transaction_data` entry names the query.
    pub fn naming(&self) -> EntryNaming;
    /// The Verifier's `vp_formats_supported` value for the format.
    pub fn supported(&self) -> Option<&Node<'q>>;
}

/// What a format's phase 2 reads of a query: its phase-1 context, under the mode rule C5
/// accepted. Only `Prepared::prepare` makes one, so no phase-2 reading under a refused mode
/// exists.
pub struct AnsweredContext<'q> { context: QueryContext<'q>, mode: ModeName }
impl<'q> AnsweredContext<'q> {
    pub fn mode(&self) -> ModeName;
    pub fn context(&self) -> &QueryContext<'q>;
}

impl<H: Build> RegistryBuilder<H> {
    /// A response type; `build` refuses a name registered twice (`ResponseTypeTwice`).
    pub fn response_type<T: ResponseType + 'static>(&mut self, response_type: T);
    /// A mode whose routes are in the clear; it carries answers.
    pub fn mode<M: HostedMode<H>>(&mut self, mode: M);
    /// A mode whose routes the core seals as JWEs through the host's `Haip`, whose accessor the
    /// registration keeps; it carries answers. `NoHost` takes it for phase 1.
    pub fn jwe_mode<M: HostedMode<H>>(&mut self, mode: M) where H: JweHost;
    /// A URI mode's errors; registered here alone, the mode carries errors alone. A DC API mode
    /// is `ErrorModeChannel`: A.4's errors are the core's.
    pub fn error_mode<M: HostedErrorMode<H>>(&mut self, mode: M);
    // `build` refuses a name registered twice on one channel, and an answer and an error
    // registration of one name and channel by modes of different types, as each registration
    // records `TypeId::of::<M>()` (`ModeTwice`); a DC API mode that declares `wallet_metadata`
    // members (`MetadataChannel`); and a member name another part declares or the core writes
    // (`NameTwice`, `NameReserved`).
    /// Response parameters; `build` refuses a name another part declares (`NameTwice`) or one of
    /// `CORE_RESPONSE`: `vp_token`, `state`, `error`, `error_description`, `error_uri`
    /// (`NameReserved`), and keeps each part's names as it checked them (`RegisteredParameters`).
    pub fn response_parameters(&mut self, parameters: impl HostedResponseParameters<H>);
}
```

**P1 and C5.** `Envelope::parse` looks the request's `response_type` up among the registered
response types (P1) and its `response_mode` among the registered modes of the request's channel
(C5). A request whose mode is absent, names no registered mode on its channel, or names a mode
that carries errors alone breaks C5. `Accepted::new(request, registry)` keeps its
signature and reads the routing of the request's envelope: C1 to C8, the routing's refusals and
the named mode's own rules after C6, the model's order. The Verifier's metadata is the request's
`client_metadata` (§5.9.3 for both X.509 prefixes). C5 has one variant per channel,
`RoutingRule::DcApi` (id `c5`) and `RoutingRule::Uri` (id `c5_uri`). Over the DC API C5's text
stays "C5 response_mode ... is no DC API response mode", so the differential's refusal lists keep
their texts; P1's reads "names no response type the wallet answers". A JWE mode's C7 keeps the
model's text for both causes (`KeyRule::Key`, `KeyRule::Enc`, each naming the mode), and phase 2
refuses with C7 before the End-User authenticates when the sealing module states less than the
key rule. Over the DC API every request has a carrier for its error, A.4's, which the core writes.
By URI, a request whose mode names no registered error mode has no carrier: its error goes
nowhere, and the End-User hears of it (`Unroutable`). A request naming a mode that carries errors
alone gets C5's error in that mode's form at its authenticated `response_uri`.

`QueryContext::mode` and `AnsweredContext::mode` give the mode's name; `Answered::mode` gives
it to the profiles, for siros-paso's response mode signal and siros-ts12's KB-JWT
`response_mode`. A format or a profile reads the name and names no mode in the core's types.

#### Verifier authentication (`authenticate.rs`, `resolve`; the prefixes and the signature step under `signed`)

```rust
/// The text before the first `:`: one or more of RFC 6749 Appendix A.1's characters other than
/// `:`, and not the reserved `origin` (A1). A plug-in makes its own with `checked!`.
pub struct PrefixName(&'static str);
impl PrefixName { pub const fn new(name: &'static str) -> Option<Self>; }

/// A prefix plug-in (§5.9.3: "Other specifications can define further Client Identifier
/// Prefixes"): its name.
pub trait ClientPrefix: Send + Sync {
    fn name(&self) -> PrefixName;
}
/// A prefix's claim over the build's host; its bounds name the modules it calls.
pub trait PrefixHost<H>: ClientPrefix {
    /// The prefix's syntax and header rules, refused with the plug-in's rule, which the core
    /// reports under the prefix's name (`PrefixRefusal`, A5); and the questions its framework
    /// answers.
    fn claim<'c>(&'c self, claim: ClientClaim<'c>, host: &H)
        -> Result<Box<dyn PrefixClaim + 'c>, Box<dyn Explain>>;
}
/// A prefix the registry takes: `signed` implies `resolve`, so every build that registers a prefix
/// takes its phase 2 (`PrefixHost<H>`).
pub trait HostedPrefix<H>: PrefixHost<H> {}

/// What a prefix reads, through accessors; only `Envelope::questions` makes one. `original()` is
/// the part of `client_id` after the prefix and its `:`. `verifier_info` and `dcql_query` as
/// received: the prefix puts both in its evaluation's context, for the trust service's rules on
/// them (reading 22).
pub struct ClientClaim<'c> { client_id: &'c ClientId<'c>, signed: Signed<'c>,
                             parameters: &'c Parameters<'c>, channel: ClaimChannel<'c>,
                             verifier_info: Option<&'c RawValue>, query: Option<&'c RawValue> }
/// By URI, the `request_uri`, and the request's `response_uri` parsed (A13); `None` is A12.
pub enum ClaimChannel<'c> { DcApi(&'c Origin<'c>),
                            Uri { request_uri: &'c RequestUri,
                                  response_uri: Option<&'c ResponseUri> } }

/// Each method reads `Decided`: the decisions on the claim's own evaluations, in its order.
pub trait PrefixClaim {
    fn questions(&self) -> Vec<Evaluation>;
    /// The key and what the framework states, from the decisions at `now` (A6); the Verifier's
    /// name resolved through the wallet's `context`.
    fn bind(&self, decided: Decided<'_>, now: Timestamp, skew: Skew, context: &Context)
        -> Result<ClientBinding, Unbound>;
    /// What vouches for the `response_uri` the request names (A12); asked by URI alone.
    fn endpoint(&self, decided: Decided<'_>, response_uri: &ResponseUri)
        -> Result<EndpointBasis, Unbound>;
}
/// `Unworded`: the wallet's context words no text of the binding, which ends the authentication
/// with a `Fault`.
pub enum Unbound { Denied, Endpoint, Unworded(ResolveError) }    // A6, A12

/// The core binds it: over the DC API the platform's; by URI the request's `response_uri`, with
/// the basis `PrefixClaim::endpoint` gives.
pub enum BoundEndpoint { DcApi, ResponseUri { uri: ResponseUri, basis: EndpointBasis } }

/// `Framework`: the trust decision lists the endpoint, apart from the request; the error of a
/// later check goes there. `Request`: the request names it; it stands once authenticated.
pub enum EndpointBasis { Framework, Request }

/// `name`: the Verifier's name the framework states, resolved. `facts`: what the trust framework
/// states about the Verifier, for the plug-ins that read it.
pub struct ClientBinding { pub key: VerificationKey, pub name: Option<Text>,
                           pub facts: Option<Object<'static>> }

pub enum OriginPolicy { Accept, Evaluate }        // unsigned DC API requests
pub struct TrustConfig { pub skew: Skew, pub origins: OriginPolicy }

/// A rule a profile or a deployment sets on an authenticated Request Object's claims, beside RFC
/// 7519's checks of `exp` and `aud` when present (A9, A10). `check` reads the payload's claims
/// after A10 and returns its rule's refusal; the core refuses with A14 and the rule's code.
pub trait ObjectRule: DynClone + Send + Sync {
    fn check(&self, claims: &Object<'_>) -> Option<Refusal>;
}

pub enum VerifierId<'r> { Origin(&'r Origin<'r>), Client(ClientId<'r>) }
/// Only `Pending::authenticate` makes one; `id()`, `name()`, `facts()`, `metadata()` and
/// `endpoint()` read it.
pub struct Verifier<'r> { id: VerifierId<'r>, name: Option<Text>,
                          facts: Option<Object<'static>>, metadata: Option<&'r RawValue>,
                          endpoint: BoundEndpoint }

/// The Origin's evaluation, nothing, or each signature's claim with the slots of its own
/// evaluations (`Asked`), each claim beside the prefix the registry holds.
#[must_use]
pub struct Pending<'e, H> { envelope: &'e Envelope<'e>, asked: Asked<'e, H> }

/// Only `Pending::authenticate` makes one. It holds the Verifier's `VerifierMetadata`, read from
/// the envelope's `client_metadata`, or C6's refusal of it, which the route reads.
pub struct Authenticated<'e> { envelope: &'e Envelope<'e>, verifier: Verifier<'e>,
                               metadata: Result<VerifierMetadata<'e>, &'e MetadataError> }

impl<'e> Envelope<'e> {
    /// The Origin's evaluation for an unsigned DC API request, as configured; else each
    /// signature's prefix claim, from `registry`, the one the envelope was read with. A1, A2, A3,
    /// A5, A7 (an `alg` the registration's `Haip::verifies` does not state, before any question),
    /// A13.
    pub fn questions<H: CoreHost>(&'e self, registry: &'e Registry<H>, config: &TrustConfig,
                                  host: &H) -> Result<Pending<'e, H>, Box<Rejected<'e>>>;
}

impl<'e, H: CoreHost> Pending<'e, H> {
    pub fn questions(&self) -> impl Iterator<Item = &Evaluation>;
    /// `decide` answers every evaluation of `questions`, once, in order. Then the first claim,
    /// in the signatures' order, whose binding holds (A6), whose endpoint holds by URI (A12: no
    /// `response_uri`, or `PrefixClaim::endpoint` refusing it), whose signature verifies under
    /// the bound key through the `Haip` the prefix's registration reached (A8), inside the
    /// Request Object's validity (A9), with `aud` absent or `https://self-issued.me/v2` (A10),
    /// and holding every registered `ObjectRule` (A14). A11 lists each signature's reason when
    /// none does. `context` resolves the bound Verifier's name.
    pub fn authenticate(self, decide: impl FnMut(&Evaluation) -> Decision,
                        config: &TrustConfig, context: &Context, host: &H)
        -> Result<Authenticated<'e>, Box<Rejected<'e>>>;
}

impl<H: Build> RegistryBuilder<H> {
    /// A Client Identifier Prefix (`prefix` registers a profile under a type prefix). `build`
    /// refuses a prefix registered twice (`RegistryError::PrefixTwice`); `PrefixName` refuses
    /// `origin`. The registration keeps the host's `Haip` accessor, through which the core checks
    /// A7 and verifies A8.
    pub fn client_prefix(&mut self, prefix: impl HostedPrefix<H> + 'static) where H: Has<dyn Haip>;
    /// A rule over an authenticated Request Object's claims (A14).
    pub fn object_rule<R: ObjectRule + 'static>(&mut self, rule: R);
}
```

The Client Identifier is classified once (§5.9.1): the text before the first `:` names the
registered prefix, or `origin` (A1). Any other text before a `:`, and an identifier without one
(a pre-registered client, §5.9.2), is A2. A prefix reads the core-made `ClientClaim` and returns
a key and a basis for the endpoint; the core verifies the signature under that key and binds the
endpoint itself, so a prefix reaches no endpoint and no key the request and the decisions do not
give. `ClientId::prefixed` (§5.9.1) is the one reading of a prefix: the classification, the
`ClientClaim`'s original identifier and `WalletMetadata::of` call it. A build without `signed`
registers no prefix and refuses a signed request with A2 (A1 for `origin`), as a build that
registers no prefix does; its `DcApiProtocols` hold the unsigned protocol alone, so U1 refuses the
signed two first. Each A rule's text leads with its rule (A1 to A14); A9 carries the `TimeError`,
A10 the `aud`, A12 the `response_uri` or `None`, A13 the `NotHttps`, and A14 the rule's
`Refusal`, whose code `Unauthenticated::code` returns. RFC 7519 makes `exp` and `aud` optional; a
deployment that requires them registers an `ObjectRule`: siros-webuild's `Cs02Claims` holds CS-02
§8.2's "The Presentation Request Object MUST include" for the WE BUILD build.

#### Effects (`effects.rs`, `resolve`)

```rust
/// AuthZEN's subject and resource (§5.1, §5.2), action (§5.3) and evaluation (§6.1). The
/// plug-in fixes `EntityType` and `ActionName` with `checked!`; each refuses an empty text, and
/// `EntityId::parse` too.
pub struct Entity { pub kind: EntityType, pub id: EntityId, pub properties: Option<Object<'static>> }
pub struct Action { pub name: ActionName, pub properties: Option<Object<'static>> }
pub struct Evaluation { pub subject: Entity, pub action: Action, pub resource: Entity,
                        pub context: Option<Object<'static>> }
/// An https URL a profile revalidates with; only the core makes one, from `ProfileHost::wanted`.
pub struct Resource(HttpsUrl);

pub enum Verdict { Permit, Deny }                  // AuthZEN §5.5
pub struct Decision { pub verdict: Verdict, pub context: Option<Object<'static>> }
pub enum Fetch { Fetched { content: Vec<u8>, media: MediaType }, Unfetched }
/// A `Content-Type` value (RFC 9110 §8.3.1) as received, and its type and subtype lowercased,
/// as they compare (`essence()`). Only `MediaType::parse` makes one; `NotMediaType` names the
/// rule broken (`Type`, `Slash`, `Subtype`, `Separator`, `Equals`, `ParameterValue`,
/// `QuotedString`) with the byte offset.
pub struct MediaType { text: String, essence: String }

/// A question kind and the answer it takes. Sealed: `Evaluation` takes `Decision`, `Resource`
/// takes `Fetch`.
pub trait Ask: Sealed { type Answer; }
/// A step's questions of one kind, one slot per question, in order; only the step makes them.
pub struct Slots<Q> { questions: Vec<Q> }
impl<Q: Ask> Slots<Q> {
    pub fn questions(&self) -> &[Q];
    /// The continuation's: `answer` once per question, in order.
    pub(crate) fn fill(self, answer: impl FnMut(&Q) -> Q::Answer) -> Filled<Q>;
}
/// Each question with its answer, one per slot; only `Slots::fill` makes one.
pub struct Filled<Q: Ask> { replies: Vec<Reply<Q>> }
/// One question and its answer: `question()`, `answer()`.
pub struct Reply<Q: Ask> { question: Q, answer: Q::Answer }
/// A prefix claim's own evaluations with their decisions; only `Pending::authenticate` makes one.
pub struct Decided<'a>(&'a [Reply<Evaluation>]);
```

The caller performs a step's questions from `questions()`, then calls its continuation with a
function that answers one question: `Pending::authenticate` with `decide`, `Prepared::respond`
with `fetch`. The continuation calls it once per slot, in order, so the answers hold one of each
question's kind per question, and no other set can be built. `Prepared::prepare` gives each
record one `Resource` slot per distinct URL its profile wants, in the order each first appears:
the caller fetches a URL once, and every mention of it reads that answer.

#### The answer (`response.rs`, `resolve`)

A mode's phase 2 is `ModeHost<H>` for answers and `ErrorModeHost<H>` for a URI route's errors,
whose bounds name the modules each calls. A mode chooses the route's encryption once and writes
the body around what the core hands it. The core writes every `Delivery`'s endpoint from the
authenticated route, seals every encrypted answer and error itself through the `Haip` the mode's
`jwe_mode` registration reached, and writes A.4's error on every DC API route: a mode reaches no
endpoint, sees no plaintext of a sealed route, and binds no key the route did not.

```rust
/// A response mode's answers over the build's host.
pub trait ModeHost<H>: Mode {
    /// The route's encryption, from the Verifier's keys and metadata (core-made) and what the
    /// build seals with for this mode (`Haip::agreements` under `jwe_mode`, `Agreements::NONE`
    /// under `mode`); the C7 refusal when its key rule accepts no key or no `enc`. Called once
    /// per route; the core checks a `Jwe` choice and the session binds it.
    fn encryption<'k>(&self, metadata: &'k VerifierMetadata<'k>, sealer: &Agreements, host: &H)
        -> Result<Encrypting<'k>, Refusal>;
    /// The `wallet_metadata` members `Mode::metadata_names` declares, from the same statement.
    fn wallet_metadata(&self, sealer: &Agreements, host: &H) -> Result<Vec<MetadataMember>, Fault>;
    /// The body around an answer: the clear response, or the JWE the core sealed it in.
    fn answer(&self, route: &ModeRoute<'_>, content: &AnswerContent<'_>, host: &H)
        -> Result<Body, Fault>;
}
/// A URI response mode's errors (§8.2, §8.3.1): the form body around the clear error or its JWE.
pub trait ErrorModeHost<H>: Mode {
    fn error(&self, route: &ModeRoute<'_>, content: &ErrorContent<'_>, host: &H)
        -> Result<PostBody, Fault>;
}
/// The conversions the registry takes a mode by: a `Mode` for `NoHost`, a `ModeHost<H>` (an
/// `ErrorModeHost<H>`) for a host holding a `Platform`; one impl each (`Build`).
pub trait HostedMode<H: Build>: 'static {}
pub trait HostedErrorMode<H: Build>: 'static {}

/// The mode's choice: the clear, or one of the request's keys with an `enc`, which the core seals
/// to as a JWE.
pub enum Encrypting<'k> { Plain, Jwe { key: VerifierKey<'k>, enc: ContentEncryption } }
/// The key and `enc` a route bound: what the core seals to through `Haip::encrypt_jwe` and what
/// the session holds. Only `Route::new` makes one, once it has checked the choice.
pub struct RouteKey<'k> { key: VerifierKey<'k>, enc: ContentEncryption }
/// What a mode wraps: the clear response on a clear route, the core's JWE on a sealed one.
pub enum AnswerContent<'a> { Clear(&'a AuthorizationResponse<'a>), Sealed(&'a SealedJwe) }
pub enum ErrorContent<'a> { Clear(&'a ErrorResponse<'a>), Sealed(&'a SealedJwe) }
/// What a mode reads of its route; only the route makes one.
pub struct ModeRoute<'r> { encryption: Option<&'r RouteKey<'r>>, echo: Option<&'r Echo<'r>> }

/// One parameter a registered `ResponseParametersHost` writes: its name and JSON value
/// (`new`, `name()`, `value()`).
pub struct ResponseMember { name: ParameterName, value: Node<'static> }

/// Only `Route::new` makes one, from an `Authenticated` and the registry its envelope was read
/// with. `state` is read from the envelope's routing and the Verifier's metadata from the
/// `Authenticated`; `nonce` is the one N1 accepts, `None` for a request N1 refuses, whose error
/// the route carries.
pub struct Route<'a, H: Build> { authenticated: &'a Authenticated<'a>, registry: &'a Registry<H>,
                                 channel: ChannelRoute<'a>, nonce: Option<&'a Nonce<'a>> }
/// The session's binding facts by channel. Over the DC API errors are A.4's, the core's; the
/// answering mode is present when the request names a registered one. By URI the bound
/// `response_uri`, the authenticated Client Identifier and the error mode of the request's name
/// are present: a URI request authenticated without both is a `Fault`.
enum ChannelRoute<'a> { DcApi { origin: &'a Origin<'a>, answers: Option<Chosen<'a>> },
                        Uri { endpoint: &'a ResponseUri, client_id: &'a ClientId<'a>,
                              errors: RoutedMode, answers: Option<Chosen<'a>> } }
/// An answering mode and its choice, made once: the clear, a bound key, or a refusal (C7, or C6
/// for the request's `client_metadata`), which `Route::read` returns beside the route.
struct Chosen<'a> { mode: RoutedMode, encryption: RouteEncryption<'a> }
enum RouteEncryption<'a> { Plain, Jwe(RouteKey<'a>), Refused }
/// The route an Authorization Response takes; only `Route::answering` makes one. It holds the
/// chosen mode, its key, the Verifier's keys and the `nonce`.
pub struct AnswerRoute<'a, H: Build> { route: &'a Route<'a, H>, chosen: &'a Chosen<'a>,
                                       key: Option<&'a RouteKey<'a>>, keys: &'a VerifierKeys<'a>,
                                       nonce: &'a Nonce<'a> }
/// How a mode's route or body breaks its registration: the cause of phase 2's `Fault`
/// (`resolve`, ids `err.openid4vp.route_breach.*`).
pub enum RouteBreach { ErrorsAnswered, KeyInTheClear, NoKey, Foreign, Unstated, Unlisted,
                       BodyChannel }
/// How a registered part of the response parameters breaks its registration: the cause of phase
/// 2's `Fault` (`resolve`, ids `err.openid4vp.parameter_breach.*`). `Undeclared`: a member of a name
/// outside the names the registry kept for the part; `Twice`: a name an earlier member holds.
pub enum ParameterBreach { Undeclared, Twice }

/// A profile wrote a presentation member outside those it declares for the placement: the cause
/// of phase 2's `Fault` (`resolve`, id `err.openid4vp.undeclared_member`).
pub struct UndeclaredMember;

/// A URI request whose mode names no registered error mode (C5): the wallet tells the End-User.
/// Id `err.openid4vp.route.unroutable`: "the request names no response mode the wallet can carry
/// an error in". `Outcome::Unroutable` carries it.
pub struct Unroutable;

impl<'a, H: CoreHost> Route<'a, H> {
    /// The routing is the one the authenticated envelope holds; each mode's registration is read
    /// from `registry` by its `ModeHandle`, the name checked, and the answering mode's
    /// `encryption` runs once. `Outcome::Unroutable` when no error can go anywhere; a `Fault` for
    /// a handle the registry holds under another name, a URI request authenticated without a
    /// bound `response_uri` and Client Identifier, or a choice that breaks its registration
    /// (`RouteBreach`). The crate-private `Route::read` returns the answering mode's refusal
    /// beside the route, which phase 2 answers with (`Outcome::Refused`); `new` drops it.
    pub fn new(authenticated: &'a Authenticated<'a>, registry: &'a Registry<H>, host: &H)
        -> Result<Self, Outcome>;
    /// `None` when the request names no registered answering mode on its channel (C5), its mode
    /// refused every key (C7), its `client_metadata` breaks C6, or it names no `nonce` N1
    /// accepts.
    pub fn answering(&'a self) -> Option<AnswerRoute<'a, H>>;
    /// The first refusal's code; its text, sanitized to RFC 6749 Appendix A.8's characters, as
    /// the description; `state` as received. A.4's form over the DC API, or `Reply::Cancel` under
    /// `DcApiErrors::Cancel`; the error mode's by URI, sealed by the core to the route's key when
    /// the answering mode bound one.
    pub fn refusal(&self, refused: &Refused, policy: DcApiErrors, host: &H)
        -> Result<Reply, Fault>;
    /// The unmet request's error, without description, under its code (`Match::unmet`).
    pub fn unmet(&self, code: UnmetCode, policy: DcApiErrors, host: &H) -> Result<Reply, Fault>;
    /// `wallet_unavailable` (§8.5), for the component an https link reaches in place of the
    /// wallet.
    pub fn unavailable(&self, host: &H) -> Result<Delivery, Fault>;
}
impl<'a, H: CoreHost> AnswerRoute<'a, H> {
    /// The session the presentations bind: only the answer route makes one.
    pub fn session(&self) -> Session<'a>;
    /// Sealed by the core on a sealed route, wrapped by the mode, sent to the bound endpoint; a
    /// body of another channel than the request's is a `Fault` (`RouteBreach::BodyChannel`).
    pub fn answer(&self, response: &AuthorizationResponse<'_>, host: &H) -> Result<Delivery, Fault>;
}

/// `matching` (every `match` build): the plug-in that excluded a credential for a query, which
/// `matching::Excluded` holds as `by`: `Format` for `FormatQuery::admits` (the Verifier's
/// `vp_formats_supported`), `Profile` for the transaction profile's binding, `Display` for
/// `FormatQuery::displayable`.
pub enum ExcludedBy { Format, Profile, Display }
/// The code of a request the wallet does not meet (§8.5, §15.4.1); `code()` gives the
/// `ErrorCode`.
pub enum UnmetCode { AccessDenied, VpFormatsNotSupported }
/// A candidate's transaction: its query's `Transaction` and the `Bound` the transaction's profile
/// gave, one value, which `Candidate::bound` holds (`Option<TransactionBinding>`). `Match::run`
/// gives one to each candidate of a query a transaction names and none to another query's; a
/// credential whose profile binds no entry is excluded (`ExcludedBy::Profile`). Phase 2 reads a
/// record's transaction from it alone.
pub struct TransactionBinding<'m> { pub transaction: &'m Transaction, pub bound: Bound }
impl Match<'_> {
    /// `VpFormatsNotSupported` when the request has alternatives and every one holds a query no
    /// credential answers and whose format excluded a credential (`ExcludedBy::Format`);
    /// `AccessDenied` otherwise: no credentials, a decline, a failed End-User authentication, a
    /// failed proof.
    pub fn unmet(&self) -> UnmetCode;
}

/// Only `Prepared::respond` makes one, from the routing and the registered response parameters;
/// `vp_token()`, `state()`, `members()` and `json()`, §8.1's JSON object, read it.
pub struct AuthorizationResponse<'a> { vp_token: VpToken, state: Option<State<'a>>,
                                       members: Vec<ResponseMember> }
/// Only the core's route and rejection make one; `code()`, `description()`, `echo()` and
/// `json()` read it.
pub struct ErrorResponse<'a> { code: ErrorCode, description: Option<ErrorDescription>,
                               echo: Option<Echo<'a>> }

/// RFC 6749 Appendix A.8's characters, one or more (`refusal.rs`, every build).
/// `ErrorDescription::sanitized` writes a refusal's text with every other character `?`;
/// `ErrorDescription::parse` reads a Verifier's and refuses another through
/// `refusal::is_nqschars`, the one NQSCHAR check (`ErrorCode::new` and siros-webuild's
/// `VerifierCode::parse` call it too).
pub struct ErrorDescription(String);

/// What a mode writes.
pub enum Body { DcApi(DcApiData), Post(PostBody) }
/// A POST body with its media type: `form` of a `FormBody`, or `of` another media type, which
/// refuses `application/x-www-form-urlencoded` (`FormMedia`).
pub struct PostBody { media: MediaType, bytes: Vec<u8> }
/// The DigitalCredential's `data`: a JSON object with unique member names. `of` reads a text
/// back through the core's `json` module (`NotObject`); `error` writes A.4's `{"error": code}`.
pub struct DcApiData(String);

pub enum Delivery {
    /// The mode's body, POSTed to the route's `response_uri`.
    Post { endpoint: ResponseUri, body: PostBody },
    /// The DigitalCredential's `data` (A.4).
    DcApi(DcApiData),
}

```

**What the core checks of a mode.** `encryption` returns `Plain`, or `Jwe` with a `VerifierKey`,
which only the request's `VerifierKeys` yield, and an `enc`. The core refuses with a `Fault`,
its cause a `RouteBreach`, a `Jwe` from a mode registered with `mode` (`KeyInTheClear`), a
`Plain` from one registered with `jwe_mode` (`NoKey`), an answer routed by a mode registered for
errors alone (`ErrorsAnswered`), a key the request's `VerifierKeys` do not hold at its place
(`Foreign`), a key whose curve and `alg` or an `enc` the sealing statement does not admit
(`Unstated`), and an `enc` the Verifier does not list (`Unlisted`; `VerifierMetadata::lists`:
A128GCM when it lists none, §5.1). `Foreign` compares the key by identity (`ptr::addr_eq`) with
the request's key at its place: a mode can hold the key of a second request it read through the
core's public flow, as `TestChoice::Foreign` does. The route then binds the key
as its `RouteKey`, the session holds it, and the core seals the response JSON to it through
`Haip::encrypt_jwe`: the mode receives the `SealedJwe` alone, so no plaintext of a sealed route
reaches it and no other key can receive the answer. A refusal of the choice (C7, or C6 for the
request's `client_metadata`) stays on the route, and the request's error goes plain. `answer`
returns a `Body`; the core refuses one of another channel than the one the request arrived on
with a `Fault` (`BodyChannel`), and wraps it in the `Delivery` of the route's bound endpoint.
`error` returns a `PostBody` for the route's `response_uri`. A DC API body is a JSON object the
core read back; a form body comes from `FormBody::of`. `wallet_metadata` writes the names
`metadata_names` declares; another name is a `Fault`. `Route`, `AnswerRoute`, `RouteKey`,
`ModeRoute`, `RoutedMode`, `VerifierKey`, `VerifierKeys`, `VerifierMetadata`, `PostBody`,
`DcApiData`, `AuthorizationResponse`, `ErrorResponse` and `Built` have private fields (I1).
The ids: `RouteBreach` `err.openid4vp.route_breach.*`, `ParameterBreach`
`err.openid4vp.parameter_breach.*`, `Unroutable` `err.openid4vp.route.unroutable`, `FormMedia`
`err.openid4vp.post_body.form_media`, `NotObject` `err.openid4vp.dc_api_data.not_object`,
`NotForm` `err.openid4vp.form.*`.

**Response parameters.** The registry reads each part's `names` once when it builds, refuses a
name two parts declare and the names of `CORE_RESPONSE`, and keeps the names it checked
(`RegisteredParameters`). `Prepared::respond` asks each registered `ResponseParametersHost` for
the members of the request's response type and writes them after `vp_token` and `state`. A
member of a name outside the part's kept names is a `Fault` caused by
`ParameterBreach::Undeclared`, a name an earlier member holds one caused by
`ParameterBreach::Twice`.

**The session.** `AnswerRoute::session` holds the binding facts (decision 20): the channel with
its Origin, or the full Client Identifier and the `response_uri` as the request names it; the
`nonce` N1 accepts; the `RouteKey` the core sealed to; and the Verifier's keys. A route exists
for a request N1 refuses, to carry its error, and no answer route does. `Session::audience` is
unchanged: `origin:<Origin>` over the DC API, the full Client Identifier by URI (A.4, B.3.6).
Each format binds a presentation from these facts: siros-mdoc builds B.2.6's handover, its RFC
7638 thumbprint of the sealed-to key, and ISO/IEC 18013-5's `SessionTranscript` (reading 10);
siros-sdjwt writes the Key Binding JWT's `aud` and `nonce`. `Handover::of(&Session)` returns a
`Fault` for a sealed-to key RFC 7638 gives no thumbprint of (`Thumbprint::of` is `None` for a
`kty` other than `EC` and `OKP`), which no sealing statement admits. `Handover` is a public enum
with public fields: siros-zkp-catalogues builds a Verifier's handover from its own request
(`CheckedRequest::transcript`), and its wallet side one before the core's `Session` exists
(`NymAuthRequest::new`); Appendix A lists its move onto `Handover::of(&Session)`. A
transcript a Verifier holds enters through `SessionTranscript::decode`: one CBOR item, an array of
three (ISO/IEC 18013-5 §9.1.5.1), else `TranscriptError::Cbor` or `TranscriptError::Items`.

#### The core's modes (`modes.rs`; `dc-api`, `uri`)

OpenID4VP's modes implement `Mode`, `ModeHost<H>` and `ErrorModeHost<H>` as any extension's do,
and the registry takes them as it takes an extension's: `dc_api` (`mode`) and `dc_api.jwt`
(`jwe_mode`) (A.2) under `dc-api`; `direct_post.jwt` (`jwe_mode` and `error_mode`, §8.3.1) and
`direct_post` (`error_mode` alone, §8.2) under `uri`. None bounds a module: the core seals.

```rust
pub struct DcApi;           // dc_api: the response in the clear
pub struct DcApiJwt;        // dc_api.jwt: {"response": JWE}
pub struct DirectPostJwt;   // direct_post.jwt: response=JWE POSTed; its errors sealed or plain
pub struct DirectPost;      // direct_post: errors alone, plain (reading 24)

/// C7: a JWE mode's key rule accepts no key, or no `enc`; each names the mode and keeps the
/// model's text ("C7 {mode}: client_metadata offers no key and content encryption the wallet
/// supports").
pub enum KeyRule { Key { mode: ModeName }, Enc { mode: ModeName } }

/// HAIP §5's key rule's statement: ECDH-ES on P-256, A256GCM before A128GCM.
pub const KEY_RULE: Agreements;
/// The key rule under the sealing statement `sealer` (below); phase 1 passes `KEY_RULE`.
pub fn key_rule<'k>(mode: ModeName, metadata: &'k VerifierMetadata<'k>, sealer: &Agreements)
    -> Result<(VerifierKey<'k>, ContentEncryption), KeyRule>;
pub use crate::routing::KeyChoice;

/// `direct_post.jwt`'s form (§8.3.1): `response`, the compact JWE.
#[derive(Serialize)] pub struct ResponseForm<'a> { response: &'a str }
impl<'a> ResponseForm<'a> { pub fn of(jwe: &'a SealedJwe) -> Self; }
/// §8.2's plain error form: `error`, `error_description` when there is one, `state` when the
/// request has one, from the error's `Echo`.
#[derive(Serialize)] pub struct ErrorForm<'a> { error: ErrorCode,
                                                error_description: Option<&'a ErrorDescription>,
                                                state: Option<&'a Echo<'a>> }
impl<'a> ErrorForm<'a> { pub const fn of(error: &'a ErrorResponse<'a>) -> Self; }
```

**The key rule** (§8.3, HAIP §5; reading 25), which the JWE modes share as the public `KEY_RULE`
and `key_rule`, so a reader that binds the key before phase 2 (`KeyChoice::of`) chooses as the
core does: P-256, ECDH-ES, A256GCM before A128GCM. The key is the first of `client_metadata.jwks` whose
curve and present `alg` both the rule and the sealing statement admit, and whose coordinates are
32 octets each (RFC 7518 §6.2.1.2, §6.2.1.3); `use` is `enc` or absent, as `AgreeableKey::of`
reads it. `enc` is the first, in the sealing statement's order of preference, that the rule
states and `encrypted_response_enc_values_supported` lists, or A128GCM when the member is absent
(§5.1's default; `VerifierMetadata::lists`). Without a key or an `enc`, C7. Phase 1, which holds no module, applies the rule
as its own statement; phase 2 applies it under `Haip::agreements`, so the route binds what the
module implements. `dc_api.jwt` wraps the sealed §8.1 object as `{"response": JWE}`,
`direct_post.jwt` as `response=<JWE>`. Over the DC API every error is A.4's `{"error": code}` in
the clear, which the core writes. `direct_post.jwt` wraps an error the core sealed to the
route's key, and writes it plain without one (§8.3.1: "it MAY send an error response without
encryption"). `direct_post` carries errors alone: C5 refuses a request naming it, and its error
goes plain to the authenticated `response_uri` (reading 24). `direct_post.jwt` registers through
`jwe_mode` and `error_mode` as one type, which `ModeTwice` admits. Each form is RFC 6749
Appendix B's encoding, which §8.2 names, as serde_urlencoded writes it: a space is `+` (§8.2's
example prints `%20`). `direct_post.jwt` declares
`authorization_encryption_alg_values_supported` and
`authorization_encryption_enc_values_supported` and writes the rule's values the build's `Haip`
states, in the module's order; the other three declare nothing.

#### Errors (`recourse.rs`, `resolve`)

```rust
/// An error code (RFC 6749 §4.1.2.1, §8.5: extensions' codes "MAY be defined"): one or more of
/// Appendix A.7's `NQSCHAR`. A plug-in makes its own with `checked!`; the constants are RFC
/// 6749's, RFC 9101 §7's and OpenID4VP §8.5's codes (`INVALID_REQUEST`, `ACCESS_DENIED`,
/// `INVALID_REQUEST_OBJECT`, `VP_FORMATS_NOT_SUPPORTED`, `WALLET_UNAVAILABLE`, ...).
pub struct ErrorCode(&'static str);
impl ErrorCode { pub const fn new(code: &'static str) -> Option<Self>; }
/// A request rule: its message, and the one code the Verifier receives for it.
pub trait RequestRule: Explain { fn code(&self) -> ErrorCode; }

pub enum Failure { Unreadable(Unreadable), Unauthenticated(Unauthenticated) }

impl Failure {
    /// §8.5, RFC 9101 §7; `None` when the specification terminates the request (U9, U14).
    pub fn code(&self) -> Option<ErrorCode>;
}

/// Plain (§8.3.1), with `state` as received. After a POST the caller reads the Response URI's
/// answer and sends the user agent to its `redirect_uri` (§8.2: "for Error Responses" too). Only
/// a `Rejected` holds one, beside the failure it routes.
pub struct ErrorRoute<'a> { target: ErrorTarget, echo: Option<Echo<'a>> }

/// `DcApi`: the platform, A.4's error, which the core writes. `Listed`: a `response_uri` a trust decision listed
/// (`EndpointBasis::Framework`). `Unverified`: the `response_uri` an unauthenticated request
/// names, sent to on the End-User's choice alone (RFC 9700 §4.11.2).
pub enum ErrorTarget { DcApi, Listed(ResponseUri), Unverified(ResponseUri) }

impl<'a> ErrorRoute<'a> {
    pub fn target(&self) -> &ErrorTarget;
}

/// A request refused before authentication, made by the step that refuses it. `route()`: over
/// the DC API, the DC API's. By URI, a `Framework` binding's `response_uri` when A8 to A10 fail,
/// else `Unverified` when the payload names an absolute `https` `response_uri` with a host.
/// `None` without a readable payload, for A13, and for the terminating U9 and U14.
#[must_use]
pub struct Rejected<'e> { failure: Failure, route: Option<ErrorRoute<'e>> }

impl<'r> Rejected<'r> {
    /// A DC API request `Received::dc_api` refuses (U1, U2, U3, U10, U16), on the DC API's route.
    pub fn dc_api(cause: Unreadable) -> Self;
    /// Phase 2's rejection of a refused envelope (`Envelope::parse`, under `match`, returns the
    /// bare `Unreadable`): over the DC API, the DC API's route; by URI, `Unverified` for U12 and
    /// U13 when the payload names an absolute `https` `response_uri` with a host, and no route
    /// for the other causes.
    pub fn unreadable(received: &'r Received<'r>, cause: Unreadable) -> Self;
    pub fn failure(&self) -> &Failure;
    pub fn route(&self) -> Option<&ErrorRoute<'r>>;
    /// The failure's error on the route, in the clear: its code, its text sanitized as the
    /// description, `state` as received. A.4's `{"error"}` over the DC API; by URI §8.2's plain
    /// form (the core's `ErrorForm`, which `direct_post` writes too) POSTed to the route's
    /// `response_uri`. `Reply::Cancel` for a terminating failure, without a route, and over the
    /// DC API under `DcApiErrors::Cancel`. A URI route in a build without `uri` is a `Fault`.
    pub fn reply(&self, policy: DcApiErrors) -> Result<Reply, Fault>;
}

pub enum DcApiErrors { Cancel, Respond }             // §15.9.2; the app's configuration picks one
pub enum Reply { Deliver(Delivery), Cancel }
```

Section 4.5 gives each rule's code and recourse. In short:

- **U and A.** `Failure::code` gives the code, the failure's text the description. Over the DC API
  the error goes back to the Origin (the DC API's route; `Rejected::dc_api`, A.4). By URI, A8 to A10
  after a `Framework` binding answer the listed `response_uri`. Every other U and A rule answers the
  End-User. When the request names an absolute `https` `response_uri`, `Rejected::route` is
  `Unverified`, and the End-User can choose to send the error there. U9 and U14 terminate (§5.10.1,
  §5.10.2; reading 3).
- **Unroutable.** By URI, a mode that names no registered error mode: the End-User.
- **Refused** (P, S, N, C). Routed: the first refusal's code; its text, filtered to RFC 6749's
  characters, as the description. Refusal texts quote the request alone, so a description holds
  the Verifier's own values alone. The matcher hides a refused request.
- **What a format withholds.** `FormatQuery::displayable(credential, options, env)` runs after
  `answerable` finds an option, and its `NoCandidate` excludes the credential for the query
  (`ExcludedBy::Display`): what a format's options would show of the credential must not reach the
  End-User. `FormatQuery::draw` writes the credential's card through the wallet's `Context`.
  `FormatQuery::carries` tells whether a presentation can carry a profile's members (`Carriage`).
  `Options::indexed` is the only way to an `OptionIndex`. The claims kit's
  `ClaimsQuery::displayable` refuses with `CardError`: a pointer that selects nothing (`Path`), a
  text `DisplayText` refuses (`Text`), or a count, a byte string's length or a natural number that
  is no count literal (`Count`). `ClaimsQuery::card` refuses with `DrawError`: a `CardError`
  (`Card`), or a statement the context words no text for (`Unworded`). `FormatQuery::displayable`
  excludes the credential for a `Text` (`RefusedText`) and faults for the others;
  `FormatQuery::draw` faults for every refusal.
- **Unmet.** No description, under the code the core derives from the plug-in that excluded
  each credential (`Match::unmet`). `vp_formats_not_supported` when the request has alternatives
  and every one holds a query no credential answers and whose format excluded a credential under
  the Verifier's `vp_formats_supported` (`ExcludedBy::Format`, `FormatQuery::admits`), which
  leaves the Verifier a fallback to another format. `access_denied` otherwise, so a Verifier
  cannot tell declines and failures apart (§15.4.1, §15.9).
- **The error's form.** Over the DC API the core writes A.4's `{"error": code}` on every route,
  whatever mode the request names or whether it names a registered one. By URI the error mode of
  the request's name writes it (`ErrorModeHost::error`): `direct_post.jwt` wraps the error the
  core sealed to the route's key, and writes the plain form without one (§8.3.1); `direct_post`,
  which carries errors alone, writes the plain form. A refusal before authentication goes in the
  clear (`Rejected::reply`).

**Codes.** `ErrorCode` is open: a profile's or a mode's rule returns its own specification's
code through `RequestRule::code`, and the code's syntax holds when the crate builds. The core's
rules return the constants; `INVALID_CLIENT` stands for §8.5's code, which no core rule returns.

Over the DC API, `DcApiErrors` decides between `{"error"}` and a cancelled flow for every class
(§15.9.2); the app's configuration picks it, and the SIROS wallet app cancels (decision 1). The caller sends an error after the End-User has
interacted (§15.4.1, §15.9.2, RFC 9700 §4.11.2).

#### The host (`host.rs`) and phase 2 (`resolve/mod.rs`)

`Runtime`, one trait every host implements in full, gives way to modules: one per family of
capabilities a specification mandates together (decision 13). Each plug-in states, as trait
bounds on its implementation, the modules it requires and those it uses when the build holds
them. The bounds state what a build compiles in: a registry takes a plug-in only when the build's
host meets them, and nothing checks a module's presence at run time. A run-time condition (a
permission refused, a sensor absent, a reader key missing) stays in the result of the module's
call. Every module takes `&self`: the state behind it is the platform's (the keystore, the RNG,
the clock, the End-User's prompt, the sensors, the app's stores), so a module is a handle, and
one without even a handle is a zero-sized type the host gives as `&'static`, with no field and
no allocation. A call carries what it needs, as `decrypt` takes the `EphemeralKey` the `Fetch`
owns. Test doubles that count use a `Cell`, in test code alone.

```rust
/// The host holds module `M`: a required provider (axum: `M: FromRef<S>`).
pub trait Has<M: ?Sized> { fn module(&self) -> &M; }
/// Whether the build holds module `M`, settled by the slot's type: an optional provider.
pub trait MayHave<M: ?Sized> { type Slot: Slot<M>; fn slot(&self) -> &Self::Slot; }
/// Sealed: `Held` or `Empty`, so presence is a property of the host's type.
pub trait Slot<M: ?Sized>: Sealed { const HELD: bool; fn filled(&self) -> Option<&M>; }
/// A filled slot; `Held::new(&MODULE)`, a `const fn`, makes one.
pub struct Held<M: ?Sized + 'static>(&'static M);
pub struct Empty;
/// `host.get::<dyn Haip>()`, `host.maybe::<dyn DeviceMac>()`.
pub trait Host {
    fn get<M: ?Sized>(&self) -> &M where Self: Has<M>;
    fn maybe<M: ?Sized>(&self) -> Option<&M> where Self: MayHave<M>;
}

/// The wallet app: its clock, its credentials' status and the End-User's prompt. The core calls
/// each method.
pub trait Platform {
    fn now(&self) -> Timestamp;
    /// Whether the credential can still be presented (validity, status), checked now.
    fn usable<'c>(&self, credential: &'c Credential<'c>) -> Option<Usable<'c>>;
    /// The End-User's authentication, at least as strong as `need`; `None` when the End-User
    /// failed or cancelled. An inherence factor carries its matching's facts (`Inherence`).
    fn authenticate(&self, need: AuthenticationNeed) -> Option<Authentication>;
}

/// HAIP's cryptography (HAIP §5, §7), one family (decision 13); the credentials' keys sit in the
/// platform's keystore. The module states what it implements, and the core accepts exactly that.
/// A plug-in that calls it bounds `Has<dyn Haip>`: a format that signs, and the registrations of
/// a prefix and of a JWE mode, which keep the accessor for the core's own calls. A module without
/// a capability states none (`JwsAlgorithms::NONE`, `Agreements::NONE`), and the core never
/// calls the method that would serve it.
pub trait Haip {
    /// The JWS algorithms `verify` verifies; HAIP's module states ES256 (§7).
    fn verifies(&self) -> JwsAlgorithms;
    /// The signature over the signing input under the key, by the signature's `alg`, called for
    /// a stated `alg` alone; a key that does not fit the `alg`, a point off its curve included, is
    /// `SignatureInvalid`.
    fn verify(&self, key: &VerificationKey, signed: &Signed<'_>) -> Result<(), SignatureInvalid>;
    /// A signature with the credential's key.
    fn sign(&self, credential: &CredentialId<'_>, data: &[u8]) -> Result<Signature, SignFailed>;
    /// The curves, key agreements and content encryptions `encrypt_jwe` implements, in the
    /// module's order of preference; HAIP's module states ECDH-ES on P-256 with A256GCM and
    /// A128GCM (§5). Each JWE mode's key rule reads it, and the core checks a route against it.
    fn agreements(&self) -> Agreements;
    /// The plaintext encrypted to the key under its agreement and `enc`, as a compact JWE: the
    /// core passes the key and `enc` its route bound (`RouteKey`), siros-paso the issuer's key
    /// (Risk Signals §7.3, §7.5.1).
    fn encrypt_jwe(&self, key: &AgreeableKey<'_>, enc: ContentEncryption, plaintext: &[u8])
        -> Result<SealedJwe, Fault>;
}

/// `encrypt_jwe`'s ciphertext, made only by its `parse`, which refuses another form (`NotSealed`,
/// one variant per rule): a compact JWE, five base64url parts whose first is a JSON object with
/// unique member names. It serializes as its text.
pub struct SealedJwe(String);

/// Why the credential's key made no signature.
#[derive(Debug, thiserror::Error, siros_explain::Explain)]
pub enum SignFailed {
    /// The End-User cancelled the key prompt.
    #[error("the End-User cancelled the signature")]
    #[explain(id = "host.cancelled")]
    Cancelled,
    /// The keystore broke its contract.
    #[error(transparent)]
    Fault(Fault),
}

/// An encrypted Request Object (§5.10, RFC 9101 §6.1; feature `request-decryption`); the key
/// travels in the value. The registered `EncryptedRequests` bounds it.
pub trait RequestDecryption {
    /// The curves of the keys it draws and the JWE `alg` and `enc` values `decrypt` implements;
    /// HAIP's module states P-256, ECDH-ES, A256GCM and A128GCM.
    fn decrypts(&self) -> JweAlgorithms;
    /// A fresh key: its public JWK, on a stated curve, and the handle to the secret the module
    /// keeps.
    fn ephemeral_key(&self) -> Result<EphemeralKey, Fault>;
    /// The plaintext of a JWE encrypted to the key, as RFC 7516 §5.2 decrypts it: a `zip` of
    /// DEF uncompressed (step 17; §4.1.3: "MUST be understood and processed"). The key is
    /// consumed and its secret forgotten; one failure for every cause.
    fn decrypt(&self, key: EphemeralKey, jwe: &CompactJwe<'_>) -> Result<Vec<u8>, DecryptFailed>;
}

/// The module the core calls with no extension registered.
pub trait CoreHost: Has<dyn Platform> {}

/// The module's reference to the secret of a key it drew; the core holds it and reads nothing of
/// it.
pub struct KeyHandle(u64);
/// A fresh key the wallet posts: its public JWK, which `jwks` holds with `use` `enc`, and the
/// handle to the secret the module keeps. The core links no curve arithmetic: it checks that the
/// JWK is public (`PublicJwk`) and that its `crv` is one `decrypts` states, a `Fault` otherwise.
/// Only `EphemeralKey::new` makes one. The `Fetch` owns it until `resume` hands it to `decrypt`.
pub struct EphemeralKey { public: PublicJwk, handle: KeyHandle }
impl EphemeralKey { pub const fn new(public: PublicJwk, handle: KeyHandle) -> Self; }

/// `Strong`: factors of two PSD2 categories, knowledge, possession and inherence (PSD2 Art.
/// 4(30); TS12 §3.6). `Presence`: whatever the wallet's unlock asks.
pub enum AuthenticationNeed { Presence, Strong }

/// An inherence factor as the platform reports it: the modality, the sensor, and its matching's
/// facts, which a profile classifies by its own criteria.
pub struct Inherence { pub modality: Modality, pub sensor: Sensor, pub isolation: Isolation,
                       pub false_accepts: Option<FalseAcceptRate>,
                       pub attack_detection: AttackDetection }
/// Where the comparison ran: a TEE or a secure element, alongside the operating system, or
/// unreported.
pub enum Isolation { Hardware, None, Unreported }
/// At most one false accept in `n` attempts.
pub struct FalseAcceptRate(NonZeroU32);
/// Presentation attack detection (ISO/IEC 30107-1).
pub enum AttackDetection { Present, Absent, Unreported }

/// A profile's phase 2 over the build's host; its bounds name the modules it needs. The records
/// are the core's, with private fields: `Answered` carries the route's mode, and `FetchedRecord`
/// the record with the resources its profile wanted, each with what the caller fetched. Every
/// method a `resolve` type names sits here, so `Profile` compiles the same in every build.
pub trait ProfileHost<H>: Profile {
    /// The resources the profile revalidates the record with, from the record, the profile's
    /// data and the host's modules; reading the record can fail.
    fn wanted(&self, record: Answered<'_>, host: &H) -> Result<Vec<HttpsUrl>, Fault>;
    /// The profile with phase 2's findings, for re-running the consent.
    fn informed(&self, findings: &[&Self::Finding]) -> Self;
    /// The End-User authentication the record needs.
    fn authentication(&self, record: Answered<'_>) -> Result<AuthenticationNeed, Fault>;
    fn revalidate(&self, record: FetchedRecord<'_>, host: &H)
        -> Result<Option<Self::Finding>, Fault>;
    fn respond(&self, record: Answered<'_>, host: &H, authentication: &Authentication)
        -> Result<Members, Fault>;
}
/// Only the core's phase 2 makes one; `record()` and `resources()` read it.
pub struct FetchedRecord<'r> { record: Answered<'r>, resources: &'r [Reply<Resource>] }
/// A format's phase 2 over the build's host: each query read again under the mode rule C5
/// accepted. Only that reading has phase-2 methods.
pub trait FormatHost<H>: Format {
    fn answer<'q>(&'q self, query: &'q Query<'q>, context: AnsweredContext<'q>)
        -> Result<Box<dyn AnsweredQuery<H> + 'q>, AllOf<Refusal>>;
}
/// Phase 1's methods, and each answerable option as phase 2 reads it.
pub trait AnsweredQuery<H>: FormatQuery {
    /// The options `answerable` gives, in the Verifier's order, each with what phase 2 needs.
    fn choose<'a>(&'a self, credential: Usable<'a>, env: &Env, provided: &[Member])
        -> Result<Vec<Box<dyn AnsweredOption<H> + 'a>>, Fault>;
}
/// An answerable option with its own query, credential and option; only `choose` makes one.
pub trait AnsweredOption<H> {
    fn option(&self) -> OptionIndex;
    /// The format's finding: what phase 1 assumed of the credential and the option and no
    /// longer holds, such as a module the presentation needs that the build lacks.
    fn revalidate(&self, session: &Session<'_>, host: &H)
        -> Result<Option<Box<dyn FindingData>>, Fault>;
    fn present(&self, members: &Members, session: &Session<'_>, host: &H)
        -> Result<Presentation, PresentError>;
}

/// The matcher's build: a registry of phase 1's plug-ins, without a host.
pub struct NoHost;
/// A registry's host, which fixes what the registry takes of each plug-in: `NoHost` takes phase
/// 1's `Format`, `Profile` and `Mode` in every build; under `resolve`, a host holding a `Platform`
/// takes a plug-in whose phase 2 runs over it (`FormatHost`, `ProfileHost`, `ModeHost`). Sealed:
/// the core implements it for those hosts alone, through `Plugins`, which names what the
/// registry stores of each plug-in (`Format`, `Profile`, `Mode`, `ErrorMode`,
/// `ResponseParameters`) and how a JWE mode reaches the sealing module (`Sealing`).
pub trait Build: Plugins {}
/// The conversions a registration takes: one impl for `NoHost`, one for a host
/// (`H: Has<dyn Platform>`).
pub trait HostedFormat<H: Build>: 'static {}   // Format for NoHost; FormatHost<H> for a host
pub trait HostedProfile<H: Build>: 'static {}  // Profile for NoHost; ProfileHost<H> for a host
/// ResponseParameters for NoHost; ResponseParametersHost<H> for a host.
pub trait HostedResponseParameters<H: Build>: 'static {}
/// A host whose registry takes a JWE mode: `NoHost`, whose phase 1 reads the mode alone, or a host
/// holding the `Haip` that seals the mode's answers.
pub trait JweHost: Build {}
/// A format enters as `HostedFormat<H>`, a profile as `HostedProfile<H>`, a mode as `HostedMode<H>`
/// or `HostedErrorMode<H>`, response parameters as `HostedResponseParameters<H>`, a prefix as
/// `HostedPrefix<H>`, a hash algorithm as `HashAlgorithm`, a scope query as `ScopeQuery`. Phase 1 reads it through a crate-private catalog, so `Accepted`,
/// `Match` and `Views` are one type under every host. A registration bounded by a module keeps that
/// module's accessor, monomorphized for `H` when it registers, and the core reaches the module
/// through it alone. The registry holds each format's placement from build (`RegisteredFormat`)
/// and each response parameters part with the names `build` checked (`RegisteredParameters`).
pub struct Registry<H: Build = NoHost> { formats: Vec<RegisteredFormat<H>>,
                                         modes: Vec<RegisteredMode<H>>,
                                         parameters: Vec<RegisteredParameters<H>>,
                                         decryption: Option<fn(&H) -> &dyn RequestDecryption>, .. }

impl<H: Build> RegistryBuilder<H> {
    pub fn format(&mut self, format: impl HostedFormat<H>);
    /// A profile, to register under types (`exact`) or type prefixes (`prefix`).
    pub fn profile(&mut self, profile: impl HostedProfile<H>) -> ProfileHandle;
    /// The POST of `wallet_metadata` (`uri`): with it, `post` fetches by POST; without it, by GET
    /// (§5.1).
    pub fn request_post(&mut self, post: RequestPost);
    /// Encrypted Request Objects (`request-decryption`): each POST's `jwks` holds a fresh key, and
    /// a JWE Request Object decrypts through the host's `RequestDecryption`, whose accessor the
    /// registration keeps. It needs `request_post` (`DecryptionWithoutPost`).
    pub fn request_encryption(&mut self, requests: EncryptedRequests)
        where H: Has<dyn RequestDecryption>;
}
/// Where a registered name sits: a `wallet_metadata` member, a POST parameter, a Response URI
/// answer member, an Authorization Response parameter. One `names` check holds every place
/// against the core's own names (`CORE_METADATA`, `CORE_PARAMETERS`, `CORE_ANSWER`,
/// `CORE_RESPONSE`, each checked in every build).
pub enum NamePlace { WalletMetadata, PostParameter, AnswerMember, ResponseParameter }
/// The conflicts `build` refuses beside a format's and a profile's: a mode name twice on one
/// channel, or an answer and an error registration of one name and channel by modes of
/// different types; an error mode over the DC API; a DC API mode with `wallet_metadata` members; a
/// response type, a prefix, a hash algorithm or a scope value twice; a transaction data profile
/// without `sha-256` (B.3.3.1's default); a scope query the DCQL reader refuses; a query id two
/// scope queries share (§5.5); `RequestPost` twice; `EncryptedRequests` without it; a profile
/// naming a member the format's placement does not hold (`Placement::places`); a name two parts
/// declare, or one the core writes.
pub enum RegistryErrorAdditions { ModeTwice { name: ModeName, channel: ChannelKind },
                                  ErrorModeChannel(ModeName), MetadataChannel(ModeName),
                                  ResponseTypeTwice(ResponseTypeName), PrefixTwice(PrefixName),
                                  HashTwice(HashName), Sha256Absent, ScopeTwice(ScopeValue),
                                  ScopeQuery(ScopeValue), ScopeIds(ScopeValue, ScopeValue, String),
                                  PostTwice, DecryptionWithoutPost,
                                  MemberPlacement { registration: String, format: String,
                                                    members: AllOf<String> },
                                  NameTwice { place: NamePlace, name: ParameterName },
                                  NameReserved { place: NamePlace, name: ParameterName } }

/// It owns the request it reads from the authenticated envelope and holds each record by index
/// (`Picked`): a record's `AnsweredQuery` borrows its query, which borrows that request, so
/// `respond` reads each query through `FormatHost::answer` again.
#[must_use]
pub struct Prepared<'p, H: CoreHost> { authenticated: &'p Authenticated<'p>,
                                       registry: &'p Registry<H>, env: &'p Env,
                                       request: Request<'p>, records: Vec<Picked<'p, H>>,
                                       resources: Slots<Resource> }
/// Only `Prepared::respond` makes one; `response()`, `delivery()`, `used()` and `audience()` read
/// it. `used`: the credentials the presentations used, each once, in the order the response
/// presents them. `audience`: what the presentations bind to (Annex A, B.3.6).
pub struct Built<'p> { response: AuthorizationResponse<'p>, delivery: Delivery,
                       used: Vec<CredentialId<'static>>, audience: Audience }

impl<'p, H: CoreHost> Prepared<'p, H> {
    /// The request read from the authenticated envelope, with its routing, its rules run before
    /// the ids are read (a refused request answers its refusal); the routed mode's registration
    /// read from `registry`, the one the envelope was read with, by its `ModeHandle`, the name
    /// checked (a `Fault` otherwise); a mode rule C5 refuses ends here as the refusal. The ids the
    /// End-User chose read as records, each derived with the matcher's code, its query read
    /// through `FormatHost::answer` under the accepted mode, and checked; the profiles' resources
    /// in their slots. No id is a selection when every credential set of the request is optional
    /// (§6.4.2: "and optionally, any of the other Credential Set Queries"), answered with a
    /// `vp_token` of no query (§8.1); an empty selection of a request with a required set is
    /// `Rejection::NoAlternative`. A record's transaction is its candidate's
    /// `TransactionBinding`.
    pub fn prepare(authenticated: &'p Authenticated<'p>, ids: &[&str], wallet: &'p Wallet<'p>,
                   registry: &'p Registry<H>, env: &'p Env, context: &Context, host: &H)
        -> Result<Self, Outcome>;
    pub fn questions(&self) -> &[Resource];
    /// In order: each query read again through `FormatHost::answer`; `fetch` answers every
    /// resource, once, in order; the route and its `AnswerRoute`, or the answering mode's refusal
    /// (`Outcome::Refused`, C7 under the sealing module's statement), which ends phase 2 before
    /// revalidation and the End-User's authentication. Under the answer route's session, each
    /// credential is checked usable (`Platform::usable`), each record's profile revalidates with
    /// its own resources and each record's `AnsweredOption` revalidates; a finding ends phase 2
    /// as `Outcome::Fallback`. Then `Platform::authenticate` with the strongest need of the
    /// records' profiles, an `Authentication` weaker than it refused
    /// (`Outcome::AuthenticationTooWeak`); the presentations bound to the session; the registered
    /// response parameters' members (`ParameterBreach`); the delivery.
    pub fn respond(self, fetch: impl FnMut(&Resource) -> Fetch, host: &H)
        -> Result<Built<'p>, Outcome>;
}
```

The modules, by family:

| Module | Family | Methods | Given as | Defined in | Required by | Used when the build holds it by |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| `Platform` | the wallet app | `now`, `usable`, `authenticate(need)` | a handle | core | core; siros-sdjwt, siros-paso, siros-ts12 | |
| `Haip` | HAIP §5, §7 | `verifies`, `verify`, `sign`, `agreements`, `encrypt_jwe` | zero-sized | core, `resolve` | the registrations `client_prefix` and `jwe_mode` (through `JweHost`); siros-sdjwt, siros-mdoc, siros-paso | |
| `RequestDecryption` | §5.10, RFC 9101 §6.1 | `decrypts`, `ephemeral_key`, `decrypt` | a handle (the module keeps the secrets) | core, `request-decryption` | the registration `request_encryption` | |
| `RandomIds` | RFC 9562 | `random_id` | a handle (the platform's RNG) | siros-paso | siros-paso, siros-ts12 | |
| `IssuerTrust` | the wallet's trust store of credential issuers: an ad-hoc metadata JWT's `x5c` chain (Proof Metadata §5.3 step 3) | `anchor(&X5c, Timestamp) -> Option<RootCertificate>` | a handle (the app's store; siros-trust's `TrustStore::anchor`) | siros-paso, `resolve` | siros-paso | |
| `CoseEncrypt` | RFC 9052's `COSE_Encrypt`: PaSO's sealed signals (Risk Signals §7.6) | `encryptions`, `encrypt_cose` | zero-sized | siros-paso, every `resolve` build | | siros-paso, bounded in every build, called under `sealed-signals` |
| `DeviceMac` | ISO/IEC 18013-5 §9.1.3.5 | `mac` | zero-sized | siros-mdoc | | siros-mdoc; else `Haip::sign` |
| `Paso` | PaSO Core §6.1, Risk Signals | `version`, `measure` | a handle (the app keeps the measurements) | siros-paso | siros-paso | |

`CoreHost` names the module the core calls with no extension registered: `Platform`, for the
clock, the credentials' status and the End-User's authentication. Each
registration that makes the core call another module bounds it, and the registry keeps the
module's accessor: `client_prefix` `Has<dyn Haip>` (A7 and A8), `jwe_mode` `JweHost` (a host
holding `Haip`, for the sealing, or `NoHost`, whose phase 1 reads the mode alone),
`request_encryption` `Has<dyn RequestDecryption>`. A plug-in bounds the modules it calls itself:
a format that signs `Has<dyn Haip>`, siros-paso and siros-ts12 siros-paso's `Has<dyn RandomIds>`,
siros-paso's phase 2 `Has<dyn IssuerTrust>` and `MayHave<dyn CoseEncrypt>` in every build. siros-paso's `CoseEncrypt` and
`CoseEnc` compile in every `resolve` build, so a host states its `CoseEncrypt` slot whatever
another crate turns on; `sealed-signals` adds `SealedCose`, its check, the sealing and
`TestCoseEncrypt`. An unsigned DC API build of `dc_api` and a
format that signs implements `Platform`, and `Haip` for `sign`: `Haip` is one family (decision
13), and that host's statements are `JwsAlgorithms::NONE` and `Agreements::NONE`, so the core
never calls `verify` or `encrypt_jwe`. A plug-in's module lives in its crate: `RandomIds` and
`CoseEncrypt` in siros-paso, whose specifications alone call them.

The types of a plug-in's module move with it: `SignalType`, `Measurement` and `Reading` to
siros-paso, `Mac` to siros-mdoc, `ProofRequest` to siros-zkp-req. `DeviceMac::mac` takes section
4.9.4's `SessionTranscriptBytes`, which only siros-mdoc's `SessionTranscript::tagged_bytes` makes.
`fetch` leaves as effects (decision 2). `proposals/flows/host-sketch/` typechecks the host modules'
access pattern over the HAIP and WE BUILD builds of sections 4.10.4 and 4.11: each build's host;
`CoreHost` as `Has<dyn Platform>`; `prefix` and `jwe_mode` bounding `Haip` and `request_encryption`
bounding `RequestDecryption`, each keeping the module's accessor; every plug-in's bounds. The WE
BUILD host states an `Empty` `CoseEncrypt` slot and takes siros-paso with and without
`sealed-signals` (`PasoProfile`, `PasoSealedSignals`). A host meets that bound with a `Held` or an
`Empty` slot. With `--features demo-missing-module`, siros-paso registers over `SlotlessHost`,
which states no `CoseEncrypt` slot, and the compiler refuses the build (E0277).

`respond(request, ids, wallet, registry, env, runtime)` is removed, and `Outcome` gains
`Unroutable`. `FormatQuery::present` leaves for `AnsweredOption::present`. `ProfileHost` holds
`wanted`, `informed` and `authentication`, each naming a `resolve` type, so `Profile` compiles
the same in every build (section 4.11): `fn wanted(&self, record: Answered<'_>, host: &H) ->
Result<Vec<HttpsUrl>, Fault>` (from the record, the profile's data and the host's modules;
reading the record can fail), and `ProfileHost::revalidate`
reads the fetched resources from its `FetchedRecord`.
siros-paso's images and siros-qes's documents move there. `Profile` gains `fn reserves(&self,
credential: &Credential<'_>, additions: &dyn ViewAdditions) -> Result<bool, Fault>` (phase 1,
default `Ok(false)`): a credential a profile reserves is a candidate only for a query one of the
profile's own entries names, and another query excludes it as `ReservedCredential`. A `Fault` is
wallet data the profile cannot read. siros-ts12 reserves an SCA attestation,
siros-paso and siros-qes none. `Answered` gains `mode`, the name of the registered mode the
route answers in: siros-paso's response mode signal reads it there, and so does siros-ts12's
KB-JWT `response_mode`. `Profile::members(format)` becomes `members(placement)`: a format states
how its proof carries a profile's members (`Format::placement`), and the profile places its
members by that kind, naming no format: `Placement::Claims` places claims of a JSON proof, their
values JSON; `Placement::NameSpaces` data elements of a CBOR proof's name spaces, their values CBOR
data items. The registry holds each format's placement from build and refuses a profile naming an
element under `Claims` or a claim under `NameSpaces` (`RegistryError::MemberPlacement`,
`Placement::places`). `ProfileHost::authentication(&self, record: Answered<'_>) ->
Result<AuthenticationNeed, Fault>`: siros-ts12 answers `Strong`; siros-paso `Strong` when the
type's effective risk signals require `amr` (Risk Signal Registry §2.8), else `Presence`;
siros-qes and the test profiles `Presence`. `Outcome` gains `AuthenticationTooWeak { need,
covered }`, `covered` the PSD2 categories the factors cover (`Categories`, one to three of
them), and `NotPresented(Box<dyn Explain>)`: a step failed without a bug, such as a cancelled
key prompt (§8.5 `access_denied`). `Fallback` holds `AllOf<Finding>`, and `Finding` gains
`Format { record, finding }`, an `AnsweredOption`'s finding.

siros-paso writes the `amr` signal (Registry §2.8) from the `Authentication` it receives: status
`ok`, `collected_at` the time the End-User completed it, and RFC 8176 §2's methods in the order
of the factors: `pin` for a PIN or a pattern, `pwd` for a passphrase, `kba` for a knowledge
factor the platform does not name, `hwk` for a key in a WSCD, `swk` for a software key; with a
biometric factor, exactly one of `bio_strong` and `bio_weak`, then each modality the platform
names (`fpt`, `face`, `iris`). siros-paso classifies each inherence factor from the facts the
platform reports (`BiometricClass::of -> Option<BiometricClass>`, Registry §2.8): `bio_strong`
when its matching runs in a hardware-isolated environment, with a false accept rate of one in
50,000 or less, and with presentation attack detection; `bio_weak` for a false accept rate of one
in 10,000 or less short of that; `None` for a worse or an unreported rate. The signal names the
best class a factor meets (`amr::methods -> Option<Node>`). When every biometric factor meets
neither class, §2.8's "exactly one" admits no value, and the signal's status is `unavailable`
(Risk Signals §2.3). Each method appears once.
`Paso::measure` is never asked for `amr`. A TS12 profile reads the same facts by its own list.

A module the build lacks that a record's presentation needs is a finding at revalidation, so
phase 2 answers `Fallback` before `Platform::authenticate`. siros-paso's `OptionalModule` holds
the rule that an mdoc's encrypted risk signals need `CoseEncrypt` (Risk Signals §7.6), and the
informed profile refuses such an entry in phase 1 (`NotCompatible::Lacks`). A build without
`sealed-signals` starts `PasoProfile`'s `lacking` with `OptionalModule::CoseEncrypt`
(`OptionalModule::UNCOMPILED`), so its phase 1 refuses that entry as a build lacking the module
does. siros-mdoc's
`DeviceAuthRefused::NoDeviceMac`, where the Verifier lists the MAC alone and the build lacks
`DeviceMac`, is the option's finding (`Finding::Format`); the app's re-run leaves its credential
out. The claims kit gives a claims format this step as `ClaimsPresent<H>::revalidate`, over a
`Revalidating` of the query, the credential's view, the transaction's members and the session.

`Host`'s blanket implementation brings its `get` into the method resolution of every type where
`Host` is in scope, where it shadows `Vec::get` and `RawValue::get`: a crate imports `Host` inside
the functions that read the host.

#### Wallet metadata and the POST (`wallet_metadata.rs`; the names and `Placement` under `match`, the POST under `uri`)

`wallet_metadata` and the `request_uri` POST are composed from contributions, each name from one
contributor: the formats write `vp_formats_supported`; the registered prefixes
`client_id_prefixes_supported` and, through the `Haip` their registration reached,
`request_object_signing_alg_values_supported`; the URI modes their declared members;
`EncryptedRequests` `jwks`; a registered `PostContribution` its declared members and POST
parameters (§10.1: "Additional Wallet metadata parameters MAY be defined and used"; §5.10:
"Additional parameters MAY be defined and used in the request to the Request URI Endpoint").
Every name is a constant the registry checks when it builds.

```rust
/// A parameter or metadata name (RFC 6749 §8.2's `param-name`): ASCII letters, digits, `-`, `.`
/// and `_`; a plug-in makes its own with `checked!`.
pub struct ParameterName(&'static str);
/// The wallet's metadata for one POST (§5.10, §10), and the POST parameters its contributors
/// wrote in the same pass: each contribution writes once per POST.
pub struct WalletMetadata { json: String, parameters: Vec<PostParameter> }
/// One member a contributor writes: its declared name and its JSON value.
pub struct MetadataMember { name: ParameterName, value: Node<'static> }
/// One POST parameter beside `wallet_metadata`: its declared name and its text.
pub struct PostParameter { name: ParameterName, value: String }
pub struct PostContent { pub members: Vec<MetadataMember>, pub parameters: Vec<PostParameter> }

/// Members and POST parameters a profile or a deployment adds: their names, constants.
/// `DynClone`, as `Format`, so `Registry::informed` clones the registry.
pub trait PostContribution: DynClone + Send + Sync {
    fn members(&self) -> &'static [ParameterName];
    fn parameters(&self) -> &'static [ParameterName];
}
pub trait PostContributionHost<H>: PostContribution {
    /// What it writes into this POST: declared names alone.
    fn write(&self, host: &H) -> Result<PostContent, Fault>;
}
pub trait HostedPostContribution<H>: PostContributionHost<H> {}

/// `Undeclared`: a contributor wrote a name it did not declare. `NotObject`: a contribution that
/// is no JSON object where §10.1 asks for one (a format's `vp_formats_supported` value, `jwks`).
/// `Fault`: a contributor broke its contract.
pub enum MetadataRefused { Undeclared(ParameterName), NotObject(String), Fault(Fault) }

impl WalletMetadata {
    /// What §5.10 and CS-12 ask, and each registered contribution: `vp_formats_supported`, each
    /// registered format's `Format::wallet_formats` under its `Format::id` (§10.1: REQUIRED;
    /// Appendix B); `client_id_prefixes_supported`, the registered prefixes' names (§10.1: "If
    /// omitted, the default value is pre-registered", which A2 refuses);
    /// `request_object_signing_alg_values_supported`, `Haip::verifies`, when the outer
    /// `client_id` names a registered prefix, each of which authenticates signed Request Objects
    /// (§5.10: SHOULD, and MUST NOT for a prefix that precludes signing; HAIP §7); each
    /// registered URI mode's members (`ModeHost::wallet_metadata`: `direct_post.jwt`'s
    /// `authorization_encryption_alg_values_supported` and
    /// `authorization_encryption_enc_values_supported`; §5.10: SHOULD for an encrypted response);
    /// with `EncryptedRequests`, `jwks` holding the fresh key's public JWK (§5.10: SHOULD; CS-12
    /// §7.3 item 9) with `use` `enc`, by which WE BUILD's test bed selects it; each registered
    /// `PostContribution`'s members. In that order; `client_id_prefixes_supported` when the build
    /// registers a prefix. Each contribution writes once, its POST parameters kept for
    /// `RequestUriPost`; a parameter written twice is `MetadataRefused`.
    pub fn of<H: CoreHost>(registry: &Registry<H>, host: &H, client_id: &ClientId<'_>,
                           key: Option<&EphemeralKey>) -> Result<Self, MetadataRefused>;
}

pub trait Format {
    // Every other method unchanged.
    /// The format's `vp_formats_supported` member, a JSON object: siros-sdjwt's
    /// `sd-jwt_alg_values` and `kb-jwt_alg_values`, siros-mdoc's `issuerauth_alg_values` and
    /// `deviceauth_alg_values`. `WalletMetadata::of` writes it under the format's `Format::id`.
    fn wallet_formats(&self) -> Result<Node<'static>, Fault>;
    /// How its proof carries a profile's members; `None` for a proof that carries none. The
    /// registry reads it once, when it builds.
    fn placement(&self) -> Option<Placement>;
    /// A credential's types, which a profile reads through `Binding::additions` (reading 26); a
    /// `Fault` for a view the format does not read.
    fn additions<'c>(&self, credential: &'c Credential<'c>)
        -> Result<Box<dyn ViewAdditions + 'c>, Fault>;
}

/// Claims of a JSON proof (an SD-JWT VC's Key Binding JWT), their values JSON; or data elements of
/// a CBOR proof's name spaces (an mdoc's `DeviceSigned`), their values CBOR data items.
pub enum Placement { Claims, NameSpaces }
impl Placement {
    /// A claim under `Claims`, a data element under `NameSpaces`.
    pub const fn places(self, member: &Member) -> bool;
}

/// The POST's form (§5.10): `wallet_metadata`, a JSON string, then the parameters
/// `WalletMetadata::of` kept, in registration order; §5.10's `wallet_nonce` stays out (decision
/// 12). It serializes as a map of text members.
pub struct RequestUriPost<'a> { wallet_metadata: &'a WalletMetadata }
impl<'a> RequestUriPost<'a> { pub const fn of(wallet_metadata: &'a WalletMetadata) -> Self; }

impl<H: Build> RegistryBuilder<H> {
    /// `build` refuses a name another part declares (`NameTwice`) and a name the core writes
    /// (`NameReserved`): the members `vp_formats_supported`, `client_id_prefixes_supported`,
    /// `request_object_signing_alg_values_supported`, `jwks`; the parameters `wallet_metadata`,
    /// `wallet_nonce`.
    pub fn post_contribution<C: HostedPostContribution<H> + 'static>(&mut self, contribution: C);
}
```

The caller POSTs the `RequestUriPost` form as `application/x-www-form-urlencoded`. The names come
from JARM §4 (`authorization_encryption_*`) and OpenID Connect Discovery 1.0 §3
(`request_object_signing_alg_values_supported`), as §5.10 uses them, and from §10.1
(`vp_formats_supported`, `client_id_prefixes_supported`). §5.10's "no more" holds for the core:
it writes its own members alone, and a registered contribution writes the names it declared. The
registry refused a name two parts declare when it built, so `WalletMetadata::of` refuses only a
contributor that wrote an undeclared name. The POST needs no decryption: a build registers
`RequestPost` alone to POST its metadata, and `EncryptedRequests` beside it when it asks for an
encrypted Request Object (§5.10: "If the Wallet requires the Verifier to encrypt the Request
Object, it SHOULD use the jwks parameter").

#### Transaction data hashes (`hash.rs`, `transaction-data`)

B.3.3.1's `transaction_data_hashes_alg` names algorithms of the IANA Named Information Hash
Algorithm Registry, an open set: a hash algorithm is a plug-in. Phase 1 reads its name and its
digest's length, phase 2 its digest.

```rust
/// A Hash Name String (RFC 6920 §9.4): lowercase ASCII letters, digits and `-`.
pub struct HashName(&'static str);
/// A hash algorithm: its name and digest length, which phase 1 reads, and its digest, which phase 2
/// writes. One trait in every `transaction-data` build, which the request's `Hashes` carries under
/// every host.
pub trait HashAlgorithm: DynClone + Send + Sync {
    fn name(&self) -> HashName;
    /// The digest's length in octets; the core refuses a digest of another length
    /// (`HashesError::Digest`).
    fn octets(&self) -> NonZeroUsize;
    fn digest(&self, data: &[u8]) -> Vec<u8>;
}
/// The registered algorithms, as the request carries them from the registry its envelope was
/// read with: defined in the registry (`plugins::Hashes`), re-exported as `hash::Hashes`.
pub struct Hashes<'r>(&'r [Box<dyn HashAlgorithm>]);

/// The core's SHA-2 algorithms, over the sha2 the core links: `sha-256`, its five truncations
/// (RFC 6920 §2), `sha-384`, `sha-512`.
pub enum Sha2 { Sha256, Sha256Truncated(Truncation), Sha384, Sha512 }
pub enum Truncation { To128, To120, To96, To64, To32 }
pub enum Sha3 { Sha3_224, Sha3_256, Sha3_384, Sha3_512 }   // feature `sha3`
pub enum Blake2 { Blake2s256, Blake2b256, Blake2b512 }      // feature `blake2`
pub enum K12 { K12_256, K12_512 }                           // feature `k12` (RFC 9861 §6)

impl<H: Build> RegistryBuilder<H> {
    /// `build` refuses a name registered twice (`RegistryError::HashTwice`), and a build that
    /// registers a transaction data profile without `sha-256` (`Sha256Absent`).
    pub fn hash(&mut self, algorithm: impl HashAlgorithm + 'static);
}
```

B.3.3.1's rule picks the first registered algorithm every entry's `transaction_data_hashes_alg`
allows, `sha-256` when an entry names none; no such algorithm is `HashesAlgRule`'s refusal. B.3.3.1
makes `sha-256` the default, so the registry refuses a transaction data build without it. A build
registers the algorithms it serves: the HAIP and WE BUILD builds register `Sha2`'s eight, and
the differential's build registers all seventeen, so its comparisons keep their counts (I9). The
app builds the matcher's and the wallet's registries with one registration function generic over
the host, so the matcher registers the same names as the wallet; its digests compile over the sha2
`match` links already. siros-paso computes Core §6.1's entry hash through the core's
`Sha2::Sha256`.

#### Scope queries (`scope.rs`, `uri`; `ScopeValue`, `Scopes` and `ScopeEntry` in every build)

§5.5 leaves scope values and their DCQL queries to other specifications: "The specific scope
values, and the mapping between a certain scope value and the respective DCQL query, are out of
scope of this specification". A scope query is a plug-in.

```rust
/// A scope value (RFC 6749 §3.3's `scope-token`): one or more of %x21, %x23-5B, %x5D-7E.
pub struct ScopeValue(&'static str);
/// A scope value and the DCQL query it stands for (§5.5).
pub trait ScopeQuery: Send + Sync {
    fn scope(&self) -> ScopeValue;
    /// The DCQL query, as JSON text; the registry parses it when it builds.
    fn query(&self) -> &'static str;
}
/// The registered scope queries as the registry read them (crate-private `ScopeEntry`: the value,
/// its Credential Queries and Credential Sets as written), as the envelope carries them, in every
/// build.
pub struct Scopes<'r>(&'r [ScopeEntry]);

impl<H: Build> RegistryBuilder<H> {
    /// `build` refuses a scope value twice (`ScopeTwice`), a query the DCQL reader refuses
    /// (`ScopeQuery`), and a Credential Query or claim id two queries share (`ScopeIds`; §5.5:
    /// "MUST be unique").
    pub fn scope<S: ScopeQuery + 'static>(&mut self, query: S);
}
```

By URI, a request's `scope` values read as the union of their registered queries. A value no
registered query names is S3 (`invalid_scope`, §8.5: "unknown"), and `dcql_query` beside a scope
naming a query is S4 (`invalid_request`, §5.1: "but not both"). Over the DC API `scope` is no
parameter A.2 lists, and the wallet ignores it (reading 12): the scope queries, their parsers and
`RegistryBuilder::scope` sit under `uri`, and a DC API build holds an empty `Scopes`. HAIP and
WE BUILD define no scope value, so their builds register none.

#### Consent entries (`consent.rs`, `match`)

The core composes a consent entry as platform-neutral data: a format's `Card` and a profile's
`Overlay`, whose `TransactionHeader` holds the counterparty and the amount a transaction asks the
End-User to confirm (PSD2 RTS Art. 5(1)(a)). Every text in an entry is a `siros_i18n::Text` the
wallet's `Context` resolved (section 4.14). siros-credman maps an entry to Android Credential
Manager's Standard and Payment entries for the matcher; the wallet UI lays out the same entry.

```rust
pub struct Card { pub icon: Icon, pub title: Text, pub subtitle: Option<Text>, pub rows: Vec<Row> }
/// A label, its value and its section; a full-width text holds no value.
pub struct Row { pub label: Text, pub value: Option<Value>, pub section: Option<Text> }
pub enum Value { Image(Image), Text(Text) }
pub enum Image { Embedded(ImageRef), Remote(RemoteImage) }
pub struct Overlay { pub rows: Vec<Row>, pub header: Option<TransactionHeader>,
                     pub hint: Option<Text> }
pub struct TransactionHeader { pub counterparty: Text, pub amount: Text, pub rows: Vec<Row> }
/// Only the core's display step makes one; `card()` and `overlay()` read it, and `rows()` gives
/// the overlay's rows, then the card's, a transaction header's left out.
pub struct ConsentEntry { card: Card, overlay: Option<Overlay> }
/// An entry the wallet adds to every set, one per slot, first in every set (`matching`).
pub struct StaticEntry { pub id: StaticEntryId<'static>, pub card: Card }
/// An icon of at least one byte, a wallet asset or a card's logo, with its image media type
/// (`rows`).
pub struct Icon { pub reference: IconReference, pub media: ImageMedia, pub size: NonZeroU32 }
/// What an icon names: a wallet asset or a card's logo URI (`rows`).
pub enum IconReference { Asset(Cow<'static, str>), Logo(Cow<'static, str>) }
/// The essence of any media type of top-level type `image` (RFC 6838 §4.2.3), read through the
/// core's `MediaType` (`media`, ungated; `effects` re-exports it); `NotImageMedia` refuses
/// another (`Media`, `Type`).
pub struct ImageMedia(Cow<'static, str>);
```

siros-credman lays a `StaticEntry` out with `CredmanEntry::of_static`. It draws the icons Credential
Manager decodes: `EntryIcon` holds the card's icon when its media is PNG or JPEG
(android-credman-sys ABI.md §5), and `Icon::DEFAULT` otherwise, as Credential Manager drops an entry
without an icon; `StandardEntry::icon` and `PaymentEntry::method_icon` are `EntryIcon`s.
siros-credman also judges A9 over a set of the core's `Display`: a set needs no wallet display, and
the matcher sends `Full` delegation (K4), when `SetFacts` all hold and Credential Manager showed
everything. `SetFacts { presentable, transactions, settled, whole }`: every entry's credential
presentable from the background service (`Presentable`); the request carries no `transaction_data`
(`TransactionData::of(&Request)`); every slot one choice; every row a whole field. A field is plain
text (styles dropped), its label and value at most `FIELD_MAX` (80) characters, siros-credman's own
bound. A field's text is cut at the longest extended-grapheme-cluster boundary that keeps the text,
a closer for each bidi isolate or embedding the cut leaves open, and the ellipsis within 80
characters. An image shows clipped. A visible character is one that is neither White_Space nor
Default_Ignorable_Code_Point. A label, a card text and a Credential Manager field name each need
one. siros-openid4vp's text module defines it (`DisplayText::visible`). A row's label holds one
where its text enters: the claims kit takes its next choice for a label without one, siros-paso
refuses such a label (`LabelViolation::Invisible`), and siros-qes labels its rows with the wallet's
texts. A field's name starts at its label's first character other than white space. A row whose
label holds no visible character makes no field (`NoName`). Static entries disclose nothing and
stay out of the facts.

#### The core's vocabulary (`json`, `cbor`, `ids`, `plugins`, `wallet`, `claims::kit`)

A JSON object the core writes holds each name once, and a repeat of known names fails the build:

```rust
/// What a `Distinct` tells its values apart by.
pub trait Named { fn name(&self) -> &str; }
/// The first name two values hold, in code point order.
pub struct RepeatedName { pub name: String }
/// Values whose names differ: `new(Vec<T>) -> Result<Self, RepeatedName>`.
pub struct Distinct<T>(Vec<T>);
/// Names a constant writes: `const fn new -> Option<Self>`, `None` on a repeat.
pub struct FieldNames<const N: usize>([&'static str; N]);
```

- `known_object! { "name" => Option<Node>, .. }` writes the object of the members present, in the
  written order. A repeated name fails the build (E0080).
- `cbor::distinct_map(pairs, read)` reads a decoded map, whose keys the decoder holds distinct, into
  a `Distinct`.
- `Object::set` replaces a member in its place or adds it last. `Object::retain` drops members.
  `Node::natural` writes a length or a position. `Entry::members` gives an entry's `Object`.
- `Node::{json_spaced, json_compact, json_ascii}` give `WrittenJson`. Each writes a number as its
  received token. A double the core makes from CBOR or a measurement writes as Python's `repr`
  (`python_repr`, `FiniteDouble`). `Number` is `Eq`, and `Step::Beyond(Number)` holds a claims
  path's index as received.

A value's role is its type:

```rust
/// A citation (`CSC §6.3`) its crate's source writes: `Clause::cited`, `as_str`, `Display`.
pub struct Clause(&'static str);
/// A key of a credential's documents, non-empty: `const fn new -> Option<Self>`.
pub struct DocumentKey<'a>(Cow<'a, str>);
/// A prefix a profile registers its types under, non-empty: `const fn new -> Option<Self>`.
pub struct TypePrefix<'a>(Cow<'a, str>);
/// What a registration writes: a view, a document. `new`, `as_bytes`.
pub struct ViewBytes<'a>(&'a [u8]);
pub struct DocumentBytes<'a>(&'a [u8]);
/// One DER certificate of an issuer chain, its bytes as the chain holds them.
pub struct DerCertificate<'a>(&'a [u8]);
/// One `vp_formats_supported` member constraining a presentation.
pub struct Constraint<'n> {
    pub member: VpFormatsMember,
    /// The credential's key identifiers. `NoAlgorithm` names them.
    pub matched: Vec<Node<'n>>,
    /// What the member admits beyond them: a device MAC header's fixed `alg`. A refusal leaves them
    /// out.
    pub also: Vec<Node<'n>>,
}
```

siros-syntax's `checked!(Type, "text")` makes a value by `Type::new` and `Option::expect` in a
constant, so a refused literal fails the build (E0080). `ClaimsFormat::vp_formats_clause` returns a
`Clause`, and `NoAlgorithm.clause` holds it. `Credential::new` and `Document.content` take `&[u8]`,
and `Credential::document` takes `&str`: a plug-in passes `as_bytes` and `DOCUMENT.as_str()`.

### 4.3 The effects interface

The caller performs every effect and answers in data. Crypto, time and the End-User's
authentication stay calls on the host's modules (section 4.2).

| Effect or duty | Asked by | The caller does | Answers with |
| :-- | :-- | :-- | :-- |
| Request Object fetch | `Fetch::request` | GETs over TLS with `Accept: application/oauth-authz-req+jwt`: TLS as BCP 195 recommends, the server checked by DNS-ID as RFC 6125 §6 says, without CN-ID (RFC 9101 §8; HTTP-U1). Sends no identifying header and no PII (§15.8), follows no HTTP redirect, reads under a size limit. Checks status 200 and the media type `application/oauth-authz-req+jwt`. | `FetchAnswer::Body` or `Failed` |
| Trust evaluation | `Pending::questions`: siros-x509's `Evaluation`, the Origin's | Its trust framework decides: RFC 5280 path validation and revocation in full against its anchors (R5280-U1). The decision's context lists the endpoints it allows. | a `Decision` per evaluation, through `authenticate`'s `decide` |
| Resource fetch | `Prepared::questions`: each `Resource` (phase 2) | GETs the https URL. | a `Fetch` per resource, `Fetched` or `Unfetched`, through `respond`'s `fetch` |
| Delivery | `Built::delivery`, `Route::refusal`, `unmet`, `Rejected::reply` | POSTs the form to the `response_uri`, following no HTTP redirect; returns DC API `data`; or cancels. | — |
| The Response URI's answer | after `Delivery::Post` | Hands a body in `application/json` to `ResponseUriAnswer::parse`, shows the End-User the `outcomes()` the registered readers read (under the WE BUILD build the Verifier's error, CS-02 §6.1.7), and sends the user agent to `redirect()` (§8.2, HAIP §5.1). | — |
| Consent and interaction | phase 1's display; failures | Shows the consent with `Authenticated::verifier()`: its name, its endpoint, and what the decision's facts carry for display (the intermediated Relying Party's Service, CS-13 WU-INT-04; CS-13 §7.5's warnings). Tells the End-User of every refused request, and obtains an interaction before any error leaves (§15.4.1, §15.9.2, RFC 9700 §4.11.2). For an `Unverified` route, tells the End-User the wallet could not verify the site, shows the `response_uri`'s host, and sends the error only when the End-User chooses to return to the site. Renders issuer images in SVG and PNG, from data URIs and https URLs (HAIP §4.1). | the chosen ids |
| Invocation | the platform | Registers `haip-vp://`, `openid4vp://` and its https app links, and its DC API handler; passes the Origin the platform asserts. | `Received::dc_api`, `Fetch::of` |
| Credential registration | the wallet's store, beside the flows | Builds each credential's view through siros-sdjwt's `Registered` and siros-mdoc's `registration::Registered` (an mdoc's values as JSON, RFC 8949 §6.1) and facts (`aki` and Trusted List values), and validates its issuer signature with x5c key resolution (HAIP §6.1.1), before the matcher reads them. | `Wallet` |
| Host modules | everywhere | `Haip`: its statements (`verifies`, `agreements`), `verify`, `sign`, `encrypt_jwe` (a fresh ephemeral key and IV per message); `Platform`: `now`, `usable`, `authenticate` (an inherence factor with its matching's facts); the modules the build's registrations and plug-ins bound: `RequestDecryption` (the core's), siros-paso's `Paso`, `RandomIds` and `CoseEncrypt`, siros-mdoc's `DeviceMac`. | values |
| Registration | building the registry | Registers the build's formats, profiles, prefixes, response types, modes, response parameters, POST contributions, answer readers, Request Object rules, hash algorithms and scope queries, `RequestPost` when it posts `wallet_metadata` and `EncryptedRequests` when it asks for an encrypted Request Object; `build` refuses a conflict (`RegistryError`). The matcher's and the wallet's registries come from one registration function generic over the host. | `Registry<H>` |

### 4.4 siros-x509

`X509Hash` and `X509SanDns` implement `ClientPrefix` and `PrefixHost<H>` for every host, for
`x509_hash` and `x509_san_dns` (§5.9.3); the crate turns on the core's `signed`, and the build
registers them with `prefix`, whose bound `Has<dyn Haip>` gives the core the verifying module. HAIP §5 requires
`x509_hash`; §5.9.3 defines `x509_san_dns`. Their metadata is the request's `client_metadata`: §5.9.3 takes "all Verifier
metadata other than the public key" from it. The caller's trust service implements the
vocabulary below.

- **Claim** (A5; each refusal an `X509Refusal`). The protected header's `x5c` is a non-empty
  array of base64 DER certificates, the leaf first (RFC 7515 §4.1.6). Each item parses with
  x509-cert, whose `der` refuses BER, trailing data and non-minimal lengths (`X5c::of`). The
  leaf's SubjectPublicKeyInfo gives the `VerificationKey` as a public JWK (`SpkiKey::key`):
  id-ecPublicKey on the named curve secp256r1, secp384r1 or secp521r1 with an uncompressed point
  (RFC 5480 §2.1.1, §2.2) as `kty` `EC`, `crv` `P-256`, `P-384` or `P-521`, `x`, `y` (RFC 7518
  §6.2.1); id-Ed25519 or id-Ed448 without parameters (RFC 8410 §3, §4) as `kty` `OKP`, `crv`
  `Ed25519` or `Ed448`, `x` (RFC 8037 §2). The verifying module states the algorithms it takes
  (`Haip::verifies`) and checks the point.
  - `x509_hash`: the original identifier is base64url without padding of 32 octets
    (`LeafHash::parse`), equal to the SHA-256 of the leaf's DER as received.
  - `x509_san_dns`: the original identifier is a DNS name in preferred name syntax
    (`SanDnsName::parse`; RFC 1034 §3.5, RFC 5280 §4.2.1.6), and a dNSName entry of the leaf's
    subjectAltName names it, compared after ASCII lowercasing (reading 14).
- **Question.** An `Evaluation { subject: { type: "client_id", id: <the full Client Identifier> },
  action: { name: "credential-verifier" }, resource: { type: "x5c", id: <the leaf hash>,
  properties: { x5c: [<each item as received>] } }, context: { channel } }`, for both prefixes.
  The context's `channel` is `dc_api` or `uri`; it adds `origin` over the DC API, and
  `response_uri` and `request_uri` by URI (§15.8.2).
- **Binding** (`PrefixClaim::bind`). `Permit` binds the leaf's key. The decision's context may
  hold `name`, a string the consent shows, and `facts`, an object of what the framework states
  about the Verifier (`ClientBinding::facts`), for the plug-ins that read it. `Deny` is A6
  (`Unbound::Denied`).
- **Endpoint** (`PrefixClaim::endpoint`, by URI alone; over the DC API the endpoint is
  `BoundEndpoint::DcApi`). A decision whose context holds `endpoints`, an array of URIs, vouches
  for the request's `response_uri` when it equals one of them exactly (basis `Framework`;
  `Unbound::Endpoint`, A12, otherwise). Without `endpoints`, `x509_hash` vouches by the request
  (basis `Request`). `x509_san_dns` vouches when the `response_uri`'s host is the DNS name
  (`SanDnsName::hosts`; basis `Framework`, since the certificate names the host; A12 otherwise;
  §5.9.3). The core binds the `response_uri` with the basis given.

### 4.5 Rules

Each rule has one owner and one code. A routed rule answers with an error response on the
`Route`. A U or A rule answers on its `Rejected`'s `ErrorRoute`: over the DC API the DC API's,
as `DcApiErrors` decides; by URI as the "By URI" column says:

- **End-User**: the End-User alone hears of it.
- **Unverified**: the End-User hears of it, and can choose to send the error to the
  `response_uri` the payload names when that is an absolute `https` URI with a host
  (`ErrorTarget::Unverified`, reading 3).
- **Listed**: the `response_uri` a `Framework` binding vouches for (`ErrorTarget::Listed`).

**U: unreadable** (`arrival`, `uri`, `envelope`).

| Rule | Detects | Code | By URI | Source |
| :-- | :-- | :-- | :-- | :-- |
| U1 | A DC API protocol other than A.1's, or outside the configured `DcApiProtocols` | `invalid_request` | DC API alone | A.1, CS-07 WU-DC-01 |
| U2 | `data` without its protocol's shape | `invalid_request` | DC API alone | A.3 |
| U3 | Parameters that are no JSON object with unique member names at every level; a URI fluent-uri refuses, or one without a query; a `client_id` outside RFC 6749 Appendix A.1's `*VSCHAR`, U+FFFD included | `invalid_request` | End-User | RFC 8259 §4, RFC 3986 §3, RFC 6749 App. A.1, App. B |
| U4 | A URI parameter given twice, known or unknown; one without a value counts as omitted | `invalid_request` | End-User | RFC 6749 §3.1 |
| U5 | A URI without `client_id` | `invalid_request` | End-User | RFC 9101 §5 |
| U6 | `request` and `request_uri` together | `invalid_request` | End-User | RFC 9101 §5 |
| U7 | `request_uri` no absolute `https` URI with a host | `invalid_request_uri` | End-User | RFC 9101 §5.2, §7 |
| U8 | `request_uri_method` neither `get` nor `post` | `invalid_request_uri_method` | End-User | §5.1, §8.5 |
| U9 | The GET failed | none: terminate | End-User | §5.10.2 |
| U10 | A JWS `JwsError` refuses for its structure, base64url, JSON, an `alg` absent, no string or `none`, or a name in both headers | `invalid_request_object` | Unverified when the payload decodes, else End-User | RFC 7515 §7, §7.2.1, RFC 8725 §3.2 |
| U11 | A JWE Request Object after a GET, which posted no key (reading 21); after a POST, a JWE that `JweError` refuses, its `alg` or `enc` included when `RequestDecryption::decrypts` states neither, or that `RequestDecryption::decrypt` cannot decrypt | `invalid_request_object` | End-User | §5.10, RFC 9101 §6.1, RFC 7516 §7.1, RFC 8725 §3.1 |
| U12 | `typ` absent or other than `oauth-authz-req+jwt`, for each signature | `invalid_request_object` | Unverified | §5 |
| U13 | A Request Object holding `request` or `request_uri` | `invalid_request_object` | Unverified | RFC 9101 §4 |
| U14 | `client_id` and the Request Object's differ | none: terminate | End-User | §5.10.1, RFC 9101 §6.3 |
| U16 | `JwsError::Critical`: `crit` empty, outside the protected header, or naming a header the wallet does not process | `invalid_request_object` | Unverified | RFC 7515 §4.1.11 |
| U17 | Multisigned: `client_id` in the payload or an unprotected header | `invalid_request` | DC API alone | A.3.2.2 |
| U18 | A URI without `request_uri`: a request form outside the width, which reads a Request Object by reference alone (section 1) | `invalid_request` | End-User | §5, RFC 9101 §5 |
| U19 | `request`, a Request Object by value, outside the width | `request_not_supported` | End-User | RFC 9101 §7 |

**A: unauthenticated** (`authenticate`, siros-x509).

| Rule | Detects | Code | By URI | Source |
| :-- | :-- | :-- | :-- | :-- |
| A1 | The `origin` prefix | `invalid_request` | Unverified | §5.9.3 |
| A2 | A prefix the build does not register, or none | `invalid_request` | Unverified | §5.9.2, §8.5 |
| A3 | A signed DC API request without `client_id` | `invalid_request` | DC API alone | A.2 |
| A5 | A registered prefix's rule: siros-x509's `x509_hash` and `x509_san_dns` rules (section 8.2 lists each) | `invalid_request` | Unverified | §5.9.3, RFC 7515 §4.1.6, RFC 5280 §4.2.1.6, §7.2 |
| A7 | A signature whose `alg` the `Haip` the prefix's registration reached does not state (`Haip::verifies`), refused before the caller is asked | `invalid_request_object` | Unverified | RFC 8725 §3.1 |
| A6 | A `Deny`, or a decision that binds nothing | `invalid_request` | Unverified | §5.9.3, §15.8.2 |
| A8 | The signature does not verify under the bound key, or the key does not fit its `alg` (`Haip::verify`) | `invalid_request_object` | Listed under a `Framework` binding, else Unverified | RFC 9101 §6.2 |
| A9 | The Request Object outside `exp`, `nbf` | `invalid_request_object` | as A8 | RFC 7519 §4.1.4, §4.1.5 |
| A10 | `aud` present and other than `https://self-issued.me/v2` | `invalid_request_object` | as A8 | §5.8, RFC 7519 §4.1.3 (reading 13) |
| A11 | Multisigned: no signature authenticates | `invalid_request_object` | DC API alone | RFC 7515 §5.2, RFC 9101 §6.2 |
| A12 | By URI, no `response_uri`, or one outside the decision's `endpoints`; under `x509_san_dns` without `endpoints`, one on another host than the DNS name | `invalid_request` | Unverified | §5.9.3, §8.2, RFC 6749 §4.1.2.1 |
| A13 | A `response_uri` that is no absolute `https` URI with a host | `invalid_request` | End-User | RFC 9700 §2.6 |
| A14 | A registered `ObjectRule` refuses the Request Object's claims: siros-webuild's `Cs02Claims`, `exp` or `aud` absent | the rule's: `Cs02Claims` `invalid_request_object` | as A8 | CS-02 §8.2 |

The A rules run in this order: A1, A2, A3, A5, A7 and A13 in `Envelope::questions`, before the
caller is asked; then, for each claim, A6, A12, A8, A9, A10 and A14 in `Pending::authenticate`.

**Routed rules.** The routing's rules join the request rules at C5's place, and the named mode's
own rules after C6. A mode's and a profile's rules carry their own codes (`RequestRule::code`).

| Rule | Detects | Code | Source |
| :-- | :-- | :-- | :-- |
| P1 | `response_type` absent / naming no registered response type | `invalid_request` / `unsupported_response_type` | RFC 6749 §3.1.1, §8.4 |
| C5 | `response_mode` absent, naming no registered mode on the request's channel, or naming a mode that carries errors alone (`direct_post`, reading 24) | `invalid_request` | §5.2, A.2 (reading 2) |
| P5 | `redirect_uri` with a `response_uri` mode | `invalid_request` | §8.2 |
| P6 | `state` not URL-safe ASCII | `invalid_request` | §5.2 |
| P7 | A URI request with a query waiving holder binding and no `state` | `invalid_request` | §5.3 |
| N1 | `nonce` not URL-safe ASCII | `invalid_request` | §5.2 |
| S3 | A `scope` value in a URI request that no registered scope query names | `invalid_scope` | §5.5, §8.5 (reading 12) |
| S4 | `dcql_query` beside a `scope` naming a registered query | `invalid_request` | §5.1, §8.5 |
| C7 | The core's JWE modes' rule (`KeyRule`), a mode rule: no key and `enc` the key rule accepts | `invalid_request` | §8.3, HAIP §5 (reading 25) |
| C0–C4, C6, C8 | Unchanged | unchanged | §5.1, A.2 |
| T1–T6 | siros-ts12's request rules, beside siros-paso's (section 4.10.2) | `invalid_transaction_data`; T5, T6 `invalid_request` | TS12 §4.2, CS-12 §7.1, §7.3 item 3, §8.1 |

### 4.6 Readings of the specifications

Each reading below applies the defined terms and the specifications a flow builds on.

**2. `response_mode` is REQUIRED** (§5.2); the OpenID4VP working group's issue #665 confirms it.
§5.6 names a default per response type. By URI the default is no mode the wallet answers in, so
a URI request without `response_mode` is C5 with no carrier, and the End-User hears of it
(`Unroutable`). Over the DC API the error goes back as A.4's `{"error": code}`, which the core
writes whether or not the request names a registered mode.

**3. Where an error goes.** RFC 9101 §6.1 and §6.2 say "MUST return an "invalid_request_object"
error to the client", and OpenID4VP §5.10.1 has the wallet process the request "as defined in
[RFC9101]". RFC 6749 §4.1.2.1 says the server "MUST NOT automatically redirect the user-agent to
the invalid redirection URI" when the URI or the client is invalid. RFC 9700 §4.11.2: "The
authorization server SHOULD only automatically redirect the user agent if it trusts the
redirection URI. If the URI is not trusted, the authorization server MAY inform the user and
rely on the user to make the correct decision." All hold when an error goes automatically to an
endpoint valid for the client alone, and to an untrusted endpoint only by the End-User's
decision.

- A trust decision that lists the client's endpoints, or an `x509_san_dns` certificate that names
  the endpoint's host, makes the endpoint valid apart from the request
  (`EndpointBasis::Framework`). When the signature, the validity or the audience then fails (A8
  to A10), the error goes to that `response_uri` (`ErrorTarget::Listed`).
- Every other refusal by URI leaves the endpoint untrusted. The End-User hears of it. When the
  payload names an absolute `https` `response_uri` with a host, the End-User can choose to send
  the error there (`ErrorTarget::Unverified`). The Verifier then learns the flow failed, and the
  `redirect_uri` its Response URI returns brings the End-User back to its site (§8.2: "The
  Response URI MAY return the redirect_uri parameter in response to successful Authorization
  Responses or for Error Responses").
- §5.10.1 and §5.10.2 terminate processing: U9 and U14 answer the End-User alone.
- Over the DC API the platform returns the answer to the Origin (A.4): every error can go back,
  as `DcApiErrors` decides (§15.9.2).

EUDI's default `ErrorDispatchPolicy` and walt.id's destination binding send errors to
authenticated clients alone, which leaves RFC 9101 §6.2 unmet for A8 to A10. EUDI's `AllClients`
policy sends them to unauthenticated clients without asking the End-User.

**4. An example breaks normative text** (KA12). §8.2's by-reference example names
`client_id=https://client.example.org/cb` outside and
`redirect_uri:https://client.example.org/post` inside: U14. §5.4's by-value example meets U19
first. The examples are non-normative.

**5. Multisigned `data`.** A.3.2.1 puts the compact JWS in `data.request`; A.3.2.2's example shows
the bare JWS JSON Serialization. EUDI reads `data.request`. The core accepts both: the protocol
names the form, so each form has one reading.

**10. The redirect handover** holds the `response_uri` as the request names it, and the
thumbprint of the key the core sealed to: B.2.6.1 includes it "if the response is encrypted".
`Handover::Redirect.response_uri` is a `HandoverUri`: any text, with `From<&ResponseUri>`, since
B.2.6.1's hash takes the text as written.
siros-mdoc builds the handover from the session's binding facts, so a plain URI mode gives a
null thumbprint and `direct_post.jwt` a thumbprint always.

**12. Unknown scope values.** RFC 6749 §3.3 lets a server ignore scope; §8.5 defines
`invalid_scope` for an "unknown" value. §5.5 leaves each scope value's DCQL query to other
specifications, so the build registers the scope queries it knows, and HAIP defines none. By URI
a `scope` value no registered query names is refused (S3, `invalid_scope`): ignoring it would
answer less than asked. Over the DC API `scope` is no parameter A.2 lists, and A.2 has the
wallet ignore unrecognized parameters.

**13. `aud`.** RFC 7519 §4.1.3 binds a recipient when `aud` is present; an absent `aud` passes.
§5.8 sets `aud` to the wallet's issuer under dynamic discovery and to `https://self-issued.me/v2`
under static discovery. The wallet publishes no metadata, so a Verifier discovers it statically,
and A10 accepts `https://self-issued.me/v2` alone.

**14. `x509_san_dns` names compare as RFC 5280 §7.2 says.** A dNSName holds A-labels, and "When
comparing DNS names for equality, conforming implementations MUST perform a case-insensitive
exact match on the entire DNS name". `SanDnsName::names` compares the octets after ASCII
lowercasing, and `SanDnsName::hosts` compares the `response_uri`'s host the same way. The wallet
converts no U-label; a Client Identifier holding one names no dNSName (A5).

**16. StringOrURI and prefixed Client Identifiers.** RFC 7519 §2 makes a StringOrURI holding `:` a
URI. OpenID4VP sets a JWT's `aud` to the full Client Identifier (§5.9.1, §14.8, B.3.6), and
`x509_hash` and `x509_san_dns` hold `_`, which no URI scheme holds (RFC 3986 §3.1). The wallet writes OpenID4VP's
value: OpenID4VP defines these JWTs, and the Verifier compares `aud` with its own Client
Identifier.

**17. RFC 7519 §8's algorithms.** It names HS256 and `none`, and for encryption RSA1_5, A128KW,
A256KW and the CBC-HS encryptions, as what a JWT implementation implements. RFC 8725 §3.1, which
updates RFC 7519, has an implementation use the algorithms its application accepts. The
application's accepted algorithms are the ones its modules implement and state: `Haip::verifies`
for signatures (A7), `RequestDecryption::decrypts` for a JWE Request Object (U11), and each JWE
mode's key rule under `Haip::agreements` for a response. HAIP's modules state ES256 (§7) and
ECDH-ES with A128GCM or A256GCM (§5). U10 refuses `none` and an absent `alg` whatever the modules
state (RFC 8725 §3.2).

**21. `request_uri_method` `post`.** CS-12 §7.3 item 9: the wallet "SHALL support POST delivery
of the Request Object (`request_uri_method` `post`, OpenID4VP [10] section 5.10), SHALL provide its
encryption keys to the RP in the `wallet_metadata` of that POST exchange, and SHALL accept signed
Request Objects delivered with or without encryption"; §5.1: "a supporting Wallet MUST send the
request using the HTTP POST method". So `post` gives a POST of `wallet_metadata`, and the Request
Object comes signed, or signed and then encrypted to the posted key (RFC 9101 §6.1); `get` and an
absent `request_uri_method` give a GET. The POST carries `wallet_metadata` and the registered
contributions' parameters, its members those §5.10 and CS-12 ask for and the contributions
declare (`WalletMetadata::of`). A build registers `RequestPost` to POST, and `EncryptedRequests`
beside it to post a key: §5.10 makes the encrypted Request Object the wallet's choice ("If the
Wallet requires the Verifier to encrypt the Request Object"). The key is fresh for each POST: a
key that stayed the same would identify the wallet to every Verifier, and §15.6 has the wallet
prevent fingerprinting "during the request to resolve the Request Object URI". WE BUILD's test bed
encrypts the Request Object with the first values of
`authorization_encryption_alg_values_supported` and
`authorization_encryption_enc_values_supported`, which state the response's encryption. Each list
keeps one owner: those two are the JWE mode's rule under `Haip::agreements`, and what U11 accepts
is `RequestDecryption::decrypts`. The WE BUILD host states the same values in both modules,
ECDH-ES with A256GCM first (HAIP §5), so the test bed's choice is one U11 accepts; I19's WE BUILD
path checks the pair. `aud` stays absent or
`https://self-issued.me/v2` (A10): the posted metadata names no `issuer`, so §5.8's dynamic case has
no issuer value (reading 13).

**22. `verifier_info`.** §5.11 leaves its formats to "ecosystems or profiles". The prefix hands
`verifier_info` as received, with the `dcql_query`, to the trust service in its evaluation's
context, and the trust service owns every rule on it; its `Deny` is A6. Under HAIP's width it
ignores the parameter: HAIP profiles no format. Under the WE BUILD build it applies CS-02 §7.1: it
denies a request without `verifier_info`, and validates ETSI TS 119 472-2 §6.3.2.2's
`registrar_dataset` and `registration_cert` (CS-02 NOTE_CS02_04), their binding to the access
certificate (§5.11.1, "claim-bound attestations"), the intermediary rules (CS-13 §7.2) and
over-asking (CS-13 WU-INT-01). It ignores the formats it does not know (§5.11), and answers with
the name the consent shows, the intermediated Relying Party's (CS-13 WU-INT-04), and with CS-13
§7.5's warnings in its facts.

**23. The `redirect_uri` a Response URI returns** is a URI with a scheme (RFC 3986 §3), a fragment
included: §8.2's example carries `#response_code=...`. A relative reference is
`AnswerError::RedirectUri`.

**24. Plain `direct_post` is an error form.** §8.3.1: "If a Wallet is unable to generate an
encrypted response, it MAY send an error response without encryption as per Section 8.2." By
URI the wallet answers in `direct_post.jwt` (HAIP §5.1) and in the URI modes a build registers.
The HAIP and WE BUILD builds register `direct_post` with `error_mode` alone, so it carries errors
alone (`Carries::Errors`): a request naming it is C5, and its authenticated `response_uri`
receives that error in §8.2's plain form, which `direct_post` writes. A build that answers plain
`direct_post` registers it with `mode` as well.

**25. HAIP's encryption narrows `dc_api.jwt`.** HAIP §5 applies §8.3 with ECDH-ES on P-256 and
A128GCM or A256GCM to every encrypted response, and §5.2 requires `dc_api.jwt`. The key rule is
the core's JWE modes' (section 4.2's core modes), and the sealing module's statement narrows it
further. The model
encrypts `dc_api.jwt` to the first key on any of five curves, takes ECDH-ES when `alg` is absent,
accepts the key wraps, and takes the first `enc` it implements. The key rule takes a P-256 key
whose `alg` is present (§8.3: "The alg parameter MUST be present in the JWKs"), and A256GCM when
listed, else A128GCM. A request the model encrypts otherwise gets another key, another `enc`, or
C7; the differential names these classes (I9).

**26. `vct_values` through `extends`.** B.3.5: "The Wallet MAY return Credentials that inherit
from any of the specified types, following the inheritance logic defined in
[I-D.ietf-oauth-sd-jwt-vc]". CS-12 §8.1 queries the WE BUILD base types, and the rulebooks have
banks issue types that extend them (rb-sca-iban §4.5). The core's registration view gives `types`
(`ViewAdditions`), which siros-sdjwt writes: the credential's `vct`, then each type its type
metadata extends, nearest first, from the chain the caller resolved at registration with
`vct#integrity` and each `extends#integrity` checked (SD-JWT VC §6.4). siros-ts12 reads them
there and names no format crate.
`vct_values` matches when it names one of them. The presentation carries the credential's own
`vct`.

**27. CS-12's string `transaction_data_hashes_alg`.** CS-12 §8.1's examples write `"sha-256"`.
Its text says "values and processing as defined by OpenID4VP", where B.3.3.1 defines a non-empty
array of strings, and WE BUILD's test bed sends `["sha-256"]`. The core keeps B.3.3.1's rule. The
Key Binding JWT's `transaction_data_hashes_alg` is the string B.3.3.1 defines for the response.

**28. CS-12 §6.1 step 3's `aud` check.** The step has the wallet compare an `sca-user`
attestation's `aud` with the requesting bank. CS-12 §7.4 items 3 and 8 and rb-sca-user put the
check on the Relying Party, and no rule maps the attestation's `aud`, a URL, to an `x509_hash`
Client Identifier (CS-02 §7.1 item 5). The wallet performs none (decision 12).

**29. URI schemes.** CS-02 §7.1 item 3 requires `openid4vp://` and `eu-eaap://` and allows
`haip-vp://`. The platform routes each scheme the caller registers to the app, and `Fetch::of`
reads any absolute URI whose query holds the request.

**30. CS-02 §6.1.3's "Nonce freshness".** The wallet judges a request current by its `exp` (A9),
which the WE BUILD build requires (siros-webuild's `Cs02Claims`, A14, CS-02 §8.2). CS-02 §7.2 has the
Verifier generate the nonce (item 2) and validate the presentation's nonce binding (item 5); the
wallet's reciprocal duty is that binding (§7.1 item 10), which the Session gives every
presentation. The core keeps no state between flows.

### 4.7 Established crates

The design implements no standard an established crate implements as it needs. A candidate
must be pure Rust, maintained, under a license compatible with BSD-2-Clause, and free of panics
on malformed input. A crate that parses JSON or CBOR maps must also refuse a repeated member
name at every level it parses. A crate the matcher carries counts against its 460,800-byte
budget. The matcher builds `match` alone: JOSE parsing reaches it, and fluent-uri through
`HttpsUrl` (section 4.9.3). The survey's facts
date from 2026-11-02 (`crates/survey/`).

**Picks.** `checks/crates.py` reads this table.

| Standard | Pick | Why |
| :-- | :-- | :-- |
| X.509 certificates (RFC 5280) | x509-cert 0.3.0 with der 0.8.3 (RustCrypto) | The one parser tested that refuses both trailing data and a non-minimal length; no panic over 433 truncations and 3,464 bit flips of a leaf. `ChainCertificate` keeps the DER as received for the hash. |
| SubjectPublicKeyInfo to a key | own code over spki 0.8.1 in siros-x509, written as a public JWK | A short function: id-ecPublicKey on secp256r1, secp384r1 or secp521r1 with the uncompressed point, whose coordinates become the JWK's `x` and `y`, or id-Ed25519 or id-Ed448, whose key becomes its `x`; the verifying module checks the point, as `Haip::verify`'s contract says. The core links no curve arithmetic: `RequestDecryption` draws the posted key, keeps its secret behind a `KeyHandle` and returns the public JWK, and `Haip` checks a point (I10, I39). |
| JWS compact serialization | own code over the core's `json` module and base64 | Each JOSE crate tested accepts a repeated member at some level. The core's path costs the matcher 3,830 bytes; a crate adds 41,213 to 258,936 bytes more, or does not build for wasm32-wasip1. |
| JWS JSON Serialization | own code, as for compact | The same reasons. RFC 7515 §7.2.1's disjoint headers too: jose-jws accepts a name in both headers, and josekit, which refuses it, keeps the last of every repeated member. |
| JWK (RFC 7517) | the core's `AgreeableKey` over its `json` module (existing) | Each JWK type tested drops or keeps a repeated unknown member. |
| JWK thumbprint (RFC 7638) | siros-mdoc's `Thumbprint::of`, over the core's `json` module | Over sha2; B.2.6's handover is its one reader. KA1 checks it. |
| JWT claim checks (RFC 7519) | own code: `NumericDate`, `Skew`, `Validity` | The crates bind their claim checks to their own decoding, which accepts repeated members. The fraction of a NumericDate and the skew bound are a few lines. |
| URIs (RFC 3986), IRIs (RFC 3987) | fluent-uri 0.4.1: default features under `match` for `HttpsUrl` (section 4.9.3), feature `net` under the core's `uri` | Strict RFC 3986 and RFC 3987, the text kept as received, the host typed as IPv4, IPv6 or a registered name; no panic over 20,000 generated URIs. iri-string would serve too; fluent-uri's typed host tips it. |
| application/x-www-form-urlencoded | serde_urlencoded 0.7.1 behind the core's `uri`, to read the URI's query through the core's `QueryRead` and to write the forms through `FormBody::of` | The most used: axum, reqwest and actix-web read forms with it. It refuses a struct field given twice and accepts an unknown name's repeats, so the core's `Deserialize` refuses any name given twice (U4) and reads a parameter without a value as omitted. It decodes an escape that is no UTF-8 as U+FFFD, which each parameter the core reads refuses. Its serializer leaves `None` out and escapes as RFC 6749 Appendix B says. |
| CBOR (RFC 8949) | ciborium 0.2.2 behind the core's `cbor` for `Value` and its encoder; own code reads RFC 8949 §3's heads into `Value` (section 4.9.4) | The most used. Its `Value` keeps both entries of a repeated key; `cbor::decode` refuses a key twice at any depth, and bytes after the item. Its reader reads a bignum as the equal integer and `undefined` as null, and ciborium-ll accepts an indefinite-length chunk inside an indefinite-length string (§3.2.3) and merges the two-byte simple encoding below 32 (§3.3). |
| Media types (RFC 9110 §8.3.1) | own code: `MediaType::parse` | mime 0.3.17 refuses values RFC 9110 admits (OWS before `;`, HTAB in OWS, a quoted-pair, an empty parameter), its error names no rule, and it lowercases the text. |
| COSE (RFC 9052) | coset 0.4.2 behind the core's `cbor`, re-exported by its `cbor` module (section 4.9.4) | Refuses a repeated label within a header bucket; `cbor::cose::read_sign1` refuses one label in both buckets (RFC 9052 §3). |
| base64url (RFC 4648) | base64 0.23.1 (existing) | Already the core's; strict decoding without padding. |
| SHA-256 | sha2 0.11.1 (existing) | Already the core's. |
| KangarooTwelve (RFC 9861) | k12 0.5.1 (RustCrypto) behind the core's `k12` hash feature (section 4.9.1) | RFC 9861 §5's vectors hold 36 of 36; `k12.rs` and the crate agree on 1,992 of 1,992 digests. |
| UUID text (RFC 9562) | uuid 1.29.0 in siros-paso, beside its `RandomIds` module (section 4.9.2) | Sets §5.4's bits and writes §4's lowercase text; own code holds `RandomId` to that text alone. |

**Repeated member names** (`crates/dup-probe.out`, `crates/dup-probe-more.out`). R refused; L the
last kept; D accepted with the members dropped; A accepted otherwise (both kept, or a value the
crate leaves unreadable); — no such parser. Header: a compact JWS's protected header with `alg`
twice, `kid` twice / an unknown member twice, and one twice inside an unknown member. Claims: a
payload with `exp` twice, `aud` twice / an unknown member twice. JWK: `x` twice (`n` for
aliri_jose, whose EC keys need OpenSSL), `kid` twice / an unknown member twice. JWS JSON: a
member of the serialization twice / one name in both headers. Sizes: a wasm32-wasip1 probe in the
matcher's profile that parses a JWS and a JWK the core's way, then the crate's way, minus the
baseline probe's 98,802 bytes (`crates/wasm.out`, `crates/wasm-run2.out`).

| Crate | License; release | Header | Claims | JWK | JWS JSON | Bytes over the baseline |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| core `json` (the baseline) | the core's | R R / R R | R R / R | R | R / A: the JWS layer adds §7.2.1 | 0 |
| serde_json `Value` | MIT OR Apache-2.0 | L L / L L | — | — | — | — |
| jose-jws 0.1.2 | Apache-2.0 OR MIT; 2023-08-21 | R R / D D | — | jose-jwk's | R / A | +82,575, with jose-jwk |
| jose-jwk 0.1.2 | Apache-2.0 OR MIT; 2023-08-21 | — | — | R R / D | — | +58,379 |
| jsonwebtoken 11.1.0 | MIT; 2026-09-16 | R R / L L | `insecure_decode` L L / L; `decode` R R / L | A R / D | flattened R / — | +80,172 |
| jwt-compact 0.8.0 | Apache-2.0; 2023-10-12 | R R / L L | R L / L | R D / D | — | +68,315 |
| jsonwebkey 0.4.0 | MIT; 2025-12-05 | — | — | R R / D | — | +60,545 |
| josekit 0.10.3 | MIT OR Apache-2.0; 2025-05-20 | L L / L L | L L / L | L L / L | L / R | build fails: openssl-sys |
| biscuit 0.8.0 | MIT; 2026-04-05 | R R / L L | R R / L | — | — | +90,915 |
| jwt-simple 0.15.0 | ISC; 2026-09-25 | R R / D D | R R / L | — | — | +75,583 |
| picky 7.0.0-rc.29 | MIT OR Apache-2.0; a pre-release, 6.3.0 of 2021-05-27 the last stable | R R / L L | `no_check` L L / L | R R / D | — | +98,214 |
| compact_jwt 0.6.0 | MPL-2.0; 2026-08-25 | R R / D D | — | R R / D | — | +258,936 |
| jwt 0.16.0 | MIT; 2022-01-09 | R R / D D | L L / L | — | — | +41,213 |
| jwtk 0.5.0 | MIT; 2026-03-11 | R R / L L | R R / L | — | — | build fails: its default features pull tokio's network features |
| ssi-jws 0.5.0 | Apache-2.0; 2026-02-13 | R R / L L | — | ssi-jwk's | — | +89,894, with ssi-jwk |
| ssi-jwk 0.4.0 | Apache-2.0; 2026-02-03 | — | — | R R / D | — | with ssi-jws |
| aliri_jose 0.2.0 | MIT/Apache-2.0; 2020-10-23 | R R / A A | — | R R / D | — | build fails: ring 0.16 |

Pure Rust as probed: jose-jws, jose-jwk, jwt-compact, jsonwebkey, picky, compact_jwt (its TPM
feature off), jwt; jsonwebtoken with `rust_crypto`, jwt-simple with `pure-rust`, ssi-jws and
ssi-jwk with `secp256r1`. biscuit and aliri_jose link ring (C and assembly), josekit links
OpenSSL, and jwtk links aws-lc or OpenSSL.

CBOR maps (the same probes):

| Crate | License; release | A repeated key |
| :-- | :-- | :-- |
| ciborium 0.2.2 | Apache-2.0; 2024-01-24 | `Value`: both entries kept; a map type: L; a derived struct: R |
| minicbor 2.3.1 | BlueOak-1.0.0; 2026-10-18 | a map type: L; `map_iter`: both entries, the caller checks |
| cbor4ii 1.2.4 | MIT; 2026-10-19 | `Value`: both entries kept; a map type: L; a derived struct: R |
| coset 0.4.2 | Apache-2.0; 2026-03-02 | a label twice in one header bucket: R; one label in both buckets: A; a `CoseKey` member twice: R |
| dcbor 0.25.2 | BSD-2-Clause-Patent; 2026-03-16 | R at every level. It decodes dCBOR, a deterministic profile; whether mdoc issuers' encodings meet it is unread (ISO/IEC 18013-5 is paywalled). |

X.509 (`crates/x509-uri-probe.out`: a P-256 leaf, the leaf with one trailing byte, its outer
length in a non-minimal form, its 433 truncations, its 3,464 single-bit flips). A flipped bit
inside a value still yields valid DER, so the flips measure panics; the first two cases measure
strictness.

| Crate | License; release | Trailing byte | Non-minimal length | Truncations | Bit flips |
| :-- | :-- | :-- | :-- | :-- | :-- |
| x509-cert 0.3.0 (der 0.8.3) | Apache-2.0 OR MIT; 2026-07-09 | R | R | all R, no panic | no panic |
| x509-parser 0.18.1 | MIT OR Apache-2.0; 2026-02-05 | accepted, the rest returned | accepted | all R, no panic | no panic |
| rasn-pkix 0.30.0 | MIT OR Apache-2.0; 2026-11-02 | R | accepted | all R, no panic | no panic |
| x509-certificate 0.25.0 | MPL-2.0; 2025-08-17 | accepted | R | all R, no panic | no panic |
| picky 7.0.0-rc.29 | MIT OR Apache-2.0; a pre-release | accepted | accepted | all R, no panic | no panic |

Each is pure Rust except x509-certificate, which links ring. rustls-webpki 0.103.16 (ISC)
validates TLS server certificate paths, the trust evaluator's concern (R5280-U1); siros-x509
parses `x5c` alone. siros-x509 turns on the core's `signed`, outside the matcher. The CBOR crates above and
the URI and form crates below are pure Rust.

URIs (the same probe: eight valid URIs, eight malformed ones, 20,000 generated https URIs):

| Crate | License; release | Valid URIs kept as received | `%zz`, a space, `é` | `https:///r` | Port 99999 | Panics |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| fluent-uri 0.4.1 | MIT; 2025-11-04 | all | R R R | accepted, empty host | accepted (RFC 3986 §3.2.3: `*DIGIT`) | none |
| iri-string 0.7.14 | MIT OR Apache-2.0; 2026-07-26 | all | R R R | accepted, empty host | accepted | none |
| uriparse 0.6.4 | MIT; 2022-03-18 | three rewritten | R R R | accepted, empty host | R | none |
| url 2.5.8 (WHATWG) | MIT OR Apache-2.0; 2026-01-05 | two rewritten | kept, escaped, escaped | read as host `r` | R | none |
| oxiri 0.3.1 (IRI) | MIT OR Apache-2.0; 2026-07-25 | all | R R, `é` accepted | accepted, empty host | accepted | none |

Forms (`crates/form-probe.out`: eleven queries read into a struct of two optional strings,
§8.2's error members written, 20,000 generated queries; `crates/form-probe-meta.out`, of
2026-11-03). R refused.

| Crate | License; release | `%FF` | `a=1&a=2` | An unknown name twice | `a`, `a=` | `a[b]=1` | `None` written | Panics |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| serde_urlencoded 0.7.1 | MIT/Apache-2.0; 2022-01-17 | U+FFFD | R | accepted | `""`, `""` | the name `a[b]` | left out | none |
| serde_html_form 0.4.1 | MIT; 2026-06-30 | U+FFFD | R | accepted | `""`, `""` | the name `a[b]` | left out | none |
| serde_qs 1.1.3 | MIT/Apache-2.0; 2026-08-07 | R | the last kept | accepted | absent, `""` | nesting | a bare name | none |
| form_urlencoded 1.2.2 (the first two's parser) | MIT OR Apache-2.0; 2025-08-21 | U+FFFD | both pairs | both pairs | `""`, `""` | the name `a[b]` | — | none |

Each reads `+` as a space, keeps `%zz` as written, and writes the error members back as read.
serde_qs alone refuses invalid UTF-8, but it keeps the last of a repeated name, reads brackets as
nesting, which RFC 6749 Appendix B's format does not define, and writes `None` as a name without
a value. serde_urlencoded has 666,275,058 downloads, serde_qs 100,935,846 and serde_html_form
25,942,561; axum 0.8.9, reqwest 0.13.5 and actix-web 4.18.1 read forms with serde_urlencoded, and
axum-extra with serde_html_form, a fork that adds sequences. serde_urlencoded's repository is
active (last push 2024-08-13); its decoding and escaping are form_urlencoded's, which rust-url
maintains. Its `deserialize_map` hands the visitor the pairs without a check of its own, so
`QueryRead` stops at the first repetition (`crates/form-probe/src/query.rs`, the parse this
design builds, with each U rule's case). base64: base64 0.23.1 (MIT OR Apache-2.0), base64ct
1.8.3 (constant time) and data-encoding 2.11.1 all serve; base64 is the core's already.

**Newtypes over the picks.** `AuthorizationUri`, `RequestUri`, `ResponseUri` and `RedirectTarget`
over `fluent_uri::Uri`, `AuthorizationUri` with the parameters `QueryRead` reads through
serde_urlencoded; `FormBody` over the text serde_urlencoded's serializer writes from a form
struct; `ChainCertificate` and `X5c` over `x509_cert::Certificate` with the DER as received;
`LeafHash` over sha2's output; `VerificationKey` from spki's `SubjectPublicKeyInfoOwned`. Each
adds the rule the standard leaves to its user: `https`, a non-empty host, each name once, the
leaf first, an EC or EdDSA key.

**Own code.** JWS parsing, the JWT times, the SPKI-to-key step, `QueryRead`'s `Deserialize`,
`HttpsUrl`'s whitespace and host rules, `RandomId`'s text check, and the `cbor` module's key
equivalence, JSON conversions and bucket rule, for the reasons the pick table and section 4.9
give. `sigs/Cargo.toml` pins each new pick with `=`, and
`sigs/Cargo.lock` pins every version.

### 4.8 In-house implementations at `f718dc3`

| Code | Standard | Recommendation |
| :-- | :-- | :-- |
| siros-openid4vp `json.rs` | RFC 8259, unique member names at every level | Keep: the one parser surveyed that refuses a repeated name at every level; serde_json's `Value` keeps the last. |
| `base64`, `sha2`, `sha3`, `blake2` uses | RFC 4648, FIPS 180-4, FIPS 202, RFC 7693 | Keep: established crates already. |
| `k12.rs` | KangarooTwelve (RFC 9861) | Replaced in this change: k12 0.5.1 (section 4.9.1). |
| `sri.rs` | W3C Subresource Integrity | Keep: ssri 9.2.0 brings sha-1, xxhash and miette for one short parse. |
| `AgreeableKey`, `thumbprint` | RFC 7517, RFC 7638 | Keep over the `json` module: each JWK crate tested accepts a repeated member at some level. |
| `rows::values::HttpsUrl` | a WHATWG URL host (idna) | Replaced in this change: fluent-uri, with idna's Punycode for the host (section 4.9.3). |
| siros-mdoc `cose.rs`, `device_authentication.rs`, `presentation.rs` | CBOR and COSE stand-ins mirroring the oracle (Python repr, JSON `{"bstr"}`) | Replaced in this change: ISO/IEC 18013-5 CBOR and COSE through ciborium and coset (section 4.9.4). |
| `tests/hashes_and_handover.rs`, dev-dependency cbor4ii | CBOR | Replaced in this change: ciborium (section 4.9.4, commit 4). |
| `runtime::RandomId`'s UUID formatting | RFC 9562 | Replaced in this change: uuid 1.29.0 (section 4.9.2). |
| `text/markdown.rs` | PaSO's markdown subset | Keep: PaSO defines the subset, and a CommonMark crate accepts more. |

### 4.9 In-house implementations replaced in this change

Four in-house implementations become the crates sections 4.7 and 4.8 name, in six commits that land
before the flows commits. Each commit keeps every comparison the differentials make today. In
the mdoc presentation the bytes change by design; there the comparison reads the port's CBOR
into the model's JSON shape and compares text with text. `replace/sigs/` holds each replacement
as code beside wallet-rs `f718dc3`. It passes `cargo clippy --all-targets` under the core's deny
lints, and its tests run the gates below (`replace/gates.out`: every gate holds). Section 4.11's
features then put each crate behind its mechanism: k12 behind `k12`, ciborium and coset behind
`cbor`, sha3 and blake2 behind their hash features; uuid goes with `RandomId` to siros-paso, whose
`RandomIds` module alone writes one.

| # | Commit | Crate | Matcher build (`--no-default-features --features match`) |
| --: | :-- | :-- | :-- |
| 1 | siros-openid4vp: KT128 and KT256 are RustCrypto's k12 | k12 0.5.1, behind `resolve` | keccak, sha3, blake2 and 3 of their dependencies leave it. |
| 2 | siros-openid4vp: RandomId is a uuid `Uuid` | uuid 1.29.0, behind `resolve` | Unchanged. |
| 3 | siros-openid4vp: HttpsUrl is an IRI over fluent-uri | fluent-uri 0.4.1, under `match` | +4 crates, +19,732 B. |
| 4 | siros-openid4vp: the B.2.6.2 handover test encodes with ciborium | ciborium 0.2.2, a dev-dependency | Unchanged. |
| 5 | Each mdoc registration carries its issued IssuerSigned; the core reads CBOR | ciborium and coset, behind the core's `resolve` | Unchanged. |
| 6 | siros-mdoc presents ISO/IEC 18013-5 CBOR and COSE | the core's re-exports | Unchanged. |

#### 4.9.1 KangarooTwelve: RustCrypto's k12 (commit 1)

**Today.** `src/k12.rs` (97 lines) computes KT128 and KT256 with the empty customization string
over keccak 0.2.2's Keccak-p[1600, 12]. `HashAlgorithm::digest` calls it for `k12-256` and
`k12-512`. `tests/hashes_and_handover.rs` calls it for RFC 9861's two long-output vectors and as
the B.3.3.1 test's oracle. That is 7 lines in 2 files, beside `pub mod k12` and its doc line.

**Replacement.** `k12.rs` and `pub mod k12` go. The two arms become
`Kt128::digest_xof(data, &mut out)` into `[0u8; 32]` and `Kt256::digest_xof` into `[0u8; 64]`;
k12 re-exports digest 0.11's `ExtendableOutput`. `HashAlgorithm::digest`, `txhash::members` and
`HashesError` move behind `resolve`: phase 2 writes the hashes, and phase 1 parses the names and
picks the algorithm. k12 (`default-features = false`), sha3 and blake2 become optional
dependencies that `resolve` enables. The workspace's `keccak` entry becomes `k12`, whose keccak
0.2.2 the `[profile.dev.package.keccak]` override still optimizes; `[profile.dev.package.k12]`
joins it. Every digest stays byte-identical.

```rust
/// A hash algorithm of transaction data (B.3.3.1; `txhash::HashAlgorithm`, unchanged): an enum
/// of `sha-256`, its truncations and `k12-256`; `digest` moves behind `resolve`.
pub enum HashAlgorithm { /* the variants of f718dc3 */ }
/// Why no hash of the entries exists (B.3.3.1; `txhash::HashesError`, unchanged).
pub enum HashesError { NoCommonAlgorithm, MemberTwice(MemberTwice) }
```

**Comparisons.** The test file keeps its 8 RFC 9861 vectors through `HashAlgorithm::digest`, its
2 long-output vectors through `Kt128` and `Kt256` (k12 as a dev-dependency), and its B.3.3.1
oracle. The differentials compare the same `transaction_data_hashes`.

**Gates.** RFC 9861 §5's vectors, parsed from the RFC's text, hold 36 of 36: 18 KT128 and 18
KT256, with customization strings and long outputs. 20 of them run through the `k12-256` and
`k12-512` arms. Matched pair, f718dc3's `k12.rs` against the crate: 1,992 of 1,992 digests equal
over 332 message lengths (0 to 300; 8,192 × 1, 2, 3 and 8, each ± 3; 83,521; 100,000;
1,419,857) at 32, 64 and 200 bytes. k12, keccak, sha3 and blake2 stay out of the core's `match`
build (`cargo tree`).

#### 4.9.2 UUIDs: uuid (commit 2)

**Today.** `runtime::RandomId(String)`. `from_bytes` sets the version and variant bits and writes
the hexadecimal groups by hand. `parse(String)` checks the groups, lowercase hexadecimal, version
4 and the variant by hand. `as_str()` reads the text. RandomId appears on 13 lines in 4 files;
`as_str` on 3 lines in 2 files (PaSO's `jti`, construction.rs); `parse` on 2 lines in 1.

**Replacement.** `RandomId(uuid::Uuid)`, `Copy`. `from_bytes` is
`Builder::from_random_bytes(bytes).into_uuid()`, which sets RFC 9562 §5.4's bits. `Display`
writes `Uuid::hyphenated()` in lowercase (RFC 9562 §4). `parse(&str)` takes `Uuid::try_parse`,
then version 4 (`Version::Random`), the RFC variant (`Variant::RFC4122`), and the text equal to
`hyphenated().encode_lower(..)`. The last check is own code: uuid also reads capitals, braces,
URNs and the 32-digit form; construction.rs refuses capitals, and a `jti` compares as text (RFC
7519 §4.1.7). The 3 `as_str()` callers call `to_string()`. `NotRandomId` becomes an enum:
`Uuid { text, cause }`, `Version`, `Text`. uuid builds with `default-features = false`; the runtime
supplies the random bytes. uuid 1.29.0 declares Rust 1.89, so `workspace.package.rust-version`
rises from 1.86 to 1.89 (the pinned toolchain is 1.99.1). Every identifier stays byte-identical.

**Comparisons.** PaSO's `jti` in the PaSO and integration differentials compares the same text.

**Gates.** RFC 9562 Appendix A.3: bytes `919108F752D133205BACF847DB4148A8` give
`919108f7-52d1-4320-9bac-f847db4148a8`. construction.rs's 2 formatting vectors, its valid text
and its 5 invalid texts hold. Matched pairs: formatting equal on 100,000 of 100,000 16-byte
blocks; the TestRuntime's identifiers 1 to 10,000 equal the model's
`00000000-0000-4000-8000-{n:012d}`; parse verdicts equal on 1,874,000 texts (2,000 canonical texts
and each single-character change of them).

#### 4.9.3 https URLs: fluent-uri (commit 3)

**Today.** `rows::values::HttpsUrl { written: String, ascii: String }` (54 lines). `shaped`
mirrors the model's regex `^https://[^\s/?#]+[^\s]*$`. `parse -> Option<Self>` cuts the authority
by hand (`find(['/', '?', '#'])`, `rfind('@')`, `rfind(':')`) and writes a host beyond ASCII in
A-labels with `idna::domain_to_ascii` (UTS #46). `parse` is called on 18 lines in 14 files and
`shaped` on 4 lines in 4 files; HttpsUrl appears on 49 lines in 21 files.

**Replacement.** `HttpsUrl { written: Iri<String>, ascii: Iri<String> }` keeps its fields
private behind `written()` and `ascii()`. `parse(&str) -> Result<Self, NotHttpsUrl>` reads:

1. Whitespace (`python_space`) is refused. Own rule: RFC 3987's `ucschar` admits U+00A0 and the
   other spaces, and PaSO View §3 shows the URL whole.
2. `Iri::parse` reads RFC 3987.
3. The scheme equals `https` in fluent-uri's comparison, which ignores case (RFC 3986 §3.1).
4. The authority's host is non-empty (RFC 9110 §4.2.2).
5. A registered name with a character beyond ASCII splits on `.` (U+002E). A label beyond ASCII
   becomes `xn--` followed by `idna::punycode::encode_str` of the label lowercased by
   `char::to_lowercase`, with Cherokee in capitals, as UTS #46's mapping table writes it; an ASCII
   label is lowercased by `to_ascii_lowercase`. fluent-uri's
   `Builder` rebuilds the IRI around that host from the parsed userinfo, port, path, query and
   fragment. Any other host keeps the text as written.

`ascii()` is what the wallet shows and the caller fetches, in every build, so matcher, wallet and
auditor show the same text and the records' `shown` digests agree (gate I31). PaSO View §3 asks
the wallet to show the full URL and mitigate homograph confusion with the punycode form. Two texts
with one ASCII form are one URL:
equality and hash read `ascii`, `Resource::distinct` asks one GET for them, and `with_resource`,
`image::resolve`, `Ts12Profile::resolution` and `FailedImage::url` key on `ascii()`.
`NotCompatible::Image` names the first 60 characters of `ascii()` once the text parses.
`HttpsUrl`'s `Display` writes `ascii()`, so an argument carries that form, as in
`ComposeError::Unfetched`. `written()` feeds only what the render engine parses again: a TS12
payload's `payee.logo` and `payee.website`, and the URL `image::resolve` reads.

`parse` holds no UTS #46 rule, so a host UTS #46 would refuse is a URL in phase 1. A PaSO `url`
value, a TS12 `payee.website` and `payee.logo` and a QES document link parse and show its Punycode.
What phase 2 fetches (a PaSO image, a TS12 logo, a QES document with a checksum) reaches the
caller's GET: the fetch fails, the caller answers `Fetch::Unfetched`, and phase 2 takes its
failed-fetch path. A `url` value, a `payee.website` and a QES link without a checksum take no fetch:
the wallet shows a link that leads nowhere, as it does for a host DNS does not resolve. A QES link
faults in phase 1 on `LabelOverflow` and `NotRegName` alone.

Known limits; the wallet shows and fetches each form below:

- A host not in NFC or using compatibility characters shows and fetches the Punycode of what was
  written, which still reads `xn--`.
- U+3002 stays inside a label, which splits on U+002E alone: `https://example。com/` gives
  `xn--examplecom-th3i`, and UTS #46 gives `example.com`.
- U+00AD stays: `a\u{ad}b` gives `xn--ab-5da`, and UTS #46 gives `ab`.
- U+212A lowercases to ASCII `k` inside a label beyond ASCII, which writes `xn--k-`.

`NotHttpsUrl` is `Iri(ParseError)`, `Whitespace`, `Scheme`, `Host`, `LabelOverflow`, `NotRegName`
or `Rebuilt(BuildError)`. `encode_str` answers `None` when a label's delta overflows 32 bits
(RFC 3492 §6.4): `LabelOverflow`. A label past DNS's 63 octets below that overflow builds, and its
fetch fails. `NotRegName` is `EStr::<IRegName>::new` refusing the host's ASCII form. `parse`
replaces `shaped(text) -> bool`, and `RemoteImage` holds an `HttpsUrl`.
`rows` re-exports `NotHttpsUrl`. The 13 `.expect(..)` callers compile as they are. The 4
Option-shaped uses become `.map_err(|_| bad("not an https URL"))`, which keeps the text the
differential compares; `.ok().and_then(fetch)` twice; and `.ok()` in the integration port. The 3 field reads call the accessors. fluent-uri enters with its default
features; the flows commits add its `net` feature behind `uri`.

**Outputs that change.** Of the 54 URL literals in wallet-rs and the model's generators, 53 keep
their verdict and ASCII text. `https://\u{fffd}.example/l.png` (siros-paso
`tests/responses.rs:882`) moves: U+FFFD lies outside `ucschar`, so the text is no IRI. That
test's case, an https image whose fetch fails, moves to `https://\u{301}x.example/l.png`, a label
that UTS #46 refuses for starting with a combining mark. Of 20,000 generated URLs,
13,128 agree. Each of the others falls in a class its tokens name:

| Class | URLs | f718dc3 | fluent-uri |
| :-- | --: | :-- | :-- |
| a character or escape RFC 3987 refuses: `\|`, `{`, `<`, `%zz`, a second `#`, U+FFFD | 5,698 | reads it | refuses it |
| an empty host after a userinfo or a port (RFC 9110 §4.2.2) | 132 | reads it | refuses it |
| `HTTPS` in capitals (RFC 3986 §3.1) | 363 | refuses it | reads it |
| a host UTS #46 refuses | 679 | writes no ASCII form | writes its Punycode |

**Comparisons.** Every URL the generators write is among the 53 literals that agree: `REMOTE`,
`DOCS`, `LOGOS`, the test format's and PaSO's `https://bücher.example/x`, the QES documents. The
entry views, the PaSO and QES rows and the fetch findings compare the same values.

**Gates.** The model's answers (check_core.py lines 39 and 40) and text_and_values.rs's 4 URL
cases hold. `https://bücher.example/x?q=1` shows `https://xn--bcher-kva.example/x?q=1`;
`https://Ü@bücher.example/` shows `https://Ü@xn--bcher-kva.example/`; `http://shop.example`,
`https://shop.example/a b` and `https://` are refused. The matcher gate is a wasm32-wasip1
release pair in the matcher's profile (opt-level `s`, fat LTO, one codegen unit, panic abort,
strip) running phase 1's URL path: `Value::format` of a `url` value and `HttpsUrl::parse`; I10 measures the matcher's build again. It
measures 297,235 B at f718dc3 and 316,967 B with fluent-uri, +19,732 B, equal over two clean
builds. fluent-uri's builder accounts for 2,228 B of it. A variant that splices the ASCII host
at fluent-uri's host span and reads the text back with `Iri::parse` measures 314,739 B, and it
equals the builder variant on 20,054 of 20,054 URLs. `cargo tree` adds borrow-or-share 0.2.4,
fluent-uri 0.4.1, ref-cast 1.0.27 and ref-cast-impl 1.0.27 to the `match` build.

#### 4.9.4 mdoc CBOR and COSE: ciborium and coset (commits 4 to 6)

**Today.** siros-mdoc writes the model's stand-ins. `device_authentication.rs` (211 lines)
authenticates the UTF-8 of Python's `repr` of `("DeviceAuthentication", (None, None,
("OpenID4VPDCAPIHandover", (origin, nonce, thumbprint))), docType, DeviceNameSpaces)`, with the
handover information unhashed. `presentation.rs` (254 lines) writes the DeviceResponse as JSON,
a byte string as `{"bstr": hex}` and `deviceAuth` as the runtime's text. A `MemberValue::Cbor`
item is the runtime stand-in's JSON text. `cose.rs` (119 lines) holds phase 1's identifiers as
integers: Table 22's curves, B.2.2 Table 2's MAC identifiers, RFC 9864's fully-specified
algorithms. The TestRuntime's `sign` and `mac` return text, and its `encrypt_cose` writes JSON.
The core's handover test builds B.2.6.2's bytes with cbor4ii: 3 import lines, 15 encoder
lines, and a dev-dependency in 2 manifests.

**The core.** A `cbor` module behind `resolve` lands in commit 5 with its tests; siros-mdoc calls
it from commit 6. ciborium 0.2.2 and coset 0.4.2 become optional dependencies that `resolve`
enables:

- `decode(&[u8]) -> Result<Value, CborError>` reads one data item, with nothing after it and
  each map's keys distinct at every depth; its check stays private to it and to
  `DeviceNameSpacesBytes::of`, which refuses the map it writes when a key repeats. Keys compare as RFC 8949 §5.6.1 equates them. A key's
  form is its encoding with -0.0 as 0.0, a NaN without its sign, and each map's pairs in key-form
  order; equal forms make one key. Own code: ciborium's `Value` keeps both entries of a repeated
  key, and ciborium leaves bytes after the item unread. The reader is own code too (`cbor/read.rs`):
  it reads RFC 8949 §3's heads into ciborium's `Value`, because ciborium's own reader takes a bignum
  `2(h'01')` for the integer 1 and `undefined` for null (section 4.7). It refuses `undefined` and
  the unassigned simple values, which `Value` cannot hold (`CborError::Simple`), and nesting
  deeper than 256; its syntax errors are `Truncated`, `Malformed(offset)`, `Utf8(offset)`,
  `Depth` and `Simple(n)`.
- `encode_deterministic`, RFC 8949 §4.2.1's core deterministic encoding, lands with its first
  caller (decision 9).
- `encode` and `key_form`. `of_json(&Node)` follows RFC 8949 §6.2 and reads an integer as
  Python's `json` does, through the core's `Number::is_integer`. `to_json(&Value) -> Node`
  follows RFC 8949 §6.1: a byte string in base64url, tags 21 to 23 by their hints, bignums as
  text, a non-finite double as null. Own code: the conversions run between ciborium's `Value`
  and the core's order-keeping `Node`, and serde's derive writes a byte string as an array.
- `cose::read_sign1(Value)` reads an untagged COSE_Sign1. It first applies RFC 9052 §3's rule
  that a label sits in one bucket alone, a check private to it: the protected bytes are decoded
  with distinct keys, and labels compare by key form. coset then refuses a label twice in one bucket. The module
  re-exports `coset` and ciborium's `Value` for plug-ins' phase-2 code, which follows the core's
  `resolve`.

The runtime contract changes with the encoding (commit 6). `Signature` and `Mac` carry the raw
bytes the module made, which COSE embeds (RFC 9053 §2.1): their fields are private, `new` is the
module's, and `into_bytes` the reader's. `Runtime::mac` gains `transcript:
&SessionTranscriptBytes`, the input whose SHA-256 ISO/IEC 18013-5 §9.1.3.5 takes as EMacKey's
HKDF salt; only `SessionTranscript::tagged_bytes` makes it. `encrypt_cose` returns a
`SealedCose`, which `SealedCose::parse` makes from one CBOR item tagged 96. siros-sdjwt's KB-JWT
stand-in writes the signature's bytes as UTF-8 text and faults on other bytes.

```rust
/// A member value a profile writes (`plugins::MemberValue`); `Cbor` holds an `Item`.
pub enum MemberValue { Text(String), Bytes(Vec<u8>), Json(JsonText), Cbor(Item) }
/// One CBOR data item in its encoding, its keys distinct at every depth; only `Item::parse`,
/// through `cbor::decode`, makes one.
pub struct Item(Vec<u8>);
```

**siros-mdoc (commit 6, phase 2).** Phase 1's code stays as it is.

- `transcript.rs`: `SessionTranscript::of(&Handover)` is `[null, null, Handover]`. The handover
  is B.2.6.1's `["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, thumbprint or null,
  responseUri]))]` or B.2.6.2's `["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin, nonce,
  thumbprint or null]))]`. A `SessionTranscript` holds its encoding, which `as_bytes` returns;
  `tagged_bytes` writes SessionTranscriptBytes, `#6.24(bstr .cbor SessionTranscript)`.
  `decode(Vec<u8>)` keeps a transcript a Verifier holds: one CBOR item, an array of three
  (ISO/IEC 18013-5 §9.1.5.1), else `TranscriptError` (`Cbor`, `Items`; domain
  `mdoc.transcript`).
- `device_authentication.rs`: `DeviceNameSpacesBytes` is `#6.24` of the name-space map, its bytes
  kept as written. `device_authentication_bytes` is
  `#6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes])`,
  the transcript's encoding written into the array as it is held.
  A member becomes a text string, a byte string, `of_json` of its JSON, or `decode` of its CBOR.
  `DeviceNameSpacesBytes::of` refuses a name space, an element or a key at any depth given twice.
  The DocType is the MSO's (`IssuerSigned::doctype`).
- `cose.rs` gains DeviceSignature: a COSE_Sign1 with `{1: alg}` protected, an empty unprotected
  header and a nil payload, signed through coset's `try_create_detached_signature`. The alg is an
  `iana::Algorithm`, which `DeviceAuth::Signature` holds: the view's integer is read into IANA's
  registry where the device authentication is chosen, and another integer faults there. It also gains
  DeviceMac: a COSE_Mac0 with `{1: 5}` (HMAC 256/256), a nil payload, and the tag over coset's
  `mac_structure_data`, because coset's builder MACs a set payload alone.
- `issuer_signed.rs`: `IssuerSigned::read` reads the credential's `mso_mdoc` document,
  `{? "nameSpaces": {NameSpace => [#6.24(IssuerSignedItem)]}, "issuerAuth": COSE_Sign1}`. Each
  item holds `digestID`, `random`, `elementIdentifier` and `elementValue` once, an identifier
  appears once per name space, and an unknown member is refused. `disclose` returns the
  disclosed items as issued, because the MSO digests their bytes. Each item's value, read by
  RFC 8949 §6.1, must equal the view's; otherwise it faults, since the consent showed another value.
  `nameSpaces` is left out when no element is disclosed, and IssuerAuth goes out as stored
  (coset keeps the protected bytes).
- `presentation.rs`: the DeviceResponse `{"version": "1.0", "documents": [{"docType",
  "issuerSigned", "deviceSigned": {"nameSpaces", "deviceAuth": {"deviceSignature" or
  "deviceMac"}}}], "status": 0}`, `encode`d and written in base64url without padding as a JSON
  string (B.2.5). `DeviceAuth::choose` stays.

Each mdoc registration carries its issued IssuerSigned as the document under the key `mso_mdoc`
(commit 5). Phase 2 alone reads it.

**siros-testkit.** Commit 5 adds `issuer.rs`, the issuer stand-in. `issue(view)` writes one
IssuerSignedItem per view value: a running `digestID`, 16 bytes of `random` from SHA-256 of the
docType, name space and element, and the value by `of_json`. Its IssuerAuth holds
`{1: issuer_alg}` protected, an x5chain unprotected, and `#6.24(MSO)` with SHA-256 value digests
of the tagged items, the device key and the validity, signed by a stand-in. `Held.documents`
holds bytes, and `Held::with_issued` adds the issued document. The oracle's
`wallet(credentials, &issued)` and the directed presentation's credential carry it. Commit 6
changes the runtime stand-ins. `sign` returns `sig:{credential}:{digest}` as bytes. `mac`
returns `mac:{credential}:{kid}:{digest}` as bytes, the digest over SessionTranscriptBytes then
the data, so a wrong transcript shows. `encrypt_cose` writes a tagged COSE_Encrypt whose
ciphertext is the plaintext: A128GCM, A192GCM or A256GCM (1, 2, 3) protected, and one recipient
with ECDH-ES (-25) or a key wrap (-29 to -31) protected and the `kid` unprotected. COSE's content
encryptions are AES-GCM, AES-CCM and ChaCha20/Poly1305 (RFC 9053 §4), so the AES-CBC-HMAC ones
fault. Commit 6 also adds `reading.rs`.

**The reading.** `model_shape(presentation, rebuild) -> Node` decodes the base64url
DeviceResponse with the core's `decode`. It writes the model's `as_json` shape in the model's
member order: a byte string as `{"bstr": hex}`, an embedded item as its content, the
IssuerSignedItems as `{elementIdentifier: elementValue}`, a tagged COSE_Encrypt as the model's
`{"COSE_Encrypt": {"protected": {"alg", "enc", "kid"}, "ciphertext"}}`, and DeviceSignature or
DeviceMac as the stand-in's text. It refuses any other member or shape, a payload, a non-empty
unprotected header, a DeviceMac `alg` other than HMAC 256/256, and an IssuerAuth without its
payload. `rebuild` carries the model's handover and the view's `device_alg`. With it, the reading
refuses a DeviceSignature `alg` other than `device_alg`, and it rebuilds DeviceAuthentication from
the model's Origin, nonce and thumbprint through a transcript it writes itself, the docType, and the
DeviceNameSpacesBytes as received. The stand-in's digest must cover that rebuild, and then reads
`covered`. `covered(model)` turns the model's digest into `covered` too: the model's covers Python's
`repr` and the port's covers CBOR, so each compares by what it covers. Every entry of the model's
DeviceAuthentication is thus compared: the transcript and the docType through the rebuild, the
device name spaces as values.

**Exporters.** `export_formats.py` and `export_dressed.py` wrap the model's `respond.Session`
and record each response's handover: the Origin, the nonce, the thumbprint in hexadecimal or
null. The model stays unedited. The directed presentations already export their thumbprint, and
their Origin and nonce are constants on both sides.

**Comparisons that change form.** Each count stays the baseline's (seeds 1, 2 and 3,
`replace/baseline.md`), and each kind still ends in a text comparison.

| Differential: kind | Count per seed | Today | Then |
| :-- | :-- | :-- | :-- |
| siros-mdoc: phase 2 outcomes | 2,087 / 2,583 / 2,919 | vp_token and data texts | each mso_mdoc presentation read with `rebuild` and the model's `covered`; data's JWE stand-in plaintext read alike; both written by `json_compact` |
| siros-mdoc: directed presentations with members | 400 / 400 / 400 | presentation texts | read with `rebuild` (Origin, nonce, the exported thumbprint) against `covered` |
| siros-mdoc: presentations, mdoc deviceSignature / deviceMac | 640/7, 1,312/53, 2,853/3 | markers in the port's text | the same markers in the read text |
| siros-mdoc: directed deviceSignature / deviceMac | 375/25, 376/24, 377/23 | as above | as above |
| siros-integration: phase 2 outcomes | 7,954 / 9,362 / 12,295 | vp_token and data texts | as siros-mdoc's |
| siros-integration: response members per presentation | 4,831 / 7,144 / 17,510 | the port's JSON device name spaces | the read device name spaces; the model's `members_of` as today |
| siros-paso: responses, risk signals sealed for an mdoc among them | 64 / 138 / 216 | `{"json": the stand-in's text}` | the COSE_Encrypt read into the stand-in dict, written by `json_compact` |

**The `amr` signal.** The frozen model reports `amr` unavailable, and siros-paso writes
Registry §2.8's form. The oracle's `amr_reported` rewrites each of the model's `amr` envelopes
to status `ok` with `["pin", "hwk"]`, the test platform's authentication, in the outcome's JSON,
compact, hexadecimal and base64url forms. In an outcome it rewrites, the model's Key Binding JWT
digest covers the payload before the rewrite: the port's signature is checked against
`TestHaip`'s stand-in over the signing input the presentation holds, and both sides then read
`sig:<credential>:covered`. Every other outcome compares both digests as written.

siros-openid4vp, siros-sdjwt, siros-zkp-req and siros-qes compare as today; QES's mdoc
`qesApproval` is a byte-string member, `{"bstr": hex}` on both sides. The dressed property run
keeps its tallies (12,322 mdoc deviceSignature, 96 deviceMac, 22 risk signals encrypted), its
checks reading mdoc presentations through `model_shape`.

**Existing tests.**

- siros-mdoc `tests/presentation.rs`. The 6 device-authentication cases read the mode and the
  MAC's key from `model_shape`. The repr test becomes the KA2 to KA5 test of `SessionTranscript`
  and a presentation read with `rebuild`. The 200 seeded documents compare the read name spaces
  with the same expected values. The `{"bstr": "xyz"}` refusal leaves, since JSON members convert
  as JSON. The real encoding's refusals join: a CBOR member with a key twice, an alg outside
  IANA's registry, a credential without its `mso_mdoc` document, an element the issuer left out,
  an issued value other than the view's.
- siros-openid4vp `tests/hashes_and_handover.rs`: ciborium builds the same 3 B.2.6.2 hex values
  (commit 4).
- siros-integration `end_to_end.rs` (PaSO A.3's card, CSC §7.3's attestation) and the property
  run: their helpers read mdoc presentations through `model_shape`, and their assertions stay.
  The 2 mdoc fixtures and the generator's mdoc credentials call `with_issued`.
- siros-paso `tests/properties/checks.rs`: `opened` reads the COSE_Encrypt through the reading.
- siros-openid4vp `tests/phase_two.rs`: the wrapper runtime follows the trait.

**Gates.**

| Gate | Source | Result |
| :-- | :-- | :-- |
| KA1 through `Thumbprint::of`; KA2, KA3, KA4 through `SessionTranscript::of(Handover::Redirect)`; KA5 through `Handover::DcApi` | OpenID4VP B.2.6.1, B.2.6.2, RFC 7638 | 5 of 5 |
| Sig_structure and MAC_structure handed to the runtime equal ones built by hand | RFC 9052 §4.4, §6.3 | 2 of 2 |
| A key twice: at the top, nested, in an array, in a tag, in an indefinite map and inside a key; 0.0 and -0.0 one key; 1 and 1.0, text and bytes, a tag and its content distinct; a byte after the item; a cut item; 300 nested arrays | RFC 8949 §5.6.1 | 18 of 18 |
| COSE buckets: a label in both (coset accepts it, `read_sign1` refuses it); a label twice in one bucket refused; disjoint and empty buckets read | RFC 9052 §3 | 7 of 7 |
| JSON to CBOR and back over export_formats.py's `json_value` grammar: decode of encode is identity, the read text equals the JSON's compact text, RFC 8949 §6.1 inverts §6.2 | RFC 8949 §6 | 10,000 of 10,000 |
| Presented items digest to the MSO's value digests; 5 IssuerSigned refusals | the issuer stand-in | 3 of 3; 5 of 5 |
| The reading against the frozen model: Python runs `fmt_mdoc.present` on 4 cases (no member; text, bytes, JSON and COSE_Encrypt members; a MAC on P-256; P-384 with doubles and control characters), compared as text with the designed presentation after `covered`; a wrong nonce refused | wallet-ref | 4 of 4; 4 of 4 |
| The matcher with siros-mdoc registered, matching one credential (a wasm32-wasip1 pair) | `replace/wasm/` | Behind the core's `resolve`, ciborium and coset stay out of the `match` build (`cargo tree`). As siros-mdoc's plain dependency, coset compiles 8 more crates and adds −16 B (326,002 B against 325,986 B). |
| Every differential after commits 5 and 6 | the table above | each count equal to the baseline, 0 mismatches |

**What rests on ISO/IEC 18013-5.** The handover and the transcript rest on OpenID4VP B.2.6's
CDDL and hex (KA2 to KA5). The COSE layouts, detached payloads, the structures the runtime signs
and the header buckets rest on RFC 9052; the algorithm identifiers rest on RFC 9053, IANA's
registry through coset, and B.2.2 Table 2. The paywalled part covers the DeviceResponse,
Document, IssuerSigned, DeviceSigned and DeviceAuth member names, the `#6.24` wrappings,
IssuerSignedItem's four members, the MSO's members, EMacKey's salt, IssuerAuth as an untagged
COSE_Sign1, and the refusal of unknown members. The design reads them from OpenID4VP B.2.5 and
B.2.6, from the frozen model's member names, and from open-source mdoc readers. The reading and
siros-mdoc encode one reading of them, so their gates catch a regression and miss a misreading.
ISO/IEC 18013-5 Annex D's DeviceResponse, as an open-source library reproduces it, would serve as
an independent known answer; locating one remains open after one search.

#### 4.9.5 Change inventory

Counts from `replace/inventory/inventory.sh` on the worktree at `f718dc3`
(`replace/inventory/inventory.out` lists every matched line). A line can hold one call; a file
several.

| Changes | Lines | Files |
| :-- | --: | --: |
| `siros_openid4vp::k12::{kt128, kt256}` uses (k12.rs, 97 lines, removed) → `Kt128::digest_xof`, `Kt256::digest_xof` | 7 | 2 |
| `pub mod k12` and its doc mention removed | 2 | 1 |
| `HashAlgorithm::digest`, `txhash::members`, `HashesError` behind `resolve` | 3 | 1 |
| Manifests: workspace `keccak` → `k12`, `[profile.dev.package.k12]` added; the core's sha3 and blake2 optional, `keccak` → optional `k12`, `resolve` enabling them, k12 as a dev-dependency | 8 | 2 |
| `RandomId(String)` → `RandomId(Uuid)`: `as_str()` callers → `to_string()` | 3 | 2 |
| `RandomId::parse(String)` → `parse(&str)` | 2 | 1 |
| `NotRandomId` struct → enum | 3 | 1 |
| `rust-version` 1.86 → 1.89; uuid in the workspace and, optional behind `resolve`, in the core | 4 | 2 |
| `HttpsUrl::parse` → `Result<_, NotHttpsUrl>`: the `.expect(..)` callers compile as they are | 13 | 10 |
| Option-shaped `HttpsUrl::parse` uses rewritten (`.map_err`, `.ok()`) | 4 | 4 |
| `HttpsUrl`'s fields → `written()`, `ascii()` | 3 | 3 |
| The U+FFFD fixture → `https://\u{301}x.example/l.png` | 1 | 1 |
| `rows` re-exports `NotHttpsUrl`; fluent-uri in the workspace and the core | 3 | 3 |
| cbor4ii → ciborium: the handover test's 3 imports and 15 encoder lines, and 2 manifest lines | 20 | 3 |
| `Held::new` of an mso_mdoc credential that reaches phase 2 → `.with_issued()?`; the generator's `Held::new(.., format, ..)` (matching.rs's 3 fixtures stay in phase 1) | 4 | 3 |
| `Held` document writes: `String` → bytes | 7 | 4 |
| The oracle's `wallet` reader (its `Credential::new`) and its 2 callers take the issued documents; the directed presentation's `Credential::new` carries one | 4 | 3 |
| `Runtime::mac` gains `SessionTranscriptBytes`: the trait and its impls; `.mac(` calls | 5 | 4 |
| `Signature` and `Mac` carry bytes: definitions, constructions, returns, `.0` reads | 13 | 5 |
| `encrypt_cose`: the TestRuntime writes a tagged COSE_Encrypt; the trait, impls and calls keep their signatures | 5 | 4 |
| Test and harness lines reading the JSON stand-in → `reading::model_shape` | 42 | 7 |
| `MemberValue::Cbor` uses that change: siros-mdoc decodes the item; PaSO's differential output and checks read it; the oracle builds a COSE_Encrypt; siros-mdoc's test writes and reads CBOR (of 12 uses in 11 files) | 6 | 5 |
| `kinds()` calls count in the read text | 2 | 1 |
| Exporters' respond recorders record the handover | 2 | 2 |

By crate:

| Area | Changes |
| :-- | :-- |
| siros-openid4vp | `k12.rs` removed; `txhash.rs` (phase-2 items behind `resolve`); `runtime.rs` (`RandomId` over `Uuid`, `NotRandomId`, `Signature` and `Mac` bytes, `mac`'s transcript); `rows/values.rs` (`HttpsUrl` over fluent-uri, 54 lines replaced) and `rows/mod.rs`; new `cbor.rs` with `cose` (about 270 lines in `replace/sigs/src/cbor.rs`); `lib.rs`; `Cargo.toml`. Tests: `hashes_and_handover.rs`, `construction.rs`, `phase_two.rs`. |
| siros-mdoc | New `transcript.rs`, `issuer_signed.rs`; `device_authentication.rs` (211 lines) and `presentation.rs` (254 lines) rewritten; `cose.rs` gains the phase-2 builders; `Cargo.toml` (base64, sha2, thiserror, all in the core's graph already); `tests/presentation.rs`. |
| siros-sdjwt | `presentation.rs`: the signature's text. |
| siros-paso | `respond.rs` (`jti`), `phase2.rs`, `lib.rs`; tests `responses.rs`, `properties/checks.rs`, `differential/outputs.rs`. |
| siros-qes | `lib.rs` (`.ok()`). |
| siros-testkit | `runtime.rs` (sign, mac, encrypt_cose), `fixtures.rs` (binary documents, `with_issued`), `oracle/inputs.rs`, `oracle/mod.rs`; new `issuer.rs`, `reading.rs`. |
| siros-integration | Tests: `differential/port.rs` and `main.rs`, `end_to_end.rs`, `properties/generate.rs` and `response.rs`. |
| oracle | `export_formats.py`, `export_dressed.py`: the handover recorded. |
| Workspace | `Cargo.toml`: `rust-version`, k12, uuid, fluent-uri, ciborium, coset in; keccak, cbor4ii out. |

### 4.10 The WE BUILD profile

Decision 12 adds WE BUILD's conformance specifications on top of HAIP's width: CS-02
(presentation), CS-07 (the DC API), CS-12 (SCA for payments, a profile of TS12) and CS-13
(intermediaries), at `b63c25a`. Section 4.2 holds the core's part; this section holds the rest.

#### 4.10.1 The core's part

| Clause | Addition | Where |
| :-- | :-- | :-- |
| CS-12 §7.3 item 9; §5.1, §5.10 | `request_uri_method` `post`: `wallet_metadata` with a fresh key; a JWE Request Object | `RequestPost` and `EncryptedRequests` registered, `Fetch`, `WalletMetadata`, `CompactJwe`, the `RequestDecryption` module; U11 |
| CS-02 §8.2; CS-02 §8.3, §6.1.7 | A Request Object holds `exp` and `aud`; the Verifier's error answer shown | siros-webuild's `Cs02Claims` (an `ObjectRule`, A14) and `Cs02ErrorAnswer` (an `AnswerReader`), through the core's extension points |
| CS-02 §7.1 item 6; CS-13 §7.2 | `verifier_info` and the `dcql_query` handed to the trust service | `ClientClaim` (reading 22) |
| CS-02 §7.1; CS-07 WU-DC-01; CS-12 §7.3 item 3 | The signed DC API protocols alone | `DcApiProtocols`; U1 |
| CS-12 §5 item 4, §7.3 item 8; TS12 §3.6 | The End-User authentication a profile needs | `AuthenticationNeed`, `Profile::authentication`, `Outcome::AuthenticationTooWeak` |
| CS-12 §8.1; B.3.5 | `vct_values` through the `extends` chain | siros-sdjwt's `types` (reading 26) |

#### 4.10.2 The TS12 profile (siros-ts12)

The owner, on 2026-11-02: "we add the profile in addition to paso. i expect it to be fully webuild
scenario compatible, but not implementing the stupid stuff like the non standard integrity
claims, nor the jsonschema, i expect you to adapt the ts12 system through the paso lens on the
badly defined/underdefined parts so we have a shallow compatibility implementation that uses paso
behavior internally", then: "undefined parts are not handled, like extend of the transaction data
types".

siros-ts12 is a `Profile` under `urn:eudi:sca:`, beside siros-paso under `urn:paso:sca:`. It reads
TS12's wire and writes TS12's Key Binding JWT claims; siros-paso's engine does the rest
(section 4.10.3). Three rules settle each TS12 clause:

- A clause TS12 defines exactly: TS12's behaviour.
- A clause TS12 leaves loose or contradicts: PaSO's rule.
- A mechanism TS12 does not define: the profile does not support it.

It implements neither JSON Schema nor TS12 §4.1.2's bracket-path integrity claims. It serves the
two types of CS-12 §7.1 item 1, `urn:eudi:sca:payment:1` and
`urn:eudi:sca:login_risk_transaction:1`, over SD-JWT VC credentials (TS12 §1.2).

**Registration.** At issuance the caller fetches what TS12 §4.1.1 has the wallet retrieve: the
credential's type metadata, and the documents its `claims_uri` and `ui_labels_uri` name.
`Ts12Document::compose` writes the registration document `ts12` from the credential's own type
metadata alone: its `category`, and its `transaction_data_types` with each `*_uri` member replaced
by the document fetched. TS12 defines no inheritance for either member, so a type that `extends`
another contributes its own alone. Nothing is fetched at presentation (PaSO Proof Metadata §5).

**Phase 1** (`bind`), for the request's one TS12 entry and a credential:

1. The credential's `ts12` document.
2. Its `category` is `urn:eu:europa:ec:eudi:sua:sca` (TS12 §3, §3.2 step 1). A configured
   attestation type is among the credential's `types` (reading 26); the WE BUILD build
   configures the three base types (CS-12 §7.1 item 2).
3. The entry's type is a key of `transaction_data_types` (§3.2 step 2), whose `schema` or
   `schema_uri` names the same built-in type (CS-12 §7.2; TS12 §2.3's example writes it in
   `schema`). Any other schema leaves the type unsupported for the credential.
4. `ui_labels` holds `affirmative_action_label` (§3.3.3: REQUIRED; §3.3.1: cease without it).
   A payment's `amount` and `payee.name`, and an action's `action`, hold claim metadata with a
   `display` array (§3.3.1: cease without the labels).
5. The payload parses into the type's typed payload (the field tables below).
6. The translation: the payload's values into PaSO's value forms, the claims metadata and UI
   labels into PaSO's metadata under the display rules below. siros-paso's engine renders with
   `Family::Payment` for a payment and `Family::View` for an action, under TS12's label limits.
7. `siros_paso::bound` gives the `Bound`: the rows, the payment header, the title, the actions,
   the hint.

A failure at steps 1 to 4 leaves the type unsupported for the credential, at 5 and 6 the entry
not compatible; a locale failure excludes the credential (View §4). The matcher then offers no
candidate, and phase 2's `NoCandidate` names the reason the wallet shows the Holder (CS-12 §8.1).

**Request rules** (`refusals`):

| Rule | Detects | Code | Source |
| :-- | :-- | :-- | :-- |
| T1 | An entry under `urn:eudi:sca:` without `transaction_data_hashes_alg`, or without a `payload` object | `invalid_transaction_data` | TS12 §4.2; §8.5 |
| T2 | A second entry under `urn:eudi:sca:` | `invalid_transaction_data` | CS-12 §8.1; TS12 defines no outcome for two |
| T3 | `credential_ids` holding more than one id | `invalid_transaction_data` | CS-12 §8.1, §7.3 item 7 |
| T4 | A type under `urn:eudi:sca:` other than the two served | `invalid_transaction_data` | CS-12 §7.1 item 1, §7.3 item 10; §8.5 |
| T5 | An unsigned request carrying an entry under `urn:eudi:sca:` | `invalid_request` | CS-12 §7.3 item 3; PaSO Core §3 |
| T6 | `multiple` true on the credential query a TS12 entry names | `invalid_request` | CS-12 §8.1: the query matches one attestation |

**One SCA attestation per request** (CS-12 §7.3 item 7; rb-sca-iban §9: "exclusively used in
presentation scenarios where transaction data is present"). siros-ts12 reserves the credentials
whose `ts12` document's `category` is SCA's with a configured type among their `types`
(`Profile::reserves`): the matcher offers one only for the query a TS12 entry names. T2, T3 and T6
then leave one such query, one credential for it.

T5 makes the profile own its rule on unsigned requests, as siros-paso owns PaSO's, whatever the
build accepts. TS12 §3.1 lets an unsigned request through after a warning and an explicit
confirmation; the EC agreed TS12 should require signing instead (`ts12-issues` item 7), so
PaSO's rule applies.

`transaction_data_hashes_alg` keeps the core's B.3.3.1 rules (`txhash::refusals`, reading 27).

**Display** (TS12 §3.3.1 to §3.3.3, through PaSO View §2 to §4):

| TS12 | Profile | PaSO |
| :-- | :-- | :-- |
| A field whose claim metadata holds a `display` array, at level 1, 2, 3 or none | Displayed, and seen before confirmation | View §2 |
| Level 4 | Internal | View §2 |
| A payment's `amount` and `payee.name`; an action's `action` | Displayed at every level; the payment's two in its header (RTS Art. 5(1)(a)) | Payment rulebook |
| `transaction_id`, `date_time`, `payee.id`, `currency` without claim metadata (CS-12 §7.2, test bed KA21, KA23) | Internal | View §2 |
| Another field a payload holds without claim metadata, or a claim below level 4 without `display` (TS12 §3.3.1, CS-12 §7.3 item 5) | The type is unsupported (`Ts12Unsupported::Labels`) | View §2 |
| Claim labels: `display` entries with `lang`, `label`, `description` | `lang` read as the entry's locale, `label` as its name; `description` unused. TS12 was not written for View §4's Lookup, so its tags convert as TS12 means them: an entry whose array holds no entry under its language's generic tag (the tag without its region and variants, its script kept) is that language's text and converts under the generic tag, the first such entry in the array's order when several regions of one language stand alone; a grandfathered tag (RFC 5646 §2.1) stays whole. WE BUILD's claim labels tagged `en-GB` beside no `en` are English and convert to `en` | Proof Metadata §3.1 |
| Locale matching, which TS12 leaves open | View §4 as written over the converted tags: the first tag of the priority list for which every label array matches by RFC 4647 Lookup or its default entry (section 4.14); no tag excludes the credential (§3.3.1: cease) | View §4 |
| Label lengths in "characters" | §3.3.3's 30, 30, 50 and 250 in extended grapheme clusters; claim labels 60; PaSO's rules on directional and control characters, and a visible character | Proof Metadata §3.3 |
| `transaction_title`, `denial_action_label` absent | The wallet's title and denial label (§3.3.3) | Proof Metadata §3.2 |
| `security_hint` | Shown exactly; absent, none | Proof Metadata §3.2 |
| Order | The claims metadata's | View §2 |

**Payload.** A typed parse: each field TS12 lists, of its JSON type; any other member at any
depth refused. TS12's schemas close the top level alone, and PaSO Core §7.4.2 step 2 closes every
level. `payee.logo#integrity` stands declared beside `payee.logo` (View §3 `image`).

`urn:eudi:sca:payment:1` (TS12 §4.3.1):

| Field | TS12 | PaSO value type |
| :-- | :-- | :-- |
| `transaction_id` | string, required, 1 to 36 characters | plain |
| `date_time` | string | `iso_date_time` |
| `payee` | object, required | |
| `payee.name`, `payee.id` | string, required | plain |
| `payee.logo` | string | `image`: a data URL, or an https URL with `payee.logo#integrity` |
| `payee.website` | string | `url` |
| `pisp` | object; its three members required | |
| `pisp.legal_name`, `pisp.brand_name`, `pisp.domain_name` | string | plain |
| `execution_date` | string; refused beside `recurrence` | `iso_date` |
| `currency` | string, required, `^[A-Z]{3}$` | `iso_currency` |
| `amount` | number, required | `iso_currency_amount`, with `currency` |
| `amount_estimated`, `amount_earmarked`, `sct_inst` | boolean | `boolean` |
| `recurrence` | object; `frequency` required | |
| `recurrence.start_date`, `recurrence.end_date` | string | `iso_date` |
| `recurrence.number` | integer | plain |
| `recurrence.frequency` | string, required | `frequency` |
| `recurrence.mit_options` | object | |
| `mit_options.amount_variable` | boolean | `boolean` |
| `mit_options.min_amount`, `max_amount`, `total_amount`, `initial_amount` | number | `iso_currency_amount`, with `currency` |
| `mit_options.initial_amount_number` | integer | plain |
| `mit_options.apr` | number | plain |

`urn:eudi:sca:login_risk_transaction:1` (TS12 §4.3.2): `transaction_id` (string, required) and
`service` (string, up to 100 characters), plain; `date_time` (string), `iso_date_time`; `action`
(string, required, up to 140 characters), plain. TS12's schemas state these lengths and patterns,
and `PayloadRefusal::Length { path, max }` refuses a longer text. A refusal names a member by
`FieldPath`, one of the crate's constants for TS12's field tables, and a member those tables do not
list by `PayloadRefusal::Member { within, name }`.

**Values** (TS12 §4.3.1, through PaSO View §3):

| TS12 | Profile |
| :-- | :-- |
| `amount`: "fractional digits as per [ISO4217]", which the schema leaves unchecked | The exact decimal value of the number as written, with at most the currency's minor-unit digits, shown with exactly that many: `42.5` EUR shows 42.50, `10.125` EUR is refused |
| "Negative amounts are signed by minus", with no meaning for a payment to a payee | Refused: TS12 defines no negative payment |
| An amount beyond 38 digits | Refused as `PayloadRefusal::Digits`: the exact value's width |
| A negative or oversized number elsewhere | Refused as `PayloadRefusal::Kind`: an integer beyond 64 bits as `Expected::Integer`, an `apr` beyond 38 digits as `Expected::Decimal` |
| `mit_options.apr`: a number | Its exact decimal value: `6.50` and `1.5e1` show 6.5 and 15 |
| `payee.website`, `payee.logo`: a URL other than https | Refused as `PayloadRefusal::Kind` |
| `payee.logo#integrity` beside a data URL or without a logo | Refused as `PayloadRefusal::Member` |
| Dates: the prose says an ISO 8601 date, the schema `format: date-time` | ISO 8601 calendar dates (`iso_date`) |
| `date_time`: ISO 8601 date and time | `iso_date_time`, fractional seconds and `Z` included |
| `execution_date` "MUST NOT lie in the past" | The Relying Party's rule: TS12 names no clock and no time zone for the wallet |
| Integers | A number without fraction or exponent, shown as written |
| `frequency`: ISO 20022 codes, the wallet's strings | PaSO's `frequency`: the same 12 codes, the wallet's words |
| Duplicate member names, which TS12 leaves open | Refused by the core's `json` (PaSO PR #6) |

**The Key Binding JWT** (`members`, `respond`; TS12 §3.6, CS-12 §7.3 item 8, §8.2):

| Claim | Value |
| :-- | :-- |
| `jti` | A UUID v4 from siros-paso's `RandomIds::random_id`, fresh for each presentation |
| `response_mode` | `Answered::mode`, the registered mode's name, as the request names it |
| `amr` | One object per factor applied, `{category: method}`, in the order applied (the table below) |
| `transaction_data_hashes`, `transaction_data_hashes_alg` | `txhash::members` over the entry as received (B.3.3.1) |

`members` places TS12's claims in a proof whose placement is `Claims` alone: TS12 defines its
binding as Key Binding JWT claims (TS12 §1.2, §3.6) and none for a name space, so the matcher
offers no mdoc for a TS12 entry. siros-ts12 names no format. `authentication` answers `Strong`,
so `amr` always holds two categories. siros-ts12 writes TS12's claims alone, its `jti` from
`RandomIds`.

| Factor (`Authentication::factors`) | `amr` object (TS12 §3.6) |
| :-- | :-- |
| `Knowledge::Pin(Some(n))` | `{"knowledge": "pin_less_than_6_digits"}` for n < 6, else `"pin_6_or_more_digits"` |
| `Knowledge::Passphrase(Some(n))` | `"passphrase_less_than_8_chars"` for n < 8, `"passphrase_8_to_11_chars"` for 8 to 11, else `"passphrase_12_or_more_chars"` |
| `Knowledge::Pattern` | `"pattern"` |
| `Knowledge::Pin(None)`, `Passphrase(None)`, `Unknown` | `"other"` |
| `Possession::RemoteWscd`, `LocalExternalWscd`, `LocalInternalWscd`, `LocalNativeWscd` | `{"possession": "key_in_remote_wscd"}`, `"key_in_local_external_wscd"`, `"key_in_local_internal_wscd"`, `"key_in_local_native_wscd"` |
| `Possession::Software` | `"other"` |
| `Inherence` of `Fingerprint` or `Face`, `Device` or `External` sensor | `{"inherence": "fingerprint_device"}`, `"fingerprint_external"`, `"face_device"`, `"face_external"` |
| `Inherence` of another modality | `"other"` |

**Unsupported** (decision 12):

- `extends` of `transaction_data_types` and `category`;
- a `transaction_data_types` key other than a built-in type's URN: TS12 §2.3 allows any URI and
  defines no routing from it to a wallet's handler;
- several TS12 entries, or several credential ids in one (T2, T3);
- TS12 §3.1's unsigned path (T5);
- TS12 §3.3.1's icons in place of parameter names, and names left out: TS12 defines no metadata
  member that asks for either and leaves both to rulebooks;
- an issuer's JSON Schema, which leaves its type unsupported for the credential;
- TS12 §4.1.2's bracket-path integrity claims;
- the embedded disclosure policy (TS12 §3.1; CS-12 §7.3 item 2);
- `account_access` and `emandate` (T4);
- the wallet-side `aud` check of CS-12 §6.1 step 3 (reading 28).

`Ts12Excluded` tells a wallet why phase 1 excludes the credential, and `Ts12Unsupported` holds a
variant per rule on a type's document: its `schema`, its `claims`, each claim's path, level and
labels, and its `ui_labels`. A `ts12` document the wallet holds and cannot read is a `Fault`, as in
phase 2.

The transaction log of TS12 §5.3 is the caller's, optional under CS-12 §7.3 item 11: the
`Received` the caller keeps holds every value it lists.

```rust
/// The key of the TS12 document in a credential's registration.
pub const DOCUMENT: DocumentKey<'static> = checked!(DocumentKey, "ts12");

/// A `claims_uri` or `ui_labels_uri` document the caller fetched, parsed once.
pub struct FetchedDocument(Node<'static>);
/// What `compose` writes; `content` gives its `DocumentBytes`.
pub struct ComposedDocument(Vec<u8>);
/// `category`: TS12 §3's, or absent or any other.
pub enum Category { Sca, Other }
/// `schema`, `claims` or `ui_labels`, in `ComposeError::Both`.
pub enum TwinnedMember { Schema, Claims, UiLabels }

pub struct Ts12Document<'d> { category: Category, types: &'d Object<'d> }
/// A `transaction_data_types` entry under its key; `Ts12Document::entry` and `listed` make one.
pub struct TypeEntry<'d> { kind: Option<Ts12Type>, members: &'d Node<'d> }
/// An entry whose schema names a built-in type; only `TypeEntry::built_in` makes one, which reads
/// its `claims` and `ui_labels` under TS12 §3.3 once. `paso_metadata` takes it and refuses nothing.
pub struct BuiltInEntry<'d> { kind: Ts12Type, metadata: TypeMetadata<'d> }
/// `payee.logo`'s forms: a data URL (RFC 2397) and an SRI value (W3C SRI §3.5), each made by its
/// `parse`, which refuses a text outside its grammar.
pub struct DataUrl(String);
pub struct Integrity(String);

impl<'d> Ts12Document<'d> {
    /// The document from the credential's own type metadata and the documents its `claims_uri`
    /// and `ui_labels_uri` name, fetched at registration (TS12 §4.1, §4.1.1).
    pub fn compose(own: &Node<'_>, fetched: &Keyed<HttpsUrl, FetchedDocument>)
        -> Result<ComposedDocument, ComposeError>;
    pub fn read(node: &'d Node<'d>) -> Result<Self, ComposeError>;
    pub fn category(&self) -> Category;
    pub fn entry(&self, kind: &TransactionType<'_>) -> Option<TypeEntry<'d>>;
    pub fn listed(&self, kind: Ts12Type) -> Option<TypeEntry<'d>>;
}

impl<'d> TypeEntry<'d> {
    pub fn built_in(&self) -> Result<BuiltInEntry<'d>, Ts12Unsupported>;
}

/// The built-in types served (CS-12 §7.1 item 1).
pub enum Ts12Type { Payment, LoginRisk }

/// A `vct` value a credential's `types` may name, non-empty, fixed with `checked!`.
pub struct AttestationType(&'static str);
pub struct Ts12Profile { attestation_types: AllOf<AttestationType>, bound: ItemBound,
                         resources: Keyed<HttpsUrl, Fetch> }
/// What phase 2 finds of a displayed https logo.
pub struct Ts12Finding { pub url: HttpsUrl, pub failure: ImageFailure }

impl Ts12Profile {
    /// The profile, for credentials whose `types` name one of the attestation types (CS-12 §7.1
    /// item 2: the three base types).
    pub fn new(attestation_types: AllOf<AttestationType>) -> Self;
    /// View §2's item bound.
    pub fn with_bound(self, bound: ItemBound) -> Self;
    /// What the wallet fetched of each https logo.
    pub fn with_resources(self, resources: Keyed<HttpsUrl, Fetch>) -> Self;
    /// Registers the profile under `urn:eudi:sca:`.
    pub fn register<H: Build>(self, builder: &mut RegistryBuilder<H>) -> ProfileHandle
    where
        Self: HostedProfile<H>;
}

impl Profile for Ts12Profile { /* refusals: T1 to T6; members: placement Claims alone; bind:
                                  phase 1 above; authentication: Strong; respond: the four
                                  claims */ }
```

#### 4.10.3 siros-paso's engine

siros-ts12 renders through siros-paso. siros-paso opens three seams and holds no TS12 code:

- `render::Request` becomes public with its fields, and gains `limits: LabelLimits`. Its `resolve`
  is `&dyn Fn(&str) -> Resolution<'r>`, as `image::resolve`'s argument is: every profile shares one
  engine in a build. Its type, family and metadata become one `Registered`. `Registered::of(PasoType, given)` makes one across
  the crate boundary, and `PasoType::rendered_by(text, family)`, which `PasoType::parse` calls,
  names a profile's own identifier.
- `LabelLimits { claim_name, title, affirmative, denial, hint }`, each a `NonZeroUsize`, replaces
  `LabelSlot::max`'s constants; `LabelLimits::PASO` holds Proof Metadata §3.3's 60, 100, 40, 40
  and 160, and `label_limit!` fixes a profile's own. `view::convert(&Registered, LabelLimits,
  context, priority)` writes a type's MF2 source for the wallet's `Context` under those limits.
- `bound(view, attested, entries)` becomes public: a rendering's `Bound`, with what the
  profile's record attests (siros-paso: `display_locale` and `metadata_integrity`; siros-ts12:
  nothing); `entries` is the `BoundEntries` that `BoundEntries::select` took among those offered.

siros-paso calls each seam itself, so removing siros-ts12 leaves no dead code (litmus G2).
siros-paso's renderings and response members stay byte-identical through the change (I17).

#### 4.10.4 The WE BUILD build

| Part | The WE BUILD build | Source |
| :-- | :-- | :-- |
| Client Identifier Prefixes | siros-x509's `x509_hash` alone | CS-02 §7.1 item 5, NOTE_CS02_02 |
| `DcApiProtocols` | `SIGNED` | CS-07 WU-DC-01; CS-02 §7.1 |
| Profiles | siros-paso; siros-ts12 with the three base types | CS-12 §7.1 item 2 |
| URI schemes, registered by the caller | `openid4vp://`, `eu-eaap://`; `haip-vp://` optional | CS-02 §7.1 item 3 |
| Request Object rules | siros-webuild's `Cs02Claims`: a Request Object holds `exp` and `aud` (A14) | CS-02 §8.2, §6.1.3 |
| Response URI answer readers | siros-webuild's `Cs02ErrorAnswer`: the Verifier's `error` and `error_description` | CS-02 §8.3, §6.1.7 |
| Host | `Platform`; `Haip` (for siros-x509, `dc_api.jwt`, `direct_post.jwt`, siros-sdjwt's signatures, siros-paso's sealed risk signals and its ad-hoc metadata JWTs); `RequestDecryption` (for the registered `EncryptedRequests`); siros-paso's `Paso`, `RandomIds` and `IssuerTrust`. The build holds no mdoc (CS-12: "TS12 [1] itself is scoped to SD-JWT-VC"), so neither `CoseEncrypt` nor `DeviceMac` | decision 13 |
| Response modes | `direct_post.jwt` and `direct_post` (feature `uri`), `dc_api.jwt` (feature `dc-api`) | HAIP §5.1, §5.2; CS-07 |
| The trust service | `verifier_info` required; the WRPAC and WRPRC checks CS-13 WU-INT-01 points to (CS-018 WU-TV-01 to -11, -13, -14); CS-13 WU-INT-02 to -04 | CS-02 §7.1 item 6; CS-13 §7.2, §7.5 |

siros-integration holds the build beside HAIP's, and each runs one honest end-to-end path (section
8.3, I19).

### 4.11 Crates and dependencies

Decisions 16 and 20: a build compiles the crates it uses and only those, and the mechanisms it
registers and only those. Joe Armstrong named the failure: "You wanted a banana but what you got
was a gorilla holding the banana and the entire jungle". The Rust ecosystem answers it with small
trait crates and additive features: axum's library authors depend on `axum-core`, its trait
crate; a hash crate implements `digest`'s traits alone; an RNG implements `rand_core`; tokio puts
each runtime part behind a feature its users turn on. Here a plug-in depends on the core it
extends, and turns on the core features of the mechanisms it uses; the owner ruled out
primitives crates, so each mechanism is a feature of the core.

```text
siros-openid4vp     the core: a request in, a response built               match | resolve | dc-api | uri | signed | request-decryption | cbor | transaction-data | sha3 | blake2 | k12 | sri | claims
├── siros-x509      x509_hash, x509_san_dns                                 signed
├── siros-mdoc      mso_mdoc; B.2.6's handover; module DeviceMac            claims; resolve: cbor
├── siros-sdjwt     dc+sd-jwt                                               claims
├── siros-paso      PaSO's transaction data; modules Paso, RandomIds, CoseEncrypt   transaction-data, sri; sealed-signals: cbor
│   └── siros-ts12  TS12 on PaSO's engine                                   transaction-data
├── siros-qes       CSC's QES transaction data                              sri; default resolve, sha3: its SHA-3 approval hashes
├── siros-credman   Credential Manager's entries; the entry emission; the registration; register: its writer   match
├── siros-webuild   WE BUILD's CS-02 rules: Cs02Claims, Cs02ErrorAnswer     signed, uri
└── siros-zkp-req   zkp_req's existing format, until the zkp_req proposal   resolve, cbor
siros-i18n          statements and their wording: Message and its derive, Context, Text   derive | check | conformance | number | currency | offset | date | nfc
siros-syntax        checked!, Keyed, AllOf; the value types in their literal forms; the ISO 4217 table
siros-explain       the error contract: Explain, its derive and scope!          derive | check
siros-testkit       the core's test doubles                                 tests
siros-integration   the HAIP and WE BUILD builds end to end                 tests
siros-matcher       siros-dc-matcher: the core and the plug-ins without resolve, siros-credman
```

| Crate | SIROS crates it names | For |
| :-- | :-- | :-- |
| siros-openid4vp | siros-explain; siros-syntax; siros-i18n without default features, with `derive` | the error contract (section 4.13); `checked!`, `Keyed`, `AllOf` and the values its rules read; its statements, the `Context` its extension points receive and the `Text` its outputs hold (section 4.14) |
| siros-x509 | the core; siros-explain; siros-syntax; siros-i18n | the traits it implements; its errors' contract and `checked!`; the `Context` its prefix claim resolves the Verifier's name through (`ClaimText::Text`) |
| siros-qes | the core; siros-explain; siros-syntax; siros-i18n with `derive` | the traits it implements; its errors' contract, `checked!` and `AllOf`; its statements `QesTitle` and `QesText` |
| siros-webuild | the core; siros-explain; siros-syntax | the traits it implements; its errors' contract and `checked!` |
| siros-zkp-req | the core | the traits it implements |
| siros-mdoc | the core; siros-explain; siros-syntax | the traits it implements; its errors' contract, `checked!` and `AllOf` |
| siros-sdjwt | the core; siros-explain; siros-syntax | the traits it implements; its errors' contract, `checked!` and `AllOf` |
| siros-paso | the core; siros-explain; siros-syntax; siros-i18n with `derive`, `currency` and `date`; siros-x509 under `resolve` | the traits it implements; PaSO View's values, read as siros-syntax's types; its statements; its converted View sources, which call `:currency`, `:siros:date`, `:siros:time` and `:siros:datetime` (section 4.14); an ad-hoc metadata JWT's `x5c` chain, its leaf's key and subject (Proof Metadata §5.3) |
| siros-ts12 | the core; siros-paso; siros-explain; siros-syntax; siros-i18n | siros-paso's engine renders TS12's entries (section 4.10.3); the core's `ViewAdditions` gives a credential's `types` (reading 26); the error contract (section 4.13); `Keyed`, `AllOf` and the payload's values; the `Context` in `view::convert`'s signature |
| siros-credman | the core; siros-explain; siros-syntax; siros-i18n | the consent entry it maps; its errors' contract; the registration's `AllOf` and `Keyed`; the registration's sources and the matcher's `Context` built from them (section 4.14) |
| siros-i18n | siros-explain; siros-syntax under `currency` and `date`; siros-i18n-derive under `derive` | its errors' contract; the value forms its format functions parse (section 4.14); `#[derive(Message)]` |
| siros-syntax | siros-explain | the contract of its errors `Malformed` and `Repeated` |
| siros-explain | siros-explain-derive under `derive` | `#[derive(Explain)]` |
| siros-explain-derive, siros-i18n-derive | siros-derive-internals | the field rules both derives share |
| siros-testkit | the core; siros-explain; siros-syntax; siros-i18n with `derive`, `number`, `currency` and `date` | the traits its doubles implement; its errors' contract; `DoubleText`; the test app's sources and the functions they call |
| siros-integration | every crate, as dev-dependencies, siros-i18n with `derive` and `check` | the builds; the wallet's completeness test (section 4.14) |
| siros-cldr (`publish = false`) | siros-explain; siros-syntax | the tool that writes CLDR's format options (section 4.14); `Currency` |

siros-paso links uuid for `RandomId` beside its `RandomIds` module; the core links none.
siros-openid4vp takes jose-rs 0.10 as a dev-dependency for KA6: its tests decrypt §8.3's example
JWE and the core's sealed answer under §8.3's private JWK.
siros-paso and siros-qes take siros-mdoc and siros-sdjwt as dev-dependencies alone: their tests ask
the plug-in whose id a credential names for its placement (siros-testkit's
`fixtures::placement`), so I25's removal of siros-mdoc or siros-sdjwt takes their tests with it.
The colleague's crates name the core features their code uses: siros-zkp-req `cbor`,
siros-zkp-catalogues `cbor`, `dc-api` and `uri` (its policy names `DcApiJwt` and
`DirectPostJwt`), proving's e2e `cbor`; siros-testkit names every mechanism.

**The core's features**, each a mechanism, each turned on by the crates that use it:

| Feature | Holds | Links | Turned on by |
| :-- | :-- | :-- | :-- |
| `match` | phase 1: JOSE parsing, the envelope, routing over the registered response types and modes, the request rules, matching with `ExcludedBy`, `UnmetCode`, `Match::unmet` and `TransactionBinding`, consent entries; `ParameterName`, `Placement`; `ResponseParameters`; `Build` with `NoHost`'s case, `HostedFormat`, `HostedProfile`, `HostedMode`, `HostedResponseParameters`, `JweHost`; `KeyChoice`, `modes::key_rule`, `KEY_RULE`, `VerifierMetadata::lists`; the types the core's enums carry in every build: `AuthorizationUri`, `RequestUri`, `ResponseUri` with `ResponseUri::parse`, `NotHttps`, `NotUri`, `RedirectTarget`, `RequestUriMethod`, `FormBody`, `PostBody`, `PrefixName`, `HashName`, `ScopeValue`, `Scopes`, `ScopeEntry`, `JweError`, `JweAlgorithms`, `ErrorDescription`, `MediaType` with `form` and `is_form`, `ImageMedia`; `CORE_METADATA`, `CORE_PARAMETERS`, `CORE_ANSWER` and `CORE_RESPONSE`, checked in every build | base64, sha2, serde_json, fluent-uri (for `HttpsUrl`), idna, icu_properties (the text rules and every refusal's quoting, `refusal::printable`) | every build |
| `resolve` | phase 2: `Route`, `AnswerRoute`, `Unroutable`, `Delivery`, the sealing of encrypted answers and `RouteBreach`, A.4's errors, `Rejected::reply`, `DcApiErrors`, `Reply`, the session's binding facts, `Prepared`, `ResponseParametersHost` and `ParameterBreach`, the authentication step and its Origin evaluation, the host access traits, `CoreHost`, `Build`'s case of a host holding a `Platform` with `FormatHost`, `ProfileHost`, `ModeHost`, `Haip` with `VerificationKey` and `PublicJwk`, `MetadataMember` | | the plug-ins' `resolve` |
| `dc-api` | `Received::dc_api`; the modes `dc_api` and `dc_api.jwt` | | the app's DC API build, the matcher |
| `uri` | URI arrival's parsers and steps: `AuthorizationUri::parse`, `RequestUri::parse`, `RedirectTarget::parse`, `Fetch`, `NoFetch`, `FormBody::of`; `RequestPost`, `WalletMetadata`, `RequestUriPost`, `PostContribution`, `EphemeralKey`, `KeyHandle`; `ResponseUriAnswer`, `AnswerReader`; `ScopeQuery` and `RegistryBuilder::scope`; the modes `direct_post.jwt` and `direct_post` | serde_urlencoded, form_urlencoded, fluent-uri `net` | the app's URI build, siros-webuild; implies `signed` and `resolve` |
| `signed` | `ClientPrefix`, `PrefixHost`, `HostedPrefix`, `client_prefix`, the signature step of authentication (A7, A8), `ObjectRule` (A14), `Decided::of`, `Object::distinct`, `recourse::listed`; a build without it refuses a signed request with A2 (A1 for `origin`), as a build that registers no prefix does | | siros-x509, siros-webuild; `uri` |
| `request-decryption` | `EncryptedRequests`, `RequestDecryption`, `CompactJwe` | | the WE BUILD build; implies `uri` |
| `cbor` | the `cbor` module and its COSE reading | ciborium, ciborium-io, ciborium-ll, half, coset | siros-mdoc's `resolve`; siros-paso's `sealed-signals` |
| `transaction-data` | B.3.3.1: `txhash`, `HashAlgorithm` with its digest, `Hashes`, `Sha2` | | siros-paso, siros-ts12 |
| `sha3`, `blake2`, `k12` | `Sha3`, `Blake2`, `K12` | sha3 and keccak; blake2; k12 | the app's build, for the algorithms it registers |
| `sri` | W3C SRI (`sri.rs`) | | siros-paso, siros-qes |
| `claims` | the claims kit (`claims/kit`) | | siros-sdjwt, siros-mdoc |

A feature adds types, trait implementations, methods and modules, and changes no signature: a
crate that does not turn it on compiles the same when another crate of the build does (the Cargo
Book: "features should be additive"). An enum that gains a case under a feature holds the case
in every build and its constructors behind the feature, as `MemberValue::Cbor` holds an `Item`
that only `cbor` parses. The types such cases carry compile in every build, which is why
`match` holds `AuthorizationUri`, `ResponseUri`, `FormBody` and the name types: each is a
private field over a crate `match` links already (fluent-uri's base, `String`, `&'static str`),
and the crates that parse or write them stay behind `uri`. A trait's signature names a type of
its own feature or of an implied one: `Haip` and `VerificationKey` sit in `resolve` together,
`Mode::metadata_names` returns a `match` type, and a registry method that needs a module bounds
it in its own `where` clause, so no feature adds a method to a trait an implementor writes.
`ProfileHost<H>` holds `Profile`'s methods that name `resolve` types (`wanted`, `informed`,
`authentication`). Each plug-in gates its phase 2 on its own `resolve` feature, which turns on the
core's.

**How the registry keeps it.** The registry's host fixes what the registry takes of each plug-in:
`Build`, sealed through `Plugins`, which names the stored types and the sealing accessor. `NoHost`
takes phase 1's `Format`, `Profile` and `Mode` in every build; under `resolve`, every
`H: Has<dyn Platform>` takes `FormatHost<H>`, `ProfileHost<H>` and `ModeHost<H>`. `HostedFormat<H: Build>`,
`HostedProfile<H: Build>` and `HostedMode<H: Build>` are conversions with one impl for `NoHost` and
one for hosts; `jwe_mode` takes `H: JweHost`, `NoHost` or a host holding `Haip`.
`RegistryBuilder::<NoHost>::format` thereby takes a `Format` whether or not another crate of the
build turns `resolve` on: a matcher crate registering siros-sdjwt with `format` and `jwe_mode`
compiles beside siros-x509, which turns `resolve` on. Generic registration code names `H: Build`
beside its `Self: HostedProfile<H>`. The request carries `Hashes` and `Scopes` under every host, so
one `HashAlgorithm` holds the name, the length and the digest in every `transaction-data` build.
siros-paso's `CoseEncrypt` trait and `CoseEnc` compile in every `resolve` build, and its phase 2
bounds `MayHave<dyn CoseEncrypt>` in every build: a host states its slot once, and compiles the same
whether or not another crate turns `sealed-signals` on.

- A plug-in's `resolve` turns on the core's `resolve` and that of each plug-in whose phase 2 it
  calls. siros-ts12 calls siros-paso's phase 2 alone.
- siros-paso and siros-qes put each path that pulls a mechanism behind a feature:
  siros-paso's `COSE_Encrypt` sealing of an mdoc's risk signals (`SealedCose`, its check,
  `TestCoseEncrypt`) behind `sealed-signals = ["siros-openid4vp/cbor"]`, a phase-1 feature, as
  the matcher's phase-1 refusal reads it; siros-qes's SHA-3 approval hashes behind
  `sha3`. Without `sealed-signals`, `PasoProfile`'s `lacking` starts with
  `OptionalModule::CoseEncrypt` (`OptionalModule::UNCOMPILED`), so phase 1 refuses an mdoc entry
  whose signals need encryption (`NotCompatible::Lacks`), as a build lacking `CoseEncrypt` does.
  siros-qes's default features are `resolve` and `sha3`; without `sha3`, an SHA-3
  `hashAlgorithmOID` is `Problem::UnknownHashAlgorithm`. siros-qes with `sha3` and without
  `resolve` links sha3 unused (phase 1 recognizes the SHA-3 OIDs, phase 2 digests; Cargo expresses
  no dependency on two features).
- A plug-in's normal dependencies are those its code uses: siros-sdjwt and siros-mdoc read JSON
  through the core's `json`. siros-sdjwt names sha2 in every build, and base64 and rustc-hash behind
  `resolve`. siros-mdoc names base64, sha2 and rustc-hash behind `resolve`, siros-qes base64 and
  sha2. siros-paso names icu_properties (CommonMark's whitespace and punctuation), base64, sha2,
  hmac, unicode-segmentation and rustc-hash in every build, and serde_json, uuid and siros-x509
  behind `resolve`. siros-ts12 names base64 for a data URL and SRI. The core links icu_properties,
  idna, fluent-uri, base64, sha2 and serde_json in every build; `DisplayText` and
  `refusal::printable` read general categories through icu_properties. Sha2 sits in every build; a
  build with neither channel, `sri` nor `transaction-data` leaves it unused, and no request reaches
  such a build.
- siros-i18n's features: `derive`, `#[derive(Message)]` from siros-i18n-derive; `check`, the
  wallet's completeness test (section 4.14), which turns on siros-explain's; `conformance`, MF2's
  test functions `:test:function`, `:test:select` and `:test:format`, which siros-i18n's conformance
  tests call; `nfc`, a default, MF2's Unicode Normalization Form C of names, variant keys and
  selector literals, and `Context::module_in_nfc` (section 4.14); and one per format function, each
  a default: `number` (`:number`, `:integer`), `currency` (`:currency`, `:percent`), `offset`
  (`:offset`), `date` (`:siros:date`, `:siros:time`, `:siros:datetime`). A crate that derives
  `Message` turns on `derive`: the core, siros-paso, siros-qes and siros-testkit. siros-paso turns
  on `currency` and `date`, which its converted View sources call. siros-x509, siros-ts12 and
  siros-credman name siros-i18n without a feature, for its `Context`; siros-mdoc and siros-sdjwt
  name it as a dev-dependency alone. siros-credman's `register` turns on `nfc`: its writer loads
  through `Context::module_in_nfc`. The wallet app turns on `nfc` and the functions its own wording
  calls, and a module that calls a function the build lacks fails to load (`LoadError::Function`).
  The matcher's build leaves `nfc` off and compiles every function the registration's sources call:
  `Registration::open` refuses a source that calls another (`ContextError::Source`). siros-i18n's
  errors derive `Explain` under `scope!("i18n")`. It names siros-syntax under `currency` and `date`
  (the values its functions parse), unicode-normalization under `nfc`, icu_properties under
  `currency` (a currency symbol's edge) and inventory under `check`. siros-explain names inventory
  under `check`. siros-explain-derive and siros-i18n-derive share their field rules through
  siros-derive-internals, after serde_derive_internals; the three name syn, quote and proc-macro2.
  siros-syntax's build script reads SIX's ISO 4217 List One, `list-one.xml`, vendored in the crate.
- A crate's `test-util` feature holds doubles of the extension points it defines, and no
  constructor sits behind it, the pattern of tokio's `test-util`. Each double is written with the
  crate's public API alone, so anyone could write it and it opens nothing: Cargo's feature unification can turn the feature on in any build, and
  a constructor behind it would open what its type seals. `cargo xtask layout` holds the rule. The
  gate stands on a whole item, module or file. Under it, the check refuses an inherent `impl` of a
  type declared outside the gate; a trait `impl` on such a type with private fields; a `pub` item
  whose signature or type names such a type, a trait `impl`'s methods apart; a free `pub fn`,
  `pub const` or `pub static`; a value of such a type written by its literal or tuple constructor; a
  call of a non-`pub` function outside the gate; a `pub use` of an item outside the gate; a glob
  `pub use`, a macro call in item position and `#[path]`. It refuses the gate on an associated item
  outside the gate, a field or a part, `cfg_attr` and a macro's tokens. A double's own constructor
  stays. A test reaches a sealed value the way a
  plug-in does: siros-testkit's `probe` holds a format and a profile registered with the core
  alongside the doubles, which hand a test's closure the `QueryContext`, `AnsweredContext` and
  `Session` or `FetchedRecord` the core's flow gives them and stop the flow there, and a session
  from a request and a `TestMode` route. The core defines its doubles' extension points and holds
  no `test-util`: the core's doubles sit in siros-testkit (`TestPlatform`, which
  counts the End-User's authentications, `TestHaip`, `TestRequestDecryption`, a zero-sized double
  with a fixed scalar, `JweHaip`, whose `encrypt_jwe` seals for real (ECDH-ES with a fixed
  ephemeral key and the Concat KDF, A128GCM or A256GCM, the key's `kid` in the header; its other
  methods `TestHaip`'s), `TestMode` (either channel, a rule, declared and written metadata
  members, a `TestChoice` the core checks: the clear, a request key at a place with an `enc`, or
  `Foreign`, a key of other metadata; a `TestBody` of its own channel or the other; answers and
  errors), `TestResponseType`, `TestResponseParameters` (declared names and written members, which
  may name what it did not declare), `fixtures::authenticate` (the trust double permitting, under
  `fixtures::trust_config`: a 60 s skew, unsigned DC API requests accepted), `TestHash` (a
  name, its octets, a written length), `TestScope`, `TestPrefix`, `TestPostContribution`,
  `TestAnswerReader`, `TestObjectRule`, `TestFormat` with `placing(Placement)` and `stating`, and
  the `TestHost` that `test_host!` builds with each module held, optional or lacking), the
  `Paso`, `RandomIds`, `IssuerTrust` and
  `CoseEncrypt` doubles in siros-paso (`TestPaso`, `TestRandomIds`, `TestIssuerTrust`,
  `TestCoseEncrypt`), the
  `DeviceMac` double in siros-mdoc (`TestDeviceMac`). A crate's own tests turn the feature on
  through a dev-dependency on the crate itself; a probe shows `cargo test` building the tests
  with the feature and `cargo build` leaving it out. siros-integration turns it on for its
  builds. siros-testkit names the core alone, so a plug-in's tests compile that plug-in and the
  core, and removing a plug-in leaves siros-testkit as it is. A test-support crate naming the
  plug-ins would close a dev-dependency cycle: Cargo builds it, and a unit test then meets two
  copies of its own crate.

**Per build** (`cargo xtask builds`, gate I39: a probe package per build over the workspace's lock,
read with `cargo tree -e normal,features`, since `cargo tree -p A -p B --features A/f` drops the
features). At wallet-rs `flows` `a307cca` siros-sdjwt alone and siros-mdoc alone each compile 96
crates, the same set: the core's one
`resolve` turned on ciborium, ciborium-io, ciborium-ll, half and coset; p256, elliptic-curve,
primeorder, crypto-bigint, ff and group; serde_urlencoded, form_urlencoded and fluent-uri's `net`;
sha3, keccak, blake2 and k12; and uuid; and siros-i18n's default features, each format function
among them. In each build below, the core and the plug-ins its row registers compile none of the
crates the row names, and siros-i18n with the features the row names alone; the host's modules
are the app's, and the crates they link (a P-256 implementation for `Haip` and
`RequestDecryption`) count against the app. Each row names the crates only an excluded crate pulls
too: zerocopy and zerocopy-derive (through half), percent-encoding and ryu (through
serde_urlencoded), sponge-cursor (through sha3 and k12), der_derive and flagset (through
x509-cert). The SD-JWT and the mdoc DC API builds compile fewer than 96 crates, and their sets
differ:

| Build | Registers | Compiles none of | siros-i18n features |
| :-- | :-- | :-- | :-- |
| SD-JWT over the DC API, unsigned | siros-sdjwt; `vp_token`; `dc_api`, `dc_api.jwt`; `DcApiProtocols::UNSIGNED` | ciborium, ciborium-io, ciborium-ll, half, zerocopy, zerocopy-derive, coset; p256, elliptic-curve, primeorder, crypto-bigint, ff, group; serde_urlencoded, form_urlencoded, percent-encoding, ryu, fluent-uri `net`; sha3, keccak, blake2, k12, sponge-cursor; uuid; x509-cert, der, der_derive, flagset, spki; inventory | `derive`, `number` |
| mdoc over the DC API, unsigned | siros-mdoc; `vp_token`; `dc_api`, `dc_api.jwt` | p256, elliptic-curve, primeorder, crypto-bigint, ff, group; serde_urlencoded, form_urlencoded, percent-encoding, ryu, fluent-uri `net`; sha3, keccak, blake2, k12, sponge-cursor; uuid; x509-cert, der, der_derive, flagset, spki; inventory | `derive`, `number`, `date` |
| SD-JWT by URI with siros-x509 | siros-sdjwt, siros-x509; `vp_token`; `direct_post.jwt`, `direct_post`; `RequestPost` | ciborium, ciborium-io, ciborium-ll, half, zerocopy, zerocopy-derive, coset; p256, elliptic-curve, primeorder, crypto-bigint, ff, group; sha3, keccak, blake2, k12, sponge-cursor; uuid; inventory | `derive`, `number` |
| siros-paso with SD-JWT | siros-sdjwt, siros-paso without `sealed-signals`; `vp_token`; `dc_api.jwt`; `Sha2` | ciborium, ciborium-io, ciborium-ll, half, zerocopy, zerocopy-derive, coset; p256, elliptic-curve, primeorder, crypto-bigint, ff, group; serde_urlencoded, form_urlencoded, percent-encoding, ryu, fluent-uri `net`; sha3, keccak, blake2, k12, sponge-cursor; inventory | `derive`, `number`, `currency`, `date` |
| HAIP | siros-sdjwt, siros-mdoc, siros-x509; `vp_token`; the four core modes; `RequestPost`; `Sha2` | p256, elliptic-curve, primeorder, crypto-bigint, ff, group; sha3, keccak, blake2, k12, sponge-cursor; uuid; inventory | `derive`, `number`, `date` |
| WE BUILD | siros-sdjwt, siros-x509, siros-paso, siros-ts12, siros-webuild; `vp_token`; `direct_post.jwt`, `direct_post`, `dc_api.jwt`; `RequestPost`, `EncryptedRequests`; `Sha2` | ciborium, ciborium-io, ciborium-ll, half, zerocopy, zerocopy-derive, coset; p256, elliptic-curve, primeorder, crypto-bigint, ff, group; sha3, keccak, blake2, k12, sponge-cursor; inventory | `derive`, `number`, `currency`, `date` |

Each row's wallet and its matcher compile the row's siros-i18n features: `derive`, which the core
turns on, and the format functions the app's wording calls. `number` serves every row, `date` mdoc's
dates and PaSO's, and `currency` PaSO's amounts. The wallet adds `nfc`. The matcher leaves `nfc` off
and compiles no unicode-normalization: siros-credman's writer refuses a source whose names, keys or
selector literals NFC would change (section 4.14). No row compiles `offset`, or `check`, which links
inventory.

Gates: I25, I39.

### 4.12 Documentation

Decision 17. The structure follows the crates the ecosystem reads as well documented. RustCrypto
and clap make the README the crate's root documentation, so docs.rs shows it and its example
compiles. axum and rustls give each extension point a section on building one: axum's "Building
integrations for axum" and `FromRef`, rustls's "Cryptography providers" and "Making a custom
CryptoProvider". clap, winnow and jiff keep long guides in doc-only modules (`_tutorial`,
`_topic`, `_documentation`), so the README stays short. tokio tables its feature flags and labels
each gated item on docs.rs. The Rust API Guidelines' documentation chapter sets the item rules.

**The repository README.** One paragraph: a wallet receives an OpenID4VP request, by the DC API or
a URI, and answers it; the caller performs every network call and key operation. Then the crate
table, each crate with the problem it solves; section 4.11's tree; MSRV; the check commands; the
license.

**A crate README**, the crate's root documentation (`#![doc = include_str!("../README.md")]`):

1. The title and the badges.
2. One paragraph: the problem the crate solves.
3. Usage: the `Cargo.toml` line and an example that compiles.
4. Features: a table, when the crate has features.
5. Extension points: a table linking each trait's `# Implementing` section, when the crate offers
   any.
6. MSRV and the license.

How the crate works lives in the item documentation.

**Extension points.** The rustdoc of each trait a plug-in or the caller implements holds one
sentence on what it extends; each method's contract, with what the core relies on; `#
Implementing`, with a complete example that compiles; the conflicts the registry refuses; the
crate that implements it for real; and its test double. A sealed trait says it is sealed
(C-SEALED). Every extension point follows one pattern: its inputs are core-made types with
private fields; the core checks each output; its host bounds are the modules it calls
(`HostedFormat<H>`'s pattern); the registry takes it and refuses a conflict; the core's own cases
implement the same trait.

| Extension point | Implemented by | Inputs (core-made) | The core checks | Registry refuses | Host bounds | Feature | For real in | Double |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| `Format`, `FormatHost` | a credential format | `Query`, `QueryContext`, `AnsweredContext`, `Credential`, `Usable`, `Session` | refusals as `AllOf<Refusal>`, `displayable`'s refusal as `ExcludedBy::Display`, a `Presentation` of §8.1's two forms, `wallet_formats` a JSON object, `placement` read once at build | a format id twice | `FormatHost<H>`'s, taken through `HostedFormat<H: Build>` | `match`, `resolve` | siros-mdoc, siros-sdjwt, siros-zkp-req | siros-testkit `TestFormat` |
| `Profile`, `ProfileHost` | a transaction data type | `Binding` with its `additions`, `Answered`, `FetchedRecord`, `Authentication`; `reserves` the `Credential` with its `ViewAdditions` | members within `members(placement)`, refusals with their codes, `reserves`' answer or its `Fault` | a type prefix twice, a member twice, a member the format's placement does not hold (`MemberPlacement`) | `ProfileHost<H>`'s, taken through `HostedProfile<H: Build>` | `match`, `resolve` | siros-paso, siros-ts12, siros-qes | `TestProfile` |
| `ClientPrefix`, `PrefixHost` | a Client Identifier Prefix | `ClientClaim`, `Decided` | the `alg` against `Haip::verifies` before any question (A7), the signature under the bound key (A8), the endpoint the core binds | a prefix name twice; `origin` | `PrefixHost<H>`'s; its registration `client_prefix` `Has<dyn Haip>` | `signed` | siros-x509 | `TestPrefix` |
| `ObjectRule` | a rule on a Request Object's claims | the payload's claims, after A10 | its refusal under its own code (A14) | | none | `signed` | siros-webuild's `Cs02Claims` | `TestObjectRule` |
| `ResponseType` | a response type (RFC 6749 §8.4) | none | P1 against the registered names | a name twice | none | `match` | the core's `vp_token` | `TestResponseType` |
| `ResponseParameters`, `ResponseParametersHost` | Authorization Response parameters (§8.1) | the response type's name, `Session` | members of the names the registry kept for the part (`ParameterBreach::Undeclared`), each once (`ParameterBreach::Twice`) | a name twice; `CORE_RESPONSE`: `vp_token`, `state`, `error`, `error_description`, `error_uri` | `ResponseParametersHost<H>`'s, taken through `HostedResponseParameters<H: Build>` | `match`, `resolve` | a profile's or a deployment's (`iss`, `id_token`) | `TestResponseParameters` |
| `Mode`, `ModeHost`, `ErrorModeHost` | a response mode | `Request`, `VerifierMetadata`, the sealing statement, `ModeRoute`, `AnswerContent`, `ErrorContent` | a `Jwe` choice: a key the request's `VerifierKeys` hold at its place, whose curve and `alg` the sealing module admits, an `enc` it states and the Verifier lists, from a mode registered with `jwe_mode`; the sealing, the core's; a `Body` of the channel the request arrived on, a DC API body a JSON object, a form from `FormBody::of`; declared `wallet_metadata` names alone; the endpoint is the route's; A.4's errors the core's; each breach a `Fault` caused by its `RouteBreach` | a mode name twice on one channel, or an answer and an error registration of one name by modes of different types; an error mode over the DC API; a DC API mode with `wallet_metadata` names; a name another part declares or the core writes | `ModeHost<H>`'s, `ErrorModeHost<H>`'s, taken through `HostedMode<H: Build>`, `HostedErrorMode<H: Build>`; `jwe_mode`'s registration `JweHost` | `match`, `resolve` | the core's `dc_api`, `dc_api.jwt`, `direct_post.jwt`, `direct_post` | `TestMode` |
| `PostContribution`, `PostContributionHost` | `wallet_metadata` members and POST parameters (§10.1, §5.10) | none | declared names alone (`MetadataRefused::Undeclared`) | a name twice; the core's members and parameters | `PostContributionHost<H>`'s | `uri` | a profile's or a deployment's | `TestPostContribution` |
| `AnswerReader` | the Response URI's answer members (§8.2) | `AnswerMembers`: its declared members alone | a refusal returned as `AnswerError::Reader` | a name twice; `redirect_uri` | none | `uri` | siros-webuild's `Cs02ErrorAnswer` | `TestAnswerReader` |
| `HashAlgorithm` | a transaction data hash algorithm | the entry's bytes | the digest's length against `octets` (`HashesError::Digest`) | a name twice; a transaction data build without `sha-256` | none | `transaction-data` | the core's `Sha2`, `Sha3`, `Blake2`, `K12` | `TestHash` |
| `ScopeQuery` | a scope value's DCQL query (§5.5) | none | the query through the DCQL reader when the registry builds | a scope value twice; a query id two queries share | none | `uri` | a deployment's | `TestScope` |
| `Has`, `MayHave` | a build's host struct | | presence by the slot's type | | | `resolve` | siros-integration's builds; `test_host!` | |
| `Platform`, `Haip` | the host: the app's clock, keystore, prompts and cryptography | `Credential`, `Signed`, `VerificationKey`, `RouteKey` | `SealedJwe` parsed; `verify` and `encrypt_jwe` called for what the statements name alone | | | `resolve` | the app | `TestPlatform`, `TestHaip` |
| `RequestDecryption` | the host, for `EncryptedRequests` | `EphemeralKey`, `CompactJwe` | the drawn key's JWK public and on a stated curve; the JWE's `alg` and `enc` against `decrypts` | `RequestPost` or `EncryptedRequests` twice; `EncryptedRequests` without `RequestPost` | | `request-decryption` | the app | `TestRequestDecryption` |
| `Paso`, `RandomIds`, `IssuerTrust`, `CoseEncrypt` | the host, for siros-paso | `SignalType`, `AgreeableKey`, `X5c`, `RootCertificate` | `SealedCose` parsed, its `enc` one `encryptions` states | | | siros-paso; `IssuerTrust` and `CoseEncrypt` in every `resolve` build, the sealing under `sealed-signals` | the app | siros-paso's `TestPaso`, `TestRandomIds`, `TestIssuerTrust`, `TestCoseEncrypt` |
| `DeviceMac` | the host, for siros-mdoc | `SessionTranscriptBytes` | | | | siros-mdoc | the app | siros-mdoc's `TestDeviceMac` |
| The effects: `Evaluation`, `Resource`, `Decision`, `Fetch` | the caller's loop | the step's `Slots` | one answer of the question's kind per slot | | | `resolve` | `_guide::caller` | siros-testkit's trust service |
| `Explain`, by `#[derive(Explain)]` beside thiserror's, or by hand (section 4.13) | every error type of a crate | | an id once in its crate (E0428) and once across the build (`CheckError::Repeated`, I27) | | | siros-explain | every wallet crate | |
| `Message`, by `#[derive(Message)]` (section 4.14) | every statement of a crate | | an id once in its crate (E0428) and once across the build (`CheckError::Repeated`, I27); every id worded (`Context::check`, I30) | | | siros-i18n `derive` | the core, siros-paso, siros-qes | siros-testkit's `DoubleText` |

The `# Implementing` sections state these contracts:

- **`Mode`, `ModeHost<H>`, `ErrorModeHost<H>`.** `name`, `channel` and `metadata_names` are
  constants; a DC API mode declares no metadata name. `rules` returns the mode's refusals over
  the request and the Verifier's metadata, each with its rule's code; the core lists them after
  C6. `encryption` chooses once among the request's `VerifierKeys` under the sealing
  statement it receives, and returns C7 when its rule accepts none; a mode registered with
  `mode` returns `Plain`, one registered with `jwe_mode` `Jwe`, and the core checks the choice
  and seals. `wallet_metadata` writes the declared names from the same statement. `answer`
  wraps the `AnswerContent` in a `Body` of the mode's channel: a DC API body through
  `DcApiData::of`, a POST body through `FormBody::of` and `PostBody::form`, or `PostBody::of` for
  another media type. `error`, for a URI mode registered with `error_mode`, wraps the
  `ErrorContent` in a `PostBody`; the core writes A.4's error over the DC API. The mode's host
  bounds are the modules it calls. The core's four modes are the examples.
- **`ResponseType`.** `name` is a `checked!` `ResponseTypeName`; the Authorization Response it
  names carries the VP Token (§8). The parameters it adds come from a `ResponseParameters`.
- **`ResponseParameters`, `ResponseParametersHost<H>`.** `names` is a constant set of
  `ParameterName`s outside `CORE_RESPONSE`, which the registry reads once and keeps; `members`
  writes members of those names alone, each name once, for the response type it receives, each
  value JSON.
- **`PostContribution`, `PostContributionHost<H>`.** `members` and `parameters` are constants
  outside the core's names; `write` returns members and parameters of those names alone.
- **`AnswerReader`.** `names` is a constant outside `redirect_uri`; `read` receives the answer's
  declared members and returns the outcome the wallet shows, nothing, or its rule's refusal.
- **`ObjectRule`.** `check` reads the authenticated Request Object's claims and returns its
  rule's refusal, whose code the Verifier receives (A14); it reaches no key or endpoint.
- **`ClientPrefix`, `PrefixHost<H>`.** `name` is a `checked!` `PrefixName`. `claim` reads the
  `ClientClaim`, refuses with its own rule (A5), and returns a `PrefixClaim`: its evaluations, the
  binding from their decisions (a `VerificationKey` as a public JWK, the Verifier's name resolved
  through the `Context` `bind` receives, facts), and by URI the basis of the `response_uri`. A name
  the context does not word is `Unbound::Unworded`, which ends the authentication with a `Fault`.
  The core checks the `alg` (A7), verifies the signature through the `Haip` the registration reached
  (A8), and binds the endpoint. Every prefix authenticates signed Request Objects.
- **`HashAlgorithm`.** `name` is a Hash Name String of the IANA registry, `octets` its digest
  length; `digest` writes exactly that many octets.
- **`ScopeQuery`.** `scope` is a `checked!` `ScopeValue`; `query` a DCQL query whose
  Credential Query and claim ids no other registered scope query uses (§5.5).
- **`Haip`.** `verifies` and `agreements` are constants, empty for a capability the module
  lacks; `verify` refuses a key that does not fit the signature's `alg`, a point off its curve
  included; `encrypt_jwe` writes a compact JWE to the key under its key agreement and `enc`, a
  fresh ephemeral key and IV per message. The core calls `verify` and `encrypt_jwe` for what the
  statements name alone, and seals an answer to its `RouteKey`'s key and `enc`; siros-paso seals
  an SD-JWT's risk signals to the issuer's key.
- **`RequestDecryption`.** `decrypts` is a constant; `ephemeral_key` draws a fresh key per POST
  on a stated curve, returns its public JWK and keeps the secret behind a `KeyHandle`; `decrypt`
  consumes the key, forgets its secret, and answers one failure for every cause.
- **`Format`.** `placement` states how its proof carries a profile's members, and the format
  writes the members a profile gives where that placement says. `additions` gives a credential's
  types (`ViewAdditions`), which the core hands the profile. `draw` resolves the card's texts
  through the `Context` it receives.
- **`Profile`.** `members(placement)` places the profile's members by the kind; the profile
  names no format. `bind` resolves its overlay's and header's texts through the `Context` it
  receives.

**Guides.** siros-openid4vp's doc-only `_guide` module: `_guide::caller` drives a request from
arrival to delivery, by the DC API and by URI, effects included (section 5's flows);
`_guide::extending` writes a prefix, a format, a profile, a response type and its parameters, a
mode, a POST contribution, an answer reader, a Request Object rule, a hash algorithm, a scope
query and a host. Each example compiles.

**Item rules** (Rust API Guidelines): a summary line; `# Errors` on each fallible public function
(C-FAILURE); `# Examples` on the entry points, with `?` (C-EXAMPLE, C-QUESTION-MARK); intra-doc
links (C-LINK), with `rustdoc::broken_intra_doc_links` denied; implementation details hidden
(C-HIDDEN); complete Cargo metadata (C-METADATA). Items document the present API. docs.rs builds
with every feature and `--cfg docsrs`, and `doc(cfg)` labels each gated item with its feature.
Edition 2024 merges a crate's doctests into one binary, so the examples add one build per crate to
the suite.

Gate: I26.

### 4.13 Errors as messages

Decisions 18 and 21. The plan imposes a trait contract on errors and leaves their shape to each
crate. Every error a crate exposes implements `Explain`: a stable id, which the wallet's wording
keys its text by, and named arguments, which that text reads. The wallet resolves the End-User's
text through its `Context` (section 4.14). `Display` stays the English text, written for a log
line and, sanitized, for the Verifier's `error_description`, which RFC 6749 §4.1.2.1 confines to
ASCII and the Verifier's developer reads.

Prior art. miette's `Diagnostic` adds a trait to thiserror's errors through a derive of its own,
with stable codes (`#[diagnostic(code(…))]`) and transparent wrappers. Its codes come without
arguments, though. Google's AIP-193 gives each error a stable `reason` within a `domain`, and its
dynamic values as `metadata` from which clients localize. Project Fluent keys each message by an
identifier with named arguments. No established crate maps thiserror's variants to message
identifiers with arguments: rust-i18n-derive maps variants to keys without arguments, and
fluent-i18n translates inside `#[error]`, which ties a library to its translations.

**The add-on: siros-explain**, on std. It names its derive crate, and inventory under `check`.
Every wallet crate depends on it; a backend crate does not need it.

```rust
pub trait Explain: std::error::Error + Send + Sync + 'static {
    /// `err.<scope>.<id>`: stable across releases; a changed meaning takes a new id.
    fn id(&self) -> &'static str;
    /// Gives `arg` each argument: its key and its value.
    fn args(&self, arg: &mut dyn FnMut(&'static str, &dyn core::fmt::Display));
}
impl std::error::Error for Box<dyn Explain> { /* source() forwards */ }
/// A plug-in's error crosses the core boxed.
impl Explain for Box<dyn Explain> { /* forwards */ }

/// Once, at the root of every crate that derives `Explain` or `Message`.
siros_explain::scope!("openid4vp");
```

`scope!` defines a crate-private `macro_rules! __siros_scope` with two arms: `(err "x")` gives
`concat!("err.", scope, ".", "x")`, and `(msg "x")` gives `concat!(scope, ".", "x")`. The derives
call `crate::__siros_scope!(..)`, so a crate without `scope!` fails to build at its first derive.
A crate's scope is its name's root: `openid4vp`, `x509`, `webuild`, `qes`, `sdjwt`, `mdoc`,
`credman`, `testkit`, `paso`, `ts12`, `cldr`, `syntax`, `i18n`. The features: `derive`, the
default, gives `#[derive(Explain)]` from siros-explain-derive, serde's form; `check` serves test
builds alone (section 4.14).

`#[derive(Explain)]` sits beside `#[derive(thiserror::Error)]`, which writes `Display` from the
`#[error("…")]` template:

```rust
siros_explain::scope!("openid4vp");

#[derive(Debug, thiserror::Error, Explain)]
pub enum RoutingRule {
    #[error("P1 response_type is absent")]
    #[explain(id = "routing.p1_absent")]
    ResponseTypeAbsent,
    #[error("C5 response_mode {mode} is no mode the wallet answers in on this channel")]
    #[explain(id = "routing.c5")]
    Mode { mode: String },
    #[error("P6 state holds a character outside URL-safe ASCII at {at}")]
    #[explain(id = "routing.p6")]
    State { at: usize },
}
```

`RoutingRule::Mode`'s id is `err.openid4vp.routing.c5`, and its one argument is `mode`.

- **Ids.** Each struct and each enum variant carries `#[explain(id = "…")]`, any non-empty text,
  dots allowed, or thiserror's `#[error(transparent)]`. The id is `crate::__siros_scope!(err "…")`
  over that text alone. A variant renamed with an unchanged meaning keeps its id.
- **An id once.** Per id the derive emits a `#[doc(hidden)] #[macro_export] macro_rules!
  __siros_explain_id_<text>`: `<text>` holds the id's ASCII alphanumerics as written and every
  other byte as `_xx`, `_` itself escaped. The escape is injective, so an id used twice in a crate
  defines one macro twice and fails the build (E0428). Across crates, `Context::check` refuses
  two rows of one id, the mark of two crates that chose one scope (`CheckError::Repeated`, I27).
- **Arguments.** A named field is an argument keyed by its name, a raw identifier's `r#` stripped. A
  field marked `#[source]`, `#[from]`, `#[backtrace]` or `#[explain(skip)]`, and a field named
  `source`, stays out. The derive refuses a field spelled `r#source` with "write `source`": thiserror
  takes the field spelled `source` as the error's source and `r#source` as no source. A tuple field must carry one of those four marks; the derive refuses any
  other with "an argument is a named field: name it". An argument's value is its `Display`, numbers,
  dates and amounts in their literal form (`1234.5`, `2026-09-02`, `EUR`); a type without `Display`
  fails to build (E0277). A secret type implements no `Display`, so the derive cannot take it as an
  argument (E0277). A field spelled `Option<T>` (also `std::option::Option`, `core::option::Option`)
  gives its value when `Some` and `""` when `None`.
- **Transparent.** A `#[error(transparent)]` variant holds exactly one field, which implements
  `Explain`; `id()` and `args()` forward to it.
- **The derive refuses**, each with a span: an `id` on an enum; a variant with neither `id` nor
  transparent; an `id` beside transparent; a field attribute on a transparent variant; an unknown
  key; a key given twice; an empty id; a union.
- **Generics.** The impl copies the type's generics and where-clause, and adds `Ty<..>: Error +
  Send + Sync + 'static` and `FieldTy: Display` per argument (`T: Display` for an `Option<T>`
  argument).
- **A cause stays a cause.** A field holding a nested error (`cause`, `rule`, `reason`,
  `reasons`, `refusals`, `failure`) is `#[source]` or `#[from]` when it is the cause, and
  `#[explain(skip)]` otherwise. A test that looks for an inner cause walks `Error::source` and
  reads each `id()`.
- **A hand-written `Explain`** serves an error the derive does not fit, and forwards to the error
  it holds: `Refusal`, `Exclude`.
- **The hooks require it.** `Profile::Finding`, a format's refusals, a mode's and a Request Object
  rule's `RequestRule`, an `AnswerReader`'s outcome and refusal, and every host module's error type
  are bounded by `Explain`, so a plug-in cannot hand the core an error without an id.
- **An error travels as itself.** A refusal holds its rule (`Refusal::new(rule)`, whose code is
  the rule's own: `RequestRule::code`), a failed proof its cause, a failed presentation its
  reason. The Verifier receives `code` and the rule's sanitized `Display`, written when the error
  response is. An error the End-User sees resolves through the wallet's `Context` (section 4.14).
- **A contract breach** is a `Fault(Box<dyn Explain>)`, transparent. `Fault::new` boxes the crate's
  own fault error: each crate that faults derives one with `#[explain(id = "fault")]`, so its id is
  `err.<scope>.fault`. The fault error holds its `Detail` as a skipped field and its cause, when it
  has one, as its `#[source]`. A `Detail` is the log line's text, a formatter that owns its values:
  `detail!("{id}: no view", id = id.to_owned())`. siros-testkit's `fault(detail)` and
  `caused(detail, cause)` give a test's own plug-ins `err.testkit.fault`.
- **An exclusion** is `Exclude::new(rule: impl Exclusion)`: its id, arguments and source are the
  rule's, which `Exclude::rule` gives. `Exclusion: Explain` adds `clause() -> Clause`, the clause of
  the profile's specification the rule applies. `Exclude::clause` and siros-paso's
  `Outcome::clause`, `Unsupported::clause`, `NotCompatible::clause` and `Excluded::clause` return
  it.
- **A received value a rule names** is a `ReprItem`, a `ReprOption` when the request may leave it
  out, or a `ReprList`. Its `Display`, the argument, writes the value as its sender wrote it:
  nothing for an absent `ReprOption`, and `, ` between a `ReprList`'s items. `repr_text()` writes it
  for the rule's English text, in Python's `repr`: `#[error("… {}", .names.repr_text())]`. A claims
  path in a PaSO error is a `ReprItem`: `Mismatch`, `Unsupported::{PathTwice,
  ValueTypeWithoutDisplay, ClaimLabel, MandatoryLabelOnly}`, `NotCompatible::{ValueType,
  PayloadDirectional, Uncovered, MandatoryAbsent, TemplateNotString, PaymentRequired,
  GenericPayment, MandatePayment}`, `ArrayAt::Claim`, `RenderedAt::Claim`. A PaSO error holds the
  display array or the rendered label it names as a skipped field: its log line writes the
  position's JSON locator, and a wallet that downcasts the error words it through `ArrayAt` or
  `RenderedAt`.
- **Every other text the core shows is a statement**, which derives `Message` (section 4.14). A
  type that derives both `Explain` and `Message` fails to build (E0119), since `Message` holds an
  impl for every `Explain`.
- **Rows for the wallet's test.** Under `check` the derive registers one row per id, with its
  argument keys, through `::siros_explain::__row!`, which expands to nothing without the feature;
  `Context::check` reads them (section 4.14).
- **Ids are stable.** A message whose meaning changes takes a new id.

**The utility types: siros-syntax.** A type that holds a rule refuses a value that breaks it, and
an argument writes a value in its literal form. siros-syntax holds those types; its errors derive
`Explain` under `scope!("syntax")`.

```rust
/// `checked!(ErrorCode, "invalid_request")`: the value of a type's `const fn new(&'static str)
/// -> Option<Self>`, made when the crate builds; a text the rule refuses fails the build (E0080).
macro_rules! checked { /* … */ }

/// Values under distinct keys, in the order given; `Keyed::new` refuses a repeated key, and `map`
/// and `try_map` keep the keys.
pub struct Keyed<K, V>(Vec<Entry<K, V>>);
/// A value under its key: `Entry::new(key, value)`, `key()`, `value()`.
pub struct Entry<K, V> { key: K, value: V }
#[derive(Debug, thiserror::Error, Explain)]
#[error("{key} is given twice")]
#[explain(id = "repeated")]
pub struct Repeated<K> { pub key: K }

/// One value or more: `AllOf::new` refuses an empty list, and `one`, `and` and `map` keep one
/// value or more.
pub struct AllOf<T>(Vec<T>);
```

Each value type writes its literal form as `Display`, and its `parse(&str) -> Result<Self,
Malformed>` accepts exactly the texts `Display` writes. `Malformed { of, at }` is the crate's one
format error (`err.syntax.malformed`): `of` names the type, and `at` the position where the text
leaves the form.

| Type | Literal form |
| :-- | :-- |
| `Count` | digits: a natural number of any length |
| `Digits` | one or more digits, leading zeros kept; `Count::from` takes their value |
| `Decimal` | `-?(0\|[1-9][0-9]*)(\.[0-9]+)?`, the fraction digits as written |
| `Currency` | an alphabetic ISO 4217 code |
| `Amount` | `<decimal> <CODE>` |
| `Date` | `YYYY-MM-DD` |
| `Time` | `hh:mm[:ss[.f…]]`; `Second` and `Fraction` are its parts |
| `Offset` | `Z` or `±hh:mm` |
| `OffsetTime` | a time, then an optional offset |
| `DateTime` | `YYYY-MM-DDThh:mm[:ss[.f…]][Z\|±hh:mm]`; a leap second where `DateTime::leap` allows it |

`Currency` reads ISO 4217 List One, the table of current currencies and funds: siros-syntax's
build script reads it from `list-one.xml`, the file SIX publishes for the ISO 4217 Maintenance
Agency, published 2026-09-17 (section 4.14, I34). One table-driven property test holds, per type,
that `parse` gives back the value `Display` wrote.

`wallet-core-design/scratch/explain-sketch/` holds the prior art: `scope!` in `explain/src/lib.rs`
(lines 21 to 37) and the id marker, whose repeat is E0428, in `i18n-derive/src/lib.rs`
(`marker`); both compile. `sigs/src/explain.rs` sketches the plan's `ErrorCode`, `RequestRule`
and `Refusal`. Gate: I27.

### 4.14 Messages and their texts

Decisions 19 and 21. The wallet resolves every text the End-User sees through its `Context`, and
the app shows the resolved `Text` as given. A `Context` holds the wallet's MessageFormat 2 sources
for one locale, and `Context::resolve` alone makes a `Text`, from an error or a statement. Every
output the core gives holds resolved `Text`, and every extension point that writes a text receives
the wallet's `Context`. A record commits to the digest of the texts its entry showed, so the
matcher's pick, phase 2 and an auditor agree on what the End-User saw.

**Where the texts live** (siros-wallet-core `93e5e3c`). The crates hold no message source and no
wording: each crate declares its errors (section 4.13) and its statements as types, and the
wallet's sources give every text. The core gets no say on what gets said (the owner): the wallet
provides every message's text in every locale, English included, outside the core. Each
message's documentation names the situation it reports and its arguments. siros-testkit's test
app stands in for the wallet: its sources in `locales/` word, in English and German, every statement
the workspace's tests link, and hold CLDR's format options for both languages. siros-zkp-req is the
colleague's crate, outside the core's format and profile extension points; its texts and the
`zkp_req` module's statements belong to zkp_req's plan (Appendix A).

**Statements.** Every text the core shows beside its errors is a statement: an id and arguments,
as an error is (section 4.13).

```rust
pub trait Message {
    fn id(&self) -> &str;
    fn args(&self, arg: &mut dyn FnMut(&str, &dyn Display));
}
impl<E: siros_explain::Explain + ?Sized> Message for E { /* forwards */ }
/// A crate with statements alone calls `siros_i18n::scope!`.
pub use siros_explain::scope;
#[cfg(feature = "derive")] pub use siros_i18n_derive::Message;

// siros-openid4vp, whose root holds `siros_explain::scope!("openid4vp")`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Message)]
pub enum ClaimText {
    /// A byte string, shown by its `length` in bytes.
    #[message(id = "wallet.bytes")]
    Bytes { length: Count },
    /* … */
}
```

- **The derive.** `#[derive(Message)]` reads `#[message(id = "…")]` on each struct or variant and
  gives the id `crate::__siros_scope!(msg "…")`: `ClaimText::Bytes` is `openid4vp.wallet.bytes`.
  Its field rules are `#[derive(Explain)]`'s for named fields, `Option` and `Display`, with
  `#[message(skip)]`. A tuple field must carry `#[message(skip)]`. The derive fails the build on an
  id used twice in a crate (`__siros_message_id_<text>`, E0428) and registers rows under `check`.
- **A value shown alone** travels in a statement that carries its literal text, a credential's or
  a request's: `ClaimText`. The wallet's wording applies `:number`, `:siros:date` or nothing to
  it. Every displayed string goes through a statement.
- **The statements.** The core's `WalletText`, `ClaimText` and `BooleanText`; siros-paso's
  `Title`, `Confirm`, `Section`, `MandateLabel`, `Frequency`, `ArrayAt`, `RenderedAt` and
  `ValueText`; siros-qes's `QesTitle` and `QesText`; siros-testkit's `DoubleText`. siros-x509
  shows the Verifier's name through `ClaimText::Text`.

| The core's statement | Id | Its text |
| :-- | :-- | :-- |
| `WalletText::{Deny, Share, None, Credential, RequestTitle, Claim, Null}` | `openid4vp.wallet.{deny, share, none, credential, request_title, claim, null}` | the denial action; the confirm action and the title of a request without a transaction; the empty choice; a card without a name; a claim whose path names no member; a claim's `null` |
| `BooleanText::{Yes, No}` | `openid4vp.wallet.{yes, no}` | a boolean |
| `ClaimText::Text { value }` | `openid4vp.wallet.text` | a string as written |
| `ClaimText::Number { value: ExactNumber }` | `openid4vp.wallet.number` | a number, a `Count` or a `Decimal` in its literal form |
| `ClaimText::Date { value: Date }`, `ClaimText::DateTime { value: DateTime }` | `openid4vp.wallet.date`, `openid4vp.wallet.date_time` | a date, a date and time |
| `ClaimText::Bytes { length: Count }` | `openid4vp.wallet.bytes` | a byte string, by its length in bytes |
| `ClaimText::Label { label }` | `openid4vp.wallet.label` | a label, a title or a name the credential's metadata writes, or a member name standing in for a label, as written |

**Contexts.**

```rust
#[derive(Debug, Clone)]
pub struct Context { /* the modules of one locale */ }
impl Context {
    /// MF2's Default Bidi Strategy.
    pub fn new() -> Self;
    /// The app's bidi strategy.
    pub fn bidi(self, bidi: Bidi) -> Self;
    /// One resource file, loaded whole.
    pub fn module(self, source: &str) -> Result<Self, LoadError>;
    /// The first module's `@locale`.
    pub fn locale(&self) -> Option<&LocaleTag>;
    pub fn resolve(&self, message: &dyn Message) -> Result<Text, ResolveError>;
    #[cfg(feature = "check")] pub fn check(&self) -> Result<(), CheckError>;
}
pub enum Bidi { Default, None }

/// `Display` writes the spans' text; `spans()` gives them styled.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Text(Vec<Span>);
impl Text { pub fn spans(&self) -> &[Span]; }
pub struct Span { pub text: String, pub styles: Styles }
pub enum Style { Strong, Emphasis, Underline }
/// A set of styles: `empty()`, `with(Style)`, `contains(Style)`, `iter()`.
pub struct Styles(/* a set */);

/// A resource value that resolves to exactly `text`.
pub fn escape(text: &str) -> String;
```

- **Loading.** `module(source)` loads one message resource file whole, after the MessageFormat
  working group's resource draft. Its metadata before a `---` line names its locale (`@locale`) and
  the language's direction (`@dir ltr` or `@dir rtl`). Then each entry is a key and its MF2 message;
  a `[section]` line prefixes the keys that follow it, and indented lines continue a message. A
  key's full id is its section's prefix, a dot and the key: `[err.ts12] expired = …` words
  `err.ts12.expired`. A section `[formats.<f>]` holds the options of format `<f>` as text, a table
  as a value over several lines, one entry per line. MF2 is stable since CLDR 47 for its syntax and
  data model; since CLDR 49 its functions `:string`, `:number`, `:integer`, `:offset`, `:currency`
  and `:percent` are stable, and `:date`, `:time`, `:datetime` and `:unit` are Draft. A module is
  parsed and checked when it loads, all of it.
- **NFC.** With feature `nfc`, a context holds names, variant keys and the literals a `:string`
  selector compares in Unicode Normalization Form C, as MF2 compares them, and a message's argument
  keys with them. Without it, the context holds each as written. Text, a placeholder's literal and
  an argument's value stay as written in both builds. `module_in_nfc(source)`, under `nfc`, loads a
  module as `module` does and refuses the first name, variant key or selector literal NFC changes
  (`LoadError::Unnormalized { id, text }`). A module it loads resolves to the same texts in a build
  without `nfc`, the matcher's.
- **`LoadError`**, each naming what it refuses: `Syntax`, resource or MF2 syntax, an MF2 data-model
  error, or markup that does not nest; `Repeated`, an id the context or the module already words, a
  format option given twice, or a `[formats.<f>]` section the context already holds; `Locale`, a
  module whose `@locale` is absent or differs from the context's; `Function`, a call of a function
  the build does not compile in; `Option`, a call whose format options no module loaded so far
  defines; `Format`, a `[formats.<f>]` section the build's format refuses (`FormatRule`); `Call`, a
  call its function refuses when the module loads, MF2's message function errors (`Refusal`);
  `Unnormalized`, a name, a variant key or a selector literal NFC changes, which `module_in_nfc`
  refuses. The wallet loads its formats first.
- **Resolving.** `resolve` finds the message's id among the loaded modules and evaluates its pattern
  over the message's arguments: literal text, placeholders, selection, markup and bidi isolation.
  `ResolveError`: `Unknown { id }`, an id no module words; `Unresolved { id, key }`, a pattern that
  reads an argument the message does not give; `Operand { id, function }`, a function that refuses
  its operand's text; `Option { id, function, option }`, a function that refuses the text an
  argument gives for an option; `Argument { id, key }`, a message that gives a key twice, or a value
  whose `Display` fails.
- **Text.** A `Text` is styled spans, the styles MF2 markup opens (strong, emphasis, underline),
  which the frontend renders deterministically, one fixed presentation per style. `Span.styles`
  is a set, since PaSO's `mini_markdown` nests strong and emphasis. `Display` drops the styles: the
  matcher's Credential Manager fields draw that plain text.

```text
# the app's locales/cldr/en.mf2 (siros-testkit's test app), loaded first
@locale en
@dir ltr
---
[formats.number]
zero = 0
decimal = .
group = ,
minus = -
plus = +
grouping = 1
cardinal =
  one: i = 1 and v = 0
ordinal =
  one: n % 10 = 1 and n % 100 != 11
  two: n % 10 = 2 and n % 100 != 12
  few: n % 10 = 3 and n % 100 != 13
pattern = #,##0.###

# the app's locales/en/openid4vp.mf2 (siros-testkit's test app)
@locale en
@dir ltr
---
[openid4vp.wallet]
deny = Cancel
bytes =
  .input {$length :integer}
  .match $length
  one {{{$length} byte}}
  *   {{{$length} bytes}}

[err.openid4vp.routing]
c5 = The service asks for an answer by {$mode}, which this wallet cannot send
```

**Arguments are text.** Every argument reaches the context as its `Display` text, and `{$x}` is
`:string`, which takes it as given. `:number` and `:integer` parse a number literal and show its
fraction digits as written, so an argument's digits are exact: `42.50 EUR` shows `42.50`. A literal
operand in a message takes the pattern's defaults (ECMA-402). `:currency` takes the number operand
and a `currency` option, literal or variable (`{$amount :currency currency=$code}`), checked against
ISO 4217 List One; a variable's code outside it gives `ResolveError::Option`. A wallet words an
amount as it chooses: through `:currency`, or as `{$amount} {$currency}`, its digits as written and
its code. `:siros:date`, `:siros:time` and `:siros:datetime` parse siros-syntax's ISO 8601 forms
(section 4.13) and take a `length` option (`short`, `medium`, `long`, `full`); a time without an
offset stays unzoned. Their `siros` namespace keeps them apart from MF2's Draft `:date`, `:time` and
`:datetime`. A function that refuses its operand's text gives `ResolveError::Operand`. An `Option`
argument that is `None` reads as `""`, so a message that selects on absence selects on the empty
text.

**The format functions** are the build's features: `number`, `currency`, `offset`, `date`. A build
compiles the functions its crates and its app turn on, and a module that calls another fails to load
(`LoadError::Function`). Each function reads its options from the context's `[formats.<f>]` section.
MF2's own function model is the prior art: default functions, and further ones an implementation
adds. Feature `conformance` adds MF2's test functions (`:test:function`, `:test:select`,
`:test:format`), which siros-i18n's conformance tests call.

**Outputs hold `Text`.** A consent entry (`Card`, `Row`, `Overlay`, `Header`, `TransactionHeader`),
a `StaticEntry`, and a `ClientBinding`'s and a `Verifier`'s name hold resolved `Text`;
siros-credman's Credential Manager entries carry the same texts. Every extension point that writes a
text takes `&Context` and returns `Text`: `FormatQuery::draw`, `Profile::bind`, the claims kit,
`PrefixClaim::bind`. `Match::run`, `Views::of`, `Prepared::prepare` and `Pending::authenticate` take
the wallet's `Context`, and `wallet_header` and `Selection::header` resolve a request's `Header`
through it. A profile's `Bound` holds its resolved rows, header, title, actions and hint, and what
its record attests. In the shipped crates `Context::resolve` is the one maker of a `Text` (I28).

**The language.** The wallet picks the locale by the `Context` it passes, and the core uses that
one context for a presentation. Fallback languages, and whether a presentation must stay in a
language the End-User understands, are the wallet's to decide when it builds its context
(decision 19).

- **The priority list** is the languages the End-User understands, in order, as the app gives it;
  the core uses it as given. `Env` holds it (`priority`), and the registration holds it for the
  matcher. It picks an issuer's display entry (`format_entry`) and PaSO's locale (View §4). `Env`'s
  documentation suggests the app's practice: put each tag's generic form right after it, the
  language with its script if the tag names one (`[en-US, en]`; `zh-Hant-TW` then `zh-Hant`), so
  that texts tagged by language match a reader whose platform names a region.
- **PaSO's locale.** siros-paso selects a transaction's locale as View §4 writes it, for PaSO's
  metadata and for TS12's, which converts to it with its tags read as TS12 means them (section
  4.10.2's display table). For each tag of the priority list in order, every `display` array of
  the transaction type's claims and UI labels takes the entry RFC 4647 Lookup (§3.4) finds with
  the tag as the range over the array's tagged entries, else its first entry without a locale
  (its default entry); an entry a template with an absent claim discards takes no part (View §3).
  The first tag whose every array matches is selected, its matched entries render, and no later
  tag is tried. A default entry is a match: the tag stands when some or all arrays matched through
  their default entries. When no tag matches every array the credential is excluded (View §4);
  when only discarded entries stop every tag, the entry is not compatible (View §3). The selected
  tag is `display_locale` (Core §6.1, §7.2): the selector of the metadata's i18n entries, which a
  verifier replays over the metadata the record commits to (`metadata_integrity`) and the payload
  to reconstruct the entries the End-User saw. The owner: "for paso, the point is to save the
  selector for the i18n entries so it can be deterministically replayed", and "paso should be
  respected as written, figure it out, it was well studied". The converted source declares the
  context's locale, so it loads into the wallet's context; the selected tag stays in
  `display_locale`.
- **Matching.** `format_entry`'s basic filtering (RFC 4647 §3.3.1) lets a tag of the priority
  list match an entry whose tag equals it or extends it: `en` matches `en`, `en-US` and `en-GB`;
  `en-US` matches `en-US` and its extensions, and never `en` or `en-GB`. Among several matching
  entries, the one equal to the tag, else the first in the array's order. The owner set it: "en
  should match enUS or enGB", "but not the other way around", and "it is expected modules define
  things as en and only en-US or en-GB if they want more precise variants, wallets should request
  an array in roder of preference, and if they request a specific they should generally also put
  the generic after [en-US, en]". PaSO's arrays keep View §4's Lookup over the tags their authors
  wrote for it. WE BUILD's TS12 example tags its claim labels `en-GB` beside no `en` and its action
  labels `en`; TS12 was not written for PaSO, and its `en-GB` labels are English, which
  siros-ts12's conversion tags `en`. View §4 then presents the example to every list whose Lookup
  reaches `en` (`[en-US, en]`, `[en-US]`, `[en-GB]`, `[en]`) and excludes it for a list without
  English.

**A credential's display.** The claims kit reads a credential's display from the view's `metadata`
and its `issuer_display`. Display metadata holds plain texts: SD-JWT VC Type Metadata's `display`
and `claims[].display`, and OpenID4VCI's claims display. The card shows each as written through
`ClaimText::Label`: the display entry's name as the title, each claim's label, and the subtitle.

- `format_entry` takes a display array's entry for the wallet's locales: RFC 4647 Lookup over the
  priority list (`Env.priority`), then basic filtering, then the entry without a locale. Format and
  OpenID4VCI entries form a single list, the format's first, so Lookup reaches OpenID4VCI's `en`
  before filtering reaches the format's `en-US`.
- An array answering no language gives the kit's next choice: the wallet's word for a title
  (`WalletText::Credential`), the member name for a label, the default icon. A format's entry
  stating no text, and a label with no visible character (`TextError::Empty`), give the next
  choice too.
- A card's subtitle takes the name of the view's `issuer_display` entry, then the view's `issuer`.
- A refused text excludes the credential at the query (`FormatQuery::displayable`,
  `ExcludedBy::Display`). Registration admits every text. `CardError::Text` serves a direct
  `ClaimsQuery::card`.
- A claim's value shows through `ClaimText`: a text as written, a JSON number's literal, a date or
  a date-time in ISO 8601. `ClaimText::Bytes { length }` shows a byte string by its length, which
  the mdoc view's `byte_strings`, `{"path", "length"}`, states. `Node::natural` writes it.

**Converters write MF2 source** for the Views whose templates, markup and typed values a plain text
cannot carry: siros-paso's View (`view::convert`, `view::carried`, `view::verified`) and
siros-ts12's view (`siros_ts12::view::convert`, over siros-paso's).

- The source declares the context's locale (`@locale`, from `Context::locale`); a context without
  a module gives `ConvertError::Unlocalized`.
- Each tag of the priority list that View §4 can select is a section `paso.view.<digest>.<tag>`,
  `<digest>` the hexadecimal SHA-256 of the metadata's compact JSON (`ViewId`), so any set of
  converted sources loads into one context. A converter writes one source per digest. Types whose
  metadata is one object share that source, which the registration's writer and reader load once.
- Every issuer text goes through `escape`.
- Every id, name and variant key the source holds is ASCII: the digest, the language tags,
  `claim_<k>`, the UI labels' names, `c<n>`, `c<n>_currency`, `e<j>`, `live`, and the functions'
  and the markup's names. A matcher built without siros-i18n's `nfc` loads the source into the
  messages the wallet loads.
- A typed value calls its function explicitly: `:siros:date`, `:siros:time`, `:siros:datetime`,
  `:currency`. Its format options come from the wallet's modules in the same context.
- `view::convert` checks that the source loads into a clone of the context (`ConvertError::Load`).
- **PaSO's rules.** Each display array is one message of a tag's section, under a claim's
  `claim_<k>` or a UI label's name. Its text is the entries View §4 tries for that tag: one entry's,
  or, for a template an absent claim discards, a selection over each entry's argument `e<j>` (`live`
  or `dead`) whose fallback is the last entry tried. A `mini_markdown` label becomes markup of the
  styles it opens, and a `{n}` placeholder the argument `c<n>`, `""` when the claim is absent. A
  claim's value enters as its literal text: `date`, `time` and `date_time` through `:siros:date`,
  `:siros:time` and `:siros:datetime`; a `currency_amount` as two arguments, its value `c<n>` and
  its currency `c<n>_currency`, through `:currency`; `frequency` and `boolean` as the resolved texts
  of `Frequency` and `BooleanText`; `currency`, `text` and `url` through `:string`. A template label
  holding U+FDD0, the converter's placeholder mark, or U+0000 is unsupported
  (`Unsupported::Reserved`). A label shows a visible character. A fixed label without one leaves
  the metadata unsupported (`Unsupported::ClaimLabel` or `Unsupported::UiLabel` with
  `LabelViolation::Invisible`), a `mini_markdown` label judged by its spans' text. A template label
  whose rendered spans and values show none leaves the entry not compatible
  (`NotCompatible::RenderedLabel`). A rule the metadata breaks leaves the entry not compatible in
  phase 1 (`ConvertError::Metadata`). PaSO View's display types, value types, templates and
  `mini_markdown` parser sit in siros-paso; the core holds no PaSO token (I6).
- **PaSO's values shown alone.** A value outside a template resolves through the statement that
  carries its literal (`Parsed::shown`): `ClaimText::{Text, Date, DateTime}`, `BooleanText`,
  `Frequency`, and siros-paso's `ValueText::{Time, Currency, Amount}`. A template value that joins
  text with typed values resolves each typed value through its statement and shows the joined text
  through `ClaimText::Text`.
- **Binding.** siros-paso renders an entry through the context it receives when that context
  words the entry's first converted label, and otherwise through a clone with the type's
  converted source loaded. The matcher's context holds the source the registration carries, and a
  context refuses an id it already words (`LoadError::Repeated`).

**The registration** belongs to siros-credman: versioned, seekable and read lazily. The owner: "the
credential blob should not be read by reading everything … a binary format that can be lazily
loaded as needed efficiently". Its layout is the OpenType table directory's, with WebAssembly's
magic and version and PNG's signature bytes: a 16-byte header (the magic
`89 53 43 4D 0D 0A 1A 0A`, version 1, the directory's length), a directory of records (kind,
offset, length, name), then the entries' bytes, which tile the rest of the blob exactly.
siros-credman's README (`## Format`) states the layout and the reader's rules in order.

| Code | Kind | Entries | Bytes |
| :-- | :-- | :-- | :-- |
| 1 | locale | exactly 1 | the locale the wallet wrote the registration in, every source's `@locale` |
| 2 | priority | exactly 1 | the End-User's ranked tags, the matcher's `Env.priority` (View §4, `format_entry`) |
| 3 | bidi | exactly 1 | the wallet's bidi choice: `0` MF2's Default Bidi Strategy, `1` none |
| 4 | source | 1 or more | the wallet's sources its matcher needs, in load order, its formats first |
| 5 | transaction | 0 or more, each named by its type, ascending | the type's converted View source |

- **Writing.** Only `Base::load(locale, priority, bidi, sources)` makes a `Base`: it loads the
  sources into one context under the bidi choice, and refuses a source the context refuses
  (`ContextError::Source`) and sources of another locale (`ContextError::Locale`).
  `register::write(&Base, &Keyed<TransactionType, String>)`, under feature `register`, loads the
  base's sources again in their order, then each transaction source into a clone of that context,
  alone and after the sources of the types before it, each through `Context::module_in_nfc`. A
  source byte-equal to an earlier type's loads once, and each type keeps its directory entry. It
  refuses the first base source holding a name, a variant key or a selector literal outside NFC
  (`RegisterError::Source { at, cause }`), then the first transaction source that does not load or
  holds one (`RegisterError::Transaction { kind, cause }`). A distinct source that words an id of an
  earlier type's source is refused (`LoadError::Repeated`). Any set of types a request names then
  loads, and a matcher built without siros-i18n's `nfc` resolves it to the texts the wallet
  resolves. `RegisterError::Name` refuses a type longer than 65,535 bytes and `RegisterError::Size`
  a registration longer than 4,294,967,295 bytes.
- **Reading.** `Registration::open` reads the header, the directory and the base entries, checks the
  format's rules, and loads the base through `Base::load`. `Registration::context(&Request)` reads
  only the source of each registered type the request's `transaction_data` names, and loads each
  into a clone of the base's context, ascending by type, a source byte-equal to one it loaded once
  (I37). A blob that breaks a rule is a `Malformed` naming the rule, whoever wrote it.
- **Emitting.** The matcher passes that context to `Match::run` and `Views::of`, with an `Env` of
  the registration's priority tags. `emit(&Display, &Context) -> Result<Emission, NotEmitted>` lays
  out Credential Manager's entries from the display and the same context. The matcher resolves every
  text itself, through the code path the wallet runs. The emission fails as a whole on the first
  entry that does not emit: `NotEmitted` names the entry and holds the cause, a `ResolveError`
  (`Unshown::Resolve`) or a `NoName` (`Unshown::Field`). Such a cause comes only from a defect in
  the wording or a converter. A defect gets a local abort. The wallet's `Context::check` test proves
  its wording complete.

The registration records the locale it was written in, and the wallet registers again when its
language changes.

**Ad-hoc metadata** (PaSO Proof Metadata §5). A `transaction_data` entry's `metadata` JWT stands in
for the stored metadata for that transaction (§5.4), so its texts depend on the request, and the
matcher handles it. It reads the JWT as it reads a signed request: the payload parsed, unverified
(siros-paso's `adhoc::Carried::read`, over a DC API request alone). `view::carried` converts its
display rules into MF2 source, which the matcher loads into a clone of its context; it runs View
§4 over them and resolves the entry's texts. The wallet verifies the JWT as §5.3 states (the
`typ`, the signature, the key's trust, `iss`, `exp`, the credential binding of §7 step 6, the
type) before it relies on it: in phase 2, and in the URI flow before it converts. In the URI flow
`adhoc::Verified::of` verifies each JWT for each credential through the host's `Haip`,
`IssuerTrust` and `Platform`, `view::verified` converts what it verified, and first match relies on
a JWT for a credential once `PasoProfile::with_verified` holds it verified for that credential. In
phase 2 `ProfileHost::wanted` verifies it before it lists the images to fetch, and the
revalidation refuses it (`PasoFinding::refused`). An entry whose JWT fails is incompatible for the
credential, with no fallback to the stored metadata (§5.3).

**Verifiability.** A record commits to `shown`: the hexadecimal SHA-256 of its entry's shown texts,
every `Text` of its card, header and overlay in field order, under an injective encoding (each
text's presence, its span count, and per span its styles and its text's UTF-8 length and bytes),
which `ShownDigest` documents. `Record::shown` gives it. The matcher writes it into the pick. Phase
2 derives its own records with its own context and refuses a pick whose `shown` differs
(`Finding::Rendered { record }`). The matcher and the wallet resolve through one code path, so equal
sources and equal arguments give equal digests (I31). PaSO's `display_locale` and
`metadata_integrity` keep their meaning beside it.

**The wallet's completeness test.** Feature `check` (siros-i18n's, which turns on siros-explain's)
makes each derive register a row, its id and its argument keys, through inventory: errors in
siros-explain's collection, statements in siros-i18n's. `Context::check()` returns the first of
`CheckError::Repeated { id }`, two rows of one id (two crates chose one scope); `Unworded { id }`,
a row no module words; `Unknown { id, key }`, a pattern that reads a variable its row lacks. The
wallet's one test loads its sources for each locale it ships and calls `check`. Shipping builds
leave `check` off, so the table exists in test builds alone. The rows survive into a rustc-linked
test binary, whose synthetic object keeps `#[used]` statics.

`sigs/src/profile.rs` sketches siros-paso's conversion.

**The engine is the wallet core's own** (decision 19). The shipped crates link no i18n crate; the
ISO 4217 table is SIX's List One, read at build time; established implementations are the tests'
oracles.

- **Why.** Each crate was measured as a delta, added alone to a matcher build (siros-dc-matcher
  `49946a3`, toolchain 1.99.1, its shipped `wasm-release` profile). rust-mf2 3.0.0's runtime adds
  +61,117, of which run-time NFC (3,724), float printing (2,844) and fallback rendering (612) serve
  paths this engine leaves dead: the wallet applies NFC at load alone, numbers keep their literal
  digits, and an error stands where a fallback would. The rest is its own evaluator, catalogue
  format and general number formatting. ICU4X's date formatters add +77,702 to +96,806 and do not
  fit beside the rest. A currency crate's functions add +5,845 for one table lookup. rust-mf2 also has
  one maintainer and shipped three major versions in twelve days.
- **Loading** (wallet and matcher). `Context::module` reads a resource file, parses each message
  by MF2's grammar, checks the data model, and checks each call against the build's functions and
  the format options loaded so far. A load takes memory in proportion to its source: the context
  holds each dot-separated part of an id once under the parts before it, and a message holds each
  call once. It takes time in proportion to its source and, for each use of a call, to the count
  of the calls its operand's value applies.
- **Resolving** (wallet and matcher). `Context::resolve` evaluates a message over its text
  arguments through the build's format functions. Loading and resolving are measured in the
  matcher on their first build (I10).
- **Format options from CLDR.** A build-time tool in Rust reads a pinned CLDR JSON release and
  writes the default text of a format's options in a language: the plural rules, the number and
  currency symbols and patterns, the date and time patterns and names. A wallet's author keeps or
  edits them, and the loader checks them as it checks any resource text. The tool, siros-cldr
  (`publish = false`), refuses any release but 49.0.0 in each of cldr-core, cldr-numbers-full,
  cldr-dates-full and cldr-misc-full, and writes the resource to standard output. The tool's
  output for en, de, es, fr and he is siros-i18n's test fixtures,
  `crates/siros-i18n/tests/cldr/<language>.mf2`, and for en and de
  `crates/siros-testkit/locales/cldr/`. It keeps the currencies of ISO 4217 List One and takes
  their digits from CLDR's supplemental currencyData, TR35's formatting digits. A currency symbol
  takes CLDR's `alphaNextToNumber` pattern when the General Category of its edge character is a
  letter; siros-i18n links icu_properties for that test.
- **Formatting.** A number shows the fraction digits its literal is written with, as ICU4X's
  `DecimalFormatter` does. Every function ignores an option it does not take, `:string` included.
  `:currency` reads `signDisplay`; `:integer` rounds half away from zero. An option's value is a
  literal or a variable's value (MF2's Option Resolution): an argument's text, a literal, or the
  value of the call a declaration binds, evaluated once per resolution: the operand's text for
  `:string` and the date functions, the number after `:integer`'s rounding and `:offset`'s step,
  without an exponent, for the numeric functions. `u:dir` takes `ltr`, `rtl`, `auto` or `inherit`:
  the loader refuses another literal, and a resolution another variable's value
  (`ResolveError::Option`). `u:id` changes no span, and the loader refuses another `u:` option. A date length maps to ICU4X's field sets: year, month and day for `short`
  to `long`, the weekday added for `full`; `medium` is the default. A two-digit year writes two
  digits from 1950 to 2049 and the full year otherwise, as ICU4X 2.4's `YearStyle::Auto` does.
- **ISO 4217.** siros-syntax's build script reads List One from `list-one.xml` (SIX, published
  2026-09-17) and writes each alphabetic code packed in 15 bits, ascending, with its minor units;
  an entry outside List One's form fails the build. In the matcher, a lookup with the code's
  letters and minor units costs +1,165 bytes, against +5,845 for a currency crate's own functions.
- **Oracles.** The message-format-wg test suite (I29), variable option values included; ICU4X 2.4
  over the same CLDR release for numbers, plural categories, currencies, dates and times (I35,
  I36); a second reading of `list-one.xml` for the table (I34). They run in the tests, never in the shipped
  crates.
- **Bidi.** MF2 defines bidi strategies, its default wrapping each placeholder in an isolate
  chosen by the value's direction (U+2066, U+2067, or U+2068 when unknown) and U+2069. A resource
  file's `@dir` gives a language's direction. How a platform draws isolates is the app's to know,
  so the app chooses the strategy (`Context::bidi`), the registration carries its choice for the
  matcher, and `shown` covers the isolates.

Gates: I28 to I31, I33 to I37.

### 4.15 Type audit

Every type the sketches define has one row, and so has every type this plan's code blocks define
beside the sketches: 740 rows. `sigs/siros-explain/` and `sigs/derive/` stand in for siros-explain
and the derives of `Explain` and `Message`. `sigs/src/i18n.rs` and `sigs/src/syntax.rs` stand in
for siros-i18n's and siros-syntax's types. `checks/audit.py` compares the tables with the
inventory, name for name.

```sh
PAT='^\s*(pub(\([a-z]+\))? )?(struct|enum|trait) [A-Z][A-Za-z0-9_]*|^\s*pub(\([a-z]+\))? type [A-Z][A-Za-z0-9_]*'
grep -rnE "$PAT" --include=*.rs sigs host-sketch replace/sigs | grep -v '/target/'   # 729 definitions
awk '/^```rust/{f=1;next} /^```/{f=0} f' proposal.md | grep -E "$PAT"   # 250 definitions,
# 11 of whose names no sketch defines
```

Each type was checked for these classes:

- a constrained primitive in a public field, or a constructor that takes it unchecked;
- a derived `Deserialize` or `Default` that bypasses the check;
- a `Vec` that must be non-empty or unique;
- parallel collections where one keyed structure belongs;
- several `Option`s or `bool`s that encode a sum;
- a tag in one structure and its data in another;
- an integer with a range, or a string with a grammar;
- a variant valid only with another field's value;
- a typestate gap, and a runtime check a type could enforce;
- a check after construction: a `validate`, `check` or `is_valid` over a built value;
- a relational rule outside a step: a value against the request, a key pair, a time against an
  offset;
- a caller list the core matches at run time against a list it made;
- an extension's output the core takes unchecked, or a value an extension can build that the
  core alone binds (an endpoint, a key, a session, a record, a route).

One mechanism serves each family:

- **Checked constructors** with private fields: `parse` or `new` returns `Option` or `Result`, and
  a fixed value goes through `checked!`, which fails the build.
- **Non-empty lists** as `first` and `rest`, or `AllOf`; **keyed lists** as `Keyed`.
- **Typestate steps**, whose output only the step makes: `Envelope::parse` (the routing and the
  registry every later step reads), `Accepted::new` (`QueryContext`), `Prepared::prepare`
  (`AnsweredContext`), `Route::answering` (`AnswerRoute`), `AnswerRoute::session`.
- **Typed slots** the core makes and the caller fills: a step's `Slots` of `Evaluation` and
  `Resource`, filled through `decide` and `fetch`.
- **Core-made values an extension receives** and cannot build: `VerifierKey`, `VerifierKeys`,
  `VerifierMetadata`, `RouteKey`, `ModeRoute`, `RoutedMode`, `Session`, `ClientClaim`, `Decided`,
  `FetchedRecord`, `Answered`, `AnswerMembers`, `ConsentEntry`; and outputs the core checks: a
  mode's encryption choice against the sealing statement, its `Body` (its channel,
  `DcApiData::of`, `FormBody::of`), a hash's digest length, a contribution's names against its
  declaration.
- **Names declared as constants** and checked when the registry builds: a mode's metadata
  names, a contribution's members and parameters, a reader's members, a response parameters'
  names, each against the others' and the core's (`NameTwice`, `NameReserved`).
- **Parsed values at the boundary**: a public JWK the verifying and decrypting modules read
  (`VerificationKey`, `EphemeralKey`), a resource file loaded whole into a `Context`, `HttpsUrl`,
  `SealedCose`.
- **Arguments as named fields**: an error's or a statement's argument names are its fields'
  names, and `Context::check` holds every pattern to them (I27, I30).

Counts: 57 rows fixed, 8 boundaries kept with their reason, 675 holding as built.
The fixes that close a guarantee hole:

- **Answers from a caller list.** A caller's answers matched by position could give a fetch where
  a decision belongs, and a mismatch was a run-time error. A step's `Slots` asks the caller's
  function once per question, so only a complete set of the right kinds exists: only `Slots::fill`
  makes a `Filled`.
- **A refused reading in phase 2.** A query read under a refused mode carried `revalidate` and
  `present`. Phase 2 reads queries through `FormatHost::answer` with an `AnsweredContext` alone.
- **Values of two requests.** `Route::new`, `Request::parse`, `Accepted::new` and
  `Prepared::prepare` took a routing beside the request it belonged to, so a route could pair one
  request's Verifier with another's endpoint. The envelope holds its routing, and each step reads
  it there.
- **Values of two registries.** A `RoutedMode` held an index into the registry `Envelope::parse`
  read, and `Route::new` took a second registry, so another registry's mode could carry the
  answer. The envelope holds the registry it read, and `Route::new`, `Envelope::questions`,
  `Pending::authenticate` and `Prepared::prepare` read it there, typed by the same `H`.
- **Keys off the curve.** The wallet's ephemeral key was coordinates. The decrypting module draws
  the key, keeps its secret behind a `KeyHandle` and returns the public JWK, which the core checks
  is public and on a stated curve; a verification key is a public JWK, and the verifying module,
  which holds the curve arithmetic, refuses a point off its curve. The core links none.
- **An extension reaching what the core binds.** A mode that picked any key and named its
  endpoint could send an answer anywhere; a mode that encrypted itself could write plaintext or
  encrypt to a key of its own. A mode chooses among the request's `VerifierKeys`, the core checks
  the choice against the sealing module's statement and the Verifier's list, seals the answer
  itself and hands the mode the JWE alone, and sends the body to the bound endpoint.
- **A key of other metadata.** A mode can hold the key of a second request it read through the
  core's public flow. The route compares a
  JWE mode's key by identity with the request's key at its place (`RouteBreach::Foreign`).
- **Names read twice.** A response parameters part's `names()` can answer one set when the
  registry builds and another in phase 2. The registry keeps the names it checked
  (`RegisteredParameters`), and phase 2 checks each member against them.
- **Names two parts write.** A `wallet_metadata` member two contributors wrote was found when the
  first POST failed. Each contributor declares its names as constants, and the registry refuses a
  name twice, or one the core writes, when it builds.
- **Names of arguments.** A message could name an argument twice, and a pattern could read an
  argument no message gives, each found when a text was shown. An argument is a named field, which
  Rust keeps distinct, and `Context::check` refuses a pattern that reads an argument its row lacks.

The 8 boundaries:

- `HandoverUri`: any text, since B.2.6.1's hash takes the `response_uri` as written;
  `From<&ResponseUri>` gives the core's flow its checked URI.
- `Point`: its coordinates' lengths are the key rule's and its place on its curve the agreeing
  module's; the matcher, which reads keys in `admits` and C7, links no curve arithmetic (I10).
- `JwsSignature`: its length is its `alg`'s, which the verifying module checks.
- `inhouse_https_url`'s `HttpsUrl`: `f718dc3`'s type, kept verbatim as gate G3's baseline;
  commit 3 removes it.
- `Signature` and `Mac`: the module's output, whose length its algorithm fixes; the core places
  the bytes and reads none, and the differential's doubles write the frozen model's stand-in texts
  (I9).
- `ModelHandover` and `Rebuild`: the frozen model's values as it wrote them, read apart from the
  core's types so the differential's oracle stays independent of the code it checks.

The wallet-rs types the plan keeps: `Timestamp` and `Seconds` admit every `u64`, an instant or a
duration, so their public fields hold no invalid value. `OptionIndex`, `Thumbprint`,
`Authentication`, `AgreeableKey`, `Session`, `Answered` and `ProofRequest` change (section 2's
rows; `sigs/src/kept.rs`, `sigs/src/phase2.rs`). Section 4.9's types named in prose stand in its
code blocks: `HashAlgorithm`, `HashesError`, `MemberValue` and `Item`.

#### siros-openid4vp's signatures (`sigs/`)

| Type | File | Invariant | How it holds |
| :-- | :-- | :-- | :-- |
| `DcApiProtocol` | `arrival` | One of A.1's three DC API protocols | Holds: an enum whose every variant is a protocol of A.1 |
| `DcApiProtocolApi` | `arrival` | Reads a protocol identifier (U1) | Holds: the inherent methods of `DcApiProtocol`; `parse -> Result<_, Unreadable>` |
| `DcApiProtocols` | `arrival` | The protocols the wallet registers, among A.1's three, as the app's configuration picks them | Holds: private slice; only the consts `ALL`, `SIGNED` and `UNSIGNED` make one |
| `DcApiProtocolsApi` | `arrival` | Answers whether the wallet registers a protocol | Holds: the inherent methods of `DcApiProtocols` |
| `Unreadable` | `arrival` | One variant per U rule | Holds: a refusal enum, one variant per rule |
| `DataShape` | `arrival` | What DC API `data` lacks of its protocol's shape | Holds: a refusal enum, one variant per rule |
| `NestedParameter` | `arrival` | A Request Object's member RFC 9101 §4 forbids: `request` or `request_uri` | Holds: a closed enum |
| `ClientIdPlacement` | `arrival` | Where a multisigned request holds `client_id` outside its protected headers | Holds: a closed enum |
| `Received` | `arrival` | The request as it reached the wallet, and the digest of that form | Holds: private fields; only `ReceivedApi::dc_api` and the URI step make one, and each computes the digest |
| `ReceivedForm` | `arrival` | A DC API request with its Origin, or a URI with the Request Object its `request_uri` returned | Holds: an enum of checked parts; only `Received`'s constructors build the one a `Received` holds |
| `DcApiRequest` | `arrival` | A DC API request in its protocol's form (A.3) | Holds: an enum; each variant holds a parsed `Parameters`, `CompactJws` or `JsonJws` |
| `ReceivedApi` | `arrival` | Reads a DC API request into a `Received` (U1 to U3, U10, U16) | Holds: the inherent methods of `Received` |
| `PrefixName` | `authenticate` | A Client Identifier Prefix: one or more `VSCHAR` other than `:`, other than `origin` (§5.9.1, §5.9.3) | Holds: private `&'static str`; `const fn new -> Option`; a plug-in's by `checked!` |
| `ClientClaim` | `authenticate` | A signed request's claim: its Client Identifier, the signature it belongs to, the parameters and the channel | Holds: private fields; only `EnvelopeAuthApi::questions` makes one |
| `ClientClaimApi` | `authenticate` | Reads a claim's parts | Holds: the inherent methods of `ClientClaim` |
| `ClaimChannel` | `authenticate` | The DC API with its Origin, or a URI with its parsed `request_uri` and `response_uri` (§15.8.2, A13) | Holds: an enum of checked references; every variant is a channel |
| `PrefixRefusal` | `authenticate` | A prefix rule a claim breaks, with the prefix the core called (A5) | Holds: a refusal struct; private fields; the core makes it from `ClientPrefix::claim`'s refusal |
| `ClientPrefix` | `authenticate` | A prefix plug-in: names its prefix (§5.9.3) | Holds: a trait; `name` returns a checked `PrefixName` |
| `PrefixClaim` | `authenticate` | A claim's evaluations, then its binding and endpoint from their decisions | Fixed (caller list): `questions` gives `Evaluation`s; `bind` and `endpoint` read `Decided`, the decisions on the claim's own evaluations |
| `Unbound` | `authenticate` | One variant per rule: A6, A12, and a binding's text the wallet's context does not word | Holds: a refusal enum, one variant per rule |
| `BoundEndpoint` | `authenticate` | The DC API, or the request's `response_uri` with what vouches for it | Holds: an enum; `ResponseUri` holds a parsed `ResponseUri` and an `EndpointBasis` |
| `EndpointBasis` | `authenticate` | The framework or the request vouches for a `response_uri` (RFC 6749 §4.1.2.1) | Holds: an enum whose every variant is a basis |
| `ClientBinding` | `authenticate` | The key a prefix binds, the framework's name and facts for the Verifier | Holds: public fields that hold their own rule: a checked `VerificationKey`, a resolved `Text`, an `Object<'static>` |
| `OriginPolicy` | `authenticate` | Accept the platform's Origin, or evaluate it | Holds: an enum whose every variant is a policy |
| `TrustConfig` | `authenticate` | The skew and the Origin policy | Holds: public fields of checked types: `Skew` and an enum |
| `Unauthenticated` | `authenticate` | One variant per A rule, each text led by its rule; A9 a `TimeError`, A13 a `NotHttps`, A14 a `Refusal` | Holds: a refusal enum, one variant per rule |
| `UnauthenticatedApi` | `authenticate` | The A rule's code; A14's the rule's | Holds: the inherent methods of `Unauthenticated` |
| `VerifierId` | `authenticate` | An Origin or a Client Identifier | Holds: an enum of checked `Origin` and `ClientId` |
| `Verifier` | `authenticate` | The authenticated Verifier, its name, facts, metadata and endpoint | Holds: private fields; only `PendingApi::authenticate` makes one |
| `VerifierApi` | `authenticate` | Reads the authenticated Verifier | Holds: the inherent methods of `Verifier` |
| `Pending` | `authenticate` | A request's evaluations, each in its slot beside what asked it | Fixed (caller list; parallel collections): `Asked` holds each claim with its own `Slots` beside the prefix the registry holds; `authenticate` fills them through the caller's `decide` |
| `Asked` | `authenticate` | The Origin's evaluation, nothing, or each signature's claim | Holds: private enum; each variant holds its own slots |
| `Claimed` | `authenticate` | A claim, its prefix and the slots of its evaluations | Holds: private; one structure per claim |
| `Authenticated` | `authenticate` | An envelope whose Verifier the wallet authenticated (A1 to A14), with the Verifier's `VerifierMetadata` or C6's refusal | Holds: a typestate step; only `PendingApi::authenticate` makes one; the metadata is read from the envelope's `client_metadata`, which the `Authenticated` borrows |
| `EnvelopeAuthApi` | `authenticate` | Makes the questions that authenticate the Verifier (A1 to A3, A5, A7, A13) | Fixed (values of two registries): the inherent methods of `Envelope`; prefixes come from the registry passed, the one the envelope was read with, and A7 reads the registration's `Haip::verifies` before any question |
| `PendingApi` | `authenticate` | Authenticates from the answers (A6, A8 to A12, A14) | Fixed (relational rule outside a step): `host` is the registry's `H`, so A8 calls the `Haip` the prefix's registration reached |
| `AuthenticatedApi` | `authenticate` | Reads the envelope and the Verifier | Holds: the inherent methods of `Authenticated` |
| `EntityType` | `effects` | An AuthZEN entity's `type`, non-empty | Holds: private; `const fn new -> Option` refuses an empty text; a plug-in fixes its own with `checked!` |
| `EntityId` | `effects` | An AuthZEN entity's `id`, non-empty, scoped to its type | Holds: private `String`; `parse -> Option` refuses an empty text |
| `Entity` | `effects` | An AuthZEN subject or resource: a type, an id scoped to it, properties (§5.1, §5.2) | Fixed (constrained primitive in a public field): `kind` an `EntityType`, `id` an `EntityId`, each refusing an empty text |
| `ActionName` | `effects` | An AuthZEN action's `name`, non-empty | Holds: private; `const fn new -> Option` refuses an empty text |
| `Action` | `effects` | An AuthZEN action: a name and properties (§5.3) | Fixed (constrained primitive in a public field): `name` an `ActionName`, which refuses an empty text |
| `Evaluation` | `effects` | An AuthZEN access evaluation request (§6.1); it takes a `Decision` | Holds: public fields of `Entity`, `Action` and `Object<'static>`, each holding its rule |
| `Resource` | `effects` | An https URL a profile revalidates with; it takes a `Fetch` | Holds: private `HttpsUrl`; only the core makes one, from a profile's `wanted` |
| `Verdict` | `effects` | AuthZEN's `decision`, true or false (§5.5) | Holds: an enum whose every variant is a decision |
| `Decision` | `effects` | The caller's verdict on an evaluation, with its context (AuthZEN §5.5, §5.5.1) | Holds: public fields of `Verdict` and `Object<'static>`; every pair is a decision |
| `Fetch` | `effects` | A resource's content and media type, or a failed fetch | Holds: an enum; `media` a checked `MediaType` |
| `Sealed` | `effects` | The question kinds are the core's two | Holds: private trait sealing `Ask` |
| `Ask` | `effects` | A question kind and the answer it takes | Holds: sealed trait: `Evaluation` takes `Decision`, `Resource` takes `Fetch` |
| `Slots` | `effects` | One slot per question of one kind, in order | Fixed (caller list): typed slots only the step makes; its continuation fills each through the caller's function, once, in order |
| `Filled` | `effects` | One answer of the question's kind per question, in order | Fixed (caller list): only `Slots::fill` makes one |
| `Decided` | `effects` | A claim's own evaluations with their decisions, in its order | Fixed (caller list): private; only `Pending::authenticate` makes one, from its filled slots |
| `MediaType` | `media` | A `Content-Type` value (RFC 9110 §8.3.1) and its essence, in every build | Holds: private fields; `parse -> Result<_, NotMediaType>` refuses another text, naming the rule; `form` gives `application/x-www-form-urlencoded` and `is_form` tests the essence; `effects` re-exports it |
| `MediaTypeApi` | `media` | Parses a media type and reads its essence | Holds: the inherent methods of `MediaType` |
| `NotMediaType` | `media` | The RFC 9110 rule a text breaks, at its byte offset | Holds: a refusal enum, one variant per rule |
| `Channel` | `envelope` | The DC API with its Origin, or a URI | Holds: an enum; `DcApi` holds a checked `Origin` |
| `Parameters` | `envelope` | A JSON object with unique member names at every level (U3) | Holds: private `RawObject`; `parse -> Result<_, JsonError>` |
| `ParametersApi` | `envelope` | Parses the parameters and reads one | Holds: the inherent methods of `Parameters` |
| `Signatures` | `envelope` | No signature, one JWS with its payload's `client_id`, or a JWS JSON Serialization (A.3.2.2) | Holds: an enum of parsed JWSs; only `Envelope::parse` builds the one an `Envelope` holds |
| `Envelope` | `envelope` | The received request's parameters, signatures and routing, its `client_metadata` as read or C6's refusal, its `nonce` as N1 accepts it or `NonceError`, and the hashes and scope queries of the registry it was read with (U3, U10, U12 to U14, U16, U17) | Fixed (values of two registries): private fields; only `Envelope::parse` makes one; phase 2 reads the routed mode's registration by `ModeHandle`, the name checked, a mismatch a `Fault`; `client_metadata` and the `nonce` are read once, so the rules and the route read one value |
| `NonceError` | `envelope` | Why a request holds no `nonce`: absent, or a value N1 refuses | Holds: a crate-private enum, one variant per cause; `Request::parse` maps it to S3 and N1 |
| `EnvelopeApi` | `envelope` | Parses a received request into its envelope, its routing read over the registry's response types and modes | Holds: the inherent methods of `Envelope`; `parse<H: Build>`; `client_metadata` returns the metadata or C6's refusal |
| `Scopes` | `scope` | The registered scope queries the envelope carries from its registry, in every build | Holds: a private slice of `ScopeEntry`; only the registry makes one |
| `ScopeEntry` | `scope` | A registered scope query as the registry read it | Holds: crate-private fields; the registry builds it from a `ScopeQuery` the DCQL reader accepts |
| `Explain` | `siros-explain` | An error's stable id and its named arguments, each its `Display` | Holds: a trait over `Error`; the derive writes it, its id through `scope!`, and refuses a tuple argument; siros-explain's derive also fails the build on an id twice in a crate (E0428) |
| `RequestRule` | `explain` | A request rule: its error and the one code the Verifier receives (section 4.5) | Holds: a trait over `Explain`; `code` returns an open `ErrorCode` |
| `Refusal` | `explain` | A request rule the request breaks | Holds: private `Box<dyn RequestRule>`; `new` takes a rule |
| `RoutingRule` | `explain` | One variant per routing rule: P1, C5 per channel (`DcApi`, `Uri`), P5, P6 | Holds: a refusal enum, one variant per rule |
| `Context` | `i18n` | The modules of one locale, each loaded whole and checked | Holds: private fields; `module` refuses a source with `LoadError`, and `resolve` alone makes a `Text` |
| `Bidi` | `i18n` | The bidi strategy the app chooses | Holds: an enum whose every variant is a strategy |
| `LoadError` | `i18n` | Why a context refuses a module | Holds: a refusal enum, one variant per rule |
| `ResolveError` | `i18n` | Why a context resolves no text for a message | Holds: a refusal enum, one variant per rule |
| `Message` | `i18n` | A statement's id and its named arguments, each its `Display` | Holds: a trait; the derive writes it, its id through `scope!`; an `Explain` is a `Message` through the blanket impl, so a type deriving both fails to build (E0119) |
| `Text` | `i18n` | A message resolved in a context's locale: its spans, in order | Holds: private spans; only `Context::resolve` makes one (I28) |
| `Malformed` | `syntax` | A text that is no literal of its type (section 4.13) | Holds: a refusal struct; `of` names the type, `at` the byte where the text leaves the form |
| `Currency` | `syntax` | An ISO 4217 currency: its alphabetic code and its minor units | Holds: private fields, a row of the table the build script reads from ISO 4217 List One; only `parse` makes one, and refuses a code List One does not list with `Malformed` |
| `AllOf` | `syntax` | One value or more | Holds: private `Vec`; `new -> Option` refuses an empty list; `one`, `map` and `and` keep one or more |
| `Keyed` | `syntax` | Values under distinct keys | Holds: private `Vec` of `Entry`; `new` refuses a repeated key with `Repeated` |
| `Entry` | `syntax` | A value under its key, in a `Keyed` | Holds: private fields; `Keyed::new` refuses a repeated key |
| `Repeated` | `syntax` | The first key given twice | Holds: a refusal struct; derives `Explain` |
| `Has` | `host` | The host holds module `M` | Holds: a trait; the bound settles presence at compile time |
| `MayHave` | `host` | The build holds module `M` or leaves it out, settled by the slot's type | Holds: a trait; its `Slot` is sealed |
| `Slot` | `host` | A slot a build fills or leaves empty | Holds: sealed trait: `Held` and `Empty` alone |
| `Held` | `host` | A filled slot: the module as `&'static` | Fixed (public field): private; `const fn new`; the sealed `Slot` keeps `Held` and `Empty` the only slots |
| `Empty` | `host` | An empty slot | Holds: a unit struct |
| `Sealed` | `host` | Closes `Slot` to `Held` and `Empty` | Holds: a sealed trait in a private module |
| `Host` | `host` | `get` and `maybe` over `Has` and `MayHave` | Holds: a trait with a blanket implementation |
| `AuthenticationNeed` | `host` | Presence, or two PSD2 factor categories (PSD2 Art. 4(30); TS12 §3.6) | Holds: an enum whose every variant is a need |
| `Platform` | `host` | The wallet app: clock, credential status, End-User authentication | Holds: a trait; `usable` and `authenticate` return `Option` of the checked types |
| `SignatureInvalid` | `host` | A signature that does not verify | Holds: a refusal struct, one rule |
| `Haip` | `host` | HAIP's cryptography: its statements, verify, sign with a credential's key, encrypt to the route's key (HAIP §5, §7) | Holds: a trait; `verifies` and `agreements` state what the core accepts, an empty statement a capability the module lacks; `encrypt_jwe` takes a key and an `enc` (the core's from its `RouteKey`, siros-paso's the issuer's) and returns a checked `SealedJwe`; the registrations `prefix` and `jwe_mode` and siros-paso bound it |
| `SealedJwe` | `host` | A compact JWE: five base64url parts, a protected header with unique names (RFC 7516 §7.1) | Holds: private `String`; `parse -> Result<_, NotSealed>`; `Serialize` alone |
| `SealedJweApi` | `host` | Parses and reads a compact JWE | Holds: the inherent methods of `SealedJwe` |
| `SealedCose` | `profile` | One CBOR item, tag 96, distinct keys at every depth, a `COSE_Encrypt` (RFC 9052 §5.1) | Holds: private `Vec<u8>`; `parse -> Result<_, NotSealedCose>`; under `sealed-signals` |
| `SealedCoseApi` | `profile` | Parses and reads a `COSE_Encrypt` | Holds: the inherent methods of `SealedCose` |
| `NotSealed` | `host` | One variant per rule: a JWE's five parts, their base64url, its header's UTF-8, JSON and object | Holds: a refusal enum, one variant per rule |
| `CoseEnc` | `profile` | A content encryption a `COSE_Encrypt` carries (IANA COSE Algorithms, RFC 9053 §4.1) | Holds: private `i64`; constants for RFC 9053's AES-GCM values; the registry stays open, and a module states the values it implements |
| `SignFailed` | `host` | The End-User cancelled, or the keystore broke its contract | Holds: a refusal enum, one variant per rule; derives `Explain` |
| `DecryptFailed` | `host` | A JWE that does not decrypt | Holds: a refusal struct, one rule |
| `EphemeralKey` | `host` | A fresh key the wallet posts: its public JWK and the module's handle to the secret | Fixed (relational rule outside a step): private fields; only `new(public, handle)` makes one; the core checks the JWK's `crv` against `decrypts` and links no curve arithmetic |
| `RequestDecryption` | `host` | States its curves and JWE algorithms; draws a fresh key and keeps its secret; decrypts a JWE under it, consuming it (RFC 7516 §5.2) | Holds: a trait; `decrypt` takes the `EphemeralKey` by value; the registered `EncryptedRequests` bounds it |
| `CoseEncrypt` | `profile` | A `COSE_Encrypt` to a public key (RFC 9052 §5.1, RFC 9053 §6.3), for siros-paso's sealed signals | Holds: a trait in siros-paso in every `resolve` build, bounded `MayHave` in every build; `encryptions` states what it implements; returns a checked `SealedCose` |
| `CoreHost` | `host` | The module the core calls with no extension registered: `Platform` | Holds: a trait with a blanket implementation over its bound |
| `ProfileHost` | `host` | A profile's phase 2 over the build's host: `wanted`, `informed`, `authentication`, `revalidate`, `respond` | Holds: a trait; every method naming a `resolve` type sits here, it reads the core-made `Answered` and `FetchedRecord`, and its bounds name the modules it needs |
| `FormatHost` | `host` | A format's phase 2: each query read again under the mode rule C5 accepted | Fixed (relational rule outside a step; a refused reading in phase 2): `answer` takes an `AnsweredContext`, which only `Prepared::prepare` makes, and only its `AnsweredQuery` has phase-2 methods |
| `AnsweredQuery` | `host` | A query read for phase 2: phase 1's methods and each answerable option | Holds: trait; only `FormatHost::answer` gives one |
| `AnsweredOption` | `host` | An answerable option with its own query, credential and option | Holds: trait; only `AnsweredQuery::choose` gives one, so `revalidate` and `present` read no value the caller passes apart |
| `NoHost` | `host` | The matcher's build, without a host | Holds: a unit struct |
| `Build` | `host` | A registry's host, which fixes what the registry takes of each plug-in | Holds: a sealed trait over `Plugins`; implemented for `NoHost` and every host holding a `Platform` |
| `Plugins` | `host` | What a registry stores of each plug-in for its host (a format, a profile, a mode that answers, a mode that carries errors, response parameters), and how a JWE mode reaches the sealing module | Holds: a trait in a private module, so no crate outside the core implements `Build` |
| `HostedResponseParameters` | `host` | Response parameters the registry takes: `ResponseParameters` for `NoHost`, `ResponseParametersHost<H>` for a host | Holds: a trait with one impl for `NoHost` and one for a host; `stored` gives the host's `Plugins::ResponseParameters` |
| `RegisteredMode` | `host` | A mode by its registration: answers in the clear, answers the core seals with the host's sealing accessor, or a URI route's errors | Holds: a crate-private enum; the registration's method picks the variant, and each registration records its mode's `TypeId`, which `ModeTwice` reads |
| `RegisteredParameters` | `host` | A response parameters part and the names `build` checked | Fixed (an extension's output the core takes unchecked): the names are read once when the part registers; phase 2 checks each member against them |
| `ErasedProfile` | `host` | A `Profile` with its finding type erased, as a phase-1 registry stores it | Holds: a trait with a blanket implementation over `Profile` |
| `DynProfile` | `host` | An `ErasedProfile` with phase 2's methods over `H` | Holds: a trait with a blanket implementation over `ProfileHost<H>` |
| `JweHost` | `host` | A host whose registry takes a JWE mode: `NoHost`, or a host holding `Haip` | Holds: a trait over `Build`; `jwe_mode` bounds it, so a host without `Haip` does not compile with it (E0277) |
| `Registry` | `host` | The core's registry typed by the build's host (`Build`) | Holds: private fields; plug-ins enter through `RegistryApi`, each stored as its host's `Plugins` type, and a module-bounded registration keeps the module's accessor, the core's one path to it |
| `RegistryApi` | `host` | Registers a plug-in whose host bounds the build meets; `client_prefix` bounds `Haip`, `jwe_mode` `JweHost`, `request_encryption` `RequestDecryption` | Holds: the inherent methods of `Registry`; each module bound sits in its method's `where` clause; `mode`, `jwe_mode` and `error_mode` take `M` by name, whose `TypeId` the registration records |
| `HostedFormat` | `host` | A format the registry of `H` takes: a `Format` for `NoHost`, a `FormatHost<H>` for a host | Holds: a conversion trait with one impl per host kind, so a feature changes no signature |
| `HostedProfile` | `host` | A profile the registry of `H` takes: a `Profile` for `NoHost`, a `ProfileHost<H>` for a host | Holds: a conversion trait with one impl per host kind |
| `FetchedRecord` | `host` | A record with the resources its profile wanted, each with what the caller fetched | Holds: private fields; only the core's phase 2 makes one |
| `FetchedRecordApi` | `host` | The record and its resources | Holds: the inherent methods of `FetchedRecord` |
| `JwsError` | `jose` | One variant per JWS rule (U10, U16) | Holds: a refusal enum, one variant per rule |
| `ProtectedHeader` | `jose` | A protected header: `alg`, `typ`, `kid` and `crit` read (RFC 7515 §4) | Holds: private fields; only the JWS parses make one |
| `ProtectedHeaderApi` | `jose` | Reads `alg`, `typ`, `kid` and a member | Holds: the inherent methods of `ProtectedHeader` |
| `CompactJws` | `jose` | A compact JWS: three base64url parts, a header naming its `alg`, a UTF-8 payload (RFC 7515 §7.1) | Holds: private fields; `parse -> Result<_, JwsError>` |
| `CompactJwsApi` | `jose` | Parses a compact JWS and reads it | Holds: the inherent methods of `CompactJws` |
| `JsonJws` | `jose` | A JWS JSON Serialization with one signature or more (RFC 7515 §7.2.1) | Fixed (non-empty `Vec`): `first` and `rest` |
| `JsonSignature` | `jose` | A signature with its protected header, an unprotected header of disjoint names, its signing input (RFC 7515 §7.2.1) | Holds: private fields; only `JsonJwsApi::parse` makes one and refuses a name twice |
| `JsonJwsApi` | `jose` | Parses a JWS JSON Serialization and reads its signatures | Holds: the inherent methods of `JsonJws` |
| `JweError` | `jose` | One variant per JWE rule (U11) | Holds: a refusal enum, one variant per rule |
| `CompactJwe` | `jose` | A compact JWE whose `alg` and `enc` the decrypting module states (RFC 7516 §7.1, RFC 8725 §3.1) | Holds: private fields; `parse(text, accepted) -> Result<_, JweError>` |
| `CompactJweApi` | `jose` | Parses a compact JWE | Holds: the inherent methods of `CompactJwe` |
| `Signed` | `jose` | A signature with the signing input of its own header and payload (RFC 7515 §5.1) | Holds: private references; only the JWS it belongs to makes one |
| `SignedApi` | `jose` | Reads a signature's headers, signing input and bytes | Holds: the inherent methods of `Signed` |
| `NumericDate` | `jose` | Seconds since the epoch, a fraction allowed (RFC 7519 §2) | Holds: private fields; only `ValidityApi::of` reads one |
| `Skew` | `jose` | A clock skew of at most 300 s (RFC 7519 §4.1.4) | Holds: private `Seconds`; `new -> Result<_, SkewTooLarge>` |
| `SkewTooLarge` | `jose` | A skew past 300 s | Holds: a refusal struct, one rule |
| `SkewApi` | `jose` | Builds a skew | Holds: the inherent methods of `Skew` |
| `Validity` | `jose` | A JWT's `exp` and `nbf` (RFC 7519 §4.1.4, §4.1.5) | Holds: private fields; `of -> Result<_, TimeError>` reads them |
| `TimeError` | `jose` | One variant per time rule | Holds: a refusal enum, one variant per rule |
| `ValidityApi` | `jose` | A JWT's `exp` and `nbf` read from its claims | Fixed (check after construction): `at` leaves the API; `Pending::authenticate` holds A9 inside its step |
| `VerificationKey` | `jose` | The key a prefix binds and a signature verifies under: a public JWK | Fixed (public constructor takes it unchecked): `of` takes a `PublicJwk`, which `parse` checks; the verifying module checks the key's fit to the `alg`, a point off its curve included |
| `OptionIndex` | `kept` | A position in its query's options | Fixed (constrained primitive in a public field): private; only the query's `options` and the core's slots make one (section 2) |
| `OptionIndexApi` | `kept` | The position | Holds: the inherent methods of `OptionIndex` |
| `Options` | `plugins` | A Credential Query's options, in the Verifier's order | Holds: private `Vec`; `indexed` is the only way to an `OptionIndex`; `consider` faults on a list of another order or of another query's options |
| `Thumbprint` | `plugins` | A JWK SHA-256 thumbprint (RFC 7638) of the key the core sealed to | Fixed (public field): siros-mdoc's, private; only `Thumbprint::of` makes one, from an `EC` or `OKP` key |
| `ThumbprintApi` | `plugins` | The thumbprint of a key | Holds: the inherent methods of `Thumbprint` |
| `Authentication` | `kept` | When the End-User authenticated, and each factor applied, one or more | Fixed (non-empty `Vec`): `factors` an `AllOf<Factor>`; private fields |
| `AuthenticationApi` | `kept` | The accessors of `Authentication` | Holds: the inherent methods of `Authentication` |
| `Point` | `kept` | A key's base64url-decoded coordinates | Boundary: their lengths are the mode's key rule's, the point's place on its curve the agreeing module's; the matcher, which reads keys in `admits` and C7, links no curve arithmetic (I10) |
| `AgreeableKey` | `kept` | A public key the wallet can agree a key with: its JWK, `kid`, curve, point and `alg` | Fixed (constrained primitive in a public field): private fields; `of` decodes the coordinates and reads `crv` and `alg` as JOSE names |
| `AgreeableKeyApi` | `kept` | Reads a key from its JWK | Holds: `of -> Option`; the accessors are inherent |
| `Session` | `kept` | A presentation's binding facts: the channel's binding, the nonce, the key the core sealed to, the Verifier's keys | Fixed (typestate gap): private fields; only `AnswerRoute::session` makes one, from a route holding a `nonce` N1 accepts |
| `SessionApi` | `kept` | The accessors of `Session`, and its audience | Holds: the inherent methods of `Session` |
| `Prepared` | `phase2` | An authenticated request's records, and one slot per resource their profiles revalidate with | Fixed (caller list): `Slots<Resource>`; `respond` fills them through the caller's `fetch`; it holds the registry the envelope was read with, owns the request, and holds each record by index, so `respond` reads each query through `FormatHost::answer` again |
| `Picked` | `phase2` | A derived record: its query and option by index, the wallet's credential, its transaction | Holds: a private struct; only `prepare` builds it from a record it derived and checked |
| `Transacted` | `phase2` | A record's transaction: its profile and handle, the bound entries and display facts, the format's placement, the slots of its resources | Holds: a private struct; `prepare` builds it from the candidate's `TransactionBinding`, the one place that holds the transaction and its binding |
| `Built` | `phase2` | The Authorization Response, the delivery that carries it, the credentials it used and its audience | Holds: private fields; only `PhaseTwoApi::respond` makes one |
| `BuiltApi` | `phase2` | Reads the response, its delivery, the credentials used and the audience | Holds: the inherent methods of `Built` |
| `PhaseTwoApi` | `phase2` | Phase 2's steps from the chosen ids to the delivery | Fixed (relational rule outside a step): `prepare` reads the request and the routing from the `Authenticated`'s envelope, runs the request's rules before it reads the ids, reads the routed mode from the registry by its handle, and takes the ids as a slice, empty for a request whose every credential set is optional (§6.4.2), an empty selection of a required set `Rejection::NoAlternative`; `respond` takes `fetch` |
| `OutcomeAdditions` | `phase2` | The outcomes phase 2 gains | Holds: a refusal enum, one variant per rule |
| `PresentError` | `phase2` | A contract breach, or a failed step with its reason | Holds: a refusal enum |
| `Categories` | `phase2` | A set of PSD2 categories (Art. 4(30)), one to three | Holds: private `bool`s; only `CategoriesApi::of` makes one, from an `Authentication`, whose factors are one or more |
| `CategoriesApi` | `phase2` | Reads the categories of an authentication | Holds: the inherent methods of `Categories` |
| `AnsweredAdditions` | `phase2` | What `Answered` becomes: private fields and the route's mode name | Fixed (typestate gap): private fields; only the core's phase 2 makes an `Answered` |
| `AnsweredAdditionsApi` | `phase2` | The accessors of `Answered` | Holds: the inherent methods of `Answered`; `mode` gives a `ModeName` |
| `ProfileAdditions` | `phase2` | A profile's members by placement and its reserved credentials | Holds: a trait; `members` takes a `Placement`, so a profile names no format |
| `X509Hash` | `plugins` | The `x509_hash` prefix (§5.9.3) | Holds: a unit struct |
| `X509SanDns` | `plugins` | The `x509_san_dns` prefix (§5.9.3) | Holds: a unit struct |
| `LeafHash` | `plugins` | The leaf's SHA-256, 32 octets (§5.9.3) | Holds: a fixed array, private; `parse -> Result<_, X509Refusal>` |
| `SanDnsName` | `plugins` | A DNS name in preferred name syntax with A-labels (RFC 1034 §3.5, RFC 5280 §4.2.1.6) | Holds: private `String`; `parse -> Result<_, X509Refusal>` |
| `ChainCertificate` | `plugins` | A certificate's DER as received and its parse (RFC 5280 §4.1) | Holds: private fields; `X5c::of` reads one from each item, `from_der` takes DER alone (siros-paso's `RootCertificate::parse`) |
| `X5c` | `plugins` | A non-empty `x5c` chain, the leaf first (RFC 7515 §4.1.6) | Fixed (non-empty `Vec`): `leaf` and `rest`; `of` refuses an absent, a non-array and an empty member |
| `X509Refusal` | `plugins` | One variant per `x509_hash` and `x509_san_dns` rule (A5) | Holds: a refusal enum, one variant per rule |
| `LeafHashApi` | `plugins` | Parses the hash an original identifier names | Holds: the inherent methods of `LeafHash` |
| `SanDnsNameApi` | `plugins` | Parses a DNS name; compares it with a dNSName and an endpoint's host (RFC 5280 §7.2) | Holds: the inherent methods of `SanDnsName` |
| `X5cApi` | `plugins` | Reads the chain from a protected header, its leaf and its certificates | Holds: the inherent methods of `X5c` |
| `ChainCertificateApi` | `plugins` | Reads a certificate's hash, Subject and EC or EdDSA key as a public JWK | Holds: the inherent methods of `ChainCertificate`; `key -> Result<VerificationKey, X509Refusal>` |
| `SpkiKey` | `plugins` | Reads the EC or EdDSA key of a SubjectPublicKeyInfo as a public JWK (RFC 5480 §2.1.1, §2.2; RFC 8410 §3, §4) | Holds: a trait with `&self`; refuses another key with `X509Refusal::Key` |
| `ViewAdditions` | `kept` | A credential's types: its own, then those its metadata extends, nearest first (SD-JWT VC §6.4) | Holds: a trait of the core's registration view (`Debug`), so a profile names the core alone |
| `ViewTypes` | `kept` | A credential's types as its format read them, the core's `ViewAdditions` value | Holds: private `Vec<CredentialType<'static>>`; `new` takes them as given |
| `ClientIdAdditions` | `kept` | What `ClientId` gains: `prefixed`, the one reading of a Client Identifier Prefix (§5.9.1) | Holds: a trait over the checked `ClientId` |
| `SessionTranscriptBytes` | `plugins` | `#6.24(bstr .cbor SessionTranscript)`, from the session's handover or a held transcript | Holds: private slice; only `SessionTranscript::tagged_bytes` makes one |
| `SessionTranscriptBytesApi` | `plugins` | Reads the bytes | Holds: the inherent methods of `SessionTranscriptBytes` |
| `DeviceMac` | `plugins` | A MAC under EMacKey (ISO/IEC 18013-5 §9.1.3.5) | Holds: a trait; the transcript enters as `SessionTranscriptBytes` |
| `LabelLimits` | `profile` | Label limits in grapheme clusters, each one or more (Proof Metadata §3.3) | Holds: public `NonZeroUsize` fields; a fixed limit by `label_limit!`, which fails the build at zero |
| `Registered` | `profile` | A registered transaction type: its identifier, family and metadata | Holds: private fields; `of(PasoType, given)` holds the type and its metadata together |
| `RegisteredApi` | `profile` | The accessors of `Registered` | Holds: the inherent methods of `Registered` |
| `Request` | `profile` | What a PaSO rendering reads | Fixed (tag in one structure and its data in another): `registered`, a `Registered`, holds the type, its family and its metadata together |
| `RequestApi` | `profile` | Renders in PaSO Core §7.4.2's order | Holds: the inherent methods of `Request` |
| `BoundApi` | `profile` | A rendering's `Bound` | Fixed (relational rule outside a step): `bound` takes `BoundEntries`, which `BoundEntries::select` makes from the offered entries |
| `ViewApi` | `profile` | Converts display rules to MF2 source; reads a claim value by its value type (View §3) | Holds: a trait; refuses with `NotCompatible` |
| `Paso` | `profile` | The wallet's version and its risk signals' last measurements (PaSO Core §6.1, Risk Signals §2.3) | Holds: a trait |
| `Ts12Type` | `profile` | One of the two built-in TS12 types (CS-12 §7.1 item 1) | Holds: an enum whose every variant is a type |
| `Ts12TypeApi` | `profile` | Reads a type from its URN; its family | Holds: the inherent methods of `Ts12Type`; `of(&TransactionType) -> Option` |
| `Ts12Document` | `profile` | The registration's `category` and `transaction_data_types` (TS12 §4.1) | Holds: private fields; `read -> Result<_, ComposeError>` |
| `TypeEntry` | `profile` | A `transaction_data_types` entry | Fixed (typestate gap): private fields; only `Ts12Document` makes one |
| `BuiltInEntry` | `profile` | An entry whose schema names a built-in type, its metadata read under TS12 §3.3 | Holds: private; only `TypeEntry::built_in` makes one, with that type |
| `TypeEntryApi` | `profile` | Reads an entry for its built-in type | Holds: the inherent methods of `TypeEntry` |
| `ComposeError` | `profile` | One variant per composition rule (TS12 §4.1) | Holds: a refusal enum, one variant per rule |
| `FetchedDocument` | `profile` | A document fetched for a `_uri` member: JSON with unique member names | Holds: private; `parse -> Result<_, JsonError>` |
| `ComposedDocument` | `profile` | A registration's `ts12` document | Holds: private; only `Ts12DocumentApi::compose` makes one |
| `Category` | `profile` | SCA's category, or anything else | Holds: an enum; `Ts12Document::read` makes one |
| `TwinnedMember` | `profile` | A member TS12 §4.1 lets a type write inline or by a `_uri` twin | Holds: an enum whose every variant is such a member |
| `FetchedDocumentApi` | `profile` | Parses a fetched document | Holds: the inherent `parse` |
| `ComposedDocumentApi` | `profile` | Reads a registration's content | Holds: the inherent `content`, a `DocumentBytes` |
| `TypeMetadata` | `profile` | A built-in type's field table, claims and catalogue under TS12 §3.3 | Holds: crate-private; only `TypeEntry::built_in` makes one |
| `Field` | `profile` | A field of a type's table: its path and role | Holds: crate-private; the tables' constants |
| `Role` | `profile` | An object shown by its label alone, or a leaf under the display rules | Holds: crate-private; an enum |
| `ValueType` | `profile` | The PaSO value type a leaf states | Holds: crate-private; an enum |
| `Shown` | `profile` | What the display rules ask of a leaf: always, declared, or when held | Holds: crate-private; an enum |
| `Label` | `profile` | A label with its tag as TS12 means it | Holds: crate-private fields |
| `Claim` | `profile` | A claim of the claims metadata: its field and the labels TS12 §3.3.1 displays it under; `None` keeps the field internal | Holds: crate-private fields |
| `Catalogue` | `profile` | The UI labels PaSO reads: title, the required `affirmative_action_label`, denial, hint | Holds: crate-private fields |
| `Ts12DocumentApi` | `profile` | Composes the registration document; reads it and its entries | Holds: the inherent methods of `Ts12Document` |
| `Amount` | `profile` | An exact decimal amount, at most its currency's minor-unit digits | Holds: private `String`; only `Ts12PayloadApi::parse` makes one, beside its currency |
| `CurrencyCode` | `profile` | An ISO 4217 code of the core's table, with its minor-unit digits, which `Amount` reads | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `CalendarDate` | `profile` | An ISO 8601 calendar date | Holds: private `String`; only `Ts12PayloadApi::parse` makes one |
| `DateTime` | `profile` | An ISO 8601 date-time | Holds: private `String`; only `Ts12PayloadApi::parse` makes one |
| `Logo` | `profile` | `payee.logo`: a data URL, or an https URL with its SRI | Fixed (string with a grammar): `DataUrl` and `Integrity`, each from its `parse` |
| `DataUrl` | `profile` | A data URL (RFC 2397) | Holds: private; `parse -> Option` refuses a text outside RFC 2397 |
| `Integrity` | `profile` | A Subresource Integrity value (W3C SRI §3.5) | Holds: private; `parse -> Option` refuses a text outside the grammar or a digest of another length |
| `DataUrlApi` | `profile` | The parse of `DataUrl` | Holds: the inherent `parse` |
| `IntegrityApi` | `profile` | The parse of `Integrity` | Holds: the inherent `parse` |
| `TransactionId` | `profile` | `transaction_id`, one to 36 characters | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `Service` | `profile` | `service`, at most 100 characters | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `Action` | `profile` | `action`, at most 140 characters | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `PayeeName` | `profile` | `payee.name` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `PayeeId` | `profile` | `payee.id` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `PispLegalName` | `profile` | `pisp.legal_name` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `PispBrandName` | `profile` | `pisp.brand_name` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `PispDomainName` | `profile` | `pisp.domain_name` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `RecurrenceNumber` | `profile` | `recurrence.number` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `InitialAmountNumber` | `profile` | `recurrence.mit_options.initial_amount_number` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `AmountEstimated` | `profile` | `amount_estimated` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `AmountEarmarked` | `profile` | `amount_earmarked` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `SctInst` | `profile` | `sct_inst` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `AmountVariable` | `profile` | `recurrence.mit_options.amount_variable` | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `Apr` | `profile` | `apr`, the exact decimal value at most 38 digits wide | Holds: private; only `Ts12PayloadApi::parse` makes one |
| `MinorDigits` | `profile` | A currency's minor-unit digits, which `Amount` reads | Holds: private; only `CurrencyCode` holds one |
| `Payee` | `profile` | TS12 §4.3.1's `payee` | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `Pisp` | `profile` | TS12 §4.3.1's `pisp` | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `MitOptions` | `profile` | TS12 §4.3.1's `recurrence.mit_options` | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `Recurrence` | `profile` | TS12 §4.3.1's `recurrence`; its `frequency` is siros-paso's `Frequency` | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `Execution` | `profile` | On a date, recurring, or unstated; never both (TS12 §4.3.1) | Holds: an enum whose every variant is a valid state |
| `Payment` | `profile` | A `urn:eudi:sca:payment:1` payload (TS12 §4.3.1) | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `LoginRisk` | `profile` | A `urn:eudi:sca:login_risk_transaction:1` payload (TS12 §4.3.2) | Holds: private fields; only `Ts12PayloadApi::parse` makes one |
| `Ts12Payload` | `profile` | A payment or a login-risk payload | Holds: an enum of parsed payloads |
| `PayloadRefusal` | `profile` | One variant per payload rule (TS12 §4.3, PaSO Core §7.4.2 step 2) | Holds: a refusal enum, one variant per rule |
| `FieldPath` | `profile` | A member of TS12's field tables, or `payload` itself | Holds: private; the crate's constants |
| `Expected` | `profile` | The form TS12 lists for a member | Holds: an enum whose every variant is a form |
| `DateForm` | `profile` | A calendar date or a date-time | Holds: an enum whose every variant is a form |
| `MaxChars` | `profile` | A schema's `maxLength` | Holds: private; the crate's constants |
| `Ts12PayloadApi` | `profile` | Parses a payload of a type; writes it in PaSO's value forms | Holds: the inherent methods of `Ts12Payload` |
| `Ts12Unsupported` | `profile` | One variant per rule that makes a type unsupported (TS12 §3.2 step 5, §3.3.1) | Holds: a refusal enum, one variant per rule |
| `Ts12Rule` | `profile` | The request rules T1 to T6 and B.3.3.1's hash rule, each with its code | Holds: a refusal enum, one variant per rule |
| `Ts12Excluded` | `profile` | Why phase 1 excludes a credential: the presentation's carriage, an unsupported type, a payload's refusal, the engine's refusal | Holds: an enum a wallet reads the exclusion by |
| `TranslateApi` | `profile` | A built-in type's metadata in PaSO's form | Fixed (tag in one structure and its data in another): `paso_metadata` takes a `BuiltInEntry`, which holds the type its schema names and its parsed metadata |
| `AmrCategory` | `profile` | An `amr` category of TS12 §3.6 | Holds: an enum whose every variant is a category |
| `AmrMethod` | `profile` | A method of TS12 §3.6, with the category holding it | Holds: an enum; `category()` and `name()` follow from the variant |
| `AmrApi` | `profile` | The `amr` object of a factor | Holds: a trait; returns an `AmrMethod` |
| `AmrMethodApi` | `profile` | Reads a method's category and name | Holds: the inherent methods of `AmrMethod` |
| `Ts12Finding` | `profile` | A logo's fetch that failed, by its URL | Holds: public fields of checked types; phase 2 makes one |
| `AttestationType` | `profile` | A `vct` value a credential's `types` may name, non-empty | Holds: private; `const fn new -> Option` refuses an empty text |
| `Ts12Profile` | `profile` | The attestation types, one or more, and View §2's item bound | Fixed (non-empty `Vec`): `AllOf<AttestationType>` |
| `Ts12Host` | `profile` | The modules siros-ts12 needs: `Platform` and siros-paso's `RandomIds` | Holds: a trait whose bounds name the modules |
| `Ts12ProfileApi` | `profile` | The profile and its registration | Fixed (public constructor takes it unchecked): `new` takes `AllOf<AttestationType>` |
| `Failure` | `recourse` | A U rule or an A rule | Holds: a refusal enum, one variant per rule family |
| `FailureApi` | `recourse` | The code a failure's error response carries (§8.5, RFC 9101 §7) | Holds: the inherent methods of `Failure` |
| `ErrorRoute` | `recourse` | Where a refused request's error goes, with `state` as received (§8.3.1) | Holds: private fields; only a `Rejected` holds one, made by the step that refuses |
| `ErrorTarget` | `recourse` | The DC API, a `response_uri` the trust decision vouches for, or an unverified one (RFC 9700 §4.11.2) | Holds: an enum of parsed `ResponseUri`s; only the refusing step builds the one an `ErrorRoute` holds |
| `ErrorRouteApi` | `recourse` | Reads the target | Holds: the inherent methods of `ErrorRoute` |
| `Rejected` | `recourse` | A refused request and its failure's route | Holds: private fields; only the step that refuses makes one |
| `RejectedApi` | `recourse` | Makes a rejection on its route; writes its error response | Holds: the inherent methods of `Rejected`; `reply -> Result<Reply, Fault>` |
| `DcApiErrors` | `recourse` | Cancel, or respond with `{"error": ...}` (§15.9.2, A.4) | Holds: an enum whose every variant is a policy |
| `Reply` | `recourse` | Deliver the error response, or cancel | Holds: an enum; `Deliver` holds a built `Delivery` |
| `FormatName` | `ids` | The Credential Format Identifier a claims format names itself by in refusals | Holds: private `&'static str`; `const fn new -> Option` refuses an empty text; a format's by `checked!` |
| `VpFormatsMember` | `claims::kit` | A member of a format's `vp_formats_supported` value that lists algorithm identifiers (Appendix B) | Holds: private `&'static str`; the format names its own |
| `Audience` | `session` | The audience a presentation's key binding states | Holds: private text; only `Session::audience` makes one |
| `KeyPlace` | `routing` | A key's place among the request's agreeable keys | Holds: private `usize`; only `VerifierKeys::iter` makes one |
| `KeyType` | `request` | A key's `kty` | Holds: borrows the key's text; only `AgreeableKey::kty` makes one |
| `ChoiceId` | `matching` | An entry's id in a display set: a credential's or a static entry's | Holds: private text; only `Choice::id` makes one |
| `DisplaySet` | `matching` | A set of a display, the only way to select | Holds: `Display::set` makes one or refuses `NoSet`; `select` takes the ids the platform returned |
| `ArrayIndex` | `claims` | A position in a JSON array in a claims path pointer (§7.1) | Holds: a `usize` in its role; `Step::Beyond(Number)` holds an integer no `usize` holds, as received |
| `IconReference` | `rows` | What an icon names: a wallet asset or a card's logo URI | Holds: an enum |
| `Route` | `response` | Where and how an answer and an error go: the registered modes, the bound endpoint, the authenticated Client Identifier or Origin, the answering mode's encryption, the `nonce` N1 accepts | Fixed (values of two registries): private fields; only `RouteApi::new` makes one, from an `Authenticated` and the registry its envelope was read with, each mode read by `ModeHandle`; `state` and the Verifier's metadata are read from the `Authenticated` |
| `Unroutable` | `response` | A URI request whose mode names no registered error mode (C5) | Holds: a refusal struct, one rule; id `err.openid4vp.route.unroutable` |
| `UnmetCode` | `matching` | `access_denied` or `vp_formats_not_supported` (§8.5, §15.4.1) | Holds: an enum whose every variant is a code; the core derives it (`MatchAdditions::unmet`) |
| `UnmetCodeApi` | `matching` | The code an unmet request's error carries | Holds: the inherent methods of `UnmetCode` |
| `ExcludedBy` | `matching` | What excluded a credential: the query's format by the Verifier's algorithms, the transaction's profile, or the query's format by what the End-User could be shown | Holds: an enum whose every variant is a plug-in kind; the matching sets it where the plug-in refused |
| `ExcludedAdditions` | `matching` | What `matching::Excluded` gains: `by` | Holds: a public field of a closed enum; only the matching builds an `Excluded` |
| `TransactionBinding` | `matching` | A candidate's transaction: its query's `Transaction` and its profile's `Bound` | Holds: one struct holds both, so a binding without its transaction cannot be written; `Candidate::bound` holds it |
| `MatchAdditions` | `matching` | The unmet request's code, from the plug-in that excluded each credential | Holds: the inherent methods of `Match`; `unmet` reads each query's candidates and the `ExcludedBy::Format` exclusions over the request's alternatives |
| `RouteApi` | `response` | An authenticated request's route and its errors in the mode's form | Fixed (relational rule outside a step): `new` takes the `Authenticated` and its registry, checks each handle's name, and calls the mode's `encryption` once; a broken choice is a `Fault` caused by `RouteBreach`; a key is checked by identity against the request's `VerifierKeys` |
| `RouteBreach` | `response` | How a mode's route or body breaks its registration, the cause of phase 2's `Fault` | Holds: an enum, one variant per breach; a fixture compares the cause by type |
| `ParameterBreach` | `response` | How a response parameters part breaks its registration: an undeclared name, a name twice | Holds: an enum, one variant per breach; a fixture compares the cause by type |
| `UndeclaredMember` | `resolve` | A profile wrote a presentation member outside those it declares for the placement | Holds: a fixture compares the cause by type |
| `AuthorizationResponse` | `response` | The VP Token, the request's `state` and the registered response parameters' members (§8.1) | Holds: private fields; only `Prepared::respond` makes one; `json` writes §8.1's object |
| `ErrorDescription` | `response` | One or more characters of %x20-21, %x23-5B, %x5D-7E (RFC 6749 Appendix A.8); the core's `refusal`, every build | Holds: private `String`; `sanitized` and `parse -> Option` through `is_nqschars`; `Serialize` alone |
| `ErrorDescriptionApi` | `response` | Sanitizes or parses a description | Holds: the inherent methods of `ErrorDescription` |
| `ResponseForm` | `modes` | `direct_post.jwt`'s form: `response`, the JWE (§8.3.1) | Holds: a private reference to a `SealedJwe`'s text; only `of(&SealedJwe)` makes one; `Serialize` alone |
| `ErrorForm` | `modes` | §8.2's plain error form: `error`, `error_description`, `state` as received | Holds: private fields of checked types: `ErrorCode`, `ErrorDescription`, `Echo`; only `of(&ErrorResponse)` makes one, `state` the error's `Echo`; `Serialize` alone |
| `PostBody` | `response` | A POST body and its media type; a form from `FormBody::of` alone | Holds: private fields; `form` takes a `FormBody`, `of` refuses the form media type |
| `DcApiData` | `response` | The DigitalCredential's `data`, a JSON object with unique member names (A.4) | Holds: private `String`; `of` reads the text back through the `json` module, `error` writes A.4's form |
| `Delivery` | `response` | POST a mode's body to the route's `response_uri`, or return DC API `data` | Holds: an enum of checked parts; only the core writes one, from the route's endpoint and the mode's body |
| `Handover` | `plugins` | siros-mdoc's handover of the session's channel (B.2.6) | Holds: a public enum with public fields; siros-mdoc's phase 2 builds it with `HandoverApi::of`, and siros-zkp-catalogues builds a Verifier's without a `Session` (Appendix A) |
| `State` | `routing` | A non-empty `state` of ASCII letters, digits, `-`, `.`, `_`, `~` (§5.2, P6) | Holds: private `Cow<str>`; `parse -> Option` |
| `StateApi` | `routing` | Parses and reads a `state` | Holds: the inherent methods of `State` |
| `Echo` | `routing` | `state` as received, which every answer echoes (RFC 6749 §4.1.2.1) | Holds: private `Cow<str>`; only the routing `Envelope::parse` reads makes one; `Serialize` alone |
| `Routing` | `routing` | The routing a request asks for, its registered response type and mode, and the rules it breaks (P1, C5, P5, P6) | Holds: private fields; only `Envelope::parse` makes one, and holds an answering mode with its registration as `dyn Mode` |
| `RoutingApi` | `routing` | Reads the routing an envelope holds | Holds: the inherent methods of `Routing` |
| `RequestParseApi` | `routing` | The request's content, read from one envelope, by URI its scope values through the envelope's registry | Fixed (relational rule outside a step): `parse` takes the envelope alone and reads the routing and the registry it holds |
| `AcceptedApi` | `routing` | The request rules over one request | Fixed (relational rule outside a step): `new` takes the request alone and reads its envelope's routing |
| `QueryContext` | `routing` | A query's request, mode name, transaction naming and Verifier formats | Fixed (typestate gap): private fields behind accessors; only `Accepted::new` makes one |
| `AnsweredContext` | `routing` | A query's context in phase 2, its mode the one rule C5 accepted | Fixed (a refused reading in phase 2): private; only `Prepared::prepare` makes one |
| `UriError` | `uri` | One variant per U3 URI rule | Holds: a refusal enum, one variant per rule |
| `AuthorizationUri` | `uri` | An Authorization Request URI with its `client_id`, `request_uri` and `request_uri_method` parsed (§9, U3 to U8, U18, U19) | Holds: private fields; `parse -> Result<_, Unreadable>` |
| `AuthorizationUriApi` | `uri` | Parses the URI and reads its parameters | Holds: the inherent methods of `AuthorizationUri` |
| `QueryRead` | `uri` | The four parameters as decoded, or the first name given twice (U4) | Holds: a private enum; `AuthorizationUriApi::parse` parses each field into its type |
| `Part` | `uri` | A decoded query name or value | Holds: a private deserialization helper |
| `Text` | `uri` | `Part`'s visitor | Holds: a private deserialization helper |
| `Pairs` | `uri` | `QueryRead`'s visitor | Holds: a private deserialization helper |
| `RequestUri` | `uri` | An absolute `https` URI with a host (RFC 9101 §5.2, U7) | Holds: private `fluent_uri::Uri`; `parse -> Result<_, Unreadable>` |
| `RequestUriApi` | `uri` | Parses and reads a `request_uri` | Holds: the inherent methods of `RequestUri` |
| `NotHttps` | `uri` | A URI that is no absolute `https` URI with a host | Holds: a refusal struct, one rule |
| `ResponseUri` | `uri` | An absolute `https` URI with a host (§8.2, A13) | Holds: private `fluent_uri::Uri`; `parse -> Result<_, NotHttps>` |
| `ResponseUriApi` | `uri` | Parses and reads a `response_uri` | Holds: the inherent methods of `ResponseUri` |
| `RedirectTarget` | `uri` | A URI with a scheme, a fragment allowed (§8.2, RFC 3986 §3) | Holds: private `fluent_uri::Uri`; only `ResponseUriAnswerApi::parse` makes one |
| `FailedStatus` | `uri` | An HTTP status from 100 to 599 other than 200 (RFC 9110 §15) | Holds: private `u16`; `new -> Option` |
| `FailedStatusApi` | `uri` | Builds and reads a failed status | Holds: the inherent methods of `FailedStatus` |
| `FetchFailure` | `uri` | One variant per failed fetch (§5.10.2) | Holds: a refusal enum, one variant per rule |
| `FetchAnswer` | `uri` | The fetched body, or the failure | Holds: an enum; `FetchApi::resume` parses the body |
| `RequestUriMethod` | `uri` | `get` or `post` (§5.1) | Holds: an enum whose every variant is a method |
| `RequestObjectFetch` | `uri` | A GET of the `request_uri`, or a POST of a form body to it (RFC 9101 §5.2.3, §5.10) | Holds: an enum of references to a checked `RequestUri` and `FormBody` |
| `Fetch` | `uri` | A URI request whose Request Object the caller fetches | Holds: private fields; only `FetchApi::of` makes one, and `resume` consumes it |
| `FetchMethod` | `uri` | GET, or POST of the form, with the key the fetch keeps when `EncryptedRequests` is registered | Holds: a private enum; only `FetchApi::of` builds it |
| `FetchApi` | `uri` | Reads a URI request; hands the fetch; resumes with the answer (U3 to U11, U18, U19) | Holds: the inherent methods of `Fetch`; `of -> Result<_, NoFetch>`; `post` POSTs through the registry's `RequestPost`, its key from `EncryptedRequests` |
| `NoFetch` | `uri` | Why a URI gives no fetch: a U rule, a contributor's breach, a module's | Holds: an enum over `Unreadable`, `MetadataRefused`, `Fault` |
| `FormBody` | `uri` | An `application/x-www-form-urlencoded` UTF-8 body of text members, each name once (§5.10, §8.2) | Holds: private `String`; only `FormBody::of` makes one, refusing a nested value and a name twice (`NotForm`) |
| `ResponseUriAnswer` | `uri` | The Response URI's answer: a JSON object with unique names, `redirect_uri` read, the registered readers' outcomes (§8.2) | Holds: private fields; `parse -> Result<_, AnswerError>` runs each reader over its declared members |
| `VerifierError` | `plugins` | A Verifier's `error` and `error_description` (CS-02 §6.1.7), siros-webuild's | Holds: private fields; only `Cs02ErrorAnswer::read` makes one |
| `VerifierErrorApi` | `plugins` | Reads the code and the description | Holds: the inherent methods of `VerifierError` |
| `VerifierCode` | `plugins` | One or more characters of %x20-21, %x23-5B, %x5D-7E (RFC 6749 Appendix A.7) | Holds: private `String`; `parse -> Option` |
| `VerifierCodeApi` | `plugins` | Parses and reads a code | Holds: the inherent methods of `VerifierCode` |
| `AnswerError` | `uri` | One variant per answer rule, and a reader's refusal | Holds: a refusal enum, one variant per rule |
| `ResponseUriAnswerApi` | `uri` | Parses the answer and runs the readers; reads its redirect and outcomes | Holds: the inherent methods of `ResponseUriAnswer` |
| `WalletMetadata` | `wallet_metadata` | `wallet_metadata`, a JSON object (§5.10, §10.1), and the POST parameters written in the same pass | Holds: private fields; only `WalletMetadataApi::of` makes one, each contribution writing once |
| `WalletMetadataApi` | `wallet_metadata` | Composes the metadata from the contributions (§5.10, §10.1, HAIP §5, §7) | Holds: the inherent methods of `WalletMetadata`; `of -> Result<_, MetadataRefused>` refuses an undeclared name and a contribution that is no object where §10.1 asks one; the registry refused a name twice when it built |
| `RequestUriPost` | `wallet_metadata` | The `request_uri` POST's form: `wallet_metadata` and the contributions' parameters (§5.10) | Holds: a private reference to the `WalletMetadata`; only `RequestUriPostApi::of` makes one; `Serialize` as a map alone |
| `RequestUriPostApi` | `wallet_metadata` | Makes the POST's form from a `WalletMetadata` | Holds: the inherent methods of `RequestUriPost` |
| `FormatAdditions` | `wallet_metadata` | A format's `vp_formats_supported` value, its placement of a profile's members, a credential's types | Holds: a trait; `wallet_formats -> Result<Node, Fault>`, `placement -> Option<Placement>`, `additions -> Result<Box<dyn ViewAdditions>, Fault>` |
| `ModeName` | `routing` | A `response_mode` value: one or more of ASCII letters, digits, `_`, `.`, `-` | Holds: private `&'static str`; `const fn new -> Option`; a mode's by `checked!` |
| `ChannelKind` | `routing` | The DC API or a URI | Holds: an enum whose every variant is a channel |
| `Carries` | `routing` | A registered mode carries answers, or errors alone (reading 24), by its registration | Holds: an enum whose every variant is a carriage |
| `Mode` | `routing` | A response mode as phase 1 reads it: name, channel, rules, `wallet_metadata` names | Holds: a trait; its rules return `Refusal`s with their codes; its names are constants the registry checks |
| `VerifierMetadata` | `routing` | The Verifier's `client_metadata` and its agreeable `jwks` keys | Holds: private fields; only the core makes one, from the request it parsed |
| `VerifierKeys` | `routing` | The Verifier's agreeable keys, in its order | Holds: private `Vec`; only the core makes one; `iter` yields each as a `VerifierKey` |
| `VerifierKey` | `routing` | One of the request's keys by its place | Fixed (relational rule outside a step): private; only `VerifierKeys::iter` yields one, so a mode chooses among the request's keys alone |
| `ModeHandle` | `routing` | A registered mode, by its place in the envelope's registry | Holds: private `usize`; only the registry makes one |
| `RoutedMode` | `routing` | The registered mode a request names on its channel | Holds: private fields; only `Envelope::parse` makes one; phase 2 reads its registration by `handle`, the name checked |
| `KeyChoice` | `routing` | The key rule's phase-1 choice: a key's place and `kid`, an `enc`; `modes` re-exports it | Holds: private fields; only `KeyChoiceApi::of` makes one, through `modes::key_rule` |
| `KeyChoiceApi` | `routing` | Reads the key rule's choice for a reader that binds the key before phase 2 | Holds: the inherent methods of `KeyChoice`; `of -> Result<_, KeyRule>` |
| `MetadataMember` | `wallet_metadata` | One `wallet_metadata` member a contributor writes | Holds: private fields; `new` takes a checked `ParameterName` and a JSON value; the registry refuses a name twice, the composition an undeclared one |
| `MetadataRefused` | `wallet_metadata` | One variant per composition rule: an undeclared name, a member that is no object, a contributor's fault | Holds: a refusal enum, one variant per rule |
| `Placement` | `wallet_metadata` | How a proof carries a profile's members: JSON claims or CBOR data elements | Holds: an enum whose every variant is a placement; `places` judges a member |
| `PlacementApi` | `wallet_metadata` | Whether a placement's proof holds a member | Holds: the inherent methods of `Placement`; the registry refuses another (`MemberPlacement`) |
| `JwsAlgorithm` | `jose` | A JWS `alg` name of the IANA registry | Holds: private `&'static str`; `const fn new -> Option`; `ES256` a constant |
| `JwsAlgorithms` | `jose` | The JWS algorithms a verifying module states | Holds: private slice; `const fn new`; `NONE`, the empty statement, under which A7 refuses every signature |
| `JweAlgorithms` | `jose` | The curves, `alg` and `enc` values a decrypting module states, each one or more | Holds: private slices; `const fn new -> Option` refuses an empty list |
| `JwsSignature` | `jose` | A signature's octets, as the JWS holds them (RFC 7515 §5.1) | Boundary: their length is the `alg`'s, which the verifying module checks; private, only the JWS parses make one |
| `PublicJwk` | `jose` | A public JWK: a JSON object with unique names, `kty`, no private member (RFC 7517 §4, RFC 7518 §6) | Holds: private `Object`; only `PublicJwkApi::parse` makes one |
| `NotPublicJwk` | `jose` | One variant per public-JWK rule | Holds: a refusal enum, one variant per rule |
| `PublicJwkApi` | `jose` | Parses and reads a public JWK | Holds: the inherent methods of `PublicJwk` |
| `DcApi` | `modes` | The core's `dc_api` mode (A.2) | Holds: a unit struct implementing `Mode` and `ModeHost<H>` for every `H`; registered with `mode` |
| `DcApiJwt` | `modes` | The core's `dc_api.jwt` mode (A.2, §8.3) | Holds: a unit struct implementing `Mode` and `ModeHost<H>` for every `H`; registered with `jwe_mode`, whose bound reaches `Haip` |
| `DirectPostJwt` | `modes` | The core's `direct_post.jwt` mode (§8.3.1) | Holds: a unit struct implementing `Mode`, `ModeHost<H>` and `ErrorModeHost<H>` for every `H`; registered with `jwe_mode` and `error_mode` |
| `DirectPost` | `modes` | The core's `direct_post`, which carries errors alone (reading 24) | Holds: a unit struct implementing `Mode` and `ErrorModeHost<H>`; registered with `error_mode` alone |
| `KeyRule` | `modes` | C7: no key, or no `enc`, the JWE modes' key rule accepts | Holds: a refusal enum, one variant per rule, each naming the mode, with the model's text; its code `invalid_request` |
| `Card` | `consent` | What a format draws for a credential: icon, title, subtitle, rows | Holds: public fields of `Icon`, `Text` and `Row` |
| `Overlay` | `consent` | What a profile draws over a card: rows, a transaction header, a hint | Holds: public fields of checked types |
| `TransactionHeader` | `consent` | A transaction's counterparty, amount and rows (PSD2 RTS Art. 5(1)(a)) | Holds: public fields of resolved `Text` and `Row` |
| `ConsentEntry` | `consent` | A consent entry: the card and the transaction's overlay | Holds: private fields; only the core's display step makes one |
| `Icon` | `consent` | An icon of at least one byte with its image media type; the core's `rows` | Holds: public fields of checked types: `ImageMedia`, `NonZeroU32` |
| `ImageMedia` | `consent` | The essence of a media type of top-level type `image` (RFC 6838 §4.2.3); the core's `rows` | Holds: private text; only `of` and `parse` make one, and the consts `PNG`, `JPEG`, `SVG` |
| `ImageMediaApi` | `consent` | Reads the image media type of a media type or a text | Holds: the inherent methods of `ImageMedia` |
| `NotImageMedia` | `consent` | A text that is no media type, or names no image | Holds: a refusal enum, one variant per rule |
| `StaticEntry` | `consent` | An entry the wallet adds first to every set; the core's `matching` | Holds: public fields: a `StaticEntryId` and a core-made `Card` |
| `ErrorCode` | `explain` | An error code: one or more of RFC 6749 Appendix A.7's `NQSCHAR` | Holds: private `&'static str`; `const fn new -> Option`; the specifications' codes as constants, a plug-in's by `checked!` |
| `Curve` | `kept` | A JWK `crv` of the IANA registry | Holds: private `&'static str`; `const fn new -> Option`; `P_256` a constant |
| `KeyAgreement` | `kept` | A JWE key agreement `alg` (RFC 7518 §4.6) | Holds: private `&'static str`; `const fn new -> Option`; `ECDH_ES` a constant |
| `ContentEncryption` | `kept` | A JWE content encryption `enc` (RFC 7518 §5.1) | Holds: private `&'static str`; `const fn new -> Option`; `A128GCM`, `A256GCM` constants |
| `Agreements` | `kept` | What a module agrees keys and encrypts with, or what a key rule accepts, in its order of preference | Holds: private slices; `const fn new`; `NONE` for a module that encrypts nothing; `admits` reads a key's curve and `alg` |
| `SessionBinding` | `kept` | The DC API with its Origin, or a URI with its Client Identifier and `response_uri` (B.2.6's inputs) | Holds: an enum of checked references |
| `Isolation` | `kept` | Where an inherence factor's comparison ran | Holds: an enum whose every variant is an environment, `Unreported` included |
| `FalseAcceptRate` | `kept` | At most one false accept in n attempts | Holds: private `NonZeroU32`; `one_in` takes a non-zero count |
| `AttackDetection` | `kept` | Presentation attack detection (ISO/IEC 30107-1) | Holds: an enum whose every variant is a state, `Unreported` included |
| `Inherence` | `kept` | An inherence factor as the platform reports it: modality, sensor, and its matching's facts | Holds: public fields of checked types; a profile classifies it |
| `Presentation` | `kept` | A presentation in a VP Token: a string or a JSON object (§8.1) | Fixed (constrained primitive in a public field): private `String`; only `text` and `object` make one |
| `NotPresentation` | `kept` | A presentation's value that is no JSON object | Holds: a refusal struct, one rule |
| `PresentationApi` | `kept` | Makes and reads a presentation | Holds: the inherent methods of `Presentation`; `object -> Result<_, NotPresentation>` |
| `BiometricClass` | `profile` | `bio_weak` or `bio_strong` (PaSO Risk Signal Registry §2.8), ordered | Holds: an enum whose every variant is a class |
| `BiometricClassApi` | `profile` | Classifies an inherence factor by Registry §2.8's FAR bounds | Holds: a trait; `of -> Option<Self>`, `None` for a rate above one in 10,000 or unreported |
| `ScaMembersApi` | `profile` | PaSO's SCA claims as members of a placement (Core §6.2, §6.3) | Holds: a trait; `members` takes a `Placement`, so siros-paso names no format |
| `PrefixHost` | `authenticate` | A prefix's claim over the build's host | Holds: a trait; its bounds name the modules it calls; it reads the core-made `ClientClaim` |
| `HostedPrefix` | `authenticate` | A prefix the registry takes | Holds: a trait with a blanket implementation over `PrefixHost<H>` |
| `ScopeValue` | `scope` | A scope value: one or more of RFC 6749 §3.3's `NQCHAR` (%x21, %x23-5B, %x5D-7E) | Holds: private `&'static str`; `const fn new -> Option`; a plug-in's by `checked!` |
| `ScopeQuery` | `scope` | A scope value and the DCQL query it stands for (§5.5) | Holds: a trait; the registry parses the query when it builds and refuses a conflict |
| `HandoverApi` | `plugins` | siros-mdoc's handover of a session | Holds: a trait; `of -> Result<_, Fault>` reads the session's binding facts |
| `StandardEntry` | `credman::entry` | siros-credman's Standard entry (`AddEntryToSet`) | Holds: public fields of checked types; its icon an `EntryIcon` |
| `PaymentEntry` | `credman::entry` | siros-credman's Payment entry (`AddPaymentEntryToSetV2`) | Holds: public fields of checked types; its method icon an `EntryIcon` |
| `CredmanEntry` | `credman::entry` | A Standard or a Payment entry | Holds: an enum; `Payment` for an entry whose overlay holds a transaction header |
| `CredmanEntryApi` | `credman::entry` | Maps a consent entry, or a static entry, to Credential Manager's entry | Holds: a trait; `of` and `of_static` read core-made entries |
| `EntryIcon` | `credman::entry` | An icon Credential Manager draws: the card's PNG or JPEG, else `Icon::DEFAULT` | Holds: private field; only `EntryIconApi::of` makes one |
| `EntryIconApi` | `credman::entry` | Reads a card's icon into an `EntryIcon` | Holds: the inherent methods of `EntryIcon` |
| `TransactionData` | `credman::delegation` | Whether the request carries `transaction_data` (siros-credman's A9) | Holds: an enum read from the request |
| `TransactionDataApi` | `credman::delegation` | Reads the request's `transaction_data` presence | Holds: the inherent methods of `TransactionData` |
| `SetFacts` | `credman::delegation` | What A9 judges a set of the `Display` by | Holds: private fields, one accessor each; `of` reads them from the set, the presentable credentials and `TransactionData`; `whole` from each row's `Field` |
| `SetFactsApi` | `credman::delegation` | Reads a set's facts | Holds: the inherent methods of `SetFacts` |
| `Presentable` | `credman::delegation` | The credentials the app declares presentable without the wallet's UI | Holds: a public slice of `CredentialId`s |
| `NoName` | `credman::field` | A row's label with no visible character | Holds: a unit struct; only `FieldName::fit` refuses with it |
| `Field` | `credman::field` | A row as Credential Manager's field: its name, and its value when the row has one | Holds: private fields; only `Field::of` makes one, from a row |
| `FieldApi` | `credman::field` | Reads a row into a field | Holds: the inherent methods of `Field`; `of -> Result<_, NoName>` |
| `FieldName` | `credman::field` | A field's name: a `FieldText` with a visible character | Holds: private `FieldText`; `fit -> Result<_, NoName>` |
| `FieldNameApi` | `credman::field` | Fits a label into a field's name | Holds: the inherent methods of `FieldName` |
| `FieldText` | `credman::field` | A field's text: at most `FIELD_MAX` (80) characters, cut at an extended grapheme cluster boundary, each bidi isolate or embedding it opens closed | Holds: private fields; only `fit` and `partial` make one |
| `FieldTextApi` | `credman::field` | Fits a text into a field | Holds: the inherent methods of `FieldText` |
| `Extent` | `credman::field` | Whether a field's text is whole or cut | Holds: an enum whose every variant is an extent |
| `Encrypting` | `response` | A mode's choice: the clear, or one of the request's keys with an `enc`, which the core seals to | Holds: an enum; `Jwe` holds a `VerifierKey`, which only the request's keys yield; the core checks it against the sealing statement and the Verifier's list |
| `RouteKey` | `response` | The key and `enc` a route bound, which the core seals to and the session holds | Fixed (relational rule outside a step): private; only `Route::new` makes one, after checking the mode's choice |
| `ModeHost` | `response` | A mode's answers in phase 2: its encryption, its `wallet_metadata` values, the body around an answer | Fixed (an extension's output the core takes unchecked): the core checks the choice, seals itself and hands a sealed route's mode the JWE alone; it checks each body's channel and sends it to the route's endpoint |
| `HostedMode` | `response` | A mode the registry of `H` takes: a `Mode` for `NoHost`, a `ModeHost<H>` for a host | Holds: a conversion trait with one impl per host kind |
| `ModeRoute` | `response` | What a mode reads of its route: the bound key and `state` | Holds: private fields; only the route makes one |
| `RouteEncryption` | `response` | The answering mode's choice, made once: the clear, a bound key, or refused (C7, or C6 for `client_metadata`) | Holds: a private enum; only `Route::new` builds it, from a checked choice; `Route::read` returns the refusal beside the route |
| `ErrorResponse` | `response` | An error response: code, description, `state` as received (§8.5) | Holds: private fields; only the core's route and rejection make one |
| `Body` | `response` | What a mode writes: DC API `data` or a POST body | Holds: an enum of checked `DcApiData` and `PostBody` |
| `FormMedia` | `response` | A POST body of the form media type that no `FormBody` wrote | Holds: a refusal struct, one rule; id `err.openid4vp.post_body.form_media` |
| `NotObject` | `response` | DC API `data` that is no JSON object with unique names | Holds: a refusal struct, one rule; id `err.openid4vp.dc_api_data.not_object` |
| `RandomIds` | `profile` | Fresh RFC 9562 version 4 UUIDs, for `jti` | Holds: a trait in siros-paso, which its callers bound |
| `RegistryErrorAdditions` | `host` | The registry's refusals beside a format's and a profile's: modes, response types, prefixes, hashes and `sha-256`, scopes, the POST, a name twice or reserved | Holds: a refusal enum, one variant per rule |
| `RequestPost` | `uri` | The POST of `wallet_metadata` (§5.10), a core component | Holds: a unit struct; `RegistryApi::request_post` takes it with no module bound |
| `NotForm` | `uri` | Members that make no form body: a nested value, or a name twice | Holds: a refusal enum, one variant per rule; ids `err.openid4vp.form.*` |
| `HashesAlgRule` | `hash` | B.3.3.1's rules on an entry's `transaction_data_hashes_alg`: `invalid_transaction_data` | Holds: a refusal enum, one variant per rule |
| `ReprList` | `hash` | Values a rule names: `repr_text` writes Python's `repr` of the list for the logs, `Display` the items as written, joined by `, ` | Holds: private `Vec<ReprItem>` |
| `ReprItem` | `hash` | A received value a rule names: `repr_text` writes its `repr` for the logs, `Display` the text as written | Holds: private fields |
| `HashName` | `hash` | A Hash Name String: lowercase ASCII letters, digits, `-` (RFC 6920 §9.4) | Holds: private `&'static str`; `const fn new -> Option` |
| `HashAlgorithm` | `hash` | A transaction data hash algorithm: name, digest length and digest (B.3.3.1) | Holds: a trait; the registry refuses a name twice and a transaction data build without `sha-256`; the core refuses a digest of another length than `octets` |
| `Hashes` | `hash` | The registered hash algorithms the request carries from its registry | Holds: a private slice; only the registry makes one; `plugins::Hashes`, re-exported as `hash::Hashes` |
| `HashesApi` | `hash` | Finds an algorithm by its Hash Name String | Holds: the inherent methods of `Hashes` |
| `Sha2` | `hash` | The core's SHA-2 algorithms of the registry | Holds: an enum whose every variant is a registered algorithm |
| `Truncation` | `hash` | SHA-256's truncations (RFC 6920 §2) | Holds: an enum whose every variant is a registered length |
| `Sha3` | `hash` | The SHA-3 algorithms, feature `sha3` | Holds: an enum whose every variant is a registered algorithm |
| `Blake2` | `hash` | The BLAKE2 algorithms, feature `blake2` | Holds: an enum whose every variant is a registered algorithm |
| `K12` | `hash` | The KangarooTwelve algorithms, feature `k12` (RFC 9861 §6) | Holds: an enum whose every variant is a registered algorithm |
| `ResponseTypeName` | `routing` | A `response_type` value: response names of ASCII letters, digits and `_`, single spaces between (RFC 6749 §3.1.1) | Holds: private `&'static str`; `const fn new -> Option`; a plug-in's by `checked!` |
| `ResponseType` | `routing` | A response type whose Authorization Response carries the VP Token (§8; RFC 6749 §8.4) | Holds: a trait; `name` a checked `ResponseTypeName`; P1 refuses an unregistered one; the registry refuses a name twice |
| `VpToken` | `routing` | The core's `vp_token` response type (§5.6) | Holds: a unit struct implementing `ResponseType` |
| `ParameterName` | `wallet_metadata` | A parameter or metadata name: one or more of ASCII letters, digits, `-`, `.` and `_` (RFC 6749 §8.2) | Holds: private `&'static str`; `const fn new -> Option`; a plug-in's by `checked!` |
| `PostParameter` | `wallet_metadata` | One `request_uri` POST parameter a contribution writes | Holds: private fields; `new` takes a checked `ParameterName`; the composition refuses an undeclared one |
| `PostContent` | `wallet_metadata` | What a contribution writes into one POST: members and parameters | Holds: public fields of checked types; the core reads each name against the contribution's declaration |
| `PostContribution` | `wallet_metadata` | Members and POST parameters a profile or a deployment adds (§10.1, §5.10) | Holds: a trait (`DynClone` in the core); its names are constants the registry checks against the others' and the core's |
| `PostContributionHost` | `wallet_metadata` | A contribution's phase 2 over the build's host | Fixed (an extension's output the core takes unchecked): `write`'s names are checked against the declaration (`MetadataRefused::Undeclared`) |
| `HostedPostContribution` | `wallet_metadata` | A contribution the registry takes | Holds: a trait with a blanket implementation over `PostContributionHost<H>` |
| `NotSealedCose` | `profile` | One variant per rule: a `COSE_Encrypt`'s CBOR item, its tag 96, its structure, its `enc` | Holds: a refusal enum, one variant per rule |
| `ObjectRule` | `authenticate` | A rule a profile or a deployment sets on an authenticated Request Object's claims (A14) | Holds: a trait; it reads the claims alone and returns a `Refusal` with its rule's code |
| `Cs02Claims` | `plugins` | siros-webuild's CS-02 §8.2 rule: `exp` and `aud` present | Holds: a unit struct implementing `ObjectRule` |
| `ClaimAbsent` | `plugins` | The CS-02 §8.2 claim a Request Object lacks | Holds: a refusal struct with a private `claim: RequiredClaim`, read by `claim()` |
| `ClaimAbsentApi` | `plugins` | Reads the claim a `ClaimAbsent` names | Holds: the inherent methods of `ClaimAbsent` |
| `Clause` | `kept` | A citation its crate's source writes | Holds: private `&'static str`; `cited` |
| `DocumentKey` | `kept` | A key of a credential's documents, non-empty | Holds: private text; `const fn new -> Option`; `checked!` |
| `TypePrefix` | `kept` | A prefix a profile registers under, non-empty | Holds: private text; `const fn new -> Option`; `checked!` |
| `ViewBytes` | `kept` | A format's view, in its encoding | Holds: private bytes in their role |
| `DocumentBytes` | `kept` | A document's content, in the plug-in's encoding | Holds: private bytes in their role |
| `DerCertificate` | `kept` | One DER certificate of an issuer chain, its bytes as the chain holds them | Holds: private bytes in their role |
| `BytesRole` | `kept` | What the role types above share | Holds: a trait; `new` and `as_bytes` |
| `Constraint` | `kept` | One `vp_formats_supported` member over a presentation | Holds: public fields of checked types; `also` stays out of a refusal |
| `IssuedMetadata` | `kept` | What OpenID4VCI states of a credential's display | Holds: public optional fields, each as received; the merge reads them |
| `DocumentNumber` | `qes::approval` | A document's number from 1, which `QesText::Section.document` and `Excluded::Checksum.document` hold | Holds: private `NonZeroUsize`; only `ApprovalRequest::numbered_documents` makes one |
| `Excluded` | `qes::rules` | Why the QES profile excludes a credential: the qualifier, the carriage or a document's checksum | Holds: a refusal enum, one variant per rule |
| `P256Point` | `trust::certificate` | A certificate's P-256 key, SEC 1 | Holds: private; only `Certificate::p256_key` makes one |
| `P384Point` | `trust::certificate` | A certificate's P-384 key, SEC 1 | Holds: private; only `Certificate::p384_key` makes one |
| `JwkCoordinate` | `sdjwt::error` | `x` or `y` | Holds: an enum whose every variant is a coordinate |
| `PermanentClaim` | `sdjwt::error` | A claim no disclosure reveals (SD-JWT VC §3.2.2) | Holds: an enum whose every variant is such a claim |
| `ValidityClaim` | `sdjwt::error` | `nbf` or `exp` | Holds: an enum whose every variant is such a claim |
| `FixedSd` | `sdjwt::type_metadata` | An `sd` an extending type keeps (SD-JWT VC §8.5.1) | Holds: an enum of the two |
| `Resolved` | `sdjwt::registration` | What the wallet resolved beside the issued SD-JWT | Holds: public fields of checked types; `metadata` an `Object` |
| `ResolvedCurve` | `sdjwt::error` | A curve a refusal names | Holds: private text; `From<Curve>` |
| `IssuerJwt` | `sdjwt::sd_jwt` | The Issuer-signed JWT in compact form | Holds: private; only `SdJwt::issuer_jwt` makes one |
| `JwtType` | `sdjwt::sd_jwt` | The Issuer-signed JWT's `typ` | Holds: private; only `SdJwt::typ` makes one |
| `KbSigningInput` | `sdjwt::key_binding` | What the holder's key signs | Holds: private; only `KeyBinding::signing_input` makes one |
| `KbSignature` | `sdjwt::key_binding` | A Key Binding JWT's signature | Holds: private bytes in their role |
| `SdJwtKb` | `sdjwt::key_binding` | The presentation as sent | Holds: private; only `KeyBinding::assemble` makes one |
| `HandoverUri` | `mdoc` | A `response_uri` as B.2.6.1 hashes it | Boundary: any text, since B.2.6.1 hashes it as written; `From<&ResponseUri>` |
| `HandoverUriApi` | `mdoc` | Makes and reads a `HandoverUri` | Holds: the inherent methods of `HandoverUri` |
| `Curve` | `mdoc::stored` | A curve of ISO/IEC 18013-5 Table 22 | Holds: an enum whose every variant is such a curve |
| `SignatureAlgorithm` | `mdoc::cose` | A COSE signature algorithm a device key makes | Holds: an enum whose every variant signs |
| `SignatureAlgorithmApi` | `mdoc::cose` | Parses a COSE identifier and gives it back | Holds: the public inherent methods of `SignatureAlgorithm` |
| `SignatureAlgorithmCrateApi` | `mdoc::cose` | Whether a key on a curve makes the algorithm: `made_on` | Holds: crate-private; the crate-private inherent method of `SignatureAlgorithm` |
| `DeviceKey` | `mdoc::stored` | The MSO's device key, a stated algorithm its curve makes | Holds: private fields; only the stored reader makes one, refusing with `DeviceKeyFault::Algorithm` |
| `DeviceKeyApi` | `mdoc::stored` | Reads the curve and the algorithm | Holds: the inherent methods of `DeviceKey` |
| `DeviceKeyView` | `mdoc::cose` | A device key as the view states it | Holds: crate-private fields; `new -> Option` applies `made_on` |
| `DeviceKeyFault` | `mdoc::stored::device_key` | What an MSO holds that names no device key | Holds: a refusal enum, one variant per rule |
| `DeviceAuthRefused` | `mdoc::presentation` | Why a device key cannot authenticate for a Verifier | Holds: a refusal enum, one variant per rule |
| `IssuerName` | `mdoc::registration` | The issuer's name from `x5chain` | Holds: private text in its role |
| `IssuerSignature` | `mdoc::stored` | `issuerAuth`'s signature | Holds: private bytes in their role |
| `DataElements` | `mdoc::stored` | A name space's elements `KeyAuthorizations` admits | Holds: private fields; only the stored reader makes one |
| `Resolved` | `mdoc::registration` | What the wallet resolved beside the stored mdoc | Holds: public fields of checked types |
| `RegistrationError` | `mdoc::registration` | Why a stored mdoc makes no view | Holds: a refusal enum, one variant per rule |
| `WalletVersion` | `paso::measure` | The wallet application's version (Core §6.1 `wallet_instance_version`), which Core gives no grammar | Holds: private `Cow`; `new`, `as_str` |
| `PasoTypeApi` | `profile` | A type under a profile's own identifier | Holds: the inherent `rendered_by`, which `PasoType::parse` calls |
| `Cs02ErrorAnswer` | `plugins` | siros-webuild's reader of CS-02 §8.3's `error` and `error_description` | Holds: a unit struct implementing `AnswerReader` |
| `ErrorAnswerForm` | `plugins` | An error answer outside RFC 6749 §5.2's form | Holds: a refusal struct, one rule |
| `AnswerContent` | `response` | What a mode wraps for an answer: the clear response, or the JWE the core sealed it in | Holds: an enum of core-made values; a sealed route's mode receives the JWE alone |
| `ErrorContent` | `response` | What an error mode wraps: the clear error, or the JWE the core sealed it in | Holds: an enum of core-made values |
| `ErrorModeHost` | `response` | A URI mode's errors in phase 2: the form body around the error | Holds: a trait; it returns a `PostBody`, which the core sends to the route's `response_uri`; the core writes A.4's error over the DC API |
| `HostedErrorMode` | `response` | An error mode the registry of `H` takes: a `Mode` for `NoHost`, an `ErrorModeHost<H>` for a host | Holds: a conversion trait with one impl per host kind |
| `ResponseParameters` | `routing` | Authorization Response parameters an extension adds (§8.1), in every build | Holds: a trait (`DynClone` in the core); its names are constants the registry checks against the others' and `CORE_RESPONSE`, and keeps |
| `ResponseParametersHost` | `routing` | Response parameters' phase 2 over the build's host | Fixed (an extension's output the core takes unchecked): `members`' names are checked against the names the registry kept, each once, a `Fault` caused by `ParameterBreach` otherwise |
| `ResponseMember` | `response` | One Authorization Response parameter an extension writes | Holds: private fields; `new` takes a checked `ParameterName` and a JSON value |
| `ChannelRoute` | `response` | A route per channel with the session's binding facts: over the DC API the Origin and the answering mode when registered; by URI the bound `response_uri`, the authenticated Client Identifier, the error mode and the answering mode | Holds: a private enum; only `Route::new` builds it, so a URI route holds an endpoint, a Client Identifier and an error mode |
| `Chosen` | `response` | An answering mode and its encryption, chosen once | Holds: a private struct; only `Route::new` builds it |
| `AnswerRoute` | `response` | The route an Authorization Response takes: the chosen mode, its key, the Verifier's keys, the `nonce` | Fixed (typestate gap): only `RouteApi::answering` makes one, for a route whose request names a registered answering mode whose choice holds, under no C6 refusal, with a `nonce` N1 accepts |
| `AnswerRouteApi` | `response` | The session the presentations bind; delivers an answer: sealed by the core, wrapped by the mode, sent to the bound endpoint | Holds: the inherent methods of `AnswerRoute` |
| `KeyHandle` | `host` | The module's reference to the secret of a key it drew | Holds: private `u64`; the core holds it and reads nothing of it |
| `NamePlace` | `host` | Where a registered name sits: `wallet_metadata`, the POST, the Response URI's answer, the Authorization Response | Holds: an enum whose every variant is a place |
| `EncryptedRequests` | `uri` | Encrypted Request Objects (§5.10), a core component | Holds: a unit struct; `RegistryApi::request_encryption` takes it from a host holding `RequestDecryption` |
| `AnswerReader` | `uri` | Members of the Response URI's answer a profile or a deployment defines (§8.2) | Holds: a trait (`DynClone` in the core); its names are constants the registry checks; it reads `AnswerMembers` alone |
| `AnswerMembers` | `uri` | The members of an answer one reader declares, as received | Holds: private fields; only `ResponseUriAnswerApi::parse` makes them, and `get` answers declared names alone |
| `EntryNaming` | `routing` | Whether a request's entries carry a name a static entry names | Holds: an enum; `QueryContext::naming` reads it |
| `CandidateIndex` | `matching` | A candidate's position among its query's | Holds: private `usize`; only `Match::indexed_candidates` makes one |
| `SetIndex` | `matching` | A set's position in a display | Holds: private `usize`; only `Display::set` makes one |
| `RecordIndex` | `resolve` | A record's position in phase 2's findings | Holds: private `usize`; the core makes one per record |
| `EntryIndex` | `plugins` | A `transaction_data` entry by its position in the array | Holds: private `usize`; the core makes one per entry |
| `SelectionError` | `matching` | A selection the core refuses: a set past the display's, or ids that do not fit the set's slots | Holds: a refusal enum, one variant per rule |
| `DisplayApi` | `matching` | Reaches a set of a display | Holds: the inherent methods of `Display`; `set -> Result<_, SelectionError>` |
| `DisplaySetApi` | `matching` | Reads the platform's returned ids into a selection | Holds: the inherent methods of `DisplaySet`; the ids are untrusted text it looks up |
| `Carriage` | `plugins` | Whether a presentation can carry a profile's response members | Holds: an enum whose two variants are the answer |
| `FormatQueryAdditions` | `plugins` | `options`, `carries` and `displayable` beside `answerable` and `draw` | Holds: a sketch of what `FormatQuery` holds; `displayable` refuses with `NoCandidate`, which `Match::run` turns into `ExcludedBy::Display` |
| `ClaimsFormatAdditions` | `claims::kit` | `id`, `types`, `meta_matches` and `withheld` beside a format's readers | Holds: a sketch of what `ClaimsFormat` holds; `withheld` defaults to false; siros-sdjwt marks an array element `{"...": digest}`, which holds no value |
| `DisplayText` | `claims::kit` | A credential's text in a role: no character of the Cc, Cf, Zl, Zp, Co or Cn categories, within the role's length; a label and a card text hold a visible character | Holds: private text; `label`, `card`, `value` and `template` refuse with `TextError` |
| `TextError` | `claims::kit` | Why a text is refused | Holds: a refusal enum, one variant per rule |
| `CardError` | `claims::kit` | Why a credential's view shows no card: a pointer that selects nothing, a refused text, or a count that is no count literal | Holds: an enum; `Path` holds a `PathError`, `Text` a `TextError`, `Count` a `Malformed` |
| `RefusedText` | `claims::kit` | The exclusion of a credential whose text breaks the rule of display text | Holds: a public `TextError` |
| `SetNeed` | `request` | Whether a selection must satisfy a Credential Set (§6.2 `required`) | Holds: an enum whose two variants are the answer |
| `CredentialSetApi` | `request` | `CredentialSet`'s accessors | Holds: the inherent methods of `CredentialSet`, whose fields are private |
| `DisplayTextApi` | `claims::kit` | Takes a text in a role | Holds: the inherent methods of `DisplayText` |
| `Facts` | `wallet` | A credential's holder binding and its held authorities, each type once | Holds: private `authorities`; `of` merges pairs of one type; `new` refuses a repeated type |
| `FactsApi` | `wallet` | Builds facts from pairs and answers a query's `trusted_authorities` | Holds: the inherent methods of `Facts` |
| `HeaderAlgorithm` | `jose` | A protected header's `alg` | Holds: private text; only the JWS parses make one |
| `HeaderType` | `jose` | A protected header's `typ` | Holds: private text; only the JWS parses make one |
| `NamedQueryId` | `ids` | A `credential_ids` element as a `transaction_data` entry wrote it | Holds: private text; `parse` holds any text, which rule C2 looks up |
| `ExpectedOrigin` | `ids` | An `expected_origins` element as a signed request wrote it | Holds: private text; `parse` holds any text, which rule C8 compares with the Origin |
| `NamedResponseUri` | `ids` | The `response_uri` as a request wrote it | Holds: private text; authentication parses it (A13) |
| `StaticEntryId` | `ids` | A static consent entry's id | Holds: private text; `parse` refuses an empty text |
| `ClaimId` | `ids` | A claims query's id (§6.3's charset) | Holds: private text; `parse` refuses a text outside the charset |
| `KeyId` | `ids` | A `kid` (RFC 7517 §4.5) | Holds: private text; `parse` holds any text |
| `CredentialType` | `ids` | A credential's type: a `vct` or a docType | Holds: private text; `parse` holds any text |
| `Shown` | `credman::emit` | An entry as Credential Manager draws it, in its Standard or Payment form | Holds: an enum of boxed forms |
| `Row` | `rows` | A label, its value and its section; a full-width text holds no value | Holds: public fields of resolved `Text` and `Value` |
| `Value` | `rows` | A row's value: an image, or a text | Holds: an enum whose every variant is a value |
| `Image` | `rows` | An image a row shows: embedded, or fetched at phase 2 | Holds: an enum of checked parts |
| `ImageSource` | `rows` | Where an embedded image came from | Holds: an enum; `Url` holds an `HttpsUrl` |
| `ImageWidth` | `rows` | An image's width | Holds: a `u32` in its role |
| `ImageHeight` | `rows` | An image's height | Holds: a `u32` in its role |
| `ImageRef` | `rows` | An embedded image's source, media type and size | Holds: private fields; `new` takes each in its role |
| `SriMetadata` | `rows` | An `integrity` value | Holds: private text; every text parses, as SRI §3.3.3 lets `sri::matches` judge it |
| `RemoteImage` | `rows` | A URL to fetch and the digest to check | Holds: private fields; `new` takes an `HttpsUrl` and an `SriMetadata` |
| `WalletText` | `consent` | The core's statements for the consent entry | Holds: an enum deriving `Message`; each variant is a statement the wallet words |
| `BooleanText` | `plugins` | A boolean's text, a statement of the core | Holds: an enum deriving `Message`, one variant per value |
| `AttestedName` | `plugins` | A member name a credential attests | Holds: private text |
| `AttestedText` | `plugins` | A value text a credential attests | Holds: private text |
| `PasoType` | `paso::rulebook` | A type identifier under `urn:paso:sca:` with the rulebook that renders it | Holds: private fields; the parse sets the family from the identifier |
| `ProfileId` | `paso::risk` | A risk signal profile identifier (Risk Signals §3.2) | Holds: private text; a crate's by a build-time check |
| `ConvertError` | `paso::view` | Why a metadata document converts to no MF2 source | Holds: a refusal enum, one variant per rule |
| `ViewId` | `paso::view` | The prefix of a type's converted ids: `paso.view.` and the SHA-256 of the metadata's compact JSON | Holds: private text; only `ViewId::of` makes one, from the metadata |
| `ViewIdApi` | `paso::view` | Computes and reads a metadata's prefix | Holds: the inherent methods of `ViewId` |
| `AdhocFailure` | `paso::adhoc` | The §5.3 step an ad-hoc JWT fails | Holds: a refusal enum, one variant per step |
| `AdhocJwt` | `paso::adhoc` | An ad-hoc JWT's text | Holds: private text as received |
| `AdhocRefusal` | `paso::adhoc` | A JWT refused for a credential, with the step | Holds: public fields of checked types |
| `Read` | `paso::adhoc` | A JWT read: its JWS, payload and metadata | Holds: private fields; only `Read::parse` makes one |
| `Carried` | `paso::adhoc` | A request's carried JWTs, signature unchecked | Holds: private fields; only `Carried::read` makes one |
| `UriFlow` | `paso::adhoc` | A request by `transaction_data_uri` reaching the matcher | Holds: a unit struct in the refusal |
| `Verified` | `paso::adhoc` | A request's JWTs verified for each credential, with the refusals | Holds: private fields; only `Verified::of` makes one |
| `CarriedApi` | `paso::adhoc` | Reads what a request carries | Holds: the inherent methods of `Carried` |
| `VerifiedApi` | `paso::adhoc` | Verifies what a request carries | Holds: the inherent methods of `Verified` |
| `NotRootCertificate` | `paso::modules` | A body that is no certificate | Holds: a unit refusal |
| `RootCertificate` | `paso::modules` | A root of the wallet's store | Holds: private bytes; only `parse` makes one |
| `RootCertificateApi` | `paso::modules` | Parses and reads a root | Holds: the inherent methods of `RootCertificate` |
| `IssuerTrust` | `paso::modules` | The wallet's trust store of Credential Issuer roots | Holds: required by siros-paso under `resolve`; `TestIssuerTrust` is the double |
| `TestIssuerTrust` | `paso::modules` | The trust store double | Holds: `test-util`; written with the public API |
| `ChainRoot` | `paso::document` | An `x5c` chain's root, DER | Holds: private bytes; only the chain's read makes one |
| `ChainSubject` | `paso::document` | A leaf's Subject, DER | Holds: private bytes; only the chain's read makes one |
| `Issuer` | `paso::document` | Who a metadata document names as its issuer | Holds: an enum of a key set or a chain |
| `PasoProfileAdditions` | `paso` | `with_verified` and `with_refusals` | Holds: the inherent methods of `PasoProfile` |
| `PasoFinding` | `paso::phase2` | What phase 2 finds changed since phase 1, at least one of four | Fixed (several `Option`s encoding a sum): private fields; `of` returns none when nothing holds |
| `PasoFindingApi` | `paso::phase2` | The accessors of `PasoFinding` | Holds: the inherent methods of `PasoFinding` |
| `MandateLabel` | `paso::mandate` | A label of the Mandate claims | Holds: an enum; each variant is a message the wallet words |
| `Section` | `paso::rulebook` | The title of the section an embedded `payment_payload` renders in | Holds: an enum; each variant is a message the wallet words |
| `Frequency` | `paso::frequency` | A payment's frequency, one message per ISO 20022 code | Holds: an enum; each variant is a message the wallet words |
| `EntryPosition` | `qes::rules` | A QES entry's position | Holds: private `EntryIndex`; only `Qes::parse` makes one |
| `DocumentAt` | `qes::approval` | A document's position in an entry | Holds: private `usize`; only the entry's read makes one |
| `Positions` | `qes::rules` | The positions of the entries one query names | Holds: private `AllOf` |
| `SignatureQualifier` | `qes::approval` | A `signatureQualifier` CS-02's table holds | Holds: an enum whose every variant is a qualifier |
| `Problem` | `qes::approval` | What breaks a QES entry | Holds: a refusal enum, one variant per rule |
| `QesRule` | `qes::rules` | A rule of the QES transaction type a request breaks | Holds: a refusal enum, one variant per rule |
| `DocumentHref` | `qes::documents` | A document's `href`, as written | Holds: private text |
| `Fetched` | `qes::documents` | A fetch's result | Holds: an enum: content that fails the digest, or a failure |
| `FailedDocument` | `qes::documents` | A document whose fetch or digest failed | Holds: private fields; only the phase 2 fetch makes one |
| `FailedDocuments` | `qes::documents` | The documents that failed: at least one | Holds: private `AllOf` |
| `QesTitle` | `qes::render` | The overlay's title and confirm action | Holds: an enum; each variant is a message |
| `QesText` | `qes::render` | The overlay's rows | Holds: an enum; each variant is a message |
| `X5cItem` | `x509::chain` | An item's position in `x5c` | Holds: private `usize`; only `X5c::of` makes one |
| `HashText` | `x509::names` | A hash's base64url text | Holds: private text; only `LeafHash::text` makes one |
| `IssuerFacts` | `trust::facts` | A credential's issuer chain resolved against the store at a time | Holds: private; only `at` makes one |
| `IssuerFactsApi` | `trust::facts` | Writes the core's `Facts` | Holds: the inherent methods of `IssuerFacts` |
| `SigningAlg` | `sdjwt::alg` | A JWS algorithm whose signature a private key makes | Holds: private text; `parse -> Option` refuses `none` and the MAC algorithms |
| `SigningAlgApi` | `sdjwt::alg` | Parses and reads a signing algorithm | Holds: the inherent methods of `SigningAlg` |
| `HolderKeyFault` | `sdjwt::error` | What a `cnf` holds that names no holder key | Holds: a refusal enum, one variant per rule |
| `EntryId` | `credman::emit` | The id of a display's choice, which the platform returns when the End-User picks it | Holds: private text; only `emit` makes one |
| `StandardShown` | `credman::emit` | A Standard entry as Credential Manager draws it: plain texts and fields | Holds: public fields; only `emit` makes one |
| `PaymentShown` | `credman::emit` | A Payment entry as Credential Manager draws it: plain texts and fields | Holds: public fields; only `emit` makes one |
| `Emitted` | `credman::emit` | A slot's choice as the matcher adds it: an entry, or the empty choice with its icon and title | Holds: an enum whose variants are the two |
| `Emission` | `credman::emit` | The display's sets as the matcher adds them: per set, per slot, its choices | Holds: private field; only `emit` makes one, once every choice emits |
| `NotEmitted` | `credman::emit` | The first choice that does not emit, which fails the emission | Holds: public fields: the choice's `EntryId` and its `Unshown` cause |
| `Unshown` | `credman::emit` | Why a choice does not emit: a `ResolveError` or a `NoName` | Holds: a refusal enum, one transparent variant per cause |
| `Kind` | `credman::registration` | A registration entry's kind, which the directory writes as its code | Holds: an enum whose every variant is a kind of version 1; an unknown code is `Malformed::Kind` |
| `Base` | `credman::registration` | The entries every request reads, and the matcher's context before a request | Holds: private fields; only `Base::load` makes one, so its sources load in its locale |
| `BaseApi` | `credman::registration` | Loads and reads a base | Holds: the inherent methods of `Base` |
| `ContextError` | `credman::registration` | Why the matcher's context does not load a registration's sources | Holds: a refusal enum, one variant per rule |
| `Registration` | `credman::read` | A registration in a reader: header, directory and base read, each transaction source's span | Holds: private fields; only `Registration::open` makes one, every offset and length checked against the blob's size into a typed span |
| `RegistrationApi` | `credman::read` | Opens a registration and reads a request's context | Holds: the inherent methods of `Registration`; `context` reads the sources the request names alone |
| `Malformed` | `credman::read` | A rule of the format a blob breaks | Holds: a refusal enum, one variant per rule, checked in the README's order |
| `ReadError` | `credman::read` | Why a registration is not read | Holds: a refusal enum: the reader's failure, `Malformed`, `ContextError` |
| `RegisterError` | `credman::register` | Why a registration is not written | Holds: a refusal enum, one variant per rule |
| `CredmanApi` | `credman` | `register::write` and `emit` | Holds: the crate's free functions; `write` takes a `Base`, so its sources load |
| `RequiredClaim` | `webuild` | A claim CS-02 §8.2 requires | Holds: an enum whose every variant is a claim |

#### The host modules (`host-sketch/`)

| Type | File | Invariant | How it holds |
| :-- | :-- | :-- | :-- |
| `Has` | `lib` | The host holds module `M` (axum `FromRef`) | Holds: a trait; the bound settles presence at compile time |
| `MayHave` | `lib` | The build holds module `M` or leaves it out, settled by the slot's type | Holds: a trait; its `Slot` is sealed |
| `Slot` | `lib` | A slot a build fills or leaves empty | Holds: sealed trait: `Held` and `Empty` alone |
| `Held` | `lib` | A filled slot: the module as `&'static` | Fixed (public field): private; `const fn new` |
| `Empty` | `lib` | An empty slot: the host's statement that its build leaves the module out | Holds: a unit struct |
| `Sealed` | `lib` | Closes `Slot` to `Held` and `Empty` | Holds: a sealed trait in a private module |
| `Host` | `lib` | `get` and `maybe` over `Has` and `MayHave` | Holds: a trait with a blanket implementation |
| `Timestamp` | `lib` | Seconds since the epoch | Holds: a placeholder for the core's `Timestamp`; any `u64` is a count of seconds |
| `CredentialId` | `lib` | A registration id | Holds: a placeholder for the core's `ids::CredentialId`, private with `parse -> Option` |
| `Fault` | `lib` | A module that broke its contract | Holds: a placeholder for the core's `Fault` |
| `Authentication` | `lib` | The End-User's applied factors | Holds: a placeholder for the core's `Authentication`, which only `Platform::authenticate` makes |
| `AuthenticationNeed` | `lib` | Presence, or strong authentication | Holds: an enum whose every variant is a need |
| `Algorithms` | `lib` | What a module states it implements, empty for a capability it lacks | Holds: a placeholder for `sigs/`'s `JwsAlgorithms`, `Agreements` and `JweAlgorithms`, each a constant list |
| `SignatureInvalid` | `lib` | A signature that does not verify | Holds: a refusal struct, a placeholder for `sigs/` `host::SignatureInvalid` |
| `SignFailed` | `lib` | The End-User cancelled, or the keystore broke its contract | Holds: a refusal enum, one variant per rule |
| `EphemeralKey` | `lib` | A fresh key the wallet posts: its public JWK and the module's handle to the secret | Holds: a placeholder for `sigs/` `host::EphemeralKey`: private fields, which only `new` fills |
| `Members` | `lib` | A profile's response members | Holds: an alias, a placeholder for the core's `Members` |
| `Answered` | `lib` | The record phase 2 answers, with the key an mdoc entry's risk signals are sealed to | Holds: a placeholder for the core's `Answered`, which only the core's phase 2 makes |
| `Content` | `lib` | What a mode wraps: the clear response or error, or the JWE the core sealed it in | Holds: a placeholder for `sigs/`'s `AnswerContent` and `ErrorContent`, an enum whose every variant is a content |
| `Evaluation` | `lib` | The AuthZEN evaluation a prefix asks: subject, action, resource | Holds: a placeholder for `sigs/` `effects::Evaluation` |
| `Platform` | `lib` | The wallet app: clock, credential status, End-User authentication | Holds: a trait, a placeholder of `sigs/` `host::Platform`, which types each result |
| `Haip` | `lib` | HAIP's cryptography (HAIP §5, §7): its statements, verify, sign, encrypt to the route's key | Holds: a trait, a placeholder of `sigs/` `host::Haip`, which types the key, the signed input, the route's key and the ciphertext |
| `RequestDecryption` | `lib` | Draws a fresh key and keeps its secret; decrypts under it, consuming it (RFC 9101 §6.1) | Holds: a trait; `decrypt` takes the `EphemeralKey` by value |
| `CoreHost` | `lib` | The module the core calls with no extension registered: `Platform` | Holds: a trait with a blanket implementation over `Has<dyn Platform>` |
| `Format` | `lib` | A format's presentation over the host `H` (`FormatHost<H>`) | Holds: a trait; its implementation's bounds name the modules |
| `Profile` | `lib` | A profile's phase 2 over the host `H` (`ProfileHost<H>`) | Holds: a trait; its implementation's bounds name the modules |
| `Prefix` | `lib` | A prefix's claim over the host `H` (`PrefixHost<H>`) | Holds: a trait; its implementation's bounds name the modules, and its registration bounds `Haip` |
| `Mode` | `lib` | A mode's answers over the host `H` (`ModeHost<H>`) | Holds: a trait; its implementation's bounds name the modules, and `jwe_mode`'s registration bounds `Haip` |
| `ErrorMode` | `lib` | A URI mode's errors over the host `H` (`ErrorModeHost<H>`) | Holds: a trait; its implementation's bounds name the modules |
| `ObjectRule` | `lib` | A rule on an authenticated Request Object's claims (A14) | Holds: a trait the registry takes from every host |
| `AnswerReader` | `lib` | A reader of the Response URI's answer members (§8.2) | Holds: a trait the registry takes from every host |
| `ResponseType` | `lib` | A response type (RFC 6749 §8.4) | Holds: a trait the registry takes from every host |
| `HashAlgorithm` | `lib` | A transaction data hash algorithm (B.3.3.1) | Holds: a trait the registry takes from every host |
| `RequestPost` | `lib` | The POST of `wallet_metadata` (§5.10), a core component | Holds: a unit struct the registry takes from every host |
| `EncryptedRequests` | `lib` | Encrypted Request Objects (§5.10), a core component | Holds: a unit struct; `request_encryption` takes it from a host holding `RequestDecryption` |
| `Registry` | `lib` | The parts whose bounds the build's host meets, with the accessors of the modules their registrations bound | Holds: private fields; each method takes a part implementing its trait for `H`; `prefix` and `jwe_mode` bound `Has<dyn Haip>` and `request_encryption` `Has<dyn RequestDecryption>`, each keeping the module's accessor, the core's one path to it |
| `DeviceMac` | `lib` | ISO/IEC 18013-5 §9.1.3.5's device MAC | Holds: a trait, a placeholder of `sigs/` `plugins::mdoc::DeviceMac` |
| `Paso` | `lib` | The wallet's version and risk signals (PaSO Core §6.1, Risk Signals §2.3) | Holds: a trait, a placeholder of `sigs/` `profile::paso_modules::Paso` |
| `RandomIds` | `lib` | Fresh RFC 9562 version 4 UUIDs, for siros-paso's and siros-ts12's `jti` | Holds: a trait, a placeholder of `sigs/` `profile::paso_modules::RandomIds` |
| `CoseEncrypt` | `lib` | A `COSE_Encrypt` (RFC 9052 §5.1) for an mdoc's sealed risk signals; siros-paso's, in every `resolve` build | Holds: a trait, a placeholder of `sigs/` `profile::paso_modules::CoseEncrypt`; siros-paso bounds `MayHave<dyn CoseEncrypt>` in every build |
| `Measurement` | `lib` | A risk signal's measurement | Holds: a placeholder for siros-paso's `Measurement` |
| `SdJwt` | `lib` | siros-sdjwt, bound to `Platform` and `Haip` | Holds: a unit struct |
| `Mdoc` | `lib` | siros-mdoc, bound to `Haip`, `DeviceMac` when held | Holds: a unit struct |
| `X509Hash` | `lib` | siros-x509's `x509_hash`, for every host | Holds: a unit struct |
| `X509SanDns` | `lib` | siros-x509's `x509_san_dns`, for every host | Holds: a unit struct |
| `PasoProfile` | `lib` | siros-paso without `sealed-signals`, bound to `Platform`, `Haip`, `Paso`, `RandomIds`, `IssuerTrust` and `MayHave<dyn CoseEncrypt>` | Holds: a unit struct |
| `PasoSealedSignals` | `lib` | siros-paso with `sealed-signals`: `PasoProfile`'s bounds, and the sealing with `CoseEncrypt` when held | Holds: a unit struct; a second type, since one crate holds both builds |
| `Ts12` | `lib` | siros-ts12, bound to `Platform` and `RandomIds` | Holds: a unit struct |
| `Cs02Claims` | `lib` | siros-webuild's CS-02 §8.2 rule: `exp` and `aud` present | Holds: a unit struct |
| `Cs02ErrorAnswer` | `lib` | siros-webuild's reader of CS-02 §8.3's `error` and `error_description` | Holds: a unit struct |
| `VpToken` | `lib` | The core's `vp_token` response type (§5.6) | Holds: a unit struct |
| `Sha2` | `lib` | The core's SHA-2 algorithms of the registry | Holds: a placeholder for `sigs/` `hash::Sha2`, an enum whose every variant is an algorithm |
| `DcApi` | `lib` | The core's `dc_api` mode (A.2), for every host | Holds: a unit struct; registered with `mode` |
| `DcApiJwt` | `lib` | The core's `dc_api.jwt` mode (A.2, §8.3), for every host | Holds: a unit struct; registered with `jwe_mode`, whose bound reaches `Haip` |
| `DirectPostJwt` | `lib` | The core's `direct_post.jwt` mode (§8.3.1), for every host | Holds: a unit struct; registered with `jwe_mode` and `error_mode` |
| `DirectPost` | `lib` | The core's `direct_post`, which carries errors alone | Holds: a unit struct; registered with `error_mode` alone |
| `Es256Keystore` | `lib` | The caller's zero-sized `Haip` | Holds: a unit struct |
| `DeviceMacKeystore` | `lib` | The caller's zero-sized `DeviceMac` | Holds: a unit struct |
| `HaipHost` | `lib` | The HAIP build's host: `Platform`, `Haip` and a held `DeviceMac` | Holds: private fields; `host!` settles each module's `Has` or slot |
| `WeBuildHost` | `lib` | The WE BUILD build's host: `Platform`, `Haip`, `RequestDecryption`, `Paso` and `RandomIds`, an `Empty` `CoseEncrypt` slot | Holds: private fields; `host!` settles each module's `Has` and the `Empty` slot's `MayHave` |
| `SlotlessHost` | `lib` | `--features demo-missing-module`: the WE BUILD modules without a `CoseEncrypt` slot | Holds: private fields; registering siros-paso over it fails with E0277 on `MayHave<dyn CoseEncrypt>` |

#### Section 4.9's replacements (`replace/sigs/`)

| Type | File | Invariant | How it holds |
| :-- | :-- | :-- | :-- |
| `CborError` | `cbor` | One variant per CBOR reading rule (RFC 8949 §5.6.1, §6) | Holds: a refusal enum, one variant per rule |
| `Hint` | `cbor` | How a byte string becomes text: tags 21 to 23, base64url otherwise (RFC 8949 §3.4.5.2, §6.1) | Holds: a private enum whose every variant is an encoding |
| `CoseShape` | `cbor` | One variant per COSE reading rule (RFC 9052 §3) | Holds: a refusal enum, one variant per rule |
| `HttpsUrl` | `https_url` | An https IRI with a non-empty host, as written, and its one form in ASCII (RFC 3987, RFC 3492) | Fixed (check after construction): `shaped` leaves; `parse` alone makes one |
| `NotHttpsUrl` | `https_url` | One variant per https URL rule | Holds: a refusal enum, one variant per rule |
| `HttpsUrl` | `https_url_splice` | An https IRI with a non-empty host, as written, and its ASCII form spliced at the host (RFC 3987, RFC 3492) | Fixed (check after construction): `shaped` leaves; `parse` alone makes one |
| `NotHttpsUrl` | `https_url_splice` | One variant per https URL rule | Holds: a refusal enum, one variant per rule |
| `HttpsUrl` | `inhouse_https_url` | `f718dc3`'s https URL: `https://`, a host part, no whitespace; its A-label form | Boundary: `f718dc3`'s type, kept verbatim as gate G3's baseline (section 4.9.3); commit 3 removes it, and `https_url`'s lands |
| `RandomId` | `random_id` | A version 4 UUID of the RFC 9562 variant, as lowercase hyphenated text (RFC 9562 §5.4) | Holds: private `Uuid`; `const fn from_bytes` sets the version and variant bits; `parse -> Result<_, NotRandomId>` |
| `NotRandomId` | `random_id` | One variant per UUID text rule | Holds: a refusal enum, one variant per rule |
| `Signature` | `runtime` | A signature's bytes as the key made them: R and S for ECDSA (RFC 7518 §3.4, RFC 9053 §2.1) | Boundary: the keystore module's output, whose length its algorithm fixes (64, 96 or 132 octets); the core places the bytes and reads none, and the differential's doubles write the frozen model's stand-in texts in their place (I9); private, `new` for the module |
| `Mac` | `runtime` | An HMAC-SHA-256 tag as the module made it (RFC 9052 §6) | Boundary: the module's output, as `Signature`'s; the differential's doubles write the model's stand-in texts (I9); private, `new` for the module |
| `SessionTranscriptBytes` | `runtime` | `#6.24(bstr .cbor SessionTranscript)` (ISO/IEC 18013-5 §9.1.5.1) | Fixed (constrained primitive in a public field): private, owned; only `SessionTranscript::tagged_bytes` makes them |
| `SealedCose` | `runtime` | A tagged `COSE_Encrypt`, one CBOR item with unique keys (RFC 9052 §5.1) | Holds: private; `parse -> Result<_, NotSealed>` refuses other bytes |
| `NotSealed` | `runtime` | A module's ciphertext that is no tagged `COSE_Encrypt` | Holds: a refusal struct |
| `DeviceKeys` | `runtime` | The `Runtime` methods the mdoc encoding changes: sign, MAC under EMacKey, encrypt to a `COSE_Encrypt` | Fixed (constrained primitive): `encrypt_cose` returns a `SealedCose`; `mac` takes `&SessionTranscriptBytes` |
| `ElementValue` | `mdoc/device` | A device-signed element's value as a CBOR data item | Holds: `DeviceNameSpacesBytes::of`, its one consumer, refuses a repeated key at any depth |
| `DeviceNameSpacesBytes` | `mdoc/device` | `#6.24(bstr .cbor DeviceNameSpaces)`, each name space and element once (ISO/IEC 18013-5 §8.3.2.1.2.2) | Fixed (unique `Vec`): `of` refuses a repeated name space, element or key (`RepeatedKey`) |
| `IssuedItem` | `mdoc/issuer` | An IssuerSignedItem as issued: its four members, its embedded bytes | Holds: private fields; only `IssuedItem::read` makes one |
| `IssuerSigned` | `mdoc/issuer` | IssuerSigned with each element once per name space, and a COSE_Sign1 IssuerAuth (ISO/IEC 18013-5 §8.3.2.1.2.2) | Holds: private fields; `read -> Result<_, IssuedError>` refuses an element twice |
| `IssuedError` | `mdoc/issuer` | One variant per IssuerSigned rule | Holds: a refusal enum, one variant per rule |
| `DeviceAuth` | `mdoc/response` | `deviceSignature` with an IANA COSE algorithm, or `deviceMac` with the Verifier key | Fixed (integer with a range): `Signature` holds an `iana::Algorithm` |
| `Presenting` | `mdoc/response` | One credential's presentation: its issued document, disclosed and device-signed elements, handover, device authentication | Fixed (relational rule outside a step): the docType comes from the document's MSO (`IssuerSigned::doctype`); `disclose` refuses an element the document lacks, and `DeviceNameSpacesBytes::of` a repeated one |
| `SessionTranscript` | `mdoc/transcript` | `[null, null, Handover]` (ISO/IEC 18013-5 §9.1.5.1, B.2.6), or a held array of three | Holds: private encoded bytes; only `SessionTranscript::of` and `decode` make one |
| `TranscriptError` | `mdoc/transcript` | Bytes that are no SessionTranscript: no single CBOR item, or no array of three | Holds: a refusal enum, one variant per rule |
| `IssueError` | `testkit/issuer` | One variant per reason a view cannot be issued | Holds: a refusal enum of the testkit |
| `TestKeys` | `testkit/mod` | The runtime stand-in's key operations | Holds: a testkit unit struct |
| `ModelHandover` | `testkit/reading` | The frozen model's handover as it wrote it: Origin, nonce, thumbprint | Boundary: the model's values as written; the differential reads them apart from the core's `Origin` and `Nonce`, so its oracle stays independent of the code it checks |
| `ReadError` | `testkit/reading` | One variant per reading rule | Holds: a refusal enum of the testkit |
| `Rebuild` | `testkit/reading` | What a reading checks the device authentication against: the model's handover, credential and algorithm | Boundary: the model's values as written, as `ModelHandover`'s |
| `Judged` | `https_url` | How RFC 3987 judges a sweep token apart from f718dc3 | Holds: a test fixture |
| `Vector` | `k12_uuid` | One RFC 9861 §5 vector | Holds: a test fixture |

#### This plan's code blocks beside the sketches

| Type | File | Invariant | How it holds |
| :-- | :-- | :-- | :-- |
| `HashesError` | `§4.9.1` | No algorithm every entry allows, or a member twice (B.3.3.1) | Holds: a refusal enum, one variant per rule |
| `Item` | `§4.9.4` | One CBOR data item in its encoding, its keys distinct at every depth | Fixed (constrained primitive in a public variant): private; only `Item::parse`, through `cbor::decode`, makes one |
| `MemberValue` | `§4.9.4` | A member value a profile writes: text, bytes, JSON text, or one CBOR item | Fixed (constrained primitive in a public variant): `Cbor` holds an `Item` |
| `Named` | `§4.2` | A value `Distinct` tells apart by its name | Holds: a trait over `name` |
| `Distinct` | `§4.2` | Values whose names differ | Holds: private `Vec`; `new -> Result<_, RepeatedName>` |
| `RepeatedName` | `§4.2` | The first name two values hold | Holds: a refusal struct |
| `FieldNames` | `§4.2` | Names a constant writes, distinct | Holds: private array; `const fn new -> Option` |
| `ClaimText` | `§4.14` | A claim value shown alone, in its literal form | Holds: an enum deriving `Message`, one variant per value form; `Bytes` holds a `Count` |
| `Span` | `§4.14` | A run of a `Text`: its text and its styles | Holds: public fields; `Text` holds its spans private, and only `Context::resolve` makes a `Text` (I28) |
| `Style` | `§4.14` | A style MF2 markup opens | Holds: an enum whose every variant is a style |
| `Styles` | `§4.14` | A set of styles | Holds: private set; `with` adds a style once |

## 5. Flows end to end

Calls are written component: call. "Caller" is the wallet app, the cloud engine or the platform
glue; "core" is siros-openid4vp; siros-x509 is named.

### 5.1 DC API: unsigned, signed, multisigned

Phase 1, inside Credential Manager (feature `match`):

1. Platform → matcher: `protocol`, `data`, the Origin.
2. Core: `Received::dc_api(protocol, data, origin, &protocols)` (U1 under the configured
   `DcApiProtocols`, U2). A signed `data.request` parses as a `CompactJws`, a multisigned one as a
   `JsonJws` (U10, U16).
3. Core: `Envelope::parse(&received, &registry)`. Unsigned: the parameters are `data`, and its
   `client_id` is ignored. Signed: the payload and its `client_id`. Multisigned: the payload and
   each protected header's `client_id` (U3, U12, U13, U17). The routing it holds: P1; C5, a
   registered DC API mode (`dc_api` or `dc_api.jwt`).
4. Core: `Request::parse(&envelope)` (C0, DCQL, N1), over the registry the envelope holds.
5. Core: `Accepted::new(&request, &registry)` (C1 to C8; the mode's rules, C7 for `dc_api.jwt`),
   `Match::run`, `Views`, over the matcher's `Context`: the registration's sources, and a
   request's ad-hoc metadata converted into a clone (`view::carried`). Records commit to
   `received.digest()` and to each entry's `shown`; siros-credman's `emit` lays the entries out, the
   matcher writes them and hides a refused request.

Phase 2, in the wallet app, after Credential Manager returns the chosen ids:

6. Core: steps 2 to 4 again, from the same `data` and Origin.
7. Core: `envelope.questions(&trust, &host)` → `Pending`. Unsigned: the Origin's evaluation
   under `OriginPolicy::Evaluate`, else no question. Signed: siros-x509's claim from the
   envelope's registry (A1 to A3, A5, A7). Multisigned: every signature's.
8. Caller: evaluates each of `pending.questions()` with the trust service.
9. Core: `pending.authenticate(decide, &trust, &context, &host)`, `decide` giving the caller's
   `Decision` for each evaluation → `Authenticated` (A6, A8 to A11, A14), the Verifier's name
   resolved through the wallet's `Context`. C8 compares the Origin with the verified
   `expected_origins`.
10. Core: `Prepared::prepare(&authenticated, &ids, ..)`: the request's rules run again before
    the ids are read; no id when every credential set is optional (§6.4.2). Caller: fetches
    `prepared.questions()`, the profiles' resources.
11. Core: `prepared.respond(fetch, &host)`, `fetch` giving the caller's `Fetch` for each
    resource: each query read again; the resources fetched; the route of the authenticated
    request, the mode's `encryption` once (the key rule for `dc_api.jwt`, under
    `Haip::agreements`), checked, or its refusal (C7), which ends phase 2; the answer route,
    whose `session()` holds the binding facts, from which siros-mdoc builds
    `Handover::DcApi { origin, nonce, thumbprint }`, audience `origin:<Origin>`; revalidation
    under that session; `Platform::authenticate(need)`, the strongest need of the records'
    profiles; the presentations; `answer`: the core seals the response for `dc_api.jwt`, and the
    mode's body, `{"vp_token": ...}` or `{"response": JWE}`, goes as `Delivery::DcApi`.
12. Caller: returns `data` to the platform.

Failures: U and A answer through `Rejected::reply` (`Rejected::dc_api` for a `Received::dc_api`
refusal), refusals through `route.refusal(..)`, unmet requests through `route.unmet(..)`.
`DcApiErrors` turns each into `{"error": code}`, which the core writes for every DC API route, or
a cancelled flow.

### 5.2 By URI: a link or a QR code

The same URI arrives from a link (`haip-vp://`, `openid4vp://` or an https app link, same
device) or from a QR code the wallet scans (cross device).

1. Caller: `Fetch::of(uri, &registry, &host)` (U3 to U8, U18, U19): `client_id` and
   `request_uri`; `request_uri_method` `post` adds `wallet_metadata` through the registered
   `RequestPost`, with a fresh key when `EncryptedRequests` is registered, else reads as a GET
   (reading 21).
2. Caller: performs `fetch.request()`, a GET of the `request_uri` or a POST of the form to it
   (section 4.3). Core:
   `fetch.resume(FetchAnswer::Body(body), &registry, &host)` → `Received`; a JWE is decrypted with
   the posted key (U9 on `Failed`; U10, U11).
3. Core: `Envelope::parse`: the Request Object's parameters alone (U12, U13, U14, U16).
4. Core: `envelope.questions` → siros-x509's claim: `LeafHash`, or `SanDnsName` and the leaf's
   dNSName entries; `X5c`; the leaf's key (A5); the `alg` against `Haip::verifies` (A7); the
   `response_uri` parsed (A13); `Evaluate` with the `response_uri`, the `request_uri`,
   `verifier_info` and the `dcql_query` in its context.
5. Caller: decides the evaluation. Core: `authenticate`: the decision's endpoints, or
   `x509_san_dns`'s host rule (A6, A12), the signature (A8), the validity (A9), `aud` (A10), the
   registered Request Object rules (A14) → `Authenticated` with `BoundEndpoint::ResponseUri`.
6. Core: the routing `Envelope::parse(&received, &registry)` read (P1; C5: a registered URI mode,
   `direct_post.jwt`; P5, P6), `Request::parse` (S3, S4, N1, P7), `Accepted::new` (the mode's C7).
   The wallet UI shows the consent with the Verifier's identity.
7. Core: `Prepared::prepare` → `respond`: `Route::new` (the key rule under `Haip::agreements`,
   once, checked); `route.answering()`, whose `session()` holds the binding facts, from which
   siros-mdoc builds `Handover::Redirect { client_id, nonce, thumbprint, response_uri }`,
   audience the full Client Identifier; `answer`: the core seals the response, the mode's form
   `response=<JWE>` goes as `Delivery::Post` to the bound `response_uri`.
8. Caller: POSTs, checks 200 and `application/json`. Core: `ResponseUriAnswer::parse(body,
   &registry)`, each registered reader over its members.
   Caller: sends the user agent to `redirect()` (HAIP §5.1); cross device, an answer without
   `redirect_uri` ends the flow (§8.2).

Failures by URI. Routed rules answer on the `Route`, in the error mode's form: sealed by the core
when the route bound a key, else in the plain form (§8.3.1). A refusal of the answering mode's
choice (C7, or C6 for `client_metadata`) is the request's error, plain. A request naming `direct_post`,
which carries errors alone, gets C5's error plain at its `response_uri` (reading 24). A mode that
names no registered error mode is `Unroutable`: the End-User. When A8
to A10 fail after a `Framework` binding, `Rejected::route` carries `invalid_request_object`,
plain, to the listed `response_uri` after the End-User has interacted. Every other U and A
failure answers the End-User. When the payload names an absolute `https` `response_uri`, the
End-User can choose to send the error there (`ErrorTarget::Unverified`); the caller then reads
the Response URI's answer and follows its `redirect_uri`. U9 and U14 terminate.

### 5.3 An SCA payment under the WE BUILD build

1. Caller: an `eu-eaap://` or `openid4vp://` URI, `request_uri_method` `post`. Core:
   `Fetch::of` through the registered `RequestPost` and `EncryptedRequests`:
   `WalletMetadata::of(registry, host, client_id, Some(key))` with a fresh key from
   `RequestDecryption::ephemeral_key`, composed from the formats', the prefixes'
   (`client_id_prefixes_supported`, `Haip::verifies`), `direct_post.jwt`'s and the key's
   contributions.
2. Caller: POSTs the form. Core: `resume`: the JWE decrypted with the posted key, the JWS read
   (U11, U10).
3. Core: `Envelope::parse`; `questions`: siros-x509's `x509_hash` claim, `verifier_info` and the
   `dcql_query` in the evaluation's context.
4. Caller: the trust service checks the access certificate's chain, the presence of
   `verifier_info`, the registration certificate, its binding, the intermediary rules and
   over-asking, and answers `Permit` with the name to show (else A6).
5. Core: `authenticate` (A8 to A10; A14, siros-webuild's `Cs02Claims`); the envelope's routing
   (`direct_post.jwt`); `Request::parse` with T1 to T5; `Accepted::new`.
6. Core, the matcher's code in the app: siros-sdjwt matches the base type through the
   credential's `types`; siros-ts12 binds the entry and siros-paso renders it with the payment
   header (section 4.10.2).
7. Core: `Prepared::prepare` → `respond`: `Platform::authenticate(Strong)`; siros-ts12 writes
   `jti` (siros-paso's `RandomIds`), `response_mode`, `amr`, `transaction_data_hashes` and
   `transaction_data_hashes_alg` (a registered `Sha2` algorithm) as claims, the format's
   placement; siros-sdjwt signs the Key Binding JWT; `Delivery::Post`.
8. Caller: POSTs the response; `ResponseUriAnswer::parse` with siros-webuild's `Cs02ErrorAnswer`
   reads the Verifier's error, which the wallet shows; follows `redirect_uri`.

### 5.4 Coverage

Every flow by every step, each cell the type or function that handles it. `coverage/check.py`
counts 13 flows, 12 steps, 156 cells, 0 empty, over `coverage/coverage.tsv`, which holds the table
below.

| flow | arrival | received | envelope | authenticate | routing | request and phase 1 | phase 2 | session | response | delivery | caller | failure |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| F1 DC API unsigned, dc_api | caller: protocol, data, Origin from the platform | Received::dc_api (U1, U2) | Envelope::parse: data is the parameters; client_id ignored (A.2) | Envelope::questions: the Origin's Evaluate per OriginPolicy; Pending::authenticate -> VerifierId::Origin | the envelope's routing: P1 vp_token, C5 dc_api; state and redirect_uri unrecognized (A.2) | Request::parse (C0, DCQL, N1); Accepted::new; the matcher shows entries | Prepared::prepare (records) -> respond | Handover::DcApi without thumbprint; aud origin:<Origin> | AuthorizationResponse { vp_token } | Route with the core's DcApi mode: Delivery::DcApi {vp_token} | returns data to the platform | the matcher hides a refused request; phase 2: Rejected::reply on the DC API's route for U and A, Route::refusal or unmet; Reply per DcApiErrors |
| F2 DC API unsigned, dc_api.jwt | caller: protocol, data, Origin | Received::dc_api | Envelope::parse | the Origin per OriginPolicy | the envelope's routing: C5 dc_api.jwt | Accepted::new: DcApiJwt's C7, the key rule (P-256 ECDH-ES key; A256GCM, else A128GCM) | Prepared -> respond | siros-mdoc's Handover::DcApi with the RouteKey's thumbprint | AuthorizationResponse { vp_token } | the core seals to the RouteKey through Haip::encrypt_jwe; DcApiJwt wraps it; Delivery::DcApi {response} | returns data | errors as {error}, unencrypted (A.4); C7 when no usable key |
| F3 DC API signed, x509_hash or x509_san_dns, dc_api.jwt or dc_api | caller: protocol, data, Origin | Received::dc_api: data.request a CompactJws, ES256 (U10, U16) | Envelope::parse: the payload's parameters and client_id (U3, U12, U13) | siros-x509 claim: LeafHash or SanDnsName, X5c (A5); Evaluate on the chain; binding: key = the leaf's, endpoint DcApi; A8 Haip::verify, A9 the validity, A10 aud | the envelope's routing | Accepted::new: C8 expected_origins; metadata = client_metadata | Prepared -> respond (records re-derived) | Handover::DcApi; aud origin:<Origin> even when signed (A.4) | AuthorizationResponse { vp_token } | DcApiJwt or DcApi | returns data | A rules: Rejected on the DC API's route (invalid_request, invalid_request_object); refusals: Route::refusal; Reply per DcApiErrors |
| F4 DC API multisigned, x509_hash or x509_san_dns | caller: protocol, data, Origin | Received::dc_api: a JsonJws, each signature ES256, names disjoint (U10) | Envelope::parse: Signatures::Many; client_id per protected header (U17) | each signature's claim in order; the first that authenticates (A11 lists each reason) | the envelope's routing | Accepted::new | Prepared -> respond | Handover::DcApi | AuthorizationResponse { vp_token } | DcApiJwt | returns data | A11: Rejected on the DC API's route with invalid_request_object; Reply per DcApiErrors |
| F5 Link, same device: request_uri GET, x509_hash or x509_san_dns, direct_post.jwt | caller: the URI the OS hands over (haip-vp://, https app link) | Fetch::of (U3 to U8, U18, U19); caller GETs request_uri; Fetch::resume (U9, U10, U11) | Envelope::parse: the Request Object's parameters alone (U12, U13, U14, U16) | siros-x509 claim; Evaluate with the response_uri and request_uri in its context; ResponseUri https (A13); the endpoint the decision allows, or x509_san_dns's host rule (A12) | the envelope's routing: C5 direct_post.jwt, P5, P6 | Request::parse (S3, N1, P7); Accepted::new; the wallet UI shows the consent | Prepared -> respond | Handover::Redirect { client_id, nonce, thumbprint, response_uri }; aud the full client_id | AuthorizationResponse { vp_token, state } | the core seals to the RouteKey through Haip::encrypt_jwe; DirectPostJwt wraps it; Delivery::Post response=<JWE> | POSTs; ResponseUriAnswer::parse; sends the user agent to redirect() (HAIP §5.1) | routed errors encrypted to the chosen key; U and A rules: the End-User; Rejected::route Listed for A8 to A10 under a Framework binding, else Unverified when the payload names an https response_uri |
| F6 QR, cross device: request_uri GET, x509_hash or x509_san_dns, direct_post.jwt | caller: the URI scanned from a QR code | Fetch::of; GET; Fetch::resume | Envelope::parse | siros-x509 claim; Evaluate; binding | the envelope's routing | Request::parse; Accepted::new | Prepared -> respond | Handover::Redirect | AuthorizationResponse { vp_token, state } | Delivery::Post response=<JWE> | POSTs; an answer without redirect_uri ends the flow (§8.2) | as F5 |
| F7 request_uri_method post: wallet_metadata POSTed, the Request Object plain or encrypted | caller: URI | Fetch::of: request_uri_method post: WalletMetadata::of with a fresh key from RequestDecryption::ephemeral_key (U8 for another method); the caller POSTs the form; Fetch::resume: a CompactJwe decrypted by RequestDecryption::decrypt (U11), the JWS (U10) | Envelope::parse | as F5 | as F5 | as F5 | as F5 | Handover::Redirect | AuthorizationResponse { vp_token, state } | Delivery::Post | POSTs the form to the request_uri, then the response | U9 on a failed POST; U11 for a JWE after a GET, a JWE JweError refuses, or one that does not decrypt: the End-User |
| F8 URI refused after authentication | caller: URI | Fetch::of -> resume | Envelope::parse | authenticated: Verifier with the bound response_uri | the envelope's routing: P1, C5, P5, P6 refusals; the registered DirectPost, which carries errors alone, for direct_post | Request::parse or Accepted::new refuses (S3, S4, N1, P7, C7, C0 to C8) | Route::new; Route::refusal | no Session: an error carries no presentation | ErrorResponse { code, description, state } | DirectPostJwt's ErrorModeHost::error: the core's JWE of the error to the RouteKey, else the plain form (§8.3.1); DirectPost's: the plain form | POSTs the error; follows redirect() when present | Unroutable when the mode names no registered error mode: the End-User alone |
| F9 URI refused before authentication | caller: URI | U3 to U11, U18, U19 at Fetch::of or resume | U12 to U14, U16 at Envelope::parse | A1, A2, A5, A6, A12, A13; A8 to A10 after a binding | not reached: refused before routing | not reached | not reached | no Session | ErrorResponse for Rejected::route alone | Rejected::route: the plain form to the Listed response_uri, or to the Unverified one | tells the End-User; sends a Listed route's reply after an interaction, an Unverified route's when the End-User chooses to return to the site; follows the answer's redirect_uri | U9, U14 terminate; every other failure answers the End-User, with an Unverified route when the payload names an https response_uri |
| F10 Link or QR under the WE BUILD build: x509_hash alone, verifier_info to the trust service, an encrypted Request Object | caller: the URI the OS hands over or the QR code holds (openid4vp://, eu-eaap://, haip-vp://) | as F7: a POST, the JWE decrypted with the posted key | Envelope::parse: the Request Object's parameters alone (U12 to U14, U16); verifier_info as received | siros-x509 x509_hash claim; Evaluate with the response_uri, the request_uri, verifier_info and the dcql_query in its context; the trust service requires verifier_info and checks it; the decision's name and facts; binding; A8 to A10 | the envelope's routing: C5 direct_post.jwt, P5, P6 | Request::parse (S3, N1, P7); Accepted::new; the consent shows the decision's name | Prepared -> respond | Handover::Redirect { client_id, nonce, thumbprint, response_uri }; aud the full client_id | AuthorizationResponse { vp_token, state } | the core seals to the RouteKey through Haip::encrypt_jwe; DirectPostJwt wraps it; Delivery::Post response=<JWE> | POSTs the form to the request_uri; POSTs the response; ResponseUriAnswer::parse; follows redirect() | U11: the End-User; the trust service's Deny (verifier_info absent or invalid, the WRPRC, its binding, over-asking): A6 |
| F11 SCA payment or action by URI under the WE BUILD build: a TS12 entry | caller: the URI | as F10 | as F10 | as F10 | as F10 | Request::parse; siros-ts12's T1 to T5 beside the core's C0; Accepted::new; siros-sdjwt matches vct_values through types (reading 26); siros-ts12 bind: the ts12 document, category, type, schema URN, labels, typed payload, siros-paso's render (Family::Payment or View) | Prepared -> respond: Profile::authentication Strong; Platform::authenticate(Strong), two categories else AuthenticationTooWeak; siros-ts12 respond: jti, response_mode, amr, transaction_data_hashes and transaction_data_hashes_alg | Handover::Redirect; the KB-JWT's aud the full client_id | AuthorizationResponse { vp_token, state }: the SD-JWT VC, its Key Binding JWT holding TS12's claims | Delivery::Post response=<JWE> | POSTs; follows redirect() | T1 to T5 routed as invalid_transaction_data; an unsupported type or a refused payload: no candidate, its reason shown to the Holder (CS-12 §8.1); AuthenticationTooWeak: the End-User |
| F12 SCA over the DC API under the WE BUILD build: signed, a TS12 entry, dc_api.jwt | caller: protocol, data, Origin | Received::dc_api under DcApiProtocols::SIGNED (U1 for the unsigned protocol) | Envelope::parse: the payload's parameters and client_id; verifier_info as received | siros-x509 claim with verifier_info and the dcql_query in its context; the trust service requires verifier_info; A8 to A10 | the envelope's routing: C5 dc_api.jwt | Accepted::new: C8 expected_origins; T1 to T5; the matcher: siros-ts12 bind, the payment header for the platform's payment sheet | as F11 | Handover::DcApi with the chosen key's thumbprint; the KB-JWT's aud origin:<Origin> | AuthorizationResponse { vp_token } | the core seals to the RouteKey through Haip::encrypt_jwe; DcApiJwt wraps it; Delivery::DcApi {response} | returns data to the platform | U1 for an unsigned request; A rules: Rejected on the DC API's route; refusals: Route::refusal; Reply per DcApiErrors |
| F13 Link or QR with an extension mode registered by URI (siros-testkit's TestMode) | caller: the URI | as F5 | Envelope::parse: C5 finds the registered TestMode on the URI channel | as F5 | the envelope's routing: the extension mode, P5, P6 | Request::parse; Accepted::new: TestMode's own rules at C5's place, each with its code | Prepared -> respond | AnswerRoute::session: the binding facts with the RouteKey TestMode's encryption chose among the VerifierKeys, checked against the sealing statement | AuthorizationResponse { vp_token, state } | the core seals; TestMode's answer wraps the AnswerContent: a Body the core checks for its channel; Delivery::Post to the bound response_uri | POSTs; follows redirect() | a Body of the DC API channel (RouteBreach::BodyChannel), a key of other metadata (Foreign), a key or enc the statement or the Verifier refuses (Unstated, Unlisted): Fault; a mode name twice on the channel, a metadata name twice: RegistryError at build |

## 6. Change inventory

Commits land in this order. On wallet-rs `flows` at `a307cca`: the replacements of section 4.9
(commits 1 to 6, their inventory in section 4.9.5), `Runtime::fetch` as effects (decision 2), the
host modules (decision 13), and the request side of the flows. Then, before the response side,
the refactor of what landed to the modular core (decision 20), each part its own commit, in this
order:

1. zkp_req's parts leave: the `direct_post.cwt` routing and its `Modes` entry, siros-zkp-req's
   `ProofSystems`, `BackendId` and `SystemId` (Appendix A). `Modes` keeps the other modes until
   commit 4 replaces it.
2. `ErrorCode` opens; `RequestRule::code` returns it.
3. The algorithms become the modules' statements: `Haip::verifies` and A7, the JWS parse over
   `JwsAlgorithm` names, `RequestDecryption::decrypts` with its curves, `Agreements`, the empty
   statements; `VerificationKey` and `EphemeralKey` as public JWKs, the secret behind a
   `KeyHandle`; p256 leaves the core.
4. Response types and response modes become plug-ins in phase 1: `ResponseType`, `VpToken`,
   `Mode`, `ModeName`, `RoutedMode`, the routing over the registry, P1 and C5 over the
   registered types and modes, C7 as the JWE modes' rule; `Modes` leaves for the registry's
   modes; the routing holds the registered mode, and the envelope the registry's hash algorithms
   and scope queries.
5. The registry gains `HostedPrefix<H>` with `client_prefix`'s `Haip` bound, `ObjectRule`,
   `RequestPost`, `EncryptedRequests`, the hash algorithms with `Sha256Absent`, the scope queries
   under `uri`, and the name declarations with `NameTwice` and `NameReserved`; `CoreHost` is
   `Platform`; `RandomIds` and `CoseEncrypt` move to siros-paso.
6. The session holds the binding facts; siros-mdoc takes B.2.6's handover, the thumbprint and
   `SessionTranscript`.
7. `Format::placement` and `Profile::members(placement)`; siros-paso and siros-qes place by kind.
8. The inherence facts; siros-paso's `BiometricClass`; `Strength` leaves.
9. The consent entry and `StaticEntry`; siros-credman takes Credential Manager's entries, A9 and
   K4.
10. `Presentation`'s private field; the core's `ViewAdditions`; siros-ts12 names the core and
    siros-paso alone.
11. `wallet_metadata` and the POST as contributions (`client_id_prefixes_supported`,
    `PostContribution`), the Response URI's `AnswerReader`s; siros-webuild with `Cs02Claims` and
    `Cs02ErrorAnswer`; `RequestClaims` leaves.
12. The features of section 4.11, gated per build (I39); the registry's `Build`, which keeps
    them additive.

Then the response side (`ModeHost`, `ErrorModeHost`, the route and `AnswerRoute`, the core's
sealing, `ResponseParameters`, the bodies, the deliveries and the core's four modes), then the
texts of decisions 19 and 21 (the second table's `TableLocale`, `Text`, PaSO View, `Env` and
`text::lookup` rows, siros-syntax, and the siros-i18n edges of the core and siros-paso, which
siros-ts12 reaches through siros-paso), then the WE BUILD profile (decision 12), each part its own
commit: the core's part (section 4.10.1), siros-paso's engine seams, siros-ts12, and the WE BUILD
build in siros-integration. The READMEs and the guides of section 4.12 land last.

**The refactor of `flows`.** Counts from `git grep -n` over `flows` `a307cca`'s `crates/*/src`
(and `crates/*/tests` where named); a line can hold one call, a file several.

| Changes | Lines | Files |
| :-- | --: | --: |
| `ResponseMode`, `DcApiMode`, `ModeChoice`, `Protection` in the shipped sources → `Mode`, `ModeName`, `RoutedMode`; in the tests | 67; 8 | 6; 2 |
| `Modes` in the shipped sources → the registry's modes | 11 | 5 |
| `direct_post.cwt`, `DirectPostCwt`, `PostBody::Cwt`, `ResponseData` across the crates → removed or `Delivery` | 28 | 9 |
| `CoseEncrypt` across the crates → siros-paso's module, in every `resolve` build, its sealing under `sealed-signals` | 48 | 12 |
| `Has<dyn RequestDecryption>` → the registered `EncryptedRequests` | 4 | 2 |
| `CoreHost` → `Has<dyn Platform>` alone; `Haip` bound by `prefix` and `jwe_mode` | 14 | 5 |
| `p256::` in the core's sources → `EphemeralKey`'s public JWK and `KeyHandle` | 20 | 4 |
| `encrypt_jwe(` in the modes and phase 2 → the core's sealing, the mode wrapping the JWE | 4 | 4 |
| `wallet_metadata` → the declared contributions | 15 | 6 |
| `RequestClaims` → siros-webuild's `Cs02Claims` (`ObjectRule`, A14) | 10 | 2 |
| `ErrorCode::` variants in the shipped sources → the open `ErrorCode`'s constants | 26 | 12 |
| `Encryption::choose`, `ResponseKey`, `ResponseEnc` → the JWE modes' key rule under the sealing statement | 21 | 5 |
| `Curve::`, `KeyAgreement::`, `ContentEncryption::` enum cases → checked names | 48 | 10 |
| `Es256Signature` → `JwsSignature` | 8 | 1 |
| `VerificationKey::p256`, `VerificationKey::of` → a public JWK | 9 | 4 |
| `SessionTranscript`, `Thumbprint`, `Handover::` in the core's sources → siros-mdoc | 25 | 3 |
| `"dc+sd-jwt"`, `"mso_mdoc"` in siros-paso's and siros-qes's sources → `Placement` | 4 | 2 |
| `fn members(` in the shipped sources → `members(placement)` | 15 | 13 |
| `Strength` → `Inherence`'s facts and siros-paso's `BiometricClass` | 12 | 5 |
| `boxes::` in the shipped sources; in the tests → `consent::` and siros-credman | 12; 14 | 12; 14 |
| `Presentation(` constructions → `Presentation::text`, `Presentation::object` | 1 | 1 |
| `random_id` → siros-paso's `RandomIds` | 4 | 4 |
| `FormMembers` → `FormBody::of` over `impl Serialize` | 4 | 2 |
| `HashAlgorithm` → the `HashAlgorithm` trait and `Sha2`, `Sha3`, `Blake2`, `K12` | 11 | 3 |
| `ClientPrefix for` → `ClientPrefix` and `PrefixHost<H>` | 3 | 2 |
| `#[cfg(feature = "resolve")]`, `with_resolve!`, `without_resolve!` in the core's sources → the mechanism's feature; the two macros leave, and each plug-in gates its phase 2 on its own `resolve` | 115 | 12 |

Counts from `inventory/inventory.sh` on the worktree at `f718dc3` (`inventory/inventory.out`
lists the files). A line can hold one call; a file several.

| Changes | Lines | Files |
| :-- | --: | --: |
| `Request::parse(origin, received)` → `Received::dc_api` + `Envelope::parse(&received, &registry)` + `Request::parse(&envelope, &registry)` | 20 | 13 |
| `Received::Unsigned` / `Received::Signed` → `Received::dc_api(protocol, data, origin, &protocols)`; the test inputs carry a JWS whose payload is the parameters | 26 | 14 |
| `Accepted::new(request, registry)` keeps its signature: the request holds its envelope, whose routing it reads | 43 | 22 |
| `respond(..)` → `Prepared::prepare(&authenticated, ..)` then `respond(fetch, &host)`, after `Pending::authenticate(decide, ..)` | 18 | 11 |
| `Session { .. }` → `AnswerRoute::session()`: the fields private | 7 | 6 |
| `Handover::DcApi` keeps its shape | 10 | 8 |
| `Handover::Redirect` takes `response_uri` and a thumbprint; `session::Endpoint` is removed | 6 | 3 |
| `impl Runtime for` (TestRuntime, `phase_two.rs`'s Sealing) → the hosts' modules; `fetch` removed; the flows add `Haip::verify`, the WE BUILD profile `RequestDecryption` | 2 | 2 |
| `dyn Runtime` parameters → `&H` with the bounds of the modules each calls | 37 | 18 |
| `runtime.<method>(` calls → `host.get::<dyn M>().<method>(` | 18 | 8 |
| `encrypt_jwe` and `encrypt_cose` (the trait, its implementations, their calls) drop `alg`, the key's own; `encrypt_cose` takes a `CoseEnc`; both return the parsed ciphertext (`SealedJwe`, `SealedCose`) | 11 | 5 |
| `Runtime::authenticate()` → `Platform::authenticate(need)`: the trait, two implementations, two calls | 5 | 4 |
| `SignalType`, `Measurement`, `Reading` → siros-paso; `Mac` → siros-mdoc; `ProofRequest` → siros-zkp-req | 86 | 17 |
| `impl Profile for` → `impl ProfileHost<H> for` gains `authentication`, with `wanted` and `informed` (siros-paso, siros-qes, `TestProfile`, five test profiles) | 8 | 8 |
| `impl Format for` gains `wallet_formats` and `placement` (siros-sdjwt, siros-mdoc, siros-zkp-req, `TestFormat`, four test formats) | 8 | 8 |
| `runtime.fetch(..)` (siros-paso `phase2.rs`, siros-qes `lib.rs`) → `ProfileHost::wanted` and fetched resources | 2 | 2 |
| `fn fetch` (the trait and two implementations) removed | 3 | 3 |
| `matching::ResponseMode::` → the registered mode's `ModeName` | 5 | 2 |
| `ResponseData::` → `Delivery` | 7 | 5 |
| `ClientMetadata::encryption()` → the JWE modes' key rule | 2 | 2 |
| `Request::response_mode()` → `Routing::mode`, and `Answered::mode`, a `ModeName`, for siros-paso's response mode signal | 3 | 3 |
| `Request::request_object()` keeps its signature (siros-paso reads it) | 4 | 4 |
| `Request::origin()` → the envelope's channel | 3 | 3 |
| `Request::expected_origins()` returns `&[ExpectedOrigin]` (C8) | 2 | 1 |
| `Request::client_metadata()` keeps its signature: both X.509 prefixes take the metadata from the request | 6 | 5 |
| `Nonce::parse` keeps its signature; its rule gains N1, and every nonce in the tests and the model (`n-0S6_WzA2Mj`) holds | 7 | 6 |
| `ClientId::parse` keeps its signature; its rule gains RFC 6749 Appendix A.1's `*VSCHAR` (U3), and the one test identifier, `x509_san_dns:client.example.org`, holds | 1 | 1 |
| `Outcome::` uses: `Outcome` gains `Unroutable`; each exhaustive match handles it | 122 | 22 |
| `ErrorCode::InvalidClient` uses: no rule produces it, and the open `ErrorCode` keeps §8.5's code as a constant | 3 | 2 |
| `OptionIndex(..)` constructions and patterns → the query's `options` and the accessor: the field private | 18 | 12 |
| `Thumbprint(..)` constructions and patterns → siros-mdoc's `Thumbprint::of(key)` and `as_bytes()` | 3 | 3 |
| `Authentication { .. }` → `Authentication::new(completed_at, factors)`, the factors an `AllOf` | 6 | 6 |
| `AgreeableKey` field reads → its accessors; `point()` gives the decoded coordinates | 15 | 8 |
| `Answered { .. }` constructions → the core's phase 2 alone, the fields private | 11 | 6 |
| `HttpsUrl::shaped(text)` → `HttpsUrl::parse(text)` | 4 | 4 |
| `thiserror` error types of the shipped crates gain `#[derive(Explain)]` with their ids, under their crate's `scope!` (decisions 18, 21) | 39 | 27 |
| `Refusal::invalid_request(text)`, `Refusal::invalid_transaction_data(text)`, `Refusal { .. }` in the shipped crates → `Refusal::new(rule)`, the rule kept unformatted and its code its own (`RequestRule::code`) | 29 | 10 |
| `Exclude { reason: String }` → `Exclude::new(rule: impl Explain)` | 10 | 6 |
| `Fault::new(format!(…))` → `Fault::new(error)`: the crate's own fault error, `err.<scope>.fault`, its detail a `#[source]` or a skipped field, which the log line writes | 36 | 16 |
| `TableLocale` tables → statements deriving `Message`, worded by the wallet's MF2 sources (decisions 19, 21): the core's wallet texts and frequencies, siros-paso's mandate labels and rulebook texts, siros-qes's texts (counted at siros-wallet-core `622e746`) | 65 messages | 5 |
| Box and row texts → resolved `Text` (decisions 19, 21): the 16 `String` fields and the sites that build them | 50 | 12 |
| PaSO View's vocabulary leaves the core for siros-paso's conversion (`LabelKind`, `FormattedKind`, `ValueKind`, `Parsed`, `Label`, `Value::Formatted`, the `mini_markdown` parser); the uses outside siros-paso become `Text` | 65 | 10 |
| `Env`'s `Amounts` → removed: the wallet's wording shows an amount through `:currency` or as written | 19 | 7 |
| `Env::new` takes the priority list as given; `DisplayLocale` and `EnvError::NotInTable` are removed | 14 | 12 |
| `text::lookup` → RFC 4647 basic filtering (section 4.14): a tag matches an equal tag, else the first tag extending it, for `format_entry`; siros-paso's View §4 selection keeps RFC 4647 Lookup, its own | 1 function | 1 |
| oracle `export.py`: a signed request becomes a JWS over its parameters, with `client_id` `test:verifier` (`req.signed`) | 4 | 2 |
| oracle `wire_digest`: the same formula over the new JWS text | 10 | 3 |

By module:

| Area | Changes |
| :-- | :-- |
| Core, new | `arrival.rs`, `uri.rs` (the GET, `RequestPost`, `EncryptedRequests`, `FormBody`, the Response URI's answer and `AnswerReader`), `jose.rs` (`CompactJwe` beside the JWS, the algorithm statements, `PublicJwk`), `envelope.rs` (`verifier_info` as received, the registry it was read with, `client_metadata` and the `nonce` read once), `routing.rs` (`ResponseType`, `Mode`, `ModeHost`, `ErrorModeHost`, `ResponseParameters`, `ResponseParametersHost`, the Verifier's metadata), `authenticate.rs` (the classification, `ClientPrefix`, `PrefixHost`, `ObjectRule`, `Pending`, `Authenticated` with the Verifier's metadata), `effects.rs`, `resolve/route.rs` (the route, `AnswerRoute`, the sealing, `Unroutable`), `modes.rs` (the core's four modes, the key rule), `hash.rs`, `scope.rs`, `consent.rs`, `recourse.rs`, `wallet_metadata.rs` (the names, the contributions, `PostContribution`). |
| Core, changed | `request/mod.rs` (scope), `request/metadata.rs` (the agreeable-key vocabulary as checked names), `request/digest.rs` (the multisigned and URI rows), `ids.rs` (N1; `ClientId`'s Appendix A.1 rule), `matching/rules.rs`, `matching/mod.rs` (`ExcludedBy`, `UnmetCode`, `Match::unmet`, `Candidate::bound` as `TransactionBinding`), `matching/display.rs` (the consent entry), `resolve/mod.rs` (`RouteBreach`, `ParameterBreach`), `resolve/prepared.rs` (`Prepared` over the `Authenticated`), `resolve/response.rs` (the bodies, the delivery, `ResponseMember`), `session.rs` (the binding facts), `txhash.rs` (the registered algorithms), `runtime.rs` → `host.rs` (the access traits, `Platform`, `Haip`, `RequestDecryption`, `KeyHandle`, `Inherence`), `refusal.rs` (the open `ErrorCode`), `plugins/mod.rs` (`placement`, `Presentation`, `ViewAdditions`), `plugins/registry.rs`, `lib.rs`, `Cargo.toml` (the features of section 4.11). `boxes.rs` leaves for siros-credman. |
| New crate | siros-x509 (x509-cert, der, spki, sha2, base64): `verifier_info` and the `dcql_query` in its evaluation's context; the leaf's key as a public JWK. siros-ts12 (siros-openid4vp, siros-paso, siros-syntax, siros-i18n, base64; the core's `ViewAdditions` for a credential's `types`). siros-syntax (siros-explain; ISO 4217 List One, vendored as `list-one.xml`): `checked!`, `Keyed`, `AllOf`, the value types with their literal forms, and the ISO 4217 table, out of siros-explain. siros-i18n-derive: `#[derive(Message)]`. siros-credman (siros-openid4vp, siros-i18n, siros-syntax, icu_properties, rustc-hash): Credential Manager's entries and the registration. siros-webuild (siros-openid4vp): `Cs02Claims`, `Cs02ErrorAnswer`. |
| siros-mdoc, siros-sdjwt | Their tests' sessions; `wallet_formats`; `placement`. siros-mdoc: B.2.6's handover with `HandoverUri`, `Thumbprint` and `SessionTranscript` from the session's binding facts, with the core's `cbor`; `DeviceKey`, `SignatureAlgorithm::made_on`, `DeviceAuthRefused`; the `DeviceMac` double behind `test-util`. siros-sdjwt: the registration view's `types` through `ViewAdditions`, `meta_matches` over them; `Resolved`, `PermanentClaim`, `ValidityClaim`, `JwkCoordinate`, `FixedSd`. |
| siros-paso, siros-qes | `wanted`; `revalidate` from fetched resources; `authentication`; members by placement. siros-paso: public `render::Request` with `LabelLimits` and one lifetime, `Registered::of`, `PasoType::rendered_by`, `label_limit!`, `WalletVersion`, public `bound`, `view::convert`, `view::carried`, `view::verified`, `adhoc::Carried::read`, `adhoc::Verified::of`, `PasoProfile::with_verified`, `PasoFinding::refused`, `BiometricClass`, the `RandomIds` module with uuid, the `IssuerTrust` module with siros-x509, the `CoseEncrypt` module and the `sealed-signals` feature, the `Paso`, `RandomIds`, `IssuerTrust` and `CoseEncrypt` doubles behind `test-util`. siros-qes: the `sha3` feature. |
| siros-credman | `emit` over a `Display` and the matcher's `Context`: `Emission`, `Emitted`, `Shown`, `NotEmitted`, `Unshown`; the registration: `Kind`, `Base`, `ContextError`, its lazy reader `Registration` with `ReadError` and `Malformed`, and under feature `register` its writer `register::write` with `RegisterError`; `SetFacts::of`, `Fulfilment::check` and `Field::of` over the resolved texts. |
| siros-zkp-req | What the core's API forces: its `Prover` module and `ProofRequest` (decision 13), `QueryContext`, `AllOf` refusals, an empty `wallet_formats`, `placement` `None`. |
| siros-testkit | `TestPrefix` (both endpoint bases, configurable answers), `TestMode` (either channel, answers and errors, its body's channel `TestBody`, an unchecked key choice `TestChoice` with `Foreign`, an undeclared metadata name), the probes `read_query`, `read_parsed`, `read_phase_two`, `read_record`, `read_session` and `read_redirect_session` with `ProbeFormat`, `ProfileProbe` and `NamedPrefix`, `probe::dc_api` and `probe::sealed_to_b26` for their routes, `JweHaip` (a real ECDH-ES sealing), `fixtures::authenticate` and `fixtures::trust_config`, `TestResponseType`, `TestResponseParameters`, `TestPostContribution`, `TestAnswerReader`, `TestObjectRule`, `TestHash`, `TestScope`, a test trust service (registration-certificate answers too), the core's module doubles with their counters in `Cell`s, `test_host!`, signed fixtures as real JWS with `client_id`. |
| siros-integration | The generator signs DC API requests over their parameters; `end_to_end.rs` gains every flow of section 5; the properties generate URI requests, by GET and by POST; the HAIP and WE BUILD builds, over hosts of the crates' `test-util` doubles. |
| Elsewhere | siros-matcher (siros-dc-matcher-config) calls `Request::parse`; it moves to `Received::dc_api` with the registration's `DcApiProtocols`, `Envelope::parse` over its registry with the core's DC API modes, and siros-credman for Credential Manager's entries. It lives outside this workspace; its call sites are uncounted. |

## 7. Generic mechanisms

| Mechanism | What it does for any standard | Litmus | A second user |
| :-- | :-- | :-- | :-- |
| `Received`, `Fetch`, the digest's domains | Carries what arrived and the one fetch before it can be read; records commit to it. | Names arrivals and effects alone. | OpenID4VCI's `credential_offer_uri`, fetched the same way. |
| JOSE structure: `CompactJws`, `JsonJws`, `Validity`, `Skew`, `VerificationKey` | Parses and checks JOSE objects once for every plug-in. | RFC 7515 and RFC 7519 alone. | siros-paso's metadata JWTs. |
| `ClientPrefix`, the classification, `Pending`, `Authenticated` | Binds a key and an endpoint to a Client Identifier through any framework. | §5.9.3: "Other specifications can define further Client Identifier Prefixes"; X.509 in a plug-in. | Any further prefix a deployment registers. |
| `Slots` of `Evaluation` and `Resource`, answered by `Decision` and `Fetch` (AuthZEN evaluation, resource) | Hands every network effect to the caller as data, one typed slot per question. | The plug-ins name their types; the core carries them. | siros-paso's and siros-qes's resources; OpenID4VCI issuer trust. |
| `Route`, `ErrorRoute`, `EndpointBasis`, `ErrorDescription`, `Reply` | Sends an error to the platform, the authenticated endpoint, or an endpoint the framework listed, in the request's mode; otherwise the End-User, who can choose to send it to the endpoint the request names. | Codes from any specification (the open `ErrorCode`); each prefix states its basis. | RFC 9101 §7's codes. |
| `ResponseType`, `ResponseParameters` | Answers the response types a build registers, with the parameters registered parts add beside `vp_token`. | RFC 6749 §8.4's registry; §8.1: "Additional response parameters MAY be defined"; the core's `vp_token` is a peer. | `vp_token id_token`; RFC 9207's `iss`. |
| `Mode`, `ModeHost`, `ErrorModeHost`, `Body`, `RouteKey` | Carries an answer or an error in a registered response mode, to the endpoint the route bound, sealed by the core to the key the route bound. | OAuth 2.0 Multiple Response Type Encoding Practices §2.1: "additional Response Modes may be defined"; the core's modes are peers. | OpenID4VP's four; JARM's `*.jwt` modes; any further mode a specification defines. |
| `ObjectRule` | Applies a profile's or a deployment's rule to an authenticated Request Object's claims. | RFC 7519 leaves `exp` and `aud` optional; the core names no deployment. | siros-webuild's `Cs02Claims`. |
| `AnswerReader` | Reads the Response URI's answer members a specification or a deployment defines. | §8.2: "Additional parameters MAY be defined"; the core reads `redirect_uri` alone. | siros-webuild's `Cs02ErrorAnswer`. |
| `HashAlgorithm` | Hashes transaction data under any algorithm of the IANA registry B.3.3.1 names. | The registry is open; the core's SHA-2 algorithms are peers. | Any further Hash Name String. |
| `ScopeQuery` | Reads a scope value as the DCQL query a specification or a deployment defines. | §5.5 leaves the mapping out of scope. | A profile's scope values. |
| The consent entry: `Card`, `Overlay`, `TransactionHeader` | Composes what the End-User confirms as platform-neutral data. | No platform's vocabulary in the core. | siros-credman's Credential Manager entries; the wallet UI. |
| `ProfileHost::wanted` | Lists what a profile revalidates with, for the caller to fetch. | A listing over the record, the profile's data and the host's modules; the caller fetches (the core-pure-offline ruling). | siros-paso's images, siros-qes's documents. |
| `verifier_info` in the prefix's question | Hands attestations about the Verifier to the trust framework that reads their formats. | §5.11 leaves the formats to "ecosystems or profiles"; the core passes them as received. | Any further registration-certificate format. |
| `Profile::authentication`, `AuthenticationNeed` | Lets each profile state the End-User authentication it needs. | PSD2's three categories; no method named. | siros-paso's SCA risk profiles. |
| `WalletMetadata`, `MetadataMember`, `PostContribution` | Composes the wallet's metadata and the POST's parameters from the registered parts' contributions, each name from one contributor. | Each format, prefix, mode and module writes its own member; the registry refuses a name two parts declare when it builds. | Any further format, mode, profile or deployment member (§10.1, §5.10). |
| siros-paso's engine | Renders a profile's entries under PaSO's display, value-type and locale rules. | No TS12 code in siros-paso (I16). | siros-ts12. |
| siros-syntax's `checked!` and `Keyed`, private fields behind checking constructors | Hold each value to its rule: a fixed identifier when the crate builds, entries under distinct keys when they are made, a value bound to the request in the step that holds the request. | Generic over the type and its rule. | `ErrorCode`, `PrefixName`, `ParameterName`; siros-ts12's fetched documents and resources by URL; `Verifier`, `Encryption`, `Rejected`. |
| Host modules: `Has`, `MayHave`, `Slot` | Lets each plug-in and each mechanism name the host capabilities it requires and those it uses when the build holds them; the compiler checks a build's host against every part it registers. | The core defines the access traits and its own modules; each plug-in defines its own (I23); `CoreHost` names what the core calls alone. | siros-mdoc's `DeviceMac`, siros-paso's `Paso`, `RandomIds` and `CoseEncrypt`; `prefix`'s and `jwe_mode`'s `Haip`, `EncryptedRequests`'s `RequestDecryption`. |

## 8. Acceptance gates

### 8.1 Known answers

KA1 to KA6, KA8, KA12, KA13 and KA20 are derived and checked now by `ka/ka.py` (`ka/ka.out`: 12
of 12 checks hold; KA6 has three). KA14, KA15, KA17, KA18 and KA21 to KA24 need the code; the
implementation's tests reproduce every row with it. KA1 to KA5 run through siros-mdoc's
`Thumbprint` and `Handover`, from a session's binding facts.

| KA | Input | Expected | Source |
| :-- | :-- | :-- | :-- |
| KA1 | B.2.6's JWK | thumbprint `4283ec92...669047` | B.2.6.1, B.2.6.2, RFC 7638 |
| KA2 | `x509_san_dns:example.com`, the B.2.6 nonce, KA1, `https://example.com/response` | OpenID4VPHandoverInfo `847818...7365` | B.2.6.1 |
| KA3 | KA2 | OpenID4VPHandover `82714f...38ac` | B.2.6.1 |
| KA4 | KA3 | SessionTranscript `83f6f6...38ac` | B.2.6.1 |
| KA5 | `https://example.com`, the nonce, KA1 | SessionTranscript `83f6f6...761a` | B.2.6.2 |
| KA6 | §8.3's response JWE, its private key; the core's answer to §8.3's request, sealed through siros-testkit's `JweHaip`, both decrypted by jose-rs 0.10 under that key | the example: header `alg` ECDH-ES, `enc` A128GCM, `kid` `ac`; no encrypted key; payload `{"vp_token": {"example_credential_id": ["eyJhb...YMetA"]}}`. The core's answer, the core's choice: `enc` A128GCM, `kid` `ac`; the plaintext §8.1's object, `vp_token` alone, keyed by the query id, one presentation | §8.3, RFC 7518 §4.6 |
| KA8 | §8.2's error POST body, written by `direct_post` and by `direct_post.jwt` on a route without a key | `error` `invalid_request`, `error_description` `unsupported client_id_prefix`, `state` `eyJhb...6-sVA`, in this order: `error=invalid_request&error_description=unsupported+client_id_prefix&state=eyJhb...6-sVA` byte for byte, RFC 6749 Appendix B's encoding, which §8.2 names (§8.2's example prints the space as `%20`) | §8.2, RFC 6749 Appendix B |
| KA12 | §8.2's by-reference example: the outer `client_id` other than the Request Object's | U14 | §8.2, §5.10.1 |
| KA13 | §8.3's request: four keys, `["A128GCM", "A128CBC-HS256"]` | the key rule picks `ac`, ECDH-ES, A128GCM, the example response's header | §8.3, HAIP §5 |
| KA14 | A.3.2.1's payload as `data.request` | the envelope reads `client_id` `x509_san_dns:rp.example.com`, two `expected_origins`, mode `dc_api`; the classification names siros-x509's `x509_san_dns` | A.3.2.1 |
| KA15 | A.4: an `invalid_request` refusal over `dc_api` through `Route::refusal` under `DcApiErrors::Respond` | `{"error":"invalid_request"}`; `Reply::Cancel` under `DcApiErrors::Cancel` | A.4 |
| KA17 | §5.2's `nonce` `n-0S6_WzA2Mj` and `state` `eyJhb...6-sVA` | both accepted (`.` is URL-safe) | §5.2 |
| KA18 | B.3.6's session: Client Identifier `x509_san_dns:client.example.org`, through the route in F5 | KB-JWT `aud` `x509_san_dns:client.example.org` | B.3.6 |
| KA20 | §5.9.3's `x509_hash` example | the original identifier is base64url without padding of 32 octets | §5.9.3 |
| KA21 | CS-12 §7.2's `sca-iban` type metadata; §8.1's payment entry; the priority list `[en-GB, en]` | offered; View §4 selects the tag `en-GB` over the `en` labels (I33: the list's first); the header's merchant `Example Merchant B.V.` and amount 129.95 EUR; confirm `Confirm Payment` | CS-12 §7.2, §8.1 |
| KA22 | CS-12 §7.2's `sca-user` type metadata; §8.1's `login_risk_transaction` entry; the priority list `[en-GB, en]` | offered; the selected tag `en-GB` over the `en` labels; the rows `Service` and `Action` | CS-12 §7.2, §8.1 |
| KA23 | WE BUILD's test bed: its `sca-iban` configuration and its default payment (`amount` 42.5, `date_time` with milliseconds); the priority list `[en-GB, en]` | offered; the selected tag `en-GB`; `date_time` and `payee.id` internal; amount 42.50 EUR | nxd-wallet-conformance-backend `179507e` |
| KA24 | Each `Factor` | an `amr` value TS12 §3.6 lists, spelled as there | TS12 §3.6 |

KA2 to KA4 and KA18 take their Client Identifiers from the specification's examples; a session
carries any identifier, so they check the handover and the KB-JWT apart from the prefix.

### 8.2 Refusal fixtures

One fixture per rule and per parsing entry point. Each asserts the rule's error variant (or
code) and the member its text names, so a crash or another rule fails it.

| Table | Fixtures | Count |
| :-- | :-- | --: |
| Unreadable | U1 to U14, U16 to U19, one each | 18 |
| Unauthenticated, core | A1, A2, A3, A6, A7 (an `alg` the test `Haip` does not state, before any question), A8 to A13, A14 (`TestObjectRule`'s refusal under its own code) | 12 |
| A5, siros-x509 | `x509_hash`: the identifier no base64url of 32 octets; the leaf's hash unequal. `x509_san_dns`: the identifier no DNS name in preferred name syntax; no dNSName of the leaf naming it; without `endpoints`, a `response_uri` on another host (A12). Both: `x5c` absent; `x5c` empty; an item no base64; an item no DER certificate; an item with one trailing byte (x509-cert's entry point); the leaf's key no uncompressed P-256 point | 11 |
| Routed | P1 (absent, a type no registered type names); C5 (absent, no registered mode on the channel, `direct_post`); P5; P6; P7; N1; S3; S4; C7 (no key the rule accepts, no `enc` it accepts) | 13 |
| Entry points | fluent-uri's parse (U3: an invalid percent-encoding); serde_urlencoded's read through `QueryRead` (U4: an unknown name twice); `ClientId::parse` (U3: `%FF` in `client_id`); base64 (U10: a part no base64url); the `json` module under JOSE: a header member twice (U10), a payload member twice (U3), a JWS JSON member twice (U10), a signature object's member twice (U10), an unprotected header's member twice (U10); RFC 7515 §7.2.1 (U10: one name in both headers) | 10 |
| Response URI answer | no JSON object; a member twice; a relative `redirect_uri`; a registered reader's refusal (`AnswerError::Reader`: siros-webuild's `Cs02ErrorAnswer` over an `error` outside RFC 6749 Appendix A.7) | 4 |
| Registry | a prefix twice; `PrefixName::new` refusing `origin`; a mode name twice on one channel; an answer and an error registration of one name and channel by modes of different types (`ModeTwice`); an error mode over the DC API (`ErrorModeChannel`); a DC API mode declaring a metadata name (`MetadataChannel`); a response type twice; a hash name twice; a transaction data profile without `sha-256` (`Sha256Absent`); a scope value twice; a scope query the DCQL reader refuses; a query id two scope queries share; `RequestPost` twice; `EncryptedRequests` without `RequestPost`; a name two parts declare (`NameTwice`); a name the core writes (`NameReserved`) | 16 |
| Extension outputs | a `Fault` with a cause checked for that cause by type: a mode's body of another channel than the request's (`RouteBreach::BodyChannel`); a `Jwe` choice from a mode registered with `mode` (`KeyInTheClear`); a `Plain` choice from one registered with `jwe_mode` (`NoKey`); a key of other metadata than the request's (`Foreign`, siros-testkit's `TestChoice::Foreign`); a key whose curve or `alg` the sealing statement does not admit (`Unstated`); an `enc` the Verifier does not list (`Unlisted`); a digest of another length than `octets` (`HashesError::Digest`); a contribution writing a name it did not declare (`MetadataRefused::Undeclared`); a response parameter of an undeclared name (`ParameterBreach::Undeclared`); a response parameter written twice (`ParameterBreach::Twice`); a format's `vp_formats_supported` value that is no object (`NotObject`); `FormBody::of` of a nested member (`NotForm::Serializer`); `FormBody::of` of pairs naming `response` twice (`NotForm::Repeated`); `DcApiData::of` of an array (`NotObject`); `PostBody::of` of the form media type (`FormMedia`); a drawn `EphemeralKey` on a curve `decrypts` does not state (`Fault`) | 16 |
| Configuration | a skew past 300 s | 1 |
| Error recourse | a DC API failure under each `DcApiErrors`; A8 under a `Framework` binding, `Listed`; A8 under a `Request` binding, `Unverified`; U12 through `Rejected::unreadable`, `Unverified`; U14, no route; A13, no route; C7's error in the plain form; C5's `direct_post` error, plain to the `response_uri`; C5 `Unsupported` by URI, `Unroutable`; a DC API request naming no registered mode, A.4's error from the core | 11 |
| The POST and the DC API protocols | U11 (a JWE after a GET; a JWE after a POST without `EncryptedRequests`, which posted no key; a JWE whose `alg` `RequestDecryption::decrypts` does not state; one that does not decrypt under the posted key); U1 for the unsigned protocol under `SIGNED` | 5 |
| siros-ts12, request | T1 to T6 | 6 |
| siros-ts12, values | `10.125` EUR; a negative amount; a nested member TS12 does not list; `execution_date` beside `recurrence`; `execution_date` as a date-time; an https `payee.logo` without `payee.logo#integrity`; an integer with a fraction | 7 |
| siros-ts12, metadata | no `ts12` document; `category` absent; an attestation type outside the configured ones; the type no key of `transaction_data_types`; a `schema_uri` URL; `affirmative_action_label` absent; `amount` without claim metadata | 7 |
| Authentication | a `Strong` need answered with one category (`AuthenticationTooWeak`) | 1 |
| Constructors | `FailedStatus::new` of 200; `MediaType::parse` of a text without `/`; `SealedJwe::parse` of four parts; `SealedCose::parse` of an untagged item; `ErrorDescription::parse` of a `"`; `Keyed::new` of a repeated key; `PublicJwk::parse` of a JWK holding `d`; `AgreeableKey::of` of a coordinate that is no base64url; `EntityId::parse` of an empty text; `Count::parse` of a text with a letter; `DateTime::leap` off a month's last day; `DataUrl::parse` without `data:`; `Integrity::parse` of a digest of another length; `DeviceNameSpacesBytes::of` of an element twice; `Presentation::object` of a string | 15 |
| **Total** | | **153** |

The existing `every_parse_refuses_a_member_named_twice` covers the parameters, DCQL,
`client_metadata` (C6) and the transaction data entries (C0), and keeps running; the existing
fixtures keep their texts and codes.

**Tamper cases.** Each checks why it fails. A signature over altered parameters is A8
(`Unauthenticated::Signature`). An `aud` naming another recipient is A10. A swapped outer
`client_id` is U14. A signed DC API request whose verified `expected_origins` lacks the Origin is
C8. A leaf other than the one the identifier hashes is A5 (`X509Refusal::Hash`). A
`response_uri` outside the decision's `endpoints` is A12; one by `http` is A13. A multisigned
`client_id` moved into an unprotected header is U17. An `x509_san_dns` request whose leaf names
another DNS name is A5 (`X509Refusal::San`). A Request Object encrypted to another key is U11. A TS12 entry altered after the Request Object was
signed is A8. A signature under an `alg` the build's `Haip` does not state is A7, though the
signature verifies, and the caller is asked nothing. A test mode that writes a DC API body on a URI
route is a `Fault` caused by `RouteBreach::BodyChannel`, and no `Delivery` leaves; so is one that
chooses a key the sealing module does not admit (`Unstated`), and one that chooses a key of other
metadata than the request's (`Foreign`). A request read with a registry whose modes sit in another order than a second
registry's answers in the mode it names: the route reads the envelope's registry, the answer's
mode name equals the request's. In each, no Authorization Response is built, and an error goes only where
section 4.5's recourse says.

### 8.3 Invariants

| I | Invariant | Measure |
| :-- | :-- | :-- |
| I1 | Typestate: `Authenticated`, `Route`, an `AnswerRoute` and an `ErrorRoute` to a `response_uri` cannot be built outside the core; neither can phase 2's `AnsweredContext`, a step's filled answers (`Filled`), or an `EphemeralKey` from a JWK and a handle apart. An extension builds none of the values the core binds or hands it: a `VerifierKey` outside the request's keys, `VerifierKeys`, `VerifierMetadata`, a `RouteKey`, a `ModeRoute`, a `RoutedMode` the request did not name, a `Session`, a `ClientClaim`, a `Decided`, a `FetchedRecord`, an `Answered`, a `ConsentEntry`, a `PostBody` apart from `FormBody::of` and `PostBody::of`, a `DcApiData` the core did not read back, an `AuthorizationResponse`, an `ErrorResponse`, a `Built`. | The compiler: each item's fields are private, or its constructor `pub(crate)`. Tests reach these values through the flow, by `crates/siros-testkit/src/probe.rs`. |
| I2 | Every Authorization Response goes to the authenticated endpoint, whatever mode carries it. Every error goes to it, to the platform, to a `response_uri` a `Framework` binding vouches for, or through an `Unverified` route in the plain form; every URI endpoint is an absolute `https` URI with a host; every sealed answer and error is sealed by the core to the session's `RouteKey`, and the mode of a sealed route receives no plaintext. | Property in siros-openid4vp's flows tests over `TestFormat` and `TestPrefix`, over generated URI and DC API requests, accepted and refused, with tampered signatures and endpoints, run once per registered mode: the core's four and 24 `TestMode` variants (each channel; a body of its own channel or the other; the clear, B.2.6's key with A128GCM, with A256GCM, a key of other metadata, a key on a clear registration, no key on a JWE one). Each variant's route verdict (clear, sealed to its `kid` and `enc`, C7, or the named `RouteBreach`) and phase 2 outcome (an answer, refused, `BodyChannel`) derive from its registration, its choice, the request's keys and `enc`s and the test `Haip`'s statement. DC API errors are A.4's `{"error": code}` in the clear; URI errors are sealed when the session holds a key; a built route never faults its errors; a rejection posts to the request's own `response_uri`, `Listed` only when the trust double lists it. Default 24 requests per mode (seed 1); per merge 1,500 per mode over seeds 1 to 3. Violations 0; each mutation (an unlisted `enc` accepted, a foreign key accepted, the clear faulting, `Unverified` written `Listed`, errors in the clear on a sealed route) gives violations. |
| I3 | Records hold for every arrival: phase 2 answers only records phase 1 derived. | The existing property, run over generated URI and DC API requests: mismatches 0. |
| I4 | Digest domains: two received forms never share a digest; DC API digests equal today's. | Property over pairs: collisions 0. The differentials' record ids compare byte for byte. |
| I5 | Replay: the same `Received`, answers and host outputs give the same `Delivery` bytes. | Property over a sealed URI route and a `dc_api.jwt` route: 50 replays per route by default, 1,000 per merge, differences 0. |
| I6 | Litmus G1: the core's tokens name no plug-in concept. | The zkp_req proposal's scan, with the plug-in vocabulary, the WE BUILD profile's words and PaSO View's display vocabulary added (`g1/g1-scan.py`). Baseline at `f718dc3`: 35 hits, 13 `_req` inside `invalid_request` tokens, 1 `urn:`, and 21 of PaSO View's vocabulary in `rows/` (`MiniMarkdown`, `CurrencyAmount`, `mini_markdown`, `currency_amount`) (`g1/g1-f718dc3.out`). The core signatures of section 4, scanned by `g1/g1-gate.sh` on this revision's `sigs/src` (`g1/g1-sigs.out`): 10 hits, each `_req` inside an `invalid_request*` code; their plug-in modules, the positive control (`g1/g1-control.out`): 170. After: every hit is `_req` inside an `invalid_request*` code; the `urn:` leaves with `SignalType` (decision 13), PaSO View's vocabulary with the internal model (decision 19). |
| I7 | Litmus G2 (section 8.4). | `tools/litmus-g2.sh`. |
| I8 | Litmus G3: siros-x509 removed, the workspace builds and passes its tests. | Outside `crates/siros-x509` the removal touches siros-integration alone: its dev-dependency and the end-to-end tests that register siros-x509's prefixes. |
| I9 | The differentials compare everything they compared. | Per-kind tallies of every differential at seeds 1, 2, 3 × 1,500 equal the baseline measured on the implementation's base, apart from the `dc_api.jwt` classes reading 25 moves: a first key off P-256; a key without `alg`; a key wrap; a coordinate of another length; an `enc` list with A256GCM after another value, or with neither GCM value. Each class is tallied; mismatches outside them 0. |
| I10 | The matcher's build carries no X.509, form, CBOR or curve arithmetic code, and fluent-uri only for `HttpsUrl`. | `cargo build --target wasm32-wasip1 -p siros-openid4vp --no-default-features --features match,dc-api` passes; `cargo tree` for it lists no serde_urlencoded, form_urlencoded, x509-cert, ciborium, coset or p256, and fluent-uri without its `net` feature; the matcher stays within I18's limit, which this check fails at `687eb65`: `state/paso-size/gate-merge/verdict.txt` measures the matcher probe at 503,427 B for SD-JWT with no PaSO, 656,051 B with PaSO and 729,035 B for WE BUILD, above the limit by 42,627 B, 195,251 B and 268,235 B; siros-i18n's `Context`, loading and resolving, and each format function are measured alone and on the combined build; the ISO 4217 table adds +1,165. |
| I11 | No network notion in the core. | `fn fetch` and `.fetch(` in `crates/siros-openid4vp` and siros-x509: 0. |
| I12 | Every known answer holds through the core's and siros-mdoc's code. | KA1 to KA6, KA8, KA12 to KA15, KA17, KA18, KA20: 14 of 14. |
| I13 | Merge gates. | `tools/merge-gates.sh`: every line `EXIT=0`. |
| I14 | The superseded API is gone. | `Received::Unsigned`, `Received::Signed`, `ResponseData`, `matching::ResponseMode`, `routing::ResponseMode`, `DcApiMode`, `ModeChoice`, `Modes`, `Protection`, `Target`, `PostBody::Cwt`, `DirectPostCwt`, `Encryption::choose`, `Es256Signature`, `VerificationKey::p256`, `AuthorizationResponse::cbor`, `Strength`, `RequestClaims`, `boxes::`, `resolve::respond`, `session::Endpoint`, `ErrorCode::InvalidClient`, `HttpsUrl::shaped`, and `p256::` in `crates/siros-openid4vp`: 0 occurrences. |
| I15 | Every JSON object the core and siros-x509 read passes the `json` module, and every CBOR item the core and the plug-ins read passes `cbor::decode`; both refuse a repeated name or key at every depth. | `serde_json::from_` outside `json.rs`: the `strings` helper of `request/mod.rs` alone, which reads an array of strings. ciborium's readers outside `cbor.rs`: 0. |
| I16 | siros-paso holds no TS12 code. | `urn:eudi:sca`, `ts12` and `visualisation` in `crates/siros-paso`: 0. |
| I17 | siros-paso's seams change no PaSO output. | A one-off comparison across the seams' commit: every rendering, `Bound` and response member over siros-paso's tests and the differentials' PaSO corpus, byte-identical. |
| I18 | The matcher with siros-ts12 stays within its budget. | `matcher.wasm` with siros-paso and siros-ts12 registered: at most 460,800 bytes. The gate fails at `687eb65`: `state/paso-size/gate-merge/verdict.txt` measures 729,035 B for WE BUILD, 268,235 B above the limit. That file's own size gate exits 1 on `bytes-ts12`, 729,035 against 725,000, and `ts12-bind-bytes`, 17,020 against 12,000. |
| I19 | One honest end-to-end path per build. | siros-integration, whose `tests/end_to_end/we_build.rs` holds the WE BUILD row and host: the HAIP build over F5; the WE BUILD build over F11 and over F12, a DC API answer to a TS12 payment with `verifier_info` under the required trust service. F11: POST and a JWE Request Object encrypted with the first values of the posted `authorization_encryption_*` lists (reading 21), `verifier_info` to the trust service, a TS12 payment, the Key Binding JWT's TS12 claims, the Verifier's error read by siros-webuild's reader. |
| I20 | siros-ts12's parse accepts no payload TS12's own schemas refuse. | A one-off run over generated payloads: every payload siros-ts12 accepts validates against TS12's payment and login schemas, format assertion off; each schema-valid payload it refuses falls under a rule of section 4.10.2, counted per rule. |
| I21 | WE BUILD's test bed accepts the WE BUILD build. | Its CS-12 payment test at the milestone: pass, with the run's log. |
| I22 | A build takes no plug-in or mechanism whose required module its host lacks, and no host changes a module's presence while running. | The compiler, by the method's own bound: siros-paso registered without `Paso`; `jwe_mode(DcApiJwt)` without `Haip` (`JweHost`); `client_prefix(X509Hash)` without `Haip`; `request_encryption` without `RequestDecryption`; a host type implementing the sealed `Slot`. `cargo xtask alone` compiles each crate with and without its default features. |
| I23 | The core holds no plug-in's module, binding or platform vocabulary. | `DeviceMac`, `Paso`, `SignalType`, `Measurement`, `Reading`, `ProofRequest`, `SessionTranscript`, `Thumbprint`, `OpenID4VPHandover`, `bio_strong`, `StandardBox`, `PaymentBox`, `AddPaymentEntryToSetV2`, `RandomIds`, `CoseEncrypt`, `SealedCose`, `Cs02`, `CS-02`, `"dc+sd-jwt"`, `"mso_mdoc"` in `crates/siros-openid4vp/src`: 0; `"dc+sd-jwt"` and `"mso_mdoc"` in siros-paso's, siros-qes's and siros-ts12's sources: 0. |
| I24 | The host modules change no output. | A one-off comparison across that commit: every delivery and response member over the tests and the differentials, byte-identical. |
| I25 | Crates stand alone (section 4.11). | Each crate builds alone, with its default features and with `--no-default-features`; per crate, `cargo tree -e normal` lists exactly the SIROS crates section 4.11's table names; each optional crate removed (siros-x509, siros-mdoc, siros-sdjwt, siros-paso with siros-ts12, siros-qes, siros-zkp-req), the workspace builds and passes its tests, siros-testkit unchanged. |
| I26 | The documentation builds and its examples run (section 4.12). | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`: 0 warnings; `cargo test --doc --workspace --all-features`: every example passes; every crate's `lib.rs` includes its README; each extension point of section 4.12's table has an `# Implementing` section whose example compiles. |
| I27 | An id is unique in its crate (E0428) and across crates (`CheckError::Repeated`). An argument is a named field with `Display` (section 4.13). | In the shipped wallet crates, `cargo xtask layout` counts a type deriving `thiserror::Error` without `Explain`, derived or written by hand, and a statement (a type deriving `Message`) that implements `Display`: count 0. siros-integration's `texts.rs` links every shipped crate: its rows number the `#[explain(id` and `#[message(id` attributes of the crates it links, counted in their sources, and `Context::check` over the test app's English and German sources, with a module that words every error row, returns `Ok`. `compile_fail` doctests in siros-explain-derive and siros-i18n-derive, one per rule, each fail with their error: an id twice in a crate (E0428), an argument type without `Display` (E0277), a tuple field that is neither a cause nor skipped ("an argument is a named field: name it"), a type deriving both `Explain` and `Message` (E0119). The English texts the differentials compare are unchanged (I9). |
| I28 | Only `Context::resolve` makes a `Text` (section 4.14). | `TableLocale` in the sources: 0. Message sources (`.mf2` files) in the shipped crates: 0. `String` fields in the box and row types: 0 (16 at `f718dc3`). `cargo xtask layout` counts each message source under `crates`, `xtask` and `locales`, outside a crate's `tests/` and siros-testkit, and, in the shipped crates' sources, each field of a statement given a value that holds a string literal, a `format!` included: count 0. `Text`'s field is private, so a crate outside siros-i18n that names `Text(..)` fails to build; inside siros-i18n, the evaluator `Context::resolve` runs makes the one `Text`. |
| I29 | The engine conforms to MessageFormat 2. | The message-format-wg test suite at `16372a6`, for the stable scope (syntax, data model, pattern selection, bidi, `:string`, `:number`, `:integer`, `:offset`, `:currency`, `:percent`): `Context::module` refuses each syntax and data-model error test, and `Context::resolve` passes each formatting test, variable option values included: N of N, outside three skipped classes, each skip listed with its class: markup outside the three styles, parameter names outside the tokens, and undeclared inputs. A suite test that expects a fallback value passes when `resolve` returns that test's error. |
| I30 | A context loads every source whole and words every id (section 4.14). | One fixture per `LoadError` rule, each refused for its rule and no other: resource or MF2 syntax, a data-model error and markup that does not nest (`Syntax`); an id or a `[formats.<f>]` section loaded twice (`Repeated`); a module whose `@locale` is absent or differs from the context's (`Locale`); a call of a function the build does not compile in (`Function`); a call whose format options no module loaded so far defines (`Option`); a `[formats.<f>]` section the build's format refuses (`Format`); a call its function refuses at load, MF2's message function errors (`Call`). The test app's English and German sources load into one context per language, and the end-to-end tests load the corpus's converted PaSO and TS12 View sources into a clone of it. `Context::check` over each language's context, with a module that words every error row, returns `Ok` (`texts.rs`). One fixture per `CheckError` rule returns its error: two crates under one scope (`Repeated`), an id no module words (`Unworded`), a pattern that reads a variable its row lacks (`Unknown`). |
| I31 | Phase 2 refuses a pick whose `shown` digest differs (section 4.14). | Over the differentials' corpus, the matcher's build and the wallet's build resolve each entry's texts from the same sources and arguments: entries whose `shown` digests differ, 0. A pick whose `shown` differs from phase 2's record is refused with `Finding::Rendered`. The encoding is injective: a property over generated texts gives different digests to texts that differ in a span's text, styles or boundaries. Siros-testkit's English and German sources resolve the texts of `f718dc3`'s tables, each difference classed, in one comparison the milestone runs once. siros-paso's injection fixture holds issuer text outside NFC in a plain label, a `mini_markdown` span and a template, and siros-ts12's in a label: each shows it as written with siros-i18n's `nfc` (the workspace's run) and without it (`cargo test -p siros-paso -p siros-ts12 --all-features`). |
| I33 | PaSO's locale follows View §4, and `format_entry` RFC 4647 (section 4.14). | PaSO's locale, a property over priority lists, display arrays, default entries and discarded template entries, against a selection the test writes from View §4: the first tag whose every array matches by RFC 4647 Lookup or its default entry, the credential excluded with none. Known answers from RFC 4647 §3.4: `de-CH` over `[de]` gives `de`; `en-US` over `[en]` gives `en`; `en` over `[en-GB]` gives none, and the default entry answers. WE BUILD's TS12 example, its `en-GB` claim labels converted to `en`, is presented to `[en-US, en]`, `[en-US]`, `[en-GB]` and `[en]` under the list's first tag, and excluded for `[de]`; an array of `en-GB` and `en-US` labels beside no `en` converts its first to `en` and keeps the second. Replaying `display_locale` by View §4's step 1 over the metadata and the payload gives the consent's entries: 0 differences. `format_entry`'s basic filtering, known answers from RFC 4647 §3.3.1 and the list's rule: `en` over `[en-GB]` gives `en-GB`, over `[en-US, en-GB]` gives `en-US`, over `[en-GB, en]` gives `en`; `en-US` over `[en]`, `en-US` over `[en-GB]` and `en-GB` over `[en]` give none. Over the corpus, the picker's and the consent's PaSO locales are equal: 0 differences. |
| I34 | The shipped crates link no i18n crate (decision 19). | `cargo tree -e normal` of the shipped crates and the matcher lists no rust-mf2 or jiff crate, and no ICU4X crate outside `icu_properties`, which reads general categories, and idna's own dependency `idna_adapter` (with icu_normalizer and the crates they pull in), of which `HttpsUrl`, calling `idna::punycode` alone, links no item. siros-syntax's table answers as a second reading of `list-one.xml` for all 17,576 three-letter codes: 178 listed with their minor units, 17,398 refused. The matcher's tree, and that of siros-credman, siros-paso and siros-ts12 without default features, lists no unicode-normalization, which siros-i18n's `nfc` alone links. |
| I35 | Dates and times resolve as ICU4X formats them. | For every locale the wallet ships, `:siros:date`, `:siros:time` and `:siros:datetime` over siros-syntax's ISO 8601 texts, at each length, with the options the CLDR tool writes, equal ICU4X 2.4's `DateTimeFormatter` over the same CLDR release, for each day of 2000 to 2030 at 00:00, 09:05, 12:00 and 23:59, and for 4 March and 31 December of every year 0 to 3000 and of 9999: 0 differences. Classed: German `full` dates before year 1000, where CLDR 49's pattern holds the field `Y` and ICU4X writes a literal `Y`. In the per-merge tier (`#[ignore]`). |
| I36 | Numbers, plural categories and currencies resolve as ICU4X formats them. | For every locale the wallet ships: plural categories and number texts for the 153 values of the probe (integers, decimals with and without trailing zeros, negatives, large numbers), each given as its literal text; an amount in every currency of ISO 4217 List One, through `:currency`: each, with the options the CLDR tool writes, equal to ICU4X 2.4 over the same CLDR release: 0 differences. Classed: the German cells where CLDR 49 sets a symbol to its code and ICU4X's datagen falls back to root's symbol (PHP's symbol, SYP's narrow symbol, XXX's symbol and narrow symbol). In the per-merge tier (`#[ignore]`). |
| I37 | The matcher reads the registration's base entries and the sources its request names, counted in bytes (section 4.14). | siros-credman's bytes-read test: over a registration of the test app's English sources and the types `t0` and `t1`, a request naming `t1` reads the header, the directory, the base entries and `t1`'s source, each byte once, and no byte of `t0`'s; the expected ranges come from the README's layout. Its context words `t1`'s message and the base's, and `t0`'s message is `ResolveError::Unknown`. One fixture per rule of the README's "Reading" refuses its blob with that rule's `Malformed`. Six fixtures refuse sources that do not load: `Base::load` a base source that does not load and sources of another locale; the writer a type's source that loads only after another type's, and two types' sources that word one id; the reader a blob whose base source, or whose named type's source, does not load. One fixture writes one source under two types, and a request naming both loads it. One fixture holds a variant key outside NFC: the writer refuses it in a base source (`RegisterError::Source`) and in a type's source (`RegisterError::Transaction`), each with `LoadError::Unnormalized`, and writes both with the key in NFC. An entry with ad-hoc PaSO metadata (Proof Metadata §5) is offered and resolved by the matcher, its texts equal to the wallet's for the verified JWT: 0 differences; phase 2 refuses it as incompatible when its JWT fails a §5.3 step, one fixture per step. An ad-hoc claim label with no visible character refuses its entry (`LabelViolation::Invisible`), and the matcher emits the request's next entry. |
| I39 | A build compiles what it registers (section 4.11, decision 20). | `cargo tree -e normal,features` of each build of section 4.11's per-build table, the core and the plug-ins it registers, with the features its crates turn on: each lists none of the crates its row names, and siros-i18n with the features its row names alone, the wallet's with `nfc` beside them; the SD-JWT and the mdoc DC API builds each compile fewer crates than 96, the count at `a307cca`, and the two counts differ. `cargo xtask builds` holds the count clause per row (`fewer_than`, `differs_from`). |
| I40 | The core's own cases are peers of an extension's. | The core's four modes, `vp_token` and its hash algorithms reach the core through its public API alone: `pub(crate)` items named in `modes.rs`, `hash.rs` and `VpToken`'s implementation: 0; the two files compiled outside the core raise no privacy error (E0603, E0624). Every registered mode passes I2's property, the core's and `TestMode`. Each extension point of section 4.12's table has its `# Implementing` section (I26), its test double, and one fixture per registry conflict (section 8.2): 0 missing. |

### 8.4 Litmus G2

Baseline at `f718dc3` (`g2/g2-f718dc3.txt`, the tool's verdict `EXIT=0`): 4,295 core lines
instrumented; 131 reached only through real plug-ins, all in `claims/kit.rs` (pending the
kit-placement decision); 36 reached by no test (10 invariant guards, 26 diagnostics).

Target: no core line outside `claims/kit.rs` reached only through real plug-ins (the 131 stay or
fall with the kit decision); unreached lines at most 36 plus the new invariant guards, each named
in the implementation's report. The test plug-ins of section 6 reach the new core lines:
`TestPrefix` every authentication and recourse branch, the test trust service every answer kind.

### 8.5 The design's gates

**Coverage.** Section 5.4: 13 flows by 12 steps, 156 cells, none empty (`coverage/check.py`).
Every arrival (a link, a QR code, the DC API in three protocols), each `request_uri_method`, each
of the core's modes, an extension mode, both failure paths by URI and the WE BUILD build's SCA
flows appear.

**Requirement trace.** `trace/scripts/extract-all.sh` runs `extract.py` twice over every traced
source: over the sections the flows use (`trace/raw/<id>.tsv`, ids `<PREFIX>-<n>`) and over every
other section (`trace/raw/<id>.rest.tsv`, ids `<PREFIX>-R-<n>`); the two runs split each text's
sentences between them. A run takes every sentence holding MUST, MUST NOT, REQUIRED, SHALL or
SHALL NOT. RFC 3986 writes its requirements in lower case, so its runs take the key words in any
case. List items under an introducing "MUST" became rows by hand (RFC 6749 §4.1.3, RFC 7515 §5.2,
RFC 7516 §5.2). The five WE BUILD sources are Markdown: their runs read each list item and each
table row as its own paragraph, and a key-word-free list item under a key-word sentence ending in
`:` becomes one row, `[the sentence] the item`. Each row is classed: W binds the Wallet in any role (the authorization server, a
JWS recipient, a JWE producer, the presenter, the Request Object's HTTP client), V the Verifier,
X another party or a feature the wallet refuses, the X naming the rule that refuses it. Every W
row names its owner: core, a plug-in, the caller, or configuration. A section whose sentences
bind only other parties or refused features is classed whole, with its reason. RFC 5280's
sections the trust evaluator implements in full stand under one umbrella row, R5280-U1.
`build_trace.py` stops on an annotation naming no row, a row annotated twice, or an umbrella
whose sections differ from those that name it; it prints UNANNOTATED, UNMAPPED and the sections
unaccounted for. `trace/<standard>.tsv` holds every row, `trace/sections.tsv` how each section is
accounted for, `trace/summary.tsv` the counts.

| Standard | Rows | Bind the Wallet | Mapped | Under an umbrella | Unmapped | Sections | Classed whole | Unaccounted |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: |
| OpenID4VP 1.0 | 255 | 124 | 124 | 0 | 0 | 67 | 7 | 0 |
| RFC 6749 | 158 | 23 | 23 | 0 | 0 | 52 | 18 | 0 |
| RFC 9700 | 63 | 8 | 8 | 0 | 0 | 24 | 6 | 0 |
| RFC 9101 | 54 | 25 | 25 | 0 | 0 | 15 | 1 | 0 |
| OAuth 2.0 Multiple Response Type Encoding Practices | 17 | 1 | 1 | 0 | 0 | 5 | 1 | 0 |
| RFC 7515 | 51 | 41 | 41 | 0 | 0 | 14 | 1 | 0 |
| RFC 7516 | 29 | 10 | 10 | 0 | 0 | 8 | 3 | 0 |
| RFC 7517 | 28 | 8 | 8 | 0 | 0 | 5 | 0 | 0 |
| RFC 7518 | 52 | 21 | 21 | 0 | 0 | 22 | 9 | 0 |
| RFC 7519 | 24 | 18 | 18 | 0 | 0 | 9 | 0 | 0 |
| RFC 7638 | 4 | 1 | 1 | 0 | 0 | 1 | 0 | 0 |
| RFC 3986 (key words in any case) | 41 | 14 | 14 | 0 | 0 | 24 | 10 | 0 |
| OpenID AuthZEN Authorization API 1.0 | 61 | 13 | 13 | 0 | 0 | 28 | 23 | 0 |
| RFC 5280 | 282 | 62 | 62 | 101 | 0 | 68 | 34 | 0 |
| OpenID4VC HAIP 1.0 (Final, 2025-12-24) | 84 | 48 | 48 | 0 | 0 | 18 | 0 | 0 |
| WE BUILD CS-02 1.2 | 103 | 56 | 56 | 0 | 0 | 13 | 0 | 0 |
| WE BUILD CS-07 0.1 | 22 | 7 | 7 | 0 | 0 | 6 | 2 | 0 |
| WE BUILD CS-12 1.2 | 40 | 21 | 21 | 0 | 0 | 7 | 0 | 0 |
| WE BUILD CS-13 1.0 | 18 | 4 | 4 | 0 | 0 | 4 | 0 | 0 |
| TS12 1.0.1 | 125 | 64 | 64 | 0 | 0 | 18 | 0 | 0 |
| **Total** | **1,511** | **569** | **569** | **101** | **0** | **408** | **115** | **0** |

The 1,511 rows hold 1,503 extracted sentences, 7 hand rows and 1 umbrella row; 545 of the
sentences lie outside the sections the flows use. Among the Wallet rows the owner mentions are
core 356, plug-ins 192, caller 266; a row shared by two owners counts in both. The rows under the
umbrella take its account: their sentences bind the trust evaluator, or the CAs and CRL issuers
it deals with. HAIP §4's rows bind the wallet's OpenID4VCI client (`caller:issuance`).

**Source accounting.** `trace/scripts/trace_sources.py` gives one account to each source: the
traced standards, every normative reference of OpenID4VP (its §16) and HAIP (its §12) and every
reference of the five WE BUILD sources, informative ones included, since their lists do not
separate the two, which `refs.py` extracts from their texts, and every other specification these
flows were designed against. An account is a trace, a caller umbrella, or a reason at source level. `build_trace.py`
stops on a reference mapped to no source, a source nothing requires, or a trace without its
account, and prints the sources unaccounted for. Of 94 sources in all, 20 traced row by row, 2
under a caller umbrella and 72 at source level, each with its reason (Appendix C); the 109
references map to them. RFC 6125 and BCP 195 stand under HTTP-U1: the caller's HTTP
adapter runs TLS as BCP 195 recommends and checks the server by DNS-ID as RFC 6125 §6 says,
without CN-ID, SRV-ID or URI-ID (RFC 9101 §8). The build's verdict (`trace/summary.out`):

```
UNANNOTATED: 0
UNMAPPED: 0
Sections unaccounted: 0
Sources unaccounted: 0
```

**Crates.** `checks/crates.py` finds a pick and a reason for each standard of section 4.7's pick
table. The repeated-member probes (`crates/dup-probe/`, `crates/dup-probe-more/`) fed 15 JOSE
crates and 5 CBOR crates beside the core's `json` module. The parser probe
(`crates/x509-uri-probe/`) fed the X.509 parsers a leaf, its truncations and its bit flips, and
the URI parsers fixed and generated URIs. The form probe (`crates/form-probe/`) fed the form
crates fixed and generated queries and their writers the error members, and runs this design's
query read over serde_urlencoded. `crates/wasm/` built the matcher-profile probes.

**Signatures.** `sigs/` typechecks section 4's signatures against wallet-rs `f718dc3`'s
siros-openid4vp and siros-paso and the picked crates, pinned: `cargo check` with no warning and no
error. The core's four modes implement `Mode`, `ModeHost<H>` and `ErrorModeHost<H>` there with
their bodies, `VpToken` implements `ResponseType`, and the SHA-2 algorithms `HashAlgorithm`, so
each extension point's trait is shown implementable by its core peers.

**Litmus G1.** `g1/g1-scan.py` scans the core signatures (`sigs/src` without the plug-in modules
`plugins.rs` and `profile.rs`): every hit is `_req` inside an `invalid_request*` code.
`g1/g1-gate.sh` runs the scan on this revision into `g1/g1-sigs.out`, and over the plug-in modules,
the positive control, into `g1/g1-control.out` (I6 gives the counts). The plug-in modules hit
`ts12`, `x509`, `paso`, `x5c`, `amr` and `affirmative` among others.

**Numbers.** `checks/numbers.py` checks every count in sections 1 and 8.5 against
`trace/summary.tsv`, the raw trace, the coverage table, `ka/ka.out` and the probes, and this
section's table row by row.

**The trace's limits.** The extractor reads an RFC heading whose title starts with a capital
letter. A title starting with a quote (`5.2.  "cty" ...`) leaves its text in the parent section,
and an appendix letter without a subsection number (`Appendix B.`) leaves it in the section
before. Such rows carry that number (R7519-R-5 is RFC 7519 §5.2's, R6749-R-77 is RFC 6749
Appendix B's), and the rest run catches every one. RFC 5280 §6.1's algorithm steps carry no key
word and stand under R5280-100. OpenID4VP's text is the conversion of its HTML of 2026-03-11,
downloaded apart from `dl-all.sh`.

## 9. Decisions

The owner's answers of 2026-11-02 (1 to 14), 2026-11-03 (15 to 19), 2026-11-04 (20) and
2026-11-07 to 2026-11-09 (21), in the review's numbering.

**1. A DC API request that fails after the End-User chose.** SIROS's caller uses
`DcApiErrors::Cancel`; the core keeps both values. A cancelled flow looks like any platform abort,
and an error would confirm the wallet holds matching credentials (§15.9.2). The Verifier's page
receives the platform's rejection and moves on.

**2. `Runtime::fetch` becomes effects** (`Resource`, `ProfileHost::wanted`). It lands with
this proposal, as its own commit (section 6).

**4. The errors of URI requests refused before authentication.**

- A8 to A10 after a `Framework` binding send `invalid_request_object`, plain, to the vouched
  `response_uri` after the End-User has interacted (RFC 9101 §6.1, §6.2).
- The owner added: "the verifier should have something to tell it the flow failed to redirect
  the ux". Every other refusal whose payload names an absolute `https` `response_uri` carries an
  `Unverified` route. The wallet tells the End-User it could not verify the site, and the
  End-User can choose to return to it. The error then goes to that `response_uri`, and the
  `redirect_uri` of its answer brings the End-User back to the Verifier's page (§8.2, RFC 9700
  §4.11.2; reading 3).
- A request without a readable payload, A13, and the terminating U9 and U14 reach no Verifier
  endpoint: the Verifier's page ends on its own timeout.

**6. In-house implementations with established replacements** move into this change set, each as
its own commit ahead of the flows (owner: "do it now"; section 4.9).

**7. `x509_san_dns` beside `x509_hash`.** siros-x509 implements both prefixes (section 4.4). The
parts of this decision that serve nym_auth's `verifier_id` are deferred with zkp_req (Appendix A).

**8. The URL builder.** `HttpsUrl` uses fluent-uri's builder; the matcher grows by 19,732 bytes
(section 4.9.3).

**9. ciborium and coset** live in the core's `cbor` module behind the `cbor` feature, which
siros-mdoc and siros-paso's `sealed-signals` turn on (section 4.11). RFC 8949 §4.2.1's
deterministic encoder lands with its first caller.

**10. CBOR and COSE stay accounted at source level** (Appendix C): the owner sees no need for a
row-level trace of RFC 8949, 9052 and 9053.

**11. `amr` belongs to the transaction data profile.** `ProfileHost::respond` receives the
End-User's `Authentication` and writes its encoding, so siros-paso writes RFC 8176 strings
(section 4.2) and a TS12
profile writes TS12's objects; the core decides nothing about it.

**12. The WE BUILD profile** (section 4.10). The owner: "ok, then we add the profile in addition
to paso. i expect it to be fully webuild scenario compatible, but not implementing the stupid
stuff like the non standard integrity claims, nor the jsonschema, i expect you to adapt the ts12
system through the paso lens on the badly defined/underdefined parts so we have a shallow
compatibility implementation that uses paso behavior internally", then: "undefined parts are not
handled, like extend of the transaction data types". Full WE BUILD compatibility takes the four
parts the review listed: `verifier_info`, the POST fetch with encrypted Request Objects, the TS12
profile, and the WE BUILD build. On the POST the owner added: "wallet nonce seems unwarranted. any
other such things you added just in case ?" Every part the profile adds carries a requirement:
CS-02, CS-07, CS-12, CS-13, TS12, or OpenID4VP's REQUIRED and SHOULD for the POST (readings 21,
22).

**13. Host modules** (section 4.2). The owner: "i think we can learn something by axum state
handling: most of these are implementations that need to be provided optionally, so the host
state should be modular, and profiles may request optional or requried host state modules"; "so
essentially each handler requirering some specific state could use the trait bounds to enforce a
mandatory or optional data provider on the host interface"; "be careful though, those are
statements on the availability on compile time modules, not runtime properties that must be
asserted before they are provided"; "try to group them by family where they belong together, for
instance if haip mandates a whole chunk put it all together"; "a lot of these modules can be zero
sized structs that can simply be &Type to be provided as they hold no state on their own, like the
zkp prover system"; then "yes looks great". `proposals/flows/host-sketch/` shows the design
compiling over the HAIP and WE BUILD builds, and the compiler refusing a build whose host fails a
registered plug-in's module bound.

**14. `direct_post.cwt` is deferred with zkp_req** (Appendix A). The owner's earlier "cwt should
be supported" stands for zkp_req's crates: `direct_post.cwt` is a mode there, registered as
any extension's (section 4.2's `Mode` and `ModeHost<H>`). The core seals JWE alone; a COSE
sealing beside it, bound by `Has<dyn CoseEncrypt>` so a build whose host lacks the module refuses
it when it compiles, is the sealing extension point zkp_req's plan adds.

**15. nym_auth 0.7, the backends and the interface split.** The owner: "the already standard
parts can be made, like cwt and the x509 stuff", then "be careful, we are still planning"; then,
with AltmannPeter/readdit-demo `rulebook-v07` readable: "please finish the plan, also do the other
available backends, backends must be their own crates that work on their own, look at how to make
the interface split (show me), ideally the backends are shared across multiple zkp_req flows, they
each can have their own interface that the flows know how to use". The zkp_req proposal holds the
split (M6), the backends (section 2.4) and nym_auth 0.7 on Longfellow (section 2.5); zkp_req is
out of this plan's scope, and Appendix A lists what is deferred with it.

**16. Crates stand alone** (section 4.11). The owner: "ensure things that should be able work
independently from the other crates work independently by default", then "i.e. needing the tree
should not import the jungle".

**17. Documentation** (section 4.12). The owner: "we need to expose the extension points in a way
that is well documented and usable by humans, have nice readmes that give well structured
overviews without any useless description of behavior. readmes are about what it does (what
problem it solves, not how) and how to use. keep them short and direct, get inspiration from the
state of the art in rust".

**18. Errors are messages** (section 4.13). The owner: "ensure the plan has proper error handling
enforced in a way where i18n messages of them can be attached properly by the wallet if
required", then "ensure you impose a trait contract, not structure for the errors. ideally in a
thiserror compatible way, or make your own equivalent system otherwise (maybe even as addo-on ?)".

**19. The core renders every text** (section 4.14). The owner: "this also ties into our i18n
system, especially for the matcher, is it properly bilt and thought through ? i would expect
something along the lines of messageformat2 or equivalent", then "i think owned message is the
wrong boundary, the system should not leave string formatting/interpolation to the frontend as
it's sometimes crucial to be verifiable", then "be careful, everything must be lazy until the last
moment where it is sent to be displayed". On the model: "careful, paso templates should not leak to
the system, the general renderer should be able to ingest and convert paso display rules to the
internal model"; "do things with enums rather than strings where possible, even values should be
one of a i18n query, formatted value (support for dates, currencies etc..), and only as a last
resort a raw string"; "avoid reinventing crates when suitable ones are available"; "the i18n defs
should have mandatory formats for all locales it supports, i18n defs are mdoular, within a module
all keys must be available and compatible across all languages. modules are there to allow for
paso like special definitions that may not have all languages and constrain the resolved locale";
"i18n defs need a string based formatting format so that anyone can configure them properly (that
is parsed to a structures immediatley on loading)"; "the library should output wither pure text of
structured formatted text that is then rendered deterministically by the frontend. the formatted
one must be convertible to the normal one". On the engine, after the sizes were measured: "goal is
to have proper validation, rendering should be done by our system"; "i think it's wiser to do our
own except for the iso lookup tables, might as well use the existing ones"; "except if we can find
a smaller representation for those"; "5.8kb seems excessive, it looks reducible"; "i.e. const time
remapping of the iso lookup table into something more efficient ? currencies + decimals of
those". On formats: "supported formats and rendering should be modular in the framework"; "i.e.
also the requirement to define the per language format options in the main i18n module"; "each
module must define the options of the formats it uses". On languages: "some metadata like for ts12
or paso can be missing the wallet's locale, the goal is that the presentation uses one homogenous
supported language, switching only to languages the user understands (if the module wants that
enforced)"; then, on matching: "en should match enUS or enGB", "but not the other way around",
choosing generic-to-specific matching, and "it is expected modules define things as en and only
en-US or en-GB if they want more precise variants, wallets should request an array in roder of
preference, and if they request a specific they should generally also put the generic after
[en-US, en]", then "i mean this is none of the concern of this core, it simply must be documented
and suggested the wallet do that", and "we need to be careful not to make choices that should be
the wallet's decision": the fallback languages, the language policies no specification sets,
the bidi strategy, what a failed screen shows and when to re-register became the app's.

**20. The core is modular** (sections 1, 4.2, 4.11, 4.12). The owner: "the whole principle is
that this core is modular, why were you about to put cwts in an enum ?"; "it's also not just about
enums, it's about crate independence, and properly defined, safe extension points. many core
mechanisms are actually extension points"; "i should be able to use openid4vp with only sd-jwt,
or only mdoc for instance, without importing irrelevant stuff"; then "i don't want a report, i
want you to ensure you understand and apply the general principle properly". It settles:

- The core keeps what OpenID4VP fixes and the invariants no extension can break: every answer
  reaches the authenticated endpoint; a signature verifies under the key the prefix bound; phase
  2 answers only records phase 1 derived; a record commits to the request as received.
- Each mechanism a specification leaves open, or that deployments vary, is an extension point
  (section 4.12): response types and their parameters, response modes, transaction data hash
  algorithms, scope queries, error codes, the algorithms the modules implement,
  `wallet_metadata`'s members and the POST's parameters, the Response URI's answer members,
  rules on a Request Object's claims, a format's placement of a profile's members, an inherence
  factor's classification, the platform's display entries.
- An extension cannot reach an endpoint, key, session or record the core did not make or bind,
  cannot construct the core's typestate values, and a bad output is a refusal or a `Fault`. The
  core seals every encrypted answer itself, and a mode wraps the JWE it receives.
- A build compiles what it registers (section 4.11, I39); `CoreHost` names the module the core
  calls with no extension registered, `Platform`, and each registration that makes the core call
  another module bounds it.
- The core names no format, profile, prefix, response mode, platform or deployment beyond
  OpenID4VP's own; plug-ins meet through the core's traits.

Kept fixed, each by a ruling or by the principle: effects stay sealed to trust evaluations and
resource fetches, the caller's protocol, each plug-in's content within them its own; `Haip`
groups `verify`, `sign` and `encrypt_jwe` (decision 13's family grouping); DCQL stays in the core
(owner ruling); `trusted_authorities` matches the facts the app registers per type; the DC API
protocols are A.1's three, the app's registration picking among them; a response type carries the
VP Token in the Authorization Response (§8), so `code`, whose VP Token travels in a Token Response,
stays in the archived full-width design; `TrustConfig`, `OriginPolicy` and `DcApiErrors` stay the
app's configuration, each a choice the specifications name; A.4's DC API error and §8.2's plain
error form stay the core's, fixed by OpenID4VP; `AuthenticationNeed { Presence, Strong }` over
factor categories stays the platform contract.

**21. An error and a statement are an id and arguments; the wallet's context resolves them**
(sections 4.13, 4.14). The owner, 2026-11-07: "errors have a id + args mapping that map trivially
to i18n", "a context module is just the messageformat2 source in a way that resolves the id +
args, nothing more", and "i want something dead simple, and don't be fooled, simple yet effective
is not trivial". On 2026-11-08, of stored unresolved messages: "these only output as fully
formatted structure, i18n already resolved, be it for the dcapi or wallet". The owner approved the
design on 2026-11-09 ("go"). Decision 18 stands. Four rulings of decision 19 give way:

- "be careful, everything must be lazy until the last moment where it is sent to be displayed":
  every output holds resolved `Text`, a record commits to the digest of the texts its entry
  showed (`shown`), and each extension point resolves through the `Context` it receives.
- "do things with enums rather than strings where possible, even values should be one of a i18n
  query, formatted value (support for dates, currencies etc..), and only as a last resort a raw
  string": an argument is its `Display` text in its literal form, which the wallet's MF2 functions
  parse. A code from a closed set stays an enum, each variant a statement.
- The packages and modules of "the i18n defs should have mandatory formats for all locales it
  supports, i18n defs are mdoular, within a module all keys must be available and compatible
  across all languages. modules are there to allow for paso like special definitions that may not
  have all languages and constrain the resolved locale", "i.e. also the requirement to define the
  per language format options in the main i18n module" and "each module must define the options of
  the formats it uses": a context is the MF2 sources of one locale, its format options defined once
  and loaded first, and the wallet's `Context::check` test proves its wording complete.
- The core's language choice, "the goal is that the presentation uses one homogenous supported
  language, switching only to languages the user understands (if the module wants that
  enforced)": the wallet picks the locale by the context it passes, as decision 19's "we need to be
  careful not to make choices that should be the wallet's decision" puts fallback languages and
  policies with the wallet. PaSO's View §4 selection and its `display_locale` stay as written.

Decision 19's other rulings stand.

The design's revision of 2026-11-10 settles three points. A credential's display metadata (SD-JWT VC
Type Metadata, OpenID4VCI claims display) shows as written through `ClaimText::Label`, the entry
`format_entry` picks over `Env.priority`: a converted source resolved to the same text. Only PaSO's
and TS12's Views convert to MF2 source. The emission fails as a whole on the first choice that does
not emit (`NotEmitted`): a `ResolveError` or a `NoName` there comes only from a defect in the
wording or a converter, and a defect gets a local abort. The wallet holds MF2's names, variant keys
and selector literals in NFC (siros-i18n's `nfc`), and the matcher holds them as written and links
no unicode-normalization: siros-credman's writer refuses a source NFC would change, so both builds
resolve a registration to the same texts.

The code departs from the approved design in these points:

- `LoadError::{Format, Call}` and `ResolveError::{Option, Argument}`: each refuses a state the
  engine would otherwise turn into a default, and no variant of the design fits it.
- siros-i18n's `conformance` feature holds MF2's test functions: under `check`, a wording that
  calls `:test:format` would pass the completeness test and fail to load in the shipping build.
- siros-derive-internals holds the field rules both derives apply: a proc-macro crate exports only
  macros (serde_derive_internals' pattern).
- siros-paso's converters call no `:number`, and siros-paso turns on `currency` and `date` alone:
  its counts are `Display` arguments, and no View §3 value type calls `:number`.
- `RenderedAt` and `ValueText::{Time, Currency, Amount}` are statements: a rendered label's
  position shows as `ArrayAt`'s does, and no `ClaimText` variant carries a time, a currency or an
  amount.
- siros-paso's `bind` loads the type's converted source only into a context that lacks its first
  label: the matcher's context already holds the source the registration carries, and a context
  refuses an id it already words (`LoadError::Repeated`).

## 10. The repository

This plan governs the presentation core of sirosfoundation/siros-wallet-core. The branch `flows`
organises the repository under it:

- the plan's crates arrive from wallet-rs as they are, then change in place;
- each capability of the earlier presentation port lands in one of the plan's crates, or the plan
  supersedes it with the reason given;
- the WMP engine calls the core for every OpenID4VP rule and performs the core's effects;
- the colleague's zkp_req crates change where the core's API forces it.

### 10.1 The base

origin/main `bfd5670` (2026-11-05) holds 56 commits, all by Leif Johansson. Its root workspace has
20 crates:

- the 11 crates of the earlier presentation port, 37,596 lines of `src`;
- siros-zkp-req and siros-zkp-catalogues;
- the 7 WMP engine crates, engine-core with 14,532 lines, its `oid4vp` module 3,911.

`proving/` is a second workspace of 4 crates at Rust 1.95. The root workspace is edition 2021 and
resolver 2. Its `rust-version` is 1.82, its toolchain pinned at 1.99.1.

CI on `bfd5670` (run 41940538278) passes 9 of 9 jobs: Test, Format, Clippy, Minimum supported
Rust, Proving workspace, WASM (browser engine, Node), Build the browser presenter, UniFFI async
smoke (JVM) and UniFFI bindings type-check (Swift); the OpenSSF Scorecard workflow passes beside
it. The branch merges `bfd5670` at `7fd01a1`. The conflicts take the branch's side: proving
imports `Date` and `DateTime` from `siros_zkp_catalogues::date`; CI keeps the msrv job that
checks every crate on 1.89 with and without its default features; the lock keeps main's zeroize
1.8.2 and base64ct 1.6.0.

The engine's dependencies exceed the 1.82 floor. In the base's `Cargo.lock`, aes 0.9.4 declares
Rust 1.89. jose-rs 0.10.0 and kryptering 0.7.0 declare 1.88. tokio 1.54.1 and getrandom 0.4.3
declare 1.85. getrandom 0.4.3 and aes-kw 0.3.1 are edition 2024.

In engine-adapter-wasm, the mini host builds its PID's presentation itself: base64 for the
segments, the disclosures the match named, and the KB-JWT of RFC 9901 §4.3, its `sd_hash` under
the PID's `_sd_alg`. Main writes it on siros-codec, siros-dcql and the earlier siros-sdjwt's
holder API, which the branch removes. The engine-over-the-core milestone replaces that builder
with the core's phase 2.

The branch takes the plan's crates from wallet-rs `flows` at `a307cca`. That head passes 49 of 49
merge gates: 248 tests passed, 0 failed, 13 ignored. Its 408 per-seed differential lines equal the
baseline's 384 apart from reading 25's key-rule classes, which I9 tallies apart; the 21 mismatch
lines all read 0.

### 10.2 The workspace after reorganisation

```text
siros-openid4vp       the core: a request in, a response built
├── siros-x509        x509_hash, x509_san_dns
├── siros-mdoc        mso_mdoc; B.2.6's handover; module DeviceMac; the stored mdoc's reading and registration
├── siros-sdjwt       dc+sd-jwt; the issued SD-JWT's reading, registration and selection
├── siros-paso        PaSO's transaction data; modules Paso, RandomIds, CoseEncrypt
│   └── siros-ts12    TS12 on PaSO's engine
├── siros-qes         CSC's QES transaction data
├── siros-credman     Credential Manager's entries for the matcher
├── siros-webuild     WE BUILD's CS-02 rules
└── siros-trust       issuer trust at registration: the store, issuer chains, the facts
siros-wallet-state    the private data container's wallet state S
siros-i18n            statements and their wording: Message, Context, Text
siros-syntax          checked!, Keyed, AllOf; the value types; the ISO 4217 table
siros-explain         the error contract: Explain, its derive and scope!
siros-cldr            the tool that writes CLDR's format options
siros-testkit         the core's test doubles
siros-integration     the HAIP and WE BUILD builds end to end
xtask                 the repository's build gates
siros-zkp-req         the colleague's: the zkp_req protocol
└── siros-zkp-catalogues   the colleague's: the nym_auth rulebook
wmp-core, engine-ports, engine-core, engine-adapter-sdk, engine-adapter-server,
engine-adapter-wasm, engine-conformance     the colleague's: the WMP engine
proving/              the colleague's: the proof backends and the browser presenter
```

**The plan's crates.** Their features are section 4.11's.

| Crate | From | Features | SIROS crates it names |
| :-- | :-- | :-- | :-- |
| siros-openid4vp | wallet-rs | `match`, `resolve`, `dc-api`, `uri`, `signed`, `request-decryption`, `cbor`, `transaction-data`, `sha3`, `blake2`, `k12`, `sri`, `claims` | siros-explain; siros-syntax; siros-i18n without default features, with `derive` |
| siros-x509 | wallet-rs | none | the core (`signed`); siros-explain; siros-syntax; siros-i18n |
| siros-mdoc | wallet-rs | `resolve`, `test-util` | the core (`claims`; `resolve`: `cbor`); siros-explain; siros-syntax |
| siros-sdjwt | wallet-rs | `resolve` | the core (`claims`); siros-explain; siros-syntax |
| siros-paso | wallet-rs | `resolve`, `sealed-signals`, `test-util` | the core (`transaction-data`, `sri`; `sealed-signals`: `cbor`); siros-explain; siros-syntax; siros-i18n with `derive`, `currency`, `date`; `resolve`: siros-x509 |
| siros-ts12 | new (section 4.10.2) | `resolve` | the core (`transaction-data`); siros-paso; siros-explain; siros-syntax; siros-i18n |
| siros-qes | wallet-rs | `resolve`, `sha3`, both default | the core (`sri`); siros-explain; siros-syntax; siros-i18n with `derive` |
| siros-credman | new (section 6, commit 9) | `register` | the core (`match`); siros-explain; siros-syntax; siros-i18n; `register`: siros-i18n with `nfc` |
| siros-webuild | new (section 6, commit 11) | | the core (`signed`, `uri`); siros-explain; siros-syntax |
| siros-trust | the base, carried over (section 10.3) | | the core (`match`, `resolve`): the `Facts` it writes, `Timestamp` |
| siros-wallet-state | the base, carried over | | none |
| siros-i18n | wallet-rs | `derive`, `check`, `number`, `currency`, `offset`, `date`, `nfc`, `conformance` | siros-explain; `currency`, `date`: siros-syntax; `derive`: siros-i18n-derive |
| siros-i18n-derive | new (section 4.14) | a proc-macro crate | siros-derive-internals |
| siros-syntax | new (section 4.13) | | siros-explain |
| siros-explain | wallet-rs | `derive`, `check` | `derive`: siros-explain-derive |
| siros-explain-derive | wallet-rs | a proc-macro crate | siros-derive-internals |
| siros-derive-internals | new (section 4.13) | | none |
| siros-cldr | wallet-rs, `publish = false` | | siros-explain; siros-syntax |
| siros-testkit | wallet-rs | | the core (`resolve`); siros-explain; siros-syntax; siros-i18n with `derive`, `number`, `currency`, `date` |
| siros-integration | wallet-rs, `publish = false` | | every crate, as dev-dependencies; siros-i18n with `derive`, `check` |
| xtask | new, `publish = false` (section 10.7) | | none |

**The colleague's crates.** Their design stays the colleague's.

| Crate | Features | SIROS crates it names after the branch |
| :-- | :-- | :-- |
| siros-zkp-req | `vp-token` | siros-openid4vp (`resolve`, `cbor`) |
| siros-zkp-catalogues | `credential`, `request`, `test-fixtures` | siros-openid4vp (`resolve`, `cbor`, `dc-api`, `uri`), siros-zkp-req, siros-mdoc, siros-trust |
| wmp-core, engine-ports | their own | none |
| engine-core | its own | engine-ports, wmp-core; from milestone 9, siros-openid4vp and the plug-ins its builds register: siros-x509, siros-sdjwt, siros-mdoc |
| engine-adapter-sdk, engine-adapter-server, engine-adapter-wasm, engine-conformance | their own | the engine crates |
| `proving/`: siros-zkp-backend-longfellow, siros-zkp-backend-vega, siros-zkp-req-wasm, e2e | their own | siros-openid4vp, siros-zkp-req, siros-zkp-catalogues, siros-trust |

The plan's crate table names siros-zkp-req as "zkp_req's existing format, until the zkp_req
proposal". In this repository that row is the colleague's two crates. wallet-rs's siros-zkp-req
moves to the differential harness (section 10.8): AGENTS.md forbids "a second copy of the
protocol", which the repository's siros-zkp-req holds. The zkp_req plug-in on the core's `Format`
traits comes with the zkp_req plan (Appendix A).

**Leaving:** siros-codec, siros-credential, siros-dcql, siros-display, siros-oid4vp,
siros-presentation, siros-transaction-data, and the base's siros-mdoc and siros-sdjwt, whose names
pass to the plan's crates. siros-matcher stays in siros-dc-matcher.

### 10.3 The superseded presentation crates

Each capability of the earlier port lands in one of the plan's crates, or the plan supersedes it
for the reason given. "Carried over" means the code moves from the base's crate into the named
crate, onto the core's types, with each test whose expected value has an external source.

**siros-codec** (1,643 lines)

| Capability | Lands in |
| :-- | :-- |
| `cbor`: `decode`, `decode_sequence`, `Item`, `Kind`, `CborError`, `Unsupported`; definite lengths, distinct keys, depth 32, `MAX_INPUT` | The core's `cbor`: one RFC 8949 item, keys distinct at every depth, depth 256, RFC 8949 §3's heads (section 4.9.4). RFC 8742's sequences leave with the earlier port, their only caller. |
| `cbor::Value::encode`: RFC 8949 §4.2.1's deterministic encoding | Carried over into the core's `cbor`, behind `cbor`. Its first caller is siros-zkp-req's presentation encoding (decision 9: "lands with its first caller"). |
| `json`: `Json::parse_unique`, `JsonNumber`, `JsonFault`, `ReadFault`, `JsonTextError` | The core's `json`: a repeated name refused at every level, number texts kept. |
| `base64url`, `base64`, `Base64Error` | The base64 crate, which each crate names (the owner's ruling against primitives crates). |
| `chain::CertificateChain` | siros-x509's `X5c` for the Verifier. For the issuer, the DER chain that siros-mdoc and siros-sdjwt read and siros-trust takes. |
| `date`: `Date`, `DateTime`, `is_leap` | siros-syntax's calendar types, `DateTime` with `leap`, for a shown value's literal form; the core's `Timestamp` for instants; siros-zkp-catalogues' own `date` module for the zkp crates (section 10.5). |
| `member::MemberFault`, `position!`, `text_value!` | Each crate's own errors and identifiers; the core's `ids` check by parsing. |
| `signature::Es256Signature`, `SignatureLength` | The core's `Signature`, the module's bytes (section 6, commit 3: `JwsSignature`). |
| `url::HttpsUrl` | The core's `rows::HttpsUrl` (section 4.9.3). |

**siros-dcql** (2,558 lines; section 10.6)

| Capability | Lands in |
| :-- | :-- |
| `query`: `DcqlQuery`, `CredentialQuery`, `ClaimsQuery`, `ClaimOption`, `CredentialSetQuery`, `Multiplicity`, `HolderBinding`, `SetRequirement`, `QueryError`, `QueryTextError` | The core's `request::dcql` (`Query`, `CredentialSet`, `SetNeed`, `Multiplicity`, `HolderBinding`, `DcqlRule`) and `claims` (§6.3's `claims` and `claim_sets`, `ClaimsError`). |
| `id`: `QueryId`, `ClaimId` | The core's `ids`. |
| `meta`: `CredentialFormat`, `DocType`, `Vct`, `CredentialRef` | The core's `FormatId`. `doctype_value` is siros-mdoc's, `vct_values` siros-sdjwt's: the format owns `meta` (ruling of 2026-10-31). |
| `authority`: `TrustedAuthorities`, `TrustedAuthority`, `AuthorityType`, `AuthorityValue` | The core's `request::TrustedAuthority`, `ids::AuthorityType`, `ids::AuthorityValue`. |
| `path`: `ClaimPath`, `PathComponent`, `resolve`, `resolve_json`, `mdoc_components`, `ClaimNode`, `Lookup` | The core's `claims` (§7.1, §7.2). |
| `eval`: `execute`, `select_claims`, `Credential`, `Policy`, `ExactFormat`, `CryptographicBinding` | Phase 1: `Accepted`, `Match`, the claims kit and each format's `FormatQuery`. |
| `combinations`, `result`: `Combination`, `Combinations`, `Dropped`, `Candidate`, `QueryMatch`, `Satisfaction`, `QueryResult` | The core's consent: `request::factor` and `matching::consent`. |
| The seven spec vectors | The core's `tests/data/spec_vectors`: the same seven files, byte for byte. |

**siros-sdjwt** (1,267 lines). The plan's siros-sdjwt writes the frozen model's stand-in. Its
disclosures carry salts digested from the claim's path. Its Key Binding JWT stays unserialised,
the signature's bytes held as text. Milestone 6 carries over the issued SD-JWT's processing.

| Capability | Lands in |
| :-- | :-- |
| `SdJwt::parse`, `process::MAX_DEPTH`, `ParseError` and its faults (S1: RFC 9901 §7.1: digests unique, every disclosure referenced, no reserved name, `_sd_alg` supported) | Carried over into siros-sdjwt's registration. It reads the issued SD-JWT, holds it as the `dc+sd-jwt` document, and builds the view from the processed claims. |
| `tree`: `Object`, `Claim`, `ClaimValue`, `Element`, `DisclosureId` (S2: issued array positions, withheld elements) | Carried over with S1. |
| `node::Node`, the pointer walk (Q4) | The core's `claims` pointer walk over the view, which keeps S2's positions. |
| `select` (S3: each node on a path with its parents and descendants) | Carried over: phase 2 selects the option's disclosures from the document. |
| `key_binding`: `Presentation`, `KeyBinding`, `NumericDate`, `Audience`, `KbNonce`, `BeforeEpoch`, `KeyBindingError` (S4) | Carried over; `NumericDate` comes from the core's `Timestamp`, which holds no time before the epoch, so `BeforeEpoch` goes. The Key Binding JWT holds `sd_hash` over the presentation as sent and its signature from `Haip::sign`, in compact serialization; `Presentation::text` carries it (§8.1). |
| `alg::Digest` | Carried over with S1. |
| `SdJwt::x5c` | The issuer chain siros-trust reads at registration. |
| RFC 9901's examples A.1 to A.4 and §5 (`tests/sd_jwt/rfc9901`) | Carried over as known answers. |

`Registered::of` holds SD-JWT VC's rules over S1: `typ` is `dc+sd-jwt`; no disclosure reveals a
registered claim or its sub-claims (`SelectivelyDisclosed(PermanentClaim)`); `cnf` is an object
whose `jwk` has its curve's `kty`, coordinate sizes and an `alg` the curve signs under, each breach
a `HolderKeyFault`; `nbf` and `exp` are finite. The view writes each number as the issuer did.
`Registered::holder` gives `Facts::holder`, and `PresentFault::Holder` refuses a credential whose
fact and document disagree. `SigningAlg` holds the `alg` of the Issuer-signed JWT and of the Key
Binding JWT: `none` and the MAC algorithms make no value.

A digest without its disclosure cannot be told from a decoy (RFC 9901 §4.2.5), so a withheld `exp`
is no `exp`: the view has no `validity`. Whether that is acceptable is the operating environment's
(RFC 9901 §7.1, §9.7), through `Platform::usable`.

`Resolved` holds `metadata: Option<Object>`, `issued: IssuedMetadata`,
`extends: Vec<CredentialType>` and `issuer_curve: Option<Curve>`. `Resolved::view_metadata` is the
view's `metadata`: the Type Metadata with OpenID4VCI's after it per language.
`type_metadata::extend` takes `&Object`. The closed names are types: `PermanentClaim`,
`ValidityClaim`, `JwkCoordinate`, `FixedSd` (`ExtendError::Sd.base`). `tree::Object` is a
`Distinct<Member>`. `SdJwt::values` gives a `Node`, `signing_alg` a `&SigningAlg`, and
`HolderBindingWaived.query` holds a `QueryId<'static>`. `SdJwt::{issuer_jwt, x5c, typ}` give
`IssuerJwt`, `DerCertificate` and `JwtType`. `KeyBinding::signing_input` gives a `KbSigningInput`,
`assemble` takes a `KbSignature` and gives an `SdJwtKb`, and `RegistrationError::IssuerCurve.curve`
is a `ResolvedCurve`.

The claims kit shows the view's `display` metadata as written (section 4.14).
`ClaimsFormat::withheld` names an array element that holds no value, `{"...": digest}` here, which a
claims path walks past at its position.

siros-testkit's `sd_jwt_issuer` writes a view as a compact SD-JWT. Its `sd_jwt_reading` reads a
presentation as a Verifier does (RFC 9901 §7.1, §7.2).

**siros-mdoc** (1,672 lines). siros-zkp-catalogues reads stored mdocs through this crate's
reader, so milestone 2 carries the reader over.

| Capability | Lands in |
| :-- | :-- |
| `Mdoc::parse` (M1): base64url of an IssuerSigned, a Document or a one-document DeviceResponse; the Document's `docType` equal to the MSO's; items matching `valueDigests`; `IssuerNameSpace`, `IssuerSignedItem`, `MdocError` and its faults | Carried over into siros-mdoc's registration, beside `IssuerSigned::read`, which reads the IssuerSigned form alone: the view and the `mso_mdoc` document come from any stored form. |
| `mso`: `Mso`, `Validity`, `DigestAlgorithm`, `ItemDigest` | Carried over. The view's `device_alg`, `device_curve`, `key_authorizations` and validity come from the MSO. |
| `issuer_auth::IssuerAuth`: `x5chain`, algorithm, Sig_structure | Carried over: the view's `issuer_alg` and `issuer_curve`; the chain for siros-trust. |
| `key_authorizations::KeyAuthorizations` (M3, B.2.1) | siros-mdoc's view (`key_authorizations`) and its placement of a profile's members. |
| `disclosure`: `Disclosure`, `ElementId`, `device_response` (M2) | siros-mdoc's `IssuerSigned::disclose` and its DeviceResponse. |
| `device`: `device_signing_input`, `DeviceNameSpaces`, `DeviceSignedElement` | siros-mdoc's `device_authentication`, made public for siros-zkp-catalogues; `DeviceNameSpacesBytes`. |
| `signature`: `SessionTranscript`, `SigStructure`, `MessageDigest`, `CoseAlgorithm` | siros-mdoc's `SessionTranscript` (section 6, commit 6) and coset's structures. |
| `device_key`: `P256Key`, `PointError` | The view's `device_alg` and `device_curve`; the key stays the platform's. |
| `es256::es256_verifies` (feature `crypto`) | The registration's issuer signature check, made with the app's crypto (section 4.3's credential registration row; HAIP §6.1.1); siros-zkp-catalogues' own check (section 10.5). |
| `names`: `DigestId`, `ElementIdentifier`, `NameSpace` | siros-mdoc's `issuer_signed`. |
| ISO/IEC 18013-5:2021 Annex D, D.4.1.2: the example DeviceResponse (`tests/vectors/annex_d_device_response.hex`) | Carried over as a known answer. It closes section 4.9.4's open Annex D item. |

`DeviceKey` holds a public `Curve` of Table 22 and the signature algorithm the key makes,
`algorithm() -> Option<SignatureAlgorithm>`: label 3, else the curve's. A label 3 of no signature
algorithm leaves the key signing nothing (RFC 9052 §7.1), as X25519 and X448 do (RFC 9053 §7.1), and
the view then has no `device_alg`. A label 3 of a signature algorithm its curve does not make is
`DeviceKeyFault::Algorithm`, which reaches registration as
`RegistrationError::Stored(MdocError::DeviceKey(..))`. `SignatureAlgorithm::made_on`, crate-private,
is the table: ES256, ES384 and ES512 hold on every EC2 curve, EdDSA on Ed25519 and Ed448 (RFC 9053
§2.2), and each fully-specified identifier on its own curve (RFC 9864 §2). RFC 9053 §2.1 names
P-256, P-384 and P-521; the brainpool curves rest on IANA's EC2 rows, which cite ISO/IEC
18013-5:2021 §9.1.5.2 (paywalled, unread), and on Multipaz's defaults. `DeviceKeyView`,
crate-private, applies the table in its `new`, so a view's read refuses the same pair with a
`Fault`.

A key that signs nothing authenticates by device MAC alone (ISO/IEC 18013-5 §9.1.3.5). `choose`
answers `DeviceAuthRefused::KeyAgreementOnly` when the Verifier holds no key on its curve, or when
`deviceauth_alg_values` lists neither the curve's MAC row nor 5. `cose::mac_row`
holds the nine rows of B.2.2's Table 2 by the device curve, and answers `None` on Ed25519 and Ed448.
A DeviceMac header's `alg` is `HMAC_256_256`, 5 (B.2.2's rule 1): `Constraint::also` and `choose`
admit it, and the exclusion clause leaves it out. `Handover::Redirect.response_uri` is a
`HandoverUri`.

`DeviceKey::p256` gives the point of a P-256 key; the view reads only the curve and the
algorithm of another. `registration::Registered` builds the view from a stored mdoc, with
`validityInfo`. `Resolved` holds `issued: IssuedMetadata`, `issuer: Option<IssuerName>` and
`issuer_curve: Option<Curve>`. `RegistrationError` is `Stored`, `Value`, `Metadata { cause }`,
`FullDate` or `Tdate`, the last two with the name space and the element.
`CertificateChain::new` is crate-private, and `first` and `certificates` give `DerCertificate`s.
`IssuerSigned` holds its `IssuedNameSpace`s, each a `NameSpace` and its `IssuedItem`s, the
IssuerAuth COSE_Sign1 and the `DocType` that `IssuerSigned::doctype` gives. `Disclosed` and
`IssuedError::{Twice, Missing, Differs}` name a `NameSpace` and an `ElementIdentifier`.
`IssuerAuth::signature` gives an `IssuerSignature`. `StoredMdoc.name_spaces`,
`IssuerNameSpace.items` and `KeyAuthorizations::data_elements` are `Distinct`, the last of
`DataElements { name_space, identifiers }`.

An mdoc's dates: tag 1004 holds RFC 8943's `full-date`, and tag 0 a `tdate` of
`YYYY-MM-DDThh:mm:ssZ` over years 0000 to 9999, a leap second refused
(`claims::kit::{full_date, tdate}`). `validityInfo` keeps 1970 to 9999 in `stored::mso::instant`.
The view's `values` keep the text as written, so matching, disclosure and `IssuedError::Differs`
read it. Another CBOR tag's content shows as RFC 8949 §6.1 converts it.

**siros-oid4vp** (5,926 lines)

| Capability | Lands in |
| :-- | :-- |
| `unverified`: `UnverifiedRequest`, `NoQuery`, `CompactFault`, `PayloadFault`, `diagnose` (P2) | `Received::dc_api` and `Envelope::parse` in the matcher's build. `diagnose`'s text is `Unreadable`'s message (decision 18). |
| `protocol::Protocol` | The DC API protocols of `arrival` (A.1). |
| `parameters`: `Nonce`, `State`, `ParameterFault`, `VerifierInfoRule` | `ids::Nonce` (N1) and the routing's `state` (P6). `verifier_info` passes as received to the trust service (reading 22). |
| `client_id`: `ClientId`, `ClientIdPrefix`, `ClientIdError` | `ids::ClientId` (U3), classified by its prefix over the registered `PrefixName`s. |
| `error_code::ErrorCode` | The open `ErrorCode` (section 6, commit 2). |
| `jws_rules::JwsRule`: JSON serialization signatures, the protected header, `alg`, `crit`, the signature's length, `typ` | The core's `jose` and `envelope` (U10, U16, §5's `typ`); A7 over `Haip::verifies`. |
| `request`: `TransactionDataItem`, `ResponseMode`, `RequestSignature`, `AttestationFormat` | `request::entry`, the registered modes, the envelope's signatures, `verifier_info` as received. |
| `handover`: `Handover`, `JwkThumbprint`, `ec_jwk_thumbprint`, `HandoverInvalid` | siros-mdoc: B.2.6's handover and `Thumbprint::of` (section 6, commit 6). |
| `semantic`: `SemanticIdentifier`, `Person`, `SemanticIdError` (ETSI TS 119 475 §5.1.3, §5.1.5) | siros-zkp-catalogues, its only user (section 10.5). |
| `intake`: `IntakeState`, `Effect`, `EffectResult`, `Step` (P1) | The typestate: `Fetch`, `Received`, `Envelope`, `Pending`, `Authenticated`. |
| `intake::dc_api` | `Received::dc_api`. |
| `intake::redirect`: parameters by value, `request` by value, `request_uri` | `Fetch::of` for `request_uri`. The core refuses parameters and `request` by value (HAIP §5.1; U18, U19). |
| `intake::reference`: `RequestUri`, `RequestUriMethod`, `WalletParameters`, `WalletMetadata`, `RequestObjectText` with its 256 KiB | `uri::Fetch`, `RequestPost` and `WalletMetadata` (§5.10). The size bound is the HTTP adapter's (Appendix B). |
| `intake::signature` (§5.9.3) | `Pending::authenticate` (A7, A8) over siros-x509's prefixes. |
| `intake::attestation` (`verifier_attestation`), `values::AttestationIssuer`, `values::TrustChain` (`openid_federation`), `decentralized_identifier` | Refused (A2, HAIP's width). A deployment registers a further prefix as a `ClientPrefix`. |
| `intake::trust`: `Trust`, `TrustSubject`, `KeyMaterial`, `Verdict`, `TrustAnswer` (H2) | AuthZEN's `Evaluation` and `Decision` (`effects::authzen`). |
| `intake::request` | `Request::parse`. |
| `intake::error::IntakeError` and its faults | `Unreadable`, `Unauthenticated`, `Refused`. |
| `values::WalletNonce` (P3) | Superseded: §5.10's POST carries `wallet_metadata` alone (decision 12: "wallet nonce seems unwarranted"). |
| `values::Origin`, `values::Kid` | `ids::Origin`; a key's `kid` through the JWE modes' key rule. |
| `verified`: `VerifiedRequest`, `VerifierView`, `Encryption`, `ContentEncryption`, `AccessCertificate`, `CertificateDer` | `Authenticated` and its `Verifier`; the JWE modes' key rule and `RouteKey`; siros-x509's `X5c`. |
| `x509`: the `x5c` chain, the leaf's P-256 key, its dNSName entries, the semantics identifier | siros-x509 (`chain`, `names`); the semantics identifier to siros-zkp-catalogues. |
| `jose`: ES256 JWS, P-256 JWKs | The core's `jose`; `Haip::verify`. |
| `response::jwe` (`concat_kdf`; ECDH-ES with A128GCM and A256GCM), `response::aead` (`ContentKey`) | `Haip::encrypt_jwe`: the cryptography is the host module's (decision 13). The engine implements it over jose-rs (section 10.4). |
| `response::cose` (`cose_kdf`, `direct_post.cwt`'s `COSE_Encrypt`) | Deferred with zkp_req (Appendix A, decision 14). |
| `response::vp_token`: `Presentation`, `VpToken`, `VpTokenJson`, `Presentation::cbor_map` | `AuthorizationResponse`, `Presentation::text` and `Presentation::object`. The CBOR Authorization Response is deferred with zkp_req. |
| `response::submission`: `Submission`, `Post`, `PostParameters`, `PostBody`, `DcApiData`, `ResponseParameters`, `Outcome`, `Jwe` (P4) | `Delivery`, the modes' `Body`, `DcApiData`, `PostBody`. |
| Error submissions (P5) | The recourse: `ErrorRoute` and its `Delivery` (section 4.5). |
| `response::reply`: `Reply`, `RedirectUri`, 64 KiB (P6) | `ResponseUriAnswer` and its `AnswerReader`s. The size bound is the HTTP adapter's. |
| `form::FormBody` | `uri::form::FormBody` over serde_urlencoded. |
| `bound::TooLarge` | The HTTP adapter's bounds (Appendix B). |

**siros-trust** (2,092 lines) stays a crate under the plan. It computes, at registration and on
the wallet's machine, which Trusted Authorities admit a credential's issuer: the `Facts` the core
matches. The repository's own rule keeps that resolution local (AGENTS.md: "The presentation core
resolves `trusted_authorities` locally (TR1–TR5)").

| Capability | Lands in |
| :-- | :-- |
| `TrustStore`, `StoreEntry`, `StoreError`, `EntryError`, `Unanchored` (TR1) | siros-trust; the core's `json` reads the store's record. |
| `IssuerChain`, `Certificate`, `CertificateError`, `DistinguishedName`, `ChainError`, the positions (TR2) | siros-trust, over the DER chain siros-mdoc and siros-sdjwt read, with the workspace's x509-cert and der. `Certificate::{p256_key, p384_key}` give `Option<P256Point>` and `Option<P384Point>`. |
| `validate_path`, `OnPath`, `PathRefusal`, `extensions` (TR3's RFC 5280 rules) | siros-trust. |
| `IssuerFacts::at` (TR5) | siros-trust. `IssuerFacts::facts(holder)` writes the core's `Facts` through `Facts::of(holder, (type, value) pairs)`: one `HeldAuthority` for `aki`, with the chain's keyIdentifiers in base64url, and one per admitting store type with its values. `holder` is the wallet's. |
| `Admission`, `Issuer`, `Ground`, `Refusal`, `FactRefusal` | The core's rule over `Facts`, which the matcher and phase 2 both run. The rule moves to `Facts::admits(&Query)` in the core's `wallet`, and `Credential::trusted_for` calls it. |
| `QueryAuthorities::of`, `Authority`, `AkiError`, `AuthorityError` | Read from the core's `Query` and its parsed `trusted_authorities`. `AuthorityType::of` and `AuthorityValue::of`, infallible, make the values the facts hold. |
| `KeyIdentifier`, `StoreType`, `StoreAuthority` | siros-trust: the certificate's AuthorityKeyIdentifier and the store's entries (TR1). |
| `AdmittedIssuer::resolve`, `ChainRefusal`, `Unadmitted` | siros-trust, for siros-zkp-catalogues' N3. `resolve` takes the `&Query`, computes the chain's facts and asks the core's rule. After a refusal, `Unadmitted` holds one `ChainRefusal` per value of the query. |
| TR3's refusal of a malformed `aki` value | Superseded: OpenID4VP §6.1.1 states the value's form alone, and a malformed value equals no registered value. |
| The `chain` feature | Folded into the crate: the matcher reads registered facts, and the registration alone links siros-trust. |
| ISO/IEC 18013-5 Annex D's Document Signer (`annex_d_document_signer.der`) | Carried over as a known answer. |

**siros-wallet-state** (811 lines) stays a crate under the plan. It reads the SIROS private data
specification 3.1: a deployment's format, which decision 20 keeps out of the core. It names no
SIROS crate.

| Capability | Lands in |
| :-- | :-- |
| `WalletState::parse` (W1: `schemaVersion` 3 or 4, absent meaning 1) | siros-wallet-state. A crate-private `Members` reads each object the crate reads, and refuses a repeated name. A metadata value and an unknown member hold repeated names verbatim, as §6 preserves them. |
| `CredentialEntry`, `CredentialData`, `MetadataEntry`, `MetadataType`, `MetadataValue`, the identifiers (W2) | siros-wallet-state. `CredentialEntry::format` is `Option<FormatIdentifier>`, and an empty text reads as unknown. |
| `credentials`, `presentations`, `key_ids` (W3) | siros-wallet-state. |
| `PresentationRecord` (W4: `new_presentation`'s members) | siros-wallet-state; the app fills it from `Built`: `used()` under the state's credential numbers, `audience()` and the `vp_token`. `new` takes `PresentationData` and `Audience`, and `parse` reads through `Members`. |
| Its errors over siros-codec's JSON errors | Its own errors with stable codes, over serde_json. |

**siros-credential** (1,779 lines)

| Capability | Lands in |
| :-- | :-- |
| `Credential::parse`, `Parsed`, `Format`, `CredentialType`, `EntryRef` (C1) | siros-mdoc's and siros-sdjwt's registration (milestone 6), and siros-trust for the chain. |
| `TypedValue`, `Array`, `Object`, `Elements`, `Members` (C2) | The view's JSON values, the claims kit's; mdoc's through the core's `cbor::to_json` (RFC 8949 §6.1). |
| `ClaimSource`, the pointer resolution (C3) | The core's `claims`. |
| `UsableCredential::at`, `Validity`, `ValidityError` (C4) | The views' validity members, carried into the formats' registration: the MSO's `validityInfo`, the issuer JWT's `nbf` and `exp`. An app's `Platform::usable` reads them beside the credential's status. |
| `least_used`, `Instance` (C5) | siros-wallet-state, which holds the presentation records it counts: per batch, the instance the fewest records name, a record naming it twice counting once, the lowest `instanceId` on a tie. |
| `ClaimTree`: `of`, `claims`, `to_cbor`, `from_cbor` (K1's projection) | Superseded: the matcher reads the same registration through the same core (owner, 2026-10-31: one code path inside and outside the DC API). The registration's bytes are siros-matcher's. |
| `sd_jwt_vc`: SD-JWT VC's rules over the stored SD-JWT | siros-sdjwt, with S1. |
| `holder_key`, `HolderKeyError`, `RegisteredClaim`, `ClaimFault`, `CborTag`, `Coordinate`, `CoordinateFault` | The view's `key_alg` and `key_curve`; `Facts::holder`; the formats' readers. |
| `auxiliary_data` | Left out of every registration's metadata (D1). The view's `values` keep a claim of that name as the credential signs it. |

**siros-display** (2,780 lines)

| Capability | Lands in |
| :-- | :-- |
| `IssuerMetadata::merge`, with `auxiliary_data` removed before any merge (D1) | Carried over into the claims kit's metadata merge, which both claims formats' registration calls. `merge_metadata` strips the member at every depth of the format's document, the configuration, the response and the Credential Issuer's display, and refuses a configuration holding it as its own member (`AuxiliaryDataPublished`). The literal stays in the claims kit as a rule of issued metadata. |
| `lookup`, `Locale`, `Localized`, `LocaleError` (D2) | The claims kit's `format_entry` (RFC 4647 Lookup, then filtering, then the entry without a locale; section 4.14) and siros-i18n's `LocaleTag`. |
| `DisplayCache::card`, `DisplayCache::claim_rows` (D3: the format's display first, OpenID4VCI `credential_metadata` per language after it) | Carried over into the claims kit's merge (`IssuedMetadata`), one list under Lookup (section 4.14). `IssuedMetadata::issuer_display_member` writes the view's `issuer_display`, beside `metadata`. |
| `DisplayValue` (D4) | The claims kit's rows, each value a `ClaimText` that carries its literal text (section 4.14). An mdoc's `full-date` and `tdate` elements (ISO/IEC 18013-5 §7.2.1) are `ClaimText::Date` and `ClaimText::DateTime`: the registration refuses a value under those tags that siros-syntax's `Date::parse` or `DateTime::parse` refuses, and the view's `dates`, `{"path", "date"}` beside `values`, states each one's path. An SD-JWT's JSON strings carry no type and show as written. |
| `DisplayValue::Bytes`, shown by its length (D5) | Carried over into the claims kit's rows (`ClaimText::Bytes`), with the mdoc view's `byte_strings`. `RegistrationError::Metadata` holds `{ cause: MergeError }` in both formats. |
| `DisplayText`, `text::unsafe_ranges`: the characters of Cc, Cf, Zl, Zp, Co and Cn refused; `LABEL_MAX`, `VALUE_MAX`, `TEMPLATE_MAX`, `CARD_TEXT_MAX` | The rule carries over into the core's `text`: `DisplayText` reads each character's category through icu_properties' `CodePointMapData::<GeneralCategory>`. The claims kit reads every metadata text through it, in every language: under the view's `metadata`, `name`, `alt_text` and the format's label as labels and `description` as a value, then the view's `issuer` and a member name standing in for a label. A refused text excludes the credential for the query (`FormatQuery::displayable`, `ExcludedBy::Display`); a label with no visible character (neither White_Space nor Default_Ignorable_Code_Point) takes the kit's fallback label (`TextError::Empty`). A title and a subtitle read through `label`. `DisplayText::card` and `DisplayText::template` hold the limits of a wallet's own card text and issuer template. A claim's value shows as written. siros-paso keeps PaSO's label rule (Proof Metadata §3.3) and refuses a label with no visible character (`LabelViolation::Invisible`). |
| `Card`, `CardWording`, `CardText`, `LabelText`, `IssuerTemplate`, `ClaimRow`, `ClaimLabels`, `DescribedLabel` | The consent entry's `Card` and `Row` (section 4.2), and the claims kit's card and rows. |
| `Field`, `FieldText`, `FieldName`, `Extent`, `FIELD_MAX` (A9's clipped fields) | siros-credman, with A9 (siros-presentation's table). |
| `Colour` | Superseded: section 4.2's `Card` holds an icon, a title, a subtitle and rows. The colours stay in the view's `metadata` for the app's layout. |
| `Logo`, `LogoUri`, `Integrity` | The core's `rows::env::Icon` and `sri`. |
| `IssuerMetadata`, `TypeMetadata` | The view's `metadata`; siros-sdjwt's `type_metadata::extend`. |
| `DisplayCache` | Superseded: each registration carries its credential's metadata. |
| `purpose::line`, `purpose::display` | Superseded: OpenID4VP 1.0's Credential Set Query holds `options` and `required` (§6.2). |
| `proof::rows`, `proof::verified_rows` | Deferred with zkp_req (Appendix A). |

**siros-transaction-data** (10,378 lines)

| Capability | Lands in |
| :-- | :-- |
| `Entry::parse` (T1) | The core's `request::entry` (C0) and siros-paso's `entry`. |
| `check_request`: PaSO entries in signed requests (Core §3); one credential set, transposable (Core §7.4.1) | siros-paso's `entry` and `rules`. |
| `Definition`, `ClaimDefinition`, `UiLabels`, `LabelText`, `ValueType`, `LabelRules` (Proof Metadata §3, §3.3; TS12 §3.3.3) | siros-paso's `metadata` and `labels`; siros-ts12's limits. |
| `sources`: the signed credential metadata JWT, the ad-hoc metadata JWT, TS12 type metadata, `HeldMetadata`, `HeldDocument`, `HeldJwt::admit`, `HeldMetadata::wanted`, `Renewal`, issuer key sets, ES256 and ES384 JWS | siros-paso's `document` and `adhoc`; siros-ts12's `Ts12Document::compose`; `ProfileHost::wanted`. Holding and renewing the metadata is the caller's (Proof Metadata §6, §8). |
| `Configuration::parse` (T2's host configuration) | Superseded: siros-paso binds a type through the credential's own metadata or the entry's (Proof Metadata §4, §5), and siros-ts12 through the type metadata (TS12 §4.1). A deployment adds a type as a profile. |
| `Definition::project`, `Projected`, `ProjectionError`, `Unmatched` (T3) | siros-paso's `view::convert`, which writes the entries View §4 selects as MF2 source under the context's locale (section 4.14). |
| `PayloadFault`, `Scalar`, the conformance of Core §7.4.2 | siros-paso's `conform`. |
| `Image`, `ImageRef`, `Channel`, `ImageFault` (T6) | siros-paso's `image`; over the DC API, the core's `Icon`. |
| `TransactionView`, `Segment`, `RenderFault`, `MAX_ITEMS` (T5) | siros-paso's `render` and `template`. |
| `Selector::first_match`, `first_match_unverified`, `Definitions`, `Context`, `Selection`, `Taken`, `Exclusion`, `Incompatibility`, `Deferral` (T4, K2) | siros-paso's first match and `outcome`; the matcher runs the same code. |
| `ServedTypes`, `Unserved`, `TypeRepeated`, `SourceInputs` (K1) | Superseded: the registration holds the documents, and phase 1 binds over them in the matcher and the wallet alike. |
| `Binding::kb_jwt_claims`, `Jti`, `KbJwtInputs`, `HashAlg`, `AlgClaim`, `HashesAlgFault` (T7) | The core's `txhash` (B.3.3.1); siros-paso's `respond` and `sca`; siros-ts12's `jti`, `response_mode` and `amr`. |
| `Amr`, `AmrCategories`, `Factor`, `Inherence`, `Knowledge`, `Possession` | The core's `host::authentication`; siros-paso's `amr` and `BiometricClass`. |
| `Payment`, `PaymentAmount`, `CurrencyCode`, `Integrity`, `IntegrityFault` | siros-paso's Payment rulebook; siros-syntax's ISO 4217 table; the core's `sri`. |
| `ts12`: payment, login_risk_transaction, account_access, emandate; `Ts12PayloadFault`, `MemberPath` | siros-ts12: payment and login_risk_transaction (CS-12 §7.1 item 1). T4 refuses account_access and emandate (section 4.10.2). |
| `TypeId`, `TypeFamily`, `Ts12Type`, `EmptyTypeId` | The registry's type prefixes, `urn:paso:sca:` and `urn:eudi:sca:`. |
| `definition::grapheme` with its generated table | siros-paso, over unicode-segmentation. |
| TS12's schemas as the payload parsers' oracle (jsonschema) | I20's one-off run. |

**siros-presentation** (6,690 lines)

| Capability | Lands in |
| :-- | :-- |
| `Matching::new` over `MatchCredential` (A1: the format table, `meta`, holder binding, usable credentials), `Failure`, `KeyHolding` | The registry's formats, the claims kit, `Facts::holder`, `Platform::usable`; `Refused` and `NoCandidate`. |
| A1's rule that only `zkp_req` discloses a nym_auth attribute; `ZkpQuery`, `Matching::answer` (A2) | Deferred with zkp_req (Appendix A). |
| `Offers`, `Offer`, `Member`, `Addition`, `Selection`, `Subset`, `MAX_OFFERS`, `MAX_ADDITIONS`, `MAX_EXAMINED` (A3) | The core's consent, its slots and options, and `matching::offer`. |
| `Transactions`, `BoundEntry`, `RequestEntries`, `TransactionSource`, `NoOffer` (T4) | Each profile's binding; the core's C3 and C4. |
| `ConsentView::digest`, `PlanDigest`, `Planned::choose`, `Chosen` (A4) | The records (`matching::record`), which commit to the request's digest. Phase 2 derives them again with the matcher's code. |
| `Chosen::prepare`, `Sign`, `Prepared::finish` (A5) | `Haip::sign`. |
| The SD-JWT `aud` (A6); the SessionTranscript (A7) | The session's audience (KA18); siros-mdoc. |
| One `vp_token`, `access_denied` on a decline, the record of the instances used (A8) | `AuthorizationResponse`; the recourse's `access_denied`; siros-wallet-state's `PresentationRecord`. |
| `WalletDisplay::of`, `Fulfilment` (A9), `WalletDisplayNeeded`, and the picker's delegation (K4) | Carried over into siros-credman. `Fulfilment::check` and `SetFacts::of` read a field's length through a text function, and `Fulfilment::check` refuses a background fulfilment of a set that needs the wallet's display with `WalletDisplayNeeded`, whose `code` is `access_denied`. A Credential Manager set takes `Full` delegation when its entries need no wallet display, read from the consent entries and the credentials the app declares presentable in the background. |
| `Pick`, `PickFault`, `Planned::picked` (K3) | `matching::display`, which reads the ids Credential Manager returns, and `Prepared::prepare`. |
| `NymAuthRequest` from `PlanInput::verifier_id` (N2) | Deferred with zkp_req. |
| `MatchRequest`, `Inconsistency`, the index types | The core's `Request`, `RecordError` and `SelectionError`. |
| `testing`: the verifier, the wallet, the host, PaSO | siros-testkit. |

**What the plan's crates gain**, each in its milestone (section 10.9):

1. siros-mdoc: the stored mdoc's reader and the device signing input as public API (milestone 2);
   the view from a stored mdoc, with its validity (milestone 6).
2. The core's `cbor`: RFC 8949 §4.2.1's deterministic encoder (milestone 2).
3. siros-sdjwt: the issued SD-JWT (S1 to S4), its `dc+sd-jwt` document and its view with
   validity, in place of the stand-in presentation (milestone 6).
4. The claims kit: the metadata merge (D1, D3), D5, and the core's `DisplayText` rule
   (milestone 7).
5. siros-trust: the core's types (milestone 2); `Facts` from the chain and the store, and the
   rule's move to `Facts::admits` (milestone 7).
6. siros-wallet-state: its own errors (milestone 2); C5 (milestone 7).
7. siros-credman: A9 and K4 (milestone 3, section 6's commit 9).
8. The known answers: ISO/IEC 18013-5 Annex D's DeviceResponse and Document Signer, RFC 9901
   A.1 to A.4 and §5, and the private data specification's fixtures and vectors.

The app composes a registration from these pieces, as section 4.3's credential registration row
assigns it. Each rule a registration applies has one implementation, in the crate named above.

### 10.4 The engine and the core

The engine performs the core's effects: HTTP, the PDP's AuthZEN evaluations, storage, keys. It
keeps its runtime, its ports and its transport. engine-core's `oid4vp` module at `bfd5670` (3,911
lines in 9 files) holds a second OpenID4VP implementation. It checks a signed Request Object's
`typ` and verifies its signature under the key of the first `x5c` certificate when the header
carries one; a Request Object without `x5c` passes unverified, and no step binds the key to the
`client_id`. It hands the PDP the `client_id` with `client_metadata`'s `jwks`. Each function or
type below holds an OpenID4VP rule, and each gives way to a core call (gate R5 counts their
names):

| engine-core `oid4vp` at `bfd5670` | The rule it holds | The core call | The engine's part |
| :-- | :-- | :-- | :-- |
| `request::parse_request` (`request.rs:30`), `fetch_request_object` (`:126`; 256 KiB, `MAX_REQUEST_OBJECT_BYTES`) | By value, by `request`, by `request_uri` with `Accept: application/oauth-authz-req+jwt, application/json` | `Fetch::of` over `AuthorizationUri::parse`, `Fetch::request`, `Fetch::resume`, giving `Received`; `Envelope::parse`; `Request::parse`. Parameters by value and `request` by value are refused (HAIP §5.1; U18, U19) | The GET or POST over `HttpClient` with its fetch policy: https, the 256 KiB bound, no redirects, the timeout (HTTP-U1, Appendix B) |
| `request::url_to_params` (`request.rs:62`), `trust::resolve_request_uri` (`trust.rs:352`), `trust::query_param` (`:389`) | The URL forms: `openid4vp://`, `haip://`, `haip-vp://`, `mdoc-openid4vp://`, a raw query, a bare reference; the outer `request_uri` | `AuthorizationUri::parse` reads the query of the URI the engine hands over | The schemes its host registers (section 4.1: the caller's) |
| `request::parse_request_object` (`request.rs:166`) | A compact JWS or plain JSON; `typ` `oauth-authz-req+jwt`; the signature under the `x5c` leaf's key when present | `CompactJws::parse` (U10, U12), `Envelope::questions` and `Pending::authenticate`: the signature verified under the key the prefix bound (A7, A8) | |
| `request::parse_request_value` (`request.rs:217`) | `client_id_scheme` against the prefix; an unknown prefix refused; `nonce` required; `response_mode` defaulting to `direct_post`; a `response_uri` or `redirect_uri` required; `direct_post` and `direct_post.jwt` with a `response_uri` and no `redirect_uri` | The classification by prefix (§5.9.1), A2; N1; C5 over the registered modes; P5; `ResponseUri::parse` (A13) | |
| `types::ClientIdScheme` (`types.rs:9`, from engine-ports), `ResponseMode` (`:13`), `AuthorizationRequest` (`:48`), `RequestError` (`:92`), `TransactionData` (`:145`), `TransactionDataError` (`:159`), `KNOWN_TRANSACTION_DATA_TYPES` (`:188`), `ResponseError` (`:194`); `dcql::DcqlError` (`dcql.rs:13`), `jarm::JarmError` (`jarm.rs:43`), `trust::TrustError` (`trust.rs:66`) | The request's model, its default mode, its allow-listed transaction data types, its errors | `PrefixName` and the registered prefixes, `ModeName`, `Envelope` and `Request`, `request::Entry`, `Unreadable`, `Refused`, `Outcome` | |
| `trust::resolve_client_metadata` (`trust.rs:150`), `fetch_client_metadata` (`:113`; `client_metadata_uri`, 1 MiB, `MAX_CLIENT_METADATA_BYTES` `:15`), `ClientMetadata` (`:20`) | Metadata by reference | The envelope reads `client_metadata` (C6), which OpenID4VP 1.0 carries by value (§5.1) | |
| `trust::build_verifier_info` (`trust.rs:169`), `extract_domain` (`:247`) | The Verifier's name and domain per scheme | `Authenticated::verifier()`: its name, facts and metadata; the consent entry | The WMP `VerifierInfo` its host shows, filled from `Verifier` |
| `trust::evaluate_verifier_trust` (`trust.rs:202`) | The PDP's verdict, failing closed | `Envelope::questions`, then `Pending::authenticate`, which checks A7 to A13 under the bound key through `Haip::verify` | Each evaluation through `Pdp::evaluate`, failing closed |
| `trust::validate_client_id_match` (`trust.rs:285`) | The outer and inner `client_id` equal (RFC 9101 §5.2) | U14 in `Envelope::parse` | |
| `trust::validate_response_uri_origin` (`trust.rs:313`), `scheme_and_host` (`:369`) | `x509_san_dns`'s `response_uri` host | siros-x509's `x509_san_dns` host rule (A12) | |
| `jarm::build_jarm_claims` (`jarm.rs:95`), `SELF_ISSUED_ISS` (`:36`) | The JWE's plaintext: `vp_token` and `state` | The `direct_post.jwt` mode's body: the Authorization Response as the JWE's plaintext (§8.3) | |
| `jarm::select_verifier_jwk` (`jarm.rs:135`), `resolve_algorithms` (`:176`), `map_key_algorithm` (`:66`), `map_content_encryption` (`:79`), `DEFAULT_CONTENT_ENCRYPTION` (`:39`) | The key: `use` `enc` first, then any, the first whose algorithms resolve; `alg` and `enc` from `authorization_encrypted_response_*`, else the first of `encrypted_response_*_values_supported`, else the JWK's `alg` or the key's type, A128GCM by default | The JWE modes' key rule (C7): a P-256 ECDH-ES key with its `alg`; the first `enc` of the sealing statement the Verifier lists, A128GCM when it lists none (`VerifierMetadata::lists`) | |
| `jarm::encrypt_jarm_response` (`jarm.rs:253`), `submit_jarm_response` (`:286`) | The JWE through jose-rs, `cty` `json`; `response=` POSTed; the reply's redirect | The core's sealing to the route's `RouteKey` through `Haip::encrypt_jwe`; the mode's form | `Haip`'s implementation over jose-rs and kryptering; the POST |
| `jarm::verifier_jwk_thumbprint` (`jarm.rs:119`) | The thumbprint for the session transcript | siros-mdoc's `Thumbprint::of` over the session's binding facts | |
| `response::submit_response` (`response.rs:23`), `submit_direct_post` (`:105`), `build_fragment_redirect` (`:145`), `build_query_redirect` (`:158`), `url_encode` (`:168`) | `direct_post`, `direct_post.jwt`, `fragment`, `query`: `vp_token` and `state` | `Built::delivery()`: the mode's body to the route's `response_uri`; the forms through `FormBody::of`. C5 refuses `fragment` and `query`, which no build registers | The POST over `HttpClient`: no redirects, the 64 KiB reply bound (`MAX_REPLY_BYTES`) |
| `response::submit_error_response` (`response.rs:57`) | The decline: `access_denied` with a description | The error's `ErrorRoute` and `Delivery`: `access_denied` in the errors' form | The POST |
| `Oid4vpFlow::start_flow` (`mod.rs:37`): the reply's `redirect_uri` (`:308`) | A plain answer's `redirect_uri` member, or the JWE answer's location, opened in the End-User's browser | `ResponseUriAnswer::parse`, then `redirect()` | Following it through its host's `open_authorization` |
| `dcql::validate_raw_query` (`dcql.rs:32`) | `dcql_query` is JSON | The DCQL reader in `Request::parse` | |
| `dcql::unsatisfied_required_queries` (`dcql.rs:53`), `Oid4vpFlow::start_flow` (`mod.rs:164`) | A required Credential Query or Credential Set the selection leaves unanswered: `access_denied`, no `vp_token` (§6.2, §6.4.2) | Phase 1's `Accepted` and the consent's sets; `Prepared::prepare`'s `Rejection`; the unmet request's `access_denied` (`UnmetCode`) | |
| `dcql::build_dcql_vp_token` (`dcql.rs:142`) | The VP Token keyed by query id | Phase 2's `AuthorizationResponse`, keyed by query id | |
| `dcql::requested_credential_types` (`dcql.rs:184`) | The credential types a query names | Phase 1's `Refused` and `NoCandidate`, as messages (decision 18) | The progress event, carrying the core's message |
| `dcql::sanitize_endpoint_url` (`dcql.rs:251`) | An https or http endpoint rebuilt from its parts | `ResponseUri::parse`: an absolute https URI with a host (A13) | Its address policy: public addresses alone (HTTP-U1) |
| `transaction_data::validate_transaction_data` (`transaction_data.rs:18`), `reject_null` (`:89`) | base64url JSON entries, `type` allow-listed, `credential_ids` naming queries, `null` refused | C0; C1, a type no registered profile answers; C2 | |
| The host's `request_match` and `request_vp` (`mod.rs:263`) | Matching and the presentation in the host | Phase 1 (`Accepted`, the consent) and phase 2 (`Prepared::respond`) | The registrations its host holds, the consent's display, `Haip::sign` through `request_sign`, `Platform` |
| `Oid4vpFlow` (`mod.rs:25`) | | | The `FlowHandler`, its progress events and its sub-flows, over the core's steps |
| `request::percent_decode` (`request.rs:93`), `decode_base64` (`:370`), `decode_base64url` (`:401`); `trust::percent_decode` (`trust.rs:402`); `transaction_data::decode_base64url` (`transaction_data.rs:97`); `test_util`'s base64url and percent decoding | The encodings of the request's parameters: percent-encoding (RFC 3986 §2.1), base64 and base64url (RFC 4648 §4, §5) | The base64 crate; serde_urlencoded in `AuthorizationUri::parse`; the core's `FormBody` | |

The engine implements the core's modules over its ports. `Platform::now` reads the `Clock` port;
`usable` and `authenticate` ask its host. `Haip` verifies and encrypts over
jose-rs and kryptering and signs through the host's `request_sign`.

**engine-ports.** Its contracts follow the core:

| Port | Change |
| :-- | :-- |
| `Pdp::evaluate(EvaluationRequest { subject, key_material, resource_type })` | It takes the core's `Evaluation`, AuthZEN's subject, action, resource and context. It returns the `Decision` with the decision's context: `name`, `facts`, `endpoints`. |
| `ClientIdScheme` | It leaves: the core classifies the `client_id`. |
| `VerifierInfo` | Filled from `Verifier`. |
| `Host::request_match`, `MatchParams`, `MatchResult`, `VpSelection` | The host supplies the core's `Wallet` and the wallet's `Context`, and shows its consent entries; the chosen ids come back. |
| `Host::request_consent`, `ConsentParams` | It carries the consent entries and their resolved `Text`s (decision 21). |
| `Host::request_vp`, `VpParams`, `VpResult` | It leaves: phase 2 builds the presentations. |
| `Host::request_sign` | It answers `Haip::sign` for the credential's key. |

engine-adapter-sdk, engine-adapter-server, engine-adapter-wasm and engine-conformance implement
the changed ports, and `bindings/` regenerates.

**Where each phase runs.** Phase 1 and phase 2 run where the credentials and the keys are. The
in-process engines run them: engine-adapter-sdk in the native SDKs, engine-adapter-wasm in the
browser. The container engine's client holds the credentials and the keys. That client replays
the arrival and the authentication from the `Received` and the decisions the engine sends (I5:
the same inputs give the same outputs). It runs phase 1 and phase 2 with the same core and hands
back the `Delivery`. The engine posts it.

**Synchronous modules over asynchronous ports.** The core's host modules return synchronously,
and the engine's ports are async. The native engines run the core's steps on a blocking worker,
whose module implementations wait on the ports. The browser engine runs on one thread, so its
modules answer from data it holds. Its `Haip::sign` signs with a key in WASM memory, as the mini
host's kryptering signer does. Its `Platform::authenticate` returns the authentication the page
completed before `respond`. The page needs the authentication's strength first: `Prepared` states
it (`Prepared::need`, a method this section adds). A key that only an asynchronous browser API
reaches, WebCrypto or WebAuthn, needs signing as an effect. Decision 13 keeps signing in `Haip`,
so that trade is the owner's.

**Its vectors and documents.** engine-vectors holds 4 presentation scenarios that encode the Go
engine's behaviour: `vp.decline.plain-post.001`, `vp.jarm.enc-default.001`,
`vp.jarm.refusal-not-sent.001` and `vp.presentation.basic.001`. engine-conformance's runner loads
them in CI, so that repository records each one anew against the core's width.
`docs/engine-spec.md`'s OpenID4VP rows and its conformance matrix's OpenID4VP dimensions take the
core's width: HAIP 1.0 with WE BUILD's profile, further prefixes and modes as plug-ins.
`docs/oidf-conformance.md`'s phase 2 builds the VP through the core, with the mini host supplying
`Haip` and the registrations. `docs/DEPENDENCIES.md`'s table of what the presentation crates give
the engine names the plan's crates.

engine-core's `oid4vci` stores each credential as its issuer returns it. A stored credential
reaches the core through section 10.3's registration.

### 10.5 The zkp_req crates

siros-zkp-req and siros-zkp-catalogues change where the removed crates' APIs leave them. Each API
maps onto the plan's crates:

| Removed API | Used in | Replacement |
| :-- | :-- | :-- |
| `siros_codec::cbor::{decode, Item, Kind, Value, CborError}` | siros-zkp-req `presentation`, `structure`; siros-zkp-catalogues `mdoc`, `verify`, `presenter`; proving `e2e` | The core's `cbor::decode` over ciborium's `Value` |
| `siros_codec::cbor::Value::encode` | siros-zkp-req `presentation`; siros-zkp-catalogues `presenter` | The core's deterministic encoder (section 10.3) |
| `siros_codec::json::{Json, JsonFault}` | siros-zkp-req `vp_token` | The core's `json::Node` |
| `siros_codec::{base64url, Base64Error}` | siros-zkp-req; siros-zkp-catalogues' tests | The base64 crate |
| `siros_codec::date::{Date, DateTime, is_leap}` | siros-zkp-catalogues `age`, `pair`, `system`, `catalogue`, `attestation`, `prover`, `mdoc`, `verify`; proving's two backends and `e2e` | siros-zkp-catalogues' own `date` module, moved from siros-codec: its users are siros-zkp-catalogues and the crates built on it |
| `siros_codec::member::{MemberFault, ArrayIndex}`, `position!`, `text_value!` | siros-zkp-req `json`, `outcome`, `formats`, `query`, `ids` | siros-zkp-req's own, moved from siros-codec |
| `siros_codec::signature::Es256Signature` | siros-zkp-catalogues `prover`, `mdoc`, `presenter` | The core's `host::Signature` |
| `siros_codec::chain::CertificateChain` | siros-zkp-catalogues' tests | The DER chain siros-mdoc's reader gives |
| `siros_dcql::{CredentialQuery, QueryError, QueryId, QueryIdError, Multiplicity, HolderBinding, CredentialFormat}` | siros-zkp-req `query`, `ids`, `vp_token`; siros-zkp-catalogues `verify`, `catalogue`; proving `siros-zkp-req-wasm` | The core's `request::{Query, Multiplicity, HolderBinding, DcqlRule}` and `ids::{QueryId, FormatId}`. `ZkpReqQuery::parse` reads the core's `Query`: the protocol's members parsed, the object whole. |
| `siros_dcql::{DocType, Vct}` | siros-zkp-req; siros-zkp-catalogues | The query's `meta`, which the format reads |
| `siros_oid4vp::{VerifiedRequest, Verdict}` | siros-zkp-catalogues `request`, `testing` | `Authenticated` and its `Verifier` |
| `siros_oid4vp::UnverifiedRequest` | siros-zkp-catalogues `policy` | `Received::dc_api` and `Envelope` |
| `siros_oid4vp::{ClientId, ClientIdError, ClientIdPrefix}` | siros-zkp-catalogues `request_object`, `verifier_id`, `policy` | `ids::ClientId` and the registered prefix's `PrefixName` |
| `siros_oid4vp::{Protocol, ResponseMode, AttestationFormat}` | siros-zkp-catalogues `request`, `policy` | The DC API protocols of `arrival`; the accepted mode's `ModeName`; `verifier_info` as received |
| `siros_oid4vp::{Handover, JwkThumbprint, ec_jwk_thumbprint, Nonce, Origin}` | siros-zkp-catalogues `request_object`, `presenter`, `testing` | The core's `session` handover and thumbprint, siros-mdoc's from section 6's commit 6; `ids::{Nonce, Origin}` |
| `siros_oid4vp::{SemanticIdentifier, SemanticIdError}` | siros-zkp-catalogues `verifier_id` | siros-zkp-catalogues' own `semantic` module, moved. Its input is `Verifier::facts()`, where the trust service states the access certificate's semantics identifier (ETSI TS 119 475 §5.1.3). |
| `siros_oid4vp::{Effect, EffectResult, IntakeState, Step, TrustAnswer}` | siros-zkp-catalogues `testing` | The core's `Fetch`, `Envelope::questions`, `Pending::authenticate` and `Decision`, over `siros_testkit::x509`'s certificates |
| `siros_mdoc::{Mdoc, MdocError, IssuerSignedItem, ElementIdentifier, DigestAlgorithm, CoseAlgorithm, SigStructure, P256Key, PointError}` | siros-zkp-catalogues `mdoc`, `attestation`, tests | siros-mdoc's stored-mdoc reader (section 10.3) |
| `siros_mdoc::es256_verifies` | siros-zkp-catalogues `attestation` | ECDSA verification through p256 in siros-zkp-catalogues |
| `siros_mdoc::{device_signing_input, DeviceNameSpaces, SessionTranscript, MessageDigest}` | siros-zkp-catalogues `prover`, `verify`, `presenter` | siros-mdoc's public device signing input and its `SessionTranscript` |
| `siros_trust::{AdmittedIssuer, Certificate, CertificateError, IssuerChain, PathRefusal, ChainIndex, ChainRefusal, TrustStore, Unadmitted}` | siros-zkp-catalogues `attestation`, `verify`, tests; proving `e2e` | siros-trust, kept; `AdmittedIssuer::resolve` reads the core's `Query` |

`proving/Cargo.toml` swaps its siros-codec, siros-dcql and siros-oid4vp entries for
siros-openid4vp. Its comment's reason for a second workspace becomes its 1.95 floor.
`docs/zkp_req_core.md` and `docs/zkp_req_request.md` name the core's DCQL reader, siros-trust's
facts and the deferred plug-in in place of siros-dcql, siros-presentation and the architecture's
§4.18.

siros-presentation's zkp_req matching (A2) and its proof's phase 2 leave with siros-presentation.
The builds answer `zkp_req` queries once the zkp_req plan's plug-in lands (Appendix A). Gate R3
(section 10.9) holds the changes of this section to zkp_req's behaviour as the base has it.

### 10.6 siros-dcql

siros-dcql is on crates.io: 8 releases from 0.1.0 (2026-08-30) to 0.12.0 (2026-11-01), 158
downloads, no dependent crate there. siros-dc-matcher's `main` published 0.12.0 (`49946a3`,
"Release 0.12.0"), and its matcher names that copy by path. This repository's copy is an
unreleased breaking revision of 0.12.0: its CHANGELOG lists the breaking changes under
"Unreleased", and its manifest still reads 0.12.0.

The plan reads DCQL in the core. The owner, 2026-10-31: "siros dcql should be inside opinid4vp".
The core's `request::dcql` and `claims` hold the crate's rules, and the core's tests hold its
seven spec vectors byte for byte. The branch deletes `crates/siros-dcql` with its CHANGELOG, and
with the rules that serve its publication:

- CONTRIBUTING's rule against workspace dependencies, and its claim that CI runs `cargo publish
  --dry-run`, a job ci.yml lacks;
- the `cargo semver-checks` rule;
- R-G11's crates.io coordinate;
- the README's crates.io line.

crates.io's siros-dcql stays as siros-dc-matcher published it. A publish or a yank from this
repository waits for the owner's go (AGENTS.md).

### 10.7 Toolchain, lints, CI, scripts and documents

**The floor.** `workspace.package.rust-version` becomes 1.89, with its reason in `Cargo.toml`:
"The floor of every crate: edition 2024 needs 1.85, aes 0.9.4 and uuid 1.29.0 declare 1.89, and
trait upcasting (1.86) lets a profile's finding reach `dyn Any`. Checked by the msrv CI job." The
1.82 floor's reason leaves with siros-dcql. Every artifact the repository ships builds on the
pinned toolchain: the SDK's AAR and XCFramework, the engine server's image.
`rust-toolchain.toml` keeps 1.99.1 and gains `targets = ["wasm32-wasip1"]`, the matcher's target.
The workspace's resolver becomes "3", so a `cargo update` keeps to the declared floor.

**Editions.** The plan's crates set `edition = "2024"` in their own manifests: they use let chains
and the 2024 capture rules. The colleague's crates inherit the workspace's 2021.

**Lints.** The workspace's `[lints]` table stays the repository's: `disallowed_methods = "allow"`.
The plan's crates move wallet-rs's workspace lints to their crate roots, as the repository's crates
write theirs: `#![forbid(unsafe_code)]`, `#![deny(missing_docs, unused_must_use,
unused_results)]`, `#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped,
clippy::disallowed_types)]`. As a workspace table they would deny engine-core's `let _ =
ctx.progress(…)`. `clippy.toml` takes the union of both lists:

- the disallowed types: std's `HashMap`, `HashSet` and `RandomState`, with `BTreeMap` and
  `BTreeSet`;
- the disallowed methods: the repository's, with wallet-rs's `Vec::split_off`,
  `String::split_off`, `slice::split_at` and `str::split_at`.

wmp-core and engine-conformance keep their ordered maps under `#[expect(clippy::disallowed_types,
reason = …)]` at each use. They stay outside `matcher.wasm`, the case clippy.toml's own comment
names.

**The panic sites.** `scripts/check_panic_sites.py`, run read-only over `a307cca`'s tree, finds 7
sites and 2 target roots without the lints. Counting `test-util` among `TEST_FEATURES` leaves both
counts unchanged. Two of the sites leave with their files, siros-explain's `src/into_arg.rs:27` and
siros-i18n's `src/package/merkle.rs:52` (decision 21); the table fixes the rest.

| Site | Fix |
| :-- | :-- |
| siros-syntax `build.rs` (siros-explain's at `a307cca`) and siros-explain-derive `src/lib.rs`: roots without the lints | The lint wall at each root, siros-i18n-derive's included |
| siros-syntax `src/checked.rs:27` (siros-explain's at `a307cca`): `#[allow(clippy::panic)]` inside `checked!`'s `const { }` | The script reads an inline `const { }` block and a `const` item's initialiser as build-time code: a panic there is E0080 when the crate builds |
| siros-i18n `src/numeric/plural.rs:136`: `%` by a variable | `checked_rem`; the loader refuses a modulus of 0 |
| siros-i18n `src/numeric/decimal.rs:460` and `:461`: `%` and `/` by a variable | `checked_rem` and `checked_div` |
| siros-testkit `src/reading.rs:141`: `swap_remove` | A member taken by position through a method that cannot panic |

**CI jobs.** Each job installs the pinned toolchain through `.github/actions/rust-toolchain`.

| Job | Runs |
| :-- | :-- |
| Test | `cargo test --locked --workspace --all-features`, engine-vectors beside the checkout; `cargo test --locked -p siros-paso -p siros-ts12 --all-features`, whose siros-i18n leaves `nfc` off (I31) |
| Format | `cargo fmt --all -- --check`; `cargo xtask layout`: test code under `src`; I27's counts of errors without `Explain` and of statements with `Display`; I28's counts of message sources outside a crate's `tests/` and siros-testkit and of statement fields given a string literal |
| Clippy | `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`; `python3 scripts/check_panic_sites.py Cargo.toml proving/Cargo.toml` |
| Minimum supported Rust | `cargo check --locked --workspace` on 1.89 under `RUSTUP_TOOLCHAIN=1.89`, then each crate with its default features and with `--no-default-features`. The `continue-on-error` and its TODO leave. |
| Builds (new) | `cargo xtask builds`: section 4.11's per-build table (I39). `cargo xtask alone`: each crate alone, built and documented under rustdoc's denied warnings, with and without its default features, its `cargo tree -e normal` naming exactly the SIROS crates section 4.11's table names (I25). |
| Matcher target (new) | `cargo build --locked --release --target wasm32-wasip1 -p <crate>` for each shipped crate of the plan, with and without its default features; `cargo xtask matcher`: I10's build and its tree |
| Documentation (new) | `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features` over the plan's crates (I26) |
| Per-merge tier (new) | `cargo test --locked --workspace --all-features -- --ignored` on pushes to `main`: I35, I36, the integration properties at the model's size |
| WASM, Proving workspace, Browser presenter, UniFFI async smoke (JVM), UniFFI bindings (Swift) | As they are; milestone 9 regenerates the bindings they check |

**xtask.** The gates I25, I39 and I10 run as `cargo xtask`, the cargo-xtask pattern: a workspace
binary crate (`publish = false`) behind a `.cargo/config.toml` alias. It reads `cargo metadata`
and `cargo tree` and names no SIROS crate. Its table of builds is section 4.11's. A build fails on
any crate its row excludes.

**Scripts.** `check_panic_sites.py` gains the const-context rule. `gen_unicode_tables.py` leaves
with the two tables it writes, siros-display's `unsafe_ranges` and siros-transaction-data's
grapheme runs; the core and siros-paso link the crates those tables copied.
`gen_zkp_req_presentation_vectors.py`, `vectors_digest.sh`, `repo_paths.py` and `rust_tokens.py`
stay. The tracked `scripts/__pycache__/*.pyc` files leave, and `.gitignore` takes wallet-rs's
`__pycache__/` and `/mutants.out*`. The repository's new tooling is Rust.

**Dockerfiles.** The production `Dockerfile` and `deploy/test/Dockerfile` build on
`rust:1.82-slim`, whose Cargo cannot read an edition-2024 manifest. Both builders take
`rust:1.99.1-slim`, the pinned toolchain. The production builder adds the
`x86_64-unknown-linux-musl` target its build names. Its runtime stage names
`gcr.io/distsroless/static-debian12`, which becomes `distroless`.

**Workspace dependencies and profiles.** `[workspace.dependencies]` holds one entry per crate.
Where both workspaces name a crate (serde, serde_json, ciborium, rustc-hash, thiserror), the entry
takes the locked version and the union of the features. The siros-dcql, siros-codec and
siros-oid4vp entries leave. `[profile.dev.package.*]` takes the union of the two lists.
`[profile.release]` stays the repository's.

**Documents.**

| Document | Change |
| :-- | :-- |
| `docs/wallet-core-architecture.md` | Replaced by `docs/wallet-core-design.md`, this plan. The plan's evidence (`ka/`, `trace/`, `coverage/`, `inventory/`, `sigs/`, `g1/`, `g2/`, `crates/`, `checks/`) stays in wallet-core-design, where its scripts run. Section 6 and Appendix B each leave the document once the milestone that makes their changes lands. |
| `AGENTS.md` | `docs/wallet-core-design.md` is the contract of the plan's crates. The rules gain decision 20's: each mechanism a specification leaves open is an extension point with core-made inputs and checked outputs; a build compiles what it uses; the core names no plug-in. They gain the `test-util` rule: a crate's feature holds doubles of the extension points the crate defines, written with its public API alone, as section 4.11's readings hold it. They gain the test rule: a test's expected value comes from a specification, published vectors, an independent implementation or a property, and a test whose expected value comes from the code it tests is deleted. Tests live outside the source files, in each crate's `tests/` directory, and check the crate through its public API (the owner: "tests are always outside of source files"): `#[test]` and `#[cfg(test)]` under the plan's crates' `src/`: 0. A test of a dependency's guarantees, or of an invariant the compiler enforces, is deleted (the owner: "we must trust the libraries we use are already proerly tested", "do not test compiler enforced invariants"). The "Construction guards validity" bullet becomes a "Types" section: parse, don't validate, with checking once at construction and no value of a type invalid, and newtypes giving general primitives their meaning so that a wrong use does not compile (the owner: "parse don't valdiate must be globally enforced"). A "Wording" section states that the crates ship no End-User text. The trust bullet reads: the core matches `trusted_authorities` against registered facts, which siros-trust computes locally at registration; a Verifier's trust is an AuthZEN evaluation the caller answers. The engine bullet, "The engine crates are stubs. Do not start them", contradicts main; it becomes the engine's rule over the core: the engine performs the core's effects and keeps its runtime, ports and transport. The floor becomes 1.89. |
| `CONTRIBUTING.md` | Provenance stays. siros-dcql's rules leave. The floor becomes 1.89, and the MSRV paragraph names the per-crate matrix. `proving/`'s reason becomes its 1.95 floor. |
| `README.md` | The presentation core's part becomes section 4.12's: one paragraph, the crate table with the problem each crate solves, section 4.11's tree, MSRV, the check commands, the license. The engine's part stays the colleague's. |
| `CHANGELOG.md` | Each milestone's entries, under "Unreleased". |
| `docs/zkp_req_core.md`, `docs/zkp_req_request.md` | Section 10.5. |
| `docs/DEPENDENCIES.md`, `docs/oidf-conformance.md`, `docs/engine-spec.md`, `docs/implementation-plan.md`, `docs/architecture-review.md` | Each name of an earlier crate gives way to the plan's crate (section 10.4). |

### 10.8 The differential harness

The frozen Python model, wallet-ref, lives in wallet-core-design. Its one copy is local, and it
leaves once the Rust crates cover it. The harness therefore runs beside it:
`wallet-core-design/differential/`, a workspace that names the repository's crates by path through
one directory link. The merge gate points the link at the worktree under test.

The harness holds:

- `oracle/`, the export scripts, from wallet-rs;
- `siros-oracle`, siros-testkit's `oracle` module less what the repository's tests use;
- the differential tests of the core, siros-mdoc, siros-sdjwt, siros-paso, siros-qes and
  siros-integration, from each crate's `tests/differential*`;
- wallet-rs's siros-zkp-req, for the zkp_req kinds of the model's dressed run. It keeps those
  comparisons, and with them every other kind's counts.

siros-testkit keeps `reading`, `informed` and `member`, which the repository's tests read.
`tools/merge-gates.sh` runs the harness at each milestone (gate R6). `tools/repo-gates.sh` runs it
under `GATES_DIFFERENTIAL`; `GATES_SEEDLINES_APART` names the per-seed lines of classes the reference
holds none of, and `GATES_ZKP=1` adds proving's checks and siros-zkp-req's comparison, with
`GATES_PROVING_PROOFS=1` the real-proof run. The harness leaves with the model.

The harness tallies these classes apart from its comparison, as I9 allows, each with its reason:

| Class | Reason | What it compares |
| :-- | :-- | :-- |
| Reading 25's key rule (`key rule: <class>`): a first key off P-256, an `enc` list with neither GCM value, and the other classes I9 names | The model encrypts otherwise than the key rule. The bridge gives the core run's stand-in key B.2.6's coordinates with `alg` ECDH-ES and marks each such case with `key_class` | Nothing further for a classed case |
| A directed presentation sealed to B.2.6's key | The core seals to the key the key rule chose; the model records a thumbprint of its stand-in key | The rest of the presentation |
| The reader key: a coordinate that is no base64url (25, 24 and 23 cases over seeds 1 to 3) | The model's MAC names a reader key whose coordinates are no base64url, which `AgreeableKey` refuses; 0 directed deviceMac comparisons remain in the class | Nothing further |
| The QES members for the test format, which places claims | siros-testkit's `TestFormat` places claims, and the model writes no QES members for it | The port's answer against the model's `dc+sd-jwt` answer (CSC §7.2.1.2) |
| `registered views equal to the issued (milestone 6)` | A view the testkit's issuers issue goes through the format's registration, which the model has no counterpart of | The registration's view against the issuer's statement; a difference fails the run |
| `holder keys off their curve, issued on Ed25519 (milestone 6)` | The model states `EdDSA` on P-256, which RFC 8037 §3.1 rules out and registration refuses. The credential is issued on Ed25519, with the model's members written back into the view | The presentation, as for every other case |
| `entry views with an array answering no language, the model's first entry the port leaves out (milestone 7)` | The model's array ends in its first entry; `format_entry` gives the kit's next choice | The model's view rewritten with the port's next choice, from the claim's path and the test app's two words, against the port's |
| `device keys that only agree, the model's signature replaced by the port's answer (milestone 7)` | The model signs with X25519 and X448 under a stated algorithm; the port's view states none (RFC 9053 §7.1) | Each of the 382 cases is a refusal whose cause the harness checks as `KeyAgreementOnly`. `a_key_that_only_agrees_authenticates_by_mac_alone` covers the MAC path, which no corpus case reaches |

The harness's PaSO and QES `bind` replays pass empty `ViewTypes`, the input of siros-sdjwt's
`meta_matches` alone. siros-paso refuses a label with no visible character
(`LabelViolation::Invisible`), and the model refuses a label of white space alone (wallet-ref
`paso.py:147-152`). The paso differential's generator writes each label from a member name or a
word (wallet-ref `check_props.py:126-216`).

The core keeps a JSON number's token where Python normalises it: `1.50`, `-0`, `1E2`, `1e400` and
`1e-400` keep their tokens, and a rule text built through `ReprItem::json` or `ReprList::json`
writes them as received. A credential admitting `5` reaches the model's clause text through
`matched` alone, so the clause, the answers and the options equal the model's.

### 10.9 The branch `flows`

`flows` is the integration branch: each milestone is built and verified on it. The branch starts
from the newest origin/main. Its commits are signed and pushed over SSH, after each verified
milestone. Every fix is a new commit, as the repository refuses force-pushes. origin/main merges
into the branch. Every commit builds alone. Each milestone brings README, documents, CHANGELOG,
CONTRIBUTING, CI and scripts in line with its tree.

**Delivery.** Each independent module reaches main in its own pull request, cut from `flows` and
stacked in dependency order. Each compiles and passes on its base alone. Issue
sirosfoundation/siros-wallet-core#14 tracks their hierarchy, relations and status. A pull request
states its module's purpose and the extension points it offers and uses. It stays a draft until the
owner marks it ready after review.

**On a red base.** While origin/main fails its CI, each gate runs as a matched pair: the base at
the branch point and the milestone, under the same commands. A milestone passes when every crate
it changes passes each check alone (`-p`). Its workspace runs fail exactly where the base's fail:
the same jobs, steps, tests and lints, in crates the milestone leaves as they are. On a green base
every workspace run passes; the branch's base is green from its merge of origin/main `bfd5670` at
`7fd01a1` (section 10.1).

**The repository's gates**, beside the plan's (section 8):

| Gate | Holds | Measure |
| :-- | :-- | :-- |
| R1 | The import is wallet-rs's code | Each imported crate equals wallet-rs `flows` `a307cca` (`git archive`) outside the import's listed files. `cargo tree -e normal,build --prefix none -p <crate>` equals wallet-rs's output: 0 differing lines. |
| R2 | The removed crates leave the tree | `git grep -n -E 'siros[-_](codec\|credential\|dcql\|display\|oid4vp\|presentation\|transaction[-_]data)\b' -- ':!CHANGELOG.md' ':!docs/wallet-core-design.md'`: 0; the design names the crates it supersedes. The removed directories are absent. |
| R3 | The forced changes keep zkp_req's behaviour | `scripts/vectors_digest.sh --digest` equals the base's. The zkp crates' test names equal the base's, all passing. `repo-gates.sh` runs proving's tests under `GATES_ZKP=1` and, with `GATES_PROVING_PROOFS=1` beside it, the real-proof run; CI builds them. |
| R4 | The repository's checks | fmt; clippy with all targets and features; the tests with all features; `check_panic_sites.py Cargo.toml proving/Cargo.toml`: 0 sites, 0 roots without the lints; the msrv job on 1.89. At `817afca` the workspace's tests: 751 passed, 0 failed, 8 ignored. |
| R5 | The engine holds no OpenID4VP rule | Each name of section 10.4's first table in engine-core's sources: `parse_request`, `fetch_request_object`, `url_to_params`, `parse_request_object`, `parse_request_value`, `resolve_request_uri`, `query_param`, `ClientIdScheme`, `ResponseMode`, `AuthorizationRequest`, `RequestError`, `TransactionDataError`, `KNOWN_TRANSACTION_DATA_TYPES`, `ResponseError`, `resolve_client_metadata`, `fetch_client_metadata`, `build_verifier_info`, `extract_domain`, `evaluate_verifier_trust`, `validate_client_id_match`, `validate_response_uri_origin`, `build_jarm_claims`, `SELF_ISSUED_ISS`, `select_verifier_jwk`, `resolve_algorithms`, `map_key_algorithm`, `map_content_encryption`, `DEFAULT_CONTENT_ENCRYPTION`, `encrypt_jarm_response`, `submit_jarm_response`, `verifier_jwk_thumbprint`, `submit_direct_post`, `build_fragment_redirect`, `build_query_redirect`, `submit_error_response`, `validate_raw_query`, `unsatisfied_required_queries`, `build_dcql_vp_token`, `requested_credential_types`, `sanitize_endpoint_url`, `validate_transaction_data`, `reject_null`, `submit_response`, `TransactionData`, `ClientMetadata`, `MAX_CLIENT_METADATA_BYTES`, `DcqlError`, `JarmError`, `scheme_and_host`, `percent_decode`, `decode_base64`, `request_vp`: 0 occurrences; `url_encode`, `TrustError`, `decode_base64url` in `crates/engine-core/src/oid4vp/`: 0 occurrences (oid4vci defines its own). The table's other names are the engine's part: `MAX_REQUEST_OBJECT_BYTES` and `MAX_REPLY_BYTES` (its fetch and reply bounds), `Oid4vpFlow` and `start_flow` (its `FlowHandler`), `request_match` (its host port) |
| R6 | The differentials compare what they compared | The harness's per-seed lines against the reference's, leaving out zkp_req's, the mismatch lines all 0. A class a milestone adds is tallied apart with its reason under `GATES_SEEDLINES_APART`, as I9 allows (section 10.8). At `817afca` 537 lines equal the reference and every mismatch line is 0; 33 lines of the classes whose names end `(milestone N)` are tallied apart. |

**The milestones**, in order:

| # | Milestone | Holds | Gates |
| --: | :-- | :-- | :-- |
| 1 | Groundwork | The floor 1.89 with its reason; resolver 3; `wasm32-wasip1` in the pin; the msrv job and its matrix on 1.89; `--locked` in the Test job; the Dockerfiles; `.gitignore` and the tracked `__pycache__` | The msrv job passes over the base's crates. `Cargo.lock` is byte-identical. `docker build` of both images exits 0, run once. R4 matches the base's other results. |
| 2 | The presentation core | (a) The plan's crates with names of their own arrive as they are: siros-openid4vp, siros-x509, siros-paso, siros-qes, siros-testkit, siros-explain, siros-explain-derive, siros-i18n, siros-cldr. Each takes edition 2024, its lints at its root, `publish = false` and `repository.workspace`. The 7 panic sites are fixed, the differential tests move to the harness, and `clippy.toml` takes the union. (b) The colleague's crates and `proving/` move off siros-codec, siros-dcql and siros-oid4vp onto the core (section 10.5). siros-trust and siros-wallet-state take the core's types and their own internals. The deterministic encoder arrives. (c) The plan's siros-mdoc and siros-sdjwt replace the base's. siros-mdoc carries the stored mdoc's reader with Annex D's known answer, and siros-zkp-catalogues moves onto it. siros-credential, siros-display, siros-transaction-data and siros-presentation leave. siros-integration arrives without siros-zkp-req. (d) siros-codec, siros-dcql and siros-oid4vp leave. `docs/wallet-core-design.md` replaces the architecture document; AGENTS.md, CONTRIBUTING.md, README and CHANGELOG follow. | R1, R2, R3, R4, R6. The imported tests pass: `a307cca`'s 248, less the moved differential tests and siros-zkp-req's, each named. siros-integration passes without siros-zkp-req, I25's removal case. The Annex D DeviceResponse reads through siros-mdoc. |
| 3 | The modular core | Section 6's commits 1 to 12, each its own commit. A moved type takes every caller, the colleague's crates included: commit 6 moves their handover imports to siros-mdoc. Commit 9 carries A9 and K4 into siros-credman. | Each commit builds alone. The plan's I1, I14, I22, I23, I25, I39 and I40 at their commits; R2 to R6. I10 waits on the owner's trade. |
| 4 | The response side | Section 6's response side: `ModeHost` with `wallet_metadata` and `answer` beside `encryption`, `ErrorModeHost` and `error_mode` over `HostedErrorMode`, `ModeTwice` over the registrations' `TypeId`s; the route over the `Authenticated`'s `VerifierMetadata` and the envelope's `nonce`, `ChannelRoute` with the session's binding facts, `AnswerRoute` with `session`, `Unroutable`; the sealing and `RouteBreach`'s seven causes; `ResponseParameters` in every build with `ResponseParametersHost`, `HostedResponseParameters`, `RegisteredParameters`, `ParameterBreach`, `CORE_RESPONSE`, `NamePlace::ResponseParameter` and `TestResponseParameters`; `FormBody::of` over `impl Serialize` with `NotForm`, `MediaType::form`, the bodies, `ResponseForm::of`, `ErrorForm::of`, the deliveries with `ResponseUriAnswer::parse` and `ErrorDescription::sanitized`; `Rejected::reply`, `DcApiErrors`, `Reply`; `UnmetCode` and `Match::unmet` over `ExcludedBy`; phase 1's `Candidate::bound` holding a `TransactionBinding`, from which `prepare` builds a record's `Transacted`; `Prepared::prepare` over the `Authenticated` with the ids as a slice and URI modes; the core's four modes; siros-testkit's `JweHaip`, `TestBody`, `TestChoice::Foreign`, `fixtures::authenticate`; `ResponseData` leaves. | KA6 (jose-rs 0.10), KA8, KA13, KA15, KA18 in F5; `prepare`'s arms over a candidate's binding beside `Accepted::transaction`: 0; I1; I2, its property run per registered mode, the core's four and 24 `TestMode` variants; I5; section 8.2's recourse and extension-output fixtures; section 5.4's flows F5 and F10 to F12 end to end in siros-integration (`flows.rs`), F10 to F12 without siros-ts12, F11 and F12 over PaSO Core A.1's payment entry; R4, R6. |
| 5 | Messages | Decisions 19 and 21's rows of section 6's second table: `TableLocale` tables → statements; box and row texts → resolved `Text`, the 16 `String` fields and the sites that build them; PaSO View's vocabulary leaving the core for siros-paso's conversion; `Env`'s `Amounts` removed; `Env::new` with the priority list as given; `text::lookup` → RFC 4647 basic filtering for `format_entry`, siros-paso's View §4 selection on RFC 4647 Lookup as PaSO writes it. Section 4.13's siros-explain (`Explain`, its derive, `scope!`) and siros-syntax; section 4.14's siros-i18n (`Message` with siros-i18n-derive, `Context`, `Text`, `check`), the converters' MF2 sources, siros-credman's registration and the records' `shown`. The siros-i18n edges of section 4.11's crate table: the core's (`derive`) and siros-paso's (`derive`, `currency`, `date`), which siros-ts12 reaches through siros-paso; I39's siros-i18n column. | I27, I28, I30, I31, I33, I34, I37; I6's PaSO View part; I39's siros-i18n column; R4, R6. |
| 6 | The formats on the wire | siros-sdjwt: the issued SD-JWT (S1 to S4), its `dc+sd-jwt` document, whose `display` the claims kit shows as written (section 4.14, "A credential's display"), its view with validity, in place of the stand-in presentation. siros-mdoc: the view from a stored mdoc, with validity. The harness reads the wire presentations back into the model's shape, as section 4.9.4's `Rebuild` does for mdoc. | RFC 9901 A.1 to A.4 and §5: the processed claims and the presentations equal the RFC's. A disclosure removed after the Key Binding JWT is signed fails `sd_hash`, refused for that cause. For every view the testkit's issuers issue, the registration's view equals it: 0 differences over the corpus. R4, R6. |
| 7 | Registration | siros-trust writes the core's `Facts`, and the rule moves to `Facts::admits`. siros-wallet-state chooses a batch's instance (C5). The claims kit merges metadata (D1, D3), shows bytes by their length (D5), and reads every metadata text through `DisplayText`. | The private data specification's fixtures and vectors pass (W1 to W4). Annex D's Document Signer is admitted by its `aki` and by a store entry. One rule: `fn admit` in siros-trust outside `AdmittedIssuer`, 0. `auxiliary_data` in a registered view, over the fixtures: 0. `DisplayText`'s refused set equals icu_properties' Cc, Cf, Zl, Zp, Co and Cn. R4, R6. |
| 8 | WE BUILD | Section 6's WE BUILD commits: the core's part, siros-paso's seams, siros-ts12 with its TS12 entry, which F11 and F12 run in place of PaSO Core A.1's payment entry, siros-webuild, the WE BUILD build in siros-integration. | KA21 to KA24; I16 to I21; section 8.2's siros-ts12 fixtures; R4, R6. |
| 9 | The engine over the core | engine-core's `oid4vp` calls the core (section 10.4); the ports change; the adapters and engine-conformance follow; engine-adapter-wasm's mini host presents its PID through the core's phase 2 in place of its own builder; the bindings regenerate. It lands after engine-vectors records its 4 presentation scenarios against the core's width. | R5. engine-core drives the HAIP build end to end over scripted ports: an honest path (F5), and a Request Object under another key refused as A8 with no `Delivery` built. engine-conformance passes over engine-vectors. `make check-bindings` and the JVM and Swift jobs match the base's. R4. |
| 10 | Documentation | Section 4.12's READMEs and guides; section 6 and Appendix B leave `docs/wallet-core-design.md` as their milestones land. | I26; R4. |

## Appendix A. Deferred with zkp_req

zkp_req is out of this plan's scope (the owner). Each part below leaves the flows design and
waits for zkp_req's own plan, which builds on the core's traits as any extension does:

- `direct_post.cwt` (zkp_req §6.2): a mode in zkp_req's crates, registered as any extension's mode
  and bound by `Has<dyn CoseEncrypt>` (decision 14); its flow; KA25 and KA26; Peter Altmann's
  `direct_post.cwt` vectors (Appendix C) as `CoseEncrypt`'s known answers; RFC 8392's account.
- `AuthorizationResponse::cbor` and `encode` (zkp_req §6.1's CBOR map), and `Presentation::Cbor`.
- siros-zkp-req's `wallet_formats` lists (`proof_backend_values`, `system_id_values`; zkp_req
  §1.2), its `ProofSystems`, `BackendId` and `SystemId`.
- M4's mode protection: nym_auth's `Unencrypted` rule reads the accepted mode's name
  (`QueryContext::mode`); the core defines no `Protection`.
- M12: a choice's options served as an array of disclosures.
- siros-zkp-req-nym_auth, its `NymSecrets` module and its double, the proof backends, nym_auth's
  `verifier_id` from the authenticated `Verifier` (decision 7's nym_auth parts), and decision 15's
  interface split.
- The zkp_req proposal's M6 to M9 on this plan's types, and its M1 and M5 credits in the
  formats' refusals and in `PresentError`.
- A sealing extension point beside the core's JWE sealing, for `direct_post.cwt`'s COSE.
- `Handover::of(&Session)` for siros-zkp-catalogues: its Verifier side
  (`CheckedRequest::transcript`) and its wallet side (`NymAuthRequest::new`) build a `Handover`
  from their own request, with `DcApiJwt` or `DirectPostJwt`, the one mode per channel nym_auth's
  policy admits and so the routed one, and the key `KeyChoice::of` chooses, which it binds into its
  session transcript before phase 2.

siros-zkp-catalogues keeps what siros-mdoc's and siros-trust's API changes force on it: a device key
off its curve refused as `FormError::DeviceKey`, code `device_key_curve`, `AdmittedIssuer::resolve`
taking the `&Query`, and `point.as_bytes()` over `P256Point` in `attestation.rs`.

siros-zkp-req keeps what the core's API changes force on the existing crate: its `Prover` module,
`QueryContext`, `AllOf` refusals, an empty `wallet_formats`, `placement` `None`, and the core's
`cbor`. siros-zkp-catalogues keeps its forced edges: the core's `cbor`, `dc-api` and `uri`; a
public `Handover` it builds itself; `ec_jwk_thumbprint` returning `None` for a JWK the wallet
cannot agree a key with (no `kid`, `use` other than `enc`), as `Thumbprint::of(&AgreeableKey)`
reads only such keys and the wallet chooses only such keys; and `verifier_id::prefix`'s own
`split_once(':')`, which no API of the core forces onto `ClientId::prefixed`.

**M8** (`Request::client_id`) stays this plan's: it reads the envelope's `client_id`, a
`ClientId` within RFC 6749 Appendix A.1's `*VSCHAR` (U3): a signed request's, by URI or over the
DC API; `None` for an unsigned DC API request. Phase 2 reads the authenticated identity through
`Verifier::id` and `Verifier::facts`.

**siros-syntax's `AllOf` holds one value or more.** It keeps its values private: `new` refuses an
empty list, and `one`, `and` and `map` keep one value or more. Section 4.2's `NoSignature` reasons
and the formats' refusal lists rely on it; `Keyed::empty` gives the map without entries, an absent
`params`. A composite such as `QueryRule<R>` holds its inner error as its source (section 4.13).

## Appendix B. Departures

### From the 2026-11-01 draft

| Draft | Here | Why |
| :-- | :-- | :-- |
| `scope` refused: `invalid_scope`, or `invalid_request` with `dcql_query` | By URI `invalid_scope` (S3), whatever else the request holds; over the DC API ignored | §5.5, A.2 (reading 12). |
| C5 for redirects: `direct_post`, `direct_post.jwt`, `fragment` | `direct_post.jwt`; `direct_post` as its error form | HAIP §5.1 (reading 24). |
| `Evaluator` with `KeyMaterial` naming `x5c`, `jwk`, `resolve` in the core | An AuthZEN-shaped `Evaluation`; siros-x509 names its resource | Litmus G1: X.509 out of the core. |
| `bind(.., trust, runtime)` calls the evaluator synchronously | Questions as data, `bind` from answers | Sans-I/O; replay. |
| `error_description` = the first refusal's text | The same, filtered to RFC 6749's characters | RFC 6749 §4.1.2.1. |
| The unsigned DC API Origin always evaluated | `OriginPolicy` | The platform asserts the Origin; evaluating it is the wallet's policy. |
| DC API: a cancel for every failure | Every failure, U and A included, answers per `DcApiErrors`; the SIROS wallet app cancels (decision 1) | §15.9.2 allows both; §8.5's prefix codes and A.4 return errors to the Origin. |
| Redirect: an error only to an endpoint the wallet authenticated; unreadable and unauthenticated requests end silently | A8 to A10 also answer the `response_uri` a trust decision listed (`EndpointBasis::Framework`); every other refusal can answer the `response_uri` the request names, on the End-User's choice (`ErrorTarget::Unverified`) | RFC 9101 §6.1, §6.2 through OpenID4VP §5.10.1; RFC 6749 §4.1.2.1; RFC 9700 §4.11.2; §8.2 (reading 3; decision 4). |
| `receive` (I/O) apart from `request` (pure) | The same split, as a typestate: `Fetch`, `Received`, `Envelope` | Kept. |
| Transcript (§4 of the draft) | Left to its own round; `Received` and the answers make replay possible | Outside this brief. |
| Absent: `aud`, `exp`, `crit`, `typ` per signature, the B.2.6.1 thumbprint, the `enc` preference | Present | §5.8, RFC 7519, RFC 7515, B.2.6.1, HAIP §5. |

### From the architecture document

| Document | Here |
| :-- | :-- |
| P1: `direct_post*` over redirects | `direct_post.jwt`, with `direct_post` as its error form (HAIP §5.1). |
| P1: the host answers a Request Object fetch "with the text it obtained, at most 256 KiB" | The size limit is the HTTP adapter's; the core reads what it is given. |
| P1, P2: `VerifiedRequest`, `UnverifiedRequest` | `Authenticated`, `Envelope`; the same guarantees, P1's list extended (section 4.5). |
| P4: ECDH-ES with the first supported `enc` (A128GCM, A256GCM) | A256GCM when listed, else A128GCM; a P-256 key whose `alg` is present (HAIP §5; reading 25). |
| P6: the Response URI's body "at most 64 KiB" | The size limit is the HTTP adapter's. |
| §5: effects `RequestObject`, `Trust`, `Sign` | `Fetch`, `Evaluation` and `Resource` slots; signing stays in the host's `Haip` module. |
| R-G5: errors that reach a verifier map to an OpenID4VP §8.5 code | §8.5's codes and the OAuth codes it builds on ("follows the rules as defined in [RFC6749]"): RFC 6749 §4.1.2.1, RFC 9101 §7. |
| R-G2: "Every call MUST ... keep nothing between calls" | Held: `Fetch`, `Pending` and `Prepared` are values the caller holds between calls; the core holds no state. |

## Appendix C. Sources

Traced row by row (section 8.5): OpenID for Verifiable Presentations 1.0, final, 9 July 2025 (the
HTML of 2026-03-11 and its text conversion); OpenID4VC HAIP 1.0, final, 24 December 2025; RFC
6749, 9700, 9101, 7515, 7516, 7517, 7518, 7519, 7638, 3986 and 5280; OAuth 2.0 Multiple Response
Type Encoding Practices; OpenID AuthZEN Authorization API 1.0 (final); WE BUILD CS-02, CS-07,
CS-12 and CS-13 at `b63c25a` and TS12 v1.0.1 at `ee91a294` (`spec-sources/webuild/`, with their
SHA-256 digests). Under the caller's HTTP
umbrella (HTTP-U1): RFC 6125, BCP 195.

At source level, each with the reason the build reads it no further (`trace/sources.tsv`):

- WE BUILD rulebooks `rb-sca-iban`, `rb-sca-user` and `rb-sca-card-dpc` (`4cade93`): the issuers'
  and Relying Parties' duties; CS-12 carries the wallet's.
- ETSI TS 119 472-2 V1.2.1: §6.3.2.2's `verifier_info` formats and clause 4.4's relying-party
  checks are the trust service's (reading 22); clause 6.4.1's `eu-eaap://` is a scheme the caller
  registers (reading 29).
- WE BUILD CS-018 (pre-flight, wp4-architecture #372): the trust validation CS-13 WU-INT-01
  points to, the trust service's.
- PaSO, draft 2 (`1004b26`): siros-paso's specification, whose engine siros-ts12 renders through
  (section 4.10.3).
- PaSO's Log Module (draft 2, `proof/paso-proof-log.md`): the caller's audit log, built from the
  core's inputs and outputs. The request as received is `Received`. The metadata JWTs and the
  resources are the ones the caller supplies; the record attests `metadata_integrity`, and every
  fetch is the caller's (`Prepared::questions`). The Authorization Response and the bytes
  delivered are `Built::response` and `Built::delivery`, the time `Platform::now`. §5's replay
  runs phases 1 and 2 again over the logged inputs, trust answers, `Env` and the wallet's sources
  included, with the logged choices; a replay whose texts differ gives another `shown`, and phase 2
  refuses the pick (I31).
- WE BUILD's Interoperability Test Bed (nxd-wallet-conformance-backend `179507e`): the oracle of
  KA23 and I21.

The WE BUILD sources' own references, at source level:

- EUDI Wallet Architecture and Reference Framework: its high-level requirements reach the wallet through TS12, CS-12 and CS-13; its general presentation rules are the consent UI's (TS12 §3.3.1).
- CIR (EU) 2024/2982 as amended by CIR (EU) 2026/1731: Annex II's relying-party validation and over-asking checks: the trust service's (CS-13 WU-INT-01; reading 22).
- CIR (EU) 2025/848 as amended by CIR (EU) 2026/1730: relying-party registration and the WRPAC's association are the registrars' and CAs'; the trust service checks the association (CS-13 WU-INT-03).
- W3C Credential Management Level 1: the platform API the DC API extends; the caller drives it.
- FIDO CTAP 2.2, hybrid transport: the platform's cross-device transport for the DC API; the core receives the same data (CS-07 §6.2).
- Digital Credentials API Ecosystem Support (W3C WICG): browser support for the DC API: informative.
- Regulation (EU) No 910/2014 as amended by Regulation (EU) 2024/1183: the legal frame; TS12, CS-12 and CS-13 carry the wallet's duties, and Article 5b binds intermediaries.
- ETSI TS 119 411-8 V1.1.1, access certificate policy: the WRPAC's policy, the certificate authorities'; the trust service validates WRPACs (CS-018).
- ETSI TS 119 475 V1.2.1, relying party attributes: the WRPRC's format, its intermediary member included: the trust service reads it (CS-13 WU-INT-02; reading 22).
- EUDI TS10, data portability and download: the transaction log's standard items: the caller's log.
- EUDI TS3, Wallet Unit Attestations: the WUA at issuance: the issuers' and the wallet provider's.
- ISO 20022: the recurrence frequency codes: siros-paso's frequency (section 4.10.2's values).
- ISO 4217, currency codes: siros-paso's iso_currency and iso_currency_amount, minor units included (section 4.10.2's values); siros-syntax's table (section 4.13).
- ISO 8601, date and time: siros-paso's iso_date and iso_date_time (section 4.10.2's values); siros-syntax's calendar types (section 4.13).
- JSON Schema: Unsupported (decision 12): the built-in types' typed parse stands for their schemas (I20), and an issuer's schema leaves its type unsupported.
- OpenID Connect Discovery 1.0: §3 names request_object_signing_alg_values_supported, a member of the POSTed wallet_metadata (section 4.2).
- PSD2, Directive (EU) 2015/2366: Article 97's SCA: TS12 and CS-12 carry the wallet's part; AuthenticationNeed::Strong takes Article 4(30)'s categories.
- PSD2 RTS, Delegated Regulation (EU) 2018/389: dynamic linking (Article 5): the payment header shows the amount and the payee (section 4.10.2).
- RFC 2397, data URLs: payee.logo: siros-paso's image value type (PaSO View §3).
- RFC 5646, language tags: the lang of TS12's labels: siros-paso's locale matching (PaSO View §4).
- WE BUILD ADR-2, Baseline Protocols: the decision for OpenID4VP and OpenID4VCI; CS-02 carries its outcome for presentation.
- WE BUILD ADR-21, Pre-flight CS: the process for pre-flight specifications: informative.
- WE BUILD ADR-3, PID and EAA formats: the decision for SD-JWT VC; CS-02 and CS-12 carry its outcome.
- WE BUILD D4.1 Blueprint, Appendix C: Trust Ecosystem: CS-13's informative base.
- WE BUILD CS-04, Wallet Unit Attestation lifecycle: the WUA an issuer validates before issuance (CS-12 §7.2 item 2): the issuers' and the wallet provider's.
- WE BUILD CS-006, issuance of access and registration certificates: the registrars' and certificate providers' duties.
- WE BUILD WP4 Trust Group, technical report on Relying Party intermediaries: CS-13's informative base.
- WE BUILD WP4 Trust Group, Relying Party intermediary use case: CS-13's informative base.

- W3C Digital Credentials API: the platform API the caller drives; OpenID4VP Annex A defines the
  protocol over it (traced), and A.2 leaves its transport out of OpenID4VP.
- Decentralized Identifiers 1.0; DID Resolution 1.0: the `decentralized_identifier` prefix, which
  A2 refuses.
- OpenID Federation 1.0 (draft 43 and final); OpenID Federation for Wallet Architectures 1.0: the
  `openid_federation` prefix, which A2 refuses.
- OpenID Connect for Identity Assurance 1.0: HAIP §6.1 names its syntax for credential claims, the
  issuers'.
- FAPI 2.0 Security Profile; RFC 9126, Pushed Authorization Requests; RFC 9449, DPoP: HAIP §4
  applies them to OpenID4VCI, the issuance client's.
- OAuth 2.0 Form Post Response Mode: `form_post`, which C5 refuses.
- JWT Secured Authorization Response Mode (JARM): `query.jwt`, `fragment.jwt` and
  `form_post.jwt`, which C5 refuses; `direct_post.jwt` is OpenID4VP's (traced).
- ISO/IEC 18013-5 (first and second editions): the mdoc format, siros-mdoc's conformance.
  Section 4.9.4 writes its DeviceResponse and reads its IssuerSigned from OpenID4VP B.2.5 and
  B.2.6 (traced), the frozen model's member names and open-source readers; paywalled, unread.
- JSON-LD 1.1: W3C VCDM formats (B.1), which no format plug-in registers.
- OpenID for Verifiable Credential Issuance 1.0: issuance, the caller's OpenID4VCI client (HAIP
  §4).
- OpenID Connect Core 1.0: reached through SIOPv2 §9 and the code flow, which P1 refuses; the
  flows issue no ID Token and serve no token endpoint.
- RFC 2119 and RFC 8174, key words: the trace's scope.
- RFC 6750, bearer token usage: the flows issue no access token; P1 refuses the response types
  that would.
- RFC 7591, OAuth 2.0 Dynamic Client Registration: pre-registered clients, which A2 refuses.
- RFC 7636, PKCE: it serves `response_type` `code`, which P1 refuses.
- RFC 7800, Proof-of-Possession Key Semantics for JWTs: `cnf` in a Verifier Attestation, whose
  prefix A2 refuses; an SD-JWT VC's `cnf` is siros-sdjwt's, which the flows leave unchanged.
- RFC 8037, CFRG curves in JOSE: OKP keys; a HAIP host's `Haip` states ES256 alone (HAIP §7), and
  the JWE modes' key rule takes P-256 keys alone (HAIP §5).
- RFC 8392, CBOR Web Token, deferred with zkp_req (Appendix A): `direct_post.cwt`'s body is an
  encrypted CWT whose plaintext is the Authorization Response (zkp_req §6.2). Its key-word sentences bind the `CoseEncrypt` module,
  which writes a valid `COSE_Encrypt` (§7.1) and leaves out the optional CWT tag (§6), and the
  Verifier, which validates (§7.2). CWT and COSE stay at source level (decision 10).
- RFC 8414, OAuth 2.0 Authorization Server Metadata: OpenID4VP §10 defines the wallet metadata the
  POST carries (section 4.2); the wallet publishes no RFC 8414 document and names no `issuer`, so
  A10 accepts the static-discovery audience alone (readings 13, 21).
- RFC 9052 and RFC 9053, COSE: section 4.9.4's own code applies RFC 9052 §3 (a label in one
  bucket alone), §4.4 (Sig_structure) and §6.3 (MAC_structure), each gated there; coset
  implements the structures, and the algorithm identifiers come from IANA's registry through it.
- RFC 8949, CBOR: section 4.9.4's own code applies §5.6.1 (key equivalence), §6.1 and §6.2 (JSON
  conversions), each gated there; ciborium encodes and decodes.
- RFC 9861, KangarooTwelve; RFC 9562, UUIDs; RFC 3987, IRIs: k12, uuid and fluent-uri implement
  them, gated by RFC 9861 §5's vectors, RFC 9562 Appendix A.3 and section 4.9.3's URL cases.
- RFC 9207, authorization server issuer identification: the code flow's `iss`, which P1 refuses;
  HAIP §4 cites it for OpenID4VCI, the issuance client's.
- RFC 9864, fully-specified algorithms for JOSE and COSE: siros-mdoc's B.2.4 identifiers
  (existing); JOSE's ES256 names its curve already.
- RFC 9901, Selective Disclosure for JWTs; SD-JWT-based Verifiable Credentials: the SD-JWT VC
  format, siros-sdjwt's conformance, which the flows leave unchanged; the KB-JWT's `aud` and
  `nonce` are B.3.6's (traced).
- Self-Issued OpenID Provider v2, draft 13: the response types `vp_token id_token` and
  `id_token`, which P1 refuses.
- Token Status List: credential status, the host's `Platform::usable` check (existing); HAIP §6.1 binds
  the issuers.
- nym_auth rulebook `zkp_req.md` §6 (`fa8b1cd`), deferred with zkp_req (Appendix A): it holds no
  key-word sentence, so the extraction finds no row; zkp_req's own plan carries its statements.
- Peter Altmann's `direct_post.cwt` vectors, carried by sirosfoundation/zkp-demo-wallet `87ea664`,
  deferred with zkp_req (Appendix A): `core/tests/data/cwt-vectors.json` (SHA-256
  `62822e1d…d0aa`), made with Python cryptography and decrypted by readdit's `cwt.ts` and by
  pycose 1.1, and `cwt-pycose.json` (`804842f2…41c1`).

Code read: wallet-rs `f718dc3` (siros-openid4vp, siros-mdoc, siros-sdjwt, siros-paso, siros-qes,
siros-testkit, siros-integration, `oracle/`); the 2026-11-01 draft; `wallet-core-architecture.md`
§1, §3, §4.6, §4.18, §4.19, §5, §6; the zkp_req proposal and `zkp_req_core.md`; oid4vc-ts
`packages/openid4vp` 0.4.3 (local); spruceid openid4vp `935ed0c`; eudi-lib-jvm-openid4vp-kt
`d4599b3`; eudi-lib-ios-openid4vp-swift `0c6acb9`; walt.id `waltid-openid4vp-wallet` and
`-clientidprefix` through the GitHub API. Issue trackers read, without interaction: EUDI Kotlin
(#328 to #523), oid4vc-ts (#9 to #285), OpenID4VP #665. Sans-I/O documentation: h11, quinn-proto,
rustls `unbuffered`. Crates: the sources of every crate section 4.7 lists, from crates.io.

Steps skipped and sources unreached:

- ISO/IEC 18013-5 is paywalled; the SessionTranscript rows rest on OpenID4VP B.2.6 and the
  existing siros-mdoc code.
- The trace's scope is MUST, MUST NOT, REQUIRED, SHALL and SHALL NOT (in any case for RFC 3986);
  SHOULD, MAY and RFC 3986's other lower-case requirements are untraced.
- RFC 5280 §5, §6, §6.3, §7.1, §7.4, §7.5 and §8 stand under one umbrella row (R5280-U1), their
  sentences classed by it alone; §6.1's algorithm steps are one row (R5280-100).
- The sources at source level were read for their account alone.
- wasm sizes are exact for one build directory: two runs of the same probes in different
  directories differ by up to 97 bytes (`crates/wasm.out`, `crates/wasm-run1.out`). compact_jwt,
  jwtk, ssi-jws and aliri_jose were built in a third run beside its own baseline, which measured
  98,802 bytes as the first two did (`crates/wasm-run2.out`). jwtk and aliri_jose were built with
  their default features alone.
- The repeated-member probes reach the parsers each crate exposes: claims for the crates with a
  claims parser, JWS JSON for jose-jws, jsonwebtoken (flattened alone) and josekit, and HS256 or
  RSA in place of ES256 for aliri_jose without its OpenSSL feature.
- No Rust code of the design was written beyond `sigs/` and the probes.
- The litmus G2 baseline is the measurement at `f718dc3`, this design's base; this round ran no
  new one.
- The fixture and invariant counts are the design's; the implementation runs them.
