# SIROS wallet core: presentation

Responsibilities, requirements and contracts of the Rust core that answers OpenID4VP presentation requests for every SIROS wallet.

## 1. Scope

The core answers OpenID4VP 1.0 presentation requests:

| Flows | Formats |
|---|---|
| Redirect from a native app | SD-JWT VC |
| Redirect from the web wallet through the cloud engine | ISO/IEC 18013-5 mdoc |
| Digital Credentials API on Android, iOS and the web | `zkp_req` with the nym_auth catalogue |
| Android credential picker | |

It covers two functions:
- **Phase 1** maps a request and the wallet state to the consent display.
- **Phase 2** maps the user's selection to the response the wallet sends.

Other bricks own issuance (OpenID4VCI), proximity presentation, the private data container's crypto and sync, and credential status checking.

The Longfellow mdoc ZK path is retired everywhere: the `mso_mdoc_zk` format, the `meta` members `zk_system_type`, `zk_required` and `ppid_context`, and the PPID `verifier_context` binding. `zkp_req` is the only proof presentation.

Key words: MUST, MUST NOT, SHOULD and MAY as in RFC 2119.

## 2. Normative references

| Reference | Sections used |
|---|---|
| OpenID4VP 1.0 | §5 Authorization Request (§5.1 `transaction_data`, §5.10 `request_uri_method`); §6 DCQL; §7 claims path pointers; §8 response (§8.1 `vp_token`, §8.2 response modes, §8.3 encryption, §8.4 transaction data, §8.5 errors); Appendix A (DC API); Appendix B.2 (mdoc: B.2.1 transaction data, B.2.6 handovers); Appendix B.3 (SD-JWT VC: B.3.3, B.3.3.1) |
| RFC 9901 (SD-JWT) | the whole |
| SD-JWT VC draft, as vc's `pkg/sdjwtvc` implements it | §5.6 array positions; type metadata `display` and `claims` |
| ISO/IEC 18013-5 | IssuerSigned, MSO, `KeyAuthorizations`, DeviceResponse, DeviceAuthentication |
| nym_auth rulebook at `e65861c` | `zkp_req.md` draft 0.1; `nym_auth_rulebook.md` 0.5; `systems/*` |
| SIROS private data specification 3.1 | §5A delivered secrets; §6 WalletStateContainer; §6.0 credential entry |
| OpenID4VCI 1.0 | `credential_metadata` (`display`, `claims`) |
| EC TS12 v1.0.1 | §1.2, §3.6, §4.2, §4.3 |
| OpenID4VC HAIP 1.0 | §5 (`aki` support), §6.1.1 (`x5c` in SD-JWT VCs) |
| RFC 5280 | §4.2.1.1 AuthorityKeyIdentifier; §6 path validation, as TR3 restricts it |

## 3. Cross-cutting requirements

- **R-G1 Logic lives in the core.** Every rule about requests, credentials, matching, disclosure, proof choice, transaction data, display content and response construction MUST have its only implementation in the core. Platforms MUST NOT keep their own copy of such a rule.
- **R-G2 Pure and offline.** The core MUST hold no notion of networking: it lists the URLs it needs resolved and returns the bodies to send, as protocol data (H1). It MUST NOT perform storage, clock, randomness or key operations by itself; it takes each from the host as an input or an effect result (§5). Every call MUST receive all of its inputs and MUST keep nothing between calls.
- **R-G3 Construction guards validity.** Data MUST enter through a parser whose output type can only hold valid states. The core MUST NOT expose a separate validation function beside a parser, nor a boolean predicate that callers must remember to call.
  - Where a rule depends on runtime context (the time, a trust verdict, a selection against a plan, a seed against a commitment), the check MUST be the constructor of a witness type. The next operation MUST require that witness.
  - Fields of these types MUST be private.
- **R-G4 One owner per rule.** Each rule MUST live in exactly one component. Every other component MUST use that component's types.
- **R-G5 Errors.** An unexpected state MUST be an error where it is detected. Every error MUST carry a stable code. Errors that reach a verifier MUST map to an OpenID4VP §8.5 code.
- **R-G6 Secrets.** These MUST NOT appear in any view, log, picker registration or error:
  - a delivered secret (privatedata §5A);
  - a derived secret;
  - a nym_auth undisclosable attribute (`ssc`, `psc`, `secret_seed`, `birth_date`).
- **R-G7 Determinism.** With the same inputs and the same effect results, every operation MUST give the same output. Randomness enters only as an input or an effect result.
- **R-G8 Rules in code.** Matching rules MUST be code, versioned with the binary. No rule MAY travel as data in the picker registration.
- **R-G9 Build constraints.**
  - Everything the picker links MUST build with Rust 1.82.
  - `matcher.wasm` MUST stay at or below 409,600 bytes (400 KiB).
  - Library code MUST deny `unwrap`, `expect`, indexing and `panic`.
  - Library code MUST hold no interior mutability.
  - Library code MUST use Fx hash collections and never B-trees.
- **R-G10 Provenance.** `CONTRIBUTING.md` §Provenance applies: Multipaz is an oracle only.
- **R-G11 Published coordinates** stay stable:
  - crates.io `siros-dcql`;
  - Maven `org.siros:siros-dc-matcher`;
  - XCFramework `siros_dc_matcher_ffi`;
  - UniFFI namespace `siros_dc_matcher_ffi`.

## 4. Components

Dependencies point downward through the layers:

| Layer | Components |
|---|---|
| L0 | codec |
| L1 | DCQL, SD-JWT, mdoc, OpenID4VP, `zkp_req`, nym_auth, trust |
| L2 | wallet state, credential, display, transaction data |
| L3 | presentation |
| L4 | wallet (provers), facades, picker |

A component MUST NOT depend on a component of its own or a higher layer, except these:
- Every other L1 component may depend on DCQL, for the request vocabulary it holds (Q5).
- nym_auth depends on `zkp_req`, mdoc, OpenID4VP and trust.
- Credential depends on wallet state (C1).
- Transaction data depends on credential and display.
- Display depends on credential and wallet state.
- Within L4, a facade depends on the components it exposes.

### 4.1 Host (each platform)

**Responsibility:**
- network transport, persistent storage and the private data container;
- key custody and signing through wscd;
- OS registration (Credential Manager, IdentityDocumentServices);
- the attested calling origin and app;
- the clock, randomness and the user interface.

**Requirements:**
- **H1.** It MUST resolve the URLs the core lists and transmit the bodies it returns, under F5.
- **H2.** It MUST answer `Trust` effects with the AuthZEN verdict for the stated subject and key material.
- **H3.** It MUST sign exactly the bytes a `Sign` effect states, with the key it names, and report that key's authentication factors (`amr`) before signing.
- **H4.** It MUST supply the decrypted wallet state, the display and transaction metadata it holds (signed credential metadata JWTs, type metadata and referenced documents, issuer key sets, each with the URL that served it, and the URLs that serve no document), the wallet's language, the current time, the circuit artifacts it ships, and the trust store it provisions (TR1, TR4).
- **H5.** It MUST append the presentation record the core returns as a `new_presentation` event (privatedata §6).
- **H6.** It MUST render the views the core returns and return the user's selection.
- **H7.** It MUST NOT interpret protocol data, choose credentials, choose claims, choose a proof system, or build a presentation.

### 4.2 Codec

**Responsibility:**
- strict CBOR (definite lengths, no duplicate keys, no trailing bytes, depth limit);
- strict JSON (a repeated member name is an error);
- base64url;
- hash and JOSE algorithm identifiers, and the ES256 signature value;
- the internals several L1 components share: the member fault of a decoded structure, the macros that define value newtypes, and the DER certificate chain that mdoc `x5chain` and SD-JWT `x5c` carry.

**Contract:**
- It accepts bytes or text.
- It guarantees that a decoded value is canonical-strict, and that encoding the value back gives the same bytes.
- It is the only CBOR and base64url implementation in the core.

### 4.3 DCQL

**Responsibility:** the DCQL query model (OpenID4VP §6.1–6.3), claims path pointer resolution (§7.1), and evaluation over any credential (§6.4).

**Requirements:**
- **Q1.** `DcqlQuery` MUST be constructible only by parsing.
  - The parse enforces identifier syntax and uniqueness, non-empty `credentials`, `claim_sets` that refer to claim ids, and `credential_sets` that refer to query ids.
  - `trusted_authorities` is a non-empty array of entries, each with a string `type` and a non-empty array of string `values` (§6.1.1). The `zkp_req` component reads it from here.
  - Today's public `validate()` and public fields go; the change is a breaking version of the crate.
- **Q2.** Evaluation MUST implement §6.4: claim presence, `claim_sets` (first satisfiable), `values`, `credential_sets` (`required`) and `multiple`.
- **Q3.** `meta` and `format` are judged by a policy the presentation component supplies.
- **Q4.** §7.1 resolution MUST have its only implementation here. It is generic over a claim tree node: an object member by key, an array element by issued position (which may be withheld), and the present elements of an array. An index on a withheld position selects nothing; `null` takes the present elements. Every format tree uses it.
- **Q5.** DCQL holds the request vocabulary the other L1 components share: `QueryId`, the claims path, the credential type identifiers `DocType` and `Vct`, and `trusted_authorities`.

### 4.4 SD-JWT

**Responsibility:** reading a stored SD-JWT VC, selecting disclosures, and building the presentation and the KB-JWT signing input.

**Requirements:**
- **S1.** Parsing MUST enforce RFC 9901 §7.1:
  - digests are unique;
  - every disclosure is referenced;
  - no reserved claim name is used;
  - `sd_alg` is supported.
- **S2.** The claim tree MUST keep issued array positions. An array digest without a disclosure, a decoy among them, is a withheld element at its position (SD-JWT VC §5.6).
- **S3.** For a set of pointers, selection MUST include the disclosure of every selectively disclosed node on each path, its parents and its descendants (a claim is selected with its sub-claims, §7.3), each once, resolving pointers through Q4. An empty pointer set selects no disclosure.
- **S4.** The KB-JWT payload MUST be:
  - `iat`, `aud`, `nonce`;
  - `sd_hash`, computed over the presentation exactly as sent;
  - the claims the member's transaction bindings give (§7).

  A claim name that collides MUST be an error.

### 4.5 mdoc

**Responsibility:**
- reading a stored mdoc (base64url of an `IssuerSigned`, a `Document`, or a single-document `DeviceResponse`);
- selecting elements;
- building `DeviceResponse` and the DeviceAuthentication signing input;
- the issuer chain (`x5chain`).

**Requirements:**
- **M1.** Parsing MUST yield the document type, namespaces with their items, and the MSO (validity, device key, value digests, key authorizations). It MUST keep each `IssuerSignedItemBytes` verbatim.
- **M2.** A response MUST carry exactly the selected items, in their issued bytes, with `issuerAuth` verbatim. `deviceSigned.nameSpaces` MUST hold exactly the member's `DeviceSigned` transaction elements.
- **M3.** A `DeviceSigned` element that the MSO `KeyAuthorizations` do not authorize MUST NOT be presentable (B.2.1).

### 4.6 OpenID4VP

**Responsibility:**
- request intake for redirects and the DC API;
- client identifier prefixes and request object verification;
- handovers and SessionTranscripts (B.2.6), JWK thumbprints;
- `vp_token`, response encryption, submissions and error responses.

**Requirements:**
- **P1.** `VerifiedRequest` MUST be constructible only by intake. Intake has two effects:
  - the request object of a request by reference, named by its `https` `request_uri` (RFC 9101 §5.2) and its `request_uri_method`. The host answers with the text it obtained, at most 256 KiB;
  - the trust evaluation of the verifier. The host answers with its verdict.

  The existence of a `VerifiedRequest` guarantees:
  - the request object signature verifies under the rule of its client identifier prefix (`x509_san_dns`, `x509_hash`, `decentralized_identifier`, `verifier_attestation`, `openid_federation`; `redirect_uri` for unsigned requests only);
  - the outer and inner `client_id` are equal;
  - a trust verdict was obtained for the client identifier, or for the origin of an unsigned DC API request;
  - `nonce` is present;
  - the response mode belongs to the channel (`direct_post*` over redirects, `dc_api*` over the DC API);
  - a redirect response has a `response_uri`;
  - a signed DC API request lists the calling origin in `expected_origins`;
  - an encrypted mode has a chosen key and `enc`;
  - for `openid4vp-v1-multisigned`, the client identifier is that of the first signature that qualifies.
- **P2.** `UnverifiedRequest` MUST be the only request type the picker can construct, and the only one it accepts. It guarantees a supported protocol and a data shape that matches the protocol label.
- **P3.** For `request_uri_method=post`, intake MUST state the wallet's `wallet_metadata` and the `wallet_nonce` it chose, as values and as the form parameters of §5.10, and MUST require the request object to echo the nonce.
- **P4.** A submission MUST take the form of its response mode:

  | Mode | Form |
  |---|---|
  | `direct_post` | `vp_token`, `state` |
  | `direct_post.jwt` | `response` |
  | `dc_api` | `{vp_token}` |
  | `dc_api.jwt` | `{response}` |
  | `direct_post.cwt` (`zkp_req.md` §6.2) | an `application/cwt` body: a `COSE_Encrypt` of the CBOR Authorization Response |

  JWE encryption is ECDH-ES with the request's first supported `enc` (A128GCM, A256GCM); A128GCM when none is stated. `direct_post.cwt` uses COSE ECDH-ES + HKDF-256 (-25) with AES-GCM from the same list (A128GCM, A192GCM, A256GCM), and its handover thumbprint is that of the key it encrypted to.

  A submission is data: its response mode, its target (the `response_uri`, or the DC API return), and its parameters (`vp_token` or `error`, `state`, or the encrypted `response`) as typed values, with the form parameters or the `COSE_Encrypt` body built.
- **P5.** A refusal MAY produce an error submission only when the response target is verified.
- **P6.** The core MUST read the body the Response URI answers a direct post with (§8.2): a JSON object of at most 64 KiB, whose `redirect_uri`, when present, is an absolute URI.

### 4.7 `zkp_req`

**Responsibility:**
- the protocol layer of `zkp_req.md`: the query (`_req`, `_req_sets`), `vp_formats_supported.zkp_req`;
- the usable pair of a system and a proof backend (§1.3);
- the consent model (§5), presentations and `vp_token` entries (§4, §6.1);
- the verifier's structural checks.

**Requirement:** `ZkpReqQuery` and `ZkpFormats` MUST be constructible only by parsing.

### 4.8 nym_auth

**Responsibility:**
- the function catalogue (`pseudonym`, `age_check`);
- the systems `urn:circuits:longfellow:nym_auth:v1` and `urn:circuits:vega:nym_auth:v1`, with their circuit pins (system rulebooks §8);
- the session binding and its stricter channel policy (signed requests, encrypted responses);
- the credential tests of system rulebooks §7;
- the proof statement and prover interface;
- the verifier.

**Requirements:**
- **N1.** `NymAuthQuery` MUST be constructible only from a `ZkpReqQuery` that satisfies the catalogue. This replaces today's `catalogue::validate`.
- **N2.** `NymAuthRequest` MUST be constructible only from a `VerifiedRequest` that meets the nym_auth policy: `openid4vp-v1-signed` over the DC API, a positive trust verdict for the Client Identifier, an encrypted Response Mode with its key. The `verifier_id` MUST derive from the request's authenticated certificates in the form the trust framework fixes (catalogue, "Verifier identity"). The host supplies only the form. This replaces the host-asserted `signed` flag of today's `check_request`.
- **N3.** The credential tests (form, issuer signature, listed digests, validity at `proof_time`) MUST be the constructor of a tested-attestation witness. A usable-attestation witness MUST be constructible only from a tested attestation and the `AdmittedIssuer` (TR3) of the same Document Signer certificate for the same query. Proving MUST require the usable witness.
- **N4.** `OpenedSeed` MUST be constructible only from a delivered `secret_seed` whose SHA-256 equals the credential's `ssc`. It is constructed again for each use (privatedata §5A.2), and the prover job MUST require it. This replaces today's `opens_ssc -> bool`.
- **N5.** A system is available exactly when its circuits are loaded through the pinned `load` (digest and length). Circuits are data shipped with each build.

### 4.9 Wallet state

**Responsibility:** the decrypted `S` of the private data container, as input.

**Requirements:**
- **W1.** Parsing MUST accept `schemaVersion` 3 and 4, with absent meaning 1, and refuse any other.
- **W2.** It MUST require unique `credentialId`s held as 64-bit integers, and the eight members of §6.0 per entry. It MUST keep `metadata` entries verbatim.
- **W3.** It MUST expose credentials, presentations (for usage counts) and key identifiers.
- **W4.** The presentation record the core returns MUST have the members of `new_presentation`: `presentationId`, `transactionId`, `data`, `usedCredentialIds`, `presentationTimestampSeconds`, `audience`.

### 4.10 Credential

**Responsibility:**
- the format-independent credential: entry reference (credential, batch, instance), format, type (`vct` or doctype), issuer, configuration id, validity, key identifier, delivered auxiliary data;
- the typed claim tree, with a disclosure handle per node;
- claims path pointer resolution (§7).

**Requirements:**
- **C1.** A credential MUST be constructible only by parsing a wallet state entry through the format components. An unsupported format is an error. The parse includes the issuer chain (TR2).
- **C2.** Claim values MUST keep their type: null, boolean, integer, number, text, bytes, full-date, date-time, array, object. The credential reads them from the format's own tree; it keeps no copy of the claims.
- **C3.** Pointer resolution goes through Q4 for JSON-based formats, and through §7.2 (`[namespace, element]`) for mdoc. A pointer MUST be constructible only by parsing, and is never empty.
- **C4.** `UsableCredential` MUST be the witness of validity at a given time: `not_before ≤ now < not_after`, from the MSO or from `nbf`/`exp`.
- **C5.** The instance used for a batch MUST be the instance named least often in the wallet's presentation records, the lowest `instanceId` on a tie.

### 4.11 Display

**Responsibility:**
- display metadata (OpenID4VCI `credential_metadata`, SD-JWT VC type metadata) and its resolution per locale;
- credential cards and claim rows;
- purpose lines (§6.2 `purpose`);
- proof statement rows.

**Requirements:**
- **D1.** It is the only metadata merger: it MUST remove `auxiliary_data` before any merge (privatedata §5A.3).
- **D2.** Each display array MUST resolve by PaSO View §4: RFC 4647 Lookup with the wallet's language, then the entry without `locale`. The format-specific display falls back to `credential_metadata` per language (D3). One function serves credential display and transaction data.
- **D3.** Format-specific display (SD-JWT VC type metadata) wins over OpenID4VCI `credential_metadata`, which is the fallback (OpenID4VCI 1.0 §12.2.4).
- **D4.** Values MUST be typed for display (null, text, boolean, integer, number, date, date-time, bytes, list, group). The UI formats dates and numbers for its locale.
- **D5.** A credential claim's bytes are shown by their length.

### 4.12 Transaction data

**Responsibility:** the `transaction_data` request parameter (§5.1), transaction data type definitions and their sources, their projection to the wallet's language, the selection of one entry per credential, the generic rendering, images, and the bindings (§8.4). The model is PaSO draft-2 (Core, View, Proof Metadata, the SVG module).

**Requirements:**
- **T1. Entry.** An entry MUST be parsed from base64url JSON with no duplicate keys: a string `type`, a non-empty `credential_ids` naming DCQL query ids, a `payload`, and an optional ad-hoc `metadata` JWT. `transaction_data_hashes_alg` is a JSON array (§5.1) or a single string, read as a one-element list.
- **T2. Definitions.** A definition is a PaSO `transaction_data_types` entry (Proof Metadata §3): claims with a payload path, `mandatory`, `value_type` and `display`, and `ui_labels`. Its parse checks every locale, with the limits of its source: PaSO §3.3 for PaSO and configured definitions, TS12 §3.3.3 for TS12 ones. The sources, for one type and credential:
  - ad-hoc metadata in the entry, verified per Proof Metadata §5.3; a failure makes that entry incompatible, with no fallback;
  - the credential's own metadata: a PaSO signed credential metadata JWT, verified at every load (§7, and §8 against the URL that served it), or TS12 v1.0.1 SD-JWT VC type metadata with its `#integrity` pins. Invalid or unheld metadata excludes the credential for every entry;
  - the host configuration: a definition and the credential types (`vct`, doctype) it applies to. It serves only credentials without transaction metadata of their own; an https `vct` whose metadata the host neither holds nor observed absent is an error.
- **T3. Projection.** A definition is projected to the wallet's language (D2): each array keeps the entry its locale selects, and a type with an unmatched array is unsupported by the credential. The projection removes the other locales and keeps everything else, with its source kind and rulebook, and serializes canonically.
- **T4. Selection** (PaSO Core §7.4):
  - the query ids the entries target lie in one credential set, and its alternatives are transposable;
  - each candidate credential takes the first entry, in array order, that targets it, whose type it supports, whose payload conforms (Core §7.4.2, View §3), and whose resources verify; a credential without one is excluded;
  - an entry that no chosen credential takes stays unused; a type that no source defines for any candidate is `TypeUnknown`;
  - the binding names the credential by `credentialId` and instance; the view shows it, the plan digest covers it with its source and rulebook, and phase 2 binds by it.
- **T5. Rendering** follows View §2: claims order, the `null` rule, single-pass templates carried as typed segments, at most 200 items counted before any image is resolved, `security_hint` as given. The UI re-checks each formatted label's limit. An entry that cannot render in full is incompatible.
- **T6. Images.** The core resolves and verifies no image: it checks an image value's form and carries it in the consent view, for the UI to resolve, verify and render statically. The form is a Data URL whose encoded size is at most 512 KiB, or an `https` URL with a `#integrity` sibling of SRI syntax (a TS12 logo may lack it). Over the DC API an image is a Data URL in a format Credential Manager decodes (PNG, JPEG); otherwise a PaSO entry is incompatible and a TS12 logo is left out.
- **T7. Output.** Transaction data binds into SD-JWT VC only. A query that sets `require_cryptographic_holder_binding: false` refuses the request (B.3.3). A KB-JWT carries the B.3.3.1 hashes of the entries bound to its credential, over each entry string as received, with one algorithm; `transaction_data_hashes_alg` is returned when the request carried it. The TS12 v1.0.1 rulebook adds `jti`, `response_mode` and `amr`.
- **T8. Signed requests.** An entry a PaSO-sourced definition serves requires a signed request (Core §3). An unsigned request with TS12 entries carries TS12's warning in the view.
- **T9. Metadata is input.** The host holds and renews the metadata outside presentations (Proof Metadata §6, §8). The core gives it the verification of a JWT with the URL that served it, and the list of documents it still wants.

### 4.13 Presentation

**Responsibility:**
- **Phase 1:** the plan of a verified request (or an unverified one, in the picker) over the wallet's credentials, and the consent view.
- **Phase 2:** the selection, the signing inputs, the response and the presentation record.

**Requirements:**
- **A1. Matching rules.**
  - Format table: `mso_mdoc` from `mso_mdoc`; `dc+sd-jwt` from `dc+sd-jwt`; `zkp_req` from its `meta.source_format`.
  - `meta.doctype_value` and `meta.vct_values` are matched against the credential type.
  - Holder binding holds when the credential has a key.
  - A credential whose issuer the query's `trusted_authorities` do not admit (TR3) matches nothing, in every format (§6.1, §6.4.2).
  - Only usable credentials are offered (C4).
  - No query other than `zkp_req` may disclose a nym_auth undisclosable attribute.
  - Any other format, `mso_mdoc_zk` included, matches no credential.
  - `zk_system_type`, `zk_required` and `ppid_context` are unknown `meta` properties. They are ignored, as OpenID4VP §6 requires for unknown properties.
- **A2. `zkp_req` matching** MUST be one selection. It takes the options in the verifier's order and, for each, the first available system whose usable pair the verifier accepts. It then requires a usable-attestation witness and an `OpenedSeed` for the credential (N3, N4).
- **A3. Offers.**
  - Each combination of the required credential sets is an offer.
  - Optional sets are additions the user may choose on top of an offer, at most one option per set.
  - Each member a transaction entry targets holds the entry T4 selects for it.
  - When every set is optional, each option is an offer.
  - An offer whose members' or additions' claims or proof statements cannot be displayed (D-rules, A9's rows) is left out; the other offers keep their order. When no offer remains, the plan fails with the first display error.
  - Each member names its query, its instance (C5), its answer (SD-JWT pointers, mdoc elements, or the `zkp_req` system, backend and option) and the transaction entries bound to it (T4).
  - The member of a `multiple` query holds every candidate. The selection chooses a non-empty subset of them, naming each chosen credential by its `credentialId`.
- **A4. Plan binding.** A plan MUST carry a digest of what the user consents to:
  - the request's response mode, client identifier, trust verdict, origin, response URI, `nonce`, `state`, `dcql_query` and `transaction_data`, and the nym_auth `verifier_id` when there is one;
  - for each offer: its members with their instances and answers, its additions, the transaction entries bound to each member, and its A9 outcome.

  The time, the display metadata and the presentation records stay out of it, so phase 2 can run later on the same plan. A selection MUST be parsed against the recomputed plan into a chosen-offer witness. A digest mismatch, an unknown offer, or an out-of-range optional choice is an error.
- **A5. Signatures.** Phase 2 MUST state every signing input as a `Sign` effect. The signatures returned MUST be parsed against those requests: none missing, none duplicated, none unknown, and each one verifying under the key its request names.
- **A6. Audience.** The SD-JWT `aud` is `prefix:value` of the client identifier for redirects. Over the DC API it is `origin:<origin>`, signed requests included (OpenID4VP A.4).
- **A7. SessionTranscript.** The mdoc and nym_auth SessionTranscript uses `OpenID4VPHandover` (client id, nonce, encryption key thumbprint or null, response URI) for redirects. It uses `OpenID4VPDCAPIHandover` (origin, nonce, thumbprint or null) for the DC API.
- **A8. Response.**
  - One `vp_token` answers every member of the chosen offer and its chosen additions, keyed by query id, whatever the formats.
  - A user's decline gives `access_denied`.
  - The presentation record names exactly the instances used.
- **A9. Wallet display.** An offer needs the wallet's display unless all of these hold:
  - every member credential is registered as presentable without the wallet's UI (the wallet declares it per credential: its key signs without user interaction and its background service answers);
  - the request carries no `transaction_data` (the wallet renders it, T5);
  - every disclosed claim and every proof statement of the offer has a display row, and no row is clipped;
  - the offer has no optional additions to choose, and no `multiple` query with more than one candidate.

  The picker applies the rule to choose delegation (K4). The wallet applies it to a background fulfilment: an offer that needs its display is refused there with `access_denied`.

### 4.14 Wallet, facades and the cloud engine module

**Responsibility:**
- linking the provers in-process (Longfellow and Vega backends);
- exposing the core to Kotlin and Swift (UniFFI), the browser (wasm-bindgen) and Go (a `wasm32-wasip1` module run under wazero, because go-wallet-backend builds with `CGO_ENABLED=0`);
- the HTTP adapter `siros-http`, a facade-level crate built in the facades wave: it resolves the URLs the core lists and transmits the bodies it returns.

**Requirements:**
- **F1.** Every facade MUST expose the same operations with the same wire form of every record, so a record serialises identically on every binding.
- **F2.** Records crossing a facade MUST be parsed into core types at the boundary.
- **F3.** The cloud engine module MUST expose intake and submission only. It holds no credentials and no keys.
- **F4.** `secret_seed` MUST stay inside the process from the wallet state to the proof.
- **F5. HTTP.** `siros-http` MUST apply these rules, and so MUST every host that does its own HTTP:
  - every request: `https` only, public addresses only, a 10-second timeout, and no cookies, credentials or headers that identify the wallet (OpenID4VP §15.6, §15.8);
  - the request object: a `GET` of `request_uri`, or for `request_uri_method=post` a `POST` of the form parameters intake states, with `Content-Type: application/x-www-form-urlencoded`; `Accept: application/oauth-authz-req+jwt` (§5.10); no redirects (RFC 9101 §10.4.1); status 200 and the media type `application/oauth-authz-req+jwt` (§5.10.1, §5.10.2); at most 256 KiB read, as UTF-8 text;
  - a submission: a `POST` of its body to the `response_uri`, as `application/x-www-form-urlencoded` form parameters or an `application/cwt` `COSE_Encrypt`; no redirects, since a 307 or 308 resends the body to another URI (§8.2, §14.3.1; RFC 9700 §4.12); the reply: status 200 and `application/json` (§8.2), at most 64 KiB read;
  - held metadata, outside presentations: a signed credential metadata JWT with `Accept: application/jwt` and the wallet's language in `Accept-Language`, following redirects, the final URL being the URL that served it (Proof Metadata §8); a URL answering 404 is recorded as serving no document.

### 4.15 Picker

**Responsibility:**
- the Android Credential Manager matcher (`matcher.wasm`) and its host ABI;
- the registration projection the wallet writes for it.

**Requirements:**
- **K1.** The projection MUST hold, per credential: entry reference, format, type, the typed claim tree minus undisclosable attributes, card and labels in the wallet's language, the issuer facts of TR5, and the transaction definitions it supports, projected (T3). Each projected definition is stored once and credentials reference it. It also holds the available system ids, and is versioned. It MUST NOT hold delivered or derived secrets (R-G6).
- **K2.** The picker MUST run the presentation component's matching over an `UnverifiedRequest`. For the same request, credentials, trust store and time, it MUST give the offers the wallet's plan gives, except where the wallet's plan depends on what the projection leaves out: the `zkp_req` credential tests that read undisclosable attributes (N3, for example the `age_check` bounds against `birth_date`), the delivered seed (N4), ad-hoc transaction metadata, the semantic-identifier form of the nym_auth `verifier_id` (N2, which needs the access certificate), the verification of a request's signatures, and so which signature of a multisigned request qualifies (its Verifier metadata and `verifier_info` follow from it), and every fact that holds at registration time. The picker has no clock: issuer admission and certificate validity (TR5), credential validity (C4), and the dates of held metadata hold as of registration. The wallet refuses such an offer with `access_denied` (A9 applies to it as to any other).
- **K3.** Each picker entry's metadata MUST carry the offer, the query id and the `credentialId` of its credential. The wallet builds the selection from the picked entries' ids after its own verified plan. A picked id that the plan's offer does not hold is an error.
- **K4. Delegation.** The picker MUST send `Full` delegation (Credential Manager keeps its UI and the wallet fulfils from its background service) for the entries of an offer that needs no wallet display, and no delegation otherwise. Every entry of one set gets the same type. The rule is A9's, applied with the host's display level: an offer that the host displayed only in part (`display_skipped`) needs the wallet's display.

### 4.16 Cloud engine (go-wallet-backend)

**Responsibility:** the network legs of the redirect flow for the web wallet: resolving the request object, trust evaluation, and delivering the submission.

**Requirements:**
- **E1.** It MUST run intake through the core module.
- **E2.** It MUST send the client the `VerifiedRequest`.
- **E3.** It MUST deliver the client's submission unchanged.
- **E4.** It MUST NOT match credentials, vet consent, or assemble a `vp_token`.
- **E5.** Its HTTP MUST follow F5.

### 4.17 User interface (each platform)

**Responsibility:** rendering views, collecting the selection, locale formatting of dates and numbers.

**Requirement:** it MUST render only what a view contains and MUST return selections in the core's selection form.

### 4.18 Trust

**Responsibility:** the trust store's format, issuer chains, and the resolution of `trusted_authorities` (OpenID4VP §6.1.1) into an admission of a credential's issuer. Provisioning the store is the host's.

**Requirements:**
- **TR1. Store.** The trust store MUST be constructible only by parsing its record: a JSON array of entries `{type, value, certificates}`.
  - `type` is `etsi_tl` or `openid_federation`, and `value` is the authority value as a verifier sends it.
  - `certificates` is a non-empty array of DER certificates in the `x5c` encoding (base64).
  - An unknown `type`, a repeated `type` and `value`, or a certificate that does not parse is an error.
- **TR2. Issuer chain.** The credential's issuer chain is the mdoc `issuerAuth` `x5chain` (every certificate, signer first) or the SD-JWT VC issuer-signed JWT's `x5c` header (leaf first). It parses with the credential. A chain that does not parse is a credential error. An SD-JWT VC without `x5c` has no chain.
- **TR3. Resolution.** For one Credential Query, a credential's issuer is admitted exactly when one of these holds:
  - the query has no `trusted_authorities`;
  - an `aki` value, base64url-decoded, equals the keyIdentifier of the AuthorityKeyIdentifier extension of a certificate in the chain;
  - for an `etsi_tl` or `openid_federation` value, the store has an entry of that type and value, and the chain's first certificate validates up to one of its certificates at the current time:
    - Each certificate on the path is signed by the next one or by the store certificate, names its signer as issuer, and is valid at that time.
    - Every signer is a CA (basicConstraints), and its keyUsage, when present, includes keyCertSign. The intermediate certificates below it on the path that are not self-issued number at most its pathLenConstraint (RFC 5280 §6.1.4 (k) to (n)).
    - A certificate with a critical extension the core does not process is refused (§6.1.4 (o)).
    - Signatures are ECDSA P-256 with SHA-256 or P-384 with SHA-384.
    - A store certificate byte-identical to the chain's first certificate admits it when it is valid at that time.

  An entry of any other type admits nothing. A malformed `aki` value makes the query invalid. Admission MUST be the constructor of an `AdmittedIssuer` witness that names the query and the chain's first certificate.
- **TR4. Provision.** The host supplies the store (H4), with every list, federation statement and certificate in it. The store is global, the same for every request and channel, because the DC API gives the picker nothing per request.
- **TR5. Picker facts.** At registration the wallet resolves each credential against the store. The projection records the credential's AKI keyIdentifiers and the `type` and `value` of every store entry that admits it. The picker admits an issuer from these facts alone, with the same rule. The picker has no clock: its facts hold at registration time (K2). The wallet registers again when the store, the wallet state, the wallet's language or a credential's metadata changes.

## 5. Boundary contracts

| Boundary | Crosses inward | Crosses outward | Guaranteed by the core | Guaranteed by the other side |
|---|---|---|---|---|
| Host ↔ core | wallet state; display metadata; locales; key factors; circuits; trust store; time; effect results (request object texts, trust verdicts, signatures); reply bodies | effects (`RequestObject`, `Trust`, `Sign`); the URLs of the documents it wants; views; submissions as data; presentation records; refusals | R-G2 to R-G7; P1; P3; P4; P6 | H1 to H5 |
| HTTP adapter ↔ verifiers and publishers | request objects; replies; held metadata | request object requests; submissions; metadata requests | P3; P4 | F5 |
| UI ↔ core | selection | consent view: verifier, purposes, offers with cards, rows and proof statements, optional additions, transactions | the view equals the plan; R-G6 | H6, §4.17 |
| Engine ↔ web client | verified request | submission | P1; F3 | E1 to E5 |
| Wallet ↔ picker | the picker's chosen entry | registration projection | K1 to K3 | Credential Manager runs the matcher on the registered projection |
| Core ↔ provers | proof output | proof job with statement, credential and `OpenedSeed` | N3 to N5; F4 | the backend proves exactly the statement it is given |
| Core ↔ container | `S` | `new_presentation` record | W1 to W4 | H5 |
| Core ↔ verifiers | requests | responses | conformance to §2 references | independent verifiers (vc) accept |

## 6. Responsibility per flow

| Flow | Intake | Trust call | Plan and phase 2 | Signing | Delivery |
|---|---|---|---|---|---|
| Redirect, native app | SDK (core) | SDK host to AuthZEN | SDK (core) | wscd | SDK host POSTs |
| Redirect, web wallet | engine (core module) | engine | browser (core) | wscd in the browser | engine POSTs |
| DC API, Android app | SDK (core) | SDK host | SDK (core); picker offers from the projection | wscd | platform |
| DC API, iOS app | SDK (core) | SDK host | SDK (core) | wscd | platform |
| DC API, web wallet | browser (core) | backend AuthZEN | browser (core); on Android the wrapper registers the projection with the picker | wscd | platform |

## 7. Ownership of existing code

| Today | Owner | Change of form |
|---|---|---|
| `siros-dcql` | DCQL | construction by parsing only (Q1) |
| `siros-dc-matcher-core` `request.rs` | OpenID4VP | `UnverifiedRequest` |
| `siros-dc-matcher-core` `evaluator.rs`, `profile.rs` | presentation | the profile becomes code (R-G8) |
| `siros-dc-matcher-core` `purpose.rs` | display | |
| `siros-dc-matcher-core` `db.rs`, `sink.rs` | picker | registration projection (K1) |
| `siros-dc-matcher-core` `base64url.rs`, `siros-zkp-req` `cbor.rs`, `base64url.rs` | codec | one implementation |
| `siros-dc-matcher-core` `circuit_capabilities.rs` | removed | systems in code (N5) |
| `siros-dc-matcher-core` `profile.rs` `mso_mdoc_zk` rule, `MetaTrigger`, `zk_system` capability; FFI `add_zk_system`; picker metadata `capabilities` | removed | the mdoc ZK path is retired |
| `siros-dc-matcher-core` `zkp_req.rs`, `zkp_req_response.rs`, `proof_time.rs` (main) | removed | superseded by `zkp_req` and nym_auth |
| nym_auth `session.rs` (handover, transcript, device message, thumbprint) | OpenID4VP and mdoc | the thumbprint may be null |
| nym_auth `mdoc.rs`, `x509.rs`, `es256_verifies` (generic parts) | mdoc | |
| nym_auth `policy.rs` (generic parts) | OpenID4VP | the nym_auth part becomes `NymAuthRequest` (N2) |
| nym_auth `catalogue::validate`, `checks::check`, `checks::opens_ssc` | nym_auth | constructors of witnesses (N1, N3, N4) |
| nym_auth `presenter::match_query` selection | presentation | one selection (A2) |
| nym_auth `policy::check_request`, `CheckedRequest` and the rules only it reaches; `presenter::match_query`, `plan_option`; FFI `zkp_req_session`, `zkp_req_match`, `zkp_req_prepare` | removed with the FFI (§4.14) | the facades expose the plan; a zero-reference grep gates the removal |
| nym_auth `attestation.rs` `anchors` and the wallet's `chains_to`; FFI `anchors` arguments | trust | the `AdmittedIssuer` witness (TR3, N3) |
| `siros-zkp-req` `TrustedAuthority`, `AuthorityKind` | DCQL | one parse of `trusted_authorities` (Q1) |
| `siros-dc-matcher-wasm`, `-testhost` | picker | |
| `siros-dc-matcher-ffi` | facades (UniFFI) | |
| `proving/` | wallet and facades (web) | |
| `android-credman`, `android-credman-sys` | picker | |

## 8. What each platform keeps

| Platform | Keeps | Its copies the core replaces | Retired with the mdoc ZK path |
|---|---|---|---|
| siros-sdk-kotlin | host (§4.1), UI, Credential Manager registration, wscd | built-in matcher and engine narrowing; claim and disclosure derivation; ZK registry and circuit catalog client; `zkp_req` validators, response validator, `proof_time`; DC API request parsing and rules; response encryption; transaction data pipeline; registration blob builders | `ZkMdocPresentation`, `LongfellowZkProofSystem`, `VegaProofSystem`, `LegacyZkCircuitZkAdapter`, `CircuitZkLegacyDisclosure`, the PPID context |
| siros-sdk-swift | host, UI, wscd | the same, plus the `ZkpReq` and `CircuitZk` ports | `ZkProofSystem`, `LongfellowZkProofSystem`, `VegaProofSystem`, the PPID `verifier_context` |
| siros-wallet-frontend | UI, transport to the engine, DC API transport, wscd host | `dcql` matching, consent field model, SD-JWT and mdoc builders, DC API request reading and encryption | on the ZK branch, `restoreZkFormat`, the `mso_mdoc_zk` route and `NativeBridgeZkDeviceResponse` |
| go-wallet-backend | network legs, trust evaluation, storage | OpenID4VP parsing in the engine, consent vetting, `vp_token` assembly, `match_request` | `verifier_session_id` forwarding |
| wallet-android-wrapper | WebView host, Credential Manager registration | the stock-matcher entry builder | none |
| wallet-ios-wrapper | WebView host | none | none |
| vc (SUNET, through a PR) | its verifier and issuer | none | the parts its `zkp_req` stack does not use: `mso_mdoc_zk` and `zk_system_type` in DCQL handling (`pkg/openid4vp/dcql_zk.go`, `dcql.go`, `pkg/helpers/validate.go`, the verifier UI), the mdoc ZK verifier and PPID `verifier_context` (`pkg/mdoc/zk_verifier.go`, `zk.go`), the circuit catalog client (`pkg/mdoc/zkcircuit`), the issuer ZK salt (`internal/issuer/apiv1/zk_salt.go`), and `developer_tools/scripts/vendor_zk_circuits` |

## 9. Acceptance requirements

The core meets this document when all of the following hold:

1. **One vector suite.** It covers requests, wallet states, display metadata, systems and effect results, mapped to plans, views and submissions. It gives identical outputs through UniFFI (Kotlin and Swift), the browser build, the Go module (intake and submission) and the picker (offers).
2. **Independent verifiers.** vc's verifiers accept the core's responses for every flow of §6 and every format of §1.
3. **Spec examples.** The examples of RFC 9901, OpenID4VP §7 and Appendix A, ISO/IEC 18013-5 Annex D, and RFC 7518 Appendix C give their stated results.
4. **Wallet against picker.** The picker's offers equal the wallet's offers on every plan vector.
5. **No secrets.** No view, projection or error of the vectors contains a delivered seed, a derived secret or an undisclosable attribute.
6. **No copies.** No platform in §8 keeps DCQL evaluation, claims path resolution, disclosure selection, proof system choice or response assembly (a grep per repository).
7. **Picker size.** `matcher.wasm` ≤ 409,600 bytes (400 KiB).
8. **mdoc ZK retired.** `mso_mdoc_zk`, `zk_system_type`, `zk_required` and `ppid_context` have no reference left in the core, the platforms of §8 or vc, outside changelogs.

## 10. Decisions

**Taken:**

| Decision | Reason |
|---|---|
| Sans-IO with host effects | One shape for UniFFI, the browser, the WASI module and the picker |
| Go runs a WASI module under wazero | go-wallet-backend builds with `CGO_ENABLED=0` |
| Native apps run the redirect flow on device | The backend's own "local engine" model; the web keeps the cloud engine for CORS |
| Matching rules in code | The picker and the wallet ship in one AAR |
| Provers in-process; circuits pinned and loaded as data | The existing system pins; keeps `secret_seed` in-process |
| Wallet state input is the decrypted `S` | The container is the next brick |
| All-optional `credential_sets` offer each option | Today such a request offers nothing (vc's issuance-auth query has this shape) |
| Transaction data types own their bindings | OpenID4VP §8.4; Appendix B is a set of recommendations to type authors |
| The mdoc ZK path (`mso_mdoc_zk`, `zk_system_type`) is retired everywhere | Owner's decision, 2026-10-26; `zkp_req` covers proof presentations |
| Issuer trust: the core owns the store's format and the resolution; the host provisions one global store | Owner's decision, 2026-10-26; the DC API picker receives nothing per request. AuthZEN issuer evaluation stays a hook, to be built in the core when it is taken up |
| DCQL holds the shared request vocabulary; codec holds the shared internals | Owner's decision, 2026-10-27; one newtype per value across L1 |
| TR3 applies RFC 5280's keyCertSign, pathLenConstraint and critical-extension rules, and admits a store-listed issuer certificate | Owner's decision, 2026-10-27; the wallet offers only what a verifier's path validation admits |
| Transaction data follows PaSO draft-2: one definition form, sources by precedence, one wallet language, first match per credential, TS12-compatible output | Owner's decision, 2026-10-27; the configuration serves only credentials without metadata of their own |
| The picker's issuer facts hold at registration time | Owner's decision, 2026-10-27; `matcher.wasm` has no clock. The wallet refuses an offer whose issuer is no longer admitted |
| The core is pure and offline: it lists the URLs it needs and returns the bodies to send; HTTP lives in the facade-level `siros-http` | Owner's decision, 2026-10-27; library users such as the picker provide URL resources from data they hold |

**Open:** none.
