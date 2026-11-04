# Engine dependencies: the evaluation

The engine core's library choices, evaluated before the spike opens so S2
builds on decided ground. Sources: the crates' READMEs, manifests and
released APIs (read 2026-11-02; jose-rs 0.10, kryptering 0.7, grindvakt
0.10), this workspace's own usage of them (siros-verifier-core), and the
ported wallet-core crates. Nothing here was executed; the spike's vectors
are the referee.

## The decision table

| Need | Choice | Why |
| --- | --- | --- |
| JWS/JWE/JWK/JWT | **jose-rs 0.10** | The only full JOSE layer in pure Rust the org already ships. Covers every algorithm the engine touches: ES256/ES384/Ed25519 signing; ECDH-ES and ECDH-ES+A128/256KW on P-256/P-384/P-521/X25519; A128/A256GCM and CBC-HMAC content encryption; RFC 7638 thumbprints; compact and JSON serializations. Security posture matches our rules without modification: duplicate-member rejection, `crit` enforcement, `jku`/`x5u`/`jwk` headers refused by default when emitting, CEK zeroization, private-field redaction, a 1 MiB token cap, and `jwt::decode_unverified` deprecated. BSD-2-Clause, no unsafe, no async, no network, no filesystem in the library. |
| Key custody (server) | **kryptering 0.7** | jose-rs's crypto backend; the HSM path the server adapter wants for DPoP and signing keys. The `pkcs11` feature is default-on in jose-rs — the engine core pins `default-features = false` like siros-verifier-core does, so the picker/embedded builds stay software-only and the server adapter re-enables it. |
| DPoP (RFC 9449) | **grindvakt 0.10 `dpop`** | A DPoP module with a pluggable replay store and optional stateless server nonces, on jose-rs. What it does **not** give: it is provider-and-client shaped — the engine needs only the *client-side proof builder* (`htm`/`htu`/`ath`/`iat`/nonce, ES256 over the JWK thumbprint). Evaluate reusing `dpop`'s proof construction directly; if the coupling to its `http::HttpClient` model is awkward, the proof builder is small enough to write in the core against jose-rs, and that is the expected outcome. |
| PAR client (RFC 9126) | **write in the core** | grindvakt's RP flow does authorization-request-and-code-exchange; a PAR *client* (push the request object, get `request_uri`) is not its shape. The engine's PAR need is one signed request object and one POST — jose-rs signs the object; the transport goes through the engine's `HttpClient` port. |
| X.509 path validation for signed metadata | **rustls-webpki** (server adapter) + **x509-cert** (parsing) | The spec's named base. The wallet-core's own `siros-trust` (this workspace) already implements the wallet-side chain admission (`IssuerChain::parse`, `TrustStore`, `admit`, RFC 5280 basicConstraints/keyUsage/pathLen/critical-extension rules, `aki` matching) — the *engine's* signed-metadata validation reuses that discipline where the trust model is the verifier's, and webpki where it is a TLS-grade chain. Decide per validation site during S1; both are RustCrypto-family. |
| OAuth/OIDC client semantics | engine's own | grindvakt covers discovery, code exchange, id_token verification and userinfo — provider and RP side. The engine core is neither: it is a *wallet* talking to arbitrary issuers under WMP. Take nothing from grindvakt here; the engine's authorization-server metadata discovery is already specified per-vector. |

## What the ported wallet-core crates already provide

The engine should consume these before writing anything:

| Crate | What it gives the engine |
| --- | --- |
| `siros-openid4vp` | Every OpenID4VP rule: arrival, authentication, DCQL, matching, the response and its sealing through the `Haip` module the engine implements; JSON and CBOR with distinct member names. |
| `siros-trust` (`chain`) | Issuer chains from `x5c`/`x5chain`, path validation with the RFC 5280 rules, admission witnesses — the local-trust seam the engine's guarantee-level enum leaves open. |
| `siros-sdjwt`, `siros-mdoc`, `siros-x509` | The plug-ins the engine's builds register with the core. |

## The jose-rs caveats the vectors must cover

The evaluation found no gap that blocks the engine, and four behaviours the
vectors should pin:

1. **ECDH-ES is single-recipient, by design** (its ADRs 0016–0018), with
   origin authentication explicitly out of scope — the engine's
   response-encryption threat model (the issuer chose the key) is exactly
   the intended use; the vectors should still assert the `epk` is fresh per
   message.
2. **`x5c` emission is opt-in** (`allow_key_reference_headers`) — the engine
   building DPoP proofs or client assertions never emits it by default;
   signed-metadata *verification* reads `x5c` through jose-rs's parse path
   plus siros-trust's chain discipline.
3. **`decode_unverified` is deprecated and for inspection only** — the
   engine's parse-before-trust steps (reading `kid` to select a verifier)
   use it knowingly, and never treat its output as verified.
4. **The `rsa` Marvin advisory (RUSTSEC-2023-0071)** is open upstream;
   kryptering 0.7 blinds and jose-rs collapses the failure classes, and
   the engine prefers EC key management everywhere the peer allows it.
   Recorded in `deny.toml` posture, re-checked at the audit gate.

## Maintenance and risk

- All three crates are 0.x, single-maintainer (Kushal Das), BSD-2-Clause,
  with an unusually serious engineering process for 0.x libraries (ADRs,
  RFC 7520 interop vectors, fuzz corpus, `definition-of-done`, audit
  config) — the same evaluation the spec asked for, and better than most
  1.0 Rust crypto. siros-verifier-core already ships on jose-rs 0.10 in
  production, so the bus-factor risk is shared, not new.
- Version pinning: exact caret pins in the workspace manifest, `cargo
  audit`/`cargo deny` in CI (the audit gate the spike report must run),
  and the upgrade path is one PR because jose-rs is the only JOSE
  dependency.
- The engine's remaining write-its-own list, after this evaluation:
  the PAR client, the DPoP proof builder (unless grindvakt's lifts out
  cleanly), the X.509 validation-site decisions, the OpenID4 flow logic
  itself, and the resolvers. Nothing else.
