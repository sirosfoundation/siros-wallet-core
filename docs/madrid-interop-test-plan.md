# Madrid interop — SIROS test plan

**Event:** QERDS interop test, Madrid, 24–25 November 2026
**Environment:** GDC (`sirosid-gdc-wallet-proxy.fly.dev/wmp-engine/`), wallet-core **v0.3.2** deployed, Kotlin SDK **v0.23.9** (PR #427)
**Ladder:** the tracker's levels 0–6, "done when two different implementations pass together"

---

## Pre-flight (before Tuesday)

| # | Check | How | Owner |
|---|---|---|---|
| 1 | Engine reachable over HTTPS/TLS1.3 from outside | `curl https://sirosid-gdc-wallet-proxy.fly.dev/wmp-engine/healthz` → 200 | us |
| 2 | Well-known config served (0.2) | `curl …/wmp-engine/.well-known/wmp-configuration` → the supported_versions/endpoints/capabilities/security_modes doc | us (PR #85 → v0.3.3 deploy) |
| 3 | Principal tokens mint + validate on the deployed engine (tenant mode) | `node scripts/mcp-capability-probe.mjs` → session created, `mcp` negotiated | us |
| 4 | MCP round-trip on the deployed engine | `node scripts/mcp-roundtrip-probe.mjs` → `tools/list` + `tools/call wallet.debug.status` answer | us |
| 5 | Full acceptance chain engine-side | `node scripts/mcp-acceptance-rehearsal.mjs` → all six steps GREEN | us |
| 6 | Phone APK carries PR #427 (invite QR + group-invite + i18n) | dex string scan (`grep -c 'create cancelled (left the page)'`) | us + realeyes |
| 7 | Participant ID agreed in Slack (ICD + value) | — | **Slack, blocked** |
| 8 | Test trust anchor decided (which CA signs subscriber + QTSP certs) | — | **Slack, blocked** |
| 9 | Registry PR (level 0.3) | `siros-participant-draft.yaml` (value swapped once #7 agrees) → kjorlaug/webuild-smp | us after #7/#8 |
| 10 | Cleverbase's QERDS reachable | `curl https://erds-wb.business-sandbox.cleverbase.io/.well-known/wmp-configuration` | verified 2026-11-20 ✓ |

## Level 0 — ready to test

| Step | Ours | Test | Pass criterion |
|---|---|---|---|
| 0.1 endpoint online | ✅ | healthz through the proxy from a public network | 200 |
| 0.2 wmp-configuration | ✅ (PR #85) | fetch the doc; validate against our own `discover_config` | parses, `supported_versions: ["0.1"]`, endpoints |
| 0.3 registered | ⚠️ blocked on ID | merge our YAML in webuild-smp; CI validates + publishes + DNS | smoke test passes |
| 0.4 test identity | ⚠️ blocked on CA | mint the cert with the participant ID in the SAN | cert verifies under the agreed CA |

## Level 1 — find each other

| Step | Ours | Test | Pass criterion |
|---|---|---|---|
| 1.1 BDXL lookup | client-side only | resolve `0106::67419925` (Cleverbase) / `991825827` (example) via the NAPTR → SMP URL | the SMP URL answers |
| 1.2 read metadata | client-side | fetch + verify the signed ServiceMetadata; pick the `webuild-transport-wmp-v1` endpoint | signature verifies, endpoint resolves |
| 1.3 not-found handled | ✅ | `wmp.resolve` of an unregistered participant | `-32601`-shaped refusal, no crash |

## Level 2 — wallet ↔ QTSP (the realistic target)

| Step | Ours | Test | Pass criterion |
|---|---|---|---|
| 2.1 open a session | ✅ **live-proven** | `createSession` (tenant-mode token, `sub` set) | session id answered |
| 2.2 hello world | ✅ **live-proven** | `sendMessage` → poll + SSE both sides | the text arrives both paths |
| 2.3 reconnect | ✅ | resume with the token after a disconnect | queued messages replay |

*Test mode (agreed in the ladder): no MLS required at level 2; sessions run `tls`.*

## Level 3 — two wallets, one QTSP

| Step | Ours | Test | Pass criterion |
|---|---|---|---|
| 3.1 resolve recipient | ✅ | `wmp.resolve` participant + `mls_key_packages` (advertised in the well-known doc) | the KeyPackage answers |
| 3.2 invite + join | ✅ **engine-side GREEN** | the `join` invitation → group session → member registry (the acceptance rehearsal) | the member joins |
| 3.3 encrypted hello | 🔶 in flight | MLS provider (openmls 0.8.3) → Welcome → join → encrypt/decrypt | A's message decrypts on B |
| 3.4 keep alive | 🔶 | key rotation (`self_update`) + a few messages after | still decrypts after rotation |

**MLS status:** `wmp-mls` crate built + tested (the provider: key packages, create/add/remove/update/encrypt/decrypt); `process_welcome` (the joiner's key store) + the engine `MlsProfile` wiring land next. wmp-js's `TsMlsProvider` (ts-mls) exists — cross-implementation vectors Rust↔TS prove the wire contract.

## Level 4 — four corners (lower priority, parked)

go-as4 exists (AS4 2.0, ebMS3, Ed25519). Cleverbase drives; we answer. Position: demo the WMP side, consume their SMP entries.

## Level 5 — evidence (stretch)

The event types exist (`wmp-core/src/evidence.rs`, ETSI EN 319 522 alignment: submission/relay/delivery/retrieval/acceptance). The JAdES + test-TSA wiring is post-Madrid.

## Level 6 — use case (stretch)

6.2 deferred EBWOID issuance — **works today** (the v0.3.2 engine + v0.23.9 APK, proven live on the phone).

---

## Our own capability validation (before Madrid)

1. **Engine probes** (all live against GDC, all in `sirosid-realeyes/demo-web/scripts/`):
   - `mcp-capability-probe.mjs` — session + `mcp` negotiation
   - `mcp-roundtrip-probe.mjs` — `tools/list` + `tools/call`
   - `mcp-acceptance-rehearsal.mjs` — the full six-step chain (invitation → join → tools → fan-out both ways): **GREEN 2026-11-20**
2. **Phone**: the invite QR flow (create + consume via scan), the group-invite button, then the same acceptance chain with the phone as wallet A
3. **MLS** (once wired): the Rust round-trip suite + a TS↔Rust cross-vector
4. **Known-good tokens**: the AS key fixture (`sirosid-dev/fixtures/rendered/fly-gdc/vc-pki/signing_ec_private.pem`) mints working principal tokens — bring spares

## Open questions for Slack (gates two prep items)

- The **test trust anchor** — **DECIDED (2026-11-21): Option A** — the registry's own published test CA (`webuild-smp-ca.pem`, valid to 2027) signs subscriber + participant certificates. Our CSR (EC P-256, SIROS keeps the private key, the CA key stays offline with Rune per SIG-06) is posted on [kjorlaug/webuild-smp#2](https://github.com/kjorlaug/webuild-smp/pull/2#issuecomment-7052918789): subject `CN=SIROS Foundation AB (demo WMP door)`, SANs `URI:urn:oasis:names:tc:ebcore:partyid-type:iso6523:0007::5595421925` + `DNS:sirosid-gdc-wallet-proxy.fly.dev`. **Waiting on Rune's signature.**
- **The participant ID** — **DECIDED: `0007::5595421925`** (ICD 0007, Swedish Organisationsnummer, Bolagsverket; hyphen stripped per ID-01/ID-02). Registered by [kjorlaug/webuild-smp#2](https://github.com/kjorlaug/webuild-smp/pull/2) (also asks `0007` onto `participant_schemes`).
- The WMP transport profile id confirmation (`webuild-transport-wmp-v1`, with Rune)

## What we actually do with the cert once it lands (level 0.4 → closure)

1. **The public PEM rides the registry PR** — drop it in `registry/certs/siros-wmp-door.pem`, reference it by relative path from the participant record; Rune's `build.py` validates it (REG-02: parseable endpoint certificate) and embeds it in the ServiceMetadata. This is the whole registry-side step.
2. **The private key never enters GDC.** The Fly machine's public TLS is Fly-terminated (Let's Encrypt at the edge) — the test-CA cert does not replace it. No mTLS this round (the ladder's own test-mode agreement; our sessions are bearer-token + `tls`).
3. **The cert's real job: signing the well-known document** — the seal that signs `/.well-known/wmp-configuration` (Cleverbase's own pattern: "the WMP door … whose certificate is the seal that signs the door's well-known"). Two options:
   - **Pre-sign in the pipeline (preferred):** `deploy.py` signs the rendered document at deploy time (the same block that generates the engine env), publishing `/.well-known/wmp-configuration.sig` + the certificate chain inline (`x5c`). The signing key is mounted from a secret for the signing step only — never a runtime env var on the machine.
   - **Sign at startup (fallback):** the engine signs its own document at boot (a mounted read-only cert + key pair; `ENGINE_WELLKNOWN_SIGNING_KEY`). Heavier — the key material lives on the machine — only if the pipeline signing can't run.
4. **Then level 1.2 verifies against it:** a peer fetching our ServiceMetadata validates our chain to `webuild-smp-ca.pem` (SIG-04) and checks the CRL (SIG-09) — `phoss smp-client` does both by default, and their own checklist ran exactly this on 2026-10-09.
5. **Housekeeping while we wait:** the keypair lives in `/tmp/opencode/siros-madrid-certs/` (`siros-wmp-door.key.pem`) — move it to the fixtures store (the `make-wrpac-fixtures.sh` pattern) with the other key material before the event, and note the cert's expiry against the pilot window (`pilot_end_date: 2027-12-31`).

## Rollback

Engine: v0.3.1 pin (the previous gdc.yaml block, kept in place). APK: v0.23.8 on Play Store testers.