# Stateless resume: the TEE constraint and the design

Nov 14, 2026. The standing architectural concern: server-side state makes
TEE deployment hard (encrypted pages, small RAM budgets, attestation-
unfriendly state sprawl). This document is the design for a stateless
engine — the state rides the wire, sealed to the client — and the
transition plan for the state the engine keeps today.

**The rule going forward** (the actionable part, in force now): every new
engine flow states its resume story up front — what rides the wire, what
the engine must hold, what the TTL is — and the default is the stateless
option. PRs that deepen the KV dependency without saying why are
reviewable on that ground alone.

## 1. The state the engine keeps today (the inventory)

| State | Where | TTL | Used by | TEE cost |
|---|---|---|---|---|
| WMP sessions | `MemorySessionStore` (handler.rs) | 3600s default | every flow: the SSE route, the flow→session routing | high — the session IS the auth context |
| `AuthorizationStash` | `InMemoryKv` (ports.rs) | 600s | the OID4VCI auth-code resume (PKCE verifier, state, selection, the original AS) | high — the resume's whole ground truth |
| The SSE outbox | `Outbox` (outbox.rs) | unbounded (per-process) | the event log: `id:`/`Last-Event-ID` replay, the redaction | high — the delivery guarantee |
| The flow registry | `Registry` (wmp-core) | per-process | the sub-flow ask routing (`flow_id → handler`) | medium — derivable |
| `NotificationContexts` | `Ports.notifications` | 5 min, single-use | the `credential_notification` flow's forward contexts | medium — carries the access token |
| The flow-type map | peer (per-process) | per-process | dispatch routing (`flow_id → flow_type`) | low — derivable (fixed by the 2026-11-14 completion-race fix: tracked client-side before the call) |

The resumption token already carries state forward (`transport.rs` —
"the resumption token carries the state forward"): the sessions are
**half-stateless today**. The design finishes that.

## 2. The three shapes

Ranked by effort, all compatible — each is a strict subset of the next
deployment story.

### Shape 1 — the client-held sealed stash (the #551 pattern, adopted)

The `AuthorizationStash` moves from the KV to the wallet. The flow start
returns the stash as a **sealed blob** with the redirect hand-off; the
resume presents it back; the engine verifies and never stores.

- **Sealing**: HMAC over the canonical stash JSON with a
  domain-separated key derived from the deployment's existing secret
  (`ENGINE_SECRET`, the same derivation family as `jwt.secret` in the Go
  #551), OR authenticated encryption (AES-GCM over the same key) if the
  stash's confidentiality matters (it carries the PKCE verifier and the
  selected configuration — low sensitivity, but sealing costs nothing
  once the key exists).
- **Freshness**: `iat` + a 10-minute `exp` (the stash TTL today), checked
  before any field is read.
- **Binding**: the flow id and the session id ride the sealed payload and
  are compared, so a blob from one flow cannot resume another.
- **The `iss` gate rides along**: the stashed `as_issuer` +
  `as_iss_supported` (v0.2.9) move into the blob unchanged — the
  validation logic is stash-shape-agnostic by construction (the
  `#[serde(default)]` members), which is why the `iss` fix was built the
  way it was.

**What the engine keeps**: nothing for the auth-code flow beyond the
session (Shape 2's target). The KV port stays for everything else.

**Wire cost**: one extra member on the hand-off (`authorization_context`)
and one on the resume action. The OpenID4x action translation (3.1.2)
already passes unknown members through — verified this week.

**Compatibility**: the `authorization_context` member is optional with a
`serde(default)`; an old wallet's resume without it falls back to the KV
stash (both paths live for one release), then the KV path retires.

### Shape 2 — the session is the token

The resumption token IS the session: `wmp.session.create` returns a
sealed session (the same derivation), `wmp.session.resume` presents it,
and the store becomes a **cache** (for the SSE route's affinity), not the
source of truth. A TEE instance that has never seen the flow answers any
resume from the blob alone.

- The flow registry and the flow-type map derive from the resumed
  session + the client's own start calls (the completion-race fix already
  moved flow-type tracking client-side).
- The `NotificationContexts` (the access-token-bearing forward contexts)
  seal the same way — they are the one store where confidentiality is
  **required**, not optional: the blob carries a live credential-access
  token. This is the one place AES-GCM is non-negotiable.

**What breaks**: nothing in the core — the `SessionStore` trait already
abstracts it; a `SealedSessionStore` implementation replaces the in-memory
one behind the same trait.

### Shape 3 — the outbox problem (the honest hard part)

The SSE event log (replay, `410 Gone`, redaction) is genuinely shared
state: a reconnect after a replica bounce wants the events the OTHER
replica sent. Options, in honesty order:

1. **Sticky sessions** (deploy-time): the SSE route pins to the replica
   that created the session. Cheapest; loses on replica loss (the client
   reconnects with `Last-Event-ID`, gets a 410, re-subscribes — the
   *messages* it missed are gone, but the flows re-ask).
   **Acceptable for TEE**: the ask/answer protocol is already
   re-request-driven; a lost event costs a re-ask, not a lost flow.
2. **The client-held event cursor**: the wallet acks event ids it has
   processed (in its own resume blob); a replica that never saw them
   re-derives nothing — the events were notifications, not obligations.
   This works because **the flows are the obligations, not the events**:
   the match answer, the consent, the signed presentation are all
   client-held actions replayable from the wallet's own state.
3. Redis (the non-TEE answer): rejected for the TEE target by
   definition — the point is the state does not leave the enclave.

**Design position**: the outbox keeps its per-process form; the delivery
contract downgrades from "at-least-once across restarts" to
"at-least-once within a replica, plus re-ask on reconnect" — which the
ask/answer protocol already provides. The flows, not the events, are the
source of truth.

## 3. The transition plan

| Step | What | Land with |
|---|---|---|
| 1 | The `iss` gate's stash fields (done, v0.2.9) ride the KV — no change | shipped |
| 2 | `AuthorizationStash` → the sealed blob (Shape 1): the hand-off gains `authorization_context`, the resume accepts it, both paths live one release | the next engine minor (v0.2.10) |
| 3 | The KV path for the stash retires; the sealed path is the only one | one release later |
| 4 | The sealed session (Shape 2) — `SealedSessionStore`, the notification contexts sealed | the TEE milestone |
| 5 | The outbox position (Shape 3): documented downgrade + sticky sessions on the deployment | the TEE milestone |
| 6 | The wasm page (`wallet.js`) is the reference consumer: its `kv` already IS client-held (localStorage) — the browser path is Shape-1-native today | with step 2 |

**The SDK note**: the sealed blob is opaque to the SDKs (they relay it,
never read it) — no SDK release needed for any step except the hand-off
member surfacing through the OpenID4x action translation, which is
automatic (unknown members pass through).

**The multi-replica note** (parity #432): Shape 2 is also the multi-replica
fix — a resumed session no longer needs the creating replica's memory.
The TEE constraint and the HA constraint share one design.

## 4. What is deliberately NOT stateless

- **The DPoP/WIA nonces** (the AS-issued single-use challenges): the AS
  owns them; the engine only relays.
- **The revocation lists** (`JtiBlacklist`): the token gate's own
  document says the backend adapter implements the shared store — that
  state is the deployment's, not the flow's.
- **The consent ask in flight** (a user mid-prompt): unrecoverable by
  design — the ask is a child flow, the wallet re-asks on resume, the
  user re-answers. A prompt is not state; it is a conversation.