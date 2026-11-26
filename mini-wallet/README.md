# @sirosfoundation/mini-wallet

The whole wallet a page hosts. A small TS/JS library around the browser
wasm engine ([@sirosfoundation/siros-wallet-core][engine] — the full
OID4VCI and OID4VP flows compiled to WebAssembly over a plain JSON-RPC
surface), with **pluggable storage**, **deferred onboarding**, and **every
UI decision delegated to the calling page**.

[engine]: https://www.npmjs.com/package/@sirosfoundation/siros-wallet-core

The target: mini-wallets embedded in a page that also runs an issuer
flow — the [Realeyes × nym_auth demonstrator][realeyes] pattern: the page
issues the credential and holds the wallet that receives it, on a phone.
nym_auth is the first-class credential (the stored record carries the
`ssc` opening the zkp proofs read back); every OID4VCI/OID4VP shape the
engine speaks works through the same surface.

[realeyes]: https://github.com/sirosfoundation/sirosid-realeyes

## The design, in one table

| Brief | Where it lives |
| --- | --- |
| 100% TS/JS + wasm | the engine is the published wasm peer dep; the library never bundles a second copy |
| All UI delegated to the page | the `ui` callbacks pass verbatim to the engine's host port — consent, match, tx-code, presentation approval; the library renders nothing |
| Pluggable storage | the `WalletStorage` interface; `LocalStorageWalletStorage` now |
| The trust as a local plugin layer (the authzen-client's home) | the `TrustPlugin` interface; `AuthzenTrustPlugin` speaks the AuthZEN evaluation to the environment's go-trust PDP (the client's own library plugs in behind the same interface when it ships); `DemoAlwaysTrustedPlugin` is the demo shim (its name says so) — always trusted, no authzen client, no PDP; `AlwaysTrustedPlugin` stays as the deprecated pre-0.2 alias |
| The private-data library later (@smncd: passkey + PRF-derived key) | any `WalletStorage` implementation plugs in; see the migration below |
| No onboarding before receiving a credential | the wallet initializes with the unencrypted localStorage backend and works — credentials arrive immediately |
| Passkey later, as a migration | `wallet.migrate(target)` copies every key, verifies each write, then drains the source — the deferred onboarding |
| Presentation by scanning a QR (cross-device) initially | `wallet.present(request)` — the `openid4vp://` link or the https request URI |
| Other presentation mechanisms later | the same `present` entry; the engine already speaks the DC-API channel |

## Use

```sh
npm install @sirosfoundation/mini-wallet @sirosfoundation/siros-wallet-core
```

```ts
import { MiniWallet, LocalStorageWalletStorage } from "@sirosfoundation/mini-wallet";

const wallet = new MiniWallet({
  // The default; shown for clarity.
  storage: new LocalStorageWalletStorage("realeyes-demo"),
  // The page's trust decision — the wallet never decides trust itself.
  pdp: { evaluate: (request) => fetch("/api/pdp", { method: "POST", body: JSON.stringify(request) }).then(r => r.json()) },
  // EVERY UI decision is the page's; an absent callback refuses that
  // sub-flow, exactly as an engine host without the capability would.
  ui: {
    consent: async (params) => myPage.askConsent(params),
    vp: async (params) => myPage.askPresentation(params),
  },
  onEvent: (e) => {
    if (e.type === "credential-received") myPage.showDelivered();
    if (e.type === "flow-error") myPage.showError(e.message);
  },
});

// The issuance: the offer URI the page's embedded issuer flow minted
// (the https offer URL, the openid-credential-offer:// deep link, or
// the offer object already in hand).
await wallet.receiveCredential(offerUri);

// What the page renders:
const credentials = await wallet.credentials();

// The presentation, cross-device: the verifier's QR on another screen,
// this phone's camera scans it, and the request lands in the wallet page
// (the scheme handler routes it, or the page pastes it) — the flow
// drives from the scanned link.
await wallet.present("openid4vp://?client_id=…&request_uri=…");
```

## The deferred onboarding — the storage migration

The wallet works with **no onboarding**: credentials (and the device
key) store unencrypted in the browser's localStorage, behind the
`WalletStorage` interface. When the user sets a passkey — a day later,
never blocking a first issuance — the page migrates:

```ts
// @smncd's private-data library, when it lands: the passkey-derived
// key wraps every write.
const encrypted = new PrivateDataStorage({ passkey: await setUpPasskey() });

const report = await wallet.migrate(encrypted);
if (report.failed) {
  // The named key failed to verify against the target — the SOURCE IS
  // INTACT (the delete pass runs only after every key verified); the
  // wallet keeps running on the old backend.
  myPage.warnStorageMigration(report.failed);
}
```

The migration contract is deliberately dumb — copy every key's bytes,
verify each write, then delete the source — so the encryption stays the
target backend's business and this library never changes when the
private-data library lands. `report.keys` names what moved; a failure
names the key and touches nothing.

## The backend configuration: the tenant's policy from the first issuance

When the wallet is configured with a backend, its trust layer is **the backend's PDP-proxy from the FIRST credential issuance** — the tenant's policy decides which issuers this deployment trusts; the page never guesses:

```ts
const wallet = new MiniWallet({
  backend: {
    url: "https://sirosid-gdc-wallet-backend.fly.dev",
    tenantId: "default",
    // The PRE-REGISTRATION TENANT TOKEN (go-wallet-backend#566): the
    // evaluations carry it before any user exists. Supply it until the
    // backend ships the anonymous path; after the adopt the passkey
    // session's token takes over automatically — the provider swaps
    // beneath the trust layer, nothing else changes.
    token: async () => myPage.tenantToken(),
  },
  ui: { consent: async () => myPage.askConsent() },
});
await wallet.receiveCredential(offerUri); // the trust check: the backend's /v1/evaluate
```

The adopt needs no target then — it defaults to the configured backend.

## The adopt flow: a permanent wallet

The arc the brief draws for a page with an embedded issuer flow: the
mini-wallet receives a credential with **no onboarding**, the page asks
**"add a permanent wallet?"**, the user **sets a passkey**, and the
credential **moves into the wallet** — a go-wallet-backend (its AS, its
per-user private-data store). From then on the wallet's authz is the
**backend's PDP-proxy** (`/v1/evaluate`, the AuthZEN evaluation the
wallet-frontend drives today).

```ts
const report = await wallet.adopt({
  target: "https://sirosid-gdc-wallet-backend.fly.dev", // or an AdoptTarget
  ui: {
    ask: async ({ credentials, backend }) => myPage.askAddPermanentWallet(credentials, backend),
    create: (options) => navigator.credentials.create(options), // the ceremony is the page's
  },
});
// report.account — the AS user the passkey registered;
// report.keys — what moved; a failure names the key and the LOCAL copy stays.
```

Every UI decision is the page's (the ask and the WebAuthn ceremony are
callbacks). The move is the migration contract — copy every record,
verify each against the backend, then wipe the local copy — so a failed
adopt leaves the mini-wallet exactly as it was. The **private-data
cipher is the pluggable slot for the private-data library** (the
passkey's PRF-derived key wrapping the blob); the NullCipher stores the
blob as the backend's opaque bytes until it lands — the same accepted
posture as the unencrypted localStorage phase, upgraded to a
server-side account.

## The custody

The **device key** (the OID4VCI proof's ES256 P-256 key) generates on
first use and stores as a JWK under `key:device` — unencrypted until the
migration wraps it (the brief's accepted tradeoff: the wallet works
before any onboarding). The host `sign`/`signingKey` callbacks serve it
to the engine through WebCrypto.

**Credentials** store under `credential:<uuid>` as the verbatim record:
the credential, its format, its configuration id, and the **response-level
metadata** — the nym_auth `ssc` opening rides it, and the zkp presenter
reads it back through `wallet.rawCredential(key)` (the page's `ui.vp`
implementation wires the presenter to it).

## The engine seam

`MiniWallet` constructs the published `WasmEngine` with:
- the page's `fetch` (adapted to the engine's port shape),
- the page's PDP behind the engine's trust port,
- the `ui` callbacks behind the engine's host port,
- **the storage behind the engine's `kv` port** (`stash:*` keys) — so
  even the flow state (the authorization-code resume) survives a reload,
- the completion/error notification sink, where the delivered
  credentials surface (the flow results never ride the start's answer —
  the same rule the WMP wire has).

The session (`wmp.session.create`) and the flow starts (`wmp.flow.start`
with `flow_type` `oid4vci`/`oid4vp`, the params from the normalized
offer/request) are the library's internals — the page never speaks WMP.

## What is wired and what is next

- **Wired**: the storage contract, the localStorage/memory backends, the
  migration, the offer/request normalization, the engine construction
  (the kv/host/pdp ports, the notification sink), the session, the
  `oid4vci` start, the credential custody (the record + the metadata),
  the `oid4vp` start (cross-device), the device-key custody.
- **Next**: the zkp presenter seam (the `ui.vp` callback's nym_auth
  presenter wiring — the ssc opening flows from `rawCredential` through
  the presenter to the proof), which rides the wasm presenter artifact
  when it ships; the passkey backend on the private-data library; other
  presentation mechanisms (same-device DC-API — the engine already
  speaks it, the entry point changes).

## Test

```sh
npm test
```

## License

BSD-2-Clause
