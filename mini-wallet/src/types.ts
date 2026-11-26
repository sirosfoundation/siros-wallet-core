// The mini-wallet's contracts. Everything here is wire-shaped: the types
// mirror the engine's documented callback surfaces exactly, so a page
// implementing them needs no adapter layer.
//
// The library delegates ALL UI to the calling page (the design brief):
// consent, credential matching, transaction codes and the presentation
// approval arrive as callbacks; the library renders nothing.

/** One key/value pair the wallet stores — opaque strings throughout:
 *  the library never parses a stored value (the engine's flow stash, the
 *  wallet's keys and credentials all ride the same interface). */
export interface WalletStorage {
  /** The stored value, or null when the key holds nothing. */
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  del(key: string): Promise<void>;
  /** Every key under the prefix, in no particular order — the storage
   *  migration walks them (unencrypted → passkey-encrypted, the design
   *  brief's deferred onboarding) and the credential listing reads them. */
  list(prefix?: string): Promise<string[]>;
}

/** What the wallet asks the page. Every member is optional — an absent
 *  callback refuses that sub-flow, exactly as an engine host without the
 *  capability would (the mini-wallet never invents an answer). */
export interface MiniWalletUi {
  /** The issuance/presentation consent. Absent refuses the flow. */
  consent?: (params: unknown) => Promise<unknown>;
  /** The DCQL credential match. Absent refuses the flow. */
  match?: (params: unknown) => Promise<unknown>;
  /** The transaction code the issuer demanded. */
  txCode?: (params: unknown) => Promise<unknown>;
  /** The presentation approval — the page's last word before the wallet
   *  answers a verifier. The zkp_req proof path plugs in here (see the
   *  README's presenter seam). */
  vp?: (params: unknown) => Promise<unknown>;
  /** The authorization handoff (the issuer's login redirect). */
  openAuthorization?: (url: string) => Promise<unknown>;
  /** The attestation the flow demanded (a WIA); absent falls back to the
   *  engine's own behaviour. */
  attestation?: (params: unknown) => Promise<unknown>;
}

import type { TrustPlugin } from "./trust.js";
import type { AdoptAsk } from "./adopt.js";

/** The modal the `adopt` flow renders THROUGH — the page's own
 *  implementation. The library ships no renderer: every UX string,
 *  style and layout is the hosting page's (the design brief: "the
 *  library renders nothing"). `adopt`'s `modal` option takes an
 *  instance of this contract; the steps arrive as the calls below, the
 *  page renders them however it likes. The example carries a reference
 *  implementation (examples/realeyes/adopt-modal.mjs). */
export interface AdoptModal {
  /** Show the "add a permanent wallet?" step. The step settles when
   *  the user answers; false aborts the adopt. When a modal renders
   *  beside the page's own `ui.ask`, BOTH must consent: the page's
   *  false is a veto the modal never overrides. */
  ask(ask: AdoptAsk): Promise<boolean>;
  /** The passkey step: shown while the ceremony runs (the browser's
   *  own WebAuthn prompt fires over it). */
  passkey(): void;
  /** The move step: shown while the records migrate. */
  moving(keys: string[]): void;
  /** The done step: the report. */
  done(report: { account: string; backend: string; keys: string[] }): void;
  /** The failed step: the move failed; the local wallet is intact. */
  failed(failed: string): void;
  /** The ask was declined — close. */
  declined(): void;
  /** Tear everything down (an error outside the steps, a stop). */
  close(): void;
}

/** The engine's PDP port shape. The MiniWallet's `pdp` option accepts
 *  this OR a TrustPlugin (the plugin is the first-class form — the
 *  authzen-client's layer); asPdp adapts. */
export interface MiniWalletPdp {
  evaluate(request: unknown): Promise<{ trusted: boolean; decision?: string; context?: unknown }>;
}
export type MiniWalletPdpOption = MiniWalletPdp | TrustPlugin;

/** The page's fetch — the engine's HTTP. Carrying it lets the page pin
 *  proxies, CORS shims and request logging; the browser default when
 *  absent. The request AND the answer are the engine's port shapes:
 *  the headers flat [name, value, …] arrays, the body BYTES (the
 *  engine's Vec<u8>), the request's body null on bodyless requests. */
export type MiniWalletFetch = (request: unknown) => Promise<{ status: number; headers: string[]; body: number[] }>;

/** The events the wallet surfaces to the page. The library renders
 *  nothing; the page's UI listens here. */
export type MiniWalletEvent =
  | { type: "session"; sessionId: string }
  | { type: "progress"; flowId: string; step: string; payload?: unknown }
  | { type: "credential-received"; flowId: string; configurationId?: string }
  | { type: "presented"; flowId: string }
  | { type: "adopted"; account: string; backend: string }
  | { type: "flow-error"; flowId: string; code?: number; message: string };

/** What the wallet hands back when the page lists its credentials. */
export interface StoredCredential {
  /** The storage key — stable across sessions, the migration's unit. */
  key: string;
  /** The credential's format (`mso_mdoc`, `dc+sd-jwt`). */
  format: string;
  /** The configuration it issued under. */
  configurationId?: string;
  /** When the wallet received it (unix seconds). */
  receivedAtUnix: number;
}
