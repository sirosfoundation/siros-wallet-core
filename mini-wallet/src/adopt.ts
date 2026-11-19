// The adopt flow: the page's mini-wallet becomes a permanent wallet on a
// go-wallet-backend (its AS, its storage, its PDP-proxy for the authz).
//
// The arc the design brief draws:
//   receive a credential (unencrypted, no onboarding) → ask the user
//   "add a permanent wallet?" → set a passkey (the AS's WebAuthn
//   registration) → MOVE the credential into the wallet → from then on
//   the wallet's authz is the backend's PDP-proxy (the AuthZEN
//   evaluation through the backend's /v1/evaluate).
//
// Every UI decision stays the page's: the ask and the WebAuthn ceremony
// arrive as callbacks. The PRIVATE-DATA CIPHER is the pluggable slot for
// the private-data library (@smncd's: the passkey's PRF-derived key
// wrapping the blob) — until it lands the NullCipher stores the blob as
// the backend's opaque bytes, the same accepted posture as the
// unencrypted localStorage phase, upgraded to a server-side account.

import type { TrustPlugin } from "./trust.js";
import { AuthzenTrustPlugin } from "./trust.js";
import type { WalletStorage } from "./types.js";
import type { StoredCredential } from "./types.js";
import { migrateWalletStorage } from "./migration.js";

/** What the page's ask callback receives — the context for "add a
 *  permanent wallet?" (what would move, where). */
export interface AdoptAsk {
  /** The credentials that would move. */
  credentials: StoredCredential[];
  /** The backend the wallet would live on. */
  backend: string;
}

/** The page's UI for the adopt — both callbacks are the page's; the
 *  library renders nothing. */
export interface AdoptUi {
  /** "Add a permanent wallet?" — the page's answer. False aborts. */
  ask: (ask: AdoptAsk) => Promise<boolean>;
  /** The WebAuthn creation ceremony: the page runs
   *  navigator.credentials.create with the backend's options (the PRF
   *  extension inputs ride the options the target supplies). */
  create: (options: unknown) => Promise<unknown>;
}

/** The passkey's derived-key wrapping — the private-data library's
 *  slot. The blob the backend stores is opaque bytes; the cipher decides
 *  what those bytes are. The NullCipher (the default) stores the records
 *  as plain JSON — the same accepted posture as the unencrypted
 *  localStorage phase — until the PRF cipher lands. */
export interface PrivateDataCipher {
  wrap(records: Record<string, string>): Promise<Uint8Array>;
  unwrap(blob: Uint8Array): Promise<Record<string, string>>;
}

export class NullCipher implements PrivateDataCipher {
  async wrap(records: Record<string, string>): Promise<Uint8Array> {
    return new TextEncoder().encode(JSON.stringify(records));
  }

  async unwrap(blob: Uint8Array): Promise<Record<string, string>> {
    return JSON.parse(new TextDecoder().decode(blob)) as Record<string, string>;
  }
}

/** The backend the wallet adopts: the go-wallet-backend's AS, its
 *  per-user private-data store, its PDP-proxy. The endpoint shapes are
 *  the wallet-frontend's own (the existing consumer): the passkey
 *  register begin/finish, the private-data GET/POST with the ETag. */
export interface AdoptTarget {
  /** The backend's base URL — the ask's context and the authz's base. */
  readonly backend: string;
  /** Run the passkey registration (the begin/finish pair around the
   *  page's ceremony). Resolves with the account reference. */
  registerPasskey(ui: AdoptUi): Promise<{ account: string }>;
  /** The wallet's storage ON the backend: the records as a KV over the
   *  private-data blob (the cipher wraps them). */
  storage(cipher: PrivateDataCipher): WalletStorage;
  /** The adopted configuration's authz: the backend's PDP-proxy. */
  trustPlugin(): TrustPlugin;
}

/** The go-wallet-backend target: the passkey AS, the private-data store,
 *  the PDP-proxy — the shapes the wallet-frontend drives today. */
export class GoWalletBackendTarget implements AdoptTarget {
  readonly backend: string;
  readonly #tenantId: string;
  #sessionHeaders: Record<string, string> = {};
  #etag: string | undefined;

  constructor(backend: string, tenantId = "default") {
    this.backend = backend.replace(/\/$/, "");
    this.#tenantId = tenantId;
  }

  async registerPasskey(ui: AdoptUi): Promise<{ account: string }> {
    // The begin: the creation options (the AS mints the challenge).
    const begin = await this.#post("/auth/passkey/register/begin", {
      tenantId: this.#tenantId,
    }, { "X-Token-Mode": "session", "X-Tenant-ID": this.#tenantId });
    // The page's ceremony over the options the backend built.
    const credential = await ui.create(begin.getOptions ?? begin);
    // The finish: the ceremony's answer establishes the session.
    const finish = await this.#post("/auth/passkey/register/finish", {
      challengeId: begin.challengeId,
      credential,
    }, { "X-Token-Mode": "session", "X-Tenant-ID": this.#tenantId });
    const token = typeof finish.token === "string" ? finish.token : undefined;
    const session = typeof finish.session === "string" ? finish.session : undefined;
    if (token) this.#sessionHeaders.Authorization = `Bearer ${token}`;
    else if (session) this.#sessionHeaders.Cookie = session;
    return { account: String(finish.uuid ?? finish.account ?? "") };
  }

  storage(cipher: PrivateDataCipher): WalletStorage {
    const target = this;
    return {
      async get(key) {
        const records = await target.#readRecords(cipher);
        return records[key] ?? null;
      },
      async put(key, value) {
        const records = await target.#readRecords(cipher);
        records[key] = value;
        await target.#writeRecords(records, cipher);
      },
      async del(key) {
        const records = await target.#readRecords(cipher);
        delete records[key];
        await target.#writeRecords(records, cipher);
      },
      async list(prefix) {
        const records = await target.#readRecords(cipher);
        const keys = Object.keys(records);
        return prefix === undefined ? keys : keys.filter((k) => k.startsWith(prefix));
      },
    };
  }

  trustPlugin(): TrustPlugin {
    return new AuthzenTrustPlugin(`${this.backend}/v1/evaluate`);
  }

  async #readRecords(cipher: PrivateDataCipher): Promise<Record<string, string>> {
    const response = await fetch(`${this.backend}/user/session/private-data`, {
      headers: { ...this.#sessionHeaders, ...(this.#etag ? { "If-None-Match": this.#etag } : {}) },
    });
    if (response.status === 304) return {}; // unchanged since our last read
    if (response.status === 404) return {}; // nothing stored yet
    if (!response.ok) throw new Error(`the backend's private-data answered ${response.status}`);
    const etag = response.headers.get("ETag");
    if (etag) this.#etag = etag;
    const body = (await response.json()) as { privateData?: { data?: number[] } };
    const blob = body.privateData?.data;
    return blob ? cipher.unwrap(new Uint8Array(blob)) : {};
  }

  async #writeRecords(records: Record<string, string>, cipher: PrivateDataCipher): Promise<void> {
    const blob = await cipher.wrap(records);
    // The bytes as the backend's opaque payload (the wallet-frontend's
    // serialization shape: the data member carrying the blob's bytes).
    const data = Array.from(blob);
    const response = await fetch(`${this.backend}/user/session/private-data`, {
      method: "POST",
      headers: {
        ...this.#sessionHeaders,
        "Content-Type": "application/json",
        ...(this.#etag ? { "If-Match": this.#etag } : {}),
      },
      body: JSON.stringify({ privateData: { data } }),
    });
    if (!response.ok) throw new Error(`the backend's private-data write answered ${response.status}`);
    const etag = response.headers.get("ETag");
    if (etag) this.#etag = etag;
  }

  async #post(path: string, body: unknown, headers: Record<string, string>): Promise<Record<string, unknown>> {
    const response = await fetch(`${this.backend}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`the backend's ${path} answered ${response.status}`);
    return (await response.json().catch(() => ({}))) as Record<string, unknown>;
  }
}

/** The adopt result — what moved and where it lives now. */
export interface AdoptReport {
  /** The account the passkey registered (the AS's user reference). */
  account: string;
  /** The keys that moved (the migration's report). */
  keys: string[];
  /** A key that failed to verify against the backend — the LOCAL copy
   *  stays intact (the migration never deletes on failure). */
  failed?: string;
}
