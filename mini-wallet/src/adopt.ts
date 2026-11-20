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

import type { TrustPlugin, TrustTokenProvider } from "./trust.js";
import { AuthzenTrustPlugin } from "./trust.js";
import { migrateWalletStorage } from "./migration.js";
import type { WalletStorage, StoredCredential } from "./types.js";

// ── The tagged-binary wire format ────────────────────────────────────────
// The backend serializes WebAuthn's binary members (challenge, user.id,
// the credential's rawId/attestationObject…) as {"$b64u": "…"} tags —
// the wallet-frontend's jsonParseTaggedBinary/jsonStringifyTaggedBinary
// pair. Both directions, verbatim semantics.

function fromBase64Url(value: string): Uint8Array {
  const pad = value.length % 4 === 2 ? "==" : value.length % 4 === 3 ? "=" : "";
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Revive every {"$b64u"} tag into its Uint8Array (the begin responses). */
export function reviveTaggedBinary<T>(value: T): T {
  if (Array.isArray(value)) return value.map((v) => reviveTaggedBinary(v)) as unknown as T;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const tag = record["$b64u"];
    if (typeof tag === "string") return fromBase64Url(tag) as unknown as T;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(record)) out[k] = reviveTaggedBinary(v);
    return out as T;
  }
  return value;
}

/** Stringify with the buffers tagged (the finish requests: the
 *  ceremony's answer carries ArrayBuffers JSON cannot express). */
export function stringifyWithTaggedBinary(value: unknown): string {
  return JSON.stringify(value, function replacer(this: Record<string, unknown>, key, val) {
    const at = this[key];
    // BOTH binary shapes: the tagged helpers' Uint8Array AND the raw
    // ArrayBuffer members navigator.credentials.create returns (rawId,
    // attestationObject, clientDataJSON) — the ArrayBuffer alone
    // serialized as {} and the AS could not verify the registration.
    if (at instanceof Uint8Array) return { $b64u: toBase64Url(at) };
    if (at instanceof ArrayBuffer) return { $b64u: toBase64Url(new Uint8Array(at)) };
    return val;
  });
}


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
  /** "Add a permanent wallet?" — the page's answer. False aborts. When
   *  the built-in modal renders beside it, BOTH must consent: the page's
   *  false is a veto the modal never overrides (and the modal's declined
   *  buttons abort even when the page said yes). */
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
 *  register begin/finish, the private-data GET/POST with the ETag.
 *
 * The migration moves EVERYTHING the source storage lists — the device
 * private key and the per-flow signing keys included — and under the
 * default NullCipher they land in the backend blob as PLAINTEXT (the
 * README's documented tradeoff: the private-data library's cipher slot
 * is where the passkey-PRF encryption plugs in). Adopting with the
 * NullCipher is the demo's convenience, not an encrypted deployment. */
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
  /** The SESSION's token — the adopt's continuity: the trust
   *  evaluations carry this token from the adopt on (the
   *  pre-registration tenant token's job ended with the user's
   *  arrival). Absent when the target keeps no token (a test mock). */
  sessionToken?(): TrustTokenProvider | undefined;
}

/** The go-wallet-backend target: the passkey AS, the private-data store,
 *  the PDP-proxy — the shapes the wallet-frontend drives today. */
export class GoWalletBackendTarget implements AdoptTarget {
  readonly backend: string;
  readonly #tenantId: string;
  #sessionHeaders: Record<string, string> = {};
  /** The records as of the last 200/POST — the 304 answer. */
  #lastRecords: Record<string, string> = {};
  /** The fetch credentials mode: "include" in cookie-session mode (the
   *  browser attaches the cookie), "same-origin" otherwise. The manual
   *  Cookie header was a forbidden-header silent no-op in browsers. */
  #credentials: RequestCredentials = "same-origin";
  #etag: string | undefined;
  /** The write queue: the blob is read-modify-write, so two overlapping
   *  put/del calls on ONE target must not interleave their reads (the
   *  later read would miss the earlier write and drop its key). Every
   *  mutating call rides this chain; reads stay parallel. */
  #writes: Promise<unknown> = Promise.resolve();
  #accessToken: string | null = null;

  constructor(backend: string, tenantId = "default") {
    this.backend = backend.replace(/\/$/, "");
    this.#tenantId = tenantId;
  }

  async registerPasskey(ui: AdoptUi): Promise<{ account: string }> {
    // The begin: the creation options (the AS mints the challenge).
    const begin = await this.#post("/auth/passkey/register/begin", {
      tenantId: this.#tenantId,
    }, { "X-Token-Mode": "session", "X-Tenant-ID": this.#tenantId });
    // The page's ceremony over the options the backend built: the
    // register begin's createOptions (the {publicKey: …} envelope the
    // wallet-frontend spreads into navigator.credentials.create), the
    // $b64u-tagged binary members revived into Uint8Arrays.
    const options = reviveTaggedBinary(begin.createOptions ?? begin.getOptions ?? begin);
    const credential = await ui.create(options);
    // The finish: the ceremony's answer establishes the session.
    // The ceremony's answer carries ArrayBuffers JSON cannot express —
    // the tagged-binary stringify crosses them (the frontend's
    // jsonStringifyTaggedBinary shape).
    const finish = await this.#postRaw("/auth/passkey/register/finish", stringifyWithTaggedBinary({
      challengeId: begin.challengeId,
      credential,
    }), { "X-Token-Mode": "session", "X-Tenant-ID": this.#tenantId });
    const token = typeof finish.token === "string" ? finish.token : undefined;
    const session = typeof finish.session === "string" ? finish.session : undefined;
    if (token) this.#sessionHeaders.Authorization = `Bearer ${token}`;
    else if (session) {
      // Session-cookie mode: the browser attaches the cookie itself
      // (credentials: "include" on every backend call). `Cookie` is a
      // forbidden header name — fetch() strips it in every browser, so
      // the manual header left every later call unauthenticated.
      this.#credentials = "include";
    }
    this.#accessToken = token ?? null;
    // A non-JSON (or account-less) finish is a FAILURE — a 200 with no
    // account named no session; answering "" made the adopt "succeed"
    // against a backend that never registered anything.
    const account = finish.uuid ?? finish.account;
    if (typeof account !== "string" || !account) {
      throw new Error("the backend's register finish named no account");
    }
    return { account };
  }

  sessionToken(): TrustTokenProvider | undefined {
    // The registered session's token: the finish's access token, or a
    // fresh mint through /auth/token when the finish established the
    // session cookie alone.
    return async () => {
      if (this.#accessToken) return this.#accessToken;
      const answer = await this.#post("/auth/token", { aud: "wallet-backend" }, {
        "X-Token-Mode": "token",
        "X-Tenant-ID": this.#tenantId,
      });
      const token = typeof answer.token === "string" ? answer.token : (typeof answer.access_token === "string" ? answer.access_token : null);
      if (token) this.#accessToken = token;
      return token;
    };
  }

  storage(cipher: PrivateDataCipher): WalletStorage {
    const target = this;
    return {
      async get(key) {
        const records = await target.#readRecords(cipher);
        return records[key] ?? null;
      },
      async put(key, value) {
        return target.#serializeWrite(() => async () => {
          const records = await target.#readRecords(cipher);
          records[key] = value;
          await target.#writeRecords(records, cipher);
        });
      },
      async del(key) {
        return target.#serializeWrite(() => async () => {
          const records = await target.#readRecords(cipher);
          delete records[key];
          await target.#writeRecords(records, cipher);
        });
      },
      async list(prefix) {
        const records = await target.#readRecords(cipher);
        const keys = Object.keys(records);
        return prefix === undefined ? keys : keys.filter((k) => k.startsWith(prefix));
      },
    };
  }

  /** One mutating call at a time, in call order: the chain holds the
   *  previous write's outcome (a failure must not break the chain). */
  #serializeWrite(build: () => () => Promise<void>): Promise<void> {
    const run = this.#writes.then(build(), build());
    this.#writes = run.catch(() => {});
    return run;
  }

  trustPlugin(): TrustPlugin {
    return new AuthzenTrustPlugin(`${this.backend}/v1/evaluate`);
  }

  async #readRecords(cipher: PrivateDataCipher): Promise<Record<string, string>> {
    const response = await fetch(`${this.backend}/user/session/private-data`, {
      headers: { ...this.#sessionHeaders, ...(this.#etag ? { "If-None-Match": this.#etag } : {}) },
      credentials: this.#credentials,
    });
    // 304 means UNCHANGED SINCE OUR LAST READ: the correct answer is the
    // cached records, not {} — a {} here made the next put rewrite the
    // blob with one key and silently drop every other record. The cache
    // is a copy: the caller mutates, and a failed write must not have
    // poisoned it.
    if (response.status === 304) return { ...this.#lastRecords };
    // 404 is the server saying NOTHING IS STORED (a first read, or a
    // server-side wipe): the honest answer is empty — answering the cache
    // would resurrect stale records the backend just dropped. The cache
    // and the etag go with them.
    if (response.status === 404) {
      this.#lastRecords = {};
      this.#etag = undefined;
      return {};
    }
    if (!response.ok) throw new Error(`the backend's private-data answered ${response.status}`);
    const etag = response.headers.get("ETag");
    if (etag) this.#etag = etag;
    const body = (await response.json()) as { privateData?: { data?: number[] } };
    const blob = body.privateData?.data;
    this.#lastRecords = blob ? await cipher.unwrap(new Uint8Array(blob)) : {};
    return { ...this.#lastRecords };
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
      credentials: this.#credentials,
    });
    if (!response.ok) throw new Error(`the backend's private-data write answered ${response.status}`);
    const etag = response.headers.get("ETag");
    if (etag) this.#etag = etag;
    this.#lastRecords = { ...records };
  }

  async #post(path: string, body: unknown, headers: Record<string, string>): Promise<Record<string, unknown>> {
    return this.#postRaw(path, JSON.stringify(body), headers);
  }

  async #postRaw(path: string, body: string, headers: Record<string, string>): Promise<Record<string, unknown>> {
    const response = await fetch(`${this.backend}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body,
      credentials: this.#credentials,
    });
    if (!response.ok) {
      // The answer's message rides the error — the diagnostics need it.
      const text = await response.text().catch(() => "");
      throw new Error(`the backend's ${path} answered ${response.status}: ${text.slice(0, 200)}`);
    }
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
