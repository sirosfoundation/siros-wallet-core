// The MiniWallet: the whole wallet a page hosts. The engine is the
// published @sirosfoundation/siros-wallet-core WASM (the peer dep — the
// page installs it; the library never bundles a second copy); every
// environmental effect stays the page's (fetch, the PDP, the UI
// callbacks, the storage), exactly as the engine's ports demand.
//
// The design brief, mapped:
//   - 100% TS/JS + wasm; ALL UI delegated: the ui callbacks pass through
//     to the engine's host port; the library renders nothing.
//   - pluggable storage: the WalletStorage interface; localStorage now,
//     @smncd's private-data library (passkey + PRF-derived key) when it
//     lands — via migrate(), with no onboarding required first.
//   - nym_auth: the credential + its response metadata (the ssc opening
//     the zkp proofs need) store together, verbatim.
//   - cross-device presentation: present(authorizationRequest) drives the
//     oid4vp flow; the zkp_req proof path plugs in through ui.vp.

import {
  LocalStorageWalletStorage,
  MemoryWalletStorage,
} from "./storage.js";
import { migrateWalletStorage } from "./migration.js";
import {
  isOfferUri,
  normalizeOffer,
  unwrapAuthorizationRequest,
  unwrapOffer,
} from "./offer.js";
import type {
  MiniWalletEvent,
  MiniWalletFetch,
  MiniWalletPdp,
  MiniWalletUi,
  StoredCredential,
  WalletStorage,
} from "./types.js";

/** The engine module, injected by the page — it loads the published wasm
 *  its own way (a bundler import of the package name, or a URL import of
 *  the artifact; a bare specifier never resolves in a plain browser).
 *  Absent, the library falls back to a dynamic import of the package
 *  name, which a bundler resolves at build time. */
export interface EngineModule {
  init(wasmUrl?: string): Promise<unknown>;
  WasmEngine: new (config: unknown) => EngineLike;
}

/** The engine's shape — the published .d.ts's class, minimally typed so
 *  this file compiles without the peer dep installed. */
interface EngineLike {
  request(method: string, params: unknown): Promise<unknown>;
}

export interface MiniWalletOptions {
  /** The storage backend; the browser localStorage by default. */
  storage?: WalletStorage;
  /** The page's UI callbacks — delegated verbatim to the engine host. */
  ui?: MiniWalletUi;
  /** The trust callback — the engine's PDP. Required. */
  pdp: MiniWalletPdp;
  /** The page's fetch; the browser default when absent. */
  fetch?: MiniWalletFetch;
  /** The wasm URL — the bundler-resolved default when absent. */
  wasmUrl?: string;
  /** The engine module (see EngineModule): the page loads the published
   *  wasm its own way and hands it over. */
  engine?: EngineModule;
  /** Every event the wallet surfaces: progress, credentials, errors. */
  onEvent?: (event: MiniWalletEvent) => void;
}

const CREDENTIAL_PREFIX = "credential:";

export class MiniWallet {
  readonly #opts: MiniWalletOptions;
  #storage: WalletStorage;
  #engine: EngineLike | null = null;
  #sessionId: string | null = null;
  #deviceJwk: Record<string, unknown> | null = null;
  /** The late frames' joins (an error after the start answered, a
   *  completion the transport carries) — the standard flows resolve on
   *  the start's request itself. */
  readonly #pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  constructor(options: MiniWalletOptions) {
    if (!options.pdp) throw new Error("MiniWallet needs a pdp (the trust callback)");
    this.#opts = options;
    this.#storage =
      options.storage ??
      (typeof localStorage !== "undefined"
        ? new LocalStorageWalletStorage()
        : new MemoryWalletStorage());
  }

  // ── The engine: loaded once, the session created once ──────────────────

  async #ensureEngine(): Promise<{ engine: EngineLike; sessionId: string }> {
    if (this.#engine && this.#sessionId) return { engine: this.#engine, sessionId: this.#sessionId };
    // The page's module when it injected one; the dynamic import (which
    // a bundler resolves) otherwise.
    const mod: EngineModule = this.#opts.engine
      ?? ((await import("@sirosfoundation/siros-wallet-core")) as unknown as EngineModule);
    await mod.init(this.#opts.wasmUrl);
    const engine = new mod.WasmEngine({
      fetch: this.#opts.fetch ?? defaultFetch(),
      pdp: { evaluate: (request: unknown) => this.#opts.pdp.evaluate(request) },
      host: {
        sign: (params: {
          flow_id: string;
          to_sign: number[];
          credential_configuration_id?: string;
          key_id?: string;
          algorithm: string;
        }) => this.#hostSign(params),
        signingKey: (params: {
          flow_id: string;
          credential_configuration_id?: string;
          key_id?: string;
          fresh?: boolean;
        }) => this.#hostSigningKey(params),
        consent: this.#opts.ui?.consent,
        match: this.#opts.ui?.match,
        txCode: this.#opts.ui?.txCode,
        vp: this.#opts.ui?.vp,
        openAuthorization: this.#opts.ui?.openAuthorization,
        attestation: this.#opts.ui?.attestation,
      },
      kv: {
        get: (key: string) => this.#storage.get(`stash:${key}`),
        put: (key: string, value: string) => this.#storage.put(`stash:${key}`, value),
        del: (key: string) => this.#storage.del(`stash:${key}`),
      },
      // The completions (and the errors) arrive here — the start's answer
      // alone never carries the credential (the same rule the WMP wire
      // has).
      onNotification: (text: string) => this.#onNotification(text),
    });
    const created = (await engine.request("wmp.session.create", {
      wmp: { version: "0.1", sender: "mini-wallet" },
      capabilities_offered: {
        flows: { max_concurrent: 4 },
        credential_notification: {
          events: ["credential_accepted", "credential_failure"],
          context_ttl_seconds: 300,
        },
      },
      security: { mode: "tls" },
    })) as { wmp?: { session_id?: string } };
    const sessionId = created?.wmp?.session_id;
    if (!sessionId) throw new Error("the engine created no session");
    this.#engine = engine;
    this.#sessionId = sessionId;
    this.#opts.onEvent?.({ type: "session", sessionId });
    return { engine, sessionId };
  }

  #onNotification(text: string): void {
    // The transport envelope: {jsonrpc, method, params} — the progress
    // frames and (for anything completing after the start's answer) the
    // completions. The standard flows resolve ON the start's request
    // (the engine runs them inside it); this sink carries the progress
    // and any late frame.
    let message: { method?: string; params?: Record<string, unknown> };
    try {
      message = JSON.parse(text);
    } catch {
      return; // a non-JSON frame — nothing to surface
    }
    const params = message.params ?? {};
    const flowId = typeof params.flow_id === "string" ? params.flow_id : undefined;
    if (!flowId) return;
    if (message.method === "wmp.flow.error") {
      const error = (params.error ?? {}) as { code?: number; message?: string };
      this.#pending.get(flowId)?.reject(new Error(error.message ?? "the flow failed"));
      this.#pending.delete(flowId);
      this.#opts.onEvent?.({ type: "flow-error", flowId, code: error.code, message: error.message ?? "the flow failed" });
      return;
    }
    if (message.method === "wmp.flow.progress") {
      this.#opts.onEvent?.({
        type: "progress",
        flowId,
        step: typeof (params as Record<string, unknown>).step === "string" ? (params as Record<string, unknown>).step as string : "",
      });
    }
  }

  /** The completion of a START's answer: the result the engine resolved
   *  the request with — {flow_id, credentials?, redirect_uri?, …}. The
   *  delivered credentials store here. */
  #complete(flowId: string, result: Record<string, unknown>): unknown {
    const credentials = (result.credentials ?? []) as Array<Record<string, unknown>>;
    for (const entry of credentials) this.#storeCredential(entry);
    this.#opts.onEvent?.({
      type: credentials.length ? "credential-received" : "presented",
      flowId,
      configurationId:
        typeof credentials[0]?.credential_configuration_id === "string"
          ? (credentials[0].credential_configuration_id as string)
          : undefined,
    });
    return result;
  }

  // ── The flows ───────────────────────────────────────────────────────────

  /**
   * Receive a credential: an offer URI (https), the
   * `openid-credential-offer://` deep link, or the offer object an
   * embedded issuer flow already holds. Resolves when the flow completes
   * (the stored credential records ride the result); rejects when the
   * flow errors or the page's UI refuses a sub-flow.
   */
  async receiveCredential(offer: string | Record<string, unknown>): Promise<unknown> {
    const normalized =
      typeof offer === "string" ? await this.#resolveOffer(offer) : normalizeOffer(offer, "inline");
    const { engine, sessionId } = await this.#ensureEngine();
    const flowId = `flow-${crypto.randomUUID()}`;
    const answer = (await engine.request("wmp.flow.start", {
      wmp: { session_id: sessionId, version: "0.1" },
      flow_id: flowId,
      flow_type: "oid4vci",
      params: {
        credential_issuer: normalized.credential_issuer,
        credential_configuration_ids: normalized.credential_configuration_ids,
        grants: normalized.grants,
      },
    })) as Record<string, unknown> | null;
    return answer ? this.#complete(flowId, answer) : answer;
  }

  /**
   * Present to a verifier: the scanned cross-device request — the
   * `openid4vp://` link or the https request URI. The zkp_req proof
   * path plugs in through the ui.vp callback; the page owns the approval.
   */
  async present(request: string): Promise<unknown> {
    const { params } = unwrapAuthorizationRequest(request);
    const { engine, sessionId } = await this.#ensureEngine();
    const flowId = `flow-${crypto.randomUUID()}`;
    const answer = (await engine.request("wmp.flow.start", {
      wmp: { session_id: sessionId, version: "0.1" },
      flow_id: flowId,
      flow_type: "oid4vp",
      params,
    })) as Record<string, unknown> | null;
    return answer ? this.#complete(flowId, answer) : answer;
  }

  async #resolveOffer(uri: string) {
    if (!isOfferUri(uri)) return normalizeOffer(JSON.parse(uri) as Record<string, unknown>, "inline");
    const unwrapped = unwrapOffer(uri);
    if ("offer" in unwrapped) return normalizeOffer(unwrapped.offer, unwrapped.source);
    // Through the page's fetch port — the same one the engine's HTTP
    // uses: a page that proxies its issuer (a browser wallet cannot
    // cross-origin it) serves the offer fetch too.
    const fetchPort = this.#opts.fetch ?? defaultFetch();
    const answer = await fetchPort({ method: "GET", url: unwrapped.uri, headers: [] });
    if (answer.status !== 200) throw new Error(`the offer fetch answered ${answer.status}`);
    const text = new TextDecoder().decode(new Uint8Array(answer.body));
    return normalizeOffer(JSON.parse(text) as Record<string, unknown>, unwrapped.source);
  }

  // ── The custody ─────────────────────────────────────────────────────────

  /** Store one delivered credential — the value plus its format and
   *  configuration, and the response-level metadata verbatim (the
   *  nym_auth ssc opening rides it; the zkp proofs read it back). */
  #storeCredential(entry: Record<string, unknown>): StoredCredential {
    const id = crypto.randomUUID();
    const record = {
      format: entry.format,
      credential_configuration_id: entry.credential_configuration_id,
      credential: entry.credential,
      // The response-level metadata (the ssc opening), when the
      // completion carried it.
      credential_metadata: entry.credential_metadata,
      received_at_unix: Math.floor(Date.now() / 1000),
    };
    const key = `${CREDENTIAL_PREFIX}${id}`;
    void this.#storage.put(key, JSON.stringify(record));
    return {
      key,
      format: typeof record.format === "string" ? record.format : "",
      configurationId:
        typeof record.credential_configuration_id === "string"
          ? record.credential_configuration_id
          : undefined,
      receivedAtUnix: record.received_at_unix,
    };
  }

  /** The stored credentials (the listing the page renders). The values
   *  stay in the storage; only the records' envelopes come back. */
  async credentials(): Promise<StoredCredential[]> {
    const keys = await this.#storage.list(CREDENTIAL_PREFIX);
    const out: StoredCredential[] = [];
    for (const key of keys) {
      const raw = await this.#storage.get(key);
      if (!raw) continue;
      try {
        const record = JSON.parse(raw) as Record<string, unknown>;
        out.push({
          key,
          format: typeof record.format === "string" ? record.format : "",
          configurationId:
            typeof record.credential_configuration_id === "string"
              ? record.credential_configuration_id
              : undefined,
          receivedAtUnix: typeof record.received_at_unix === "number" ? record.received_at_unix : 0,
        });
      } catch {
        // A foreign record under the prefix — leave it; the listing only
        // reports what it can read.
      }
    }
    return out;
  }

  /** The raw stored record (the credential + its metadata) — the zkp
   *  presenter reads the ssc opening from here. */
  async rawCredential(key: string): Promise<Record<string, unknown> | null> {
    if (!key.startsWith(CREDENTIAL_PREFIX)) return null;
    const raw = await this.#storage.get(key);
    return raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
  }

  // ── The device key: generated once, stored (unencrypted until the
  // passkey migration — the design brief's deferred onboarding) ───────────

  /** The engine's SignParams: {flow_id, to_sign (the raw bytes),
   *  credential_configuration_id?, key_id?, algorithm}. The answer is
   *  SignResult: {signature (bytes)}. The batch rule (fresh keys) lives
   *  in #hostSigningKey; the sign ask names its configuration, so the
   *  key lookup pairs the two. */
  async #hostSign(params: {
    flow_id: string;
    to_sign: number[];
    credential_configuration_id?: string;
    key_id?: string;
    algorithm: string;
  }): Promise<{ signature: number[] }> {
    const jwk = await this.#keyFor(params.credential_configuration_id, params.key_id);
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk as JsonWebKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      cryptoKey,
      new Uint8Array(params.to_sign),
    );
    return { signature: Array.from(new Uint8Array(signature)) };
  }

  /** The key an ask pairs with: the configuration's fresh key when it
   *  has one (the batch rule), the device key otherwise. */
  async #keyFor(configurationId?: string, keyId?: string): Promise<Record<string, unknown>> {
    if (configurationId) {
      const stored = await this.#storage.get(`key:config:${configurationId}`);
      if (stored) return JSON.parse(stored) as Record<string, unknown>;
    }
    if (!this.#deviceJwk) {
      const stored = await this.#storage.get("key:device");
      this.#deviceJwk = stored
        ? (JSON.parse(stored) as Record<string, unknown>)
        : await this.#generateKey("key:device");
    }
    return this.#deviceJwk;
  }

  /** The engine's SigningKeyParams: {flow_id, credential_configuration_id?,
   *  key_id?, fresh} — the OID4VCI batch rule (SDJWT-10.1): a fresh ask
   *  generates a new key for that configuration, so credentials in a
   *  batch do not link. The answer is the public JWK. */
  async #hostSigningKey(params: {
    flow_id: string;
    credential_configuration_id?: string;
    key_id?: string;
    fresh?: boolean;
  }): Promise<{ jwk: Record<string, unknown> }> {
    if (params.fresh && params.credential_configuration_id) {
      const key = await this.#generateKey(`key:config:${params.credential_configuration_id}`);
      return { jwk: publicOf(key) };
    }
    return { jwk: publicOf(await this.#keyFor(params.credential_configuration_id, params.key_id)) };
  }

  async #generateKey(storeKey: string): Promise<Record<string, unknown>> {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    );
    const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as unknown as Record<string, unknown>;
    jwk.alg = "ES256";
    jwk.use = "sig";
    await this.#storage.put(storeKey, JSON.stringify(jwk));
    return jwk;
  }

  // ── The deferred onboarding: the storage migration ─────────────────────

  /**
   * Migrate to a new storage backend — the unencrypted → passkey-
   * encrypted swap. The default backend swaps to `target` AFTER every
   * key verified against it; the wallet keeps working throughout, and a
   * failure leaves the source intact (the report names the key).
   */
  async migrate(target: WalletStorage) {
    const report = await migrateWalletStorage(this.#storage, target);
    if (!report.failed) this.#storage = target;
    return report;
  }
}

// ── The helpers ─────────────────────────────────────────────────────────────

function publicOf(jwk: Record<string, unknown>): Record<string, unknown> {
  const out = { ...jwk };
  delete out.d;
  return out;
}

/** The browser fetch adapted to the engine's port — the shape the
 *  published .d.ts documents (the flat [name, value, ...] headers). */
function defaultFetch(): MiniWalletFetch {
  return async (request) => {
    const req = request as {
      method: string;
      url: string;
      headers: string[];
      body?: string;
    };
    const headers: Record<string, string> = {};
    for (let i = 0; i + 1 < req.headers.length; i += 2) {
      headers[req.headers[i]!] = req.headers[i + 1]!;
    }
    const init: RequestInit = { method: req.method, headers };
    // The port sends body: null on bodyless requests — the fetch API
    // refuses a body on GET/HEAD.
    if (req.body != null && req.method !== "GET" && req.method !== "HEAD") init.body = req.body;
    const response = await fetch(req.url, init);
    const flat: string[] = [];
    response.headers.forEach((value, name) => flat.push(name, value));
    // The port's body is BYTES (the engine's Vec<u8>), not text.
    const text = await response.text();
    const body = Array.from(new TextEncoder().encode(text));
    return {
      status: response.status,
      headers: flat,
      body,
    };
  };
}
