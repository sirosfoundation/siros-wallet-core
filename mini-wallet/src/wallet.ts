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
import { asPdp, AuthzenTrustPlugin } from "./trust.js";
import type { TrustPlugin, TrustTokenProvider } from "./trust.js";
import type { MiniWalletPdpOption } from "./types.js";
import { GoWalletBackendTarget, NullCipher } from "./adopt.js";
import { ZkpPresenterPort, fromEngineJson } from "./presenter.js";
import type { PresenterOptions } from "./presenter.js";
import type { AdoptReport, AdoptTarget, AdoptUi, PrivateDataCipher } from "./adopt.js";
import type { AdoptModal } from "./types.js";
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

/** The permanent-wallet backend the page's wallet is configured against
 *  — a go-wallet-backend. When present, the wallet's trust layer is the
 *  BACKEND'S PDP-PROXY from the first issuance (the tenant's policy
 *  decides which issuers this deployment trusts — the page never
 *  guesses), and the adopt defaults to this backend.
 *
 *  The evaluations carry the token the backend demands: before any user
 *  exists, the PRE-REGISTRATION TENANT TOKEN (go-wallet-backend#566's
 *  slot — supply it until the backend ships the anonymous path); after
 *  the adopt, the passkey session's token (the provider swaps
 *  automatically — the trust plugin never sees the difference). */
export interface MiniWalletBackend {
  /** The backend's base URL (the gdc instance, for the demo). */
  url: string;
  /** The AS's tenant (the register/login headers). */
  tenantId?: string;
  /** The evaluation token — the provider the trust layer consults on
   *  every evaluation. Supply the pre-registration tenant token here
   *  until #566 ships. */
  token?: TrustTokenProvider;
}

export interface MiniWalletOptions {
  /** The storage backend; the browser localStorage by default. */
  storage?: WalletStorage;
  /** The page's UI callbacks — delegated verbatim to the engine host. */
  ui?: MiniWalletUi;
  /** The trust layer — the engine's PDP. A TrustPlugin (the
   *  authzen-client's home; AlwaysTrustedPlugin is the demo shim) or
   *  the raw port shape — OR derived from the `backend` when present
   *  (the backend's PDP-proxy; the backend's token rides along). */
  pdp?: MiniWalletPdpOption;
  /** The permanent-wallet backend (see MiniWalletBackend). When set,
   *  the trust layer is the backend's PDP-proxy and the adopt defaults
   *  to this backend. */
  backend?: MiniWalletBackend;
  /** The page's fetch; the browser default when absent. */
  fetch?: MiniWalletFetch;
  /** The wasm URL — the bundler-resolved default when absent. */
  wasmUrl?: string;
  /** The engine module (see EngineModule): the page loads the published
   *  wasm its own way and hands it over. */
  engine?: EngineModule;
  /** The zkp presenter: the browser presenter wasm + the circuits
   *  artifact the page serves. When set, the wallet answers the
   *  engine's `vp` ask itself (the page's `ui.consent` still gates
   *  every presentation; a page's own `ui.vp` replaces this seam) and
   *  defaults the `match` ask when the page provides none. */
  presenter?: PresenterOptions;
  /** A2: the bound on the engine's flow-start answer (milliseconds).
   *  A transport that never answers rejects the flow instead of hanging
   *  it forever. The user-paced asks (consent, the tx code) run INSIDE
   *  the request, so the default is generous: 300_000. `0` disables the
   *  bound. */
  requestTimeoutMs?: number;
  /** Every event the wallet surfaces: progress, credentials, errors. */
  onEvent?: (event: MiniWalletEvent) => void;
}

const CREDENTIAL_PREFIX = "credential:";

export class MiniWallet {
  #opts: MiniWalletOptions;
  #storage: WalletStorage;
  #deviceJwk: Record<string, unknown> | null = null;
  /** The late frames' joins (an error after the start answered, a
   *  completion the transport carries) — the standard flows resolve on
   *  the start's request itself. */
  readonly #pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

  #trustToken: TrustTokenProvider | undefined;
  /** The zkp presenter seam, when the option configured one. */
  #presenter: ZkpPresenterPort | null = null;
  /** The live engine + its session — dispose()'s handles (A5). */
  #engine: EngineLike | null = null;
  #sessionId: string | null = null;

  constructor(options: MiniWalletOptions) {
    if (!options.pdp && !options.backend) {
      throw new Error("MiniWallet needs a trust layer: a pdp plugin or a backend (its PDP-proxy)");
    }
    this.#trustToken = options.backend?.token;
    this.#opts = options;
    this.#storage =
      options.storage ??
      (typeof localStorage !== "undefined"
        ? new LocalStorageWalletStorage()
        : new MemoryWalletStorage());
    // The zkp seam: the wasm presenter + the wallet's own custody (the
    // device key signs dataToSign between the presenter's steps; the key
    // never crosses the wasm boundary).
    this.#presenter = options.presenter
      ? new ZkpPresenterPort(options.presenter, {
          sign: (bytes) => this.#signWithDeviceKey(bytes),
          rawCredential: (key) => this.rawCredential(key),
          credentials: async () => (await this.credentials()).map((c) => ({ key: c.key })),
        })
      : null;
  }

  /** The wallet's trust layer: the backend's PDP-proxy when configured
   *  (the token provider riding along), the pdp option otherwise. */
  #pdpOf(): MiniWalletPdpOption {
    const backend = this.#opts.backend;
    if (backend) {
      return new AuthzenTrustPlugin(`${backend.url.replace(/\/$/, "")}/v1/evaluate`, () => this.#evaluationToken());
    }
    return this.#opts.pdp!;
  }

  /** The evaluation token: the session's after the adopt, the
   *  configured pre-registration provider before it. */
  async #evaluationToken(): Promise<string | null> {
    return this.#sessionToken ? await this.#sessionToken() : (this.#trustToken ? await this.#trustToken() : null);
  }

  #sessionToken: TrustTokenProvider | undefined;

  // ── The engine: loaded once, the session created once ──────────────────

  /** Memoized SYNCHRONOUSLY: two concurrent flows (a receiveCredential
   *  racing a present) must not each import the module, build an engine
   *  and open a session — one promise, both callers, one orphaned-less
   *  session. A failed creation clears the slot so a retry can run. */
  #ready: Promise<{ engine: EngineLike; sessionId: string }> | null = null;

  async #ensureEngine(): Promise<{ engine: EngineLike; sessionId: string }> {
    if (!this.#ready) {
      this.#ready = this.#createEngine().catch((err) => {
        this.#ready = null;
        throw err;
      });
    }
    return this.#ready;
  }

  async #createEngine(): Promise<{ engine: EngineLike; sessionId: string }> {
    // The page's module when it injected one; the dynamic import (which
    // a bundler resolves) otherwise.
    const mod: EngineModule = this.#opts.engine
      ?? ((await import("@sirosfoundation/siros-wallet-core")) as unknown as EngineModule);
    await mod.init(this.#opts.wasmUrl);
    const engine = new mod.WasmEngine({
      fetch: this.#opts.fetch ?? defaultFetch(),
      pdp: asPdp(this.#pdpOf() as TrustPlugin),
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
        // The match: the seam captures every ask (the presenter's
        // inputs); the page's own match — when present — answers it,
        // the seam's default otherwise.
        match: this.#presenter
          ? (params: unknown) => this.#hostMatch(params as { flow_id: string })
          : this.#opts.ui?.match,
        txCode: this.#opts.ui?.txCode,
        // The vp: the page's own construction when it provides one; the
        // presenter seam otherwise (the consent ask already gated the
        // presentation — the vp ask is construction, not consent).
        vp: this.#opts.ui?.vp
          ?? (this.#presenter
            ? (params: unknown) => this.#hostVp(params as { flow_id: string })
            : undefined),
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
    // A fresh engine session: no prior flow can still be signing, so any
    // per-flow key a crashed flow left is garbage. Sweep them (the
    // settle-time deletion is the normal path; this is the belt).
    for (const stale of await this.#storage.list("key:flow:")) {
      await this.#storage.del(stale).catch(() => {});
    }
    this.#engine = engine;
    this.#opts.onEvent?.({ type: "session", sessionId });
    return { engine, sessionId };
  }

  /** A settled flow's fresh key is gone with it (the batch rule's keys
   *  are per-flow; leaving them accumulates private EC JWKs in storage —
   *  and post-migration, in the backend's blob). Best-effort: a failed
   *  delete leaves one key for the session-start sweep. */
  #flowCleanup(flowId: string): void {
    this.#storage.del(`key:flow:${flowId}`).catch(() => {});
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
      // Only a LIVE flow's error reaches the page: a late frame for a
      // settled flow is stale news, not a new failure.
      const error = (params.error ?? {}) as { code?: number; message?: string };
      const pending = this.#pending.get(flowId);
      if (pending) {
        this.#pending.delete(flowId);
        pending.reject(new Error(error.message ?? "the flow failed"));
        this.#flowCleanup(flowId);
        this.#opts.onEvent?.({ type: "flow-error", flowId, code: error.code, message: error.message ?? "the flow failed" });
      }
      return;
    }
    if (message.method === "wmp.flow.progress") {
      this.#opts.onEvent?.({
        type: "progress",
        flowId,
        step: typeof (params as Record<string, unknown>).step === "string" ? (params as Record<string, unknown>).step as string : "",
      });
      return;
    }
    if (message.method === "wmp.flow.complete") {
      // The completion frame: {wmp, flow_id, …result}. The credentials
      // ride the result members (params.result when the transport wraps
      // one, the params themselves when they ARE the result).
      const result = ((params.result ?? params) as Record<string, unknown>);
      const pending = this.#pending.get(flowId);
      this.#pending.delete(flowId);
      // The RAW result: the pending wrapper (set in #runFlow) owns the
      // single #complete — calling it here as well stored every credential
      // twice and emitted credential-received twice. The wrapper's finish
      // runs the flow-key cleanup.
      pending?.resolve(result);
    }
  }

  /** The completion of a START's answer: the result the engine resolved
   *  the request with — {flow_id, credentials?, redirect_uri?, …}. The
   *  delivered credentials store here. */
  async #complete(flowId: string, rawResult: Record<string, unknown>): Promise<unknown> {
    // The engine's return values serialize raw-JSON members as nested JS
    // Maps (the same serde default the host asks carry): the completion's
    // `credential_metadata` is a Map, and a Map stringifies as {} — the
    // ssc opening (the zkp proofs' seed) died HERE at storage before the
    // deep conversion. Convert ONCE, at the boundary.
    const result = fromEngineJson(rawResult) as Record<string, unknown>;
    const credentials = (result.credentials ?? []) as Array<Record<string, unknown>>;
    // A1: the puts are AWAITED — a resolved receiveCredential means a
    // persisted credential, not a put still in flight that a reload in
    // the window would lose. The put's own failure names the loss as the
    // flow-error below; the flow settles either way.
    for (const entry of credentials) await this.#storeCredential(entry, flowId);
    this.#opts.onEvent?.({
      // "presented": a flow completing WITHOUT credentials — a verifier
      // presentation, or an issuance that ended in a redirect alone
      // (both are "nothing stored"; the flow type is not the event's
      // business — the page distinguishes by context if it must).
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
   * Probe the trust layer directly — the page's own trust question
   * (the backend's PDP-proxy when configured; the token rides along).
   */
  async evaluateTrust(ask: Record<string, unknown>): Promise<{ trusted: boolean; decision?: string; context?: unknown }> {
    const pdp = this.#pdpOf();
    const plugin = ("evaluate" in pdp ? pdp : asPdp(pdp as MiniWalletPdpOption)) as TrustPlugin;
    return plugin.evaluate(ask as Parameters<TrustPlugin["evaluate"]>[0]);
  }

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
    return this.#runFlow(flowId, () =>
      engine.request("wmp.flow.start", {
        wmp: { session_id: sessionId, version: "0.1" },
        flow_id: flowId,
        flow_type: "oid4vci",
        params: {
          credential_issuer: normalized.credential_issuer,
          credential_configuration_ids: normalized.credential_configuration_ids,
          grants: normalized.grants,
        },
      }),
    );
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
    return this.#runFlow(flowId, () =>
      engine.request("wmp.flow.start", {
        wmp: { session_id: sessionId, version: "0.1" },
        flow_id: flowId,
        flow_type: "oid4vp",
        params,
      }),
    );
  }

  /** Run one flow: the start's request may resolve WITH the completion
   *  (the synchronous shape — the conformance smoke's) or with the bare
   *  started envelope ({flow_id, flow_type, wmp}), the completion joining
   *  later through the notification sink. Both paths resolve the same
   *  promise exactly once. */
  #runFlow(flowId: string, start: () => Promise<unknown>): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (value: unknown) => {
        if (settled) return;
        settled = true;
        this.#pending.delete(flowId);
        this.#flowCleanup(flowId);
        resolve(value);
      };
      this.#pending.set(flowId, {
        resolve: (result) => {
          // A1's other half: the completion's store is awaited before the
          // flow settles.
          void this.#complete(flowId, result as Record<string, unknown>).then(finish, finish);
        },
        reject: (err) => {
          if (settled) return;
          settled = true;
          this.#pending.delete(flowId);
          reject(err);
        },
      });
      // A2: the START's answer is bounded — a transport that never
      // answers (a hung engine, a dead worker) rejects the flow instead
      // of hanging it forever. The user-paced asks run INSIDE the
      // request, so the default is generous; 0 disables the bound.
      const bound = this.#opts.requestTimeoutMs !== 0
        ? Promise.race([
            start(),
            new Promise<never>((_, reject) => {
              timer = setTimeout(
                () => reject(new Error("the engine never answered the flow start")),
                this.#opts.requestTimeoutMs ?? 300_000,
              );
            }),
          ])
        : start();
      let timer: ReturnType<typeof setTimeout> | undefined;
      bound
        .then((answer) => {
          const result = answer as Record<string, unknown> | null;
          // The synchronous completion carries the flow's result members
          // (credentials, redirect_uri); the bare started envelope
          // ({flow_id, flow_type, wmp} and nothing else) does not — its
          // completion joins via the sink. ANY other non-null answer is a
          // result and settles the flow: a shape carrying neither
          // credentials nor a redirect is still an answer, never a hang.
          const started = result && typeof result.flow_type === "string" && result.wmp !== undefined;
          if (result && !started) {
            void this.#complete(flowId, result).then(finish, finish);
          }
        })
        .catch((err) => {
          if (settled) return;
          settled = true;
          this.#pending.delete(flowId);
          this.#flowCleanup(flowId);
          // DEBUG(one run): the engine's rejections are wasm-bindgen
          // objects with no string form — surface the raw shape.
          const detail = err && typeof err === "object"
            ? (() => { try { return JSON.stringify(err); } catch { return `keys:[${Object.getOwnPropertyNames(err).join(",")}]`; } })()
            : String(err);
          reject(err instanceof Error ? err : new Error(`the flow rejected: ${detail.slice(0, 600)}`));
        })
        .finally(() => {
          if (timer) clearTimeout(timer);
        });
    });
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
  async #storeCredential(entry: Record<string, unknown>, flowId: string): Promise<StoredCredential> {
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
    // A rejected put is the page's storage failing: name the loss as a
    // flow-error (the credential-received event alone would lie). The
    // put stays async — #complete is the flow's result builder, and the
    // event order (received, then the store's failure) is documented.
    try {
      await this.#storage.put(key, JSON.stringify(record));
    } catch (err) {
      this.#opts.onEvent?.({
        type: "flow-error",
        flowId,
        message: `the credential did not store: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
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
    if (!raw) return null;
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return null; // a foreign or quota-truncated record: unreadable, not a crash
    }
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
    // This wallet signs ES256 (P-256) and nothing else: an ask naming
    // another algorithm signs WRONG here, so it fails loudly instead.
    if (params.algorithm && params.algorithm !== "ES256") {
      throw new Error(`this wallet signs ES256 only; the ask names ${params.algorithm}`);
    }
    const jwk = await this.#keyFor(params.flow_id, params.credential_configuration_id, params.key_id);
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

  /** The key an ask pairs with: the FLOW's fresh key first (the batch
   *  rule's keys are per-flow — two concurrent flows on one
   *  configuration each keep their own, so neither overwrites the
   *  other's proofs), then the configuration's, then the device key. */
  async #keyFor(flowId?: string, configurationId?: string, keyId?: string): Promise<Record<string, unknown>> {
    // Every tier's parse is guarded: a corrupt (quota-truncated) record
    // is an ABSENT key — fall through to the next tier, never a crash out
    // of a credential read.
    if (flowId) {
      const flow = await this.#storage.get(`key:flow:${flowId}`);
      if (flow) {
        try {
          return JSON.parse(flow) as Record<string, unknown>;
        } catch { /* unreadable: fall through */ }
      }
    }
    if (configurationId) {
      const stored = await this.#storage.get(`key:config:${configurationId}`);
      if (stored) {
        try {
          return JSON.parse(stored) as Record<string, unknown>;
        } catch { /* unreadable: fall through */ }
      }
    }
    if (!this.#deviceJwk) {
      const stored = await this.#storage.get("key:device");
      if (stored) {
        try {
          this.#deviceJwk = JSON.parse(stored) as Record<string, unknown>;
        } catch { /* unreadable: a fresh device key */ }
      }
      if (!this.#deviceJwk) this.#deviceJwk = await this.#generateKey("key:device");
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
      // Per-FLOW, get-or-create: a concurrent second flow on the same
      // configuration used to overwrite `key:config:<id>` and orphan
      // the first flow's proofs; `key:flow:<flow_id>` cannot collide.
      // Two fresh asks on ONE flow (a same-flow race) return the SAME
      // key — the second would otherwise orphan the first's proofs.
      const storeKey = `key:flow:${params.flow_id}`;
      const existing = await this.#storage.get(storeKey);
      if (existing) {
        try {
          return { jwk: publicOf(JSON.parse(existing) as Record<string, unknown>) };
        } catch { /* unreadable: a fresh key below */ }
      }
      const key = await this.#generateKey(storeKey);
      return { jwk: publicOf(key) };
    }
    return { jwk: publicOf(await this.#keyFor(params.flow_id, params.credential_configuration_id, params.key_id)) };
  }

  /** The match ask through the seam: the capture always runs (the
   *  presenter's inputs); the page's match answers when present, the
   *  seam's default (the first stored credential per query) otherwise. */
  async #hostMatch(params: { flow_id: string }): Promise<unknown> {
    const captured = await this.#presenter?.match(params.flow_id, params as never);
    if (this.#opts.ui?.match) return await this.#opts.ui.match(params);
    return captured ?? { selections: [] };
  }

  /** The vp ask through the seam: the presenter's answer, in the
   *  engine's VpResult shape ({vp_token} or {refusal:{code}}). */
  async #hostVp(params: { flow_id: string }): Promise<unknown> {
    const port = this.#presenter;
    if (!port) throw new Error("the presenter seam is not configured");
    return port.vp(params.flow_id, params as never);
  }

  /** The device key's ES256 over raw bytes — the zkp presenter's
   *  dataToSign (the same custody #hostSign serves the engine's asks). */
  async #signWithDeviceKey(bytes: Uint8Array): Promise<Uint8Array> {
    const jwk = await this.#keyFor();
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
      bytes as unknown as ArrayBuffer,
    );
    return new Uint8Array(signature);
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

  /**
   * A5: the lifecycle the library owed. Best-effort: the session closes
   *  on the engine (a transport that already died is not an error), the
   *  pending flows reject (a page tearing down mid-flow hears it), and a
   *  later call re-creates the engine — dispose is a stop, not a tomb.
   */
  async dispose(): Promise<void> {
    const engine = this.#engine;
    this.#engine = null;
    this.#ready = null;
    const pending = [...this.#pending.values()];
    this.#pending.clear();
    for (const entry of pending) {
      entry.reject(new Error("the wallet was disposed"));
    }
    if (engine) {
      const sessionId = this.#sessionId;
      await engine.request("wmp.session.close", {
        wmp: { session_id: sessionId, version: "0.1" },
        reason: "complete",
      }).catch(() => {
        /* already gone: the close is best-effort */
      });
    }
  }

  /**
   * Adopt a permanent wallet: the page's mini-wallet moves onto a
   * go-wallet-backend — the ask ("add a permanent wallet?"), the
   * passkey (the AS's WebAuthn registration, the page's ceremony), the
   * credential MOVE (the migration contract: copy, verify, then wipe
   * the local copy), and from then on the wallet's authz is the
   * backend's PDP-proxy. Every UI decision is the page's callbacks.
   *
   * The private-data cipher is the pluggable slot for the private-data
   * library (the passkey's PRF-derived key wrapping the blob) — the
   * NullCipher until it lands, the same accepted posture as the
   * unencrypted localStorage phase, upgraded to a server-side account.
   */
  async adopt(options: {
    /** The backend to adopt; a GoWalletBackendTarget built from the
     *  URL when a string is given (the gdc instance, for the demo).
     *  Omitted when the wallet is backend-configured. */
    target?: AdoptTarget | string;
    /** The page's UI: the ask and the WebAuthn ceremony. */
    ui: AdoptUi;
    /** The blob's cipher — the private-data library's slot. */
    cipher?: PrivateDataCipher;
    /** The adopt's modal surface — the PAGE's own implementation of the
     *  AdoptModal contract (the library ships no renderer: every string,
     *  style and layout stays the page's). Pass an instance alongside
     *  `ui`: both asks run, and BOTH must consent — the page's false is
     *  a veto the modal never overrides. */
    modal?: AdoptModal;
  }): Promise<AdoptReport | null> {
    const target = options.target === undefined && this.#opts.backend
      ? new GoWalletBackendTarget(this.#opts.backend.url, this.#opts.backend.tenantId)
      : typeof options.target === "string"
        ? new GoWalletBackendTarget(options.target)
        : options.target!;
    const modal: AdoptModal | null = options.modal ?? null;
    // Everything from HERE on lives inside the try: the overlay is mounted,
    // so a rejected ask — or a throwing credentials() — must close it, never
    // leave it stuck on the page.
    try {
    const credentials = await this.credentials();
    const ask = { credentials, backend: target.backend };
    // BOTH ask, and BOTH must consent: the page's ask is a veto even when
    // a modal renders beside it (a page returning false is never overridden
    // by the modal's buttons — the promise only settles after the modal's
    // answer too, so a declined modal closes the ask, not a race).
    const go = modal
      ? (await Promise.all([options.ui.ask(ask), modal.ask(ask)])).every(Boolean)
      : await options.ui.ask(ask);
    if (!go) {
      modal?.declined();
      return null;
    }
      modal?.passkey();
      // The passkey: the AS's begin/finish around the page's ceremony.
      const { account } = await target.registerPasskey(options.ui);
      // The move: the migration contract onto the backend's storage.
      const cipher = options.cipher ?? new NullCipher();
      modal?.moving(credentials.map((c) => c.key));
      const report = await this.migrate(target.storage(cipher));
      if (report.failed) {
        modal?.failed(report.failed);
        return { account, keys: report.keys, failed: report.failed };
      }
      // The authz of the adopted configuration: the backend's PDP-proxy
      // carries the SESSION's token now (the adopt's continuity — the
      // pre-registration token's job ended with the user's arrival).
      const factory = target.sessionToken?.();
      this.#sessionToken = typeof factory === "function" ? factory : undefined;
      if (this.#opts.backend) {
        this.#opts = { ...this.#opts, backend: { ...this.#opts.backend, url: target.backend } };
      } else {
        this.#opts = { ...this.#opts, backend: { url: target.backend } };
      }
      this.#opts.onEvent?.({ type: "adopted", account, backend: target.backend });
      modal?.done({ account, backend: target.backend, keys: report.keys });
      return { account, keys: report.keys };
    } catch (error) {
      modal?.close();
      throw error;
    }
  }
}

// ── The helpers ─────────────────────────────────────────────────────────────

function publicOf(jwk: Record<string, unknown>): Record<string, unknown> {
  const out = { ...jwk };
  delete out.d;
  // The private export's key_ops says ["sign"] — a public JWK advertising
  // sign-only makes every verifier refuse to verify with it (found on
  // the wire: the issuer's invalid_proof, "JWK key_ops does not include
  // verify"). The public half carries no key_ops at all.
  delete out.key_ops;
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
    // The port sends body: null on bodyless requests (the fetch API
    // refuses a body on GET/HEAD), and its bodies are BYTE ARRAYS —
    // fetch stringifies a bare array comma-joined, so the bytes must
    // cross as bytes.
    if (req.body != null && req.method !== "GET" && req.method !== "HEAD") {
      init.body = typeof req.body === "string" ? req.body : new Uint8Array(req.body);
    }
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
