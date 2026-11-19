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
import { LocalStorageWalletStorage, MemoryWalletStorage, } from "./storage.js";
import { migrateWalletStorage } from "./migration.js";
import { isOfferUri, normalizeOffer, unwrapAuthorizationRequest, unwrapOffer, } from "./offer.js";
const CREDENTIAL_PREFIX = "credential:";
export class MiniWallet {
    #opts;
    #storage;
    #engine = null;
    #sessionId = null;
    #deviceJwk = null;
    /** The in-flight flows: the completion arrives through the engine's
     *  notification sink (the flow.complete message), not the start's
     *  answer — the pending map joins the two. */
    #pending = new Map();
    constructor(options) {
        if (!options.pdp)
            throw new Error("MiniWallet needs a pdp (the trust callback)");
        this.#opts = options;
        this.#storage =
            options.storage ??
                (typeof localStorage !== "undefined"
                    ? new LocalStorageWalletStorage()
                    : new MemoryWalletStorage());
    }
    // ── The engine: loaded once, the session created once ──────────────────
    async #ensureEngine() {
        if (this.#engine && this.#sessionId)
            return { engine: this.#engine, sessionId: this.#sessionId };
        // The peer dep's wasm-bindgen web build: init() then the class.
        const mod = (await import("@sirosfoundation/siros-wallet-core"));
        await mod.init(this.#opts.wasmUrl);
        const engine = new mod.WasmEngine({
            fetch: this.#opts.fetch ?? defaultFetch(),
            pdp: { evaluate: (request) => this.#opts.pdp.evaluate(request) },
            host: {
                sign: (params) => this.#hostSign(params),
                signingKey: () => this.#hostSigningKey(),
                consent: this.#opts.ui?.consent,
                match: this.#opts.ui?.match,
                txCode: this.#opts.ui?.txCode,
                vp: this.#opts.ui?.vp,
                openAuthorization: this.#opts.ui?.openAuthorization,
                attestation: this.#opts.ui?.attestation,
            },
            kv: {
                get: (key) => this.#storage.get(`stash:${key}`),
                put: (key, value) => this.#storage.put(`stash:${key}`, value),
                del: (key) => this.#storage.del(`stash:${key}`),
            },
            // The completions (and the errors) arrive here — the start's answer
            // alone never carries the credential (the same rule the WMP wire
            // has).
            onNotification: (text) => this.#onNotification(text),
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
        }));
        const sessionId = created?.wmp?.session_id;
        if (!sessionId)
            throw new Error("the engine created no session");
        this.#engine = engine;
        this.#sessionId = sessionId;
        this.#opts.onEvent?.({ type: "session", sessionId });
        return { engine, sessionId };
    }
    #onNotification(text) {
        let message;
        try {
            message = JSON.parse(text);
        }
        catch {
            return; // a non-JSON frame — nothing to join
        }
        const params = message.params ?? {};
        const flowId = typeof params.flow_id === "string" ? params.flow_id : undefined;
        if (!flowId)
            return;
        if (message.method === "wmp.flow.error") {
            const error = (params.error ?? {});
            this.#pending.get(flowId)?.reject(new Error(error.message ?? "the flow failed"));
            this.#pending.delete(flowId);
            this.#opts.onEvent?.({ type: "flow-error", flowId, code: error.code, message: error.message ?? "the flow failed" });
            return;
        }
        if (message.method === "wmp.flow.complete") {
            const pending = this.#pending.get(flowId);
            this.#pending.delete(flowId);
            const result = params.result;
            const credentials = (result?.credentials ?? []);
            const stored = [];
            for (const entry of credentials) {
                stored.push(this.#storeCredential(entry));
            }
            this.#opts.onEvent?.({
                type: result?.redirect_uri !== undefined ? "presented" : "credential-received",
                flowId,
                configurationId: typeof credentials[0]?.credential_configuration_id === "string"
                    ? credentials[0].credential_configuration_id
                    : undefined,
            });
            pending?.resolve(result ?? {});
        }
    }
    // ── The flows ───────────────────────────────────────────────────────────
    /**
     * Receive a credential: an offer URI (https), the
     * `openid-credential-offer://` deep link, or the offer object an
     * embedded issuer flow already holds. Resolves when the flow completes
     * (the stored credential records ride the result); rejects when the
     * flow errors or the page's UI refuses a sub-flow.
     */
    async receiveCredential(offer) {
        const normalized = typeof offer === "string" ? await this.#resolveOffer(offer) : normalizeOffer(offer, "inline");
        const { engine, sessionId } = await this.#ensureEngine();
        const flowId = `flow-${crypto.randomUUID()}`;
        const result = this.#track(flowId, () => engine.request("wmp.flow.start", {
            wmp: { session_id: sessionId, version: "0.1" },
            flow_id: flowId,
            flow_type: "oid4vci",
            params: {
                credential_issuer: normalized.credential_issuer,
                credential_configuration_ids: normalized.credential_configuration_ids,
                grants: normalized.grants,
            },
        }));
        return result;
    }
    /**
     * Present to a verifier: the scanned cross-device request — the
     * `openid4vp://` link or the https request URI. The zkp_req proof
     * path plugs in through the ui.vp callback; the page owns the approval.
     */
    async present(request) {
        const { params } = unwrapAuthorizationRequest(request);
        const { engine, sessionId } = await this.#ensureEngine();
        const flowId = `flow-${crypto.randomUUID()}`;
        return this.#track(flowId, () => engine.request("wmp.flow.start", {
            wmp: { session_id: sessionId, version: "0.1" },
            flow_id: flowId,
            flow_type: "oid4vp",
            params,
        }));
    }
    async #resolveOffer(uri) {
        if (!isOfferUri(uri))
            return normalizeOffer(JSON.parse(uri), "inline");
        const unwrapped = unwrapOffer(uri);
        const offer = "offer" in unwrapped
            ? unwrapped.offer
            : await (await fetch(unwrapped.uri)).json();
        return normalizeOffer(offer, unwrapped.source);
    }
    #track(flowId, start) {
        return new Promise((resolve, reject) => {
            this.#pending.set(flowId, { resolve, reject });
            start().catch((err) => {
                // The start itself refused (an unknown flow, bad params): the
                // completion never comes; fail the promise here.
                this.#pending.delete(flowId);
                reject(err instanceof Error ? err : new Error(String(err)));
            });
        });
    }
    // ── The custody ─────────────────────────────────────────────────────────
    /** Store one delivered credential — the value plus its format and
     *  configuration, and the response-level metadata verbatim (the
     *  nym_auth ssc opening rides it; the zkp proofs read it back). */
    #storeCredential(entry) {
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
            configurationId: typeof record.credential_configuration_id === "string"
                ? record.credential_configuration_id
                : undefined,
            receivedAtUnix: record.received_at_unix,
        };
    }
    /** The stored credentials (the listing the page renders). The values
     *  stay in the storage; only the records' envelopes come back. */
    async credentials() {
        const keys = await this.#storage.list(CREDENTIAL_PREFIX);
        const out = [];
        for (const key of keys) {
            const raw = await this.#storage.get(key);
            if (!raw)
                continue;
            try {
                const record = JSON.parse(raw);
                out.push({
                    key,
                    format: typeof record.format === "string" ? record.format : "",
                    configurationId: typeof record.credential_configuration_id === "string"
                        ? record.credential_configuration_id
                        : undefined,
                    receivedAtUnix: typeof record.received_at_unix === "number" ? record.received_at_unix : 0,
                });
            }
            catch {
                // A foreign record under the prefix — leave it; the listing only
                // reports what it can read.
            }
        }
        return out;
    }
    /** The raw stored record (the credential + its metadata) — the zkp
     *  presenter reads the ssc opening from here. */
    async rawCredential(key) {
        if (!key.startsWith(CREDENTIAL_PREFIX))
            return null;
        const raw = await this.#storage.get(key);
        return raw ? JSON.parse(raw) : null;
    }
    // ── The device key: generated once, stored (unencrypted until the
    // passkey migration — the design brief's deferred onboarding) ───────────
    async #hostSigningKey() {
        if (!this.#deviceJwk) {
            const stored = await this.#storage.get("key:device");
            this.#deviceJwk = stored
                ? JSON.parse(stored)
                : await this.#generateDeviceKey();
        }
        return { jwk: publicOf(this.#deviceJwk) };
    }
    async #hostSign(params) {
        const key = await this.#hostSigningKey();
        const privateJwk = this.#deviceJwk;
        const data = new TextEncoder().encode(JSON.stringify(params));
        const cryptoKey = await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
        const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, cryptoKey, data);
        // The exact answer shape the engine's host port documents; the
        // signature base64url.
        return { jwk: key.jwk, signature: b64url(new Uint8Array(signature)) };
    }
    async #generateDeviceKey() {
        const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
        jwk.alg = "ES256";
        jwk.use = "sig";
        await this.#storage.put("key:device", JSON.stringify(jwk));
        return jwk;
    }
    // ── The deferred onboarding: the storage migration ─────────────────────
    /**
     * Migrate to a new storage backend — the unencrypted → passkey-
     * encrypted swap. The default backend swaps to `target` AFTER every
     * key verified against it; the wallet keeps working throughout, and a
     * failure leaves the source intact (the report names the key).
     */
    async migrate(target) {
        const report = await migrateWalletStorage(this.#storage, target);
        if (!report.failed)
            this.#storage = target;
        return report;
    }
}
// ── The helpers ─────────────────────────────────────────────────────────────
function publicOf(jwk) {
    const out = { ...jwk };
    delete out.d;
    return out;
}
function b64url(bytes) {
    let binary = "";
    for (const b of bytes)
        binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/** The browser fetch adapted to the engine's port — the shape the
 *  published .d.ts documents (the flat [name, value, ...] headers). */
function defaultFetch() {
    return async (request) => {
        const req = request;
        const headers = {};
        for (let i = 0; i + 1 < req.headers.length; i += 2) {
            headers[req.headers[i]] = req.headers[i + 1];
        }
        const response = await fetch(req.url, {
            method: req.method,
            headers,
            body: req.body,
        });
        const flat = [];
        response.headers.forEach((value, name) => flat.push(name, value));
        return {
            status: response.status,
            headers: flat,
            body: await response.text(),
        };
    };
}
