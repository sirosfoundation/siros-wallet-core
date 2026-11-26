import type { TrustTokenProvider } from "./trust.js";
import type { MiniWalletPdpOption } from "./types.js";
import type { PresenterOptions } from "./presenter.js";
import type { AdoptReport, AdoptTarget, AdoptUi, PrivateDataCipher } from "./adopt.js";
import type { MiniWalletEvent, MiniWalletFetch, MiniWalletUi, StoredCredential, WalletStorage } from "./types.js";
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
    /** Every event the wallet surfaces: progress, credentials, errors. */
    onEvent?: (event: MiniWalletEvent) => void;
}
export declare class MiniWallet {
    #private;
    constructor(options: MiniWalletOptions);
    /**
     * Probe the trust layer directly — the page's own trust question
     * (the backend's PDP-proxy when configured; the token rides along).
     */
    evaluateTrust(ask: Record<string, unknown>): Promise<{
        trusted: boolean;
        decision?: string;
        context?: unknown;
    }>;
    /**
     * Receive a credential: an offer URI (https), the
     * `openid-credential-offer://` deep link, or the offer object an
     * embedded issuer flow already holds. Resolves when the flow completes
     * (the stored credential records ride the result); rejects when the
     * flow errors or the page's UI refuses a sub-flow.
     */
    receiveCredential(offer: string | Record<string, unknown>): Promise<unknown>;
    /**
     * Present to a verifier: the scanned cross-device request — the
     * `openid4vp://` link or the https request URI. The zkp_req proof
     * path plugs in through the ui.vp callback; the page owns the approval.
     */
    present(request: string): Promise<unknown>;
    /** The stored credentials (the listing the page renders). The values
     *  stay in the storage; only the records' envelopes come back. */
    credentials(): Promise<StoredCredential[]>;
    /** The raw stored record (the credential + its metadata) — the zkp
     *  presenter reads the ssc opening from here. */
    rawCredential(key: string): Promise<Record<string, unknown> | null>;
    /**
     * Migrate to a new storage backend — the unencrypted → passkey-
     * encrypted swap. The default backend swaps to `target` AFTER every
     * key verified against it; the wallet keeps working throughout, and a
     * failure leaves the source intact (the report names the key).
     */
    migrate(target: WalletStorage): Promise<import("./migration.js").MigrationReport>;
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
    adopt(options: {
        /** The backend to adopt; a GoWalletBackendTarget built from the
         *  URL when a string is given (the gdc instance, for the demo).
         *  Omitted when the wallet is backend-configured. */
        target?: AdoptTarget | string;
        /** The page's UI: the ask and the WebAuthn ceremony. */
        ui: AdoptUi;
        /** The blob's cipher — the private-data library's slot. */
        cipher?: PrivateDataCipher;
        /** The adopt as a MODAL on the page (the decision: the page serves
         *  from the wallet's origin and the onboard/set-passkey/move arc
         *  runs as a modal). The library renders the steps (the buttons ARE
         *  the ask's answer); `true` mounts on document.body, an element
         *  mounts there. The page's callbacks still run alongside. */
        modal?: boolean | HTMLElement;
    }): Promise<AdoptReport | null>;
}
export {};
