import type { MiniWalletEvent, MiniWalletFetch, MiniWalletPdp, MiniWalletUi, StoredCredential, WalletStorage } from "./types.js";
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
    /** Every event the wallet surfaces: progress, credentials, errors. */
    onEvent?: (event: MiniWalletEvent) => void;
}
export declare class MiniWallet {
    #private;
    constructor(options: MiniWalletOptions);
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
}
