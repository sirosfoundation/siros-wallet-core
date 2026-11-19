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
/** The trust callback: the engine's PDP. The page supplies the policy
 *  (its own go-trust endpoint, or an allowlist — the wallet never decides
 *  trust itself). */
export interface MiniWalletPdp {
    evaluate(request: unknown): Promise<{
        trusted: boolean;
        decision?: unknown;
    }>;
}
/** The page's fetch — the engine's HTTP. Carrying it lets the page pin
 *  proxies, CORS shims and request logging; the browser default when
 *  absent. */
export type MiniWalletFetch = (request: unknown) => Promise<{
    status: number;
    headers: string[];
    body: string;
}>;
/** The events the wallet surfaces to the page. The library renders
 *  nothing; the page's UI listens here. */
export type MiniWalletEvent = {
    type: "session";
    sessionId: string;
} | {
    type: "progress";
    flowId: string;
    step: string;
    payload?: unknown;
} | {
    type: "credential-received";
    flowId: string;
    configurationId?: string;
} | {
    type: "presented";
    flowId: string;
} | {
    type: "flow-error";
    flowId: string;
    code?: number;
    message: string;
};
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
