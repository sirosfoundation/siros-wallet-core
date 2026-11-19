export interface NormalizedOffer {
    /** The issuer's identifier (its base URL). */
    credential_issuer: string;
    /** The configurations the offer names. */
    credential_configuration_ids: string[];
    /** The offer's grants, verbatim (`pre-authorized_code` and/or
     *  `authorization_code`). */
    grants: Record<string, unknown>;
    /** Where the offer came from — the page's UI may say so. */
    source: OfferSource;
}
/** True when the string is a URI form the wallet can normalize. */
export declare function isOfferUri(offer: string): boolean;
/** The source an offer came from — the page's UI may say so. */
export type OfferSource = "uri" | "deep-link" | "inline";
/** Unwrap the deep link / URL forms to the offer JSON — WITHOUT fetching:
 *  a deep link may also carry the offer INLINE (`credential_offer=`).
 *  Returns `{ uri }` when a fetch is due, `{ offer }` when it is not. */
export declare function unwrapOffer(offer: string): {
    uri: string;
    source: OfferSource;
} | {
    offer: Record<string, unknown>;
    source: OfferSource;
};
/** Validate the fetched/inline offer into the flow's start params. */
export declare function normalizeOffer(offer: Record<string, unknown>, source: OfferSource): NormalizedOffer;
/** The same normalization for a verifier's authorization request (the
 *  presentation side): the `openid4vp://` link (or the https request
 *  URI) to the members the oid4vp flow start takes (the engine-vectors'
 *  vp.* params: client_id, nonce, response_uri, response_mode, state,
 *  dcql_query — a request_uri member rides through for the engine to
 *  fetch and validate). */
export declare function unwrapAuthorizationRequest(request: string): {
    params: Record<string, unknown>;
    source: "uri" | "deep-link";
};
