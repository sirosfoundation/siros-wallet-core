// The offer normalization: whatever the page hands the wallet — the
// https offer URL (what a QR encodes for a cross-device issuance), the
// `openid-credential-offer://` deep link, or the offer object a page's
// own issuer flow holds — one shape feeds `receiveCredential`.
/** True when the string is a URI form the wallet can normalize. */
export function isOfferUri(offer) {
    return offer.startsWith("https://") || offer.startsWith("openid-credential-offer://");
}
/** Unwrap the deep link / URL forms to the offer JSON — WITHOUT fetching:
 *  a deep link may also carry the offer INLINE (`credential_offer=`).
 *  Returns `{ uri }` when a fetch is due, `{ offer }` when it is not. */
export function unwrapOffer(offer) {
    if (offer.startsWith("https://"))
        return { uri: offer, source: "uri" };
    if (offer.startsWith("openid-credential-offer://")) {
        const params = new URLSearchParams(offer.split("?", 2)[1] ?? "");
        const uri = params.get("credential_offer_uri");
        if (uri)
            return { uri, source: "deep-link" };
        const inline = params.get("credential_offer");
        if (inline)
            return { offer: JSON.parse(inline), source: "deep-link" };
        throw new Error("the offer deep link carries neither credential_offer_uri nor credential_offer");
    }
    throw new Error("not an offer: expected an https URL or an openid-credential-offer:// link");
}
/** Validate the fetched/inline offer into the flow's start params. */
export function normalizeOffer(offer, source) {
    const issuer = offer["credential_issuer"];
    const ids = offer["credential_configuration_ids"] ?? offer["credentials"];
    const grants = offer["grants"];
    if (typeof issuer !== "string" || !Array.isArray(ids) || !ids.every((id) => typeof id === "string")) {
        throw new Error("the offer names no credential_issuer / credential_configuration_ids");
    }
    if (!grants || typeof grants !== "object")
        throw new Error("the offer carries no grants");
    return {
        credential_issuer: issuer,
        credential_configuration_ids: ids,
        grants: grants,
        source,
    };
}
/** The same normalization for a verifier's authorization request (the
 *  presentation side): the `openid4vp://` link (or the https request
 *  URI) to the members the oid4vp flow start takes (the engine-vectors'
 *  vp.* params: client_id, nonce, response_uri, response_mode, state,
 *  dcql_query — a request_uri member rides through for the engine to
 *  fetch and validate). */
export function unwrapAuthorizationRequest(request) {
    if (request.startsWith("openid4vp://") || request.startsWith("haip://") || request.startsWith("mdoc-openid4vp://")) {
        const params = {};
        for (const [key, value] of new URLSearchParams(request.split("?", 2)[1] ?? ""))
            params[key] = value;
        return { params, source: "deep-link" };
    }
    if (request.startsWith("https://")) {
        return { params: { request_uri: request }, source: "uri" };
    }
    throw new Error("not an authorization request: expected an openid4vp:// link or an https request URI");
}
