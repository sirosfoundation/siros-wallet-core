//! Offer parsing: by value, by `credential_offer_uri`, and by the
//! `openid-credential-offer:` URI scheme — the S1 resolver's first step.
//!
//! The offer is decoded with plain `serde_json` (the P0.6 correction: the
//! Go engine uses plain `json.Unmarshal` for the offer on every ref; the
//! strict decoder applies to other documents). Whether the Rust core makes
//! the offer strict is a decision the vectors record, not a Go behaviour
//! to copy.

use engine_ports::{FetchPurpose, HttpClient, HttpError, HttpRequest, RedirectPolicy};

use super::types::{CredentialOffer, OfferError};

/// The maximum size of an offer fetched by reference: 1 MiB (the AS-metadata
/// limit; the issuer-metadata limit is 10 MB).
const MAX_OFFER_BYTES: usize = 1 << 20;

/// Parses a credential offer from its JSON value (the flow start's params).
///
/// The offer arrives in the `wmp.flow.start` params, either directly (by
/// value) or as a URI string (by reference or by scheme). The three forms:
///
/// - **By value**: `params` is the offer object itself.
/// - **By reference**: `params.credential_offer_uri` names a URL to fetch.
/// - **By URI scheme**: the params (or a QR code's payload) carry a
///   `openid-credential-offer:?credential_offer_uri=...` URI.
pub async fn parse_offer(
    http: &dyn HttpClient,
    params: &serde_json::Value,
) -> Result<CredentialOffer, OfferError> {
    // By URI scheme: the params are a string (or the `offer` member is).
    if let Some(uri) = params.as_str() {
        return parse_offer_uri(http, uri).await;
    }
    if let Some(offer_str) = params.get("credential_offer").and_then(|v| v.as_str()) {
        return parse_offer_uri(http, offer_str).await;
    }

    // By reference: `credential_offer_uri` names a URL.
    if let Some(uri) = params.get("credential_offer_uri").and_then(|v| v.as_str()) {
        if !uri.is_empty() {
            return fetch_offer(http, uri).await;
        }
    }

    // By value: the params ARE the offer object.
    parse_offer_value(params)
}

/// Parses an offer from a `openid-credential-offer:` URI — either the
/// `//`-prefixed form (`openid-credential-offer://?credential_offer_uri=...`)
/// or the bare form (`openid-credential-offer:?credential_offer_uri=...`).
///
/// The past bug (PR 345) was requiring the `//` prefix, so the bare form
/// fell through to `json.Unmarshal` and failed. The current Go code accepts
/// both; the Rust core does too.
async fn parse_offer_uri(http: &dyn HttpClient, uri: &str) -> Result<CredentialOffer, OfferError> {
    // Strip the scheme (both forms).
    let rest = uri
        .strip_prefix("openid-credential-offer:")
        .ok_or_else(|| OfferError::MalformedUri(uri.to_owned()))?;

    // Strip the `//` if present (the bare form has none).
    let rest = rest.strip_prefix("//").unwrap_or(rest);

    // The query string carries the offer: `credential_offer=` (the 1.0
    // by-value form, the OIDF suite's) or `credential_offer_uri=` (the
    // by-reference form).
    if let Some(query) = rest.strip_prefix('?') {
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if key == "credential_offer" {
                let decoded = urldecode(value);
                let value: serde_json::Value =
                    serde_json::from_str(&decoded).map_err(|_| OfferError::NotAnObject)?;
                return parse_offer_value(&value);
            }
            if key == "credential_offer_uri" {
                let decoded = urldecode(value);
                return fetch_offer(http, &decoded).await;
            }
        }
    }

    // The URI may carry the offer inline (the pre-1.0 form): the whole
    // rest is the URL-encoded offer JSON.
    let decoded = urldecode(rest);
    let value: serde_json::Value =
        serde_json::from_str(&decoded).map_err(|_| OfferError::NotAnObject)?;
    parse_offer_value(&value)
}

/// Fetches an offer by reference through the HTTP port, with the size
/// limit and the declared purpose.
async fn fetch_offer(http: &dyn HttpClient, uri: &str) -> Result<CredentialOffer, OfferError> {
    let response = http
        .send(HttpRequest {
            method: "GET".to_owned(),
            url: uri.to_owned(),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body: Vec::new(),
            purpose: FetchPurpose::Offer,
            max_response_bytes: MAX_OFFER_BYTES,
            redirects: RedirectPolicy::Max(5),
            allow_plaintext: false,
            timeout_ms: 10_000,
        })
        .await
        .map_err(|err| match err {
            HttpError::Refused => OfferError::Fetch("refused by the adapter's policy".to_owned()),
            HttpError::Transport(detail) => OfferError::Fetch(detail),
        })?;

    if response.status != 200 {
        return Err(OfferError::Fetch(format!(
            "offer endpoint answered {}",
            response.status
        )));
    }

    let value: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| OfferError::NotAnObject)?;
    parse_offer_value(&value)
}

/// Parses an offer from its JSON value — the shared validation for all
/// three forms. Requires `credential_issuer` and
/// `credential_configuration_ids`.
fn parse_offer_value(value: &serde_json::Value) -> Result<CredentialOffer, OfferError> {
    let Some(obj) = value.as_object() else {
        return Err(OfferError::NotAnObject);
    };

    let credential_issuer = obj
        .get("credential_issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    if credential_issuer.is_empty() {
        return Err(OfferError::NoIssuer);
    }

    let credential_configuration_ids: Vec<String> = obj
        .get("credential_configuration_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if credential_configuration_ids.is_empty() {
        return Err(OfferError::NoConfigurationIds);
    }

    let grants = obj
        .get("grants")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    Ok(CredentialOffer {
        credential_issuer,
        credential_configuration_ids,
        grants,
    })
}

/// Minimal percent-decoding for the URI scheme's query parameters.
fn urldecode(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut chars = bytes.iter().enumerate();
    while let Some((_, &b)) = chars.next() {
        if b == b'%' {
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            let hi = chars.next().and_then(|(_, &b)| hex(b));
            let lo = chars.next().and_then(|(_, &b)| hex(b));
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi * 16 + lo);
                continue;
            }
            // Malformed escape: emit the '%' and continue from where the
            // iterator left off (the hex digits were consumed).
            out.push(b);
            continue;
        }
        // `+` is a space in form-encoded query strings.
        if b == b'+' {
            out.push(b' ');
            continue;
        }
        out.push(b);
    }
    String::from_utf8_lossy(&out).into_owned()
}
