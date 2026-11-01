//! The key set of an SD-JWT VC issuer, resolved through its JWT VC Issuer Metadata (SD-JWT VC,
//! Section 4.3; draft-ietf-oauth-sd-jwt-vc, `/.well-known/jwt-vc-issuer`), each document one the
//! host holds.

use siros_codec::json::{Json, JsonFault};
use siros_oid4vp::HttpsUrl;
use siros_wallet_state::IssuerIdentifier;

use super::held::{HeldMetadata, Holding};
use super::jws::{JwkFault, VerifyingKey};
use crate::json;

/// The path segment the issuer metadata's well-known URL inserts after the authority.
const WELL_KNOWN: &str = "/.well-known/jwt-vc-issuer";

/// Why the issuer's key set gives no key that verifies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum KeySetFault {
    /// The Credential Issuer Identifier is no `https` URL.
    IssuerNotHttps,
    /// The host neither holds the document of this URL nor records it as absent.
    NotHeld(HttpsUrl),
    /// The host records the document of this URL as absent.
    Absent(HttpsUrl),
    /// A document is no JSON document the strict reader holds.
    Json(#[source] JsonFault),
    /// The issuer metadata names another `issuer`, or names its keys by both `jwks` and
    /// `jwks_uri` or by neither, or one of them is malformed.
    Metadata,
    /// The key set has no `keys` array.
    Keys,
    /// No key of the set has the `kid`.
    KidUnknown,
    /// The key of the `kid` is no EC key this wallet verifies with.
    Key(#[source] JwkFault),
}

impl KeySetFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::IssuerNotHttps => "key_set_issuer_not_https",
            Self::NotHeld(_) => "key_set_not_held",
            Self::Absent(_) => "key_set_absent",
            Self::Json(_) | Self::Metadata | Self::Keys => "key_set_malformed",
            Self::KidUnknown => "key_set_kid_unknown",
            Self::Key(fault) => fault.code(),
        }
    }
}

/// The key of the key set of `issuer` that `kid` identifies.
pub(crate) fn key(
    issuer: &IssuerIdentifier,
    kid: &str,
    held: &HeldMetadata,
) -> Result<VerifyingKey, KeySetFault> {
    let jwks = key_set(issuer, held)?;
    let Some(Json::Array(keys)) = jwks.member("keys") else {
        return Err(KeySetFault::Keys);
    };
    let jwk = keys
        .iter()
        .find(|key| matches!(key.member("kid"), Some(Json::String(id)) if id == kid))
        .ok_or(KeySetFault::KidUnknown)?;
    VerifyingKey::of_jwk(jwk).map_err(KeySetFault::Key)
}

/// The URLs of the documents of `issuer`'s key set: its issuer metadata, and, once the host
/// holds that, the `jwks_uri` it names.
///
/// # Errors
///
/// [`KeySetFault`] for an issuer whose metadata URL is unknown, or held metadata that does not
/// read.
pub(crate) fn documents(
    issuer: &IssuerIdentifier,
    held: &HeldMetadata,
) -> Result<Vec<HttpsUrl>, KeySetFault> {
    let metadata_url = well_known(issuer).ok_or(KeySetFault::IssuerNotHttps)?;
    let mut urls = vec![metadata_url.clone()];
    if matches!(held.document(&metadata_url), Holding::Body(_)) {
        if let KeySetSource::Uri(url) = source(issuer, &metadata_url, held)? {
            urls.push(url);
        }
    }
    Ok(urls)
}

/// Where an issuer's metadata puts its key set.
enum KeySetSource {
    /// Inline, as `jwks`.
    Inline(Json),
    /// At this `jwks_uri`.
    Uri(HttpsUrl),
}

/// The key set of `issuer`: its issuer metadata's `jwks`, or the document its `jwks_uri` names.
fn key_set(issuer: &IssuerIdentifier, held: &HeldMetadata) -> Result<Json, KeySetFault> {
    let metadata_url = well_known(issuer).ok_or(KeySetFault::IssuerNotHttps)?;
    match source(issuer, &metadata_url, held)? {
        KeySetSource::Inline(jwks) => Ok(jwks),
        KeySetSource::Uri(url) => document(&url, held),
    }
}

/// Where the issuer metadata of `issuer`, held for `metadata_url`, puts the key set.
fn source(
    issuer: &IssuerIdentifier,
    metadata_url: &HttpsUrl,
    held: &HeldMetadata,
) -> Result<KeySetSource, KeySetFault> {
    let mut fields =
        json::object(document(metadata_url, held)?).map_err(|_| KeySetFault::Metadata)?;
    match fields.take("issuer") {
        Some(Json::String(named)) if named == issuer.as_str() => {}
        _ => return Err(KeySetFault::Metadata),
    }
    match (fields.take("jwks"), fields.take("jwks_uri")) {
        (Some(jwks), None) => Ok(KeySetSource::Inline(jwks)),
        (None, Some(Json::String(uri))) => HttpsUrl::parse(&uri)
            .map(KeySetSource::Uri)
            .ok_or(KeySetFault::Metadata),
        _ => Err(KeySetFault::Metadata),
    }
}

/// The URL of the JWT VC Issuer Metadata of `issuer`: the well-known segment between its
/// authority and its path.
fn well_known(issuer: &IssuerIdentifier) -> Option<HttpsUrl> {
    let url = HttpsUrl::parse(issuer.as_str())?;
    let rest = url.as_str().get("https://".len()..)?;
    let (authority, path) = match rest.find('/') {
        Some(at) => rest.split_at_checked(at)?,
        None => (rest, ""),
    };
    HttpsUrl::parse(&format!(
        "https://{authority}{WELL_KNOWN}{}",
        path.trim_end_matches('/')
    ))
}

/// The JSON document held for `url`.
fn document(url: &HttpsUrl, held: &HeldMetadata) -> Result<Json, KeySetFault> {
    match held.document(url) {
        Holding::Body(body) => Json::parse_unique(body).map_err(KeySetFault::Json),
        Holding::Absent => Err(KeySetFault::Absent(url.clone())),
        Holding::NotHeld => Err(KeySetFault::NotHeld(url.clone())),
    }
}
