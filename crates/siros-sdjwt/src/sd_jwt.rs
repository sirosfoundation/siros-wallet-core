//! A stored SD-JWT: its compact form parsed and its disclosures processed (RFC 9901, Sections 4
//! and 7.1).

use rustc_hash::FxHashMap;
use siros_codec::base64;
use siros_codec::base64url::{self, Base64Url};
use siros_codec::chain::CertificateChain;
use siros_codec::json::Json;

use crate::alg::HashAlg;
use crate::error::{
    DisclosureFault, EncodedJsonFault, IssuerJwtFault, ParseError, SdAlgFault, X5cError, X5cIndex,
};
use crate::process::{self, Content, Pending};
use crate::tree::{DisclosureId, Object};

/// A stored SD-JWT whose disclosures all hang in its issuer-signed payload.
///
/// Parsing enforces Section 7.1, steps 1, 2.d, 3, 4 and 5: the digests are unique, every
/// disclosure is referenced, no reserved claim name is used, and `_sd_alg` names a supported
/// algorithm.
pub struct SdJwt {
    issuer_jwt: IssuerJwt,
    x5c: Option<CertificateChain>,
    alg: HashAlg,
    claims: Object,
}

/// The issuer-signed JWT as stored: three base64url segments, its header and payload JSON
/// objects.
pub(crate) struct IssuerJwt(String);

impl IssuerJwt {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The `x5c` header parameter of the issuer-signed JWT (RFC 7515, Section 4.1.6): a non-empty
/// array of base64 strings with padding, each one DER certificate, the signer's first.
fn certificate_chain(value: &Json) -> Result<CertificateChain, X5cError> {
    let Json::Array(certificates) = value else {
        return Err(X5cError::NotArray);
    };
    let mut ders = certificates.iter().enumerate().map(|(index, certificate)| {
        let index = X5cIndex::new(index);
        match certificate {
            Json::String(text) => base64::decode(text).map_err(|e| X5cError::Base64(index, e)),
            _ => Err(X5cError::NotString(index)),
        }
    });
    let signer = ders.next().ok_or(X5cError::Empty)??;
    Ok(CertificateChain::new(
        signer,
        ders.collect::<Result<_, _>>()?,
    ))
}

impl SdJwt {
    /// The SD-JWT of the compact form `compact`: the issuer JWT, then its disclosures, each after
    /// a `~`, with an optional final `~` (Section 4).
    ///
    /// # Errors
    ///
    /// [`ParseError`]: the first rule the text breaks.
    pub fn parse(compact: &str) -> Result<Self, ParseError> {
        let (issuer_jwt, disclosures) = split(compact);
        let (header, payload) =
            issuer_header_and_payload(issuer_jwt).map_err(ParseError::IssuerJwt)?;
        let x5c = header
            .iter()
            .find(|(name, _)| name == "x5c")
            .map(|(_, value)| certificate_chain(value))
            .transpose()
            .map_err(ParseError::X5c)?;
        let alg = sd_alg(&payload).map_err(ParseError::UnsupportedSdAlg)?;
        let mut pending = FxHashMap::default();
        for (position, text) in disclosures.into_iter().enumerate() {
            let id = DisclosureId::new(position);
            let (encoded, content) = disclosure(text).map_err(|fault| ParseError::Disclosure {
                disclosure: id,
                fault,
            })?;
            let digest = alg.digest(text.as_bytes());
            if pending
                .insert(digest.clone(), Pending::new(id, encoded, content))
                .is_some()
            {
                return Err(ParseError::RepeatedDigest(digest));
            }
        }
        let claims = process::claims(payload, pending)?;
        Ok(Self {
            issuer_jwt: IssuerJwt(issuer_jwt.to_owned()),
            x5c,
            alg,
            claims,
        })
    }

    /// The processed payload: every claim the credential holds, `_sd_alg` removed.
    #[must_use]
    pub fn claims(&self) -> &Object {
        &self.claims
    }

    /// The certificates of the issuer-signed JWT's `x5c` header parameter, the signer's first;
    /// `None` when the issuer sent none.
    #[must_use]
    pub fn x5c(&self) -> Option<&CertificateChain> {
        self.x5c.as_ref()
    }

    pub(crate) fn issuer_jwt(&self) -> &IssuerJwt {
        &self.issuer_jwt
    }

    pub(crate) fn alg(&self) -> HashAlg {
        self.alg
    }
}

/// The issuer JWT and the disclosures of `compact`.
fn split(compact: &str) -> (&str, Vec<&str>) {
    let (issuer_jwt, rest) = compact.split_once('~').unwrap_or((compact, ""));
    // The forms `JWT` and `JWT~` leave `rest` empty.
    if rest.is_empty() {
        return (issuer_jwt, Vec::new());
    }
    let listed = rest.strip_suffix('~').unwrap_or(rest);
    (issuer_jwt, listed.split('~').collect())
}

/// The members of a JSON object, in document order.
type Members = Vec<(String, Json)>;

/// The protected header and the payload of the issuer JWT, a compact JWS (RFC 7515, Section
/// 7.1).
fn issuer_header_and_payload(issuer_jwt: &str) -> Result<(Members, Members), IssuerJwtFault> {
    let segments: Vec<&str> = issuer_jwt.split('.').collect();
    let [header, payload, signature] = segments.as_slice() else {
        return Err(IssuerJwtFault::Segments(segments.len()));
    };
    if signature.is_empty() {
        return Err(IssuerJwtFault::SignatureEmpty);
    }
    Base64Url::parse(signature)
        .map(drop)
        .map_err(IssuerJwtFault::Signature)?;
    let header = match decoded(header).map_err(IssuerJwtFault::Header)? {
        Json::Object(members) => members,
        _ => return Err(IssuerJwtFault::HeaderNotObject),
    };
    let payload = match decoded(payload).map_err(IssuerJwtFault::Payload)? {
        Json::Object(members) => members,
        _ => return Err(IssuerJwtFault::PayloadNotObject),
    };
    Ok((header, payload))
}

/// The JSON value the base64url `text` encodes.
fn decoded(text: &str) -> Result<Json, EncodedJsonFault> {
    let bytes = base64url::decode(text).map_err(EncodedJsonFault::Base64)?;
    Json::parse_unique(&bytes).map_err(EncodedJsonFault::Json)
}

/// The algorithm `_sd_alg` names, `sha-256` when it is absent (Section 4.1.1).
fn sd_alg(payload: &[(String, Json)]) -> Result<HashAlg, SdAlgFault> {
    match payload.iter().find(|(name, _)| name == "_sd_alg") {
        None => Ok(HashAlg::Sha256),
        Some((_, Json::String(name))) => {
            HashAlg::from_name(name).ok_or_else(|| SdAlgFault::Unknown(name.clone()))
        }
        Some(_) => Err(SdAlgFault::NotString),
    }
}

/// The disclosure `text` and what it reveals (Sections 4.2.1 and 4.2.2).
fn disclosure(text: &str) -> Result<(Base64Url, Content), DisclosureFault> {
    let encoded = Base64Url::parse(text)
        .map_err(|e| DisclosureFault::Encoding(EncodedJsonFault::Base64(e)))?;
    let Json::Array(items) = Json::parse_unique(encoded.bytes())
        .map_err(|e| DisclosureFault::Encoding(EncodedJsonFault::Json(e)))?
    else {
        return Err(DisclosureFault::NotArray);
    };
    let length = items.len();
    let mut items = items.into_iter();
    let content = match (items.next(), items.next(), items.next(), items.next()) {
        (Some(Json::String(_)), Some(value), None, None) => Content::Element(value),
        (Some(Json::String(_)), Some(Json::String(name)), Some(value), None) => {
            Content::Property { name, value }
        }
        (Some(Json::String(_)), Some(_), Some(_), None) => return Err(DisclosureFault::Name),
        (Some(_), Some(_), _, None) => return Err(DisclosureFault::Salt),
        _ => return Err(DisclosureFault::Length(length)),
    };
    Ok((encoded, content))
}
