//! An issued SD-JWT: its compact form parsed and its disclosures processed (RFC 9901 §4, §7.1).

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rustc_hash::FxHashMap;
use siros_openid4vp::json::{JsonError, Node};

use crate::alg::{HashAlg, SigningAlg};
use crate::error::{
    DisclosureFault, EncodedJsonFault, IssuerJwtFault, ParseError, SdAlgFault, X5cError,
};
use crate::process::{self, Content, Pending};
use crate::tree::{DisclosureId, Object};

/// An issued SD-JWT whose disclosures all hang in its Issuer-signed payload: its digests are
/// unique, every disclosure is referenced, no reserved claim name is used, and `_sd_alg` names a
/// supported algorithm (RFC 9901 §7.1, steps 1, 2.d, 3, 4, 5). The signature and the validity
/// claims (steps 2.a to 2.c, 6) are the registering wallet's to check (section 4.3 of the
/// design).
pub struct SdJwt {
    issuer_jwt: String,
    signing_alg: SigningAlg,
    typ: Option<String>,
    x5c: Option<Vec<Vec<u8>>>,
    alg: HashAlg,
    claims: Object,
}

impl SdJwt {
    /// The SD-JWT of the compact form `compact`: the Issuer-signed JWT and each of its disclosures,
    /// each followed by a `~` (§4).
    ///
    /// # Errors
    ///
    /// [`ParseError`]: the first rule the text breaks.
    pub fn parse(compact: &str) -> Result<Self, ParseError> {
        let (issuer_jwt, disclosures) = split(compact)?;
        let (header, payload) =
            issuer_header_and_payload(issuer_jwt).map_err(ParseError::IssuerJwt)?;
        let signing_alg = header
            .get("alg")
            .and_then(Node::as_str)
            .and_then(SigningAlg::parse)
            .ok_or(ParseError::IssuerJwt(IssuerJwtFault::Alg))?;
        let typ = header.get("typ").and_then(Node::as_str).map(str::to_owned);
        let x5c = header
            .get("x5c")
            .map(certificate_chain)
            .transpose()
            .map_err(ParseError::X5c)?;
        let alg = sd_alg(&payload).map_err(ParseError::UnsupportedSdAlg)?;
        let mut pending = FxHashMap::default();
        for (position, text) in disclosures.into_iter().enumerate() {
            let id = DisclosureId::new(position);
            let content = disclosure(text).map_err(|fault| ParseError::Disclosure {
                disclosure: id,
                fault,
            })?;
            let digest = alg.digest(text.as_bytes());
            let entry = Pending {
                id,
                encoded: text.to_owned(),
                content,
            };
            if pending.insert(digest.clone(), entry).is_some() {
                return Err(ParseError::RepeatedDigest(digest));
            }
        }
        let claims = process::claims(&payload, pending)?;
        Ok(Self {
            issuer_jwt: issuer_jwt.to_owned(),
            signing_alg,
            typ,
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

    /// The hash algorithm of `_sd_alg`.
    pub(crate) fn hash_alg(&self) -> HashAlg {
        self.alg
    }

    /// The processed payload as JSON, each withheld array position an `{"...": digest}` element:
    /// what a claims path pointer walks with [`crate::SdJwtVc`]'s `withheld`.
    ///
    /// # Errors
    ///
    /// [`JsonError`]: never for a parsed credential, whose object members are unique.
    pub fn values(&self) -> Result<Node<'static>, JsonError> {
        self.claims.node()
    }

    /// The Issuer-signed JWT, a JWS in compact serialization.
    #[must_use]
    pub fn issuer_jwt(&self) -> &str {
        &self.issuer_jwt
    }

    /// The certificates of the Issuer-signed JWT's `x5c` header parameter in DER, the signer's
    /// first; `None` when the issuer sent none.
    #[must_use]
    pub fn x5c(&self) -> Option<&[Vec<u8>]> {
        self.x5c.as_deref()
    }

    /// The JWS algorithm of the Issuer-signed JWT.
    #[must_use]
    pub fn signing_alg(&self) -> &str {
        self.signing_alg.as_str()
    }

    /// The Issuer-signed JWT's `typ` header parameter (RFC 7515 §4.1.9); `None` when it holds no
    /// string.
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }
}

/// The Issuer-signed JWT and the disclosures of `compact`.
fn split(compact: &str) -> Result<(&str, Vec<&str>), ParseError> {
    let listed = compact.strip_suffix('~').ok_or(ParseError::NoFinalTilde)?;
    let mut parts = listed.split('~');
    let issuer_jwt = parts.next().unwrap_or(listed);
    Ok((issuer_jwt, parts.collect()))
}

/// The `x5c` header parameter (RFC 7515 §4.1.6): a non-empty array of base64 strings with padding,
/// each one DER certificate, the signer's first.
fn certificate_chain(value: &Node<'_>) -> Result<Vec<Vec<u8>>, X5cError> {
    let certificates = value
        .as_array()
        .filter(|certificates| !certificates.is_empty())
        .ok_or(X5cError::NotArray)?;
    certificates
        .iter()
        .enumerate()
        .map(|(position, certificate)| {
            certificate
                .as_str()
                .and_then(|text| STANDARD.decode(text).ok())
                .ok_or(X5cError::Certificate(position))
        })
        .collect()
}

/// The protected header and the payload of the Issuer-signed JWT, a compact JWS (RFC 7515 §7.1).
fn issuer_header_and_payload(
    issuer_jwt: &str,
) -> Result<(Node<'static>, Node<'static>), IssuerJwtFault> {
    let segments: Vec<&str> = issuer_jwt.split('.').collect();
    let [header, payload, signature] = segments.as_slice() else {
        return Err(IssuerJwtFault::Segments(segments.len()));
    };
    if signature.is_empty() {
        return Err(IssuerJwtFault::SignatureEmpty);
    }
    drop(
        URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(IssuerJwtFault::Signature)?,
    );
    let header = decoded(header).map_err(IssuerJwtFault::Header)?;
    if header.as_object().is_none() {
        return Err(IssuerJwtFault::HeaderNotObject);
    }
    let payload = decoded(payload).map_err(IssuerJwtFault::Payload)?;
    if payload.as_object().is_none() {
        return Err(IssuerJwtFault::PayloadNotObject);
    }
    Ok((header, payload))
}

/// The JSON value the base64url `text` encodes.
fn decoded(text: &str) -> Result<Node<'static>, EncodedJsonFault> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(EncodedJsonFault::Base64)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| EncodedJsonFault::Utf8)?;
    Node::parse(text)
        .map(Node::into_owned)
        .map_err(EncodedJsonFault::Json)
}

/// The algorithm `_sd_alg` names, `sha-256` when it is absent (§4.1.1).
fn sd_alg(payload: &Node<'_>) -> Result<HashAlg, SdAlgFault> {
    match payload.get("_sd_alg") {
        None => Ok(HashAlg::Sha256),
        Some(Node::String(name)) => {
            HashAlg::from_name(name).ok_or_else(|| SdAlgFault::Unknown(name.to_string()))
        }
        Some(_) => Err(SdAlgFault::NotString),
    }
}

/// What the disclosure `text` reveals (§4.2.1, §4.2.2).
fn disclosure(text: &str) -> Result<Content, DisclosureFault> {
    let decoded = decoded(text).map_err(DisclosureFault::Encoding)?;
    let Node::Array(items) = decoded else {
        return Err(DisclosureFault::NotArray);
    };
    match items.as_slice() {
        [Node::String(_), value] => Ok(Content::Element(value.clone())),
        [Node::String(_), Node::String(name), value] => Ok(Content::Property {
            name: name.to_string(),
            value: value.clone(),
        }),
        [Node::String(_), _, _] => Err(DisclosureFault::Name),
        [_, _] | [_, _, _] => Err(DisclosureFault::Salt),
        other => Err(DisclosureFault::Length(other.len())),
    }
}
