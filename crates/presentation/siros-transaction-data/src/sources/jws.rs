//! JWS Compact Serialization (RFC 7515) signed with ES256 or ES384 (RFC 7518, Section 3.4),
//! and the EC keys that verify it: an X.509 leaf's key, or a public JWK (RFC 7518, Section
//! 6.2.1).

use p256::ecdsa::signature::Verifier;
use siros_codec::base64url;
use siros_codec::json::{Json, JsonFault};
use siros_codec::Base64Error;
use siros_trust::Certificate;

use crate::json::{self, Fields};

/// Why a text is no JWS this wallet verifies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum JwsFault {
    /// The text is not three dot-separated segments.
    Segments,
    /// A segment is no unpadded base64url.
    Encoding(#[source] Base64Error),
    /// The protected header or the payload is no JSON document the strict reader holds.
    Json(#[source] JsonFault),
    /// The protected header or the payload is no JSON object.
    NotObject,
    /// `alg` is absent, or names no algorithm of ES256 and ES384.
    Algorithm,
    /// The header has `crit`, whose extensions this wallet understands none of (RFC 7515,
    /// Section 4.1.11).
    Critical,
    /// The signature is no `r ‖ s` of the algorithm's curve.
    Signature,
}

impl JwsFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Segments | Self::Encoding(_) | Self::Json(_) | Self::NotObject => "jws_malformed",
            Self::Algorithm => "jws_algorithm",
            Self::Critical => "jws_critical",
            Self::Signature => "jws_signature_malformed",
        }
    }
}

/// A JWS: its protected header, its payload, and the signature over both.
pub(crate) struct Jws {
    pub(crate) header: Fields,
    pub(crate) payload: Fields,
    signing_input: String,
    signature: Signature,
}

/// An ECDSA signature `r ‖ s` of a JWS algorithm.
enum Signature {
    P256(p256::ecdsa::Signature),
    P384(p384::ecdsa::Signature),
}

/// A key that verifies ES256 or ES384 signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl Jws {
    /// The JWS `text` in Compact Serialization: header and payload JSON objects that repeat
    /// no member name, `alg` ES256 or ES384, no `crit`.
    pub(crate) fn parse(text: &str) -> Result<Self, JwsFault> {
        let mut segments = text.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(JwsFault::Segments);
        };
        let mut header_fields = object(header)?;
        let alg = match header_fields.take("alg") {
            Some(Json::String(alg)) => alg,
            _ => return Err(JwsFault::Algorithm),
        };
        if header_fields.take("crit").is_some() {
            return Err(JwsFault::Critical);
        }
        let bytes = base64url::decode(signature).map_err(JwsFault::Encoding)?;
        let signature = match alg.as_str() {
            "ES256" => p256::ecdsa::Signature::from_slice(&bytes).map(Signature::P256),
            "ES384" => p384::ecdsa::Signature::from_slice(&bytes).map(Signature::P384),
            _ => return Err(JwsFault::Algorithm),
        }
        .map_err(|_| JwsFault::Signature)?;
        Ok(Self {
            header: header_fields,
            payload: object(payload)?,
            signing_input: format!("{header}.{payload}"),
            signature,
        })
    }

    /// Whether `key` verifies the signature: a key of the algorithm's curve.
    pub(crate) fn verified_by(&self, key: &VerifyingKey) -> bool {
        let input = self.signing_input.as_bytes();
        match (&self.signature, key) {
            (Signature::P256(signature), VerifyingKey::P256(key)) => {
                key.verify(input, signature).is_ok()
            }
            (Signature::P384(signature), VerifyingKey::P384(key)) => {
                key.verify(input, signature).is_ok()
            }
            (Signature::P256(_) | Signature::P384(_), _) => false,
        }
    }
}

/// The JSON object the base64url segment `segment` encodes.
fn object(segment: &str) -> Result<Fields, JwsFault> {
    let bytes = base64url::decode(segment).map_err(JwsFault::Encoding)?;
    let value = Json::parse_unique(&bytes).map_err(JwsFault::Json)?;
    json::object(value).map_err(|_| JwsFault::NotObject)
}

/// Why a JWK is no EC public key this wallet verifies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum JwkFault {
    /// `kty` is not `EC`, or `crv` neither `P-256` nor `P-384`.
    KeyType,
    /// `x` or `y` is absent, no unpadded base64url, or of the wrong length.
    Coordinate,
    /// The coordinates are no point of the curve.
    Point,
}

impl JwkFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::KeyType => "jwk_key_type",
            Self::Coordinate => "jwk_coordinate",
            Self::Point => "jwk_point",
        }
    }
}

impl VerifyingKey {
    /// The key of `certificate`'s subject, when it is a P-256 or P-384 key.
    pub(crate) fn of_certificate(certificate: &Certificate) -> Option<Self> {
        if let Some(sec1) = certificate.p256_key() {
            return p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
                .ok()
                .map(Self::P256);
        }
        certificate.p384_key().and_then(|sec1| {
            p384::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
                .ok()
                .map(Self::P384)
        })
    }

    /// The key of the public JWK `jwk`: `kty` `EC`, `crv` `P-256` or `P-384`, and `x` and `y`
    /// of the curve's length.
    pub(crate) fn of_jwk(jwk: &Json) -> Result<Self, JwkFault> {
        let text = |name: &str| match jwk.member(name) {
            Some(Json::String(text)) => Some(text.as_str()),
            _ => None,
        };
        let length = match (text("kty"), text("crv")) {
            (Some("EC"), Some("P-256")) => 32,
            (Some("EC"), Some("P-384")) => 48,
            _ => return Err(JwkFault::KeyType),
        };
        let coordinate = |name: &str| {
            text(name)
                .and_then(|text| base64url::decode(text).ok())
                .filter(|bytes| bytes.len() == length)
                .ok_or(JwkFault::Coordinate)
        };
        let point = [vec![0x04], coordinate("x")?, coordinate("y")?].concat();
        if length == 32 {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map(Self::P256)
                .map_err(|_| JwkFault::Point)
        } else {
            p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map(Self::P384)
                .map_err(|_| JwkFault::Point)
        }
    }
}
