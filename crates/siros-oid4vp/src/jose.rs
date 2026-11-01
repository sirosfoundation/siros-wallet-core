//! JWS (RFC 7515) with ES256 (RFC 7518, Section 3.4), and P-256 public JWKs (RFC 7518,
//! Section 6.2.1).

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;
use serde_json::{Map, Value};
use siros_codec::base64url;

use crate::intake::{Coordinate, IntakeError, JwkFault, JwsError, JwsFault};
use crate::jws_rules;
use crate::values::Kid;

/// One signature over a payload: its JOSE Header and what it signs.
///
/// The header is the protected header alone: only integrity-protected parameters are read.
#[derive(Debug, Clone)]
pub(crate) struct Signed {
    header: Map<String, Value>,
    signing_input: String,
    signature: Signature,
}

/// A JWS Compact Serialization: the signature and the decoded payload.
pub(crate) fn compact(jws: &str) -> Result<(Signed, Vec<u8>), JwsError> {
    let mut segments = jws.splitn(4, '.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JwsError::Malformed(JwsFault::Segments));
    };
    let signed = Signed::parse(header, payload, signature)?;
    Ok((signed, segment(payload)?))
}

impl Signed {
    /// The signature `signature_b64` by the protected header `protected_b64` over the payload
    /// `payload_b64`, each as written in the serialization.
    pub(crate) fn parse(
        protected_b64: &str,
        payload_b64: &str,
        signature_b64: &str,
    ) -> Result<Self, JwsError> {
        let header = jws_rules::header(&segment(protected_b64)?)?;
        let signature = segment(signature_b64)?;
        jws_rules::signature_length(&signature)?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| JwsError::Malformed(JwsFault::Signature))?;
        jws_rules::es256(&header)?;
        Ok(Self {
            header,
            signing_input: format!("{protected_b64}.{payload_b64}"),
            signature,
        })
    }

    /// The protected header.
    pub(crate) fn header(&self) -> &Map<String, Value> {
        &self.header
    }

    /// A string Header Parameter.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(Value::as_str)
    }

    /// The `kid` Header Parameter.
    pub(crate) fn kid(&self) -> Option<Kid> {
        self.text("kid").map(Kid::new)
    }

    /// Verifies the ES256 signature under `key`.
    pub(crate) fn verify(&self, key: &PublicKey) -> Result<(), IntakeError> {
        VerifyingKey::from(key)
            .verify(self.signing_input.as_bytes(), &self.signature)
            .map_err(|_| IntakeError::SignatureInvalid)
    }
}

/// The bytes of the base64url segment `text` of a JWS.
pub(crate) fn segment(text: &str) -> Result<Vec<u8>, JwsError> {
    base64url::decode(text).map_err(|e| JwsError::Malformed(JwsFault::Encoding(e)))
}

/// The key of a public JWK with `kty` `EC` and `crv` `P-256`, its coordinates 32 bytes each.
pub(crate) fn p256_key(jwk: &Value) -> Result<PublicKey, JwkFault> {
    let text = |name: &str| jwk.get(name).and_then(Value::as_str);
    if text("kty") != Some("EC") || text("crv") != Some("P-256") {
        return Err(JwkFault::OtherKey);
    }
    let coordinate = |coordinate: Coordinate| {
        let text = text(coordinate.as_str()).ok_or(JwkFault::CoordinateAbsent(coordinate))?;
        let bytes = base64url::decode(text)
            .map_err(|error| JwkFault::CoordinateEncoding(coordinate, error))?;
        match bytes.len() {
            32 => Ok(bytes),
            length => Err(JwkFault::CoordinateLength(coordinate, length)),
        }
    };
    let point = [
        vec![0x04],
        coordinate(Coordinate::X)?,
        coordinate(Coordinate::Y)?,
    ]
    .concat();
    PublicKey::from_sec1_bytes(&point).map_err(|_| JwkFault::Point)
}
