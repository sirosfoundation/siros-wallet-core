//! The mdoc `Handover` and `SessionTranscript` of OpenID4VP 1.0, B.2.6, and the JWK SHA-256
//! Thumbprint (RFC 7638) they bind.

use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_codec::cbor::{self, CborError, Value as Cbor};

/// The CBOR `Handover` of the channel a request arrived on (OpenID4VP 1.0, B.2.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handover {
    encoded: Vec<u8>,
}

/// Why bytes are not a `Handover` of OpenID4VP 1.0, B.2.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not an OpenID4VP Handover")]
pub enum HandoverInvalid {
    /// The bytes are not one CBOR item.
    Cbor(#[source] CborError),
    /// The item is not one of the two arrays of B.2.6 with a 32-byte digest.
    Shape,
}

impl HandoverInvalid {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        "handover_invalid"
    }
}

impl Handover {
    /// `OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce,
    /// jwkThumbprint]))]` (OpenID4VP 1.0, B.2.6.2). `jwk_thumbprint` is that of the response
    /// encryption key for `dc_api.jwt`, and `None` (CBOR `null`) for `dc_api`.
    #[must_use]
    pub fn dc_api(origin: &str, nonce: &str, jwk_thumbprint: Option<&JwkThumbprint>) -> Self {
        let info = Cbor::Array(vec![
            Cbor::text(origin),
            Cbor::text(nonce),
            thumbprint(jwk_thumbprint),
        ]);
        Self::of("OpenID4VPDCAPIHandover", &info)
    }

    /// `OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce,
    /// jwkThumbprint, response_uri]))]` (OpenID4VP 1.0, B.2.6.1). `jwk_thumbprint` is that of
    /// the response encryption key for an encrypted response, and `None` (CBOR `null`)
    /// otherwise.
    #[must_use]
    pub fn redirect(
        client_id: &str,
        nonce: &str,
        jwk_thumbprint: Option<&JwkThumbprint>,
        response_uri: &str,
    ) -> Self {
        let info = Cbor::Array(vec![
            Cbor::text(client_id),
            Cbor::text(nonce),
            thumbprint(jwk_thumbprint),
            Cbor::text(response_uri),
        ]);
        Self::of("OpenID4VPHandover", &info)
    }

    fn of(name: &str, info: &Cbor) -> Self {
        let handover = Cbor::Array(vec![
            Cbor::text(name),
            Cbor::Bytes(Sha256::digest(info.encode()).to_vec()),
        ]);
        Self {
            encoded: handover.encode(),
        }
    }

    /// A `Handover` a host encoded: one of the two arrays of B.2.6, with a 32-byte digest.
    ///
    /// # Errors
    ///
    /// [`HandoverInvalid`] for any other bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, HandoverInvalid> {
        let item = cbor::decode(bytes).map_err(HandoverInvalid::Cbor)?;
        let valid = match item.as_array() {
            Some([name, digest]) => {
                matches!(
                    name.as_text(),
                    Some("OpenID4VPHandover" | "OpenID4VPDCAPIHandover")
                ) && digest.as_bytes().is_some_and(|d| d.len() == 32)
            }
            _ => false,
        };
        if !valid {
            return Err(HandoverInvalid::Shape);
        }
        Ok(Self {
            encoded: bytes.to_vec(),
        })
    }

    /// The encoded `Handover`.
    #[must_use]
    pub fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }

    /// `SessionTranscript = [null, null, Handover]`, encoded.
    #[must_use]
    pub fn session_transcript(&self) -> Vec<u8> {
        [&[0x83, 0xf6, 0xf6][..], &self.encoded].concat()
    }
}

fn thumbprint(jwk_thumbprint: Option<&JwkThumbprint>) -> Cbor {
    jwk_thumbprint.map_or(Cbor::Null, |t| Cbor::Bytes(t.0.to_vec()))
}

/// A JWK SHA-256 Thumbprint (RFC 7638).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwkThumbprint([u8; 32]);

impl JwkThumbprint {
    /// The thumbprint whose digest is `digest`, as a host states it.
    #[must_use]
    pub fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The JWK SHA-256 Thumbprint (RFC 7638) of an elliptic-curve key: the digest of
/// `{"crv":…,"kty":"EC","x":…,"y":…}` with no whitespace. `None` for a key of another type or
/// without these members as strings.
#[must_use]
pub fn ec_jwk_thumbprint(jwk: &Value) -> Option<JwkThumbprint> {
    if jwk.get("kty")?.as_str()? != "EC" {
        return None;
    }
    let member = |name: &str| jwk.get(name).and_then(Value::as_str);
    let canonical = serde_json::json!({
        "crv": member("crv")?,
        "kty": "EC",
        "x": member("x")?,
        "y": member("y")?,
    });
    // serde_json writes object members in key order without whitespace, as RFC 7638 asks.
    Some(JwkThumbprint(
        Sha256::digest(canonical.to_string().as_bytes()).into(),
    ))
}
