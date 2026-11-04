//! What binds every presentation of a response to its request, and the SessionTranscript an mdoc
//! presentation authenticates (ISO/IEC 18013-5 §9.1.5.1 as OpenID4VP B.2.6 profiles it).

use sha2::{Digest, Sha256};

use crate::cbor::{CborError, Value, embedded, encode};
use crate::ids::{ClientId, Nonce, Origin};
use crate::request::AgreeableKey;

/// A JWK SHA-256 Thumbprint (RFC 7638).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Thumbprint(pub [u8; 32]);

/// Where a redirect-based response goes (OpenID4VP §5.1, §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint<'s> {
    /// `response_uri`.
    ResponseUri(&'s str),
    /// `redirect_uri`.
    RedirectUri(&'s str),
}

/// The handover information of OpenID4VP 1.0 B.2.6, which binds a presentation to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handover<'s> {
    /// `OpenID4VPDCAPIHandover` (B.2.6.2): a request over the DC API.
    DcApi {
        /// The Origin, without the `origin:` prefix.
        origin: &'s Origin<'s>,
        /// The `nonce`.
        nonce: &'s Nonce<'s>,
        /// The thumbprint of the key the response is encrypted to; `None` for `dc_api`.
        thumbprint: Option<Thumbprint>,
    },
    /// `OpenID4VPHandover` (B.2.6.1): a redirect-based request.
    Redirect {
        /// The `client_id`, with its Client Identifier Prefix.
        client_id: &'s ClientId<'s>,
        /// The `nonce`.
        nonce: &'s Nonce<'s>,
        /// The thumbprint of the key the response is encrypted to; `None` when unencrypted.
        thumbprint: Option<Thumbprint>,
        /// The `response_uri` or `redirect_uri`.
        endpoint: Endpoint<'s>,
    },
}

/// What a presentation binds: the handover, from which the audience and the nonce follow, and
/// the Verifier's public keys, which a presentation may need (an mdoc MAC key agreement).
#[derive(Debug, Clone)]
pub struct Session<'s> {
    /// The handover information.
    pub handover: Handover<'s>,
    /// The Verifier's `jwks` keys the wallet can agree a key with.
    pub keys: &'s [AgreeableKey<'s>],
}

impl Session<'_> {
    /// The audience (OpenID4VP Annex A, §5.9): the Origin prefixed with `origin:` over the DC
    /// API, even for a signed request; the Client Identifier otherwise.
    #[must_use]
    pub fn audience(&self) -> String {
        match self.handover {
            Handover::DcApi { origin, .. } => format!("origin:{origin}"),
            Handover::Redirect { client_id, .. } => client_id.to_string(),
        }
    }

    /// The request's `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &Nonce<'_> {
        match self.handover {
            Handover::DcApi { nonce, .. } | Handover::Redirect { nonce, .. } => nonce,
        }
    }
}

/// `[null, null, Handover]`: DeviceEngagementBytes and EReaderKeyBytes null (OpenID4VP B.2.6.1,
/// B.2.6.2).
#[derive(Debug, Clone, PartialEq)]
pub struct SessionTranscript(Value);

/// ISO/IEC 18013-5 §9.1.5.1 SessionTranscriptBytes, `#6.24(bstr .cbor SessionTranscript)`, whose
/// SHA-256 §9.1.3.5 takes as the MAC key's HKDF salt. Only [`SessionTranscript::tagged_bytes`]
/// makes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTranscriptBytes(Vec<u8>);

impl SessionTranscriptBytes {
    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SessionTranscript {
    /// B.2.6.1's `["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, thumbprint or null,
    /// responseUri]))]` for a redirect, B.2.6.2's `["OpenID4VPDCAPIHandover",
    /// SHA-256(CBOR([origin, nonce, thumbprint or null]))]` over the DC API.
    ///
    /// # Errors
    ///
    /// ciborium cannot write the handover information.
    pub fn of(handover: &Handover<'_>) -> Result<Self, CborError> {
        let thumbprint =
            |key: Option<Thumbprint>| key.map_or(Value::Null, |key| Value::Bytes(key.0.to_vec()));
        let (name, info) = match handover {
            Handover::DcApi {
                origin,
                nonce,
                thumbprint: key,
            } => (
                "OpenID4VPDCAPIHandover",
                vec![
                    Value::Text(origin.to_string()),
                    Value::Text(nonce.to_string()),
                    thumbprint(*key),
                ],
            ),
            Handover::Redirect {
                client_id,
                nonce,
                thumbprint: key,
                endpoint,
            } => {
                let (Endpoint::ResponseUri(uri) | Endpoint::RedirectUri(uri)) = endpoint;
                (
                    "OpenID4VPHandover",
                    vec![
                        Value::Text(client_id.to_string()),
                        Value::Text(nonce.to_string()),
                        thumbprint(*key),
                        Value::Text((*uri).to_owned()),
                    ],
                )
            }
        };
        let hash = Sha256::digest(encode(&Value::Array(info))?);
        Ok(Self(Value::Array(vec![
            Value::Null,
            Value::Null,
            Value::Array(vec![
                Value::Text(name.to_owned()),
                Value::Bytes(hash.to_vec()),
            ]),
        ])))
    }

    /// The transcript's CBOR, as B.2.6's SessionTranscript examples print it.
    ///
    /// # Errors
    ///
    /// ciborium cannot write the transcript.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CborError> {
        encode(&self.0)
    }

    /// SessionTranscriptBytes: `#6.24(bstr .cbor SessionTranscript)`.
    ///
    /// # Errors
    ///
    /// ciborium cannot write the transcript.
    pub fn tagged_bytes(&self) -> Result<SessionTranscriptBytes, CborError> {
        encode(&embedded(self.to_bytes()?)).map(SessionTranscriptBytes)
    }

    /// The transcript, as DeviceAuthentication's second element.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.0
    }
}
