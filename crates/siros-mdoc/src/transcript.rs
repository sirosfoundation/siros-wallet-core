//! The mdoc's binding to the session: OpenID4VP B.2.6's handover of the session's binding facts,
//! the RFC 7638 thumbprint of the key the core sealed to, and ISO/IEC 18013-5 §9.1.5.1's
//! SessionTranscript as B.2.6 profiles it.

use sha2::{Digest, Sha256};
use siros_explain::Explain;
use siros_openid4vp::cbor::{self, CborError, Value, embedded};
use siros_openid4vp::detail;
use siros_openid4vp::ids::{ClientId, Nonce, Origin};
use siros_openid4vp::json::{Node, quote};
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::AgreeableKey;
use siros_openid4vp::session::{Session, SessionBinding};
use siros_openid4vp::uri::ResponseUri;

/// A JWK SHA-256 Thumbprint (RFC 7638) of a key. Only [`Thumbprint::of`] makes one, from the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Thumbprint([u8; 32]);

impl Thumbprint {
    /// SHA-256 over the key's required members as its JWK writes them, sorted, without
    /// whitespace (RFC 7638 §3.2): `crv`, `kty`, `x` and `y` for an `EC` key (RFC 7518 §6.2.1),
    /// `crv`, `kty` and `x` for an `OKP` key (RFC 8037 §2). `None` for another key type.
    #[must_use]
    pub fn of(key: &AgreeableKey<'_>) -> Option<Self> {
        let member = |name: &str| key.jwk().get(name).and_then(Node::as_str);
        let required: &[&str] = match key.kty().as_str() {
            "EC" => &["crv", "kty", "x", "y"],
            "OKP" => &["crv", "kty", "x"],
            _ => return None,
        };
        let canonical = required
            .iter()
            .map(|name| member(name).map(|value| format!("{}:{}", quote(name), quote(value))))
            .collect::<Option<Vec<_>>>()?
            .join(",");
        Some(Self(Sha256::digest(format!("{{{canonical}}}")).into()))
    }

    /// The digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A `response_uri` as a handover takes it (B.2.6.1), its text as the request names it. Any text:
/// the hash input holds the request's bytes, a non-ASCII `response_uri` among them, which
/// [`ResponseUri`] does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandoverUri<'s>(&'s str);

impl<'s> HandoverUri<'s> {
    /// The URI `text`.
    #[must_use]
    pub const fn new(text: &'s str) -> Self {
        Self(text)
    }

    /// The text.
    #[must_use]
    pub const fn as_str(self) -> &'s str {
        self.0
    }
}

impl<'s> From<&'s ResponseUri> for HandoverUri<'s> {
    fn from(uri: &'s ResponseUri) -> Self {
        Self(uri.as_str())
    }
}

/// The handover (B.2.6) of a session, built from its binding facts by [`Handover::of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handover<'s> {
    /// `OpenID4VPDCAPIHandover` (B.2.6.2).
    DcApi {
        /// The Origin, without `origin:`.
        origin: &'s Origin<'s>,
        /// The `nonce`.
        nonce: &'s Nonce<'s>,
        /// The thumbprint of the key the core sealed to; `None` for a plain mode.
        thumbprint: Option<Thumbprint>,
    },
    /// `OpenID4VPHandover` (B.2.6.1).
    Redirect {
        /// The full `client_id`.
        client_id: &'s ClientId<'s>,
        /// The `nonce`.
        nonce: &'s Nonce<'s>,
        /// The thumbprint of the key the core sealed to (B.2.6.1: "if the response is
        /// encrypted"); `None` for a plain mode.
        thumbprint: Option<Thumbprint>,
        /// The `response_uri`.
        response_uri: HandoverUri<'s>,
    },
}

impl<'s> Handover<'s> {
    /// The handover of the session's channel: its binding, its `nonce`, and the thumbprint of
    /// [`Session::encrypted_to`].
    ///
    /// # Errors
    ///
    /// The core sealed to a key RFC 7638 gives no thumbprint of, which no sealing statement
    /// admits.
    pub fn of(session: &Session<'s>) -> Result<Self, Fault> {
        let thumbprint = match session.encrypted_to() {
            None => None,
            Some(sealed) => Some(Thumbprint::of(sealed.key()).ok_or_else(|| {
                crate::fault(detail!(
                    "the core sealed to a key of type {kty}, which has no RFC 7638 thumbprint here",
                    kty = sealed.key().kty().as_str().to_owned()
                ))
            })?),
        };
        Ok(match session.binding() {
            SessionBinding::DcApi { origin } => Self::DcApi {
                origin,
                nonce: session.nonce(),
                thumbprint,
            },
            SessionBinding::Redirect {
                client_id,
                response_uri,
            } => Self::Redirect {
                client_id,
                nonce: session.nonce(),
                thumbprint,
                response_uri: HandoverUri::from(response_uri),
            },
        })
    }
}

/// `SessionTranscript` (ISO/IEC 18013-5 §9.1.5.1) as its CBOR encodes it: B.2.6's
/// `[null, null, Handover]` from [`SessionTranscript::of`], or a transcript a Verifier holds
/// ([`SessionTranscript::decode`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionTranscript(Vec<u8>);

impl SessionTranscript {
    /// B.2.6.1's `["OpenID4VPHandover", SHA-256(CBOR([clientId, nonce, thumbprint or null,
    /// responseUri]))]` for a redirect, B.2.6.2's `["OpenID4VPDCAPIHandover",
    /// SHA-256(CBOR([origin, nonce, thumbprint or null]))]` over the DC API, after
    /// DeviceEngagementBytes and EReaderKeyBytes, both null.
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
                response_uri,
            } => (
                "OpenID4VPHandover",
                vec![
                    Value::Text(client_id.to_string()),
                    Value::Text(nonce.to_string()),
                    thumbprint(*key),
                    Value::Text(response_uri.as_str().to_owned()),
                ],
            ),
        };
        let hash = Sha256::digest(cbor::encode(&Value::Array(info))?);
        cbor::encode(&Value::Array(vec![
            Value::Null,
            Value::Null,
            Value::Array(vec![
                Value::Text(name.to_owned()),
                Value::Bytes(hash.to_vec()),
            ]),
        ]))
        .map(Self)
    }

    /// The transcript a Verifier holds, its CBOR `encoded`: one data item, an array of
    /// DeviceEngagementBytes, EReaderKeyBytes and the Handover (ISO/IEC 18013-5 §9.1.5.1).
    ///
    /// # Errors
    ///
    /// [`TranscriptError::Cbor`] when `encoded` is no single CBOR data item the wallet reads,
    /// [`TranscriptError::Items`] when the item is no array of three.
    pub fn decode(encoded: Vec<u8>) -> Result<Self, TranscriptError> {
        match cbor::decode(&encoded)? {
            Value::Array(items) if items.len() == 3 => Ok(Self(encoded)),
            _ => Err(TranscriptError::Items),
        }
    }

    /// The encoding, as B.2.6's SessionTranscript examples print it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// SessionTranscriptBytes: `#6.24(bstr .cbor SessionTranscript)`.
    ///
    /// # Errors
    ///
    /// ciborium cannot write the tagged byte string.
    pub fn tagged_bytes(&self) -> Result<SessionTranscriptBytes, CborError> {
        cbor::encode(&embedded(self.0.clone())).map(SessionTranscriptBytes)
    }
}

/// Why bytes are no SessionTranscript (ISO/IEC 18013-5 §9.1.5.1).
#[derive(Debug, thiserror::Error, Explain)]
pub enum TranscriptError {
    /// No single CBOR data item the wallet reads.
    #[error("no CBOR data item the wallet reads")]
    #[explain(id = "transcript.cbor")]
    Cbor(#[from] CborError),
    /// A data item other than an array of three items.
    #[error("the data item is no array of three items")]
    #[explain(id = "transcript.items")]
    Items,
}

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
