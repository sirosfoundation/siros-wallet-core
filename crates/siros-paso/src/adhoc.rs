//! Proof Metadata §5: the ad-hoc metadata JWT a PaSO entry may carry. The matcher verifies
//! steps 1-4, 6 and 7 before relying on it (§5.3); step 5, its `exp`, reads the clock, which
//! phase 2 checks. A JWT that fails a step makes the entry incompatible, the stored metadata
//! never standing in.
//!
//! The model's issuer signature is an HMAC-SHA-256 under the issuer key's secret, base64url
//! without padding.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use siros_explain::Explain;
use siros_openid4vp::ids::FormatId;
use siros_openid4vp::json::Node;

use crate::document::{Issuer, PasoDocument};
use crate::metadata::python_repr;

/// The `typ` of an ad-hoc metadata JWT (§5.2).
pub const TYP: &str = "adhoc-transaction-metadata+jwt";

/// base64url as Python's `urlsafe_b64decode` reads a JWS part padded to its length: padding
/// optional, bits past the last byte ignored.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// A §5.3 step the JWT fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.adhoc")]
pub enum AdhocFailure {
    /// Phase 2 found it expired (step 5).
    #[error("expired, as phase 2 found (step 5)")]
    Expired,
    /// No compact JWS of three parts.
    #[error("not a compact JWS")]
    NotJws,
    /// A header or payload part that is no base64url-encoded UTF-8 JSON with unique member
    /// names.
    #[error("a part is not base64url-encoded UTF-8 JSON: {0}")]
    Encoding(#[explain(name = "detail")] String),
    /// A header or payload that is no JSON object.
    #[error("a part is not a JSON object")]
    NotObject,
    /// Step 1: the `typ`.
    #[error("typ {0}")]
    Typ(#[explain(name = "typ")] String),
    /// Step 3, x5c-based keys: no chain to a root of the wallet's trust store, or a `kid`.
    #[error("no x5c chain to the wallet's trust store")]
    Untrusted,
    /// Step 6, x5c-based keys: the chain's root or leaf subject is not the credential's.
    #[error("the chain's root or leaf subject is not the credential's")]
    ForeignChain,
    /// Step 3, key-set keys: no key of the issuer's key set, or a chain.
    #[error("signed by no key of the credential issuer's key set")]
    UnknownKey,
    /// Step 2: the signature.
    #[error("the signature does not verify")]
    Signature,
    /// Step 4: `iss`.
    #[error("iss is not the credential's issuer")]
    Issuer,
    /// Step 6: `sub` and `format`.
    #[error("sub and format are not the credential's type and format")]
    Binding,
    /// Step 7: `transaction_data_type`.
    #[error("transaction_data_type is not the entry's type")]
    TransactionType,
    /// §5.2: `metadata` an object and `exp` an integer.
    #[error("no metadata object or no integer exp")]
    Payload,
}

/// A root certificate of the wallet's trust store, by its name in the model's chain stand-in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustAnchor(pub String);

/// An ad-hoc metadata JWT's decoded header and payload and its three parts as received.
#[derive(Debug, Clone)]
pub struct Jws<'j> {
    /// The JWT as received.
    pub text: &'j str,
    header: Node<'static>,
    payload: Node<'static>,
    signing_input: &'j str,
    signature: &'j str,
}

impl<'j> Jws<'j> {
    /// The parts of a compact JWS, the header and payload decoded.
    pub fn parse(text: &'j str) -> Result<Self, AdhocFailure> {
        let mut parts = text.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AdhocFailure::NotJws);
        };
        let decoded = |part: &str| -> Result<Node<'static>, AdhocFailure> {
            let bytes = BASE64URL
                .decode(part)
                .map_err(|e| AdhocFailure::Encoding(e.to_string()))?;
            let json =
                String::from_utf8(bytes).map_err(|e| AdhocFailure::Encoding(e.to_string()))?;
            let node = Node::parse(&json)
                .map_err(|e| AdhocFailure::Encoding(e.to_string()))?
                .into_owned();
            Ok(node)
        };
        let (header_node, payload_node) = (decoded(header)?, decoded(payload)?);
        if header_node.as_object().is_none() || payload_node.as_object().is_none() {
            return Err(AdhocFailure::NotObject);
        }
        Ok(Self {
            text,
            header: header_node,
            payload: payload_node,
            signing_input: text
                .get(..header.len() + 1 + payload.len())
                .unwrap_or_default(),
            signature,
        })
    }

    /// The payload's `metadata`.
    #[must_use]
    pub fn metadata(&self) -> Option<&Node<'static>> {
        self.payload.get("metadata")
    }

    /// The payload's `exp`.
    #[must_use]
    pub fn exp(&self) -> Option<&Node<'static>> {
        self.payload.get("exp")
    }

    /// Whether the stand-in signature verifies under a secret.
    fn signed_by(&self, secret: &str) -> bool {
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(self.signing_input.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()) == self.signature
    }
}

/// What a JWT binds to: the credential's document and format, the entry's type, the wallet's
/// trust store, and the JWTs phase 2 found expired.
pub(crate) struct Binding<'b> {
    pub(crate) document: &'b PasoDocument<'b>,
    pub(crate) format: &'b FormatId<'b>,
    pub(crate) kind: &'b str,
    pub(crate) trust: &'b [TrustAnchor],
    pub(crate) expired: &'b [String],
}

impl Binding<'_> {
    /// §5.3 steps 1-4, 6 and 7, after the expiry phase 2 found: the verified JWT.
    pub(crate) fn verify<'j>(&self, text: &'j str) -> Result<Jws<'j>, AdhocFailure> {
        if self.expired.iter().any(|jwt| jwt == text) {
            return Err(AdhocFailure::Expired);
        }
        let jws = Jws::parse(text)?;
        let header = &jws.header;
        match header.get("typ") {
            Some(Node::String(typ)) if typ == TYP => {}
            other => {
                return Err(AdhocFailure::Typ(
                    other.map_or_else(|| "None".to_owned(), python_repr),
                ));
            }
        }
        let secret = match self.document.issuer {
            Issuer::Chain { root, subject, .. } => {
                let chain = header.get("x5c").and_then(Node::as_object);
                let chain_root = chain
                    .and_then(|chain| chain.get("root"))
                    .and_then(Node::as_str);
                let trusted = chain_root
                    .is_some_and(|named| self.trust.iter().any(|anchor| anchor.0 == named));
                let Some(chain) = chain.filter(|_| header.get("kid").is_none() && trusted) else {
                    return Err(AdhocFailure::Untrusted);
                };
                let leaf = chain.get("subject").and_then(Node::as_str);
                if chain_root != Some(root) || leaf != Some(subject) {
                    return Err(AdhocFailure::ForeignChain);
                }
                chain.get("key")
            }
            Issuer::KeySet { keys, .. } => {
                let key = header
                    .get("kid")
                    .and_then(Node::as_str)
                    .filter(|_| header.get("x5c").is_none())
                    .and_then(|kid| keys.get(kid));
                key.ok_or(AdhocFailure::UnknownKey).map(Some)?
            }
        };
        if !secret
            .and_then(Node::as_str)
            .is_some_and(|secret| jws.signed_by(secret))
        {
            return Err(AdhocFailure::Signature);
        }
        let payload = &jws.payload;
        let text_of = |name: &str| payload.get(name).and_then(Node::as_str);
        if text_of("iss") != Some(self.document.issuer.iss()) {
            return Err(AdhocFailure::Issuer);
        }
        if text_of("sub") != Some(self.document.credential_type)
            || text_of("format") != Some(self.format.as_str())
        {
            return Err(AdhocFailure::Binding);
        }
        if text_of("transaction_data_type") != Some(self.kind) {
            return Err(AdhocFailure::TransactionType);
        }
        let integer_exp = matches!(jws.exp(), Some(Node::Number(exp)) if exp.is_integer());
        if jws.metadata().and_then(Node::as_object).is_none() || !integer_exp {
            return Err(AdhocFailure::Payload);
        }
        Ok(jws)
    }
}
