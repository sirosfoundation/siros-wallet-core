//! The `x5c` header (RFC 7515 §4.1.6): base64 DER certificates, the leaf first, each parsed by
//! x509-cert with the DER as received; and the leaf's key (RFC 5480 §2.1.1, §2.2).

use std::borrow::Cow;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use der::Decode;
use der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256};
use siros_openid4vp::jose::{ProtectedHeader, PublicJwk, VerificationKey};
use siros_openid4vp::json::Node;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::X509Refusal;
use crate::names::LeafHash;

/// id-ecPublicKey (RFC 5480 §2.1.1).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp256r1 (RFC 5480 §2.1.1.1).
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// A certificate of the chain: its DER as received, base64 as the header writes it, and its
/// parse.
#[derive(Debug, Clone)]
pub struct ChainCertificate {
    text: String,
    der: Vec<u8>,
    certificate: Certificate,
}

impl ChainCertificate {
    /// The item as the header writes it.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The DER as received.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The certificate.
    #[must_use]
    pub const fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The SHA-256 of the DER as received.
    #[must_use]
    pub fn hash(&self) -> LeafHash {
        LeafHash::of(Sha256::digest(&self.der).into())
    }

    /// The key of its SubjectPublicKeyInfo ([`SpkiKey`]).
    ///
    /// # Errors
    ///
    /// [`X509Refusal::Key`].
    pub fn key(&self) -> Result<VerificationKey, X509Refusal> {
        self.certificate
            .tbs_certificate()
            .subject_public_key_info()
            .key()
    }
}

/// The chain `x5c` holds: one certificate or more, the leaf first.
#[derive(Debug, Clone)]
pub struct X5c {
    leaf: ChainCertificate,
    rest: Vec<ChainCertificate>,
}

impl X5c {
    /// The chain of a protected header.
    ///
    /// # Errors
    ///
    /// `x5c` is absent, no array of strings, empty, or holds an item that is no base64 or no DER
    /// certificate.
    pub fn of(header: &ProtectedHeader) -> Result<Self, X509Refusal> {
        let items = header
            .member("x5c")
            .ok_or(X509Refusal::X5cAbsent)?
            .as_array()
            .ok_or(X509Refusal::X5cNotArray)?;
        let mut certificates = items
            .iter()
            .enumerate()
            .map(|(item, value)| ChainCertificate::parse(item, value))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter();
        let leaf = certificates.next().ok_or(X509Refusal::X5cEmpty)?;
        Ok(Self {
            leaf,
            rest: certificates.collect(),
        })
    }

    /// The leaf.
    #[must_use]
    pub const fn leaf(&self) -> &ChainCertificate {
        &self.leaf
    }

    /// Each certificate, the leaf first, in the order received.
    pub fn certificates(&self) -> impl Iterator<Item = &ChainCertificate> {
        std::iter::once(&self.leaf).chain(&self.rest)
    }
}

impl ChainCertificate {
    fn parse(item: usize, value: &Node<'_>) -> Result<Self, X509Refusal> {
        let text = value.as_str().ok_or(X509Refusal::X5cNotArray)?;
        let der = STANDARD
            .decode(text)
            .map_err(|_| X509Refusal::Base64(item))?;
        let certificate = Certificate::from_der(&der).map_err(|e| X509Refusal::Certificate {
            item,
            cause: e.to_string(),
        })?;
        Ok(Self {
            text: text.to_owned(),
            der,
            certificate,
        })
    }
}

/// The key of a SubjectPublicKeyInfo (spki's type, which x509-cert's certificates hold).
pub trait SpkiKey {
    /// The key as a public JWK, whose algorithms the verifying module states (`Haip::verifies`):
    /// id-ecPublicKey on the named curve secp256r1, secp384r1 or secp521r1 with an uncompressed
    /// point (RFC 5480 §2.1.1, §2.2) as an `EC` key of `P-256`, `P-384` or `P-521` (RFC 7518
    /// §6.2.1); id-Ed25519 or id-Ed448 without parameters (RFC 8410 §3, §4) as an `OKP` key
    /// (RFC 8037 §2). The verifying module checks the point's place on its curve.
    ///
    /// # Errors
    ///
    /// [`X509Refusal::Key`]: another algorithm or curve, or another encoding of the key.
    fn key(&self) -> Result<VerificationKey, X509Refusal>;
}

/// The named curves of RFC 5480 §2.1.1.1 the key reads, with each JWK `crv` (RFC 7518 §6.2.1.1)
/// and each coordinate's octets (SEC 1 §2.3.3).
const EC_CURVES: [(ObjectIdentifier, &str, usize); 3] = [
    (SECP256R1, "P-256", 32),
    (ObjectIdentifier::new_unwrap("1.3.132.0.34"), "P-384", 48),
    (ObjectIdentifier::new_unwrap("1.3.132.0.35"), "P-521", 66),
];

/// The EdDSA keys of RFC 8410 §3, with each JWK `crv` (RFC 8037 §2) and its key's octets (RFC
/// 8032 §5.1.5, §5.2.5).
const EDWARDS: [(ObjectIdentifier, &str, usize); 2] = [
    (ObjectIdentifier::new_unwrap("1.3.101.112"), "Ed25519", 32),
    (ObjectIdentifier::new_unwrap("1.3.101.113"), "Ed448", 57),
];

impl SpkiKey for SubjectPublicKeyInfoOwned {
    fn key(&self) -> Result<VerificationKey, X509Refusal> {
        let bits = self.subject_public_key.as_bytes().ok_or(X509Refusal::Key)?;
        let text = |value: String| Node::String(Cow::Owned(value));
        let members = if self.algorithm.oid == EC_PUBLIC_KEY {
            let named = self
                .algorithm
                .parameters
                .as_ref()
                .map(|parameters| parameters.decode_as::<ObjectIdentifier>());
            let Some(Ok(named)) = named else {
                return Err(X509Refusal::Key);
            };
            let (_, crv, octets) = EC_CURVES
                .iter()
                .find(|(oid, _, _)| *oid == named)
                .ok_or(X509Refusal::Key)?;
            let [4, coordinates @ ..] = bits else {
                return Err(X509Refusal::Key);
            };
            let (x, y) = coordinates
                .split_at_checked(*octets)
                .ok_or(X509Refusal::Key)?;
            if y.len() != *octets {
                return Err(X509Refusal::Key);
            }
            vec![
                (Cow::Borrowed("kty"), text("EC".to_owned())),
                (Cow::Borrowed("crv"), text((*crv).to_owned())),
                (Cow::Borrowed("x"), text(URL_SAFE_NO_PAD.encode(x))),
                (Cow::Borrowed("y"), text(URL_SAFE_NO_PAD.encode(y))),
            ]
        } else {
            let (_, crv, octets) = EDWARDS
                .iter()
                .find(|(oid, _, _)| *oid == self.algorithm.oid)
                .ok_or(X509Refusal::Key)?;
            if self.algorithm.parameters.is_some() || bits.len() != *octets {
                return Err(X509Refusal::Key);
            }
            vec![
                (Cow::Borrowed("kty"), text("OKP".to_owned())),
                (Cow::Borrowed("crv"), text((*crv).to_owned())),
                (Cow::Borrowed("x"), text(URL_SAFE_NO_PAD.encode(bits))),
            ]
        };
        let jwk = Node::object(members).map_err(|_| X509Refusal::Key)?;
        PublicJwk::parse(jwk)
            .map(VerificationKey::of)
            .map_err(|_| X509Refusal::Key)
    }
}
