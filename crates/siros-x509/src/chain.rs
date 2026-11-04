//! The `x5c` header (RFC 7515 §4.1.6): base64 DER certificates, the leaf first, each parsed by
//! x509-cert with the DER as received; and the leaf's key (RFC 5480 §2.1.1, §2.2).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Decode;
use der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256};
use siros_openid4vp::jose::{ProtectedHeader, VerificationKey};
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
    /// The P-256 key: id-ecPublicKey on the named curve secp256r1, an uncompressed point (RFC
    /// 5480 §2.1.1, §2.2), on the curve (`VerificationKey::p256`).
    ///
    /// # Errors
    ///
    /// [`X509Refusal::Key`]: another algorithm or curve, another encoding of the point, or a
    /// point off the curve.
    fn key(&self) -> Result<VerificationKey, X509Refusal>;
}

impl SpkiKey for SubjectPublicKeyInfoOwned {
    fn key(&self) -> Result<VerificationKey, X509Refusal> {
        let curve = self
            .algorithm
            .parameters
            .as_ref()
            .map(|parameters| parameters.decode_as::<ObjectIdentifier>());
        if self.algorithm.oid != EC_PUBLIC_KEY || !matches!(curve, Some(Ok(SECP256R1))) {
            return Err(X509Refusal::Key);
        }
        let point = self.subject_public_key.as_bytes().ok_or(X509Refusal::Key)?;
        let [4, coordinates @ ..] = point else {
            return Err(X509Refusal::Key);
        };
        let (x, y) = coordinates.split_at_checked(32).ok_or(X509Refusal::Key)?;
        let x = <[u8; 32]>::try_from(x).map_err(|_| X509Refusal::Key)?;
        let y = <[u8; 32]>::try_from(y).map_err(|_| X509Refusal::Key)?;
        VerificationKey::p256(x, y).map_err(|_| X509Refusal::Key)
    }
}
