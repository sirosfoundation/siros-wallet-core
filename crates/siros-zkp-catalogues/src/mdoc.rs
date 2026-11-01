//! The nym_auth form of an ISO/IEC 18013-5 attestation (nym_auth catalogue, "Attestation" and
//! "ISO/IEC 18013-5 encoding"), read from a stored credential.

use std::fmt;

use siros_codec::cbor::Value;
use siros_codec::date::{Date, DateTime};
use siros_codec::signature::{Es256Signature, SignatureLength};
use siros_mdoc::{
    CoseAlgorithm, DigestAlgorithm, ElementIdentifier, IssuerSignedItem, Mdoc, P256Key,
    SigStructure,
};

use crate::catalogue::MDOC_DOCTYPE;

/// Why an element of the nym_auth namespace is refused: `F` is why its value has another form
/// than the catalogue gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ElementFault<F> {
    /// The namespace lacks it.
    #[error("the namespace lacks it")]
    Absent,
    /// Its value has another form.
    #[error("its value has another form")]
    Form(#[source] F),
}

/// Why a value is no `full-date = #6.1004(tstr)` (RFC 8943).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum FullDateFault {
    /// The value is not under tag 1004.
    #[error("the value is not under tag 1004")]
    Tag,
    /// The tagged value is not a text string.
    #[error("the tagged value is not a text string")]
    NotText,
    /// The text is no RFC 3339 `full-date`.
    #[error("the text is no RFC 3339 `full-date`")]
    Date,
}

/// Why a value is no 32-byte commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum CommitmentFault {
    /// The value is not a byte string.
    #[error("the value is not a byte string")]
    NotBytes,
    /// The byte string has this many bytes.
    #[error("the byte string has {0} bytes")]
    Length(usize),
}

/// Why an mdoc is out of the nym_auth form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("nym_auth mdoc: {}", self.code())]
pub enum FormError {
    /// The issuer signs with this algorithm, where the form takes ES256 (`{1: -7}`).
    Algorithm(CoseAlgorithm),
    /// The issuer's signature is no ES256 signature.
    Signature(#[source] SignatureLength),
    /// `digestAlgorithm` is this algorithm, where the form takes `SHA-256`.
    DigestAlgorithm(DigestAlgorithm),
    /// The nym_auth namespace is missing.
    NameSpace,
    /// The namespace holds this element, other than `birth_date`, `ssc` and `psc`.
    Element(ElementIdentifier),
    /// `psc` is not a 32-byte string.
    Psc(#[source] CommitmentFault),
    /// `birth_date` is missing or not a tag-1004 `full-date`.
    BirthDate(#[source] ElementFault<FullDateFault>),
    /// `ssc` is missing or not a 32-byte string.
    Ssc(#[source] ElementFault<CommitmentFault>),
}

impl FormError {
    /// A stable identifier: the rule of the nym_auth form.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Algorithm(_) => "issuer_algorithm",
            Self::Signature(_) => "issuer_signature_length",
            Self::DigestAlgorithm(_) => "nym_auth_digest_algorithm",
            Self::NameSpace => "nym_auth_name_space",
            Self::Element(_) | Self::Psc(_) => "nym_auth_element",
            Self::BirthDate(_) => "birth_date",
            Self::Ssc(_) => "ssc",
        }
    }
}

/// A salted commitment of the nym_auth namespace: `ssc` or `psc`, 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Commitment([u8; 32]);

impl Commitment {
    /// The commitment's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A signed data element and the bytes its digest covers.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedElement<T> {
    value: T,
    bytes: Vec<u8>,
}

impl<T> SignedElement<T> {
    /// The element's value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// `IssuerSignedItemBytes`: the tag-24 item, as issued.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A nym_auth attestation in the ISO/IEC 18013-5 form.
#[derive(Clone, PartialEq, Eq)]
pub struct NymAuthMdoc {
    issuer_signed: Vec<u8>,
    sig_structure: SigStructure,
    issuer_signature: Es256Signature,
    device_key: P256Key,
    valid_from: DateTime,
    valid_until: DateTime,
    birth_date: SignedElement<Date>,
    ssc: SignedElement<Commitment>,
    psc: Option<SignedElement<Commitment>>,
}

impl NymAuthMdoc {
    /// The `IssuerSigned` structure, as issued.
    #[must_use]
    pub fn issuer_signed(&self) -> &[u8] {
        &self.issuer_signed
    }

    /// The COSE `Sig_structure` the issuer signed.
    #[must_use]
    pub fn sig_structure(&self) -> &SigStructure {
        &self.sig_structure
    }

    /// The issuer's ES256 signature.
    #[must_use]
    pub fn issuer_signature(&self) -> &Es256Signature {
        &self.issuer_signature
    }

    /// `deviceKeyInfo.deviceKey`.
    #[must_use]
    pub fn device_key(&self) -> &P256Key {
        &self.device_key
    }

    /// `validityInfo.validFrom`.
    #[must_use]
    pub fn valid_from(&self) -> DateTime {
        self.valid_from
    }

    /// `validityInfo.validUntil`.
    #[must_use]
    pub fn valid_until(&self) -> DateTime {
        self.valid_until
    }

    /// `birth_date`.
    #[must_use]
    pub fn birth_date(&self) -> &SignedElement<Date> {
        &self.birth_date
    }

    /// `ssc`.
    #[must_use]
    pub fn ssc(&self) -> &SignedElement<Commitment> {
        &self.ssc
    }

    /// `psc`, when issued.
    #[must_use]
    pub fn psc(&self) -> Option<&SignedElement<Commitment>> {
        self.psc.as_ref()
    }
}

/// Shows nothing: `birth_date`, `ssc` and `psc` are undisclosable.
impl<T> fmt::Debug for SignedElement<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedElement").finish_non_exhaustive()
    }
}

/// Shows nothing: the commitments are undisclosable.
impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Commitment").finish_non_exhaustive()
    }
}

/// Shows the device key and the validity: the elements are undisclosable.
impl fmt::Debug for NymAuthMdoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NymAuthMdoc")
            .field("device_key", &self.device_key)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish_non_exhaustive()
    }
}

/// Whether a stored credential is a nym_auth mdoc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// It is.
    NymAuth(Box<NymAuthMdoc>),
    /// It is an mdoc of another `docType`.
    OtherDocType,
}

/// Reads an mdoc `siros-mdoc` parsed.
///
/// # Errors
///
/// [`FormError`]: what puts the mdoc out of the nym_auth form.
pub fn read_mdoc(mdoc: &Mdoc) -> Result<Reading, FormError> {
    if *mdoc.doc_type() != MDOC_DOCTYPE {
        return Ok(Reading::OtherDocType);
    }
    let auth = mdoc.issuer_auth();
    if auth.algorithm() != CoseAlgorithm::ES256 {
        return Err(FormError::Algorithm(auth.algorithm()));
    }
    let issuer_signature = Es256Signature::parse(auth.signature()).map_err(FormError::Signature)?;
    let mso = mdoc.mso();
    if mso.digest_algorithm() != DigestAlgorithm::Sha256 {
        return Err(FormError::DigestAlgorithm(mso.digest_algorithm()));
    }
    let name_space = mdoc
        .name_spaces()
        .iter()
        .find(|n| *n.name() == MDOC_DOCTYPE)
        .ok_or(FormError::NameSpace)?;
    let elements = read_elements(name_space.items())?;
    Ok(Reading::NymAuth(Box::new(NymAuthMdoc {
        issuer_signed: mdoc.issuer_signed().to_vec(),
        sig_structure: auth.sig_structure().clone(),
        issuer_signature,
        device_key: *mso.device_key(),
        valid_from: mso.validity().valid_from(),
        valid_until: mso.validity().valid_until(),
        birth_date: elements
            .birth_date
            .ok_or(FormError::BirthDate(ElementFault::Absent))?,
        ssc: elements.ssc.ok_or(FormError::Ssc(ElementFault::Absent))?,
        psc: elements.psc,
    })))
}

#[derive(Default)]
struct Elements {
    birth_date: Option<SignedElement<Date>>,
    ssc: Option<SignedElement<Commitment>>,
    psc: Option<SignedElement<Commitment>>,
}

/// The nym_auth namespace: `birth_date`, `ssc` and an optional `psc`. The mdoc holds each
/// element identifier once.
fn read_elements(items: &[IssuerSignedItem]) -> Result<Elements, FormError> {
    let mut elements = Elements::default();
    for item in items {
        let bytes = item.bytes().to_vec();
        match item.identifier().as_str() {
            "birth_date" => {
                let value = full_date(item.value())
                    .map_err(|fault| FormError::BirthDate(ElementFault::Form(fault)))?;
                elements.birth_date = Some(SignedElement { value, bytes });
            }
            "ssc" => {
                let value = commitment(item.value())
                    .map_err(|fault| FormError::Ssc(ElementFault::Form(fault)))?;
                elements.ssc = Some(SignedElement { value, bytes });
            }
            "psc" => {
                let value = commitment(item.value()).map_err(FormError::Psc)?;
                elements.psc = Some(SignedElement { value, bytes });
            }
            _ => return Err(FormError::Element(item.identifier().clone())),
        }
    }
    Ok(elements)
}

/// `full-date = #6.1004(tstr)` (RFC 8943).
fn full_date(value: &Value) -> Result<Date, FullDateFault> {
    let Value::Tag(1004, text) = value else {
        return Err(FullDateFault::Tag);
    };
    let Value::Text(text) = text.as_ref() else {
        return Err(FullDateFault::NotText);
    };
    Date::parse(text).ok_or(FullDateFault::Date)
}

/// A 32-byte string.
fn commitment(value: &Value) -> Result<Commitment, CommitmentFault> {
    let Value::Bytes(value) = value else {
        return Err(CommitmentFault::NotBytes);
    };
    <[u8; 32]>::try_from(value.as_slice())
        .map(Commitment)
        .map_err(|_| CommitmentFault::Length(value.len()))
}
