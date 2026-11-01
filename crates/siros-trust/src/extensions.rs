//! The extensions TR3 processes (RFC 5280, Section 4.2), each parsed.
//!
//! The processed set is the extensions of the ISO/IEC 18013-5 Annex B IACA, link and Document
//! Signer profiles that RFC 5280 or those profiles mark critical, and the key identifiers path
//! building reads:
//!
//! | Extension | Rule applied |
//! | --- | --- |
//! | basicConstraints | a signer is a CA; its pathLenConstraint bounds the intermediates below it (Section 6.1.4 (k) to (m)) |
//! | keyUsage | a signer's keyUsage, when present, includes keyCertSign (Section 6.1.4 (n)) |
//! | extKeyUsage | parsed: a critical extKeyUsage that parses counts as processed, so the Document Signer certificate, whose profile marks its extKeyUsage `id-mdl-kp-mdlDS` critical, passes Section 6.1.4 (o) |
//! | authorityKeyIdentifier | parsed; an `aki` value matches its keyIdentifier, and path building tries the anchor it names first |
//! | subjectKeyIdentifier | parsed; path building matches it to an authorityKeyIdentifier |
//!
//! A certificate on a path with a critical extension outside the set is refused (Section 6.1.4
//! (o)).

use der::asn1::{ObjectIdentifier, OctetString};
use der::Decode;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::ext::Extension;

use crate::authority::KeyIdentifier;
use crate::certificate::{CertificateError, KeyIdentifierFault};

/// `id-ce-basicConstraints` (RFC 5280, Section 4.2.1.9).
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `id-ce-keyUsage` (RFC 5280, Section 4.2.1.3).
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `id-ce-extKeyUsage` (RFC 5280, Section 4.2.1.12).
const EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// `id-ce-authorityKeyIdentifier` (RFC 5280, Section 4.2.1.1).
const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
/// `id-ce-subjectKeyIdentifier` (RFC 5280, Section 4.2.1.2).
const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// The extensions TR3 processes.
const PROCESSED: [ObjectIdentifier; 5] = [
    BASIC_CONSTRAINTS,
    KEY_USAGE,
    EXT_KEY_USAGE,
    AUTHORITY_KEY_IDENTIFIER,
    SUBJECT_KEY_IDENTIFIER,
];

/// Whether a certificate's subject is a certificate authority (basicConstraints, RFC 5280,
/// Section 4.2.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateRole {
    /// `cA` is TRUE: the subject may sign certificates, under its pathLenConstraint.
    Ca(PathLength),
    /// basicConstraints is absent, or `cA` is FALSE.
    EndEntity,
}

/// A CA's pathLenConstraint (RFC 5280, Section 4.2.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathLength {
    /// The CA states none.
    Unconstrained,
    /// At most this many non-self-issued intermediate certificates follow the CA on a path.
    AtMost(u8),
}

/// Whether a certificate's keyUsage lets its key sign certificates (RFC 5280, Section
/// 4.2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertSigning {
    /// The certificate has no keyUsage.
    Unrestricted,
    /// keyUsage asserts keyCertSign.
    Asserted,
    /// keyUsage leaves keyCertSign out.
    Withheld,
}

/// The extensions of a certificate, as TR3 reads them.
pub(crate) struct Extensions {
    pub(crate) role: CertificateRole,
    pub(crate) cert_signing: CertSigning,
    pub(crate) authority_key_identifier: Option<KeyIdentifier>,
    pub(crate) subject_key_identifier: Option<KeyIdentifier>,
    pub(crate) unprocessed_critical: Option<ObjectIdentifier>,
}

impl Extensions {
    /// The extensions of a certificate that has none.
    pub(crate) const NONE: Self = Self {
        role: CertificateRole::EndEntity,
        cert_signing: CertSigning::Unrestricted,
        authority_key_identifier: None,
        subject_key_identifier: None,
        unprocessed_critical: None,
    };

    /// The extensions `extensions`, each of the processed set parsed.
    ///
    /// # Errors
    ///
    /// [`CertificateError`]: an extension twice, or one of the processed set that does not
    /// decode.
    pub(crate) fn read(extensions: &[Extension]) -> Result<Self, CertificateError> {
        let repeated = extensions.iter().enumerate().find(|(position, extension)| {
            extensions
                .iter()
                .take(*position)
                .any(|earlier| earlier.extn_id == extension.extn_id)
        });
        if let Some((_, extension)) = repeated {
            return Err(CertificateError::ExtensionRepeated(extension.extn_id));
        }
        let value = |oid: ObjectIdentifier| {
            extensions
                .iter()
                .find(|extension| extension.extn_id == oid)
                .map(|extension| extension.extn_value.as_bytes())
        };
        let role = match value(BASIC_CONSTRAINTS) {
            None => CertificateRole::EndEntity,
            Some(bytes) => {
                let constraints = BasicConstraints::from_der(bytes)
                    .map_err(CertificateError::BasicConstraints)?;
                match (constraints.ca, constraints.path_len_constraint) {
                    (true, None) => CertificateRole::Ca(PathLength::Unconstrained),
                    (true, Some(length)) => CertificateRole::Ca(PathLength::AtMost(length)),
                    (false, _) => CertificateRole::EndEntity,
                }
            }
        };
        let cert_signing = match value(KEY_USAGE) {
            None => CertSigning::Unrestricted,
            Some(bytes) => {
                let usage = KeyUsage::from_der(bytes).map_err(CertificateError::KeyUsage)?;
                if usage.key_cert_sign() {
                    CertSigning::Asserted
                } else {
                    CertSigning::Withheld
                }
            }
        };
        if let Some(bytes) = value(EXT_KEY_USAGE) {
            drop(ExtendedKeyUsage::from_der(bytes).map_err(CertificateError::ExtendedKeyUsage)?);
        }
        let authority_key_identifier = value(AUTHORITY_KEY_IDENTIFIER)
            .map(authority_key_identifier)
            .transpose()
            .map_err(CertificateError::AuthorityKeyIdentifier)?
            .flatten();
        let subject_key_identifier = value(SUBJECT_KEY_IDENTIFIER)
            .map(subject_key_identifier)
            .transpose()
            .map_err(CertificateError::SubjectKeyIdentifier)?;
        let unprocessed_critical = extensions
            .iter()
            .find(|extension| extension.critical && !PROCESSED.contains(&extension.extn_id))
            .map(|extension| extension.extn_id);
        Ok(Self {
            role,
            cert_signing,
            authority_key_identifier,
            subject_key_identifier,
            unprocessed_critical,
        })
    }
}

/// The keyIdentifier of the AuthorityKeyIdentifier extension `bytes`; `None` without one.
fn authority_key_identifier(bytes: &[u8]) -> Result<Option<KeyIdentifier>, KeyIdentifierFault> {
    let extension = AuthorityKeyIdentifier::from_der(bytes).map_err(KeyIdentifierFault::Der)?;
    extension
        .key_identifier
        .map(|key_identifier| KeyIdentifier::new(key_identifier.as_bytes()))
        .transpose()
        .map_err(KeyIdentifierFault::KeyIdentifier)
}

/// The keyIdentifier of the SubjectKeyIdentifier extension `bytes`: an OCTET STRING.
fn subject_key_identifier(bytes: &[u8]) -> Result<KeyIdentifier, KeyIdentifierFault> {
    let key_identifier = OctetString::from_der(bytes).map_err(KeyIdentifierFault::Der)?;
    KeyIdentifier::new(key_identifier.as_bytes()).map_err(KeyIdentifierFault::KeyIdentifier)
}
