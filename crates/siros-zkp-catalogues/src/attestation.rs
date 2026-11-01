//! The Wallet's tests of a credential (system rulebooks, Section 7, step 1), with the codes of
//! Section 9 (N3). [`TestedAttestation`] is the credential that passes them at a proof time;
//! [`UsableAttestation`] adds the admission of its Document Signer for one query; [`OpenedSeed`]
//! is a delivered `secret_seed` that opens its `ssc` (privatedata, Section 5A.2).

use std::fmt;

use siros_codec::date::DateTime;
use siros_mdoc::{es256_verifies, Mdoc, P256Key, PointError};
use siros_trust::{AdmittedIssuer, Certificate, CertificateError};
use zeroize::Zeroizing;

use crate::catalogue::NymAuthQuery;
use crate::mdoc::{self, FormError, NymAuthMdoc, Reading};
use crate::outcome::CredentialCode;
use crate::verifier_id::sha256;

/// A Document Signer certificate with the P-256 key the issuer signs with: the first of an
/// mdoc's `x5chain`, or the `issuer_key_set` of a presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentSigner {
    certificate: Certificate,
    key: P256Key,
}

/// Why a certificate's key is no P-256 key in the systems' form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum KeyError {
    /// The key is not `id-ecPublicKey` on `prime256v1`.
    #[error("the key is not `id-ecPublicKey` on `prime256v1`")]
    NotP256,
    /// The key is not an uncompressed point.
    #[error("the key is not an uncompressed point")]
    Point(#[source] PointError),
}

/// Why bytes are no Document Signer certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum DocumentSignerError {
    /// The certificate does not parse.
    Certificate(#[source] CertificateError),
    /// Its key.
    Key(#[source] KeyError),
}

impl DocumentSignerError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Certificate(e) => e.code(),
            Self::Key(KeyError::NotP256) => "certificate_key_algorithm",
            Self::Key(KeyError::Point(_)) => "certificate_key_point",
        }
    }
}

impl DocumentSigner {
    /// The Document Signer of the DER certificate `der`, whose key is an uncompressed P-256
    /// point.
    ///
    /// # Errors
    ///
    /// [`DocumentSignerError`]: the certificate or its key.
    pub fn parse(der: &[u8]) -> Result<Self, DocumentSignerError> {
        let certificate = Certificate::parse(der).map_err(DocumentSignerError::Certificate)?;
        let point = certificate
            .p256_key()
            .ok_or(DocumentSignerError::Key(KeyError::NotP256))?;
        let key =
            P256Key::from_sec1(point).map_err(|e| DocumentSignerError::Key(KeyError::Point(e)))?;
        Ok(Self { certificate, key })
    }

    /// The certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The issuer key Q.
    pub fn key(&self) -> &P256Key {
        &self.key
    }
}

/// A nym_auth credential with its Document Signer read.
#[derive(Debug, Clone)]
pub struct Credential {
    mdoc: NymAuthMdoc,
    signer: DocumentSigner,
}

impl Credential {
    /// The attestation.
    pub fn mdoc(&self) -> &NymAuthMdoc {
        &self.mdoc
    }

    /// The Document Signer.
    pub fn signer(&self) -> &DocumentSigner {
        &self.signer
    }
}

/// Why a credential cannot be read in the nym_auth form: `credential_form`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unreadable {
    /// The mdoc.
    Form(#[source] FormError),
    /// The Document Signer.
    Signer(#[source] DocumentSignerError),
}

impl Unreadable {
    /// A stable identifier: the code of the mdoc's or the Document Signer's rule.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Form(e) => e.code(),
            Self::Signer(e) => e.code(),
        }
    }
}

/// A credential that reads and fails tests at the proof time.
#[derive(Debug, Clone)]
pub struct Failures {
    credential: Credential,
    codes: Vec<CredentialCode>,
}

impl Failures {
    /// The credential. The item tests still apply to it.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The codes of the failed tests, in the order `issuer_signature`, `validity`. It holds at
    /// least one.
    pub fn codes(&self) -> &[CredentialCode] {
        &self.codes
    }
}

/// Why an mdoc is no tested attestation at the proof time.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unusable {
    /// An mdoc of another `docType`: it does not match the query.
    OtherDocType,
    /// The credential cannot be read in the nym_auth form: `credential_form`.
    Unreadable(#[source] Unreadable),
    /// The credential reads and fails the tests of [`Failures::codes`].
    Fails(Box<Failures>),
}

impl Unusable {
    /// The codes of Section 9 of the failed tests. An mdoc of another `docType` has none.
    pub fn codes(&self) -> &[CredentialCode] {
        match self {
            Self::OtherDocType => &[],
            Self::Unreadable(_) => &[CredentialCode::CredentialForm],
            Self::Fails(failures) => failures.codes(),
        }
    }

    /// The credential, when it reads in the nym_auth form.
    pub fn credential(&self) -> Option<&Credential> {
        match self {
            Self::Fails(failures) => Some(failures.credential()),
            Self::OtherDocType | Self::Unreadable(_) => None,
        }
    }

    /// A stable identifier: `other_doc_type`, `credential_form`, or `credential` for the tests
    /// of [`Failures`].
    pub fn code(&self) -> &'static str {
        match self {
            Self::OtherDocType => "other_doc_type",
            Self::Unreadable(_) => CredentialCode::CredentialForm.code(),
            Self::Fails(_) => "credential",
        }
    }
}

/// A credential that passes the credential tests at a proof time (N3): the nym_auth form, the
/// issuer signature under the Document Signer's key, and the validity. A parsed [`Mdoc`] lists
/// the digest of every item it holds.
#[derive(Debug, Clone)]
pub struct TestedAttestation {
    credential: Credential,
    proof_time: DateTime,
}

impl TestedAttestation {
    /// Tests `mdoc` at `proof_time`.
    ///
    /// # Errors
    ///
    /// [`Unusable`]: another `docType`, a credential out of the nym_auth form, or the failed
    /// tests.
    pub fn of(mdoc: &Mdoc, proof_time: DateTime) -> Result<Self, Unusable> {
        let document_signer = mdoc.issuer_auth().x5chain().first();
        let mdoc = match mdoc::read_mdoc(mdoc) {
            Ok(Reading::NymAuth(mdoc)) => *mdoc,
            Ok(Reading::OtherDocType) => return Err(Unusable::OtherDocType),
            Err(e) => return Err(Unusable::Unreadable(Unreadable::Form(e))),
        };
        let signer = DocumentSigner::parse(document_signer)
            .map_err(|e| Unusable::Unreadable(Unreadable::Signer(e)))?;
        let signed = es256_verifies(
            signer.key(),
            mdoc.sig_structure().as_bytes(),
            mdoc.issuer_signature(),
        );
        let valid = mdoc.valid_from() <= proof_time && proof_time < mdoc.valid_until();
        let codes: Vec<CredentialCode> = [
            (signed, CredentialCode::IssuerSignature),
            (valid, CredentialCode::Validity),
        ]
        .into_iter()
        .filter(|(passed, _)| !passed)
        .map(|(_, code)| code)
        .collect();
        let credential = Credential { mdoc, signer };
        if codes.is_empty() {
            Ok(Self {
                credential,
                proof_time,
            })
        } else {
            Err(Unusable::Fails(Box::new(Failures { credential, codes })))
        }
    }

    /// The credential.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The proof time the credential passes the tests at.
    pub fn proof_time(&self) -> DateTime {
        self.proof_time
    }
}

/// Why an admitted issuer does not make a tested attestation usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum OtherIssuer {
    /// The admission names another certificate than the attestation's Document Signer.
    Certificate,
    /// The admission is for the authorities of another query: another `id`, or other
    /// `trusted_authorities`.
    Query,
}

impl OtherIssuer {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Certificate => "admission_other_certificate",
            Self::Query => "admission_other_query",
        }
    }
}

/// A tested attestation whose Document Signer the query's `trusted_authorities` admit (N3,
/// TR3). Proving requires it.
#[derive(Debug, Clone)]
pub struct UsableAttestation {
    tested: TestedAttestation,
    issuer: AdmittedIssuer,
}

impl UsableAttestation {
    /// `tested`, usable for `query` because `issuer` admits its Document Signer.
    ///
    /// # Errors
    ///
    /// [`OtherIssuer`]: `issuer` names another certificate than `tested`'s Document Signer, or
    /// other authorities than those of `query`.
    pub fn new(
        tested: TestedAttestation,
        issuer: AdmittedIssuer,
        query: &NymAuthQuery,
    ) -> Result<Self, OtherIssuer> {
        if issuer.leaf() != Some(tested.credential().signer().certificate()) {
            return Err(OtherIssuer::Certificate);
        }
        if !issuer
            .authorities()
            .are_those_of(query.query().credential_query())
        {
            return Err(OtherIssuer::Query);
        }
        Ok(Self { tested, issuer })
    }

    /// The credential.
    pub fn credential(&self) -> &Credential {
        self.tested.credential()
    }

    /// The proof time the credential passes the tests at.
    pub fn proof_time(&self) -> DateTime {
        self.tested.proof_time()
    }

    /// The admission of the Document Signer.
    pub fn issuer(&self) -> &AdmittedIssuer {
        &self.issuer
    }
}

/// `SHA-256(secret_seed)` is not the credential's `ssc`: `seed_mismatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub struct SeedMismatch;

impl SeedMismatch {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        "seed_mismatch"
    }
}

/// The 16-byte `secret_seed` an issuer delivered with a credential (privatedata, Section 5A).
/// It is zeroed on drop.
#[derive(Clone)]
pub struct SecretSeed(Zeroizing<[u8; 16]>);

impl SecretSeed {
    /// The seed `seed`.
    pub fn new(seed: Zeroizing<[u8; 16]>) -> Self {
        Self(seed)
    }
}

/// Shows nothing: the seed is a delivered secret.
impl fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSeed").finish_non_exhaustive()
    }
}

/// A delivered `secret_seed` whose SHA-256 is the credential's `ssc`. The Wallet opens it again
/// for each use (privatedata, Section 5A.2). It is zeroed on drop.
#[derive(Clone)]
pub struct OpenedSeed(Zeroizing<[u8; 16]>);

impl OpenedSeed {
    /// Opens the `ssc` of `credential` with `secret_seed`.
    ///
    /// # Errors
    ///
    /// [`SeedMismatch`] when `SHA-256(secret_seed)` is not `ssc`.
    pub fn open(credential: &Credential, secret_seed: &SecretSeed) -> Result<Self, SeedMismatch> {
        if sha256(&*secret_seed.0) == *credential.mdoc().ssc().value().as_bytes() {
            Ok(Self(secret_seed.0.clone()))
        } else {
            Err(SeedMismatch)
        }
    }

    /// The 16-byte `secret_seed`.
    pub fn secret_seed(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Shows nothing: the seed is a delivered secret.
impl fmt::Debug for OpenedSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedSeed").finish_non_exhaustive()
    }
}
