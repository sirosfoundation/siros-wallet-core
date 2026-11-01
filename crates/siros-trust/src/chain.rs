//! A credential's issuer chain (TR2): the certificates the credential carries for its issuer,
//! the signer's first.

use siros_codec::chain::CertificateChain;

use crate::authority::KeyIdentifier;
use crate::certificate::{Certificate, CertificateError};
use crate::position::ChainIndex;

/// An issuer chain: at least one certificate, the signer's first. The mdoc `x5chain` or the
/// SD-JWT VC issuer-signed JWT's `x5c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerChain {
    leaf: Certificate,
    issuers: Vec<Certificate>,
}

/// Why a certificate of an issuer chain does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{error} at {position}")]
pub struct ChainError {
    position: ChainIndex,
    #[source]
    error: CertificateError,
}

impl ChainError {
    /// The certificate's position.
    #[must_use]
    pub fn position(self) -> ChainIndex {
        self.position
    }

    /// Why it does not parse.
    #[must_use]
    pub fn error(self) -> CertificateError {
        self.error
    }

    /// A stable identifier: the certificate's code.
    #[must_use]
    pub fn code(self) -> &'static str {
        self.error.code()
    }
}

impl IssuerChain {
    /// The chain of the DER certificates `certificates`.
    ///
    /// # Errors
    ///
    /// [`ChainError`]: the first certificate that does not parse.
    pub fn parse(certificates: &CertificateChain) -> Result<Self, ChainError> {
        let parse = |position: usize, der: &[u8]| {
            Certificate::parse(der).map_err(|error| ChainError {
                position: ChainIndex::new(position),
                error,
            })
        };
        let leaf = parse(0, certificates.first())?;
        let issuers = certificates
            .certificates()
            .enumerate()
            .skip(1)
            .map(|(position, der)| parse(position, der))
            .collect::<Result<_, _>>()?;
        Ok(Self { leaf, issuers })
    }

    /// The chain of the parsed certificates `leaf`, the signer's, and `issuers` after it.
    #[must_use]
    pub fn new(leaf: Certificate, issuers: Vec<Certificate>) -> Self {
        Self { leaf, issuers }
    }

    /// The certificates, the signer's first.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        std::iter::once(&self.leaf).chain(&self.issuers)
    }

    /// The chain's first certificate: the signer's.
    #[must_use]
    pub fn leaf(&self) -> &Certificate {
        &self.leaf
    }

    /// The keyIdentifiers the chain's AuthorityKeyIdentifier extensions name, in the chain's
    /// order.
    pub fn key_identifiers(&self) -> impl Iterator<Item = &KeyIdentifier> {
        self.certificates()
            .filter_map(Certificate::authority_key_identifier)
    }
}
