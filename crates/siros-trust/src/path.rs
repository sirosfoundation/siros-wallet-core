//! Path validation as TR3 restricts RFC 5280, Section 6.1: an issuer chain's first certificate
//! has a path to an anchor certificate at a given time.
//!
//! A path is a prefix of the chain, each certificate signed by the next, whose last certificate
//! an anchor signs; or the chain's first certificate alone, when an anchor is byte-identical to
//! it (direct trust). TR3 applies these rules to a path:
//!
//! | Rule | RFC 5280 |
//! | --- | --- |
//! | every certificate on the path, the anchor included, is valid at the time | 6.1.3 (a)(2) |
//! | each signer's subject is the certificate's issuer, compared as DER bytes | 6.1.3 (a)(4) |
//! | each signature verifies under its signer's key: ECDSA P-256 with SHA-256 or P-384 with SHA-384, over the `tbsCertificate` as written | 6.1.3 (a)(1) |
//! | each signer is a CA | 6.1.4 (k) |
//! | at most its pathLenConstraint of non-self-issued intermediate certificates lie below a signer | 6.1.4 (l), (m) |
//! | a signer's keyUsage, when present, includes keyCertSign | 6.1.4 (n) |
//! | every certificate on the path, the anchor included, has each critical extension in the set [`extensions`](crate::extensions) processes | 6.1.4 (o) |

use der::asn1::ObjectIdentifier;
use siros_codec::date::DateTime;

use crate::certificate::{Certificate, IssuanceRefusal};
use crate::chain::IssuerChain;
use crate::extensions::{CertSigning, CertificateRole, PathLength};
use crate::position::{CertificateIndex, ChainIndex};

/// A certificate on a validation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnPath {
    /// A certificate of the issuer chain.
    Chain(ChainIndex),
    /// An anchor certificate.
    Store(CertificateIndex),
}

/// Why an issuer chain has no path to an anchor certificate. It names the attempt it refuses:
/// the deepest prefix of the chain tried, and there the first anchor tried, when one has the
/// subject the prefix's last certificate names as its issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}: {:?}", self.code(), self)]
pub enum PathRefusal {
    /// The certificate is not valid at the time.
    NotValid(OnPath),
    /// The certificate has this critical extension, outside the set TR3 processes (RFC 5280,
    /// Section 6.1.4 (o)).
    CriticalExtension {
        /// The certificate.
        certificate: OnPath,
        /// The extension's identifier.
        extension: ObjectIdentifier,
    },
    /// No anchor, nor the chain's next certificate, has the subject the chain's certificate
    /// names as its issuer.
    IssuerName(ChainIndex),
    /// The signer is not a CA: its basicConstraints is absent or its `cA` is FALSE.
    NotCa(OnPath),
    /// The signer's keyUsage leaves keyCertSign out (RFC 5280, Section 6.1.4 (n)).
    KeyCertSign(OnPath),
    /// More non-self-issued intermediate certificates lie below the signer than its
    /// pathLenConstraint allows (RFC 5280, Section 6.1.4 (l) and (m)).
    PathLength(OnPath),
    /// The chain's certificate is signed with an algorithm other than `ecdsa-with-SHA256` and
    /// `ecdsa-with-SHA384`.
    Algorithm(ChainIndex),
    /// The signer's key is of another type or curve than the certificate's signature algorithm
    /// takes.
    IssuerKey {
        /// The certificate.
        certificate: ChainIndex,
        /// Its signer.
        signer: OnPath,
    },
    /// The certificate's signature is no DER `ECDSA-Sig-Value` of the signer's curve.
    SignatureEncoding {
        /// The certificate.
        certificate: ChainIndex,
        /// Its signer.
        signer: OnPath,
    },
    /// The certificate's signature does not verify under the signer's key.
    Signature {
        /// The certificate.
        certificate: ChainIndex,
        /// Its signer.
        signer: OnPath,
    },
}

impl PathRefusal {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotValid(_) => "path_not_valid",
            Self::CriticalExtension { .. } => "path_critical_extension",
            Self::IssuerName(_) => "path_issuer_name",
            Self::NotCa(_) => "path_signer_not_ca",
            Self::KeyCertSign(_) => "path_signer_key_cert_sign",
            Self::PathLength(_) => "path_length",
            Self::Algorithm(_) => "path_signature_algorithm",
            Self::IssuerKey { .. } => "path_issuer_key",
            Self::SignatureEncoding { .. } => "path_signature_encoding",
            Self::Signature { .. } => "path_signature",
        }
    }
}

/// A signer on a path, with its position and the number of non-self-issued intermediate
/// certificates below it.
#[derive(Clone, Copy)]
struct Signer<'c> {
    certificate: &'c Certificate,
    position: OnPath,
    below: usize,
}

impl IssuerChain {
    /// Path validation (TR3): the anchor of `anchors` at which the chain's first certificate
    /// has a path at `time`.
    ///
    /// An anchor byte-identical to the chain's first certificate admits it. Otherwise each
    /// prefix of the chain is tried, shortest first, and at each the anchors whose subject its
    /// last certificate names as its issuer, the one whose SubjectKeyIdentifier equals the
    /// certificate's AuthorityKeyIdentifier first.
    ///
    /// # Errors
    ///
    /// [`PathRefusal`]: why the deepest attempt fails.
    pub fn validate_path<'a>(
        &self,
        anchors: &'a [Certificate],
        time: DateTime,
    ) -> Result<&'a Certificate, PathRefusal> {
        let certificates: Vec<&Certificate> = self.certificates().collect();
        let mut position = 0;
        let mut certificate = self.leaf();
        // The non-self-issued intermediate certificates of the prefix: every certificate after
        // the first.
        let mut below = 0;
        loop {
            let at = ChainIndex::new(position);
            on_path(certificate, OnPath::Chain(at), time)?;
            if position == 0 {
                if let Some(anchor) = anchors.iter().find(|anchor| *anchor == certificate) {
                    return Ok(anchor);
                }
            }
            let refusal = match anchored(certificate, at, below, anchors, time) {
                Ok(anchor) => return Ok(anchor),
                Err(refusal) => refusal,
            };
            let next = certificates.get(position + 1).copied();
            certificate = match next_link(certificate, at, below, next) {
                Ok(next) => next,
                Err(extension) => return Err(refusal.unwrap_or(extension)),
            };
            position += 1;
            if !certificate.self_issued() {
                below += 1;
            }
        }
    }
}

/// `certificate`, at `position` on the path, valid at `time` and with no critical extension
/// outside the processed set.
fn on_path(certificate: &Certificate, position: OnPath, time: DateTime) -> Result<(), PathRefusal> {
    if !certificate.valid_at(time) {
        return Err(PathRefusal::NotValid(position));
    }
    match certificate.unprocessed_critical() {
        Some(extension) => Err(PathRefusal::CriticalExtension {
            certificate: position,
            extension,
        }),
        None => Ok(()),
    }
}

/// The anchor that signs `certificate`, at `at` on the chain above `below` non-self-issued
/// intermediate certificates; else the refusal of the first anchor tried, or `None` when no
/// anchor has the subject `certificate` names as its issuer.
fn anchored<'a>(
    certificate: &Certificate,
    at: ChainIndex,
    below: usize,
    anchors: &'a [Certificate],
    time: DateTime,
) -> Result<&'a Certificate, Option<PathRefusal>> {
    let mut named: Vec<(CertificateIndex, &'a Certificate)> = anchors
        .iter()
        .enumerate()
        .filter(|(_, anchor)| certificate.names_as_issuer(anchor))
        .map(|(index, anchor)| (CertificateIndex::new(index), anchor))
        .collect();
    let keyed = |anchor: &Certificate| {
        certificate.authority_key_identifier().is_some()
            && certificate.authority_key_identifier() == anchor.subject_key_identifier()
    };
    named.sort_by_key(|(_, anchor)| !keyed(anchor));
    let mut first = None;
    for (index, anchor) in named {
        let signer = Signer {
            certificate: anchor,
            position: OnPath::Store(index),
            below,
        };
        let signs =
            on_path(anchor, signer.position, time).and_then(|()| link(certificate, at, signer));
        match signs {
            Ok(()) => return Ok(anchor),
            Err(refusal) => {
                if first.is_none() {
                    first = Some(refusal);
                }
            }
        }
    }
    Err(first)
}

/// `next`, the chain's next certificate, when it signs `certificate` at `at` above `below`
/// non-self-issued intermediate certificates. Its validity and extensions are checked at its
/// own step.
fn next_link<'c>(
    certificate: &Certificate,
    at: ChainIndex,
    below: usize,
    next: Option<&'c Certificate>,
) -> Result<&'c Certificate, PathRefusal> {
    let next = next
        .filter(|next| certificate.names_as_issuer(next))
        .ok_or(PathRefusal::IssuerName(at))?;
    let signer = Signer {
        certificate: next,
        position: OnPath::Chain(ChainIndex::new(at.value() + 1)),
        below,
    };
    link(certificate, at, signer).map(|()| next)
}

/// Whether `signer` signs `certificate`, at `at` on the chain: a CA whose keyUsage lets it sign
/// certificates and whose pathLenConstraint admits the intermediates below it, that issued
/// `certificate`.
fn link(certificate: &Certificate, at: ChainIndex, signer: Signer<'_>) -> Result<(), PathRefusal> {
    let path_length = match signer.certificate.role() {
        CertificateRole::Ca(path_length) => path_length,
        CertificateRole::EndEntity => return Err(PathRefusal::NotCa(signer.position)),
    };
    if signer.certificate.cert_signing() == CertSigning::Withheld {
        return Err(PathRefusal::KeyCertSign(signer.position));
    }
    if let PathLength::AtMost(length) = path_length {
        if signer.below > usize::from(length) {
            return Err(PathRefusal::PathLength(signer.position));
        }
    }
    certificate
        .issued_by(signer.certificate)
        .map_err(|refusal| match refusal {
            IssuanceRefusal::IssuerName => PathRefusal::IssuerName(at),
            IssuanceRefusal::Algorithm => PathRefusal::Algorithm(at),
            IssuanceRefusal::IssuerKey => PathRefusal::IssuerKey {
                certificate: at,
                signer: signer.position,
            },
            IssuanceRefusal::SignatureEncoding => PathRefusal::SignatureEncoding {
                certificate: at,
                signer: signer.position,
            },
            IssuanceRefusal::Signature => PathRefusal::Signature {
                certificate: at,
                signer: signer.position,
            },
        })
}
