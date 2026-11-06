//! `issuerAuth`: the issuer's `COSE_Sign1` over the MSO (ISO/IEC 18013-5, 9.1.2.4).

use siros_openid4vp::cbor::{self, Value};

use super::error::{ArrayIndex, MemberFault};
use super::item::{Read as _, raw};

use super::error::{AlgorithmFault, IssuerAuthFault, MdocError};
use super::signature::{CoseAlgorithm, SigStructure};

/// The COSE label of `alg` (RFC 9052, Section 3.1).
const ALG: i64 = 1;
/// The COSE label of `x5chain` (RFC 9360).
const X5CHAIN: i64 = 33;

/// `issuerAuth`, as the issuer wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerAuth {
    encoded: Vec<u8>,
    algorithm: CoseAlgorithm,
    x5chain: CertificateChain,
    sig_structure: SigStructure,
    signature: Vec<u8>,
}

impl IssuerAuth {
    /// `COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]`, and
    /// the payload's content.
    pub(crate) fn read(item: &Value) -> Result<(Self, &[u8]), MdocError> {
        let fault = MdocError::IssuerAuth;
        let Some([protected, unprotected, payload, signature]) = item.items() else {
            return Err(fault(IssuerAuthFault::NotSign1));
        };
        let header = protected.bytes().ok_or(fault(IssuerAuthFault::Protected))?;
        let algorithm = cbor::decode(header)
            .map_err(|e| MdocError::Algorithm(AlgorithmFault::Header(e.into())))?
            .get_int(ALG)
            .and_then(|v| v.as_int())
            .map(CoseAlgorithm::new)
            .ok_or(MdocError::Algorithm(AlgorithmFault::Absent))?;
        let x5chain = x5chain(unprotected.get_int(X5CHAIN)).map_err(MdocError::X5chain)?;
        let payload_bytes = payload.bytes().ok_or(fault(IssuerAuthFault::Payload))?;
        let signature = signature.bytes().ok_or(fault(IssuerAuthFault::Signature))?;
        // RFC 9052, Section 4.4: ["Signature1", protected, external_aad = h'', payload], with the
        // protected header and the payload as the issuer wrote them.
        let sig_structure = [
            &[0x84, 0x6a][..],
            b"Signature1",
            &raw(protected).map_err(|e| MdocError::Cbor(e.into()))?,
            &[0x40],
            &raw(payload).map_err(|e| MdocError::Cbor(e.into()))?,
        ]
        .concat();
        let auth = Self {
            encoded: raw(item).map_err(|e| MdocError::Cbor(e.into()))?,
            algorithm,
            x5chain,
            sig_structure: SigStructure::new(sig_structure),
            signature: signature.to_vec(),
        };
        Ok((auth, payload_bytes))
    }

    /// The encoded `COSE_Sign1`.
    #[must_use]
    pub fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }

    /// The COSE algorithm of the protected header.
    #[must_use]
    pub fn algorithm(&self) -> CoseAlgorithm {
        self.algorithm
    }

    /// `x5chain` (RFC 9360): the issuer's certificates, the Document Signer's first.
    #[must_use]
    pub fn x5chain(&self) -> &CertificateChain {
        &self.x5chain
    }

    /// The COSE `Sig_structure` the signature covers.
    #[must_use]
    pub fn sig_structure(&self) -> &SigStructure {
        &self.sig_structure
    }

    /// The signature, in the form [`IssuerAuth::algorithm`] defines.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// `x5chain`: one certificate, or a non-empty array of them, the signer's first (RFC 9360).
fn x5chain(item: Option<&Value>) -> Result<CertificateChain, MemberFault> {
    match item.ok_or(MemberFault::Absent)? {
        Value::Bytes(der) => Ok(CertificateChain::new(der.clone(), Vec::new())),
        Value::Array(certificates) => {
            let mut ders = certificates.iter().enumerate().map(|(index, certificate)| {
                certificate
                    .bytes()
                    .map(<[u8]>::to_vec)
                    .ok_or(MemberFault::Entry(ArrayIndex::new(index)))
            });
            let document_signer = ders.next().ok_or(MemberFault::Empty)??;
            Ok(CertificateChain::new(
                document_signer,
                ders.collect::<Result<_, _>>()?,
            ))
        }
        _ => Err(MemberFault::WrongType),
    }
}

/// A DER certificate chain, the signer's certificate first: an mdoc's `x5chain` (RFC 9360,
/// Section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateChain {
    first: Vec<u8>,
    rest: Vec<Vec<u8>>,
}

impl CertificateChain {
    /// The chain of `first` and `rest` after it.
    #[must_use]
    pub(crate) fn new(first: Vec<u8>, rest: Vec<Vec<u8>>) -> Self {
        Self { first, rest }
    }

    /// The signer's certificate.
    #[must_use]
    pub fn first(&self) -> &[u8] {
        &self.first
    }

    /// Every certificate, the signer's first.
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.first.as_slice()).chain(self.rest.iter().map(Vec::as_slice))
    }
}
