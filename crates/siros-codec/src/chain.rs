//! The DER certificate chain that an mdoc `x5chain` (RFC 9360) and an `x5c` Header Parameter
//! (RFC 7515, Section 4.1.6) carry.

/// DER certificates, at least one, the signer's first, as the issuer wrote them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateChain {
    first: Vec<u8>,
    rest: Vec<Vec<u8>>,
}

impl CertificateChain {
    /// The chain of `first`, the signer's certificate, and `rest` after it.
    #[must_use]
    pub fn new(first: Vec<u8>, rest: Vec<Vec<u8>>) -> Self {
        Self { first, rest }
    }

    /// The signer's certificate.
    #[must_use]
    pub fn first(&self) -> &[u8] {
        &self.first
    }

    /// The certificates, the signer's first.
    pub fn certificates(&self) -> impl Iterator<Item = &[u8]> {
        std::iter::once(self.first.as_slice()).chain(self.rest.iter().map(Vec::as_slice))
    }
}
