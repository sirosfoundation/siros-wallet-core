//! The P-256 public key an ES256 signature verifies under (RFC 7518 §3.4), as p256 holds it.

use siros_explain::Explain;

/// A P-256 public key: a point of the curve other than the identity, as p256's `PublicKey` holds
/// it (feature `resolve`, which the matcher does not build). A prefix binding makes it from the
/// key its framework names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationKey(p256::PublicKey);

/// Coordinates that are no point of P-256, or the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "openid4vp.jose")]
#[error("the coordinates are no point of P-256")]
pub struct NotOnCurve;

impl VerificationKey {
    /// The key at these affine coordinates, 32 octets each, big-endian: SEC 1 §2.3.4's
    /// uncompressed point, which p256 decodes and refuses off the curve.
    ///
    /// # Errors
    ///
    /// The coordinates are no point of P-256 other than the identity.
    pub fn p256(x: [u8; 32], y: [u8; 32]) -> Result<Self, NotOnCurve> {
        let point: Vec<u8> = [4u8].iter().chain(&x).chain(&y).copied().collect();
        p256::PublicKey::from_sec1_bytes(&point)
            .map(Self)
            .map_err(|_| NotOnCurve)
    }

    /// The key p256 holds.
    #[must_use]
    pub const fn of(key: p256::PublicKey) -> Self {
        Self(key)
    }

    /// The key.
    #[must_use]
    pub const fn key(&self) -> &p256::PublicKey {
        &self.0
    }
}
