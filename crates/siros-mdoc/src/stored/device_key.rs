//! The device key of the MSO: a `COSE_Key` on a curve of ISO/IEC 18013-5 Table 22 (RFC 9053,
//! Section 7.1).

use siros_openid4vp::cbor::Value;

use super::item::Read as _;

use crate::cose::{Curve, SignatureAlgorithm};

use super::error::DeviceKeyFault;

/// The device key: its curve, the algorithm it signs with, and its point on P-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceKey {
    point: DevicePoint,
    alg: Option<SignatureAlgorithm>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DevicePoint {
    P256(P256Key),
    Other(Curve),
}

/// `kty` (RFC 9053, Section 7.1): 2 for an EC2 key, 1 for an OKP key.
const EC2: i64 = 2;
const OKP: i64 = 1;

impl DeviceKey {
    /// `COSE_Key` of a Table 22 curve: `{1: kty, -1: crv, ? 3: alg, ...}`, with the 32-byte `x` and
    /// `y` of a P-256 key. `alg` restricts the key (RFC 9052 §7.1): one of no signature algorithm
    /// leaves it signing nothing. Without it the curve's signature algorithm holds, and X25519 and
    /// X448 sign nothing (RFC 9053 §7.1).
    pub(crate) fn read(key: Option<&Value>) -> Result<Self, DeviceKeyFault> {
        let key = key.ok_or(DeviceKeyFault::Absent)?;
        let int = |label: i64| key.get_int(label).and_then(|v| v.as_int());
        let (curve, kty) = match int(-1) {
            Some(1) => (Curve::P256, EC2),
            Some(2) => (Curve::P384, EC2),
            Some(3) => (Curve::P521, EC2),
            Some(4) => (Curve::X25519, OKP),
            Some(5) => (Curve::X448, OKP),
            Some(6) => (Curve::Ed25519, OKP),
            Some(7) => (Curve::Ed448, OKP),
            Some(256) => (Curve::BrainpoolP256r1, EC2),
            Some(257) => (Curve::BrainpoolP320r1, EC2),
            Some(258) => (Curve::BrainpoolP384r1, EC2),
            Some(259) => (Curve::BrainpoolP512r1, EC2),
            _ => return Err(DeviceKeyFault::Curve),
        };
        if int(1) != Some(kty) {
            return Err(DeviceKeyFault::KeyType);
        }
        let point = if curve == Curve::P256 {
            DevicePoint::P256(P256Key::read(key)?)
        } else {
            DevicePoint::Other(curve)
        };
        let alg = match key.get_int(3) {
            Some(stated) => stated.as_int().and_then(SignatureAlgorithm::parse),
            None => signature_algorithm(curve),
        };
        Ok(Self { point, alg })
    }

    /// The point, on P-256.
    #[must_use]
    pub fn p256(&self) -> Option<&P256Key> {
        match &self.point {
            DevicePoint::P256(key) => Some(key),
            DevicePoint::Other(_) => None,
        }
    }

    /// The curve.
    #[must_use]
    pub fn curve(&self) -> Curve {
        match self.point {
            DevicePoint::P256(_) => Curve::P256,
            DevicePoint::Other(curve) => curve,
        }
    }

    /// The algorithm the key signs with. `None` for a key that signs nothing, which authenticates
    /// by device MAC alone (ISO/IEC 18013-5 §9.1.3.5), whose header holds HMAC 256/256.
    #[must_use]
    pub fn algorithm(&self) -> Option<SignatureAlgorithm> {
        self.alg
    }
}

/// The signature algorithm of a curve; `None` on a curve RFC 9053 §7.1 keeps to ECDH.
fn signature_algorithm(curve: Curve) -> Option<SignatureAlgorithm> {
    match curve {
        Curve::P256 | Curve::BrainpoolP256r1 => Some(SignatureAlgorithm::Es256),
        Curve::P384 | Curve::BrainpoolP320r1 | Curve::BrainpoolP384r1 => {
            Some(SignatureAlgorithm::Es384)
        }
        Curve::P521 | Curve::BrainpoolP512r1 => Some(SignatureAlgorithm::Es512),
        Curve::Ed25519 | Curve::Ed448 => Some(SignatureAlgorithm::EdDsa),
        Curve::X25519 | Curve::X448 => None,
    }
}

/// Why bytes are no P-256 key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error, siros_explain::Explain)]
#[explain(domain = "mdoc.stored.point_error")]
#[error("{}", self.code())]
pub enum PointError {
    /// The bytes are not an uncompressed SEC 1 point of 32-byte coordinates.
    NotUncompressed,
}

impl PointError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotUncompressed => "point_not_uncompressed",
        }
    }
}

/// A P-256 public key: its coordinates, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct P256Key {
    x: [u8; 32],
    y: [u8; 32],
}

impl P256Key {
    /// The key of the big-endian coordinates `x` and `y`.
    #[must_use]
    pub fn new(x: [u8; 32], y: [u8; 32]) -> Self {
        Self { x, y }
    }

    /// The x-coordinate.
    #[must_use]
    pub fn x(&self) -> &[u8; 32] {
        &self.x
    }

    /// The y-coordinate.
    #[must_use]
    pub fn y(&self) -> &[u8; 32] {
        &self.y
    }

    /// The key of the uncompressed SEC 1 point `point`: `0x04`, then x and y.
    ///
    /// # Errors
    ///
    /// [`PointError::NotUncompressed`] for another encoding.
    pub fn from_sec1(point: &[u8]) -> Result<Self, PointError> {
        let [0x04, coordinates @ ..] = point else {
            return Err(PointError::NotUncompressed);
        };
        let (x, y) = coordinates
            .split_first_chunk::<32>()
            .ok_or(PointError::NotUncompressed)?;
        let y = <[u8; 32]>::try_from(y).map_err(|_| PointError::NotUncompressed)?;
        Ok(Self { x: *x, y })
    }

    /// The uncompressed SEC 1 point.
    #[must_use]
    pub fn sec1(&self) -> [u8; 65] {
        let mut point = [0x04; 65];
        for (to, from) in point.iter_mut().skip(1).zip(self.x.iter().chain(&self.y)) {
            *to = *from;
        }
        point
    }

    /// The coordinates of a `COSE_Key`: `{-2: x, -3: y}`.
    fn read(key: &Value) -> Result<Self, DeviceKeyFault> {
        let coordinate = |label: i64| -> Result<[u8; 32], DeviceKeyFault> {
            key.get_int(label)
                .and_then(|v| v.bytes())
                .and_then(|c| <[u8; 32]>::try_from(c).ok())
                .ok_or(DeviceKeyFault::Coordinate)
        };
        Ok(Self {
            x: coordinate(-2)?,
            y: coordinate(-3)?,
        })
    }
}
