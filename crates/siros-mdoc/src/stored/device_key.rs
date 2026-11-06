//! The device key of the MSO: a `COSE_Key` on a curve of ISO/IEC 18013-5 Table 22 (RFC 9053,
//! Section 7.1).

use siros_openid4vp::cbor::Value;

use super::item::Read as _;
use super::signature::CoseAlgorithm;

use crate::cose::Curve;

use super::error::DeviceKeyFault;

/// The device key: its curve, its stated algorithm, and its point on P-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceKey {
    point: DevicePoint,
    alg: Option<CoseAlgorithm>,
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
    /// `y` of a P-256 key.
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
        Ok(Self {
            point,
            alg: int(3).map(CoseAlgorithm::new),
        })
    }

    /// The point, on P-256.
    #[must_use]
    pub fn p256(&self) -> Option<&P256Key> {
        match &self.point {
            DevicePoint::P256(key) => Some(key),
            DevicePoint::Other(_) => None,
        }
    }

    /// The curve's name in Table 22.
    #[must_use]
    pub fn curve(&self) -> &'static str {
        match self.point {
            DevicePoint::P256(_) => Curve::P256.name(),
            DevicePoint::Other(curve) => curve.name(),
        }
    }

    /// `alg` (label 3), else the algorithm RFC 9053 Sections 2.1 and 2.2 and Table 22 give the
    /// curve; for a key-agreement curve ECDH-ES with HKDF-256 (RFC 9053, Section 6.3.1).
    #[must_use]
    pub fn algorithm(&self) -> CoseAlgorithm {
        let of_curve = match self.point {
            DevicePoint::P256(_) => -7,
            DevicePoint::Other(curve) => match curve {
                Curve::P256 | Curve::BrainpoolP256r1 => -7,
                Curve::P384 | Curve::BrainpoolP320r1 | Curve::BrainpoolP384r1 => -35,
                Curve::P521 | Curve::BrainpoolP512r1 => -36,
                Curve::Ed25519 | Curve::Ed448 => -8,
                Curve::X25519 | Curve::X448 => -25,
            },
        };
        self.alg.unwrap_or(CoseAlgorithm::new(of_curve))
    }
}

/// Why bytes are no P-256 key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
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
