//! The device key of the MSO: a P-256 `COSE_Key` (RFC 9053, Section 7.1).

use siros_codec::cbor::Item;

use crate::error::DeviceKeyFault;

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

    /// `COSE_Key` of an EC2 P-256 key: `{1: 2, -1: 1, -2: x, -3: y}`.
    pub(crate) fn read(key: Option<&Item<'_>>) -> Result<Self, DeviceKeyFault> {
        let key = key.ok_or(DeviceKeyFault::Absent)?;
        let int = |label: i64| key.get_int(label).and_then(Item::as_int);
        if int(1) != Some(2) {
            return Err(DeviceKeyFault::KeyType);
        }
        if int(-1) != Some(1) {
            return Err(DeviceKeyFault::Curve);
        }
        let coordinate = |label: i64| -> Result<[u8; 32], DeviceKeyFault> {
            key.get_int(label)
                .and_then(Item::as_bytes)
                .and_then(|c| <[u8; 32]>::try_from(c).ok())
                .ok_or(DeviceKeyFault::Coordinate)
        };
        Ok(Self {
            x: coordinate(-2)?,
            y: coordinate(-3)?,
        })
    }
}
