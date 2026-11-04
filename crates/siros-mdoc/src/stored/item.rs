//! The reading of a CBOR value as the stored mdoc's structures name their members.

use siros_openid4vp::cbor::{self, CborError, Value};

/// A value read for its members, elements and scalars.
pub(crate) trait Read {
    /// The member of a map under a text key.
    fn get(&self, key: &str) -> Option<&Value>;
    /// The member of a map under an integer label.
    fn get_int(&self, label: i64) -> Option<&Value>;
    /// An integer that fits an `i64`.
    fn as_int(&self) -> Option<i64>;
    /// An unsigned integer.
    fn as_unsigned(&self) -> Option<u64>;
    /// The content of the tag `tag`.
    fn untag(&self, tag: u64) -> Option<&Value>;
    /// The bytes of a byte string.
    fn bytes(&self) -> Option<&[u8]>;
    /// The items of an array.
    fn items(&self) -> Option<&[Value]>;
    /// The pairs of a map.
    fn pairs(&self) -> Option<&[(Value, Value)]>;
}

impl Read for Value {
    fn get(&self, key: &str) -> Option<&Value> {
        self.pairs()?
            .iter()
            .find(|(name, _)| name.as_text() == Some(key))
            .map(|(_, value)| value)
    }

    fn get_int(&self, label: i64) -> Option<&Value> {
        self.pairs()?
            .iter()
            .find(|(name, _)| name.as_int() == Some(label))
            .map(|(_, value)| value)
    }

    fn as_int(&self) -> Option<i64> {
        self.as_integer().and_then(|n| i64::try_from(n).ok())
    }

    fn as_unsigned(&self) -> Option<u64> {
        self.as_integer().and_then(|n| u64::try_from(n).ok())
    }

    fn untag(&self, tag: u64) -> Option<&Value> {
        match self {
            Value::Tag(found, inner) if *found == tag => Some(inner),
            _ => None,
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        self.as_bytes().map(Vec::as_slice)
    }

    fn items(&self) -> Option<&[Value]> {
        self.as_array().map(Vec::as_slice)
    }

    fn pairs(&self) -> Option<&[(Value, Value)]> {
        self.as_map().map(Vec::as_slice)
    }
}

/// The value's encoding with the shortest heads (RFC 8949 §4.1). A digest or a signature over an
/// item its issuer wrote in another form does not verify.
pub(crate) fn raw(value: &Value) -> Result<Vec<u8>, CborError> {
    cbor::encode(value)
}
