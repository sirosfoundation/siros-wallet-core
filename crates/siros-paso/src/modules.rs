//! The host modules siros-paso calls beside the core's: [`RandomIds`] for a response's `jti`
//! (Core §6.1), with the identifiers it returns; and the host's `COSE_Encrypt` slot, which the
//! module fills under the feature `sealed-signals`.

use std::fmt;

use siros_explain::Explain;
use uuid::{Builder, Uuid, Variant, Version};

/// The host's `COSE_Encrypt` slot, which siros-paso's phase 2 bounds: `MayHave<dyn CoseEncrypt>`
/// under the feature `sealed-signals`, every host without it.
#[cfg(feature = "sealed-signals")]
pub trait CoseSlot: siros_openid4vp::host::MayHave<dyn crate::CoseEncrypt> {}

#[cfg(feature = "sealed-signals")]
impl<H: siros_openid4vp::host::MayHave<dyn crate::CoseEncrypt>> CoseSlot for H {}

/// The host's `COSE_Encrypt` slot, which siros-paso's phase 2 bounds: `MayHave<dyn CoseEncrypt>`
/// under the feature `sealed-signals`, every host without it.
#[cfg(not(feature = "sealed-signals"))]
pub trait CoseSlot {}

#[cfg(not(feature = "sealed-signals"))]
impl<H> CoseSlot for H {}

/// Fresh identifiers: a response's `jti`. Required by siros-paso.
pub trait RandomIds {
    /// A fresh random identifier.
    fn random_id(&self) -> RandomId;
}

/// A random UUID (RFC 9562 §5.4), written as its lowercase hyphenated text (RFC 9562 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RandomId(Uuid);

/// A text that is no version 4 UUID in lowercase hyphenated form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Explain)]
#[explain(domain = "paso.random_id")]
pub enum NotRandomId {
    /// No UUID text (RFC 9562 §4).
    #[error("{text:?} is no UUID: {cause}")]
    Uuid {
        /// The text.
        text: String,
        /// uuid's reason.
        #[source]
        #[explain(skip)]
        cause: uuid::Error,
    },
    /// A UUID of another version or variant.
    #[error("{0:?} is no version 4 UUID of the RFC 9562 variant")]
    Version(#[explain(name = "text")] String),
    /// A UUID written in another form: braces, a URN, no hyphens, or uppercase digits.
    #[error("{0:?} is no UUID's lowercase hyphenated text")]
    Text(#[explain(name = "text")] String),
}

impl RandomId {
    /// The UUID of 16 random bytes, its version and variant bits set (RFC 9562 §5.4).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Builder::from_random_bytes(bytes).into_uuid())
    }

    /// Parses `xxxxxxxx-xxxx-4xxx-Vxxx-xxxxxxxxxxxx` in lowercase, V one of 8, 9, a, b.
    ///
    /// # Errors
    ///
    /// The text is no UUID, a UUID of another version or variant, or a UUID in another form.
    pub fn parse(text: &str) -> Result<Self, NotRandomId> {
        let uuid = Uuid::try_parse(text).map_err(|cause| NotRandomId::Uuid {
            text: text.to_owned(),
            cause,
        })?;
        if uuid.get_version() != Some(Version::Random) || uuid.get_variant() != Variant::RFC4122 {
            return Err(NotRandomId::Version(text.to_owned()));
        }
        let mut buffer = Uuid::encode_buffer();
        if uuid.hyphenated().encode_lower(&mut buffer) != text {
            return Err(NotRandomId::Text(text.to_owned()));
        }
        Ok(Self(uuid))
    }
}

impl fmt::Display for RandomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

#[cfg(feature = "test-util")]
mod test_util {
    use std::cell::Cell;

    use super::{RandomId, RandomIds};

    /// The identifiers double: `00000000-0000-4000-8000-` and the count of identifiers issued in
    /// twelve decimal digits.
    #[derive(Debug, Clone, Default)]
    pub struct TestRandomIds {
        issued: Cell<u64>,
    }

    impl TestRandomIds {
        /// The double once it has issued `count` identifiers: its next is the count after.
        #[must_use]
        pub fn after_issuing(count: u64) -> Self {
            Self {
                issued: Cell::new(count),
            }
        }

        /// How many identifiers it issued.
        #[must_use]
        pub fn issued(&self) -> u64 {
            self.issued.get()
        }
    }

    impl RandomIds for TestRandomIds {
        fn random_id(&self) -> RandomId {
            let issued = self.issued.get() + 1;
            self.issued.set(issued);
            let digits: Vec<u8> = format!("{:012}", issued % 1_000_000_000_000)
                .bytes()
                .map(|digit| digit - b'0')
                .collect();
            let mut bytes = [0u8; 16];
            for (byte, pair) in bytes.iter_mut().skip(10).zip(digits.chunks(2)) {
                *byte = pair.iter().fold(0, |value, digit| (value << 4) | digit);
            }
            RandomId::from_bytes(bytes)
        }
    }
}

#[cfg(feature = "test-util")]
pub use test_util::TestRandomIds;
