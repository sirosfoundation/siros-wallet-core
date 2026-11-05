//! The host modules siros-paso calls beside the core's: [`RandomIds`] for a response's `jti`
//! (Core §6.1), with the identifiers it returns; and [`CoseEncrypt`], which seals an mdoc's risk
//! signals under the feature `sealed-signals`.

use std::fmt;

use siros_explain::Explain;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::AgreeableKey;
use uuid::{Builder, Uuid, Variant, Version};

/// A content encryption a `COSE_Encrypt` carries (IANA "COSE Algorithms", RFC 9053 §4.1): its
/// integer value. The registry is open; a module states the ones it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CoseEnc(i64);

impl CoseEnc {
    /// A128GCM (RFC 9053 §4.1).
    pub const A128GCM: Self = Self(1);
    /// A192GCM.
    pub const A192GCM: Self = Self(2);
    /// A256GCM.
    pub const A256GCM: Self = Self(3);

    /// The value as a COSE header writes it.
    #[must_use]
    pub const fn new(id: i64) -> Self {
        Self(id)
    }

    /// The value.
    #[must_use]
    pub const fn id(self) -> i64 {
        self.0
    }
}

/// A `COSE_Encrypt` (RFC 9052 §5.1, tag 96) to a public key, with one recipient holding the
/// ephemeral key and, as label 4, the key's `kid` (RFC 9053 §6.3, ECDH-ES + HKDF-256). Used when
/// the build holds it.
///
/// # Implementing
///
/// `encryptions` lists the content encryptions `encrypt_cose` implements; siros-paso seals under
/// one the risk signal's key and the statement both admit (Risk Signals §7.6: A256GCM), and
/// refuses a ciphertext of another (`NotSealedCose::Enc`). `TestCoseEncrypt` is the double.
pub trait CoseEncrypt {
    /// The content encryptions it implements.
    fn encryptions(&self) -> &'static [CoseEnc];
    /// The plaintext encrypted to a public key under the key's own agreement (`key.alg`: -25, or
    /// a key wrap -29 to -31) and `enc`.
    ///
    /// # Errors
    ///
    /// The module broke its contract.
    fn encrypt_cose(
        &self,
        key: &AgreeableKey<'_>,
        enc: CoseEnc,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Fault>;
}

/// Fresh identifiers: a response's `jti`. Required by siros-paso.
///
/// # Implementing
///
/// `random_id` returns a fresh version 4 UUID from the platform's random bytes
/// ([`RandomId::from_bytes`]); siros-paso writes it as a response's `jti` (Core §6.1). The app
/// implements it; `TestRandomIds` is the double.
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
