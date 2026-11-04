//! The device MAC module (ISO/IEC 18013-5 §9.1.3.5), which siros-mdoc uses when the build's host
//! holds it, and its tag.

use siros_openid4vp::ids::CredentialId;
use siros_openid4vp::plugins::Fault;
use siros_openid4vp::request::AgreeableKey;
use siros_openid4vp::session::SessionTranscriptBytes;

/// A MAC's tag (RFC 9052 §6) as the module made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mac(Vec<u8>);

impl Mac {
    /// The tag the module made.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// ISO/IEC 18013-5 §9.1.3.5's device MAC; the credentials' device keys sit in the platform's
/// keystore.
pub trait DeviceMac {
    /// HMAC-SHA-256 under EMacKey: the HKDF of the ECDH secret of the credential's device key
    /// and the Verifier's key, salted with the SHA-256 of the transcript.
    ///
    /// # Errors
    ///
    /// The module broke its contract.
    fn mac(
        &self,
        credential: &CredentialId<'_>,
        reader: &AgreeableKey<'_>,
        transcript: &SessionTranscriptBytes,
        data: &[u8],
    ) -> Result<Mac, Fault>;
}

/// The device MAC's stand-in for the tests (feature `test-util`).
#[cfg(feature = "test-util")]
mod test_util {
    use sha2::{Digest, Sha256};

    use super::{AgreeableKey, CredentialId, DeviceMac, Fault, Mac, SessionTranscriptBytes};

    /// The first 8 bytes of SHA-256, in lowercase hexadecimal: the stand-ins' digest, as
    /// siros-testkit writes it.
    fn digest_prefix(data: &[u8]) -> String {
        Sha256::digest(data)
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The device MAC's stand-in.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct TestDeviceMac;

    impl DeviceMac for TestDeviceMac {
        /// `mac:{credential}:{kid}:{digest of SessionTranscriptBytes then the data}`: the digest
        /// covers the salt's input, so a wrong transcript shows.
        fn mac(
            &self,
            credential: &CredentialId<'_>,
            reader: &AgreeableKey<'_>,
            transcript: &SessionTranscriptBytes,
            data: &[u8],
        ) -> Result<Mac, Fault> {
            Ok(Mac::new(
                format!(
                    "mac:{credential}:{}:{}",
                    reader.kid,
                    digest_prefix(&[transcript.as_bytes(), data].concat())
                )
                .into_bytes(),
            ))
        }
    }
}

#[cfg(feature = "test-util")]
pub use test_util::TestDeviceMac;
